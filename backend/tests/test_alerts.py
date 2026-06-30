import datetime

from app import alerts
from app.models import Certificate, Endpoint, NotificationChannel, Target, utcnow
from app.scan_engine import _upsert_certificate


def _cert(db, fp="AA:BB", days=20):
    c = Certificate(
        fingerprint_sha256=fp, common_name="host.example.com", issuer_cn="Internal CA",
        not_after=utcnow() + datetime.timedelta(days=days),
    )
    db.add(c); db.flush(); return c


def _endpoint(db, target, cert):
    ep = Endpoint(target_id=target.id, host="host.example.com", ip="10.0.0.5", port=443,
                  current_cert_id=cert.id, last_status="ok")
    db.add(ep); db.flush(); return ep


def _target(db, thresholds=(90, 30, 7)):
    t = Target(name="grp", target_type="hostname", value="host.example.com",
               ports=[443], alert_thresholds=list(thresholds))
    db.add(t); db.flush(); return t


def test_certificate_deduplication(db):
    fields = {"fingerprint_sha256": "DE:AD", "common_name": "x"}
    c1 = _upsert_certificate(db, dict(fields))
    c2 = _upsert_certificate(db, dict(fields))
    assert c1.id == c2.id
    assert db.query(Certificate).count() == 1


def test_alert_threshold_logic(db):
    t = _target(db, thresholds=(90, 30, 7))
    c = _cert(db, days=20)            # 20 days -> hits the 30 threshold
    _endpoint(db, t, c)
    db.commit()
    res = alerts.evaluate_alerts(db, dispatch=False)
    assert res["created"] == 1
    events = db.query(alerts.AlertEvent).all()
    assert len(events) == 1
    assert events[0].rule_type == "expiring"
    assert events[0].threshold_days == 30
    assert events[0].severity == "warning"


def test_expired_alert(db):
    t = _target(db)
    c = _cert(db, fp="EX:PI", days=-3)
    _endpoint(db, t, c)
    db.commit()
    alerts.evaluate_alerts(db, dispatch=False)
    ev = db.query(alerts.AlertEvent).filter_by(rule_type="expired").one()
    assert ev.severity == "critical"


def test_alert_auto_resolves_when_renewed(db):
    t = _target(db)
    c = _cert(db, days=5)
    ep = _endpoint(db, t, c)
    db.commit()
    alerts.evaluate_alerts(db, dispatch=False)
    assert db.query(alerts.AlertEvent).filter_by(resolved=False).count() == 1
    # renew: bind a far-future cert
    new = _cert(db, fp="NE:W1", days=400)
    ep.current_cert_id = new.id
    db.commit()
    alerts.evaluate_alerts(db, dispatch=False)
    assert db.query(alerts.AlertEvent).filter_by(resolved=False).count() == 0


def test_suppression_and_re_alert(db, monkeypatch):
    sent = []
    monkeypatch.setattr(alerts, "send_email", lambda cfg, s, t, h=None: sent.append(s))

    t = _target(db)
    c = _cert(db, days=5)
    _endpoint(db, t, c)
    db.add(NotificationChannel(name="mail", channel_type="smtp", enabled=True,
                               config={"host": "x", "recipients": ["a@b.c"]}, re_alert_hours=24))
    db.commit()

    alerts.evaluate_alerts(db)                 # first eval: creates + notifies once
    assert len(sent) == 1
    alerts.dispatch_alerts(db)                 # immediate re-dispatch: suppressed
    assert len(sent) == 1

    # simulate the re-alert interval elapsing
    ev = db.query(alerts.AlertEvent).first()
    ev.last_notified_at = utcnow() - datetime.timedelta(hours=25)
    db.commit()
    alerts.dispatch_alerts(db)
    assert len(sent) == 2


def test_muted_and_acked_not_notified(db, monkeypatch):
    sent = []
    monkeypatch.setattr(alerts, "send_email", lambda *a, **k: sent.append(1))
    t = _target(db)
    c = _cert(db, days=2)
    _endpoint(db, t, c)
    db.add(NotificationChannel(name="m", channel_type="smtp", enabled=True,
                               config={"host": "x", "recipients": ["a@b.c"]}))
    db.commit()
    alerts.evaluate_alerts(db, dispatch=False)
    ev = db.query(alerts.AlertEvent).first()
    ev.acknowledged = True
    db.commit()
    alerts.dispatch_alerts(db)
    assert sent == []


def test_notification_formatting(db):
    t = _target(db)
    c = _cert(db, fp="FE:ED", days=5)
    ep = _endpoint(db, t, c)
    db.commit()
    alerts.evaluate_alerts(db, dispatch=False)
    ev = db.query(alerts.AlertEvent).first()
    subject, text, html, facts, link = alerts._format(db, ev)
    assert "CertWatch" in subject
    assert facts["Common Name"] == "host.example.com"
    assert facts["Fingerprint"] == "FE:ED"
    assert facts["Endpoint"] == "host.example.com:443"
    assert "Recommended action" in text
    assert "/certificates/" in link
