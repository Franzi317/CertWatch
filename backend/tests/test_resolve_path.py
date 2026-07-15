from app import alerts
from app.models import AlertEvent, Certificate, NotificationChannel, utcnow


def _resolved_alert(db, severity="critical", notify_count=1):
    c = Certificate(fingerprint_sha256="FP:R", common_name="h.example.com", source="network")
    db.add(c); db.flush()
    ev = AlertEvent(dedupe_key=f"expiring:1:{c.id}:30", certificate_id=c.id, rule_type="expiring",
                    severity=severity, message="cert expiring", resolved=True,
                    notify_count=notify_count)
    db.add(ev); db.commit()
    return ev


def _channel(db, ctype, **config):
    ch = NotificationChannel(name=f"{ctype}-ch", channel_type=ctype, enabled=True, config=config)
    db.add(ch); db.commit()
    return ch


def test_pagerduty_resolve_sent_once(db, monkeypatch):
    calls = []
    monkeypatch.setattr(alerts, "send_pagerduty",
                        lambda cfg, action, key, **kw: calls.append((action, key)))
    _channel(db, "pagerduty", routing_key="RK", min_severity="critical")
    ev = _resolved_alert(db)
    n = alerts.dispatch_resolutions(db)
    assert n == 1 and calls == [("resolve", ev.dedupe_key)]
    db.refresh(ev)
    assert ev.resolution_notified_at is not None
    # second call is a no-op (already notified)
    calls.clear()
    assert alerts.dispatch_resolutions(db) == 0 and calls == []


def test_resolve_skipped_when_never_notified(db, monkeypatch):
    calls = []
    monkeypatch.setattr(alerts, "send_pagerduty", lambda *a, **k: calls.append(1))
    _channel(db, "pagerduty", routing_key="RK")
    _resolved_alert(db, notify_count=0)  # never paged while open
    assert alerts.dispatch_resolutions(db) == 0 and calls == []


def test_teams_gets_resolved_messagecard(db, monkeypatch):
    calls = []
    monkeypatch.setattr(alerts, "send_webhook",
                        lambda cfg, title, text, facts=None, link="", color="": calls.append((title, color)))
    _channel(db, "teams", url="https://teams/x", format="teams")
    _resolved_alert(db)
    alerts.dispatch_resolutions(db)
    assert len(calls) == 1
    title, color = calls[0]
    assert "RESOLVED" in title and color == alerts._RESOLVED_COLOR


def test_resolve_ignores_ack_and_mute(db, monkeypatch):
    calls = []
    monkeypatch.setattr(alerts, "send_pagerduty", lambda cfg, action, key, **kw: calls.append(action))
    _channel(db, "pagerduty", routing_key="RK", min_severity="info")
    ev = _resolved_alert(db)
    ev.acknowledged = True
    ev.muted = True
    db.commit()
    assert alerts.dispatch_resolutions(db) == 1 and calls == ["resolve"]


def test_evaluate_alerts_reports_resolution_count(db, monkeypatch):
    monkeypatch.setattr(alerts, "send_pagerduty", lambda *a, **k: None)
    _channel(db, "pagerduty", routing_key="RK", min_severity="info")
    _resolved_alert(db)
    result = alerts.evaluate_alerts(db)
    assert result.get("resolution_notified") == 1
