from app import alerts
from app.models import AlertEvent, Certificate, NotificationChannel, utcnow


def _cert(db):
    c = Certificate(fingerprint_sha256="FP:1", common_name="h.example.com", source="network")
    db.add(c); db.flush()
    return c


def _alert(db, severity="warning", rule="expiring"):
    c = _cert(db)
    ev = AlertEvent(dedupe_key=f"{rule}:1:{c.id}:30", certificate_id=c.id, rule_type=rule,
                    severity=severity, message="cert expiring", resolved=False)
    db.add(ev); db.commit()
    return ev


def _channel(db, ctype, **config):
    ch = NotificationChannel(name=f"{ctype}-ch", channel_type=ctype, enabled=True, config=config)
    db.add(ch); db.commit()
    return ch


def test_pagerduty_trigger_dispatched(db, monkeypatch):
    calls = []
    monkeypatch.setattr(alerts, "send_pagerduty",
                        lambda cfg, action, key, **kw: calls.append((action, key)))
    _channel(db, "pagerduty", routing_key="RK", min_severity="warning")
    ev = _alert(db, severity="warning")
    alerts.dispatch_alerts(db)
    assert calls == [("trigger", ev.dedupe_key)]


def test_pagerduty_critical_only_skips_warning(db, monkeypatch):
    calls = []
    monkeypatch.setattr(alerts, "send_pagerduty", lambda *a, **k: calls.append(1))
    _channel(db, "pagerduty", routing_key="RK", min_severity="critical")
    _alert(db, severity="warning")
    alerts.dispatch_alerts(db)
    assert calls == []  # warning below critical floor -> skipped


def test_slack_routed_through_webhook(db, monkeypatch):
    calls = []
    monkeypatch.setattr(alerts, "send_webhook",
                        lambda cfg, title, text, facts=None, link="", color="": calls.append(color))
    _channel(db, "slack", url="https://hooks.slack/x", format="slack")
    _alert(db, severity="critical")
    alerts.dispatch_alerts(db)
    assert len(calls) == 1 and calls[0]  # color passed (non-empty)
