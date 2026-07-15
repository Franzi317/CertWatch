import json

import pytest

from app import notify
from app.notify import NotifyError


class _FakeResp:
    status = 202
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _capture(monkeypatch):
    calls = []
    def fake_urlopen(req, timeout=15):
        calls.append({"url": req.full_url, "headers": dict(req.header_items()),
                      "body": json.loads(req.data.decode())})
        return _FakeResp()
    monkeypatch.setattr(notify.urllib.request, "urlopen", fake_urlopen)
    return calls


def test_pagerduty_trigger_payload(monkeypatch):
    calls = _capture(monkeypatch)
    # routing_key is stored encrypted; notify.decrypt is applied. Use a plaintext
    # value and monkeypatch decrypt to identity so the test needs no master key.
    monkeypatch.setattr(notify, "decrypt", lambda v: v)
    notify.send_pagerduty({"routing_key": "RK123"}, "trigger", "expiring:1:2:30",
                          summary="cert expiring", severity="warning",
                          facts={"Owner/team": "web"}, link="http://x/certificates/2")
    assert len(calls) == 1
    body = calls[0]["body"]
    assert calls[0]["url"] == "https://events.pagerduty.com/v2/enqueue"
    assert body["routing_key"] == "RK123"
    assert body["event_action"] == "trigger"
    assert body["dedup_key"] == "expiring:1:2:30"
    assert body["payload"]["severity"] == "warning"
    assert body["payload"]["source"] == "certwatch"


def test_pagerduty_resolve_minimal(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(notify, "decrypt", lambda v: v)
    notify.send_pagerduty({"routing_key": "RK"}, "resolve", "expiring:1:2:30")
    body = calls[0]["body"]
    assert body["event_action"] == "resolve"
    assert body["dedup_key"] == "expiring:1:2:30"
    assert "payload" not in body  # resolve needs only routing_key + dedup_key


def test_pagerduty_custom_events_url(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(notify, "decrypt", lambda v: v)
    notify.send_pagerduty({"routing_key": "RK", "events_url": "https://events.eu.pagerduty.com/v2/enqueue"},
                          "trigger", "k", summary="s")
    assert calls[0]["url"] == "https://events.eu.pagerduty.com/v2/enqueue"


def test_pagerduty_missing_routing_key_raises(monkeypatch):
    monkeypatch.setattr(notify, "decrypt", lambda v: v)
    with pytest.raises(NotifyError):
        notify.send_pagerduty({}, "trigger", "k", summary="s")


def test_slack_webhook_payload(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(notify, "decrypt", lambda v: v)
    notify.send_webhook({"url": "https://hooks.slack.com/x", "format": "slack"},
                        "Cert expiring", "body text", {"Owner/team": "web"},
                        "http://x/certificates/2", color="F59E0B")
    body = calls[0]["body"]
    assert "attachments" in body
    att = body["attachments"][0]
    assert att["color"] == "#F59E0B"
    assert att["title"] == "Cert expiring"
    assert any(f["title"] == "Owner/team" and f["value"] == "web" for f in att["fields"])


def test_teams_webhook_color_override(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(notify, "decrypt", lambda v: v)
    notify.send_webhook({"url": "https://teams/x", "format": "teams"},
                        "Resolved", "body", {}, "", color="2EB67D")
    body = calls[0]["body"]
    assert body["themeColor"] == "2EB67D"  # passed color overrides default red
