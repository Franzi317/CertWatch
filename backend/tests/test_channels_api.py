def test_pagerduty_routing_key_scrubbed(client, monkeypatch):
    from tests.conftest import login_as
    login_as(client, "admin", monkeypatch)
    r = client.post("/api/channels", json={
        "name": "pd", "channel_type": "pagerduty", "enabled": True, "re_alert_hours": 24,
        "config": {"routing_key": "SECRET-RK", "min_severity": "critical"},
    })
    assert r.status_code == 201, r.text
    body = r.json()
    assert "routing_key" not in body["config_summary"]  # scrubbed
    assert body["config_summary"]["min_severity"] == "critical"  # non-secret kept
    # and it round-trips out of the list without the secret
    lst = client.get("/api/channels").json()
    assert all("routing_key" not in c["config_summary"] for c in lst)


def test_pagerduty_default_min_severity_critical(client, monkeypatch):
    from tests.conftest import login_as
    login_as(client, "operator", monkeypatch)
    r = client.post("/api/channels", json={
        "name": "pd-default", "channel_type": "pagerduty", "enabled": True, "re_alert_hours": 24,
        "config": {"routing_key": "RK"},  # no min_severity supplied
    })
    assert r.status_code == 201, r.text
    assert r.json()["config_summary"]["min_severity"] == "critical"


def test_test_channel_pagerduty(client, monkeypatch):
    from tests.conftest import login_as
    from app import main as app_main
    login_as(client, "operator", monkeypatch)
    calls = []
    monkeypatch.setattr(app_main, "send_pagerduty",
                        lambda cfg, action, key, **kw: calls.append(action))
    r = client.post("/api/channels", json={
        "name": "pd", "channel_type": "pagerduty", "enabled": True, "re_alert_hours": 24,
        "config": {"routing_key": "RK"},
    })
    cid = r.json()["id"]
    r = client.post(f"/api/channels/{cid}/test")
    assert r.status_code == 200, r.text
    # test sends a trigger then a resolve so it leaves no dangling incident
    assert calls == ["trigger", "resolve"]
