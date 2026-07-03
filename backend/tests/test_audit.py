"""Tests for actor-attributed audit log + admin audit API (Phase 0, Task 6)."""
from conftest import login_as

TARGET = {"name": "Audit box", "target_type": "ip", "value": "10.0.0.42", "ports": [443]}


def test_audit_records_actor_and_admin_can_list(client, monkeypatch):
    operator = login_as(client, "operator", monkeypatch)

    r = client.post("/api/targets", json=TARGET)
    assert r.status_code == 201

    # A fresh client-side session switch: log in as admin on the same client.
    login_as(client, "admin", monkeypatch)

    r = client.get("/api/audit")
    assert r.status_code == 200
    body = r.json()
    assert "total" in body and "items" in body
    rows = [row for row in body["items"] if row["action"] == "target.create"]
    assert rows, f"expected a target.create row, got {body['items']}"
    assert rows[0]["actor"] == operator["email"]


def test_audit_viewer_403(client, monkeypatch):
    login_as(client, "viewer", monkeypatch)
    r = client.get("/api/audit")
    assert r.status_code == 403


def test_audit_unauthenticated_401(client):
    r = client.get("/api/audit")
    assert r.status_code == 401
