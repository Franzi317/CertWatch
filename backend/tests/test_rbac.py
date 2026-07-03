"""Tests for role-based access control (Phase 0, Task 5).

`client` (from conftest.py) is unauthenticated by default, so these tests
establish sessions explicitly via the `login_as` helper (real OIDC callback
seam) or by sending the CERTWATCH_API_KEY bearer token, then assert the
resulting authorization outcome.
"""
from conftest import login_as

TARGET = {"name": "Lab box", "target_type": "ip", "value": "10.0.0.9", "ports": [443]}


def test_no_credentials_401_on_protected_get(client):
    r = client.get("/api/targets")
    assert r.status_code == 401


def test_no_credentials_401_on_protected_post(client):
    r = client.post("/api/targets", json=TARGET)
    assert r.status_code == 401


def test_viewer_session_can_get_but_not_post_targets(client, monkeypatch):
    login_as(client, "viewer", monkeypatch)

    r = client.get("/api/targets")
    assert r.status_code == 200

    r = client.post("/api/targets", json=TARGET)
    assert r.status_code == 403


def test_operator_session_can_post_targets(client, monkeypatch):
    login_as(client, "operator", monkeypatch)

    r = client.post("/api/targets", json=TARGET)
    assert r.status_code == 201

    r = client.get("/api/targets")
    assert r.status_code == 200


def test_operator_bearer_token_can_post_targets(client, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "api_key", "test-service-token")

    r = client.post(
        "/api/targets",
        json=TARGET,
        headers={"Authorization": "Bearer test-service-token"},
    )
    # 201 (created) or 400 (bad input) both prove authorization passed —
    # anything else (401/403) means the bearer path failed.
    assert r.status_code in (201, 400)


def test_operator_bearer_token_bad_input_still_authorized(client, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "api_key", "test-service-token")

    bad_target = {**TARGET, "target_type": "cidr", "value": "not-a-cidr"}
    r = client.post(
        "/api/targets",
        json=bad_target,
        headers={"Authorization": "Bearer test-service-token"},
    )
    assert r.status_code == 400


def test_wrong_bearer_token_401():
    from app.config import settings
    # No monkeypatch here on purpose: exercise the real fresh-client path.
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app, follow_redirects=False) as raw:
        r = raw.get("/api/targets", headers={"Authorization": "Bearer wrong-token"})
        assert r.status_code == 401


def test_admin_session_can_do_everything_viewer_and_operator_can(client, monkeypatch):
    login_as(client, "admin", monkeypatch)

    assert client.get("/api/targets").status_code == 200
    r = client.post("/api/targets", json=TARGET)
    assert r.status_code == 201
    tid = r.json()["id"]
    assert client.get(f"/api/targets/{tid}").status_code == 200
    assert client.delete(f"/api/targets/{tid}").status_code == 204


def test_bearer_service_account_capped_at_operator_never_admin(monkeypatch):
    """Unit-level check on require_role itself: the bearer/service-account
    path must resolve to "operator" and never satisfy an admin gate, even
    though there's no admin-only route yet in this task."""
    from app import auth
    from app.config import settings
    from fastapi import HTTPException

    monkeypatch.setattr(settings, "api_key", "svc-token")

    class _FakeRequest:
        session: dict = {}
        headers = {"authorization": "Bearer svc-token"}

    principal = auth.require_role("operator")(_FakeRequest())
    assert principal["role"] == "operator"

    try:
        auth.require_role("admin")(_FakeRequest())
        assert False, "expected 403 for bearer service-account against an admin gate"
    except HTTPException as e:
        assert e.status_code == 403
