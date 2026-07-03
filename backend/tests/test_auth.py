"""Tests for the Entra OIDC login flow (mock IdP), sessions, and break-glass
local admin (Phase 0, Task 4).

Network is never touched: `auth._fetch_token` is the only network-shaped seam
and is monkeypatched in tests to return canned IdP claims.
"""


def test_group_mapping(monkeypatch):
    monkeypatch.setenv("CERTWATCH_ENTRA_ADMIN_GROUP", "g-admin")
    monkeypatch.setenv("CERTWATCH_ENTRA_OPERATOR_GROUP", "g-op1,g-op2")
    from app import auth
    auth._reset_cache()
    assert auth.map_groups_to_role(["g-op2"]) == "operator"
    assert auth.map_groups_to_role(["g-admin", "g-op1"]) == "admin"
    assert auth.map_groups_to_role(["unknown"]) == "viewer"


def test_callback_provisions_user_and_sets_session(client, monkeypatch):
    monkeypatch.setenv("CERTWATCH_ENTRA_ADMIN_GROUP", "g-admin")
    from app import auth
    auth._reset_cache()
    monkeypatch.setattr(auth, "_fetch_token", lambda req: {
        "email": "jane@corp.com", "name": "Jane", "oid": "x", "groups": ["g-admin"]})
    r = client.get("/api/auth/callback?code=abc&state=xyz")
    me = client.get("/api/auth/me")
    assert me.status_code == 200 and me.json()["role"] == "admin"


def test_me_unauthenticated_401(client):
    assert client.get("/api/auth/me").status_code == 401
