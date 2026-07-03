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


# --------------------------------------------------------------------------- #
# Break-glass local admin (POST /api/auth/local)
#
# `local_login` reads `settings.admin_email` / `settings.admin_password_hash`
# off the module-level `auth.settings` singleton (imported from app.config at
# import time), NOT a freshly constructed Settings(). monkeypatch.setenv alone
# would be invisible to it, so these tests monkeypatch the singleton's
# attributes directly via `auth.settings` (same object as `config.settings`).
# `auth._reset_cache()` is also called for parity with the group-mapping
# tests above, though it only affects the unrelated group-role cache.
# --------------------------------------------------------------------------- #
import bcrypt  # noqa: E402


def test_local_login_correct_password_grants_admin_session(client, monkeypatch):
    from app import auth

    admin_email = "admin@corp.com"
    password_hash = bcrypt.hashpw(b"correct-password", bcrypt.gensalt()).decode()
    monkeypatch.setattr(auth.settings, "admin_email", admin_email)
    monkeypatch.setattr(auth.settings, "admin_password_hash", password_hash)
    auth._reset_cache()

    r = client.post("/api/auth/local", json={"email": admin_email, "password": "correct-password"})
    assert r.status_code == 200

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["role"] == "admin"


def test_local_login_wrong_password_rejected_no_session(client, monkeypatch):
    from app import auth

    admin_email = "admin@corp.com"
    password_hash = bcrypt.hashpw(b"correct-password", bcrypt.gensalt()).decode()
    monkeypatch.setattr(auth.settings, "admin_email", admin_email)
    monkeypatch.setattr(auth.settings, "admin_password_hash", password_hash)
    auth._reset_cache()

    r = client.post("/api/auth/local", json={"email": admin_email, "password": "wrong-password"})
    assert r.status_code == 401

    assert client.get("/api/auth/me").status_code == 401


def test_local_login_unconfigured_hash_fails_closed(client, monkeypatch):
    from app import auth

    admin_email = "admin@corp.com"
    monkeypatch.setattr(auth.settings, "admin_email", admin_email)
    monkeypatch.setattr(auth.settings, "admin_password_hash", "")
    auth._reset_cache()

    r = client.post("/api/auth/local", json={"email": admin_email, "password": "anything-at-all"})
    assert r.status_code == 401

    assert client.get("/api/auth/me").status_code == 401


# --------------------------------------------------------------------------- #
# Disabled-user refusal in the OIDC callback
# --------------------------------------------------------------------------- #
def test_callback_refuses_disabled_user_no_session(client, monkeypatch):
    from app import auth
    from app.db import SessionLocal
    from app.models import User

    email = "disabled@corp.com"
    session = SessionLocal()
    try:
        session.add(User(email=email, disabled=True, role="viewer", source="entra"))
        session.commit()
    finally:
        session.close()

    monkeypatch.setattr(auth, "_fetch_token", lambda req: {
        "email": email, "name": "Disabled Person", "oid": "y", "groups": []})
    r = client.get("/api/auth/callback?code=abc&state=xyz")
    assert r.status_code == 403

    assert client.get("/api/auth/me").status_code == 401


# --------------------------------------------------------------------------- #
# Least-privilege group mapping edges
# --------------------------------------------------------------------------- #
def test_map_groups_to_role_empty_list_is_viewer():
    from app import auth
    assert auth.map_groups_to_role([]) == "viewer"


def test_callback_missing_groups_key_defaults_to_viewer(client, monkeypatch):
    monkeypatch.setenv("CERTWATCH_ENTRA_ADMIN_GROUP", "g-admin")
    from app import auth
    auth._reset_cache()
    monkeypatch.setattr(auth, "_fetch_token", lambda req: {
        "email": "nogroups@corp.com", "name": "No Groups", "oid": "z"})
    r = client.get("/api/auth/callback?code=abc&state=xyz")
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["role"] == "viewer"
