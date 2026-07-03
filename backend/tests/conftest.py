"""Test fixtures: isolated temp SQLite DB, ORM session, and API client.

Env is set before importing app modules so the engine binds to the temp DB.
"""
import os
import tempfile

from cryptography.fernet import Fernet

os.environ["CERTWATCH_ENABLE_SCHEDULER"] = "false"
# TestClient talks to http://testserver (no TLS). httpx's cookie jar honors
# the Secure flag like a real browser, so a Secure session cookie would never
# be sent back on the next request and every "logged in" test would silently
# 401. This only relaxes the *test* environment, not the SessionMiddleware
# wiring itself (which still defaults to https_only=True in main.py).
os.environ.setdefault("CERTWATCH_COOKIE_SECURE", "false")
_fd, _path = tempfile.mkstemp(suffix=".db")
os.close(_fd)
os.environ["CERTWATCH_DATABASE_URL"] = f"sqlite:///{_path}"
# Channel-secret writes (create_channel/update_channel) require a configured
# master key; set one so existing channel tests keep working end to end.
os.environ.setdefault("CERTWATCH_MASTER_KEY", Fernet.generate_key().decode())

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import secrets as _secrets  # noqa: E402
from app.db import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Base  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_secrets_cache():
    # test_secrets.py monkeypatches CERTWATCH_MASTER_KEY and calls
    # app.secrets._reset_cache() mid-test; make sure no test leaves the
    # module-level Fernet cache pointed at a since-reverted env var.
    yield
    _secrets._reset_cache()


@pytest.fixture
def db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    Base.metadata.drop_all(engine)
    # follow_redirects=False: auth.login/callback may redirect to Entra/the
    # frontend; auto-following in tests would make httpx attempt a real
    # network request to those external URLs. The client is a single
    # TestClient/httpx.Client instance per test, so its cookie jar (and thus
    # the signed session cookie) is shared across calls within one test.
    with TestClient(app, follow_redirects=False) as c:  # lifespan creates tables + seeds settings
        yield c


_ROLE_ENV_VARS = {
    "admin": "CERTWATCH_ENTRA_ADMIN_GROUP",
    "operator": "CERTWATCH_ENTRA_OPERATOR_GROUP",
    "viewer": "CERTWATCH_ENTRA_VIEWER_GROUP",
}


def login_as(client, role: str, monkeypatch, email: str | None = None) -> dict:
    """Establish a session on `client` with the given role via the real OIDC
    callback seam (Task 4): map a synthetic Entra group to `role`, monkeypatch
    `auth._fetch_token` to return that group, then hit `/api/auth/callback`.

    Used both by test_rbac.py (to get viewer/operator/admin sessions) and by
    test_api.py (via its `client` fixture override) so the pre-existing API
    tests run against a real authenticated session instead of the old open
    bearer-token guard.
    """
    from app import auth

    email = email or f"{role}@test.local"
    group = f"g-{role}-rbac-test"
    monkeypatch.setenv(_ROLE_ENV_VARS[role], group)
    auth._reset_cache()
    monkeypatch.setattr(auth, "_fetch_token", lambda req: {
        "email": email, "name": role.title(), "oid": role, "groups": [group],
    })
    r = client.get("/api/auth/callback?code=abc&state=xyz")
    assert r.status_code == 200, r.text
    assert r.json()["role"] == role
    return r.json()
