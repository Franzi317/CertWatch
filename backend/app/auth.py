"""Entra ID OIDC login flow, signed-cookie sessions, and break-glass local admin.

Phase 0, Task 4. The ONLY function in this module that ever talks to Microsoft
is `_fetch_token(request)`. Everything else — group-to-role mapping, user
provisioning, session shape — is pure/DB logic operating on a plain claims
dict, so tests monkeypatch `_fetch_token` to return canned claims and never
touch the network.
"""
from __future__ import annotations

import bcrypt
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import User, utcnow

router = APIRouter(prefix="/api/auth", tags=["auth"])


# --------------------------------------------------------------------------- #
# Group -> role mapping
# --------------------------------------------------------------------------- #
# Cached like app.secrets._fernet: constructing a fresh Settings() re-reads
# env vars, but we only want to pay that cost once per process. Tests call
# _reset_cache() after monkeypatch.setenv() to force a re-read.
_group_role_map: dict[str, list[str]] | None = None


def _load_group_role_map() -> dict[str, list[str]]:
    from .config import Settings

    s = Settings()
    return {
        "admin": [g.strip() for g in s.entra_admin_group.split(",") if g.strip()],
        "operator": [g.strip() for g in s.entra_operator_group.split(",") if g.strip()],
        "viewer": [g.strip() for g in s.entra_viewer_group.split(",") if g.strip()],
    }


def _get_group_role_map() -> dict[str, list[str]]:
    global _group_role_map
    if _group_role_map is None:
        _group_role_map = _load_group_role_map()
    return _group_role_map


def _reset_cache() -> None:
    """Force the next map_groups_to_role() call to re-read env. Test-only."""
    global _group_role_map
    _group_role_map = None


def map_groups_to_role(group_oids: list[str]) -> str:
    """Highest configured role whose group set intersects group_oids, else viewer."""
    group_role_map = _get_group_role_map()
    oids = set(group_oids or [])
    for role in ("admin", "operator", "viewer"):  # highest rank first
        if oids & set(group_role_map[role]):
            return role
    return "viewer"


# --------------------------------------------------------------------------- #
# Entra OAuth client. Registration only stores config — Authlib doesn't fetch
# the discovery document until authorize_redirect()/authorize_access_token()
# actually runs, so importing this module never reaches the network.
# --------------------------------------------------------------------------- #
_oauth = OAuth()
_oauth.register(
    name="entra",
    server_metadata_url=(
        f"https://login.microsoftonline.com/{settings.entra_tenant_id}/v2.0/"
        ".well-known/openid-configuration"
    ),
    client_id=settings.entra_client_id,
    client_secret=settings.entra_client_secret,
    client_kwargs={"scope": "openid profile email"},
)


def _fetch_token(request: Request) -> dict:
    """Exchange the callback `code` for tokens and return the IdP claims dict.

    The only network-touching function in this module. Tests monkeypatch this
    to return canned claims (email/name/oid/groups) instead of calling Entra.
    """
    token = _oauth.entra.authorize_access_token(request)  # pragma: no cover
    return token.get("userinfo") or {}


# --------------------------------------------------------------------------- #
# Session helpers
# --------------------------------------------------------------------------- #
def current_user(request: Request) -> dict | None:
    """Return {"id","email","role"} from the session, or None if unauthenticated."""
    user = request.session.get("user")
    return user or None


def _require_user(request: Request) -> dict:
    user = current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    return user


def _upsert_user(db: Session, email: str) -> User:
    """Fetch-or-create a User by email. Raises 403 if the existing row is disabled."""
    user = db.scalar(select(User).where(User.email == email))
    if user is not None and user.disabled:
        raise HTTPException(status_code=403, detail="account disabled")
    if user is None:
        user = User(email=email)
        db.add(user)
    return user


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@router.get("/login")
def login(request: Request):  # pragma: no cover - real IdP path, not exercised in tests
    redirect_uri = settings.entra_redirect_uri or str(request.url_for("callback"))
    return _oauth.entra.authorize_redirect(request, redirect_uri)


@router.get("/callback", name="callback")
def callback(request: Request, db: Session = Depends(get_db)):
    claims = _fetch_token(request)
    email = claims.get("email") or claims.get("preferred_username") or ""
    if not email:
        raise HTTPException(status_code=400, detail="IdP response missing email")

    user = _upsert_user(db, email)
    user.display_name = claims.get("name") or user.display_name
    user.role = map_groups_to_role(claims.get("groups") or [])
    user.source = "entra"
    user.last_login_at = utcnow()
    db.commit()
    db.refresh(user)

    session_user = {"id": user.id, "email": user.email, "role": user.role}
    request.session["user"] = session_user
    return session_user


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return {"status": "ok"}


@router.get("/me")
def me(request: Request):
    return _require_user(request)


# ponytail: /api/auth/local is a break-glass path to bootstrap the first admin
# before Entra groups are configured. No rate limiting today — add a real
# limiter (e.g. slowapi) only if this endpoint is ever exposed to the internet
# rather than an internal admin network.
@router.post("/local")
async def local_login(request: Request, db: Session = Depends(get_db)):
    if "application/json" in request.headers.get("content-type", ""):
        body = await request.json()
    else:
        body = await request.form()
    email = (body.get("email") or "").strip()
    password = body.get("password") or ""

    if not settings.admin_email or not settings.admin_password_hash:
        raise HTTPException(status_code=401, detail="local admin not configured")
    # bcrypt.checkpw is constant-time; never compare passwords with `==`.
    if email != settings.admin_email or not bcrypt.checkpw(
        password.encode(), settings.admin_password_hash.encode()
    ):
        raise HTTPException(status_code=401, detail="invalid credentials")

    user = _upsert_user(db, email)
    user.role = "admin"
    user.source = "local"
    user.last_login_at = utcnow()
    db.commit()
    db.refresh(user)

    session_user = {"id": user.id, "email": user.email, "role": user.role}
    request.session["user"] = session_user
    return session_user
