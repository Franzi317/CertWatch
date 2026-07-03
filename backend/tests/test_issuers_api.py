"""Tests for the issuer management API (Phase 1, Task 5).

Mirrors test_rbac.py / the channel tests: `login_as` establishes a real
session via the OIDC callback seam, then role gates + the secret-scrubbing
and encrypt-on-write/decrypt-on-read behavior are asserted against the live
FastAPI app + a temp SQLite DB (see conftest.py).
"""
from __future__ import annotations

from conftest import login_as

from app import secrets as secrets_mod
from app.issuers.base import IssuerError

ADCS_ISSUER = {
    "name": "corp-ca",
    "issuer_type": "adcs",
    "enabled": True,
    "config": {
        "server_url": "https://ca.corp.local",
        "ca_config": "corp-CA\\ca01.corp.local",
        "template": "WebServer",
        "username": "svc-certwatch",
        "password": "hunter2",
    },
}


def test_admin_creates_adcs_issuer_password_not_echoed(client, monkeypatch, db):
    login_as(client, "admin", monkeypatch)

    r = client.post("/api/issuers", json=ADCS_ISSUER)
    assert r.status_code == 201, r.text
    body = r.json()

    # Password never comes back in cleartext (or at all) -- only a marker.
    assert "password" not in body["config"]
    assert body["config"]["password_set"] is True
    assert "username" not in body["config"]
    assert body["config"]["username_set"] is True

    from app.models import Issuer

    row = db.get(Issuer, body["id"])
    assert row is not None
    assert secrets_mod.is_encrypted(row.config["password"])


def test_viewer_can_list_but_not_create(client, monkeypatch):
    login_as(client, "viewer", monkeypatch)

    r = client.get("/api/issuers")
    assert r.status_code == 200

    r = client.post("/api/issuers", json=ADCS_ISSUER)
    assert r.status_code == 403


def test_operator_cannot_create(client, monkeypatch):
    login_as(client, "operator", monkeypatch)

    r = client.post("/api/issuers", json=ADCS_ISSUER)
    assert r.status_code == 403


def test_operator_cannot_delete(client, monkeypatch):
    login_as(client, "admin", monkeypatch)
    r = client.post("/api/issuers", json=ADCS_ISSUER)
    issuer_id = r.json()["id"]

    login_as(client, "operator", monkeypatch)
    r = client.delete(f"/api/issuers/{issuer_id}")
    assert r.status_code == 403


def test_admin_can_delete(client, monkeypatch):
    login_as(client, "admin", monkeypatch)
    r = client.post("/api/issuers", json=ADCS_ISSUER)
    issuer_id = r.json()["id"]

    r = client.delete(f"/api/issuers/{issuer_id}")
    assert r.status_code == 204


def test_operator_can_test_connection_success(client, monkeypatch):
    login_as(client, "admin", monkeypatch)
    r = client.post("/api/issuers", json=ADCS_ISSUER)
    issuer_id = r.json()["id"]

    class _FakeAdapter:
        def test_connection(self):
            return None

    monkeypatch.setattr("app.main.get_adapter", lambda issuer: _FakeAdapter())

    login_as(client, "operator", monkeypatch)
    r = client.post(f"/api/issuers/{issuer_id}/test")
    assert r.status_code == 200
    assert r.json()["ok"] is True

    from app.db import SessionLocal
    from app.models import Issuer

    s = SessionLocal()
    try:
        row = s.get(Issuer, issuer_id)
        assert row.last_test_ok is True
        assert row.last_test_at is not None
    finally:
        s.close()


def test_test_connection_issuer_error_returns_clean_200(client, monkeypatch):
    login_as(client, "admin", monkeypatch)
    r = client.post("/api/issuers", json=ADCS_ISSUER)
    issuer_id = r.json()["id"]

    class _FailingAdapter:
        def test_connection(self):
            raise IssuerError("bad credentials")

    monkeypatch.setattr("app.main.get_adapter", lambda issuer: _FailingAdapter())

    login_as(client, "operator", monkeypatch)
    r = client.post(f"/api/issuers/{issuer_id}/test")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert "bad credentials" in body["detail"]

    from app.db import SessionLocal
    from app.models import Issuer

    s = SessionLocal()
    try:
        row = s.get(Issuer, issuer_id)
        assert row.last_test_ok is False
    finally:
        s.close()


def test_viewer_cannot_test_connection(client, monkeypatch):
    login_as(client, "admin", monkeypatch)
    r = client.post("/api/issuers", json=ADCS_ISSUER)
    issuer_id = r.json()["id"]

    login_as(client, "viewer", monkeypatch)
    r = client.post(f"/api/issuers/{issuer_id}/test")
    assert r.status_code == 403


def test_put_with_blank_password_keeps_existing_encrypted_secret(client, monkeypatch, db):
    login_as(client, "admin", monkeypatch)
    r = client.post("/api/issuers", json=ADCS_ISSUER)
    issuer_id = r.json()["id"]

    from app.models import Issuer

    original_encrypted_password = db.get(Issuer, issuer_id).config["password"]

    update_body = dict(ADCS_ISSUER)
    update_body["config"] = dict(ADCS_ISSUER["config"])
    update_body["config"]["password"] = ""  # blank -- must not wipe the secret
    update_body["config"]["template"] = "WebServerV2"

    r = client.put(f"/api/issuers/{issuer_id}", json=update_body)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "password" not in body["config"]
    assert body["config"]["password_set"] is True
    assert body["config"]["template"] == "WebServerV2"

    row = db.get(Issuer, issuer_id)
    db.refresh(row)
    assert row.config["password"] == original_encrypted_password


def test_acme_issuer_account_key_never_returned(client, monkeypatch, db):
    login_as(client, "admin", monkeypatch)
    acme_issuer = {
        "name": "letsencrypt-staging",
        "issuer_type": "acme",
        "enabled": True,
        "config": {
            "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
            "contact_email": "certs@example.com",
            "account_key_pem": "-----BEGIN PRIVATE KEY-----\nfakekey\n-----END PRIVATE KEY-----\n",
        },
    }
    r = client.post("/api/issuers", json=acme_issuer)
    assert r.status_code == 201, r.text
    body = r.json()
    assert "account_key_pem" not in body["config"]
    assert body["config"]["account_key_pem_set"] is True
    assert body["config"]["contact_email"] == "certs@example.com"

    from app.models import Issuer

    row = db.get(Issuer, body["id"])
    assert secrets_mod.is_encrypted(row.config["account_key_pem"])


def test_no_credentials_401(client):
    r = client.get("/api/issuers")
    assert r.status_code == 401
