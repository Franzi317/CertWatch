"""Tests for POST /api/admin/restore-check (Phase 2, Task 6: backup/restore/DR).

Verifies a running instance after a restore: Alembic schema state, row counts
for key tables, and a decrypt-ability probe that proves the current
CERTWATCH_MASTER_KEY matches encrypted data -- without ever exposing any
secret plaintext (or ciphertext) in the response.
"""
import json

from conftest import login_as


def test_restore_check_admin_ok(client, monkeypatch):
    login_as(client, "admin", monkeypatch)

    # Seed a channel with an encrypted secret so the decrypt probe has real
    # data to exercise, not just the self round-trip.
    plaintext_password = "s3cret-restore-probe"
    r = client.post("/api/channels", json={
        "name": "hook", "channel_type": "webhook",
        "config": {"url": "https://hooks.example.com/x", "password": plaintext_password,
                   "recipients": ["a@b.c"]},
    })
    assert r.status_code == 201

    r = client.post("/api/admin/restore-check")
    assert r.status_code == 200
    body = r.json()

    assert body["schema_ok"] is True
    assert "revision" in body          # may be null (pre-stamp / create_all in tests)
    assert "head" in body
    counts = body["counts"]
    for key in ("certificates", "endpoints", "managed_certificates", "findings"):
        assert key in counts
    assert body["secret_decrypt_ok"] is True

    # No plaintext (or ciphertext) secret material anywhere in the response.
    raw = json.dumps(body)
    assert plaintext_password not in raw
    assert "enc:v1:" not in raw


def test_restore_check_viewer_403(client, monkeypatch):
    login_as(client, "viewer", monkeypatch)
    r = client.post("/api/admin/restore-check")
    assert r.status_code == 403
