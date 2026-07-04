"""Tests for the ACME HTTP-01 issuer adapter and its public challenge route.

All ACME protocol interaction is monkeypatched at the `_get_directory` /
`_new_order` / `_get_http01_challenges` / `_answer_challenges` /
`_poll_and_finalize` seams -- these tests must never hit the network or
import the real `acme` library machinery.
"""
from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.db import SessionLocal
from app.issuers.acme_http01 import AcmeHttp01Adapter
from app.issuers.base import IssuerError, get_adapter
from app.models import AcmeChallenge, Issuer


def _make_fullchain_pem() -> tuple[str, str, str, str]:
    """Build a leaf cert issued by a self-signed intermediate; return
    (fullchain_pem, leaf_pem, intermediate_pem, leaf_hex_serial)."""
    now = datetime.datetime.now(datetime.timezone.utc)

    int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    int_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA")])
    intermediate = (
        x509.CertificateBuilder()
        .subject_name(int_name)
        .issuer_name(int_name)
        .public_key(int_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(int_key, hashes.SHA256())
    )
    intermediate_pem = intermediate.public_bytes(serialization.Encoding.PEM).decode()

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_serial = x509.random_serial_number()
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "issued.example.com")]))
        .issuer_name(int_name)
        .public_key(leaf_key.public_key())
        .serial_number(leaf_serial)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=90))
        .sign(int_key, hashes.SHA256())
    )
    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()

    fullchain_pem = leaf_pem + intermediate_pem
    return fullchain_pem, leaf_pem, intermediate_pem, format(leaf_serial, "x")


def _acme_issuer(**config_overrides) -> Issuer:
    config = {
        "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
        "contact_email": "ops@example.com",
    }
    config.update(config_overrides)
    return Issuer(name="test-acme", issuer_type="acme", config=config)


def test_get_adapter_returns_acme_adapter():
    adapter = get_adapter(_acme_issuer())
    assert isinstance(adapter, AcmeHttp01Adapter)


def test_test_connection_raises_on_directory_failure(monkeypatch):
    adapter = AcmeHttp01Adapter(_acme_issuer())

    def boom():
        raise RuntimeError("network unreachable")

    monkeypatch.setattr(adapter, "_get_directory", boom)

    with pytest.raises(IssuerError):
        adapter.test_connection()


def test_test_connection_ok(monkeypatch):
    adapter = AcmeHttp01Adapter(_acme_issuer())
    monkeypatch.setattr(adapter, "_get_directory", lambda: {"newOrder": "https://example/new-order"})

    adapter.test_connection()  # should not raise


def test_issue_stores_challenge_before_answering_and_returns_issued_cert(db, monkeypatch):
    fullchain_pem, leaf_pem, intermediate_pem, hex_serial = _make_fullchain_pem()
    adapter = AcmeHttp01Adapter(_acme_issuer())

    monkeypatch.setattr(adapter, "_new_order", lambda csr_pem: object())
    monkeypatch.setattr(
        adapter,
        "_get_http01_challenges",
        lambda order: [("tok123", "tok123.thumbprint", "issued.example.com")],
    )

    seen = {}

    def fake_answer_challenges(order):
        # The AcmeChallenge row must exist (so the public responder could
        # serve it) BEFORE challenges are answered.
        session = SessionLocal()
        try:
            row = session.get(AcmeChallenge, "tok123")
            seen["key_authorization_at_answer_time"] = row.key_authorization if row else None
        finally:
            session.close()

    monkeypatch.setattr(adapter, "_answer_challenges", fake_answer_challenges)
    monkeypatch.setattr(adapter, "_poll_and_finalize", lambda order, csr_pem: fullchain_pem)

    result = adapter.issue(
        "-----BEGIN CERTIFICATE REQUEST-----\nMII...\n-----END CERTIFICATE REQUEST-----\n", {}
    )

    assert seen["key_authorization_at_answer_time"] == "tok123.thumbprint"
    assert result.certificate_pem.strip() == leaf_pem.strip()
    assert intermediate_pem.strip() in result.chain_pem
    assert result.serial == hex_serial

    # Cleaned up (best-effort) after finalize.
    session = SessionLocal()
    try:
        assert session.get(AcmeChallenge, "tok123") is None
    finally:
        session.close()


def test_challenge_route_returns_key_authorization(client):
    session = SessionLocal()
    try:
        session.add(AcmeChallenge(token="abc", key_authorization="abc.xyz"))
        session.commit()
    finally:
        session.close()

    resp = client.get("/.well-known/acme-challenge/abc")

    assert resp.status_code == 200
    assert resp.text == "abc.xyz"
    assert resp.headers["content-type"].startswith("text/plain")


def test_challenge_route_404_for_unknown_token(client):
    resp = client.get("/.well-known/acme-challenge/does-not-exist")
    assert resp.status_code == 404
