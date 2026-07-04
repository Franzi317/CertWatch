"""Tests for the AD CS (certsrv web enrollment) issuer adapter.

All HTTP is monkeypatched at the `_http_get`/`_http_post` seam -- these tests
must never hit the network. Serial parsing is exercised against a real
self-signed test certificate built with `cryptography`.
"""
from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.issuers.adcs import ADCSAdapter
from app.issuers.base import IssuerError, get_adapter
from app.models import Issuer


def _make_test_cert_pem() -> tuple[str, str]:
    """Build a self-signed cert and return (pem, hex_serial)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "issued.example.com")])
    serial = x509.random_serial_number()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    from cryptography.hazmat.primitives import serialization

    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return pem, format(serial, "x")


def _adcs_issuer(**config_overrides) -> Issuer:
    config = {
        "server_url": "https://ca.corp.local",
        "ca_config": "corp-CA\\ca01.corp.local",
        "template": "WebServer",
        "username": "svc-certwatch",
        "password": "hunter2",
    }
    config.update(config_overrides)
    return Issuer(name="test-adcs", issuer_type="adcs", config=config)


def test_get_adapter_returns_adcs_adapter():
    adapter = get_adapter(_adcs_issuer())
    assert isinstance(adapter, ADCSAdapter)


def test_issue_returns_issued_cert_with_parsed_serial(monkeypatch):
    cert_pem, hex_serial = _make_test_cert_pem()
    adapter = ADCSAdapter(_adcs_issuer())

    monkeypatch.setattr(
        adapter,
        "_http_post",
        lambda url, data: (200, "<html>...certnew.cer?ReqID=42&Enc=b64...</html>"),
    )
    monkeypatch.setattr(adapter, "_http_get", lambda url: (200, cert_pem))

    result = adapter.issue("-----BEGIN CERTIFICATE REQUEST-----\nMII...\n-----END CERTIFICATE REQUEST-----\n", {})

    assert result.certificate_pem == cert_pem
    assert result.serial == hex_serial
    assert result.chain_pem == ""


def test_issue_raises_on_pending_or_denied_request(monkeypatch):
    adapter = ADCSAdapter(_adcs_issuer())

    monkeypatch.setattr(
        adapter,
        "_http_post",
        lambda url, data: (200, "<html>Certificate Pending: Taken Under Submission</html>"),
    )
    monkeypatch.setattr(adapter, "_http_get", lambda url: (200, ""))

    with pytest.raises(IssuerError):
        adapter.issue("-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n", {})


def test_test_connection_raises_on_auth_failure(monkeypatch):
    adapter = ADCSAdapter(_adcs_issuer())
    monkeypatch.setattr(adapter, "_http_get", lambda url: (401, ""))

    with pytest.raises(IssuerError):
        adapter.test_connection()


def test_test_connection_ok(monkeypatch):
    adapter = ADCSAdapter(_adcs_issuer())
    monkeypatch.setattr(adapter, "_http_get", lambda url: (200, "certsrv"))

    adapter.test_connection()  # should not raise


def test_revoke_not_supported():
    adapter = ADCSAdapter(_adcs_issuer())
    with pytest.raises(IssuerError):
        adapter.revoke("abc123", "keyCompromise")
