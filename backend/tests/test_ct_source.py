import httpx
import pytest

from app import ct_source
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime


def _self_signed_der() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "shadow.example.com")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_list_entries_parses_json():
    def handler(req):
        assert "example.com" in str(req.url)
        return httpx.Response(200, json=[
            {"id": 10, "common_name": "a.example.com"},
            {"id": 11, "common_name": "b.example.com"},
        ])
    entries = ct_source.list_entries("https://crt.sh", "example.com", client=_client(handler))
    assert [e["id"] for e in entries] == [10, 11]


def test_list_entries_blank_url_returns_empty():
    assert ct_source.list_entries("", "example.com") == []


def test_fetch_der_returns_bytes():
    der = _self_signed_der()
    def handler(req):
        assert "d=42" in str(req.url)
        return httpx.Response(200, content=der,
                              headers={"content-type": "application/pkix-cert"})
    out = ct_source.fetch_der("https://crt.sh", 42, client=_client(handler))
    # round-trips through cryptography -> same cert
    assert x509.load_der_x509_certificate(out).subject == x509.load_der_x509_certificate(der).subject
