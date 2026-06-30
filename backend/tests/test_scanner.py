import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.scanner import parse_certificate
from app.status import days_until, expiry_phrase, severity


def make_cert(cn="host.example.com", issuer_cn=None, days_valid=20, sans=("host.example.com",)):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(4242)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), False)
    )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def test_certificate_parsing_fields():
    der = make_cert(cn="*.example.com", sans=("*.example.com", "example.com"))
    f = parse_certificate(der)
    assert f["common_name"] == "*.example.com"
    assert "example.com" in f["sans"]
    assert f["is_wildcard"] is True
    assert f["self_signed"] is True
    assert f["public_key_algorithm"] == "RSA"
    assert f["public_key_size"] == 2048
    assert f["signature_algorithm"] == "sha256WithRSAEncryption"


def test_fingerprint_is_deterministic_and_sha256():
    der = make_cert()
    a = parse_certificate(der)["fingerprint_sha256"]
    b = parse_certificate(der)["fingerprint_sha256"]
    assert a == b
    assert len(a) == 95  # 32 bytes -> 64 hex + 31 colons


def test_not_self_signed_when_issuer_differs():
    der = make_cert(cn="leaf.example.com", issuer_cn="Internal CA")
    assert parse_certificate(der)["self_signed"] is False


def test_expiration_calculation():
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    future = datetime.datetime(2026, 1, 31, tzinfo=datetime.timezone.utc)
    assert days_until(future, now) == 30
    past = datetime.datetime(2025, 12, 28, tzinfo=datetime.timezone.utc)
    assert days_until(past, now) == -4
    assert days_until(None) is None


def test_severity_levels():
    assert severity(120) == "healthy"
    assert severity(45) == "info"
    assert severity(20) == "warning"
    assert severity(3) == "critical"
    assert severity(-1) == "critical"
    assert severity(50, scan_ok=False) == "unknown"
    assert severity(None) == "unknown"


def test_expiry_phrase():
    assert expiry_phrase(27) == "Expiring in 27 days"
    assert expiry_phrase(1) == "Expiring in 1 day"
    assert expiry_phrase(0) == "Expires today"
    assert expiry_phrase(-4) == "Expired 4 days ago"
