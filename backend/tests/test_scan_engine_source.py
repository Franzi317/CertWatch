from app import scan_engine
from app.models import Certificate


def _fields(fp="AA:BB:CC"):
    return {
        "fingerprint_sha256": fp, "common_name": "h.example.com", "subject": "",
        "sans": [], "issuer": "CN=CA", "issuer_cn": "CA", "serial_number": "1",
        "signature_algorithm": "sha256WithRSAEncryption", "public_key_algorithm": "RSA",
        "public_key_size": 2048, "not_before": None, "not_after": None,
        "self_signed": False, "is_wildcard": False, "is_ca": False,
        "chain_length": 1, "pem": "",
    }


def test_upsert_defaults_to_network(db):
    c = scan_engine._upsert_certificate(db, _fields())
    assert c.source == "network"


def test_upsert_accepts_ct_source(db):
    c = scan_engine._upsert_certificate(db, _fields("DD:EE"), source="ct")
    assert c.source == "ct"


def test_upsert_existing_keeps_original_source(db):
    scan_engine._upsert_certificate(db, _fields("FF:00"), source="ct")
    # a later network scan of the same fingerprint must NOT flip source to network
    again = scan_engine._upsert_certificate(db, _fields("FF:00"), source="network")
    assert again.source == "ct"
