import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.crypto_keys import build_csr, generate_private_key
from app.models import Issuer


def test_generate_rsa_key_default_size():
    result = generate_private_key("rsa", 2048)
    key = serialization.load_pem_private_key(result.key_pem.encode(), password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048
    assert result.key.key_size == 2048


@pytest.mark.parametrize("size", [2048, 3072, 4096])
def test_generate_rsa_key_valid_sizes(size):
    result = generate_private_key("rsa", size)
    key = serialization.load_pem_private_key(result.key_pem.encode(), password=None)
    assert key.key_size == size


def test_generate_rsa_key_invalid_size_rejected():
    with pytest.raises(ValueError):
        generate_private_key("rsa", 1024)


def test_generate_ecdsa_key_256():
    result = generate_private_key("ecdsa", 256)
    key = serialization.load_pem_private_key(result.key_pem.encode(), password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP256R1)


def test_generate_ecdsa_key_384():
    result = generate_private_key("ecdsa", 384)
    key = serialization.load_pem_private_key(result.key_pem.encode(), password=None)
    assert isinstance(key.curve, ec.SECP384R1)


def test_generate_key_invalid_algorithm_rejected():
    with pytest.raises(ValueError):
        generate_private_key("dsa", 2048)


def test_build_csr_subject_and_sans():
    result = generate_private_key("rsa", 2048)
    sans = ["www.example.com", "api.example.com"]
    csr_pem = build_csr(result.key_pem, "www.example.com", sans)
    csr = x509.load_pem_x509_csr(csr_pem.encode())

    assert csr.is_signature_valid
    cn = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn == "www.example.com"

    san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = set(san_ext.value.get_values_for_type(x509.DNSName))
    assert dns_names == set(sans)


def test_build_csr_empty_sans_still_includes_cn_as_san():
    result = generate_private_key("rsa", 2048)
    csr_pem = build_csr(result.key_pem, "solo.example.com", [])
    csr = x509.load_pem_x509_csr(csr_pem.encode())

    assert csr.is_signature_valid
    san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = set(san_ext.value.get_values_for_type(x509.DNSName))
    assert dns_names == {"solo.example.com"}


def test_build_csr_with_ecdsa_key():
    result = generate_private_key("ecdsa", 256)
    csr_pem = build_csr(result.key_pem, "ec.example.com", ["ec.example.com"])
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    assert csr.is_signature_valid


def test_issuer_model_persists_with_defaults(db):
    issuer = Issuer(name="test-adcs", issuer_type="adcs", config={"server": "ca01"})
    db.add(issuer)
    db.commit()
    db.refresh(issuer)

    assert issuer.id is not None
    assert issuer.enabled is True
    assert issuer.last_test_ok is False
    assert issuer.last_test_at is None
    assert issuer.created_at is not None
    assert issuer.config == {"server": "ca01"}
