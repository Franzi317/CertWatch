"""Private key and CSR generation for issuer adapters (AD CS, ACME).

Keys generated here are returned as unencrypted PEM; callers are responsible
for encrypting at rest via `app.secrets` before persisting (wired in a later
task).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

_RSA_SIZES = {2048, 3072, 4096}
_ECDSA_CURVES = {256: ec.SECP256R1, 384: ec.SECP384R1}
_PEM_CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


@dataclass
class PrivateKeyResult:
    key_pem: str
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


def generate_private_key(algorithm: str = "rsa", size: int = 2048) -> PrivateKeyResult:
    """Generate a private key. `algorithm` is "rsa" or "ecdsa".

    For "rsa", `size` is the modulus size in bits (2048/3072/4096).
    For "ecdsa", `size` selects the curve: 256 -> SECP256R1, 384 -> SECP384R1.
    """
    if algorithm == "rsa":
        if size not in _RSA_SIZES:
            raise ValueError(f"unsupported RSA key size: {size} (allowed: {sorted(_RSA_SIZES)})")
        key = rsa.generate_private_key(public_exponent=65537, key_size=size)
    elif algorithm == "ecdsa":
        curve_cls = _ECDSA_CURVES.get(size)
        if curve_cls is None:
            raise ValueError(f"unsupported ECDSA curve size: {size} (allowed: {sorted(_ECDSA_CURVES)})")
        key = ec.generate_private_key(curve_cls())
    else:
        raise ValueError(f"unsupported algorithm: {algorithm!r} (allowed: 'rsa', 'ecdsa')")

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return PrivateKeyResult(key_pem=key_pem, key=key)


def build_csr(key_pem: str, common_name: str, sans: list[str]) -> str:
    """Build a PKCS#10 CSR PEM for `common_name`, signed by the key in `key_pem`.

    The CSR always carries a SubjectAlternativeName extension. If `sans` is
    empty, the common name is still included as a DNS SAN entry -- modern
    clients (and CAs following the CA/Browser Forum baseline requirements)
    increasingly ignore the CN for validation and only trust the SAN list, so
    a CSR without any SAN would produce a certificate that some clients treat
    as having no valid name at all.
    """
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)

    dns_names = list(sans) if sans else [common_name]
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]),
            critical=False,
        )
    )
    csr = builder.sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def build_pkcs12(
    cert_pem: str, chain_pem: str, key_pem: str, password: str, friendly_name: str = ""
) -> bytes:
    """Build a PKCS12 (.pfx) blob containing the leaf cert, its private key,
    and any chain certs as CAs. Shared by `deploy.pfx.PfxConnector` and
    `deploy.jks.JksConnector` (Task 10) -- and by `CertBundle.pfx_bytes`,
    which delegates here so the PKCS12-building logic lives in one place.

    `key_pem` MUST already be decrypted plaintext; this function never logs
    it. `password` encrypts the resulting PKCS12 blob itself (distinct from
    however the caller stored `password` at rest).
    """
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    leaf = x509.load_pem_x509_certificate(cert_pem.encode())
    chain_certs = [
        x509.load_pem_x509_certificate(block.encode())
        for block in _PEM_CERT_RE.findall(chain_pem)
    ]
    encryption = (
        serialization.BestAvailableEncryption(password.encode())
        if password
        else serialization.NoEncryption()
    )
    return pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode() if friendly_name else None,
        key=key,
        cert=leaf,
        cas=chain_certs or None,
        encryption_algorithm=encryption,
    )
