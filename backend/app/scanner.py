"""TLS certificate capture using the Python stdlib (no shelling out).

We connect with verification fully disabled so that expired, self-signed,
privately-issued, mismatched, and incomplete-chain certificates are still
inventoried — the scanner observes the cert rather than trusting it. This mirrors
the reference Go scanner's `InsecureSkipVerify` probe, ported to `ssl`.

Error codes are a stable taxonomy consumed by the UI:
  ok, connection_failed, timeout, tls_handshake_failed, non_tls_service,
  no_certificate, dns_resolution_failed.
"""
from __future__ import annotations

import hashlib
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID


@dataclass
class ScanResult:
    status: str
    error: str = ""
    sni_used: str = ""
    cert: dict | None = None
    chain_pem: list[str] = field(default_factory=list)


def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def parse_certificate(der: bytes, chain_der: list[bytes] | None = None) -> dict:
    """Extract inventory fields from a leaf certificate (DER bytes).

    Pure given its inputs — unit-tested against a generated cert.
    """
    cert = x509.load_der_x509_certificate(der)
    chain_der = chain_der or []

    def _name(name: x509.Name) -> str:
        return name.rfc4514_string()

    def _cn(name: x509.Name) -> str:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""

    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = ext.value.get_values_for_type(x509.DNSName)
        sans += [str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass

    is_ca = False
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        is_ca = bool(bc.value.ca)
    except x509.ExtensionNotFound:
        pass

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pk_algo, pk_size = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pk_algo, pk_size = f"EC ({pub.curve.name})", pub.curve.key_size
    elif isinstance(pub, dsa.DSAPublicKey):
        pk_algo, pk_size = "DSA", pub.key_size
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        pk_algo, pk_size = "Ed25519", 256
    elif isinstance(pub, ed448.Ed448PublicKey):
        pk_algo, pk_size = "Ed448", 448
    else:
        pk_algo, pk_size = type(pub).__name__, None

    cn = _cn(cert.subject)
    names = ([cn] if cn else []) + sans
    is_wildcard = any(n.startswith("*.") for n in names)
    self_signed = cert.subject == cert.issuer

    fp = hashlib.sha256(der).hexdigest()
    fingerprint = ":".join(fp[i : i + 2] for i in range(0, len(fp), 2)).upper()

    try:
        sig_algo = cert.signature_algorithm_oid._name  # human-readable name
    except AttributeError:
        sig_algo = str(cert.signature_algorithm_oid)

    leaf_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    chain_pem = [leaf_pem] + [
        x509.load_der_x509_certificate(d).public_bytes(serialization.Encoding.PEM).decode()
        for d in chain_der
    ]

    return {
        "fingerprint_sha256": fingerprint,
        "common_name": cn,
        "subject": _name(cert.subject),
        "sans": sans,
        "issuer": _name(cert.issuer),
        "issuer_cn": _cn(cert.issuer),
        "serial_number": format(cert.serial_number, "x"),
        "signature_algorithm": sig_algo,
        "public_key_algorithm": pk_algo,
        "public_key_size": pk_size,
        "not_before": _aware(cert.not_valid_before_utc) if hasattr(cert, "not_valid_before_utc") else _aware(cert.not_valid_before),
        "not_after": _aware(cert.not_valid_after_utc) if hasattr(cert, "not_valid_after_utc") else _aware(cert.not_valid_after),
        "self_signed": self_signed,
        "is_wildcard": is_wildcard,
        "is_ca": is_ca,
        "chain_length": len(chain_pem),
        "pem": "".join(chain_pem),
    }


# Substrings in SSLError messages that indicate the peer is not actually TLS.
_NON_TLS_MARKERS = ("wrong version number", "http request", "unknown protocol", "record layer")


def scan_endpoint(ip: str, port: int, sni: str = "", timeout: float = 5.0) -> ScanResult:
    """Connect to ip:port, capture the presented TLS certificate.

    `sni` is the SNI/hostname to present (empty = no SNI). `ip` is the address we
    actually dial; for hostname targets the caller resolves it first and may pass
    the same value as sni.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # observe, don't trust
    ctx.minimum_version = ssl.TLSVersion.TLSv1

    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except socket.timeout:
        return ScanResult(status="timeout", error="connection timed out")
    except OSError as e:
        return ScanResult(status="connection_failed", error=str(e))

    raw.settimeout(timeout)
    try:
        server_hostname = sni or None
        with ctx.wrap_socket(raw, server_hostname=server_hostname) as tls:
            der = tls.getpeercert(binary_form=True)
            chain_der = _unverified_chain(tls)
    except socket.timeout:
        raw.close()
        return ScanResult(status="timeout", error="TLS handshake timed out", sni_used=sni)
    except ssl.SSLError as e:
        raw.close()
        msg = str(e).lower()
        status = "non_tls_service" if any(m in msg for m in _NON_TLS_MARKERS) else "tls_handshake_failed"
        return ScanResult(status=status, error=str(e), sni_used=sni)
    except OSError as e:
        raw.close()
        return ScanResult(status="connection_failed", error=str(e), sni_used=sni)

    if not der:
        return ScanResult(status="no_certificate", error="server presented no certificate", sni_used=sni)

    try:
        cert = parse_certificate(der, chain_der)
    except Exception as e:  # malformed cert — still record the failure, never crash
        return ScanResult(status="tls_handshake_failed", error=f"certificate parse error: {e}", sni_used=sni)

    return ScanResult(status="ok", sni_used=sni, cert=cert)


def _unverified_chain(tls: ssl.SSLSocket) -> list[bytes]:
    """Best-effort full-chain capture beyond the leaf. get_unverified_chain()
    exists on Python 3.13+; on older runtimes we only have the leaf, which is
    enough for inventory.
    ponytail: leaf-only chain on <3.13; upgrade interpreter for full chains."""
    getter = getattr(tls, "get_unverified_chain", None)
    if getter is None:
        return []
    try:
        certs = getter() or []
        # _ssl.Certificate.public_bytes(Encoding.DER) -> DER bytes; skip leaf.
        return [c.public_bytes(serialization.Encoding.DER) for c in certs[1:]]
    except Exception:
        return []
