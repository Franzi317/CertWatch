"""Deployment connector protocol and cert bundle (Phase 1, Task 9).

A `DeployConnector` pushes a renewed certificate to one destination: a
filesystem path pair for `kind="pem"` (this task); a PKCS12 keystore
(`pfx`), a Java keystore (`jks`), or IIS's certificate store (`iis`) in
Tasks 10/11. `get_connector` dispatches on `DeploymentTarget.kind` via a
lazy import so importing this module never pulls in every connector's
dependencies.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

if TYPE_CHECKING:
    from ..models import DeploymentTarget

_PEM_CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


@dataclass
class DeployResult:
    ok: bool
    detail: str = ""


class DeployError(Exception):
    """Raised by a connector when a deploy step fails outright. The worker's
    deploy step treats this as fail-closed: the owning LifecycleOrder moves
    to `failed`, the ManagedCertificate's state becomes `error`, and the
    queue item is failed -- never a silently half-applied deployment."""


@dataclass
class CertBundle:
    """The renewed cert material a connector needs: the leaf certificate,
    any intermediate chain certs, and the (already-decrypted, plaintext-in-
    memory-only) private key PEM. Callers MUST decrypt the key immediately
    before building a bundle and MUST NOT log it."""

    cert_pem: str
    chain_pem: str
    key_pem: str

    @property
    def fullchain_pem(self) -> str:
        return self.cert_pem + "\n" + self.chain_pem

    def pfx_bytes(self, password: str, friendly_name: str = "") -> bytes:
        """Build a PKCS12 (.pfx) blob containing the leaf cert, its private
        key, and any chain certs as CAs. Not used by the `pem` connector
        (this task) -- implemented now because the `pfx`/`jks`/`iis`
        connectors (Tasks 10/11) need it and shouldn't have to touch
        `CertBundle` again."""
        key = serialization.load_pem_private_key(self.key_pem.encode(), password=None)
        leaf = x509.load_pem_x509_certificate(self.cert_pem.encode())
        chain_certs = [
            x509.load_pem_x509_certificate(block.encode())
            for block in _PEM_CERT_RE.findall(self.chain_pem)
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


class DeployConnector(Protocol):
    def deploy(self, bundle: CertBundle) -> DeployResult: ...


def get_connector(target: "DeploymentTarget") -> DeployConnector:
    """Dispatch on `target.kind`. Only "pem" is implemented so far --
    "pfx"/"jks"/"iis" are added in Tasks 10/11."""
    kind = target.kind
    if kind == "pem":
        from .pem import PemConnector

        return PemConnector(target)
    raise DeployError(f"connector not implemented: {kind}")
