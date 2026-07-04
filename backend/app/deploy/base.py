"""Deployment connector protocol and cert bundle (Phase 1, Task 9).

A `DeployConnector` pushes a renewed certificate to one destination: a
filesystem path pair for `kind="pem"` (this task); a PKCS12 keystore
(`pfx`), a Java keystore (`jks`), or IIS's certificate store (`iis`) in
Tasks 10/11. `get_connector` dispatches on `DeploymentTarget.kind` via a
lazy import so importing this module never pulls in every connector's
dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from .. import crypto_keys

if TYPE_CHECKING:
    from ..models import DeploymentTarget


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
        (this task) -- used by the `pfx`/`jks` connectors (Task 10) and
        available for `iis` (Task 11). Delegates to `crypto_keys.build_pkcs12`
        so the actual PKCS12-building logic lives in one place, reusable
        outside of `CertBundle` too."""
        return crypto_keys.build_pkcs12(
            self.cert_pem, self.chain_pem, self.key_pem, password, friendly_name
        )


class DeployConnector(Protocol):
    def deploy(self, bundle: CertBundle) -> DeployResult: ...


def get_connector(target: "DeploymentTarget") -> DeployConnector:
    """Dispatch on `target.kind`. "pem"/"pfx"/"jks" are implemented; "iis"
    is added in Task 11."""
    kind = target.kind
    if kind == "pem":
        from .pem import PemConnector

        return PemConnector(target)
    if kind == "pfx":
        from .pfx import PfxConnector

        return PfxConnector(target)
    if kind == "jks":
        from .jks import JksConnector

        return JksConnector(target)
    raise DeployError(f"connector not implemented: {kind}")
