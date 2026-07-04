"""Deployment connector protocol and cert bundle (Phase 1, Task 9).

A `DeployConnector` pushes a renewed certificate to one destination: a
filesystem path pair for `kind="pem"` (this task); a PKCS12 keystore
(`pfx`), a Java keystore (`jks`), or IIS's certificate store (`iis`) in
Tasks 10/11. `get_connector` dispatches on `DeploymentTarget.kind` via a
lazy import so importing this module never pulls in every connector's
dependencies.
"""
from __future__ import annotations

import os
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
    """Dispatch on `target.kind`. "pem"/"pfx"/"jks"/"iis" are all
    implemented (Tasks 9/10/11)."""
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
    if kind == "iis":
        from .iis import IisConnector

        return IisConnector(target)
    raise DeployError(f"connector not implemented: {kind}")


def atomic_write(path: str, data: bytes, restrictive: bool = False) -> None:
    """Write `data` to `path` via write-new-then-atomic-rename: the full
    content goes to `<path>.tmp` in the *same directory* (so `os.replace` is
    guaranteed atomic -- same filesystem), then `os.replace(tmp, path)` swaps
    it into place. The target path is only ever touched by a single atomic
    rename of a fully-written file: a crash mid-write leaves the `.tmp` file
    behind and the old `path` untouched -- there is no way to observe a
    partially-written file at its real path.

    When `restrictive=True` (the file contains private key material), the
    temp file is made mode 0600 before the rename. On POSIX this is baked
    into the `open()` call itself (`os.O_CREAT` with the mode set) so the
    plaintext is never briefly world/group-readable between file creation
    and a later chmod -- it is 0600 from the instant it exists on disk. On
    non-POSIX platforms (Windows), `os.chmod` runs after the write as a
    best-effort hardening -- it has very limited effect on NTFS ACLs there,
    so it is NOT a security boundary on that platform.

    Consolidated from what used to be near-identical private
    `_atomic_write` helpers in `pem.py`, `pfx.py`, and `jks.py` (Task 11
    review fold-in) -- `pem.py` calls this with `restrictive` set per-file
    (only the key file is restrictive); `pfx.py`/`jks.py` always pass
    `restrictive=True` since their whole output is a keystore containing a
    private key.
    """
    tmp_path = f"{path}.tmp"
    try:
        if restrictive and os.name == "posix":
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        else:
            with open(tmp_path, "wb") as f:
                f.write(data)
            if restrictive:
                os.chmod(tmp_path, 0o600)
    except BaseException:
        # Don't leave a leftover .tmp file behind if the write itself
        # failed partway through.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    os.replace(tmp_path, path)
