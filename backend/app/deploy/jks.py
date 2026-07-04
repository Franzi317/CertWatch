"""JKS deployment connector (Phase 1, Task 10).

ponytail: this writes a PKCS12 keystore, NOT the Sun-proprietary JKS binary
format. Java 9+ defaults its own keystore type to PKCS12 and reads PKCS12
keystores natively everywhere a JKS one is accepted, so for every currently-
supported Java runtime a `.jks`-named PKCS12 file is a drop-in keystore --
building an actual JKS encoder (a bespoke, undocumented-by-Oracle binary
format) would be real effort spent on a format modern consumers don't need.
If a consumer ever shows up that truly requires the legacy binary format
(e.g. Java 8 with keystore type pinned to `jks`), implement a real encoder
then -- don't build it speculatively now.

Writes to `target.config["keystore_path"]`; otherwise identical to
`PfxConnector` (see `pfx.py`'s docstring for the write/permissions/password/
post_deploy_command rationale, which applies here unchanged).
"""
from __future__ import annotations

import subprocess

from .. import crypto_keys, secrets
from .base import CertBundle, DeployError, DeployResult, atomic_write


class JksConnector:
    def __init__(self, target):
        self.target = target

    def deploy(self, bundle: CertBundle) -> DeployResult:
        config = self.target.config
        path = config.get("keystore_path")
        if not path:
            raise DeployError("jks connector requires config['keystore_path']")

        password = secrets.decrypt(config.get("password", ""))
        friendly_name = config.get("friendly_name", "")

        data = crypto_keys.build_pkcs12(
            bundle.cert_pem, bundle.chain_pem, bundle.key_pem, password, friendly_name
        )
        atomic_write(path, data, restrictive=True)

        cmd = self.target.post_deploy_command
        if cmd:
            code, output = _run_command(cmd)
            if code != 0:
                raise DeployError(f"post_deploy_command failed (exit {code}): {output}")

        detail = "wrote jks (pkcs12) keystore"
        if cmd:
            detail += "; ran post_deploy_command"
        return DeployResult(ok=True, detail=detail)


def _run_command(cmd: str) -> tuple[int, str]:
    """Seam: tests monkeypatch this instead of shelling out for real."""
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
