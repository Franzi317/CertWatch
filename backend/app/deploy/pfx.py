"""PFX (PKCS12) deployment connector (Phase 1, Task 10).

Writes a single PKCS12 keystore file (`target.config["pfx_path"]`) built
from the `CertBundle` via `crypto_keys.build_pkcs12`. The keystore password
is `target.config["password"]`, stored encrypted at rest (same convention as
`Issuer.config`) and decrypted via `app.secrets.decrypt` only at deploy time,
never logged. An optional `target.config["friendly_name"]` is used as the
PKCS12 entry's friendly name.

The keystore file contains the private key, so it is written with the same
write-new-then-atomic-rename + restrictive-permissions pattern as
`PemConnector`'s key file (see `pem.py`'s module docstring for the full
rationale): the full PKCS12 blob goes to `<path>.tmp` in the same directory
with mode 0600 baked in from creation (POSIX) before `os.replace` swaps it
into place, so the keystore's real path is never observed half-written or
briefly world-readable.

`post_deploy_command`, if set, runs after the keystore is written (subprocess,
output captured); a non-zero exit raises `DeployError`. `_run_command` is a
seam so tests never actually shell out.
"""
from __future__ import annotations

import subprocess

from .. import crypto_keys, secrets
from .base import CertBundle, DeployError, DeployResult, atomic_write


class PfxConnector:
    def __init__(self, target):
        self.target = target

    def deploy(self, bundle: CertBundle) -> DeployResult:
        config = self.target.config
        path = config.get("pfx_path")
        if not path:
            raise DeployError("pfx connector requires config['pfx_path']")

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

        detail = "wrote pfx keystore"
        if cmd:
            detail += "; ran post_deploy_command"
        return DeployResult(ok=True, detail=detail)


def _run_command(cmd: str) -> tuple[int, str]:
    """Seam: tests monkeypatch this instead of shelling out for real."""
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
