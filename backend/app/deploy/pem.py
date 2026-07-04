"""PEM filesystem connector (Phase 1, Task 9).

Writes `cert`/`chain`/`fullchain`/`key` PEM files to the paths configured on
the `DeploymentTarget` (`config["cert_path"]`, `["chain_path"]`,
`["fullchain_path"]`, `["key_path"]` -- all optional; only configured paths
are written).

Each file is written write-new-then-atomic-rename: the full content goes to
`<path>.tmp` in the *same directory* (so `os.replace` is guaranteed atomic --
same filesystem), the key's temp file gets restrictive permissions BEFORE
the rename, then `os.replace(tmp, path)` swaps it in. This means the target
path is only ever touched by a single atomic rename of a fully-written file:
a crash mid-write leaves the `.tmp` file behind and the old `path` untouched;
there is no way to observe a partially-written cert or key at its real path.

`post_deploy_command`, if set, runs after all files are written (subprocess,
output captured); a non-zero exit raises `DeployError` with the captured
output. `_run_command` is a seam so tests never actually shell out.
"""
from __future__ import annotations

import os
import subprocess

from .base import CertBundle, DeployError, DeployResult

# DeploymentTarget.config key -> CertBundle attribute
_FILES = {
    "cert_path": "cert_pem",
    "chain_path": "chain_pem",
    "fullchain_path": "fullchain_pem",
    "key_path": "key_pem",
}


class PemConnector:
    def __init__(self, target):
        self.target = target

    def deploy(self, bundle: CertBundle) -> DeployResult:
        written = []
        for config_key, attr in _FILES.items():
            path = self.target.config.get(config_key)
            if not path:
                continue
            content = getattr(bundle, attr)
            _atomic_write(path, content.encode(), restrictive=(config_key == "key_path"))
            written.append(path)

        cmd = self.target.post_deploy_command
        if cmd:
            code, output = _run_command(cmd)
            if code != 0:
                raise DeployError(f"post_deploy_command failed (exit {code}): {output}")

        detail = f"wrote {len(written)} file(s)"
        if cmd:
            detail += "; ran post_deploy_command"
        return DeployResult(ok=True, detail=detail)


def _atomic_write(path: str, data: bytes, restrictive: bool = False) -> None:
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "wb") as f:
        f.write(data)
    if restrictive:
        # POSIX: 0600 (owner read/write only). On Windows os.chmod has very
        # limited effect on NTFS ACLs -- this is a best-effort hardening,
        # not a security boundary on that platform.
        os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)


def _run_command(cmd: str) -> tuple[int, str]:
    """Seam: tests monkeypatch this instead of shelling out for real."""
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
