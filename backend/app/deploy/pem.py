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
On POSIX, the key's temp file is created with mode 0600 from the moment it
is opened (`os.O_CREAT` with the mode baked in) so the plaintext key is
never briefly world/group-readable between file creation and a subsequent
chmod.

`post_deploy_command`, if set, runs after all files are written (subprocess,
output captured); a non-zero exit raises `DeployError` with the captured
output. `_run_command` is a seam so tests never actually shell out.

Known limitation: write-then-rename is atomic PER FILE, but a multi-file
deploy (cert/chain/fullchain written before key) is NOT atomic across
files -- a mid-deploy failure can leave a new cert with the old key at the
target paths; the connector raises and the owning order is marked `failed`
in that case, and a re-deploy (retry) fixes the mismatch.
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
    try:
        if restrictive and os.name == "posix":
            # Create the temp file with 0600 baked into the open() call
            # itself, so the plaintext key is never briefly world/group-
            # readable at the default umask between creation and a later
            # chmod -- it is 0600 from the instant it exists on disk.
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        else:
            with open(tmp_path, "wb") as f:
                f.write(data)
            if restrictive:
                # Best-effort on Windows: os.chmod has very limited effect
                # on NTFS ACLs there, so this is hardening, not a security
                # boundary on that platform.
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


def _run_command(cmd: str) -> tuple[int, str]:
    """Seam: tests monkeypatch this instead of shelling out for real."""
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
