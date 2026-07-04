"""IIS deployment connector (Phase 1, Task 11).

Windows/IIS has no filesystem- or Java-keystore-shaped "install a cert"
operation the way `pem.py`/`pfx.py`/`jks.py` do -- the platform-native
mechanism is the Windows certificate store (`Cert:\\LocalMachine\\My`) plus
an IIS site binding pointing at a certificate thumbprint. So this connector
shells out to PowerShell (`Import-PfxCertificate` + `New-WebBinding`/
`Get-WebBinding`) instead of writing a keystore file to disk.

Config (`target.config`):
  - `pfx_password` (required): encrypted at rest (`app.secrets`, same
    convention as `pfx.py`/`jks.py`'s `password`), decrypted only at deploy
    time. Used to protect the PFX built from the `CertBundle` and to unlock
    it during `Import-PfxCertificate`.
  - `site_name` (required): the IIS site to bind the certificate to.
  - `binding` (required): IIS binding info, either `scheme://ip:port:host`
    (e.g. `https://:443:host.example.com`) or a bare `ip:port:host`
    bindingInformation string -- scheme defaults to `https` if omitted.
  - `computer_name` (optional): if set, the generated script is wrapped in
    `Invoke-Command -ComputerName` for PowerShell remoting against that
    host instead of running against the local machine.

`_build_script` is a pure (no I/O) helper that renders the PowerShell
script text, kept separate from `deploy()` so script generation is directly
unit-testable without a real PowerShell/IIS server. `_run_powershell` is
the one seam that actually invokes PowerShell (`subprocess`); tests
monkeypatch it.

SECURITY: the decrypted PFX password is embedded in the generated script
text -- there is no way to hand `Import-PfxCertificate` a password
otherwise, short of a secure out-of-band channel. It MUST NOT be written to
logs or included in any exception/error message this module raises: on
failure, `DeployError` is built only from the captured PowerShell output
(`_run_powershell`'s return value), never from the script text itself. The
temp PFX file (written via `base.atomic_write(..., restrictive=True)`, same
pattern as `pfx.py`/`jks.py` since it contains the private key) is removed
again once the script has run, success or failure.

ponytail: passing the password as plaintext inside `-Command -` script text
(fed over stdin, not argv, so it never shows up in the OS process table) is
the simplest thing that actually works for a trusted local/remote admin
PowerShell channel. `-EncodedCommand` (base64 of UTF-16LE) or a
`-Credential`/secure-string handoff would avoid ever materializing the
password as a literal string inside the script buffer -- worth doing if
this connector is ever driven over a lower-trust remoting channel, but not
implemented here: it wouldn't change what's testable, and this project's
current threat model is a trusted admin box, not a hostile one.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import uuid

from .. import secrets
from .base import CertBundle, DeployError, DeployResult, atomic_write


class IisConnector:
    def __init__(self, target):
        self.target = target

    def deploy(self, bundle: CertBundle) -> DeployResult:
        config = self.target.config
        site_name = config.get("site_name")
        binding = config.get("binding")
        if not site_name or not binding:
            raise DeployError("iis connector requires config['site_name'] and config['binding']")

        password = secrets.decrypt(config.get("pfx_password", ""))
        data = bundle.pfx_bytes(password)

        pfx_path = os.path.join(tempfile.gettempdir(), f"certwatch-iis-{uuid.uuid4().hex}.pfx")
        try:
            atomic_write(pfx_path, data, restrictive=True)

            script = _build_script(pfx_path, password, site_name, binding)
            computer_name = config.get("computer_name")
            if computer_name:
                script = _wrap_remote(script, computer_name)

            code, output = _run_powershell(script)
            if code != 0:
                # `output` is whatever PowerShell printed to stdout/stderr --
                # never the script text itself, so the password embedded in
                # the script cannot leak into this error via `output` unless
                # the script explicitly printed it (it never does).
                raise DeployError(f"iis deploy failed (exit {code}): {output}")
        finally:
            try:
                os.remove(pfx_path)
            except OSError:
                pass

        return DeployResult(ok=True, detail=f"imported cert and bound to IIS site '{site_name}'")


def _split_binding(binding: str) -> tuple[str, str]:
    """`binding` may be given as `scheme://ip:port:host` or a bare
    `ip:port:host` bindingInformation string. Returns
    `(protocol, bindingInformation)`."""
    if "://" in binding:
        protocol, info = binding.split("://", 1)
        return protocol, info
    return "https", binding


def _ps_quote(value: str) -> str:
    """Escape a value for embedding in a single-quoted PowerShell string
    literal -- the only special case in single-quoted PS strings is doubling
    an embedded single quote."""
    return value.replace("'", "''")


def _build_script(pfx_path: str, password: str, site_name: str, binding: str) -> str:
    """Pure string-building helper (no I/O, no subprocess) so the generated
    PowerShell script is unit-testable on its own.

    Renders a script that:
      1. imports the PFX at `pfx_path` into `Cert:\\LocalMachine\\My` using
         `password`, capturing the resulting certificate's thumbprint;
      2. binds that thumbprint to `site_name`'s `binding`, creating the
         binding first if it doesn't already exist.
    """
    protocol, binding_info = _split_binding(binding)

    return f"""$ErrorActionPreference = 'Stop'
# CertWatch IIS deploy: site='{site_name}' binding='{binding}'
Import-Module WebAdministration -ErrorAction SilentlyContinue

$securePwd = ConvertTo-SecureString '{_ps_quote(password)}' -AsPlainText -Force
$cert = Import-PfxCertificate -FilePath '{_ps_quote(pfx_path)}' -CertStoreLocation Cert:\\LocalMachine\\My -Password $securePwd
$thumbprint = $cert.Thumbprint
Write-Output "THUMBPRINT=$thumbprint"

$existing = Get-WebBinding -Name '{_ps_quote(site_name)}' -Protocol '{_ps_quote(protocol)}' -ErrorAction SilentlyContinue
if (-not $existing) {{
    New-WebBinding -Name '{_ps_quote(site_name)}' -Protocol '{_ps_quote(protocol)}' -BindingInformation '{_ps_quote(binding_info)}'
    $existing = Get-WebBinding -Name '{_ps_quote(site_name)}' -Protocol '{_ps_quote(protocol)}'
}}
$existing.AddSslCertificate($thumbprint, 'My')
Write-Output "BOUND site={site_name}"
"""


def _wrap_remote(script: str, computer_name: str) -> str:
    """Wrap `script` in `Invoke-Command -ComputerName` for PowerShell
    remoting against `computer_name` instead of running against the local
    machine."""
    return (
        f"$__certwatch_block = {{\n{script}\n}}\n"
        f"Invoke-Command -ComputerName '{_ps_quote(computer_name)}' -ScriptBlock $__certwatch_block\n"
    )


def _run_powershell(script: str) -> tuple[int, str]:
    """Seam: tests monkeypatch this instead of shelling out to a real
    PowerShell/IIS host. Feeds the script over stdin (`-Command -`) so it
    never appears in argv/the OS process table; see the `ponytail:` note in
    the module docstring about the remaining password-in-script-text
    tradeoff."""
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", "-"],
        input=script,
        capture_output=True,
        text=True,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
