"""Tests for the IIS deployment connector (Phase 1, Task 11).

`IisConnector` builds a PFX from the `CertBundle` (same `bundle.pfx_bytes`
used by `pfx.py`/`jks.py`), writes it to a restrictive temp path via
`base.atomic_write`, then runs a generated PowerShell script that imports
the PFX into `Cert:\\LocalMachine\\My` and binds the resulting cert
thumbprint to an IIS site. `_build_script` is a pure helper (no I/O) so the
script text is directly assertable; `_run_powershell` is the only seam that
would actually invoke PowerShell, so every test here monkeypatches it --
no real PowerShell/IIS server is touched.
"""
from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import secrets
from app.deploy import iis as iis_mod
from app.deploy.base import CertBundle, DeployError, get_connector
from app.deploy.iis import IisConnector, _build_script
from app.models import DeploymentTarget


def _self_signed(cn: str = "iis.example.com", days_valid: int = 90):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return cert_pem, key_pem


def _bundle():
    cert_pem, key_pem = _self_signed()
    return CertBundle(cert_pem=cert_pem, chain_pem="", key_pem=key_pem)


def _target(password="hunter2", site_name="Default Web Site",
            binding="https://:443:iis.example.com", **config_overrides):
    config = {
        "pfx_password": secrets.encrypt(password),
        "site_name": site_name,
        "binding": binding,
    }
    config.update(config_overrides)
    return DeploymentTarget(
        name="iis-target", kind="iis", config=config, managed_certificate_id=1,
    )


# --------------------------------------------------------------------------
# _build_script (pure helper)
# --------------------------------------------------------------------------

def test_build_script_contains_import_pfx_command_site_and_binding():
    script = _build_script("C:\\temp\\deploy.pfx", "hunter2", "Default Web Site",
                            "https://:443:iis.example.com")

    assert "Import-PfxCertificate" in script
    assert "Default Web Site" in script
    assert "https://:443:iis.example.com" in script
    assert "C:\\temp\\deploy.pfx" in script


def test_build_script_embeds_password_for_secure_string_conversion():
    script = _build_script("C:\\temp\\deploy.pfx", "hunter2", "Default Web Site",
                            "https://:443:iis.example.com")

    assert "hunter2" in script
    assert "ConvertTo-SecureString" in script


# --------------------------------------------------------------------------
# IisConnector.deploy
# --------------------------------------------------------------------------

def test_iis_connector_deploy_success_returns_ok_and_runs_expected_script(monkeypatch):
    captured = {}

    def fake_run_powershell(script):
        captured["script"] = script
        return 0, "THUMBPRINT=ABC123"

    monkeypatch.setattr(iis_mod, "_run_powershell", fake_run_powershell)
    target = _target(site_name="my-site", binding="https://:443:host.example.com")

    result = IisConnector(target).deploy(_bundle())

    assert result.ok is True
    script = captured["script"]
    assert "Import-PfxCertificate" in script
    assert "my-site" in script
    assert "https://:443:host.example.com" in script


def test_iis_connector_deploy_failure_raises_deploy_error(monkeypatch):
    monkeypatch.setattr(iis_mod, "_run_powershell", lambda script: (1, "access denied"))
    target = _target()

    with pytest.raises(DeployError, match="access denied"):
        IisConnector(target).deploy(_bundle())


def test_iis_connector_deploy_failure_does_not_leak_password_in_error(monkeypatch):
    monkeypatch.setattr(iis_mod, "_run_powershell", lambda script: (1, "access denied"))
    target = _target(password="supersecretpassword")

    with pytest.raises(DeployError) as excinfo:
        IisConnector(target).deploy(_bundle())

    assert "supersecretpassword" not in str(excinfo.value)


def test_iis_connector_cleans_up_temp_pfx_file(monkeypatch):
    captured = {}

    def fake_run_powershell(script):
        captured["script"] = script
        return 0, "THUMBPRINT=ABC123"

    monkeypatch.setattr(iis_mod, "_run_powershell", fake_run_powershell)
    target = _target()

    IisConnector(target).deploy(_bundle())

    # pull the temp pfx path out of the captured script and confirm it was
    # removed again after the deploy ran (best-effort cleanup, finally-block)
    import os
    import re

    match = re.search(r"-FilePath '([^']+)'", captured["script"])
    assert match is not None
    assert not os.path.exists(match.group(1))


def test_iis_connector_deploy_requires_site_name_and_binding():
    target = _target(site_name="", binding="")

    with pytest.raises(DeployError):
        IisConnector(target).deploy(_bundle())


def test_iis_connector_deploy_redacts_password_echoed_in_powershell_output(monkeypatch):
    # Simulate PowerShell's default error formatter echoing the failing
    # source line (which contains the plaintext password embedded in the
    # `ConvertTo-SecureString` call) back on stderr.
    monkeypatch.setattr(
        iis_mod,
        "_run_powershell",
        lambda script: (
            1,
            "At line:3 : ConvertTo-SecureString 's3cretpw' -AsPlainText ... error",
        ),
    )
    target = _target(password="s3cretpw")

    with pytest.raises(DeployError) as excinfo:
        IisConnector(target).deploy(_bundle())

    assert "s3cretpw" not in str(excinfo.value)
    assert "***" in str(excinfo.value)


# --------------------------------------------------------------------------
# _build_script comment-line sanitization
# --------------------------------------------------------------------------

def test_build_script_sanitizes_newline_in_site_name_comment():
    script = _build_script(
        "C:\\temp\\deploy.pfx",
        "hunter2",
        "Default Web Site\nStop-Computer",
        "https://:443:iis.example.com",
    )

    comment_line = next(line for line in script.splitlines() if line.startswith("#"))
    assert "Stop-Computer" in comment_line
    assert not any(
        line.strip() == "Stop-Computer" for line in script.splitlines()
    )


# --------------------------------------------------------------------------
# get_connector dispatch
# --------------------------------------------------------------------------

def test_get_connector_dispatches_iis():
    target = _target()
    connector = get_connector(target)
    assert isinstance(connector, IisConnector)
