"""Tests for the PFX and JKS/PKCS12 deployment connectors (Phase 1, Task 10).

`crypto_keys.build_pkcs12` builds a PKCS12 blob from a cert bundle + password;
`CertBundle.pfx_bytes` delegates to it. `PfxConnector` and `JksConnector` both
write a PKCS12 keystore to a configured path using the same restrictive
atomic-write pattern as `PemConnector`'s key file (the keystore contains the
private key), with the password decrypted from `target.config["password"]`
via `app.secrets.decrypt` at deploy time. `JksConnector` produces a PKCS12
file too -- modern Java (9+) reads PKCS12 natively, so there is no true
(Sun proprietary) JKS format writer here (see the `ponytail:` comment in
`app/deploy/jks.py`).
"""
from __future__ import annotations

import datetime
import os
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from app import crypto_keys, secrets
from app.deploy import base as base_mod
from app.deploy import jks as jks_mod
from app.deploy import pfx as pfx_mod
from app.deploy.base import CertBundle, DeployError, get_connector
from app.deploy.jks import JksConnector
from app.deploy.pfx import PfxConnector
from app.models import DeploymentTarget


def _self_signed(cn: str = "keystore.example.com", days_valid: int = 90):
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
    return cert_pem, key_pem, key


def _target(tmp_path, path_key="pfx_path", filename="deploy.pfx", kind="pfx",
            password="changeit", post_deploy_command="", **config_overrides):
    config = {
        path_key: str(tmp_path / filename),
        "password": secrets.encrypt(password),
    }
    config.update(config_overrides)
    return DeploymentTarget(
        name="keystore-target", kind=kind, config=config,
        post_deploy_command=post_deploy_command, managed_certificate_id=1,
    )


# --------------------------------------------------------------------------
# crypto_keys.build_pkcs12 / CertBundle.pfx_bytes
# --------------------------------------------------------------------------

def test_build_pkcs12_round_trips_key_and_leaf_cert():
    cert_pem, key_pem, key = _self_signed()
    data = crypto_keys.build_pkcs12(cert_pem, "", key_pem, "hunter2")

    loaded_key, loaded_cert, loaded_cas = pkcs12.load_key_and_certificates(data, b"hunter2")

    assert loaded_key.public_key().public_numbers() == key.public_key().public_numbers()
    assert loaded_cert.public_bytes(serialization.Encoding.PEM) == x509.load_pem_x509_certificate(
        cert_pem.encode()
    ).public_bytes(serialization.Encoding.PEM)


def test_build_pkcs12_includes_chain_as_cas():
    leaf_pem, leaf_key_pem, _ = _self_signed("leaf.example.com")
    inter_pem, _, _ = _self_signed("intermediate.example.com")

    data = crypto_keys.build_pkcs12(leaf_pem, inter_pem, leaf_key_pem, "hunter2")
    loaded_key, loaded_cert, loaded_cas = pkcs12.load_key_and_certificates(data, b"hunter2")

    assert loaded_cas is not None
    assert len(loaded_cas) == 1
    assert loaded_cas[0].subject.rfc4514_string() == "CN=intermediate.example.com"


def test_certbundle_pfx_bytes_delegates_and_round_trips():
    cert_pem, key_pem, key = _self_signed()
    bundle = CertBundle(cert_pem=cert_pem, chain_pem="", key_pem=key_pem)

    data = bundle.pfx_bytes("hunter2", friendly_name="my-cert")

    loaded_key, loaded_cert, loaded_cas = pkcs12.load_key_and_certificates(data, b"hunter2")
    assert loaded_key.public_key().public_numbers() == key.public_key().public_numbers()


# --------------------------------------------------------------------------
# PfxConnector
# --------------------------------------------------------------------------

def test_pfx_connector_writes_loadable_keystore(tmp_path):
    cert_pem, key_pem, key = _self_signed()
    bundle = CertBundle(cert_pem=cert_pem, chain_pem="", key_pem=key_pem)
    target = _target(tmp_path, password="changeit")

    result = PfxConnector(target).deploy(bundle)

    assert result.ok is True
    pfx_path = tmp_path / "deploy.pfx"
    assert pfx_path.exists()
    loaded_key, loaded_cert, _ = pkcs12.load_key_and_certificates(
        pfx_path.read_bytes(), b"changeit"
    )
    assert loaded_key.public_key().public_numbers() == key.public_key().public_numbers()
    assert not (tmp_path / "deploy.pfx.tmp").exists()


def test_pfx_connector_keystore_has_restrictive_perms(tmp_path):
    cert_pem, key_pem, _ = _self_signed()
    bundle = CertBundle(cert_pem=cert_pem, chain_pem="", key_pem=key_pem)
    target = _target(tmp_path)

    PfxConnector(target).deploy(bundle)

    pfx_path = tmp_path / "deploy.pfx"
    if os.name == "posix":
        mode = stat.S_IMODE(pfx_path.stat().st_mode)
        assert mode == 0o600
    else:
        assert pfx_path.exists()


def test_pfx_connector_wrong_password_in_config_fails_to_load(tmp_path):
    cert_pem, key_pem, _ = _self_signed()
    bundle = CertBundle(cert_pem=cert_pem, chain_pem="", key_pem=key_pem)
    target = _target(tmp_path, password="realpassword")

    PfxConnector(target).deploy(bundle)

    pfx_path = tmp_path / "deploy.pfx"
    with pytest.raises(Exception):
        pkcs12.load_key_and_certificates(pfx_path.read_bytes(), b"wrongpassword")


def test_pfx_connector_runs_post_deploy_command_on_success(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(pfx_mod, "_run_command", lambda cmd: calls.append(cmd) or (0, "reloaded"))
    cert_pem, key_pem, _ = _self_signed()
    bundle = CertBundle(cert_pem=cert_pem, chain_pem="", key_pem=key_pem)
    target = _target(tmp_path, post_deploy_command="iisreset")

    result = PfxConnector(target).deploy(bundle)

    assert result.ok is True
    assert calls == ["iisreset"]


def test_pfx_connector_failing_post_deploy_command_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(pfx_mod, "_run_command", lambda cmd: (1, "boom"))
    cert_pem, key_pem, _ = _self_signed()
    bundle = CertBundle(cert_pem=cert_pem, chain_pem="", key_pem=key_pem)
    target = _target(tmp_path, post_deploy_command="iisreset")

    with pytest.raises(DeployError, match="boom"):
        PfxConnector(target).deploy(bundle)

    # the keystore itself was still written atomically before the command ran
    assert (tmp_path / "deploy.pfx").exists()


# --------------------------------------------------------------------------
# JksConnector
# --------------------------------------------------------------------------

def test_jks_connector_writes_loadable_pkcs12_keystore(tmp_path):
    cert_pem, key_pem, key = _self_signed()
    bundle = CertBundle(cert_pem=cert_pem, chain_pem="", key_pem=key_pem)
    target = _target(tmp_path, path_key="keystore_path", filename="deploy.jks", kind="jks")

    result = JksConnector(target).deploy(bundle)

    assert result.ok is True
    jks_path = tmp_path / "deploy.jks"
    assert jks_path.exists()
    loaded_key, loaded_cert, _ = pkcs12.load_key_and_certificates(
        jks_path.read_bytes(), b"changeit"
    )
    assert loaded_key.public_key().public_numbers() == key.public_key().public_numbers()


def test_jks_connector_keystore_has_restrictive_perms(tmp_path):
    cert_pem, key_pem, _ = _self_signed()
    bundle = CertBundle(cert_pem=cert_pem, chain_pem="", key_pem=key_pem)
    target = _target(tmp_path, path_key="keystore_path", filename="deploy.jks", kind="jks")

    JksConnector(target).deploy(bundle)

    jks_path = tmp_path / "deploy.jks"
    if os.name == "posix":
        mode = stat.S_IMODE(jks_path.stat().st_mode)
        assert mode == 0o600
    else:
        assert jks_path.exists()


def test_jks_connector_failing_post_deploy_command_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(jks_mod, "_run_command", lambda cmd: (1, "boom"))
    cert_pem, key_pem, _ = _self_signed()
    bundle = CertBundle(cert_pem=cert_pem, chain_pem="", key_pem=key_pem)
    target = _target(
        tmp_path, path_key="keystore_path", filename="deploy.jks", kind="jks",
        post_deploy_command="reload",
    )

    with pytest.raises(DeployError, match="boom"):
        JksConnector(target).deploy(bundle)


# --------------------------------------------------------------------------
# get_connector dispatch
# --------------------------------------------------------------------------

def test_get_connector_dispatches_pfx(tmp_path):
    target = _target(tmp_path)
    connector = get_connector(target)
    assert isinstance(connector, PfxConnector)


def test_get_connector_dispatches_jks(tmp_path):
    target = _target(tmp_path, path_key="keystore_path", filename="deploy.jks", kind="jks")
    connector = get_connector(target)
    assert isinstance(connector, JksConnector)


def test_get_connector_iis_dispatch_moved_to_test_deploy_iis(tmp_path):
    # "iis" was the last unimplemented `kind` as of Task 10; Task 11 adds
    # `IisConnector` and its dispatch -- coverage for that now lives in
    # `test_deploy_iis.py::test_get_connector_dispatches_iis` alongside the
    # rest of the IIS connector's tests, rather than duplicated here.
    from app.deploy.iis import IisConnector

    target = _target(tmp_path, kind="iis")
    connector = get_connector(target)
    assert isinstance(connector, IisConnector)
