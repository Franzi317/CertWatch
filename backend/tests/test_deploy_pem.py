"""Tests for the PEM deployment connector and the worker's `deploy` queue
step (Phase 1, Task 9).

`PemConnector` writes cert/chain/fullchain/key PEM files to configured paths
using write-new-then-atomic-rename; `worker.process_one` handles queue kind
"deploy" by pushing a ManagedCertificate's current cert+key to every enabled
`DeploymentTarget` linked to it, then advancing the LifecycleOrder from
`deploying` to `verifying` (or `failed` if any target's connector fails).
"""
from __future__ import annotations

import datetime
import os
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import queue, secrets, worker
from app.deploy import pem as pem_mod
from app.deploy.base import CertBundle, DeployError
from app.deploy.pem import PemConnector
from app.models import (
    Certificate,
    DeploymentTarget,
    Issuer,
    LifecycleOrder,
    ManagedCertificate,
    RenewalPolicy,
    WorkQueue,
    utcnow,
)


def _target(tmp_path, post_deploy_command="", **config_overrides):
    config = {
        "cert_path": str(tmp_path / "cert.pem"),
        "chain_path": str(tmp_path / "chain.pem"),
        "fullchain_path": str(tmp_path / "fullchain.pem"),
        "key_path": str(tmp_path / "key.pem"),
    }
    config.update(config_overrides)
    return DeploymentTarget(
        name="fs-target", kind="pem", config=config,
        post_deploy_command=post_deploy_command, managed_certificate_id=1,
    )


# --------------------------------------------------------------------------
# PemConnector unit tests
# --------------------------------------------------------------------------

def test_pem_connector_writes_all_files_with_exact_content(tmp_path):
    target = _target(tmp_path)
    bundle = CertBundle(cert_pem="CERT-CONTENT\n", chain_pem="CHAIN-CONTENT\n", key_pem="KEY-CONTENT\n")

    result = PemConnector(target).deploy(bundle)

    assert result.ok is True
    assert (tmp_path / "cert.pem").read_text() == bundle.cert_pem
    assert (tmp_path / "chain.pem").read_text() == bundle.chain_pem
    assert (tmp_path / "fullchain.pem").read_text() == bundle.fullchain_pem
    assert (tmp_path / "key.pem").read_text() == bundle.key_pem
    # no leftover temp file after a successful atomic rename
    assert not (tmp_path / "key.pem.tmp").exists()


def test_pem_connector_key_file_has_restrictive_perms(tmp_path):
    target = _target(tmp_path)
    bundle = CertBundle(cert_pem="C\n", chain_pem="", key_pem="K\n")

    PemConnector(target).deploy(bundle)

    key_path = tmp_path / "key.pem"
    if os.name == "posix":
        mode = stat.S_IMODE(key_path.stat().st_mode)
        assert mode == 0o600
    else:
        # os.chmod has a very limited effect on NTFS ACLs on Windows -- this
        # is a best-effort hardening there, not a security boundary, so we
        # only assert the file was written correctly on this platform.
        assert key_path.read_text() == "K\n"


def test_pem_connector_only_writes_configured_paths(tmp_path):
    target = _target(tmp_path, chain_path="", fullchain_path="")
    bundle = CertBundle(cert_pem="C\n", chain_pem="X\n", key_pem="K\n")

    PemConnector(target).deploy(bundle)

    assert (tmp_path / "cert.pem").exists()
    assert (tmp_path / "key.pem").exists()
    assert not (tmp_path / "chain.pem").exists()
    assert not (tmp_path / "fullchain.pem").exists()


def test_pem_connector_runs_post_deploy_command_on_success(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(pem_mod, "_run_command", lambda cmd: calls.append(cmd) or (0, "reloaded"))
    target = _target(tmp_path, post_deploy_command="systemctl reload nginx")
    bundle = CertBundle(cert_pem="C\n", chain_pem="", key_pem="K\n")

    result = PemConnector(target).deploy(bundle)

    assert result.ok is True
    assert calls == ["systemctl reload nginx"]


def test_pem_connector_failing_post_deploy_command_raises_and_key_not_half_written(tmp_path, monkeypatch):
    monkeypatch.setattr(pem_mod, "_run_command", lambda cmd: (1, "boom"))
    target = _target(tmp_path, post_deploy_command="systemctl reload nginx")
    bundle = CertBundle(cert_pem="C\n", chain_pem="", key_pem="K\n")

    with pytest.raises(DeployError, match="boom"):
        PemConnector(target).deploy(bundle)

    # Files are written (atomic rename) before post_deploy_command runs, so
    # a failing command doesn't roll them back -- but critically the write
    # itself was atomic: no half-written key ever lands at the real path.
    assert (tmp_path / "key.pem").read_text() == "K\n"
    assert not (tmp_path / "key.pem.tmp").exists()


# --------------------------------------------------------------------------
# Worker "deploy" queue-step tests
# --------------------------------------------------------------------------

def _self_signed_cert_pem(cn: str = "deploy.example.com", days_valid: int = 90) -> tuple[str, rsa.RSAPrivateKey]:
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
    return cert.public_bytes(serialization.Encoding.PEM).decode(), key_pem


def _seed_deploying_order(db, tmp_path, cn="deploy.example.com", post_deploy_command=""):
    issuer = Issuer(name="corp-ca", issuer_type="adcs", config={})
    policy = RenewalPolicy(
        name="default-90d", renew_before_days=30, key_algorithm="rsa",
        key_size=2048, require_approval=True, verify_after_deploy=True, max_retries=3,
    )
    db.add(issuer)
    db.add(policy)
    db.flush()

    cert_pem, key_pem = _self_signed_cert_pem(cn)
    cert = Certificate(
        fingerprint_sha256=f"FP:{cn}", common_name=cn, sans=[cn], chain_length=1,
        pem=cert_pem, not_after=utcnow() + datetime.timedelta(days=90),
    )
    db.add(cert)
    db.flush()

    managed = ManagedCertificate(
        common_name=cn, sans=[cn], issuer_id=issuer.id, renewal_policy_id=policy.id,
        current_certificate_id=cert.id, current_key_ref=secrets.encrypt(key_pem), state="renewing",
    )
    db.add(managed)
    db.commit()
    db.refresh(managed)

    order = LifecycleOrder(
        managed_certificate_id=managed.id, action="renew", status="deploying",
        correlation_id="test-corr", transitions=[
            {"from": "issuing", "to": "deploying", "at": utcnow().isoformat(), "detail": ""},
        ],
    )
    db.add(order)
    db.commit()
    db.refresh(order)

    target = DeploymentTarget(
        name="fs-target", kind="pem",
        config={
            "cert_path": str(tmp_path / "cert.pem"),
            "chain_path": str(tmp_path / "chain.pem"),
            "fullchain_path": str(tmp_path / "fullchain.pem"),
            "key_path": str(tmp_path / "key.pem"),
        },
        post_deploy_command=post_deploy_command,
        managed_certificate_id=managed.id, enabled=True,
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    return managed, order, target


def test_worker_deploy_step_writes_files_and_transitions_to_verifying(db, tmp_path, monkeypatch):
    monkeypatch.setattr(pem_mod, "_run_command", lambda cmd: (0, "ok"))
    managed, order, target = _seed_deploying_order(db, tmp_path)
    item = queue.enqueue(db, "deploy", {"order_id": order.id})

    result = worker.process_one(db)
    assert result is True

    db.refresh(item)
    assert item.status == "done"

    db.refresh(order)
    assert order.status == "verifying"
    assert order.transitions[-1]["to"] == "verifying"

    verify_items = db.query(WorkQueue).filter(WorkQueue.kind == "verify").all()
    assert len(verify_items) == 1
    assert verify_items[0].payload == {"order_id": order.id}

    db.refresh(target)
    assert target.last_deploy_ok is True
    assert target.last_deploy_at is not None

    assert (tmp_path / "cert.pem").exists()
    assert (tmp_path / "key.pem").exists()
    written_cert = x509.load_pem_x509_certificate((tmp_path / "cert.pem").read_bytes())
    assert written_cert.subject.rfc4514_string() == f"CN=deploy.example.com"
    # the deployed key really is the decrypted managed-cert key, and is a
    # valid, loadable private key -- never logged, never left encrypted.
    written_key = serialization.load_pem_private_key((tmp_path / "key.pem").read_bytes(), password=None)
    assert written_key.public_key().public_numbers() == x509.load_pem_x509_certificate(
        (tmp_path / "cert.pem").read_bytes()
    ).public_key().public_numbers()
    # chain_length=1 (self-signed leaf only) -> no separate chain content
    assert (tmp_path / "chain.pem").read_text() == ""


def test_worker_deploy_step_failing_connector_fails_order_and_managed(db, tmp_path, monkeypatch):
    monkeypatch.setattr(pem_mod, "_run_command", lambda cmd: (1, "boom"))
    managed, order, target = _seed_deploying_order(db, tmp_path, post_deploy_command="reload")
    item = queue.enqueue(db, "deploy", {"order_id": order.id})

    result = worker.process_one(db)
    assert result is True

    db.refresh(order)
    assert order.status == "failed"
    assert "boom" in order.transitions[-1]["detail"]

    db.refresh(managed)
    assert managed.state == "error"

    verify_items = db.query(WorkQueue).filter(WorkQueue.kind == "verify").all()
    assert len(verify_items) == 0

    db.refresh(target)
    assert target.last_deploy_ok is False
    assert target.last_deploy_at is not None

    db.refresh(item)
    assert item.status in ("queued", "failed")
    assert "boom" in item.last_error


def test_worker_deploy_step_multi_target_partial_failure_fails_closed(db, tmp_path, monkeypatch):
    # target 1 has no post_deploy_command (always succeeds); target 2's
    # post_deploy_command is monkeypatched to fail. Both targets get their
    # files written -- target 1's write completes before target 2 fails --
    # but the overall deploy is fail-closed: order -> failed, managed cert
    # -> error, and no "verify" item is enqueued despite target 1's success.
    def fake_run_command(cmd):
        if cmd == "reload-target-2":
            return 1, "boom-target-2"
        return 0, "ok"

    monkeypatch.setattr(pem_mod, "_run_command", fake_run_command)
    managed, order, target1 = _seed_deploying_order(db, tmp_path)

    target2_dir = tmp_path / "target2"
    target2_dir.mkdir()
    target2 = DeploymentTarget(
        name="fs-target-2", kind="pem",
        config={
            "cert_path": str(target2_dir / "cert.pem"),
            "chain_path": str(target2_dir / "chain.pem"),
            "fullchain_path": str(target2_dir / "fullchain.pem"),
            "key_path": str(target2_dir / "key.pem"),
        },
        post_deploy_command="reload-target-2",
        managed_certificate_id=managed.id, enabled=True,
    )
    db.add(target2)
    db.commit()
    db.refresh(target2)

    item = queue.enqueue(db, "deploy", {"order_id": order.id})
    result = worker.process_one(db)
    assert result is True

    db.refresh(order)
    assert order.status == "failed"

    db.refresh(managed)
    assert managed.state == "error"

    db.refresh(target1)
    assert target1.last_deploy_ok is True

    db.refresh(target2)
    assert target2.last_deploy_ok is False

    verify_items = db.query(WorkQueue).filter(WorkQueue.kind == "verify").all()
    assert len(verify_items) == 0


def test_worker_deploy_step_with_no_targets_still_reaches_verifying(db, tmp_path):
    managed, order, target = _seed_deploying_order(db, tmp_path)
    db.delete(target)
    db.commit()

    item = queue.enqueue(db, "deploy", {"order_id": order.id})
    result = worker.process_one(db)
    assert result is True

    db.refresh(order)
    assert order.status == "verifying"

    verify_items = db.query(WorkQueue).filter(WorkQueue.kind == "verify").all()
    assert len(verify_items) == 1


def test_worker_deploy_step_disabled_target_is_ignored(db, tmp_path, monkeypatch):
    monkeypatch.setattr(pem_mod, "_run_command", lambda cmd: (1, "boom"))
    managed, order, target = _seed_deploying_order(db, tmp_path, post_deploy_command="reload")
    target.enabled = False
    db.commit()

    item = queue.enqueue(db, "deploy", {"order_id": order.id})
    result = worker.process_one(db)
    assert result is True

    db.refresh(order)
    # the only target is disabled -> effectively zero targets -> verifying
    assert order.status == "verifying"


def test_worker_deploy_step_skips_order_not_in_deploying_state(db, tmp_path):
    managed, order, target = _seed_deploying_order(db, tmp_path)
    order.status = "verifying"
    db.commit()

    item = queue.enqueue(db, "deploy", {"order_id": order.id})
    result = worker.process_one(db)
    assert result is True

    db.refresh(item)
    assert item.status == "done"
    db.refresh(order)
    assert order.status == "verifying"  # untouched
