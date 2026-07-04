"""Tests for the worker's issuance/renewal execution path (Phase 1, Task 8).

`worker.process_one` handles queue kinds "issue"/"renew": it drives a
`LifecycleOrder` from queued -> issuing -> deploying, generating a key+CSR,
calling the issuer adapter, storing the issued cert, persisting the
(encrypted) private key, and enqueueing a "deploy" work item. All issuer I/O
is monkeypatched at `AcmeHttp01Adapter`/`ADCSAdapter.issue` or `get_adapter`
so these tests never touch the network.
"""
from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import queue, scheduler, secrets, worker
from app.issuers.base import IssuedCert, IssuerError
from app.models import (
    Certificate,
    Issuer,
    LifecycleOrder,
    ManagedCertificate,
    RenewalPolicy,
    WorkQueue,
    utcnow,
)


def _self_signed_cert_pem(cn: str = "issued.example.com", days_valid: int = 90) -> tuple[str, str]:
    """Build a self-signed cert; return (pem, hex_serial) -- the hex serial is
    what `scanner.parse_certificate` will extract into `Certificate.serial_number`,
    same as a real issuer adapter does from its retrieved cert."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    serial = x509.random_serial_number()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode(), format(serial, "x")


def _seed(db, cn="host.example.com", renew_before_days=30):
    issuer = Issuer(name="corp-ca", issuer_type="adcs", config={})
    policy = RenewalPolicy(
        name="default-90d", renew_before_days=renew_before_days, key_algorithm="rsa",
        key_size=2048, require_approval=True, verify_after_deploy=True, max_retries=3,
    )
    db.add(issuer)
    db.add(policy)
    db.flush()

    current_cert = Certificate(
        fingerprint_sha256=f"FP:{cn}", common_name=cn, sans=[cn],
        not_after=utcnow() + datetime.timedelta(days=5),
    )
    db.add(current_cert)
    db.flush()

    managed = ManagedCertificate(
        common_name=cn, sans=[cn], issuer_id=issuer.id, renewal_policy_id=policy.id,
        current_certificate_id=current_cert.id, state="active",
    )
    db.add(managed)
    # renewal_tick() (and the ACME persistence check) opens its own
    # SessionLocal(), which -- unlike a plain flush() -- cannot see this
    # session's uncommitted writes, so this seed must be durably committed.
    db.commit()
    db.refresh(managed)
    return issuer, policy, managed


def _queued_renew_order(db, managed) -> tuple[LifecycleOrder, WorkQueue]:
    order = LifecycleOrder(
        managed_certificate_id=managed.id, action="renew", status="queued",
        correlation_id="test-corr", transitions=[
            {"from": "", "to": "pending_approval", "at": utcnow().isoformat(), "detail": "created"},
            {"from": "pending_approval", "to": "approved", "at": utcnow().isoformat(), "detail": ""},
            {"from": "approved", "to": "queued", "at": utcnow().isoformat(), "detail": ""},
        ],
    )
    db.add(order)
    db.commit()
    db.refresh(order)
    item = queue.enqueue(db, "renew", {"order_id": order.id})
    return order, item


def test_process_one_issues_renewal_and_enqueues_deploy(db, monkeypatch):
    issuer, policy, managed = _seed(db)
    order, item = _queued_renew_order(db, managed)

    issued_pem, issued_serial = _self_signed_cert_pem()
    canned = IssuedCert(certificate_pem=issued_pem, chain_pem="", serial=issued_serial)

    def _fake_get_adapter(iss):
        class _Adapter:
            def issue(self, csr_pem, profile):
                assert "BEGIN CERTIFICATE REQUEST" in csr_pem
                return canned

        return _Adapter()

    monkeypatch.setattr(worker, "get_adapter", _fake_get_adapter)

    result = worker.process_one(db)
    assert result is True

    db.refresh(order)
    assert order.status == "deploying"
    assert order.transitions[-2]["to"] == "issuing"
    assert order.transitions[-1]["to"] == "deploying"

    db.refresh(item)
    assert item.status == "done"

    deploy_items = db.query(WorkQueue).filter(WorkQueue.kind == "deploy").all()
    assert len(deploy_items) == 1
    assert deploy_items[0].payload == {"order_id": order.id}

    db.refresh(managed)
    assert managed.current_certificate_id is not None
    new_cert = db.get(Certificate, managed.current_certificate_id)
    assert new_cert is not None
    assert new_cert.serial_number == issued_serial

    assert managed.current_key_ref
    key_pem = secrets.decrypt(managed.current_key_ref)
    # must parse as a real private key (never stored in plaintext)
    serialization.load_pem_private_key(key_pem.encode(), password=None)
    assert managed.current_key_ref != key_pem  # confirm it really was encrypted at rest

    assert managed.state == "renewing"


def test_process_one_failing_adapter_marks_order_failed_and_managed_error(db, monkeypatch):
    issuer, policy, managed = _seed(db)
    order, item = _queued_renew_order(db, managed)

    def _fake_get_adapter(iss):
        class _Adapter:
            def issue(self, csr_pem, profile):
                raise IssuerError("CA unreachable")

        return _Adapter()

    monkeypatch.setattr(worker, "get_adapter", _fake_get_adapter)

    result = worker.process_one(db)
    assert result is True

    db.refresh(order)
    assert order.status == "failed"
    assert "CA unreachable" in order.error or "CA unreachable" in order.transitions[-1]["detail"]

    db.refresh(managed)
    assert managed.state == "error"

    db.refresh(item)
    # single-attempt default max_attempts=3 means it gets requeued, not
    # dead-lettered, but the order itself is terminal regardless of retry.
    assert item.status in ("queued", "failed")
    assert "CA unreachable" in item.last_error


def test_process_one_missing_order_fails_item(db):
    item = queue.enqueue(db, "renew", {"order_id": 999999})
    item.max_attempts = 1
    db.commit()

    result = worker.process_one(db)
    assert result is True

    db.refresh(item)
    assert item.status == "failed"


def test_process_one_skips_already_processed_order(db):
    issuer, policy, managed = _seed(db)
    order = LifecycleOrder(
        managed_certificate_id=managed.id, action="renew", status="deploying",
        correlation_id="test-corr", transitions=[],
    )
    db.add(order)
    db.commit()
    db.refresh(order)
    item = queue.enqueue(db, "renew", {"order_id": order.id})

    result = worker.process_one(db)
    assert result is True

    db.refresh(item)
    assert item.status == "done"
    db.refresh(order)
    assert order.status == "deploying"  # untouched


def test_acme_account_key_persisted_after_issuance(db, monkeypatch):
    acme_issuer = Issuer(name="letsencrypt", issuer_type="acme", config={"directory_url": "https://acme.test/dir"})
    policy = RenewalPolicy(name="acme-90d", renew_before_days=30, key_algorithm="rsa",
                           key_size=2048, require_approval=True, verify_after_deploy=True, max_retries=3)
    db.add(acme_issuer)
    db.add(policy)
    db.flush()
    current_cert = Certificate(fingerprint_sha256="FP:acme", common_name="acme.example.com",
                               not_after=utcnow() + datetime.timedelta(days=5))
    db.add(current_cert)
    db.flush()
    managed = ManagedCertificate(
        common_name="acme.example.com", sans=["acme.example.com"], issuer_id=acme_issuer.id,
        renewal_policy_id=policy.id, current_certificate_id=current_cert.id, state="active",
    )
    db.add(managed)
    db.commit()
    db.refresh(managed)

    order, item = _queued_renew_order(db, managed)

    issued_pem, issued_serial = _self_signed_cert_pem()
    canned = IssuedCert(certificate_pem=issued_pem, chain_pem="", serial=issued_serial)

    def _fake_get_adapter(iss):
        class _Adapter:
            def issue(self, csr_pem, profile):
                # Simulate the ACME adapter generating+caching an account key
                # in the (same, in-memory) issuer.config dict.
                iss.config["account_key_pem"] = secrets.encrypt("fake-account-key-pem")
                return canned

        return _Adapter()

    monkeypatch.setattr(worker, "get_adapter", _fake_get_adapter)

    worker.process_one(db)

    db.expire(acme_issuer)
    reloaded = db.get(Issuer, acme_issuer.id)
    assert reloaded.config.get("account_key_pem")


def test_renewal_tick_creates_pending_order_when_within_renew_window(db):
    issuer, policy, managed = _seed(db, renew_before_days=30)
    # current cert expires in 5 days < renew_before_days=30 -> due for renewal

    scheduler.renewal_tick()

    orders = db.query(LifecycleOrder).filter_by(managed_certificate_id=managed.id).all()
    assert len(orders) == 1
    assert orders[0].status == "pending_approval"
    assert orders[0].action == "renew"

    # WorkQueue must NOT have gained an item -- approval-gated, not auto-queued.
    assert db.query(WorkQueue).count() == 0


def test_renewal_tick_skips_cert_far_from_expiry(db):
    issuer, policy, managed = _seed(db, renew_before_days=30)
    far_cert = Certificate(fingerprint_sha256="FP:far", common_name="far.example.com",
                           not_after=utcnow() + datetime.timedelta(days=365))
    db.add(far_cert)
    db.flush()
    managed.current_certificate_id = far_cert.id
    db.commit()

    scheduler.renewal_tick()

    orders = db.query(LifecycleOrder).filter_by(managed_certificate_id=managed.id).all()
    assert len(orders) == 0


def test_renewal_tick_only_targets_active_state(db):
    issuer, policy, managed = _seed(db, renew_before_days=30)
    managed.state = "renewing"
    db.commit()

    scheduler.renewal_tick()

    orders = db.query(LifecycleOrder).filter_by(managed_certificate_id=managed.id).all()
    assert len(orders) == 0
