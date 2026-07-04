"""Tests for the worker's `verify` queue step (Phase 1, Task 12): the
post-deploy verification loop that closes a renewal only once the newly
issued certificate is actually observed live on its endpoints.

`worker.process_one` handles queue kind "verify" by loading the
`LifecycleOrder` (must be in `verifying`), its `ManagedCertificate`, that
cert's `RenewalPolicy`, and the newly-issued `Certificate`
(`managed.current_certificate_id`) -- then scanning the endpoints whose host
matches the managed cert's common_name/SANs and comparing the observed leaf
fingerprint to the expected one.
"""
from __future__ import annotations

import datetime

from app import queue, scan_engine, worker
from app.models import (
    AlertEvent,
    Certificate,
    Endpoint,
    Issuer,
    LifecycleOrder,
    ManagedCertificate,
    RenewalPolicy,
    WorkQueue,
    utcnow,
)
from app.scanner import ScanResult

NEW_FP = "AA:BB:CC:NEW"
OLD_FP = "11:22:33:OLD"


def _seed_verifying_order(
    db, cn="renew.example.com", verify_after_deploy=True, with_endpoint=True, max_retries=2
):
    issuer = Issuer(name="corp-ca", issuer_type="adcs", config={})
    policy = RenewalPolicy(
        name="default-90d", renew_before_days=30, key_algorithm="rsa", key_size=2048,
        require_approval=True, verify_after_deploy=verify_after_deploy, max_retries=max_retries,
    )
    db.add(issuer)
    db.add(policy)
    db.flush()

    new_cert = Certificate(
        fingerprint_sha256=NEW_FP, common_name=cn, sans=[cn], chain_length=1,
        pem="", not_after=utcnow() + datetime.timedelta(days=90),
    )
    db.add(new_cert)
    db.flush()

    managed = ManagedCertificate(
        common_name=cn, sans=[cn], issuer_id=issuer.id, renewal_policy_id=policy.id,
        current_certificate_id=new_cert.id, state="renewing",
    )
    db.add(managed)
    db.commit()
    db.refresh(managed)

    order = LifecycleOrder(
        managed_certificate_id=managed.id, action="renew", status="verifying",
        correlation_id="test-corr", transitions=[
            {"from": "deploying", "to": "verifying", "at": utcnow().isoformat(), "detail": ""},
        ],
    )
    db.add(order)
    db.commit()
    db.refresh(order)

    endpoint = None
    if with_endpoint:
        endpoint = Endpoint(host=cn, ip="203.0.113.10", port=443)
        db.add(endpoint)
        db.commit()
        db.refresh(endpoint)

    return managed, order, new_cert, endpoint


def _ok_result(fp: str) -> ScanResult:
    return ScanResult(status="ok", cert={"fingerprint_sha256": fp})


def test_verify_matching_fingerprint_completes_order_and_activates_cert(db, monkeypatch):
    managed, order, new_cert, endpoint = _seed_verifying_order(db)
    monkeypatch.setattr(scan_engine, "scan_endpoint", lambda ip, port, sni="", timeout=5.0: _ok_result(NEW_FP))
    item = queue.enqueue(db, "verify", {"order_id": order.id})

    result = worker.process_one(db)

    assert result is True
    db.refresh(item)
    assert item.status == "done"
    db.refresh(order)
    assert order.status == "complete"
    db.refresh(managed)
    assert managed.state == "active"


def test_verify_mismatched_fingerprint_fails_order_and_raises_alert(db, monkeypatch):
    managed, order, new_cert, endpoint = _seed_verifying_order(db)
    monkeypatch.setattr(scan_engine, "scan_endpoint", lambda ip, port, sni="", timeout=5.0: _ok_result(OLD_FP))
    item = queue.enqueue(db, "verify", {"order_id": order.id})

    result = worker.process_one(db)

    assert result is True
    db.refresh(order)
    assert order.status == "failed"
    assert "mismatch" in order.transitions[-1]["detail"]
    db.refresh(managed)
    assert managed.state == "error"

    events = db.query(AlertEvent).filter(AlertEvent.rule_type == "deploy_failed").all()
    assert len(events) == 1
    assert events[0].severity == "critical"

    db.refresh(item)
    assert item.status in ("queued", "failed")
    assert "mismatch" in item.last_error


def test_verify_after_deploy_false_skips_scan_and_completes(db, monkeypatch):
    managed, order, new_cert, endpoint = _seed_verifying_order(db, verify_after_deploy=False)
    calls = []
    monkeypatch.setattr(scan_engine, "scan_endpoint", lambda *a, **kw: calls.append((a, kw)) or _ok_result(NEW_FP))
    item = queue.enqueue(db, "verify", {"order_id": order.id})

    result = worker.process_one(db)

    assert result is True
    assert calls == []  # scan must never be invoked
    db.refresh(order)
    assert order.status == "complete"
    db.refresh(managed)
    assert managed.state == "active"


def test_verify_no_matching_endpoints_completes_without_scanning(db, monkeypatch):
    managed, order, new_cert, endpoint = _seed_verifying_order(db, with_endpoint=False)
    calls = []
    monkeypatch.setattr(scan_engine, "scan_endpoint", lambda *a, **kw: calls.append((a, kw)) or _ok_result(NEW_FP))
    item = queue.enqueue(db, "verify", {"order_id": order.id})

    result = worker.process_one(db)

    assert result is True
    assert calls == []
    db.refresh(order)
    assert order.status == "complete"
    assert "no observable endpoints" in order.transitions[-1]["detail"]
    db.refresh(managed)
    assert managed.state == "active"


def test_verify_retries_before_succeeding_on_transient_mismatch(db, monkeypatch):
    managed, order, new_cert, endpoint = _seed_verifying_order(db, max_retries=3)
    calls = {"n": 0}

    def fake_scan(ip, port, sni="", timeout=5.0):
        calls["n"] += 1
        return _ok_result(OLD_FP if calls["n"] == 1 else NEW_FP)

    monkeypatch.setattr(scan_engine, "scan_endpoint", fake_scan)
    item = queue.enqueue(db, "verify", {"order_id": order.id})

    result = worker.process_one(db)

    assert result is True
    assert calls["n"] == 2  # first attempt mismatched, second matched
    db.refresh(order)
    assert order.status == "complete"
    db.refresh(managed)
    assert managed.state == "active"


def test_verify_scan_failure_after_retries_fails_closed(db, monkeypatch):
    managed, order, new_cert, endpoint = _seed_verifying_order(db, max_retries=2)

    def raising_scan(ip, port, sni="", timeout=5.0):
        raise ConnectionError("boom")

    monkeypatch.setattr(scan_engine, "scan_endpoint", raising_scan)
    item = queue.enqueue(db, "verify", {"order_id": order.id})

    result = worker.process_one(db)

    assert result is True
    db.refresh(order)
    assert order.status == "failed"
    db.refresh(managed)
    assert managed.state == "error"
    events = db.query(AlertEvent).filter(AlertEvent.rule_type == "deploy_failed").all()
    assert len(events) == 1


def test_verify_skips_order_not_in_verifying_state(db, monkeypatch):
    managed, order, new_cert, endpoint = _seed_verifying_order(db)
    order.status = "complete"
    db.commit()
    calls = []
    monkeypatch.setattr(scan_engine, "scan_endpoint", lambda *a, **kw: calls.append(1) or _ok_result(NEW_FP))
    item = queue.enqueue(db, "verify", {"order_id": order.id})

    result = worker.process_one(db)

    assert result is True
    assert calls == []
    db.refresh(item)
    assert item.status == "done"
    db.refresh(order)
    assert order.status == "complete"  # untouched
