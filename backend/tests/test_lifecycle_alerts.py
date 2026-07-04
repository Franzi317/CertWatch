"""Tests for lifecycle alerting + dashboard metrics (Phase 1, Task 13):

- Worker failure paths (`_process_issuance`, `_process_deploy`, `_process_verify`)
  raise `renewal_failed` / `deploy_failed` AlertEvents via the shared
  `worker._raise_order_alert` -> `alerts.raise_alert` helper, deduped per order.
- `scheduler.order_stuck_tick` finds LifecycleOrders stuck in a non-terminal
  state past `scheduler.ORDER_STUCK_THRESHOLD` and raises `order_stuck` alerts,
  also deduped per order.
- `GET /api/dashboard` returns the new lifecycle-management fields.
"""
from __future__ import annotations

import datetime

from sqlalchemy import update
from conftest import login_as

from app import alerts, queue, scan_engine, scheduler, worker
from app.db import SessionLocal
from app.issuers.base import IssuerError
from app.models import (
    AlertEvent,
    Certificate,
    Endpoint,
    Issuer,
    LifecycleOrder,
    ManagedCertificate,
    RenewalPolicy,
    utcnow,
)
from app.scanner import ScanResult


def _seed_issuer_and_policy(db):
    issuer = Issuer(name="corp-ca", issuer_type="adcs", config={})
    policy = RenewalPolicy(
        name="default-90d", renew_before_days=30, key_algorithm="rsa", key_size=2048,
        require_approval=True, verify_after_deploy=True, max_retries=2,
    )
    db.add(issuer)
    db.add(policy)
    db.flush()
    return issuer, policy


# --------------------------------------------------------------------------- #
# Issuance failure -> renewal_failed
# --------------------------------------------------------------------------- #
def test_issuance_failure_raises_renewal_failed_alert(db, monkeypatch):
    issuer, policy = _seed_issuer_and_policy(db)
    current_cert = Certificate(
        fingerprint_sha256="FP:issuance-fail", common_name="fail.example.com",
        sans=["fail.example.com"], not_after=utcnow() + datetime.timedelta(days=5),
    )
    db.add(current_cert)
    db.flush()
    managed = ManagedCertificate(
        common_name="fail.example.com", sans=["fail.example.com"], issuer_id=issuer.id,
        renewal_policy_id=policy.id, current_certificate_id=current_cert.id, state="active",
    )
    db.add(managed)
    db.commit()
    db.refresh(managed)

    order = LifecycleOrder(
        managed_certificate_id=managed.id, action="renew", status="queued",
        correlation_id="test-corr", transitions=[
            {"from": "approved", "to": "queued", "at": utcnow().isoformat(), "detail": ""},
        ],
    )
    db.add(order)
    db.commit()
    db.refresh(order)
    item = queue.enqueue(db, "renew", {"order_id": order.id})

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
    db.refresh(managed)
    assert managed.state == "error"

    events = db.query(AlertEvent).filter(AlertEvent.rule_type == "renewal_failed").all()
    assert len(events) == 1
    assert events[0].severity == "critical"
    assert events[0].dedupe_key == f"renewal_failed:{order.id}"
    assert "CA unreachable" in events[0].message

    # A second failed attempt on the same order must not create a duplicate row.
    worker._raise_order_alert(db, managed, order, "renewal_failed", "duplicate attempt")
    events_after = db.query(AlertEvent).filter(AlertEvent.rule_type == "renewal_failed").all()
    assert len(events_after) == 1


# --------------------------------------------------------------------------- #
# Post-deploy verification mismatch -> deploy_failed (Task 12 path, reused)
# --------------------------------------------------------------------------- #
def _seed_verifying_order(db, cn="renew.example.com"):
    issuer, policy = _seed_issuer_and_policy(db)
    new_cert = Certificate(
        fingerprint_sha256="AA:BB:NEW", common_name=cn, sans=[cn], chain_length=1,
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

    endpoint = Endpoint(host=cn, ip="203.0.113.10", port=443)
    db.add(endpoint)
    db.commit()
    db.refresh(endpoint)

    return managed, order, new_cert, endpoint


def test_verify_mismatch_raises_deploy_failed_alert_deduped(db, monkeypatch):
    managed, order, new_cert, endpoint = _seed_verifying_order(db)
    monkeypatch.setattr(
        scan_engine, "scan_endpoint",
        lambda ip, port, sni="", timeout=5.0: ScanResult(status="ok", cert={"fingerprint_sha256": "OLD-FP"}),
    )
    queue.enqueue(db, "verify", {"order_id": order.id})

    result = worker.process_one(db)
    assert result is True

    db.refresh(order)
    assert order.status == "failed"

    events = db.query(AlertEvent).filter(AlertEvent.rule_type == "deploy_failed").all()
    assert len(events) == 1
    assert events[0].severity == "critical"
    assert events[0].dedupe_key == f"deploy_failed:{order.id}"

    # Dedup: re-raising for the same order is a no-op.
    worker._raise_order_alert(db, managed, order, "deploy_failed", "duplicate")
    events_after = db.query(AlertEvent).filter(AlertEvent.rule_type == "deploy_failed").all()
    assert len(events_after) == 1


# --------------------------------------------------------------------------- #
# order_stuck_tick
# --------------------------------------------------------------------------- #
def _seed_order(db, status="issuing", cn="stuck.example.com"):
    issuer, policy = _seed_issuer_and_policy(db)
    managed = ManagedCertificate(
        common_name=cn, sans=[cn], issuer_id=issuer.id, renewal_policy_id=policy.id, state="renewing",
    )
    db.add(managed)
    db.commit()
    db.refresh(managed)

    order = LifecycleOrder(
        managed_certificate_id=managed.id, action="renew", status=status,
        correlation_id="test-corr", transitions=[],
    )
    db.add(order)
    db.commit()
    db.refresh(order)
    return managed, order


def _age_order(db, order, age: datetime.timedelta):
    """Push `updated_at` into the past via a raw UPDATE, bypassing the ORM's
    onupdate=utcnow default (which would otherwise stamp "now" right back)."""
    old = utcnow() - age
    db.execute(update(LifecycleOrder).where(LifecycleOrder.id == order.id).values(updated_at=old))
    db.commit()


def test_order_stuck_tick_alerts_on_old_non_terminal_order(db):
    managed, order = _seed_order(db, status="issuing")
    _age_order(db, order, scheduler.ORDER_STUCK_THRESHOLD + datetime.timedelta(minutes=1))

    scheduler.order_stuck_tick()

    events = db.query(AlertEvent).filter(AlertEvent.rule_type == "order_stuck").all()
    assert len(events) == 1
    assert events[0].dedupe_key == f"order_stuck:{order.id}"
    assert events[0].severity == "warning"
    assert "issuing" in events[0].message

    # Running the tick again must not duplicate the alert (deduped per order).
    scheduler.order_stuck_tick()
    events_after = db.query(AlertEvent).filter(AlertEvent.rule_type == "order_stuck").all()
    assert len(events_after) == 1


def test_order_stuck_tick_ignores_fresh_non_terminal_order(db):
    _seed_order(db, status="deploying")  # just created, updated_at ~= now

    scheduler.order_stuck_tick()

    events = db.query(AlertEvent).filter(AlertEvent.rule_type == "order_stuck").all()
    assert len(events) == 0


def test_order_stuck_tick_ignores_old_terminal_order(db):
    managed, order = _seed_order(db, status="complete")
    _age_order(db, order, scheduler.ORDER_STUCK_THRESHOLD + datetime.timedelta(hours=1))

    scheduler.order_stuck_tick()

    events = db.query(AlertEvent).filter(AlertEvent.rule_type == "order_stuck").all()
    assert len(events) == 0


# --------------------------------------------------------------------------- #
# Regression: evaluate_alerts must not auto-resolve one-off lifecycle alerts
# --------------------------------------------------------------------------- #
def test_evaluate_alerts_does_not_auto_resolve_lifecycle_alerts(db):
    managed, order = _seed_order(db, status="issuing")

    ev = alerts.raise_alert(
        db, dedupe_key=f"renewal_failed:{order.id}", rule_type="renewal_failed",
        severity="critical", message="CA unreachable", endpoint_id=None,
        certificate_id=None,
    )
    assert ev is not None
    assert ev.resolved is False

    # Also plant a stale scan-derived alert (no matching endpoint/cert exists),
    # to confirm normal scan-derived auto-resolution still works after the fix.
    stale = AlertEvent(
        dedupe_key="expiring:999999:999999:30", endpoint_id=None, certificate_id=None,
        rule_type="expiring", severity="warning", message="stale", resolved=False,
    )
    db.add(stale)
    db.commit()

    # This is the exact call that runs after every scan job completes.
    alerts.evaluate_alerts(db, dispatch=False)

    db.refresh(ev)
    assert ev.resolved is False, "lifecycle alert must survive the scan-derived auto-resolve sweep"

    db.refresh(stale)
    assert stale.resolved is True, "stale scan-derived alerts must still auto-resolve normally"


# --------------------------------------------------------------------------- #
# Dashboard metrics
# --------------------------------------------------------------------------- #
def test_dashboard_returns_lifecycle_metrics(client, monkeypatch):
    login_as(client, "admin", monkeypatch)

    session = SessionLocal()
    try:
        issuer, policy = _seed_issuer_and_policy(session)

        managed_cert = Certificate(
            fingerprint_sha256="FP:managed", common_name="managed.example.com",
            not_after=utcnow() + datetime.timedelta(days=60),
        )
        unmanaged_cert = Certificate(
            fingerprint_sha256="FP:unmanaged", common_name="unmanaged.example.com",
            not_after=utcnow() + datetime.timedelta(days=60),
        )
        session.add(managed_cert)
        session.add(unmanaged_cert)
        session.flush()

        managed = ManagedCertificate(
            common_name="managed.example.com", sans=[], issuer_id=issuer.id,
            renewal_policy_id=policy.id, current_certificate_id=managed_cert.id, state="active",
        )
        session.add(managed)
        session.commit()
        session.refresh(managed)

        # One pending-approval order (counts toward both in-flight and pending-approval).
        pending = LifecycleOrder(
            managed_certificate_id=managed.id, action="renew", status="pending_approval",
            correlation_id="c1", transitions=[],
        )
        # One terminal, complete renew order within the 30d window (100% success so far).
        complete = LifecycleOrder(
            managed_certificate_id=managed.id, action="renew", status="complete",
            correlation_id="c2", transitions=[],
        )
        session.add(pending)
        session.add(complete)
        session.commit()
    finally:
        session.close()

    body = client.get("/api/dashboard").json()

    for key in (
        "managed_certificates", "unmanaged_certificates", "orders_in_flight",
        "orders_pending_approval", "renewal_success_rate_30d",
    ):
        assert key in body

    assert body["managed_certificates"] == 1
    assert body["unmanaged_certificates"] == 1  # only the unmanaged cert
    assert body["orders_in_flight"] == 1         # only the pending_approval order
    assert body["orders_pending_approval"] == 1
    assert body["renewal_success_rate_30d"] == 1.0  # 1 complete / 1 terminal renew order in the 30d window
