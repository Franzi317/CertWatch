"""Queue-driven worker process (Task 8).

`process_one` claims a single item from the Task 7 work queue and executes
it; `run_forever` polls in a loop and is the entry point for both the
embedded worker thread (see `main.py` lifespan, `CERTWATCH_EMBEDDED_WORKER`)
and the standalone `python -m app.worker` process used in production
(`docker-compose.yml`'s `worker` service).

Kinds "issue"/"renew" (Task 8) drive a `LifecycleOrder` through
queued -> issuing -> deploying: generate a key+CSR per the managed cert's
RenewalPolicy, call the issuer adapter, store the issued cert, persist the
(encrypted) private key, and enqueue a "deploy" work item for Task 9. Any
failure fails closed: the order transitions to "failed", the managed cert's
state becomes "error", and the queue item is failed (subject to its own
retry/backoff via `queue.fail`).
"""
from __future__ import annotations

import logging
import re
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy.orm.attributes import flag_modified

from sqlalchemy import select

from . import alerts, lifecycle, queue, reports, scan_engine, secrets
from .crypto_keys import build_csr, generate_private_key
from .db import SessionLocal
from .deploy.base import CertBundle, DeployError, DeployResult, get_connector
from .issuers.base import get_adapter
from .models import (
    Certificate,
    DeploymentTarget,
    Endpoint,
    Issuer,
    LifecycleOrder,
    ManagedCertificate,
    ReportSchedule,
    RenewalPolicy,
    utcnow,
)
from .scanner import parse_certificate

log = logging.getLogger("certwatch.worker")

_PEM_CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


def process_one(db) -> bool:
    """Claim and execute one queue item. Returns True if an item was
    processed (regardless of success/failure), False if the queue was empty."""
    item = queue.claim(db)
    if item is None:
        return False

    if item.kind == "scan":
        try:
            scan_engine.run_scan_job(item.payload["scan_job_id"])
        except Exception as e:  # noqa: BLE001 - any scan failure must not kill the worker
            log.exception("scan job failed (queue item %s)", item.id)
            queue.fail(db, item, str(e))
        else:
            queue.complete(db, item)
    elif item.kind in ("issue", "renew"):
        _process_issuance(db, item)
    elif item.kind == "deploy":
        _process_deploy(db, item)
    elif item.kind == "verify":
        _process_verify(db, item)
    elif item.kind == "report":
        _process_report(db, item)
    else:
        queue.fail(db, item, f"unknown kind: {item.kind}")

    return True


def _process_report(db, item) -> None:
    """Run the `report` queue step (Task 5): render + email the referenced
    ReportSchedule via `reports.run_schedule`. Any failure (missing schedule,
    missing/wrong-type channel, SMTP error) fails the queue item closed --
    never lets a bad report kill the worker."""
    schedule_id = item.payload.get("schedule_id")
    schedule = db.get(ReportSchedule, schedule_id) if schedule_id is not None else None
    if schedule is None:
        queue.fail(db, item, f"report schedule {schedule_id!r} not found")
        return
    try:
        reports.run_schedule(db, schedule)
    except Exception as e:  # noqa: BLE001 - any report failure must not kill the worker
        log.exception("report schedule failed (queue item %s)", item.id)
        queue.fail(db, item, str(e))
    else:
        queue.complete(db, item)


def _process_issuance(db, item) -> None:
    order_id = item.payload.get("order_id")
    order = db.get(LifecycleOrder, order_id) if order_id is not None else None
    if order is None:
        queue.fail(db, item, f"lifecycle order {order_id!r} not found")
        return

    if order.status != "queued":
        # Already processed (e.g. a stale/duplicate queue item, or a retry
        # after the previous attempt actually succeeded) -- nothing to do.
        log.info("order %s already in status %s, skipping issuance", order.id, order.status)
        queue.complete(db, item)
        return

    managed: ManagedCertificate | None = None
    try:
        lifecycle.transition(db, order, "issuing")

        managed = db.get(ManagedCertificate, order.managed_certificate_id)
        if managed is None:
            raise RuntimeError(f"managed certificate {order.managed_certificate_id} not found")

        policy = db.get(RenewalPolicy, managed.renewal_policy_id)
        issuer = db.get(Issuer, managed.issuer_id)
        if policy is None:
            raise RuntimeError(f"renewal policy {managed.renewal_policy_id} not found")
        if issuer is None:
            raise RuntimeError(f"issuer {managed.issuer_id} not found")

        key_result = generate_private_key(policy.key_algorithm, policy.key_size)
        csr_pem = build_csr(key_result.key_pem, managed.common_name, managed.sans)

        adapter = get_adapter(issuer)
        issued = adapter.issue(csr_pem, {})

        cert = _store_issued_cert(db, issued)

        managed.current_certificate_id = cert.id
        managed.current_key_ref = secrets.encrypt(key_result.key_pem)
        # Mid-flow (deployment + verification are still ahead, Tasks 9/12);
        # "active" is only set once the deploy+verify steps succeed.
        managed.state = "renewing"

        # ACME account keys are generated + cached lazily by the adapter, in
        # memory, on the *same* dict object `issuer.config` returns -- but
        # Issuer.config is a plain JSON column, not a MutableDict, so that
        # in-place mutation is invisible to SQLAlchemy's change tracking.
        # Reassigning to a *new* dict isn't enough either: SQLAlchemy's flush
        # compares the new value against the (already-mutated, since it's the
        # same dict) old value by equality and sees no net change, so the
        # UPDATE silently drops the column. flag_modified() forces it into
        # the UPDATE regardless. No-op for AD CS.
        if issuer.issuer_type == "acme":
            issuer.config = dict(issuer.config)
            flag_modified(issuer, "config")

        db.commit()

        lifecycle.transition(db, order, "deploying")
        queue.enqueue(db, "deploy", {"order_id": order.id})
    except Exception as e:  # noqa: BLE001 - fail-closed: no half-completed issuance
        log.exception("issuance failed for order %s (queue item %s)", order_id, item.id)
        db.rollback()
        lifecycle.transition(db, order, "failed", str(e))
        if managed is not None:
            managed.state = "error"
            db.commit()
            _raise_order_alert(
                db, managed, order, "renewal_failed",
                f"Issuance failed for {managed.common_name or managed.id}: {e}",
            )
        queue.fail(db, item, str(e))
    else:
        queue.complete(db, item)


def _process_deploy(db, item) -> None:
    """Run the `deploy` queue step: push the ManagedCertificate's current
    cert+key to every enabled `DeploymentTarget` linked to it, then advance
    the order to `verifying` (Task 12 owns actually verifying anything).

    A ManagedCertificate with NO deployment targets configured still
    transitions straight to `verifying` -- there's nothing to deploy, and
    treating "no targets" as a failure would make it impossible to issue a
    cert that isn't yet wired to any target. Verify/complete handle that
    order the same way a zero-target one flows through downstream.

    Fail-closed: if any target's connector fails, the order goes to
    `failed` and the managed cert's state becomes `error` -- no partial
    "some targets got the new cert, some didn't" success is reported.
    """
    order_id = item.payload.get("order_id")
    order = db.get(LifecycleOrder, order_id) if order_id is not None else None
    if order is None:
        queue.fail(db, item, f"lifecycle order {order_id!r} not found")
        return

    if order.status != "deploying":
        # Already processed (stale/duplicate queue item, or a retry after
        # the previous attempt actually succeeded) -- nothing to do.
        log.info("order %s not in deploying state (status=%s), skipping deploy", order.id, order.status)
        queue.complete(db, item)
        return

    managed: ManagedCertificate | None = None
    try:
        managed = db.get(ManagedCertificate, order.managed_certificate_id)
        if managed is None:
            raise RuntimeError(f"managed certificate {order.managed_certificate_id} not found")

        cert = db.get(Certificate, managed.current_certificate_id)
        if cert is None:
            raise RuntimeError(f"current certificate {managed.current_certificate_id} not found")
        if not managed.current_key_ref:
            raise RuntimeError("managed certificate has no current_key_ref (private key)")

        cert_pem, chain_pem = _split_leaf_and_chain(cert.pem)
        # Decrypted only here, in memory, for the duration of this deploy --
        # never logged, never persisted in plaintext.
        key_pem = secrets.decrypt(managed.current_key_ref)
        bundle = CertBundle(cert_pem=cert_pem, chain_pem=chain_pem, key_pem=key_pem)

        targets = db.scalars(
            select(DeploymentTarget).where(
                DeploymentTarget.managed_certificate_id == managed.id,
                DeploymentTarget.enabled.is_(True),
            )
        ).all()

        all_ok = True
        first_error = ""
        for target in targets:
            try:
                result = get_connector(target).deploy(bundle)
            except DeployError as e:
                result = DeployResult(ok=False, detail=str(e))
            target.last_deploy_at = utcnow()
            target.last_deploy_ok = result.ok
            if not result.ok:
                all_ok = False
                first_error = first_error or result.detail

        db.commit()

        if not all_ok:
            raise DeployError(first_error or "one or more deployment targets failed")

        lifecycle.transition(db, order, "verifying")
        queue.enqueue(db, "verify", {"order_id": order.id})
    except Exception as e:  # noqa: BLE001 - fail-closed: no partial deploy success
        log.exception("deploy failed for order %s (queue item %s)", order_id, item.id)
        db.rollback()
        lifecycle.transition(db, order, "failed", str(e))
        if managed is not None:
            managed.state = "error"
            db.commit()
            _raise_order_alert(
                db, managed, order, "deploy_failed",
                f"Deployment failed for {managed.common_name or managed.id}: {e}",
            )
        queue.fail(db, item, str(e))
    else:
        queue.complete(db, item)


def _process_verify(db, item) -> None:
    """Run the `verify` queue step (Task 12): close the renewal loop by
    actually observing the newly-issued certificate live before declaring an
    order complete. A renewal that never gets scanned back (or that's still
    serving the old cert) must NOT be reported as done.

    Linkage choice: there's no direct FK from `Endpoint`/`DeploymentTarget`
    to `ManagedCertificate` in the current schema (a `DeploymentTarget`
    describes *how* to push material, e.g. a filesystem path or keystore --
    not an observable network endpoint). The simplest correct linkage
    available is matching `Endpoint.host` against the managed cert's
    common_name + SANs: that's exactly the FQDN set a scan would have
    observed this cert under. Good enough for Phase 1; a tighter
    Endpoint<->ManagedCertificate FK can replace this later if needed.

    Fail-closed on mismatch/scan failure (order -> failed, managed cert ->
    error, deploy_failed alert raised) and on any unexpected exception. A
    `RenewalPolicy.verify_after_deploy=False` skips the scan entirely, and a
    managed cert with NO observable endpoints completes anyway (with a
    detail noting that) -- ponytail: nothing to scan isn't a reason to fail
    a renewal that otherwise succeeded.
    """
    order_id = item.payload.get("order_id")
    order = db.get(LifecycleOrder, order_id) if order_id is not None else None
    if order is None:
        queue.fail(db, item, f"lifecycle order {order_id!r} not found")
        return

    if order.status != "verifying":
        log.info("order %s not in verifying state (status=%s), skipping verify", order.id, order.status)
        queue.complete(db, item)
        return

    managed: ManagedCertificate | None = None
    try:
        managed = db.get(ManagedCertificate, order.managed_certificate_id)
        if managed is None:
            raise RuntimeError(f"managed certificate {order.managed_certificate_id} not found")

        policy = db.get(RenewalPolicy, managed.renewal_policy_id)
        if policy is None:
            raise RuntimeError(f"renewal policy {managed.renewal_policy_id} not found")

        cert = db.get(Certificate, managed.current_certificate_id)
        if cert is None:
            raise RuntimeError(f"current certificate {managed.current_certificate_id} not found")

        if not policy.verify_after_deploy:
            _complete_order(db, order, managed, "verification skipped (verify_after_deploy=False)")
            queue.complete(db, item)
            return

        endpoints = _endpoints_for_managed_cert(db, managed)
        if not endpoints:
            _complete_order(db, order, managed, "complete: no observable endpoints to verify against")
            queue.complete(db, item)
            return

        observed_ok = _verify_endpoints_serve(endpoints, cert.fingerprint_sha256, policy.max_retries)
    except Exception as e:  # noqa: BLE001 - fail-closed: no half-verified order left dangling
        log.exception("verification crashed for order %s (queue item %s)", order_id, item.id)
        db.rollback()
        lifecycle.transition(db, order, "failed", str(e))
        if managed is not None:
            managed.state = "error"
            db.commit()
        queue.fail(db, item, str(e))
        return

    if observed_ok:
        _complete_order(db, order, managed, "")
        queue.complete(db, item)
    else:
        lifecycle.transition(db, order, "failed", "post-deploy verification mismatch")
        managed.state = "error"
        db.commit()
        _raise_order_alert(
            db, managed, order, "deploy_failed",
            f"Post-deploy verification failed for {managed.common_name or managed.id}: "
            "the certificate observed live does not match the newly issued certificate.",
        )
        queue.fail(db, item, "post-deploy verification mismatch")


def _complete_order(db, order, managed: ManagedCertificate, detail: str) -> None:
    lifecycle.transition(db, order, "complete", detail)
    managed.state = "active"
    db.commit()


def _endpoints_for_managed_cert(db, managed: ManagedCertificate) -> list[Endpoint]:
    names = {n for n in ([managed.common_name] + list(managed.sans or [])) if n}
    if not names:
        return []
    return db.scalars(select(Endpoint).where(Endpoint.host.in_(names))).all()


def _verify_endpoints_serve(endpoints: list[Endpoint], expected_fingerprint: str, max_retries: int) -> bool:
    """Scan every matching endpoint and require ALL of them to be observed
    serving the expected (newly-issued) fingerprint. Each endpoint gets up to
    `max_retries` attempts (a short sleep between) so a cert that hasn't
    propagated yet (or a transient scan hiccup) isn't immediately treated as
    a hard failure -- but a scan error is never allowed to crash the worker."""
    attempts = max(1, max_retries or 1)
    for ep in endpoints:
        matched = False
        for attempt in range(attempts):
            try:
                result = scan_engine.scan_endpoint(ep.ip or ep.host, ep.port, sni=ep.host, timeout=5.0)
            except Exception as e:  # noqa: BLE001 - a scan crash is just another failed attempt
                log.warning("verify scan errored for %s:%s (attempt %s): %s", ep.host or ep.ip, ep.port, attempt + 1, e)
                result = None
            if result is not None and result.status == "ok" and result.cert and result.cert.get("fingerprint_sha256") == expected_fingerprint:
                matched = True
                break
            if attempt + 1 < attempts:
                time.sleep(0.01)
        if not matched:
            return False
    return True


def _raise_order_alert(db, managed: ManagedCertificate, order, rule_type: str, message: str) -> None:
    """Reuses `alerts.raise_alert` (one AlertEvent row per distinct
    dedupe_key, keyed per-order so re-running the same failed order doesn't
    spam duplicate events) rather than reinventing dispatch --
    `alerts.dispatch_alerts`/`evaluate_alerts` pick the row up on their
    normal cadence like any other. Used for both `deploy_failed` (post-deploy
    verification mismatch, Task 12; deployment connector failure, Task 13)
    and `renewal_failed` (issuance failure, Task 13)."""
    alerts.raise_alert(
        db,
        dedupe_key=f"{rule_type}:{order.id}",
        rule_type=rule_type,
        severity="critical",
        message=message,
        certificate_id=managed.current_certificate_id,
    )


def _split_leaf_and_chain(pem_blob: str) -> tuple[str, str]:
    """`Certificate.pem` stores the leaf cert concatenated with its chain
    (see `scanner.parse_certificate`'s `"pem": "".join(chain_pem)`, where
    `chain_pem[0]` is the leaf). Split it back into (leaf, rest-of-chain)."""
    blocks = [b + "\n" for b in _PEM_CERT_RE.findall(pem_blob)]
    if not blocks:
        return pem_blob, ""
    return blocks[0], "".join(blocks[1:])


def _store_issued_cert(db, issued):
    """Store an adapter-issued certificate as a `Certificate` row, reusing
    `scan_engine._upsert_certificate` (dedup-by-fingerprint) so issued certs
    show up in the same inventory table scanned certs do. Parses the PEM with
    `cryptography`/`scanner.parse_certificate` rather than duplicating field
    extraction here."""
    leaf_der = x509.load_pem_x509_certificate(issued.certificate_pem.encode()).public_bytes(
        serialization.Encoding.DER
    )
    chain_der = [
        x509.load_pem_x509_certificate(block.encode()).public_bytes(serialization.Encoding.DER)
        for block in _PEM_CERT_RE.findall(issued.chain_pem or "")
    ]
    fields = parse_certificate(leaf_der, chain_der)
    return scan_engine._upsert_certificate(db, fields)


def run_forever(poll_interval: float = 2.0, stop_event=None) -> None:
    """Poll the queue until the process is killed (or `stop_event` is set,
    for the embedded in-process worker thread). An exception in one
    iteration is logged and never kills the loop."""
    log.info("worker started (poll_interval=%s)", poll_interval)
    while stop_event is None or not stop_event.is_set():
        try:
            db = SessionLocal()
            try:
                processed = process_one(db)
            finally:
                db.close()
        except Exception:  # noqa: BLE001 - keep polling no matter what
            log.exception("worker iteration failed")
            processed = False
        if not processed:
            if stop_event is not None:
                stop_event.wait(poll_interval)
            else:
                time.sleep(poll_interval)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    run_forever()


if __name__ == "__main__":
    main()
