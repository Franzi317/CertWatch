"""Scan orchestration: expand a target, scan endpoints concurrently, persist
observations and deduplicated certificates, and evaluate alerts.

Threads (not asyncio) because TLS handshakes are blocking socket I/O and a bounded
ThreadPoolExecutor gives us simple per-job concurrency limiting. Each job runs in
a background thread with its own DB session; the worker never crashes on a single
endpoint error — failures are recorded as observations.
"""
from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import targets as target_lib
from .config import settings
from .db import SessionLocal
from .models import Certificate, Endpoint, CertificateObservation, ScanJob, Target, utcnow
from .scanner import scan_endpoint

log = logging.getLogger("certwatch.scan")


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def run_scan_job(job_id: int) -> None:
    """Entry point executed in a background thread. Owns its own session."""
    db = SessionLocal()
    try:
        job = db.get(ScanJob, job_id)
        if job is None:
            return
        target = db.get(Target, job.target_id) if job.target_id else None
        if target is None:
            _finish(db, job, "failed", "target no longer exists")
            return
        _execute(db, job, target)
    except Exception as e:  # never let a worker thread die silently
        log.exception("scan job %s crashed", job_id)
        db.rollback()
        job = db.get(ScanJob, job_id)
        if job:
            _finish(db, job, "failed", f"internal error: {e}")
    finally:
        db.close()


def _execute(db: Session, job: ScanJob, target: Target) -> None:
    job.status = "running"
    job.started_at = utcnow()
    db.commit()

    try:
        units = target_lib.expand(target.target_type, target.value, settings.max_cidr_hosts)
        ports = target_lib.normalize_ports(target.ports, settings.default_ports)
    except target_lib.TargetError as e:
        _finish(db, job, "failed", str(e))
        return

    # Build the work list: (host, ip, port) tuples.
    work: list[tuple[str, str, int]] = []
    for unit in units:
        ip = unit.ip
        host = unit.host
        if host and not ip:  # hostname target — resolve once
            ip = _resolve(host) or ""
            if not ip:
                # record a dns failure observation per port
                for port in ports:
                    _record_failure(db, job, target, host, "", port, "dns_resolution_failed",
                                    f"could not resolve {host}")
                continue
        for port in ports:
            work.append((host, ip, port))

    job.total_endpoints = len(work)
    db.commit()

    sni_default = target.use_sni and target.target_type == "hostname"
    concurrency = max(1, min(target.concurrency or settings.default_concurrency, 500))

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {}
        for host, ip, port in work:
            if _cancelled(db, job):
                break
            sni = host if (host and sni_default) else ""
            futures[pool.submit(scan_endpoint, ip, port, sni, target.timeout)] = (host, ip, port, sni)

        for fut in as_completed(futures):
            host, ip, port, sni = futures[fut]
            if _cancelled(db, job):
                break
            try:
                result = fut.result()
            except Exception as e:  # defensive: a scanner bug shouldn't kill the job
                _record_failure(db, job, target, host, ip, port, "connection_failed", str(e))
                job.errors += 1
            else:
                _persist_result(db, job, target, host, ip, port, sni, result)
            job.scanned_endpoints += 1
            db.commit()

    if _cancelled(db, job):
        _finish(db, job, "cancelled", "cancelled by user")
    else:
        target.last_scanned_at = utcnow()
        _finish(db, job, "completed",
                f"scanned {job.scanned_endpoints} endpoints, {job.certs_found} certs, {job.errors} errors")

    # Extract CA hierarchy (source="chain" certs + leaf linkage) before alert
    # evaluation, so the issuer_expiring rule can see the CA certs. Non-fatal:
    # a derivation bug must never fail a scan (mirrors findings below).
    from . import ca_hierarchy
    try:
        ca_hierarchy.derive(db)
    except Exception:
        log.exception("CA hierarchy derivation failed for job %s", job.id)

    # Evaluate alert rules after the job completes (import here to avoid cycle).
    from .alerts import evaluate_alerts
    try:
        evaluate_alerts(db)
    except Exception:
        log.exception("alert evaluation failed for job %s", job.id)

    # Evaluate crypto-risk findings (weak keys, deprecated signatures, self-signed
    # in prod, ...) after the job completes. Non-fatal: a findings bug must never
    # fail a scan. Full sweep (not just this job's endpoints) mirrors evaluate_alerts.
    from . import findings
    try:
        findings.evaluate_all(db)
    except Exception:
        log.exception("findings evaluation failed for job %s", job.id)


def _persist_result(db, job, target, host, ip, port, sni, result):
    endpoint = _get_or_create_endpoint(db, target, host, ip, port)
    endpoint.last_seen = utcnow()
    endpoint.sni = result.sni_used

    if result.status != "ok" or not result.cert:
        endpoint.last_status = result.status
        endpoint.last_error = result.error
        endpoint.consecutive_failures += 1
        job.errors += 1
        db.add(CertificateObservation(
            scan_job_id=job.id, endpoint_id=endpoint.id, certificate_id=None,
            status=result.status, error=result.error, sni_used=sni, change_status="",
        ))
        db.commit()
        return

    cert = _upsert_certificate(db, result.cert)
    change = _change_status(endpoint, cert)
    endpoint.last_status = "ok"
    endpoint.last_error = ""
    endpoint.consecutive_failures = 0
    endpoint.current_cert_id = cert.id
    job.certs_found += 1

    db.add(CertificateObservation(
        scan_job_id=job.id, endpoint_id=endpoint.id, certificate_id=cert.id,
        status="ok", error="", sni_used=sni, change_status=change,
    ))
    db.commit()

    if change == "changed":
        from .alerts import record_change_alert
        record_change_alert(db, endpoint, cert)


def _change_status(endpoint: Endpoint, cert: Certificate) -> str:
    if endpoint.current_cert_id is None:
        return "first_seen"
    if endpoint.current_cert_id == cert.id:
        return "unchanged"
    return "changed"


def _get_or_create_endpoint(db, target, host, ip, port) -> Endpoint:
    stmt = select(Endpoint).where(Endpoint.host == host, Endpoint.ip == ip, Endpoint.port == port)
    ep = db.scalar(stmt)
    if ep is None:
        ep = Endpoint(target_id=target.id, host=host, ip=ip, port=port)
        db.add(ep)
        db.flush()
    return ep


def _upsert_certificate(db, fields: dict, source: str = "network") -> Certificate:
    fp = fields["fingerprint_sha256"]
    cert = db.scalar(select(Certificate).where(Certificate.fingerprint_sha256 == fp))
    if cert is None:
        cert = Certificate(**fields, source=source)
        db.add(cert)
        db.flush()
    else:
        cert.last_seen = utcnow()  # preserve first_seen and source; only bump last_seen
    return cert


def _record_failure(db, job, target, host, ip, port, status, error):
    endpoint = _get_or_create_endpoint(db, target, host, ip, port)
    endpoint.last_status = status
    endpoint.last_error = error
    endpoint.last_seen = utcnow()
    endpoint.consecutive_failures += 1
    db.add(CertificateObservation(
        scan_job_id=job.id, endpoint_id=endpoint.id, certificate_id=None,
        status=status, error=error, sni_used=host, change_status="",
    ))
    job.errors += 1
    db.commit()


def _cancelled(db, job) -> bool:
    db.refresh(job, ["cancel_requested"])
    return job.cancel_requested


def _finish(db, job, status, message):
    job.status = status
    job.message = message
    job.finished_at = utcnow()
    db.commit()
