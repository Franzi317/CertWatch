"""CertWatch FastAPI application: REST API, scheduler bootstrap, static frontend.

AUTHORIZATION NOTICE: CertWatch is for authorized internal inventory only. Only
define targets for networks and hosts you are authorized to assess.
"""
from __future__ import annotations

import logging
import os
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from . import findings, lifecycle, queue, schemas, targets as target_lib
from .alerts import dispatch_alerts, evaluate_alerts
from .auth import require_role, router as auth_router
from .config import settings
from .exports import rows_to_csv
from .secrets import SecretsNotConfigured, encrypt as encrypt_secret, is_encrypted
from .db import engine, get_db, init_db, run_migrations
from .issuers.base import IssuerError, get_adapter
from .models import (
    AcmeChallenge,
    AlertEvent,
    AuditLog,
    Certificate,
    CertificateObservation,
    DeploymentTarget,
    Endpoint,
    Finding,
    Issuer,
    LifecycleOrder,
    ManagedCertificate,
    NotificationChannel,
    RenewalPolicy,
    ReportSchedule,
    ScanJob,
    SystemSetting,
    Target,
    utcnow,
)
from .metrics import setup_metrics
from .notify import NotifyError, send_email, send_webhook
from .scheduler import enqueue_scan, shutdown_scheduler, start_scheduler
from .serialize import cert_dict, endpoint_dict, observation_dict
from .status import days_until
from . import worker as worker_lib

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("certwatch")

DEFAULT_SETTINGS = {
    "scan_failure_threshold": 3,
    "alert_on_self_signed": False,
    "app_base_url": "http://localhost:5173",
    "default_ports": [443, 8443, 9443, 636, 993, 995, 465, 587, 3389, 5986],
}

# CSV column sets for ?format=csv on the list endpoints (Phase 2, Task 1).
# Each is a flat projection of the existing JSON item dict (cert_dict /
# endpoint_dict / LifecycleOrderOut / _audit_dict) -- picked as the columns
# an operator would want in a spreadsheet, dropping nested/verbose fields
# (sans, pem, transitions, endpoint list, etc).
CERTIFICATE_CSV_COLUMNS = [
    "id", "common_name", "issuer_cn", "not_before", "not_after",
    "public_key_algorithm", "public_key_size", "signature_algorithm",
    "self_signed", "fingerprint_sha256",
]
ENDPOINT_CSV_COLUMNS = [
    "id", "host", "ip", "port", "target_name", "environment", "owner",
    "last_status", "common_name", "issuer_cn", "not_after", "days_until_expiry",
]
LIFECYCLE_ORDER_CSV_COLUMNS = [
    "id", "managed_certificate_id", "action", "status", "attempts",
    "approved_by", "approved_at", "error", "created_at", "updated_at",
]
AUDIT_CSV_COLUMNS = [
    "id", "actor", "action", "entity", "entity_id", "detail", "created_at",
]
FINDING_CSV_COLUMNS = [
    "id", "rule_id", "severity", "certificate_id", "endpoint_id", "title",
    "disposition", "status", "first_seen", "last_seen",
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    if engine.dialect.name == "sqlite":
        # Dev/test: fast, and conftest/tests rely on create_all semantics.
        init_db()
    else:
        # Prod (Postgres): schema changes go through versioned Alembic
        # migrations, not create_all(). Handles both a fresh DB and a
        # pre-Phase-0 DB that predates Alembic (see run_migrations()).
        run_migrations()
    if not os.environ.get("CERTWATCH_SESSION_SECRET") and settings.cookie_secure:
        log.warning(
            "CERTWATCH_SESSION_SECRET is not set; sessions are using an ephemeral "
            "per-process secret and will not survive a restart or work across "
            "multiple replicas. Set CERTWATCH_SESSION_SECRET in production."
        )
    _seed_settings()
    if settings.enable_scheduler:
        start_scheduler()
    worker_stop_event = None
    worker_thread = None
    if settings.embedded_worker:
        # One-container dev/SQLite quickstart: drain the queue in-process
        # instead of requiring the dedicated `worker` service (see
        # docker-compose.yml, CERTWATCH_EMBEDDED_WORKER=false in prod).
        worker_stop_event = threading.Event()
        worker_thread = threading.Thread(
            target=worker_lib.run_forever,
            kwargs={"stop_event": worker_stop_event},
            daemon=True,
        )
        worker_thread.start()
        log.info("embedded worker thread started")
    yield
    if worker_stop_event is not None:
        worker_stop_event.set()
    shutdown_scheduler()


app = FastAPI(title="CertWatch", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    https_only=settings.cookie_secure,
    same_site="lax",
)
app.include_router(auth_router)

# GET /metrics: Prometheus text exposition (default HTTP metrics + CertWatch
# gauges from app/metrics.py). Deliberately unauthenticated -- restrict access
# at the network layer (firewall/reverse-proxy allowlist) in production.
setup_metrics(app)


def _seed_settings() -> None:
    from .db import SessionLocal
    db = SessionLocal()
    try:
        for key, value in DEFAULT_SETTINGS.items():
            if db.get(SystemSetting, key) is None:
                db.add(SystemSetting(key=key, value={"value": value}))
        db.commit()
    finally:
        db.close()


def audit(db: Session, actor: str, action: str, entity: str, entity_id, detail: str = "") -> None:
    db.add(AuditLog(actor=actor, action=action, entity=entity, entity_id=str(entity_id), detail=detail))


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #
@app.get("/api/health")
def health():
    return {"status": "ok", "service": "certwatch"}


# --------------------------------------------------------------------------- #
# Targets
# --------------------------------------------------------------------------- #
def _target_out(db: Session, t: Target) -> dict:
    count = db.scalar(select(func.count(Endpoint.id)).where(Endpoint.target_id == t.id)) or 0
    out = schemas.TargetOut.model_validate(t).model_dump()
    out["endpoint_count"] = count
    return out


@app.get("/api/targets", dependencies=[Depends(require_role("viewer"))])
def list_targets(db: Session = Depends(get_db)):
    return [_target_out(db, t) for t in db.scalars(select(Target).order_by(Target.name)).all()]


@app.post("/api/targets/validate", dependencies=[Depends(require_role("viewer"))])
def validate_target(body: schemas.TargetIn):
    try:
        count = target_lib.validate(body.target_type, body.value, settings.max_cidr_hosts)
        ports = target_lib.normalize_ports(body.ports, settings.default_ports)
    except target_lib.TargetError as e:
        raise HTTPException(status_code=400, detail=str(e))
    endpoints = count * len(ports)
    return {
        "host_count": count,
        "port_count": len(ports),
        "endpoint_count": endpoints,
        "large_scan": endpoints > 256,
    }


@app.post("/api/targets", status_code=201)
def create_target(
    body: schemas.TargetIn,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    try:
        target_lib.validate(body.target_type, body.value, settings.max_cidr_hosts)
        ports = target_lib.normalize_ports(body.ports, settings.default_ports)
    except target_lib.TargetError as e:
        raise HTTPException(status_code=400, detail=str(e))
    data = body.model_dump()
    data["ports"] = ports
    t = Target(**data)
    db.add(t)
    db.flush()
    audit(db, principal["email"], "target.create", "target", t.id, t.name)
    db.commit()
    return _target_out(db, t)


@app.get("/api/targets/{target_id}", dependencies=[Depends(require_role("viewer"))])
def get_target(target_id: int, db: Session = Depends(get_db)):
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(404, "target not found")
    return _target_out(db, t)


@app.put("/api/targets/{target_id}")
def update_target(
    target_id: int,
    body: schemas.TargetIn,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(404, "target not found")
    try:
        target_lib.validate(body.target_type, body.value, settings.max_cidr_hosts)
        ports = target_lib.normalize_ports(body.ports, settings.default_ports)
    except target_lib.TargetError as e:
        raise HTTPException(status_code=400, detail=str(e))
    for k, v in body.model_dump().items():
        setattr(t, k, v)
    t.ports = ports
    audit(db, principal["email"], "target.update", "target", t.id, t.name)
    db.commit()
    return _target_out(db, t)


@app.delete("/api/targets/{target_id}", status_code=204)
def delete_target(
    target_id: int,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(404, "target not found")
    audit(db, principal["email"], "target.delete", "target", t.id, t.name)
    db.delete(t)
    db.commit()


# --------------------------------------------------------------------------- #
# Scan jobs
# --------------------------------------------------------------------------- #
@app.post("/api/targets/{target_id}/scan", status_code=202)
def start_scan(
    target_id: int,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(404, "target not found")
    job = enqueue_scan(db, t, trigger="manual")
    audit(db, principal["email"], "scan.start", "scan_job", job.id, t.name)
    db.commit()
    return schemas.ScanJobOut.model_validate(job).model_dump()


@app.post("/api/scans/{job_id}/cancel")
def cancel_scan(
    job_id: int,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    job = db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(404, "scan job not found")
    if job.status in ("pending", "running"):
        job.cancel_requested = True
        audit(db, principal["email"], "scan.cancel", "scan_job", job.id)
        db.commit()
    return schemas.ScanJobOut.model_validate(job).model_dump()


@app.get("/api/scans", dependencies=[Depends(require_role("viewer"))])
def list_scans(limit: int = Query(50, le=500), db: Session = Depends(get_db)):
    jobs = db.scalars(select(ScanJob).order_by(ScanJob.id.desc()).limit(limit)).all()
    return [schemas.ScanJobOut.model_validate(j).model_dump() for j in jobs]


@app.get("/api/scans/{job_id}", dependencies=[Depends(require_role("viewer"))])
def get_scan(job_id: int, db: Session = Depends(get_db)):
    job = db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(404, "scan job not found")
    return schemas.ScanJobOut.model_validate(job).model_dump()


# --------------------------------------------------------------------------- #
# Certificates (deduplicated by fingerprint)
# --------------------------------------------------------------------------- #
@app.get("/api/certificates", dependencies=[Depends(require_role("viewer"))])
def list_certificates(
    q: str = "",
    expiring_within: int | None = None,
    expired: bool | None = None,
    self_signed: bool | None = None,
    internal: bool | None = None,
    issuer: str = "",
    sort: str = "not_after",
    limit: int = Query(100, le=1000),
    offset: int = 0,
    format: str = "json",
    db: Session = Depends(get_db),
):
    stmt = select(Certificate)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(
            func.lower(Certificate.common_name).like(like),
            func.lower(Certificate.fingerprint_sha256).like(like),
            func.lower(Certificate.issuer).like(like),
            func.lower(cast(Certificate.sans, String)).like(like),
        ))
    if issuer:
        stmt = stmt.where(func.lower(Certificate.issuer_cn).like(f"%{issuer.lower()}%"))
    if self_signed is not None:
        stmt = stmt.where(Certificate.self_signed.is_(self_signed))
    if internal is not None:
        internal_cond = or_(
            Certificate.self_signed.is_(True),
            *[func.lower(Certificate.issuer).like(f"%{p.lower()}%")
              for p in settings.internal_ca_pattern_list],
        )
        stmt = stmt.where(internal_cond if internal else ~internal_cond)
    now = utcnow()
    if expired:
        stmt = stmt.where(Certificate.not_after < now)
    if expiring_within is not None:
        stmt = stmt.where(Certificate.not_after >= now,
                          Certificate.not_after <= now + timedelta(days=expiring_within))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    order = Certificate.not_after.asc() if sort == "not_after" else Certificate.common_name.asc()
    rows = db.scalars(stmt.order_by(order).limit(limit).offset(offset)).all()
    items = [cert_dict(db, c) for c in rows]
    if format == "csv":
        csv_text = rows_to_csv(CERTIFICATE_CSV_COLUMNS, items)
        return Response(content=csv_text, media_type="text/csv",
                         headers={"Content-Disposition": 'attachment; filename="certificates.csv"'})
    return {"total": total, "items": items}


@app.get("/api/certificates/{cert_id}", dependencies=[Depends(require_role("viewer"))])
def get_certificate(cert_id: int, db: Session = Depends(get_db)):
    c = db.get(Certificate, cert_id)
    if not c:
        raise HTTPException(404, "certificate not found")
    out = cert_dict(db, c, with_endpoints=True)
    # observation history across all endpoints bound to this cert
    obs = db.scalars(
        select(CertificateObservation)
        .where(CertificateObservation.certificate_id == cert_id)
        .order_by(CertificateObservation.observed_at.desc()).limit(200)
    ).all()
    out["observations"] = [observation_dict(o) for o in obs]
    return out


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
@app.get("/api/endpoints", dependencies=[Depends(require_role("viewer"))])
def list_endpoints(
    q: str = "",
    status: str = "",
    environment: str = "",
    owner: str = "",
    port: int | None = None,
    failed: bool | None = None,
    limit: int = Query(200, le=2000),
    offset: int = 0,
    format: str = "json",
    db: Session = Depends(get_db),
):
    stmt = select(Endpoint)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(
            func.lower(Endpoint.host).like(like),
            func.lower(Endpoint.ip).like(like),
        ))
    if status:
        stmt = stmt.where(Endpoint.last_status == status)
    if failed is True:
        stmt = stmt.where(Endpoint.last_status != "ok", Endpoint.last_status != "")
    elif failed is False:
        stmt = stmt.where(Endpoint.last_status == "ok")  # hide failed/unscanned
    if port:
        stmt = stmt.where(Endpoint.port == port)
    if environment or owner:
        stmt = stmt.join(Target, Endpoint.target_id == Target.id)
        if environment:
            stmt = stmt.where(Target.environment == environment)
        if owner:
            stmt = stmt.where(func.lower(Target.owner).like(f"%{owner.lower()}%"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(Endpoint.id.desc()).limit(limit).offset(offset)).all()
    items = [endpoint_dict(db, e, with_cert=False) for e in rows]
    if format == "csv":
        csv_text = rows_to_csv(ENDPOINT_CSV_COLUMNS, items)
        return Response(content=csv_text, media_type="text/csv",
                         headers={"Content-Disposition": 'attachment; filename="endpoints.csv"'})
    return {"total": total, "items": items}


@app.get("/api/endpoints/{endpoint_id}", dependencies=[Depends(require_role("viewer"))])
def get_endpoint(endpoint_id: int, db: Session = Depends(get_db)):
    ep = db.get(Endpoint, endpoint_id)
    if not ep:
        raise HTTPException(404, "endpoint not found")
    out = endpoint_dict(db, ep, with_cert=True)
    obs = db.scalars(
        select(CertificateObservation)
        .where(CertificateObservation.endpoint_id == endpoint_id)
        .order_by(CertificateObservation.observed_at.desc()).limit(100)
    ).all()
    out["observations"] = [observation_dict(o) for o in obs]
    return out


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #
def _alert_dict(db: Session, ev: AlertEvent) -> dict:
    ep = db.get(Endpoint, ev.endpoint_id) if ev.endpoint_id else None
    cert = db.get(Certificate, ev.certificate_id) if ev.certificate_id else None
    return {
        "id": ev.id,
        "rule_type": ev.rule_type,
        "severity": ev.severity,
        "threshold_days": ev.threshold_days,
        "message": ev.message,
        "endpoint_id": ev.endpoint_id,
        "endpoint": f"{ep.host or ep.ip}:{ep.port}" if ep else "",
        "certificate_id": ev.certificate_id,
        "common_name": cert.common_name if cert else "",
        "acknowledged": ev.acknowledged,
        "muted": ev.muted,
        "muted_until": ev.muted_until,
        "resolved": ev.resolved,
        "notify_count": ev.notify_count,
        "last_notified_at": ev.last_notified_at,
        "created_at": ev.created_at,
    }


@app.get("/api/alerts", dependencies=[Depends(require_role("viewer"))])
def list_alerts(include_resolved: bool = False, db: Session = Depends(get_db)):
    stmt = select(AlertEvent).order_by(AlertEvent.updated_at.desc())
    if not include_resolved:
        stmt = stmt.where(AlertEvent.resolved.is_(False))
    return [_alert_dict(db, e) for e in db.scalars(stmt).all()]


@app.post("/api/alerts/{alert_id}/ack")
def ack_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    ev = db.get(AlertEvent, alert_id)
    if not ev:
        raise HTTPException(404, "alert not found")
    ev.acknowledged = True
    audit(db, principal["email"], "alert.ack", "alert_event", ev.id)
    db.commit()
    return _alert_dict(db, ev)


@app.post("/api/alerts/{alert_id}/mute")
def mute_alert(
    alert_id: int,
    body: schemas.AlertActionIn,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    ev = db.get(AlertEvent, alert_id)
    if not ev:
        raise HTTPException(404, "alert not found")
    ev.muted = True
    ev.muted_until = utcnow() + timedelta(hours=body.mute_hours) if body.mute_hours else None
    audit(db, principal["email"], "alert.mute", "alert_event", ev.id)
    db.commit()
    return _alert_dict(db, ev)


@app.post("/api/alerts/{alert_id}/unmute")
def unmute_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    ev = db.get(AlertEvent, alert_id)
    if not ev:
        raise HTTPException(404, "alert not found")
    ev.muted = False
    ev.muted_until = None
    audit(db, principal["email"], "alert.unmute", "alert_event", ev.id)
    db.commit()
    return _alert_dict(db, ev)


@app.post("/api/alerts/evaluate", dependencies=[Depends(require_role("operator"))])
def evaluate(db: Session = Depends(get_db)):
    return evaluate_alerts(db)


# --------------------------------------------------------------------------- #
# Findings (crypto-risk rules engine, Phase 2 Task 3)
# --------------------------------------------------------------------------- #
def finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "rule_id": f.rule_id,
        "severity": f.severity,
        "certificate_id": f.certificate_id,
        "endpoint_id": f.endpoint_id,
        "title": f.title,
        "detail": f.detail,
        "dedupe_key": f.dedupe_key,
        "disposition": f.disposition,
        "status": f.status,
        "first_seen": f.first_seen,
        "last_seen": f.last_seen,
        "created_at": f.created_at,
        "updated_at": f.updated_at,
    }


@app.get("/api/findings", dependencies=[Depends(require_role("viewer"))])
def list_findings(
    rule_id: str = "",
    severity: str = "",
    disposition: str = "",
    status: str = "active",
    q: str = "",
    format: str = "json",
    limit: int = Query(100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db),
):
    stmt = select(Finding)
    if rule_id:
        stmt = stmt.where(Finding.rule_id == rule_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if disposition:
        stmt = stmt.where(Finding.disposition == disposition)
    if status:
        stmt = stmt.where(Finding.status == status)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(
            func.lower(Finding.title).like(like),
            func.lower(Finding.detail).like(like),
        ))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(Finding.severity.asc(), Finding.id.desc()).limit(limit).offset(offset)
    ).all()
    items = [finding_dict(f) for f in rows]
    if format == "csv":
        csv_text = rows_to_csv(FINDING_CSV_COLUMNS, items)
        return Response(content=csv_text, media_type="text/csv",
                         headers={"Content-Disposition": 'attachment; filename="findings.csv"'})
    return {"total": total, "items": items}


@app.get("/api/findings/{finding_id}", dependencies=[Depends(require_role("viewer"))])
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    return finding_dict(f)


@app.post("/api/findings/{finding_id}/disposition")
def set_finding_disposition(
    finding_id: int,
    body: schemas.FindingDispositionIn,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    f.disposition = body.disposition
    audit(db, principal["email"], "finding.disposition", "finding", f.id, body.disposition)
    db.commit()
    return finding_dict(f)


@app.post("/api/findings/evaluate")
def evaluate_findings(
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    active = findings.evaluate_all(db)
    audit(db, principal["email"], "finding.evaluate", "finding", "-", str(active))
    db.commit()
    return {"active": active}


# --------------------------------------------------------------------------- #
# Notification channels
# --------------------------------------------------------------------------- #
_SECRET_KEYS = {"password", "url"}


def _encrypt_secrets(config: dict) -> dict:
    """Encrypt secret-shaped values (password, url) that aren't already encrypted.

    Raises SecretsNotConfigured (via app.secrets.encrypt) if CERTWATCH_MASTER_KEY
    isn't set and a plaintext secret needs encrypting.
    """
    out = dict(config or {})
    for k in _SECRET_KEYS:
        v = out.get(k)
        if v and not is_encrypted(v):
            out[k] = encrypt_secret(v)
    return out


def _channel_out(ch: NotificationChannel) -> dict:
    summary = {k: v for k, v in (ch.config or {}).items() if k not in _SECRET_KEYS}
    if "url" in (ch.config or {}):
        summary["url_set"] = bool(ch.config.get("url"))
    if "password" in (ch.config or {}):
        summary["password_set"] = bool(ch.config.get("password"))
    return {
        "id": ch.id, "name": ch.name, "channel_type": ch.channel_type,
        "enabled": ch.enabled, "re_alert_hours": ch.re_alert_hours, "config_summary": summary,
    }


@app.get("/api/channels", dependencies=[Depends(require_role("viewer"))])
def list_channels(db: Session = Depends(get_db)):
    return [_channel_out(c) for c in db.scalars(select(NotificationChannel)).all()]


@app.post("/api/channels", status_code=201)
def create_channel(
    body: schemas.ChannelIn,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    data = body.model_dump()
    try:
        data["config"] = _encrypt_secrets(data.get("config") or {})
    except SecretsNotConfigured as e:
        raise HTTPException(400, str(e))
    ch = NotificationChannel(**data)
    db.add(ch)
    db.flush()
    audit(db, principal["email"], "channel.create", "channel", ch.id, ch.name)
    db.commit()
    return _channel_out(ch)


@app.put("/api/channels/{channel_id}")
def update_channel(
    channel_id: int,
    body: schemas.ChannelIn,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    ch = db.get(NotificationChannel, channel_id)
    if not ch:
        raise HTTPException(404, "channel not found")
    # Merge config so a blank secret doesn't wipe an existing one.
    new_config = dict(ch.config or {})
    for k, v in body.config.items():
        if k in _SECRET_KEYS and v == "":
            continue  # keep existing secret
        new_config[k] = v
    try:
        new_config = _encrypt_secrets(new_config)
    except SecretsNotConfigured as e:
        raise HTTPException(400, str(e))
    ch.name, ch.channel_type, ch.enabled, ch.re_alert_hours = (
        body.name, body.channel_type, body.enabled, body.re_alert_hours)
    ch.config = new_config
    audit(db, principal["email"], "channel.update", "channel", ch.id, ch.name)
    db.commit()
    return _channel_out(ch)


@app.delete("/api/channels/{channel_id}", status_code=204)
def delete_channel(
    channel_id: int,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    ch = db.get(NotificationChannel, channel_id)
    if not ch:
        raise HTTPException(404, "channel not found")
    audit(db, principal["email"], "channel.delete", "channel", ch.id, ch.name)
    db.delete(ch)
    db.commit()


@app.post("/api/channels/{channel_id}/test", dependencies=[Depends(require_role("operator"))])
def test_channel(channel_id: int, db: Session = Depends(get_db)):
    ch = db.get(NotificationChannel, channel_id)
    if not ch:
        raise HTTPException(404, "channel not found")
    try:
        if ch.channel_type == "smtp":
            send_email(ch.config, "CertWatch test email",
                       "This is a test notification from CertWatch. SMTP is configured correctly.")
        else:
            send_webhook(ch.config, "CertWatch test notification",
                         "This is a test notification from CertWatch. The webhook is configured correctly.",
                         {"Channel": ch.name}, _base_url(db))
    except NotifyError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "sent"}


# --------------------------------------------------------------------------- #
# Issuers (CA integrations: AD CS, ACME)
# --------------------------------------------------------------------------- #
# Which config keys are secret, per issuer type. Everything else in `config`
# is considered non-sensitive and echoed back as-is (e.g. contact_email).
_ISSUER_SECRET_KEYS = {
    "adcs": {"username", "password"},
    "acme": {"account_key_pem"},
}


def _encrypt_issuer_secrets(issuer_type: str, config: dict) -> dict:
    """Encrypt secret-shaped values for this issuer type that aren't already
    encrypted. Raises SecretsNotConfigured (via app.secrets.encrypt) if
    CERTWATCH_MASTER_KEY isn't set and a plaintext secret needs encrypting."""
    secret_keys = _ISSUER_SECRET_KEYS.get(issuer_type, set())
    out = dict(config or {})
    for k in secret_keys:
        v = out.get(k)
        if v and not is_encrypted(v):
            out[k] = encrypt_secret(v)
    return out


def _issuer_out(issuer: Issuer) -> dict:
    secret_keys = _ISSUER_SECRET_KEYS.get(issuer.issuer_type, set())
    config = issuer.config or {}
    summary = {k: v for k, v in config.items() if k not in secret_keys}
    for k in secret_keys:
        if k in config:
            summary[f"{k}_set"] = bool(config.get(k))
    return {
        "id": issuer.id,
        "name": issuer.name,
        "issuer_type": issuer.issuer_type,
        "enabled": issuer.enabled,
        "last_test_at": issuer.last_test_at,
        "last_test_ok": issuer.last_test_ok,
        "created_at": issuer.created_at,
        "config": summary,
    }


@app.get("/api/issuers", dependencies=[Depends(require_role("viewer"))])
def list_issuers(db: Session = Depends(get_db)):
    return [_issuer_out(i) for i in db.scalars(select(Issuer)).all()]


@app.post("/api/issuers", status_code=201)
def create_issuer(
    body: schemas.IssuerIn,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("admin")),
):
    data = body.model_dump()
    if data["issuer_type"] not in _ISSUER_SECRET_KEYS:
        raise HTTPException(400, "unknown issuer type")
    try:
        data["config"] = _encrypt_issuer_secrets(data["issuer_type"], data.get("config") or {})
    except SecretsNotConfigured as e:
        raise HTTPException(400, str(e))
    issuer = Issuer(**data)
    db.add(issuer)
    db.flush()
    audit(db, principal["email"], "issuer.create", "issuer", issuer.id, issuer.name)
    db.commit()
    return _issuer_out(issuer)


@app.put("/api/issuers/{issuer_id}")
def update_issuer(
    issuer_id: int,
    body: schemas.IssuerIn,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("admin")),
):
    issuer = db.get(Issuer, issuer_id)
    if not issuer:
        raise HTTPException(404, "issuer not found")
    if body.issuer_type != issuer.issuer_type:
        raise HTTPException(400, "cannot change issuer type")
    if body.issuer_type not in _ISSUER_SECRET_KEYS:
        raise HTTPException(400, "unknown issuer type")
    secret_keys = _ISSUER_SECRET_KEYS.get(body.issuer_type, set())
    # Merge config so a blank secret field doesn't wipe an existing one.
    new_config = dict(issuer.config or {})
    for k, v in (body.config or {}).items():
        if k in secret_keys and v == "":
            continue  # keep existing secret
        new_config[k] = v
    try:
        new_config = _encrypt_issuer_secrets(body.issuer_type, new_config)
    except SecretsNotConfigured as e:
        raise HTTPException(400, str(e))
    issuer.name, issuer.enabled = body.name, body.enabled
    issuer.config = new_config
    audit(db, principal["email"], "issuer.update", "issuer", issuer.id, issuer.name)
    db.commit()
    return _issuer_out(issuer)


@app.delete("/api/issuers/{issuer_id}", status_code=204)
def delete_issuer(
    issuer_id: int,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("admin")),
):
    issuer = db.get(Issuer, issuer_id)
    if not issuer:
        raise HTTPException(404, "issuer not found")
    audit(db, principal["email"], "issuer.delete", "issuer", issuer.id, issuer.name)
    db.delete(issuer)
    db.commit()


@app.post("/api/issuers/{issuer_id}/test")
def test_issuer(
    issuer_id: int,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    issuer = db.get(Issuer, issuer_id)
    if not issuer:
        raise HTTPException(404, "issuer not found")
    ok = True
    detail = "connection ok"
    try:
        get_adapter(issuer).test_connection()
    except IssuerError as e:
        ok = False
        detail = str(e)
    issuer.last_test_at = utcnow()
    issuer.last_test_ok = ok
    audit(db, principal["email"], "issuer.test", "issuer", issuer.id, detail)
    db.commit()
    return {"ok": ok, "detail": detail}


# --------------------------------------------------------------------------- #
# Renewal policies + managed certificates (lifecycle management, Phase 1)
# --------------------------------------------------------------------------- #
@app.get("/api/renewal-policies", dependencies=[Depends(require_role("viewer"))])
def list_renewal_policies(db: Session = Depends(get_db)):
    rows = db.scalars(select(RenewalPolicy)).all()
    return [schemas.RenewalPolicyOut.model_validate(p).model_dump() for p in rows]


@app.post("/api/renewal-policies", status_code=201)
def create_renewal_policy(
    body: schemas.RenewalPolicyIn,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    policy = RenewalPolicy(**body.model_dump())
    db.add(policy)
    db.flush()
    audit(db, principal["email"], "renewal_policy.create", "renewal_policy", policy.id, policy.name)
    db.commit()
    return schemas.RenewalPolicyOut.model_validate(policy).model_dump()


def _managed_cert_out(db: Session, m: ManagedCertificate) -> dict:
    out = schemas.ManagedCertificateOut.model_validate(m).model_dump()
    if m.current_certificate_id:
        cert = db.get(Certificate, m.current_certificate_id)
        if cert:
            out["current_cert_common_name"] = cert.common_name
            out["current_cert_not_after"] = cert.not_after
    return out


def _require_issuer_and_policy(db: Session, issuer_id: int, renewal_policy_id: int) -> None:
    if not db.get(Issuer, issuer_id):
        raise HTTPException(400, "issuer not found")
    if not db.get(RenewalPolicy, renewal_policy_id):
        raise HTTPException(400, "renewal policy not found")


@app.get("/api/managed-certificates", dependencies=[Depends(require_role("viewer"))])
def list_managed_certificates(db: Session = Depends(get_db)):
    rows = db.scalars(select(ManagedCertificate)).all()
    return [_managed_cert_out(db, m) for m in rows]


@app.get("/api/managed-certificates/{managed_id}", dependencies=[Depends(require_role("viewer"))])
def get_managed_certificate(managed_id: int, db: Session = Depends(get_db)):
    m = db.get(ManagedCertificate, managed_id)
    if not m:
        raise HTTPException(404, "managed certificate not found")
    return _managed_cert_out(db, m)


@app.post("/api/managed-certificates", status_code=201)
def create_managed_certificate(
    body: schemas.ManagedCertificateIn,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    _require_issuer_and_policy(db, body.issuer_id, body.renewal_policy_id)
    m = ManagedCertificate(**body.model_dump())
    db.add(m)
    db.flush()
    audit(db, principal["email"], "managed_cert.create", "managed_certificate", m.id, m.common_name)
    db.commit()
    return _managed_cert_out(db, m)


@app.post("/api/certificates/{cert_id}/manage", status_code=201)
def promote_certificate(
    cert_id: int,
    body: schemas.ManageIn,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    cert = db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(404, "certificate not found")
    _require_issuer_and_policy(db, body.issuer_id, body.renewal_policy_id)
    m = ManagedCertificate(
        common_name=cert.common_name,
        sans=list(cert.sans or []),
        issuer_id=body.issuer_id,
        renewal_policy_id=body.renewal_policy_id,
        current_certificate_id=cert.id,
    )
    db.add(m)
    db.flush()
    audit(db, principal["email"], "managed_cert.promote", "managed_certificate", m.id, cert.common_name)
    db.commit()
    return _managed_cert_out(db, m)


@app.get(
    "/api/managed-certificates/{managed_id}/deployment-targets",
    dependencies=[Depends(require_role("viewer"))],
)
def list_deployment_targets_for_managed_cert(managed_id: int, db: Session = Depends(get_db)):
    """Read-only summary for the ManagedCerts detail view -- deliberately
    omits `config` (may hold keystore/PFX passwords or WinRM credentials,
    see DeploymentTarget's docstring) since there's no UI need to display it
    here, unlike Issuer.config which has an established scrub-and-mark
    convention (`_issuer_out`)."""
    if not db.get(ManagedCertificate, managed_id):
        raise HTTPException(404, "managed certificate not found")
    rows = db.scalars(
        select(DeploymentTarget).where(DeploymentTarget.managed_certificate_id == managed_id)
    ).all()
    return [
        {
            "id": t.id, "name": t.name, "kind": t.kind, "enabled": t.enabled,
            "last_deploy_at": t.last_deploy_at, "last_deploy_ok": t.last_deploy_ok,
            "managed_certificate_id": t.managed_certificate_id,
        }
        for t in rows
    ]


# --------------------------------------------------------------------------- #
# Lifecycle orders (Task 7): approval-gated issue/renew/revoke state machine
# --------------------------------------------------------------------------- #
LIFECYCLE_ACTIONS = {"issue", "renew", "revoke"}
# Revoke EXECUTION is out of Phase-1 scope (no worker dispatch path, no
# revoking/revoked states, and AD CS -- the primary CA -- doesn't support it).
# The two-person-rule governance mechanism in lifecycle.create_order/approve
# still fully supports revoke orders (e.g. seeded directly for tests or by a
# future admin tool); this route just refuses to CREATE one via the API so a
# real order can never get stuck dead-lettered in the work queue.
CREATABLE_ACTIONS = {"issue", "renew"}


@app.get("/api/lifecycle/orders", dependencies=[Depends(require_role("viewer"))])
def list_lifecycle_orders(format: str = "json", db: Session = Depends(get_db)):
    rows = db.scalars(select(LifecycleOrder).order_by(LifecycleOrder.id.desc())).all()
    items = [schemas.LifecycleOrderOut.model_validate(o).model_dump() for o in rows]
    if format == "csv":
        csv_text = rows_to_csv(LIFECYCLE_ORDER_CSV_COLUMNS, items)
        return Response(content=csv_text, media_type="text/csv",
                         headers={"Content-Disposition": 'attachment; filename="lifecycle-orders.csv"'})
    return items


@app.get("/api/lifecycle/orders/{order_id}", dependencies=[Depends(require_role("viewer"))])
def get_lifecycle_order(order_id: int, db: Session = Depends(get_db)):
    order = db.get(LifecycleOrder, order_id)
    if not order:
        raise HTTPException(404, "lifecycle order not found")
    return schemas.LifecycleOrderOut.model_validate(order).model_dump()


@app.post("/api/lifecycle/orders", status_code=201)
def create_lifecycle_order(
    body: schemas.LifecycleOrderIn,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    if body.action not in LIFECYCLE_ACTIONS:
        raise HTTPException(400, f"action must be one of {sorted(LIFECYCLE_ACTIONS)}")
    if body.action not in CREATABLE_ACTIONS:
        raise HTTPException(400, "revoke execution is not yet supported")
    managed_cert = db.get(ManagedCertificate, body.managed_certificate_id)
    if not managed_cert:
        raise HTTPException(404, "managed certificate not found")
    order, created = lifecycle.create_order(db, managed_cert, body.action, principal["email"])
    if created:
        audit(db, principal["email"], "lifecycle_order.create", "lifecycle_order", order.id, order.action)
    db.commit()
    return schemas.LifecycleOrderOut.model_validate(order).model_dump()


@app.post("/api/lifecycle/orders/{order_id}/approve")
def approve_lifecycle_order(
    order_id: int,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    order = db.get(LifecycleOrder, order_id)
    if not order:
        raise HTTPException(404, "lifecycle order not found")
    try:
        lifecycle.approve(db, order, principal["email"], is_admin=(principal["role"] == "admin"))
    except PermissionError:
        raise HTTPException(403, "revoke approval requires admin")
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(db, principal["email"], "lifecycle_order.approve", "lifecycle_order", order.id, order.status)
    db.commit()
    return schemas.LifecycleOrderOut.model_validate(order).model_dump()


@app.post("/api/lifecycle/orders/{order_id}/reject")
def reject_lifecycle_order(
    order_id: int,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    order = db.get(LifecycleOrder, order_id)
    if not order:
        raise HTTPException(404, "lifecycle order not found")
    try:
        lifecycle.reject(db, order, principal["email"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(db, principal["email"], "lifecycle_order.reject", "lifecycle_order", order.id, order.status)
    db.commit()
    return schemas.LifecycleOrderOut.model_validate(order).model_dump()


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #
def _base_url(db: Session) -> str:
    row = db.get(SystemSetting, "app_base_url")
    return row.value.get("value") if row else "http://localhost:5173"


@app.get("/api/settings", dependencies=[Depends(require_role("viewer"))])
def get_settings(db: Session = Depends(get_db)):
    rows = db.scalars(select(SystemSetting)).all()
    return {r.key: r.value.get("value") for r in rows}


@app.put("/api/settings")
def update_settings(
    body: dict,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    for key, value in body.items():
        row = db.get(SystemSetting, key)
        if row is None:
            db.add(SystemSetting(key=key, value={"value": value}))
        else:
            row.value = {"value": value}
    audit(db, principal["email"], "settings.update", "settings", "-", ",".join(body.keys()))
    db.commit()
    return get_settings(db)


# --------------------------------------------------------------------------- #
# Audit log (admin only)
# --------------------------------------------------------------------------- #
def _audit_dict(row: AuditLog) -> dict:
    return {
        "id": row.id,
        "actor": row.actor,
        "action": row.action,
        "entity": row.entity,
        "entity_id": row.entity_id,
        "detail": row.detail,
        "created_at": row.created_at,
    }


@app.get("/api/audit", dependencies=[Depends(require_role("admin"))])
def list_audit(
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    actor: str | None = None,
    entity: str | None = None,
    action: str | None = None,
    since: datetime | None = None,
    format: str = "json",
    db: Session = Depends(get_db),
):
    stmt = select(AuditLog)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    if entity:
        stmt = stmt.where(AuditLog.entity == entity)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if since:
        stmt = stmt.where(AuditLog.created_at >= since)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
    ).all()
    items = [_audit_dict(r) for r in rows]
    if format == "csv":
        csv_text = rows_to_csv(AUDIT_CSV_COLUMNS, items)
        return Response(content=csv_text, media_type="text/csv",
                         headers={"Content-Disposition": 'attachment; filename="audit.csv"'})
    return {"total": total, "items": items}


# --------------------------------------------------------------------------- #
# Scheduled reports (Phase 2, Task 5)
# --------------------------------------------------------------------------- #
def report_dict(s: ReportSchedule) -> dict:
    return {
        "id": s.id,
        "name": s.name,
        "report_type": s.report_type,
        "filter_params": s.filter_params,
        "format": s.format,
        "recipients": s.recipients,
        "channel_id": s.channel_id,
        "cadence": s.cadence,
        "schedule_time": s.schedule_time,
        "schedule_day": s.schedule_day,
        "enabled": s.enabled,
        "last_run_at": s.last_run_at,
        "created_at": s.created_at,
    }


@app.get("/api/reports", dependencies=[Depends(require_role("viewer"))])
def list_reports(db: Session = Depends(get_db)):
    rows = db.scalars(select(ReportSchedule).order_by(ReportSchedule.id.desc())).all()
    return [report_dict(s) for s in rows]


@app.post("/api/reports", status_code=201)
def create_report(
    body: schemas.ReportScheduleIn,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    if not db.get(NotificationChannel, body.channel_id):
        raise HTTPException(400, "notification channel not found")
    s = ReportSchedule(**body.model_dump())
    db.add(s)
    db.flush()
    audit(db, principal["email"], "report.create", "report", s.id, s.name)
    db.commit()
    return report_dict(s)


@app.put("/api/reports/{report_id}")
def update_report(
    report_id: int,
    body: schemas.ReportScheduleIn,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    s = db.get(ReportSchedule, report_id)
    if not s:
        raise HTTPException(404, "report schedule not found")
    if not db.get(NotificationChannel, body.channel_id):
        raise HTTPException(400, "notification channel not found")
    for k, v in body.model_dump().items():
        setattr(s, k, v)
    audit(db, principal["email"], "report.update", "report", s.id, s.name)
    db.commit()
    return report_dict(s)


@app.delete("/api/reports/{report_id}", status_code=204)
def delete_report(
    report_id: int,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    s = db.get(ReportSchedule, report_id)
    if not s:
        raise HTTPException(404, "report schedule not found")
    audit(db, principal["email"], "report.delete", "report", s.id, s.name)
    db.delete(s)
    db.commit()


@app.post("/api/reports/{report_id}/run")
def run_report(
    report_id: int,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_role("operator")),
):
    s = db.get(ReportSchedule, report_id)
    if not s:
        raise HTTPException(404, "report schedule not found")
    queue.enqueue(db, "report", {"schedule_id": s.id})
    audit(db, principal["email"], "report.run", "report", s.id, s.name)
    db.commit()
    return {"queued": True}


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #
@app.get("/api/dashboard", dependencies=[Depends(require_role("viewer"))])
def dashboard(db: Session = Depends(get_db)):
    now = utcnow()
    total_certs = db.scalar(select(func.count(Certificate.id))) or 0
    total_endpoints = db.scalar(select(func.count(Endpoint.id))) or 0

    def count_window(days):
        return db.scalar(select(func.count(Certificate.id)).where(
            Certificate.not_after >= now, Certificate.not_after <= now + timedelta(days=days))) or 0

    expired = db.scalar(select(func.count(Certificate.id)).where(Certificate.not_after < now)) or 0
    failed = db.scalar(select(func.count(Endpoint.id)).where(
        Endpoint.last_status != "ok", Endpoint.last_status != "")) or 0
    changed = db.scalar(select(func.count(CertificateObservation.id)).where(
        CertificateObservation.change_status == "changed",
        CertificateObservation.observed_at >= now - timedelta(days=7))) or 0
    open_alerts = db.scalar(select(func.count(AlertEvent.id)).where(AlertEvent.resolved.is_(False))) or 0

    last_ok = db.scalar(select(func.max(ScanJob.finished_at)).where(ScanJob.status == "completed"))
    next_target = db.scalars(select(Target).where(Target.enabled.is_(True))).all()
    next_scan = None
    for t in next_target:
        nxt = (t.last_scanned_at + timedelta(minutes=t.scan_frequency_minutes)) if t.last_scanned_at else now
        if next_scan is None or nxt < next_scan:
            next_scan = nxt

    # --- Lifecycle management metrics (Task 13) ---
    managed_certificates = db.scalar(select(func.count(ManagedCertificate.id))) or 0
    # "unmanaged" = observed Certificate rows that no ManagedCertificate
    # currently points to via current_certificate_id (a cert can only ever
    # be "current" for at most one ManagedCertificate).
    managed_cert_fk_ids = select(ManagedCertificate.current_certificate_id).where(
        ManagedCertificate.current_certificate_id.is_not(None)
    )
    unmanaged_certificates = db.scalar(
        select(func.count(Certificate.id)).where(Certificate.id.notin_(managed_cert_fk_ids))
    ) or 0

    orders_in_flight = db.scalar(
        select(func.count(LifecycleOrder.id)).where(
            LifecycleOrder.status.notin_(list(lifecycle.TERMINAL_STATES))
        )
    ) or 0
    orders_pending_approval = db.scalar(
        select(func.count(LifecycleOrder.id)).where(LifecycleOrder.status == "pending_approval")
    ) or 0

    since_30d = now - timedelta(days=30)
    renew_terminal_30d = db.scalar(
        select(func.count(LifecycleOrder.id)).where(
            LifecycleOrder.action == "renew",
            LifecycleOrder.status.in_(list(lifecycle.TERMINAL_STATES)),
            LifecycleOrder.updated_at >= since_30d,
        )
    ) or 0
    renew_complete_30d = db.scalar(
        select(func.count(LifecycleOrder.id)).where(
            LifecycleOrder.action == "renew",
            LifecycleOrder.status == "complete",
            LifecycleOrder.updated_at >= since_30d,
        )
    ) or 0
    renewal_success_rate_30d = (renew_complete_30d / renew_terminal_30d) if renew_terminal_30d else None

    # --- Findings risk metrics (Task 3) ---
    open_findings = db.scalar(
        select(func.count(Finding.id)).where(Finding.status == "active", Finding.disposition == "open")
    ) or 0
    severity_rows = db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.status == "active", Finding.disposition == "open")
        .group_by(Finding.severity)
    ).all()
    findings_by_severity = {sev: cnt for sev, cnt in severity_rows}

    return {
        "total_certificates": total_certs,
        "total_endpoints": total_endpoints,
        "expiring_90d": count_window(90),
        "expiring_30d": count_window(30),
        "expiring_7d": count_window(7),
        "expired": expired,
        "failed_scans": failed,
        "recently_changed": changed,
        "open_alerts": open_alerts,
        "last_successful_scan": last_ok,
        "next_scheduled_scan": next_scan,
        "managed_certificates": managed_certificates,
        "unmanaged_certificates": unmanaged_certificates,
        "orders_in_flight": orders_in_flight,
        "orders_pending_approval": orders_pending_approval,
        "renewal_success_rate_30d": renewal_success_rate_30d,
        "open_findings": open_findings,
        "findings_by_severity": findings_by_severity,
    }


# --------------------------------------------------------------------------- #
# ACME HTTP-01 challenge responder — PUBLIC (no auth), and must be registered
# before the SPA catch-all below or it would be swallowed by it.
# --------------------------------------------------------------------------- #
@app.get("/.well-known/acme-challenge/{token}")
def acme_challenge(token: str, db: Session = Depends(get_db)):
    challenge = db.get(AcmeChallenge, token)
    if challenge is None:
        raise HTTPException(status_code=404, detail="unknown challenge token")
    return PlainTextResponse(challenge.key_authorization)


# --------------------------------------------------------------------------- #
# Static frontend (production) — must be mounted last so /api wins.
# --------------------------------------------------------------------------- #
def _safe_static_path(static_dir: str, full_path: str) -> str | None:
    """Return an absolute path INSIDE static_dir for full_path, or None if it
    escapes (traversal) or isn't a real file."""
    if not full_path:
        return None
    root = os.path.realpath(static_dir)
    candidate = os.path.realpath(os.path.join(root, full_path))
    # candidate must be root itself or strictly within root
    if candidate != root and not candidate.startswith(root + os.sep):
        return None
    return candidate if os.path.isfile(candidate) else None


if settings.static_dir and os.path.isdir(settings.static_dir):
    static_dir = settings.static_dir

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        safe = _safe_static_path(static_dir, full_path)
        if safe:
            return FileResponse(safe)
        return FileResponse(os.path.join(static_dir, "index.html"))
