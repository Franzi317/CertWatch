"""Normalized SQLAlchemy data model.

Design notes:
- Certificates are deduplicated by SHA-256 fingerprint (one row per unique cert).
- Endpoints are unique by (host, ip, port) and point at their *current* cert.
- Every scan writes a CertificateObservation row — history is never overwritten,
  so a user can see exactly when a cert was replaced on an endpoint.
- Failed scans are recorded as observations too (status != "ok"); they are
  operationally useful and never discarded.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    # target_type: cidr | range | ip | hostname
    target_type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(512))
    ports: Mapped[list] = mapped_column(JSON, default=list)        # [443, 8443]
    environment: Mapped[str] = mapped_column(String(64), default="prod")
    owner: Mapped[str] = mapped_column(String(255), default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)         # ["pci", "edge"]
    # schedule_type: interval (use scan_frequency_minutes) | daily | weekly | monthly.
    # For calendar types, schedule_time is "HH:MM" in the app timezone; schedule_day is
    # the weekday (0=Mon..6=Sun) for weekly or day-of-month (1..28) for monthly.
    scan_frequency_minutes: Mapped[int] = mapped_column(Integer, default=1440)
    schedule_type: Mapped[str] = mapped_column(String(16), default="interval")
    schedule_time: Mapped[str] = mapped_column(String(5), default="00:00")
    schedule_day: Mapped[int] = mapped_column(Integer, default=0)
    timeout: Mapped[float] = mapped_column(Float, default=5.0)
    concurrency: Mapped[int] = mapped_column(Integer, default=50)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Days-before-expiry thresholds that trigger alerts.
    alert_thresholds: Mapped[list] = mapped_column(JSON, default=lambda: [90, 60, 30, 14, 7, 1])
    use_sni: Mapped[bool] = mapped_column(Boolean, default=True)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    endpoints: Mapped[list["Endpoint"]] = relationship(back_populates="target", cascade="all, delete-orphan")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id"))
    target_name: Mapped[str] = mapped_column(String(255), default="")
    # status: pending | running | completed | cancelled | failed
    status: Mapped[str] = mapped_column(String(32), default="pending")
    trigger: Mapped[str] = mapped_column(String(32), default="manual")  # manual | scheduled
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    total_endpoints: Mapped[int] = mapped_column(Integer, default=0)
    scanned_endpoints: Mapped[int] = mapped_column(Integer, default=0)
    certs_found: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (UniqueConstraint("host", "ip", "port", name="uq_endpoint"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id"))
    host: Mapped[str] = mapped_column(String(255), default="")   # hostname/FQDN or "" for raw IP
    ip: Mapped[str] = mapped_column(String(64), default="")
    port: Mapped[int] = mapped_column(Integer)
    sni: Mapped[str] = mapped_column(String(255), default="")
    current_cert_id: Mapped[int | None] = mapped_column(ForeignKey("certificates.id"))
    # last_status: ok | connection_failed | tls_handshake_failed | no_certificate |
    #              non_tls_service | timeout | dns_resolution_failed
    last_status: Mapped[str] = mapped_column(String(64), default="")
    last_error: Mapped[str] = mapped_column(Text, default="")
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    target: Mapped["Target"] = relationship(back_populates="endpoints")
    current_cert: Mapped["Certificate | None"] = relationship()


class Certificate(Base):
    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint_sha256: Mapped[str] = mapped_column(String(95), unique=True, index=True)
    common_name: Mapped[str] = mapped_column(String(255), default="")
    subject: Mapped[str] = mapped_column(Text, default="")
    sans: Mapped[list] = mapped_column(JSON, default=list)
    issuer: Mapped[str] = mapped_column(Text, default="")
    issuer_cn: Mapped[str] = mapped_column(String(255), default="")
    serial_number: Mapped[str] = mapped_column(String(128), default="")
    signature_algorithm: Mapped[str] = mapped_column(String(128), default="")
    public_key_algorithm: Mapped[str] = mapped_column(String(64), default="")
    public_key_size: Mapped[int | None] = mapped_column(Integer)
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    self_signed: Mapped[bool] = mapped_column(Boolean, default=False)
    is_wildcard: Mapped[bool] = mapped_column(Boolean, default=False)
    is_ca: Mapped[bool] = mapped_column(Boolean, default=False)
    chain_length: Mapped[int] = mapped_column(Integer, default=1)
    # network = observed on our network via a scan; ct = discovered in a
    # Certificate Transparency log for a WatchedDomain. ponytail: provenance of
    # first discovery only -- NOT flipped when a ct cert is later scanned; the
    # unknown_issuance finding clears off endpoint binding instead (findings.py).
    source: Mapped[str] = mapped_column(String(16), default="network")
    pem: Mapped[str] = mapped_column(Text, default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CertificateObservation(Base):
    """One row per endpoint per scan. Immutable history — never overwritten."""

    __tablename__ = "certificate_observations"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id"))
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), index=True)
    certificate_id: Mapped[int | None] = mapped_column(ForeignKey("certificates.id"))
    status: Mapped[str] = mapped_column(String(64))
    error: Mapped[str] = mapped_column(Text, default="")
    sni_used: Mapped[str] = mapped_column(String(255), default="")
    # change_status: new | unchanged | changed | first_seen
    change_status: Mapped[str] = mapped_column(String(32), default="")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class AlertEvent(Base):
    """Tracks alert state so we don't notify every scan. One event per
    (endpoint, cert, rule_type, threshold)."""

    __tablename__ = "alert_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    endpoint_id: Mapped[int | None] = mapped_column(ForeignKey("endpoints.id"))
    certificate_id: Mapped[int | None] = mapped_column(ForeignKey("certificates.id"))
    # rule_type: expiring | expired | changed | scan_failure | self_signed |
    #            renewal_failed | deploy_failed | order_stuck (Task 13)
    rule_type: Mapped[str] = mapped_column(String(32))
    threshold_days: Mapped[int | None] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(16), default="info")  # info|warning|critical
    message: Mapped[str] = mapped_column(Text, default="")
    dedupe_key: Mapped[str] = mapped_column(String(255), index=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    muted: Mapped[bool] = mapped_column(Boolean, default=False)
    muted_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    notify_count: Mapped[int] = mapped_column(Integer, default=0)
    last_notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    channel_type: Mapped[str] = mapped_column(String(32))  # smtp | teams | webhook
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Secrets (smtp password, webhook url) live here but are scrubbed from API output.
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    # Re-alert interval; an alert won't re-notify on this channel until elapsed.
    re_alert_hours: Mapped[int] = mapped_column(Integer, default=24)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SystemSetting(Base):
    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)


ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    # role: viewer | operator | admin (validated in the app layer, not the DB)
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    # source: entra | local
    source: Mapped[str] = mapped_column(String(16), default="entra")
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WorkQueue(Base):
    """Durable, Postgres-backed work queue. Workers claim rows with
    `queue.claim()` (SKIP LOCKED on Postgres), process the payload, then call
    `queue.complete()`/`queue.fail()`. Replaces in-process scan threads
    (wiring happens in a later task)."""

    __tablename__ = "work_queue"
    __table_args__ = (Index("ix_work_queue_status_priority_id", "status", "priority", "id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))  # "scan" in Phase 0
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    # status: queued | leased | done | failed
    status: Mapped[str] = mapped_column(String(16), default="queued")
    priority: Mapped[int] = mapped_column(Integer, default=0)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Issuer(Base):
    """A configured CA (AD CS or ACME) that certificate requests are issued
    against. `config` holds non-secret adapter fields plus secret fields the
    adapter encrypts/decrypts via `app.secrets` before use."""

    __tablename__ = "issuers"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    # issuer_type: adcs | acme
    issuer_type: Mapped[str] = mapped_column(String(16))
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_test_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RenewalPolicy(Base):
    """Rules governing how a ManagedCertificate is renewed: lead time, key
    material for the new cert, whether a human must approve before issuance,
    and post-deploy verification/retry behavior."""

    __tablename__ = "renewal_policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    renew_before_days: Mapped[int] = mapped_column(Integer, default=30)
    key_algorithm: Mapped[str] = mapped_column(String(16), default="rsa")
    key_size: Mapped[int] = mapped_column(Integer, default=2048)
    require_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    verify_after_deploy: Mapped[bool] = mapped_column(Boolean, default=True)
    max_retries: Mapped[int] = mapped_column(Integer, default=3)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ManagedCertificate(Base):
    """A lifecycle-managed certificate: created directly or by promoting an
    observed inventory `Certificate` (see `/api/certificates/{id}/manage` in
    main.py). References the observed cert via `current_certificate_id`
    rather than merging into it -- the inventory table stays the deduped
    scan artifact; this table is the operator-facing management record."""

    __tablename__ = "managed_certificates"

    id: Mapped[int] = mapped_column(primary_key=True)
    common_name: Mapped[str] = mapped_column(String(255), default="")
    sans: Mapped[list] = mapped_column(JSON, default=list)
    issuer_id: Mapped[int] = mapped_column(ForeignKey("issuers.id"))
    renewal_policy_id: Mapped[int] = mapped_column(ForeignKey("renewal_policies.id"))
    current_certificate_id: Mapped[int | None] = mapped_column(ForeignKey("certificates.id"))
    # Encrypted (app.secrets) PEM of the private key for current_certificate_id,
    # generated at issuance time (migration 0011). Needed by deployment (Task 9)
    # to build the PFX/PEM bundle -- never stored in plaintext.
    current_key_ref: Mapped[str] = mapped_column(Text, default="")
    # state: active | renewing | error | retired (validated in the app layer, not the DB)
    state: Mapped[str] = mapped_column(String(16), default="active")
    owner: Mapped[str] = mapped_column(String(255), default="")
    environment: Mapped[str] = mapped_column(String(64), default="prod")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class LifecycleOrder(Base):
    """A single issue/renew/revoke operation on a ManagedCertificate, driven
    through an approval-gated state machine (see `app.lifecycle`). Renewals
    are approval-gated by project decision; revoke requires admin approval
    (two-person rule) -- both enforced in `lifecycle.approve`, not here.

    `transitions` is an append-only audit trail of every status change:
    a list of `{"from", "to", "at", "detail"}` dicts."""

    __tablename__ = "lifecycle_orders"

    id: Mapped[int] = mapped_column(primary_key=True)
    managed_certificate_id: Mapped[int] = mapped_column(ForeignKey("managed_certificates.id"))
    # action: issue | renew | revoke
    action: Mapped[str] = mapped_column(String(8))
    # status: pending_approval | approved | queued | issuing | deploying |
    #         verifying | complete | failed | rolled_back (validated in the
    #         app layer via lifecycle.ALLOWED_TRANSITIONS, not the DB)
    status: Mapped[str] = mapped_column(String(20), default="pending_approval")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    approved_by: Mapped[str] = mapped_column(String(255), default="")
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str] = mapped_column(Text, default="")
    correlation_id: Mapped[str] = mapped_column(String(36), default="")
    transitions: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Partial unique index (matches migration 0010_open_order_unique_index
    # exactly): at most one OPEN (non-terminal) order per
    # (managed_certificate_id, action). This is what makes
    # lifecycle.create_order's idempotency race-safe -- declared here too so
    # SQLite dev/test DBs built via Base.metadata.create_all() get the same
    # guarantee as Postgres via the Alembic migration.
    __table_args__ = (
        Index(
            "uq_open_lifecycle_order",
            "managed_certificate_id", "action",
            unique=True,
            sqlite_where=text("status NOT IN ('complete','failed','rolled_back')"),
            postgresql_where=text("status NOT IN ('complete','failed','rolled_back')"),
        ),
    )


class DeploymentTarget(Base):
    """Where a ManagedCertificate's renewed material gets pushed once an
    order reaches `deploying` (Task 9). `kind` selects the connector
    (`app.deploy.get_connector`): `pem` writes plain PEM files to disk (this
    task); `pfx`/`jks`/`iis` (Tasks 10/11) build a PKCS12 keystore, a Java
    keystore, or push into IIS's certificate store, respectively.

    `config` holds connector-specific fields -- filesystem paths for `pem`,
    keystore path + password for `pfx`/`jks`, host/credential for `iis` --
    and MUST run secret fields (keystore/PFX passwords, WinRM creds) through
    `app.secrets` before storing them here, same convention as Issuer.config.
    """

    __tablename__ = "deployment_targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    # kind: pem | pfx | jks | iis (validated in the app layer, not the DB --
    # same convention as Issuer.issuer_type / ManagedCertificate.state)
    kind: Mapped[str] = mapped_column(String(8))
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    post_deploy_command: Mapped[str] = mapped_column(Text, default="")
    managed_certificate_id: Mapped[int] = mapped_column(ForeignKey("managed_certificates.id"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_deploy_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_deploy_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AcmeChallenge(Base):
    """Pending ACME HTTP-01 challenges. The public `/.well-known/acme-challenge/{token}`
    route (main.py) serves `key_authorization` for a row here; the ACME adapter
    inserts a row before answering each challenge and deletes it (best-effort)
    once the order finalizes."""

    __tablename__ = "acme_challenges"

    token: Mapped[str] = mapped_column(String(255), primary_key=True)
    key_authorization: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Finding(Base):
    """A crypto-risk condition detected on a Certificate (optionally scoped to
    an Endpoint for context-dependent rules like self_signed_prod). Upserted
    by `app.findings.evaluate_certificate` keyed on `dedupe_key`; a condition
    that stops firing is marked `status="cleared"` rather than deleted, so
    history and disposition survive re-evaluation."""

    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_dedupe_key", "dedupe_key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    # rule_id: weak_key | deprecated_signature | long_lifetime | self_signed_prod |
    #          untrusted_issuer_prod | expiring | expired
    rule_id: Mapped[str] = mapped_column(String(48))
    severity: Mapped[str] = mapped_column(String(16))  # info|warning|critical
    certificate_id: Mapped[int | None] = mapped_column(ForeignKey("certificates.id"))
    endpoint_id: Mapped[int | None] = mapped_column(ForeignKey("endpoints.id"))
    title: Mapped[str] = mapped_column(String(255))
    detail: Mapped[str] = mapped_column(Text, default="")
    dedupe_key: Mapped[str] = mapped_column(String(255))
    # disposition: open | accepted | resolved (operator-set, preserved across re-eval)
    disposition: Mapped[str] = mapped_column(String(16), default="open")
    # status: active | cleared (rule engine controlled -- active = condition
    # still present, cleared = no longer detected)
    status: Mapped[str] = mapped_column(String(16), default="active")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ReportSchedule(Base):
    """A recurring CSV report (Phase 2, Task 5): `reports.render` projects
    `report_type` (scoped by `filter_params`) to CSV on a calendar `cadence`
    and emails it through the referenced SMTP `NotificationChannel`.
    Ticked by `scheduler.report_tick` (reuses the same calendar-schedule
    helpers as Target's schedule_type), executed by
    `worker._process_report` -> `reports.run_schedule`."""

    __tablename__ = "report_schedules"
    __table_args__ = (Index("ix_report_schedules_enabled", "enabled"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    # report_type: certificates | expiring | findings | endpoints
    report_type: Mapped[str] = mapped_column(String(32))
    filter_params: Mapped[dict] = mapped_column(JSON, default=dict)
    format: Mapped[str] = mapped_column(String(8), default="csv")
    recipients: Mapped[list] = mapped_column(JSON, default=list)
    channel_id: Mapped[int] = mapped_column(ForeignKey("notification_channels.id"))
    # cadence: daily | weekly | monthly
    cadence: Mapped[str] = mapped_column(String(16), default="daily")
    schedule_time: Mapped[str] = mapped_column(String(5), default="08:00")
    schedule_day: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_created_at", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    actor: Mapped[str] = mapped_column(String(255), default="")  # acting user's email, "service-account", or "system"
    action: Mapped[str] = mapped_column(String(64))     # target.create, channel.update, ...
    entity: Mapped[str] = mapped_column(String(64))
    entity_id: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
