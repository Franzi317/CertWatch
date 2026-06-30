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
    Integer,
    String,
    Text,
    UniqueConstraint,
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
    scan_frequency_minutes: Mapped[int] = mapped_column(Integer, default=1440)
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
    # rule_type: expiring | expired | changed | scan_failure | self_signed
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


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    action: Mapped[str] = mapped_column(String(64))     # target.create, channel.update, ...
    entity: Mapped[str] = mapped_column(String(64))
    entity_id: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
