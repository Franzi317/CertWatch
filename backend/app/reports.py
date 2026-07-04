"""Scheduled CSV reports delivered by email (Phase 2, Task 5).

`render` projects one of the existing inventory tables (Certificate/
Endpoint/Finding) to CSV text, reusing `exports.rows_to_csv` and the same
enrichment helpers the list endpoints use (`serialize.cert_dict` /
`endpoint_dict`) rather than duplicating their query logic. `run_schedule`
renders + emails through the schedule's referenced SMTP NotificationChannel
and is what `worker._process_report` calls for a "report" queue item.

Deliberately does NOT import from `app.main` (main imports this module for
the `/api/reports` routes -- importing back would be circular). Column sets
are defined locally rather than shared with main.py's `*_CSV_COLUMNS`.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from . import notify
from .exports import rows_to_csv
from .models import Certificate, Endpoint, Finding, NotificationChannel, utcnow
from .serialize import cert_dict, endpoint_dict

CERTIFICATE_COLUMNS = [
    "id", "common_name", "issuer_cn", "not_before", "not_after",
    "public_key_algorithm", "public_key_size", "signature_algorithm",
    "self_signed", "fingerprint_sha256",
]
ENDPOINT_COLUMNS = [
    "id", "host", "ip", "port", "target_name", "environment", "owner",
    "last_status", "common_name", "issuer_cn", "not_after", "days_until_expiry",
]
FINDING_COLUMNS = [
    "id", "rule_id", "severity", "certificate_id", "endpoint_id", "title",
    "disposition", "status", "first_seen", "last_seen",
]

REPORT_TYPES = {"certificates", "expiring", "findings", "endpoints"}


def _finding_row(f: Finding) -> dict:
    return {
        "id": f.id,
        "rule_id": f.rule_id,
        "severity": f.severity,
        "certificate_id": f.certificate_id,
        "endpoint_id": f.endpoint_id,
        "title": f.title,
        "disposition": f.disposition,
        "status": f.status,
        "first_seen": f.first_seen,
        "last_seen": f.last_seen,
    }


def render(db, report_type: str, filter_params: dict) -> tuple[str, str]:
    """Query + flatten `report_type` (scoped by `filter_params`) and render
    it as CSV. Returns (filename, csv_text)."""
    filter_params = filter_params or {}
    now = utcnow()

    if report_type == "certificates":
        rows = db.scalars(select(Certificate)).all()
        items = [cert_dict(db, c) for c in rows]
        columns = CERTIFICATE_COLUMNS
    elif report_type == "expiring":
        within = filter_params.get("expiring_within", 30)
        stmt = select(Certificate).where(
            Certificate.not_after >= now,
            Certificate.not_after <= now + timedelta(days=within),
        )
        rows = db.scalars(stmt).all()
        items = [cert_dict(db, c) for c in rows]
        columns = CERTIFICATE_COLUMNS
    elif report_type == "findings":
        stmt = select(Finding).where(Finding.status == "active")
        severity = filter_params.get("severity")
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        rows = db.scalars(stmt).all()
        items = [_finding_row(f) for f in rows]
        columns = FINDING_COLUMNS
    elif report_type == "endpoints":
        rows = db.scalars(select(Endpoint)).all()
        items = [endpoint_dict(db, e, with_cert=False) for e in rows]
        columns = ENDPOINT_COLUMNS
    else:
        raise ValueError(f"unknown report_type: {report_type!r}")

    csv_text = rows_to_csv(columns, items)
    filename = f"{report_type}-{now.date().isoformat()}.csv"
    return filename, csv_text


def run_schedule(db, schedule) -> None:
    """Render `schedule` and email it through its referenced SMTP channel,
    then stamp `last_run_at`. Called by `worker._process_report`; any
    exception here is caught there and fails the queue item closed."""
    filename, csv_text = render(db, schedule.report_type, schedule.filter_params or {})

    channel = db.get(NotificationChannel, schedule.channel_id)
    if channel is None or channel.channel_type != "smtp":
        raise ValueError(
            f"report schedule {schedule.id} references channel {schedule.channel_id!r}, "
            "which is missing or not an smtp channel"
        )

    config = dict(channel.config or {})
    if schedule.recipients:
        config["recipients"] = schedule.recipients

    row_count = max(len(csv_text.splitlines()) - 1, 0)
    body_text = f"Attached: {filename} ({schedule.report_type} report, {row_count} rows)."
    notify.send_email(
        config,
        subject=f"CertWatch report: {schedule.name}",
        body_text=body_text,
        attachments=[(filename, csv_text)],
    )

    schedule.last_run_at = utcnow()
    db.commit()
