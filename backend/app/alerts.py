"""Alert rule evaluation, state tracking, and dispatch.

Anti-spam model: each distinct condition maps to a stable `dedupe_key`, stored as
one AlertEvent. We notify when an event is first created and then only again after
the channel re-alert interval elapses. Acknowledged / muted / resolved events are
never notified. As certs are renewed or scans recover, the matching events
auto-resolve so they stop firing.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    AlertEvent,
    Certificate,
    Endpoint,
    NotificationChannel,
    SystemSetting,
    Target,
    utcnow,
)
from .notify import NotifyError, send_email, send_webhook
from .status import days_until, expiry_phrase, severity

log = logging.getLogger("certwatch.alerts")

# Rule types that are raised one-off / event-driven (via `raise_alert` or
# `record_change_alert`) rather than recomputed every `evaluate_alerts` sweep.
# These must never be auto-resolved by the scan-derived reconciliation loop
# below, since they have no corresponding entry in `desired` -- resolving them
# there would silently prevent `dispatch_alerts` from ever sending them.
ONE_OFF_RULE_TYPES = {"changed", "renewal_failed", "deploy_failed", "order_stuck"}


def get_setting(db: Session, key: str, default):
    row = db.get(SystemSetting, key)
    return row.value.get("value", default) if row and isinstance(row.value, dict) else default


def _app_base_url(db: Session) -> str:
    return get_setting(db, "app_base_url", "http://localhost:5173")


def evaluate_alerts(db: Session, now: datetime | None = None, dispatch: bool = True) -> dict:
    """Recompute desired alerts from current state, reconcile with stored events,
    auto-resolve stale ones, then optionally dispatch. Returns a small summary."""
    now = now or utcnow()
    failure_threshold = int(get_setting(db, "scan_failure_threshold", 3))
    alert_on_self_signed = bool(get_setting(db, "alert_on_self_signed", False))

    desired: dict[str, dict] = {}
    endpoints = db.scalars(select(Endpoint)).all()
    for ep in endpoints:
        target = db.get(Target, ep.target_id) if ep.target_id else None
        thresholds = sorted(target.alert_thresholds) if (target and target.alert_thresholds) else [30, 7]

        if ep.last_status and ep.last_status != "ok" and ep.consecutive_failures >= failure_threshold:
            desired[f"scan_failure:{ep.id}"] = {
                "endpoint_id": ep.id, "certificate_id": None, "rule_type": "scan_failure",
                "threshold_days": None, "severity": "warning",
                "message": f"Scan has failed {ep.consecutive_failures} times: {ep.last_error or ep.last_status}",
            }

        cert = db.get(Certificate, ep.current_cert_id) if ep.current_cert_id else None
        if cert is None:
            continue

        days = days_until(cert.not_after, now)
        if days is not None and days < 0:
            desired[f"expired:{ep.id}:{cert.id}"] = {
                "endpoint_id": ep.id, "certificate_id": cert.id, "rule_type": "expired",
                "threshold_days": 0, "severity": "critical",
                "message": f"Certificate {cert.common_name or cert.fingerprint_sha256} {expiry_phrase(days)}",
            }
        elif days is not None:
            hit = [t for t in thresholds if days <= t]
            if hit:
                th = min(hit)
                desired[f"expiring:{ep.id}:{cert.id}:{th}"] = {
                    "endpoint_id": ep.id, "certificate_id": cert.id, "rule_type": "expiring",
                    "threshold_days": th, "severity": severity(days),
                    "message": f"Certificate {cert.common_name or cert.fingerprint_sha256} {expiry_phrase(days)} (threshold {th}d)",
                }

        if alert_on_self_signed and cert.self_signed:
            desired[f"self_signed:{ep.id}:{cert.id}"] = {
                "endpoint_id": ep.id, "certificate_id": cert.id, "rule_type": "self_signed",
                "threshold_days": None, "severity": "info",
                "message": f"Self-signed certificate observed: {cert.common_name or cert.fingerprint_sha256}",
            }

    existing = {e.dedupe_key: e for e in db.scalars(select(AlertEvent)).all()}

    created = 0
    for key, d in desired.items():
        ev = existing.get(key)
        if ev is None:
            db.add(AlertEvent(dedupe_key=key, resolved=False, **d))
            created += 1
        elif ev.resolved:
            # condition recurred — reopen and reset notification clock
            ev.resolved = False
            ev.notify_count = 0
            ev.last_notified_at = None
            ev.message, ev.severity = d["message"], d["severity"]
        else:
            ev.message, ev.severity = d["message"], d["severity"]

    # Auto-resolve events whose condition no longer holds (renewed certs, recovery).
    # One-off/event-driven alerts (see ONE_OFF_RULE_TYPES) are kept until
    # acknowledged (informational history / not part of this scan-derived sweep).
    resolved = 0
    for key, ev in existing.items():
        if key not in desired and not ev.resolved and ev.rule_type not in ONE_OFF_RULE_TYPES:
            ev.resolved = True
            resolved += 1

    db.commit()

    sent = dispatch_alerts(db, now) if dispatch else 0
    return {"created": created, "resolved": resolved, "notified": sent}


def raise_alert(
    db: Session,
    dedupe_key: str,
    rule_type: str,
    severity: str,
    message: str,
    certificate_id: int | None = None,
    endpoint_id: int | None = None,
) -> AlertEvent | None:
    """Create a one-off AlertEvent for a condition that isn't part of the
    periodic `evaluate_alerts` sweep (worker failures, stuck lifecycle
    orders, ...), deduped by `dedupe_key` the same way `evaluate_alerts`
    dedupes its own conditions -- one row per distinct condition, so calling
    this repeatedly for the same still-failing condition (e.g. a worker
    retrying the same order) never spams duplicate rows. `dispatch_alerts`
    picks the new row up on its normal cadence like any other alert; no new
    alert infrastructure. Returns the created AlertEvent, or None if one
    already existed (dedup fired -- condition already recorded)."""
    if db.scalar(select(AlertEvent).where(AlertEvent.dedupe_key == dedupe_key)):
        return None
    ev = AlertEvent(
        dedupe_key=dedupe_key,
        certificate_id=certificate_id,
        endpoint_id=endpoint_id,
        rule_type=rule_type,
        severity=severity,
        message=message,
    )
    db.add(ev)
    db.commit()
    return ev


def record_change_alert(db: Session, endpoint: Endpoint, cert: Certificate) -> None:
    """Called when an endpoint's cert fingerprint changes between scans."""
    key = f"changed:{endpoint.id}:{cert.id}"
    if db.scalar(select(AlertEvent).where(AlertEvent.dedupe_key == key)):
        return
    db.add(AlertEvent(
        dedupe_key=key, endpoint_id=endpoint.id, certificate_id=cert.id,
        rule_type="changed", severity="info",
        message=f"Certificate changed since previous scan on {endpoint.host or endpoint.ip}:{endpoint.port}",
    ))
    db.commit()


def dispatch_alerts(db: Session, now: datetime | None = None) -> int:
    now = now or utcnow()
    channels = db.scalars(select(NotificationChannel).where(NotificationChannel.enabled.is_(True))).all()
    if not channels:
        return 0
    re_alert = timedelta(hours=min(c.re_alert_hours for c in channels))

    pending = db.scalars(select(AlertEvent).where(
        AlertEvent.resolved.is_(False),
        AlertEvent.acknowledged.is_(False),
    )).all()

    sent = 0
    for ev in pending:
        if ev.muted and (ev.muted_until is None or ev.muted_until > now):
            continue
        if ev.notify_count > 0 and ev.last_notified_at and (now - _aware(ev.last_notified_at)) < re_alert:
            continue
        subject, text, html, facts, link = _format(db, ev)
        delivered = False
        for ch in channels:
            try:
                if ch.channel_type == "smtp":
                    send_email(ch.config, subject, text, html)
                else:
                    send_webhook(ch.config, subject, text, facts, link)
                delivered = True
            except NotifyError as e:
                log.warning("channel %s failed for alert %s: %s", ch.name, ev.id, e)
        if delivered:
            ev.notify_count += 1
            ev.last_notified_at = now
            sent += 1
    db.commit()
    return sent


def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _format(db: Session, ev: AlertEvent):
    ep = db.get(Endpoint, ev.endpoint_id) if ev.endpoint_id else None
    cert = db.get(Certificate, ev.certificate_id) if ev.certificate_id else None
    target = db.get(Target, ep.target_id) if (ep and ep.target_id) else None
    base = _app_base_url(db)

    where = f"{ep.host or ep.ip}:{ep.port}" if ep else "unknown endpoint"
    cn = cert.common_name if cert else ""
    sans = ", ".join(cert.sans) if cert else ""
    days = days_until(cert.not_after) if cert else None
    link = f"{base}/certificates/{cert.id}" if cert else (f"{base}/endpoints/{ep.id}" if ep else base)

    action = {
        "expiring": "Renew and re-bind the certificate before it expires.",
        "expired": "Replace the expired certificate immediately.",
        "changed": "Confirm this certificate change was expected.",
        "scan_failure": "Verify the endpoint is reachable and serving TLS.",
        "self_signed": "Replace with a CA-issued certificate if this is not intentional.",
        "renewal_failed": "Certificate renewal failed. Check the issuer connection and the lifecycle order error, then retry.",
        "deploy_failed": "Certificate deployment/verification failed. Check the deployment target and re-run the order.",
        "order_stuck": "A lifecycle order has been stuck in a non-terminal state. Investigate the worker and the order's transition log.",
    }.get(ev.rule_type, "Review the certificate.")

    facts = {
        "Endpoint": where,
        "Common Name": cn or "(none)",
        "SAN": sans or "(none)",
        "Expires": cert.not_after.isoformat() if (cert and cert.not_after) else "n/a",
        "Days remaining": str(days) if days is not None else "n/a",
        "Issuer": cert.issuer_cn if cert else "n/a",
        "Fingerprint": cert.fingerprint_sha256 if cert else "n/a",
        "Target group": target.name if target else "n/a",
        "Owner/team": target.owner if target else "n/a",
        "Environment": target.environment if target else "n/a",
        "Severity": ev.severity,
    }
    subject = f"[CertWatch {ev.severity.upper()}] {ev.rule_type} — {cn or where}"
    text_lines = [ev.message, "", *(f"{k}: {v}" for k, v in facts.items()), "",
                  f"Recommended action: {action}", f"Details: {link}"]
    text = "\n".join(text_lines)
    rows = "".join(f"<tr><td><b>{k}</b></td><td>{v}</td></tr>" for k, v in facts.items())
    html = (f"<h3>{subject}</h3><p>{ev.message}</p><table>{rows}</table>"
            f"<p><b>Recommended action:</b> {action}</p>"
            f"<p><a href='{link}'>View certificate detail</a></p>")
    return subject, text, html, facts, link
