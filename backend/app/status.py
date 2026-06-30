"""Expiration math and severity classification — pure, unit-tested.

Severity:
  critical : expired, or expires within 7 days
  warning  : expires within 30 days
  info     : expires within 90 days
  healthy  : more than 90 days out
  unknown  : no certificate / failed scan / missing not_after
"""
from __future__ import annotations

from datetime import datetime, timezone


def days_until(not_after: datetime | None, now: datetime | None = None) -> int | None:
    if not_after is None:
        return None
    now = now or datetime.now(timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    delta = not_after - now
    # Round toward zero by whole days; negative means already expired.
    return int(delta.total_seconds() // 86400)


def severity(days: int | None, scan_ok: bool = True) -> str:
    if not scan_ok or days is None:
        return "unknown"
    if days < 7:
        return "critical"
    if days < 30:
        return "warning"
    if days < 90:
        return "info"
    return "healthy"


def expiry_phrase(days: int | None) -> str:
    """Human copy: 'Expiring in 27 days', 'Expired 4 days ago'."""
    if days is None:
        return "Unknown"
    if days < 0:
        n = -days
        return f"Expired {n} day{'s' if n != 1 else ''} ago"
    if days == 0:
        return "Expires today"
    return f"Expiring in {days} day{'s' if days != 1 else ''}"


def status_phrase(scan_status: str) -> str:
    """Human copy for a scan status code."""
    return {
        "ok": "Certificate captured",
        "connection_failed": "Scan failed: connection refused or unreachable",
        "timeout": "Scan failed: connection timed out",
        "tls_handshake_failed": "Scan failed: TLS handshake failed",
        "non_tls_service": "Non-TLS service detected",
        "no_certificate": "No certificate presented",
        "dns_resolution_failed": "Scan failed: could not resolve hostname",
    }.get(scan_status, scan_status or "Unknown")
