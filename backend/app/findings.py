"""Crypto-risk rules engine: evaluates a Certificate's captured fields (and,
for context-dependent rules, its Endpoint's Target.environment) against a
fixed set of rules and upserts `Finding` rows keyed by `dedupe_key`.

Anti-spam/history model mirrors `app.alerts.evaluate_alerts`: a condition that
recurs updates the existing row's `last_seen` and reactivates it
(`status="active"`); a condition that stops firing marks the matching row
`status="cleared"` rather than deleting it, so findings history is never
lost. `disposition` (open/accepted/resolved) is operator-set and is never
touched by re-evaluation.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .alerts import get_setting
from .config import settings
from .models import Certificate, Endpoint, Finding, Target, utcnow
from .status import days_until, is_internal

EXPIRING_THRESHOLD_DAYS = 30

# Rules that need Endpoint -> Target.environment context and therefore only
# run (and only get dedupe/cleared) when `evaluate_certificate` is called
# with an `endpoint`.
ENDPOINT_SCOPED_RULE_IDS = {"self_signed_prod", "untrusted_issuer_prod"}
ALL_RULE_IDS = ENDPOINT_SCOPED_RULE_IDS | {
    "weak_key", "deprecated_signature", "long_lifetime", "expiring", "expired",
}


def _thresholds(db: Session) -> dict:
    # ponytail: read-through via alerts.get_setting (already exists for
    # scan_failure_threshold/alert_on_self_signed) -- reuses the same
    # SystemSetting override convention instead of inventing a new one.
    return {
        "min_rsa_bits": int(get_setting(db, "finding_min_rsa_bits", settings.finding_min_rsa_bits)),
        "min_ec_bits": int(get_setting(db, "finding_min_ec_bits", settings.finding_min_ec_bits)),
        "max_lifetime_days": int(get_setting(db, "finding_max_lifetime_days", settings.finding_max_lifetime_days)),
        "deprecated_sigs": [
            s.strip() for s in
            str(get_setting(db, "finding_deprecated_sig_substrings", settings.finding_deprecated_sig_substrings)).split(",")
            if s.strip()
        ],
    }


def _candidate(rule_id: str, severity: str, title: str, detail: str, endpoint_scoped: bool = False) -> dict:
    return {"rule_id": rule_id, "severity": severity, "title": title, "detail": detail,
            "endpoint_scoped": endpoint_scoped}


def _weak_key(cert: Certificate, th: dict) -> dict | None:
    if cert.public_key_size is None:
        return None
    alg = (cert.public_key_algorithm or "").lower()
    if "rsa" in alg:
        if cert.public_key_size < th["min_rsa_bits"]:
            return _candidate(
                "weak_key", "warning",
                f"Weak RSA key ({cert.public_key_size} bits)",
                f"RSA key size {cert.public_key_size} bits is below the minimum of {th['min_rsa_bits']} bits.",
            )
    elif "ec" in alg:  # covers "EC" and "ECDSA"
        if cert.public_key_size < th["min_ec_bits"]:
            return _candidate(
                "weak_key", "warning",
                f"Weak EC key ({cert.public_key_size} bits)",
                f"EC key size {cert.public_key_size} bits is below the minimum of {th['min_ec_bits']} bits.",
            )
    return None


def _deprecated_signature(cert: Certificate, th: dict) -> dict | None:
    sig = (cert.signature_algorithm or "").lower()
    hit = next((s for s in th["deprecated_sigs"] if s in sig), None)
    if hit is None:
        return None
    return _candidate(
        "deprecated_signature", "warning",
        f"Deprecated signature algorithm ({cert.signature_algorithm})",
        f"Signature algorithm '{cert.signature_algorithm}' uses deprecated digest '{hit}'.",
    )


def _long_lifetime(cert: Certificate, th: dict) -> dict | None:
    if cert.not_before is None or cert.not_after is None:
        return None
    days = (cert.not_after - cert.not_before).days
    if days > th["max_lifetime_days"]:
        return _candidate(
            "long_lifetime", "info",
            f"Certificate lifetime exceeds policy ({days} days)",
            f"Validity period of {days} days exceeds the maximum of {th['max_lifetime_days']} days.",
        )
    return None


def _expired(cert: Certificate, now: datetime) -> dict | None:
    days = days_until(cert.not_after, now)
    if days is None or days >= 0:
        return None
    return _candidate(
        "expired", "critical",
        f"Certificate expired {-days} day{'s' if -days != 1 else ''} ago",
        f"Certificate {cert.common_name or cert.fingerprint_sha256} expired on {cert.not_after}.",
    )


def _expiring(cert: Certificate, now: datetime) -> dict | None:
    days = days_until(cert.not_after, now)
    if days is None or days < 0 or days > EXPIRING_THRESHOLD_DAYS:
        return None
    return _candidate(
        "expiring", "warning",
        f"Certificate expiring in {days} day{'s' if days != 1 else ''}",
        f"Certificate {cert.common_name or cert.fingerprint_sha256} expires on {cert.not_after}.",
    )


def _self_signed_prod(cert: Certificate, target: Target | None) -> dict | None:
    if target is None or not cert.self_signed or target.environment != "prod":
        return None
    return _candidate(
        "self_signed_prod", "critical",
        "Self-signed certificate in production",
        f"Certificate {cert.common_name or cert.fingerprint_sha256} is self-signed and served by a "
        f"production endpoint.",
        endpoint_scoped=True,
    )


def _untrusted_issuer_prod(cert: Certificate, target: Target | None, patterns: list[str]) -> dict | None:
    # ponytail: heuristic only -- "untrusted" here means "issuer doesn't match
    # a configured internal-CA pattern", not a real trust-store/chain-of-trust
    # validation. A proper implementation would verify the chain against a
    # trusted root store; deferred until that's needed.
    if target is None or target.environment != "prod" or cert.self_signed:
        return None
    if is_internal(cert.issuer, False, patterns):
        return None
    return _candidate(
        "untrusted_issuer_prod", "warning",
        f"Untrusted issuer in production ({cert.issuer_cn or cert.issuer})",
        f"Certificate {cert.common_name or cert.fingerprint_sha256} is issued by '{cert.issuer}', which "
        f"matches no configured internal CA pattern, on a production endpoint.",
        endpoint_scoped=True,
    )


def evaluate_certificate(db: Session, cert: Certificate, endpoint: Endpoint | None = None) -> list[Finding]:
    """Run all applicable rules against `cert` (endpoint-context rules only
    when `endpoint` is given), upsert `Finding` rows by dedupe_key, mark
    no-longer-firing findings in this scope `status="cleared"`, and return
    the currently active findings for this cert/endpoint."""
    now = utcnow()
    th = _thresholds(db)

    candidates = [c for c in (
        _weak_key(cert, th),
        _deprecated_signature(cert, th),
        _long_lifetime(cert, th),
        _expired(cert, now),
        _expiring(cert, now),
    ) if c]

    if endpoint is not None:
        target = db.get(Target, endpoint.target_id) if endpoint.target_id else None
        candidates += [c for c in (
            _self_signed_prod(cert, target),
            _untrusted_issuer_prod(cert, target, settings.internal_ca_pattern_list),
        ) if c]
        applicable_rule_ids = ALL_RULE_IDS
    else:
        applicable_rule_ids = ALL_RULE_IDS - ENDPOINT_SCOPED_RULE_IDS

    desired: dict[str, dict] = {}
    for c in candidates:
        key = f"{c['rule_id']}:{cert.id}" + (f":{endpoint.id}" if c["endpoint_scoped"] else "")
        desired[key] = c

    # Existing rows in scope for *this* evaluation: cert-scoped rules always
    # (endpoint_id is None), endpoint-scoped rules only for this endpoint.
    existing_all = db.scalars(select(Finding).where(Finding.certificate_id == cert.id)).all()
    existing = {
        f.dedupe_key: f for f in existing_all
        if f.rule_id in applicable_rule_ids and (
            f.rule_id not in ENDPOINT_SCOPED_RULE_IDS
            or (endpoint is not None and f.endpoint_id == endpoint.id)
        )
    }

    result: list[Finding] = []
    for key, c in desired.items():
        row = existing.get(key)
        if row is None:
            row = Finding(
                rule_id=c["rule_id"], severity=c["severity"],
                certificate_id=cert.id,
                endpoint_id=endpoint.id if c["endpoint_scoped"] else None,
                title=c["title"], detail=c["detail"], dedupe_key=key,
                status="active", first_seen=now, last_seen=now,
            )
            db.add(row)
        else:
            row.severity = c["severity"]
            row.title = c["title"]
            row.detail = c["detail"]
            row.status = "active"
            row.last_seen = now
        result.append(row)

    for key, row in existing.items():
        if key not in desired and row.status != "cleared":
            row.status = "cleared"

    db.commit()
    for row in result:
        db.refresh(row)
    return result


def evaluate_all(db: Session) -> int:
    """Re-evaluate every current cert/endpoint pair, plus any certificate not
    currently bound to an endpoint (so cert-only rules still get reassessed
    for inventory-only certs). Returns the count of active findings."""
    endpoints = db.scalars(select(Endpoint).where(Endpoint.current_cert_id.isnot(None))).all()
    referenced_cert_ids: set[int] = set()
    for ep in endpoints:
        cert = db.get(Certificate, ep.current_cert_id)
        if cert is None:
            continue
        evaluate_certificate(db, cert, endpoint=ep)
        referenced_cert_ids.add(cert.id)

    all_certs = db.scalars(select(Certificate)).all()
    for cert in all_certs:
        if cert.id not in referenced_cert_ids:
            evaluate_certificate(db, cert, endpoint=None)

    # ponytail: cross-scope reconciliation -- evaluate_certificate only clears
    # endpoint-scoped findings for the (cert, endpoint) pair it's called with,
    # so a rotated/deleted endpoint's stale finding for its *old* cert is
    # never revisited above; sweep all active endpoint-scoped findings here
    # and clear any whose (certificate_id, endpoint_id) is no longer current.
    valid = {(ep.current_cert_id, ep.id) for ep in endpoints}
    stale = db.scalars(
        select(Finding).where(
            Finding.status == "active",
            Finding.rule_id.in_(ENDPOINT_SCOPED_RULE_IDS),
            Finding.endpoint_id.isnot(None),
        )
    ).all()
    for f in stale:
        if (f.certificate_id, f.endpoint_id) not in valid:
            f.status = "cleared"
    db.commit()

    return db.scalar(select(func.count()).select_from(Finding).where(Finding.status == "active")) or 0
