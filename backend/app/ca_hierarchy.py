"""CA hierarchy derivation (Phase 2.5.3).

Leaves are captured with their chain concatenated into `Certificate.pem`
(leaf PEM first, then intermediates/root). This module extracts the non-leaf
chain members into their own `Certificate` rows tagged `source="chain"` (dedup
by fingerprint, so one intermediate shared by many leaves is a single row) and
records each leaf's issuing-CA fingerprints in `chain_ca_fingerprints`.

Incremental: a leaf's pem is immutable once stored (a rotation is a new
fingerprint = a new row), so a leaf is derived exactly once -- keyed on
`chain_ca_fingerprints IS NULL`.

ponytail: full leaf scan per rollup is fine at this scale; requires Python
3.13+ full-chain capture (leaf-only runtimes yield empty chains, so the CA
view is simply empty).
"""
from __future__ import annotations

import logging
import re
from collections import Counter

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy import func, select

from . import scan_engine
from .models import Certificate, Endpoint
from .scanner import parse_certificate
from .status import days_until, expiry_phrase, severity

log = logging.getLogger("certwatch.ca_hierarchy")

_PEM_CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


def derive(db) -> int:
    """Extract CA members from not-yet-derived leaves. Returns the number of
    source="chain" certs known after the pass."""
    leaves = db.scalars(
        select(Certificate).where(
            Certificate.source != "chain",
            Certificate.chain_ca_fingerprints.is_(None),
        )
    ).all()
    for leaf in leaves:
        fps: list[str] = []
        blocks = _PEM_CERT_RE.findall(leaf.pem or "")
        for block in blocks[1:]:  # blocks[0] is the leaf itself
            try:
                der = x509.load_pem_x509_certificate(block.encode()).public_bytes(
                    serialization.Encoding.DER
                )
                fields = parse_certificate(der)
            except Exception:  # noqa: BLE001 - a malformed chain member must not fail derivation
                log.warning("ca_hierarchy: skipping unparseable chain member of cert %s", leaf.id)
                continue
            scan_engine._upsert_certificate(db, fields, source="chain")
            fps.append(fields["fingerprint_sha256"])
        leaf.chain_ca_fingerprints = fps
    db.commit()
    return db.scalar(
        select(func.count()).select_from(Certificate).where(Certificate.source == "chain")
    ) or 0


def dependent_counts(db) -> dict[str, int]:
    """fingerprint -> number of LIVE leaves (currently served by some endpoint,
    i.e. an endpoint's current_cert_id) whose chain includes that CA. Live-scoped
    so a renewed CA's dependents drop to 0 -- old rotated-away leaf rows persist in
    inventory but no longer count, which is what lets issuer_expiring auto-resolve
    on renewal and keeps the dependent count reflecting the live estate."""
    live = select(Endpoint.current_cert_id).where(Endpoint.current_cert_id.isnot(None))
    counter: Counter = Counter()
    rows = db.scalars(
        select(Certificate.chain_ca_fingerprints).where(
            Certificate.source != "chain",
            Certificate.chain_ca_fingerprints.isnot(None),
            Certificate.id.in_(live),
        )
    ).all()
    for fps in rows:
        for fp in (fps or []):
            counter[fp] += 1
    return dict(counter)


def expiring_ca_alerts(db, thresholds: list[int], now) -> dict[str, dict]:
    """Desired issuer_expiring alerts: for each source="chain" CA with >=1
    dependent leaf whose not_after falls within a threshold band (or is already
    expired -> band 0). Returned dicts are merged into evaluate_alerts' desired
    set, so they reconcile/auto-resolve like any other rule."""
    counts = dependent_counts(db)
    desired: dict[str, dict] = {}
    cas = db.scalars(select(Certificate).where(Certificate.source == "chain")).all()
    for ca in cas:
        dep = counts.get(ca.fingerprint_sha256, 0)
        if dep < 1:
            continue
        days = days_until(ca.not_after, now)
        if days is None:
            continue
        th = 0 if days < 0 else next((t for t in sorted(thresholds) if days <= t), None)
        if th is None:
            continue
        name = ca.common_name or ca.issuer_cn or ca.fingerprint_sha256
        desired[f"issuer_expiring:{ca.id}:{th}"] = {
            "endpoint_id": None, "certificate_id": ca.id, "rule_type": "issuer_expiring",
            "threshold_days": th, "severity": severity(days),
            "message": f"Issuing CA {name} {expiry_phrase(days)} — {dep} dependent certificate(s) (threshold {th}d)",
        }
    return desired
