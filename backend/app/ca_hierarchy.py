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
from .models import Certificate
from .scanner import parse_certificate

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
    """fingerprint -> number of leaves whose chain includes that CA."""
    counter: Counter = Counter()
    rows = db.scalars(
        select(Certificate.chain_ca_fingerprints).where(
            Certificate.source != "chain",
            Certificate.chain_ca_fingerprints.isnot(None),
        )
    ).all()
    for fps in rows:
        for fp in (fps or []):
            counter[fp] += 1
    return dict(counter)
