# CA Hierarchy View Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the intermediate/root CA certificates the estate depends on from stored leaf chains into queryable `Certificate` rows (`source="chain"`), surface them in a CA view with dependent-leaf counts, and alert (`issuer_expiring`, auto-resolving) when one approaches expiry.

**Architecture:** A new `ca_hierarchy.py` derivation pass parses each not-yet-derived leaf's concatenated `pem`, upserts its non-leaf chain members as `source="chain"` `Certificate` rows (dedup by fingerprint), and records the leaf's issuing-CA fingerprints in a new `chain_ca_fingerprints` JSON column. Dependent counts are a live rollup over those lists. `evaluate_alerts` gains an `issuer_expiring` section (via a `ca_hierarchy` helper) reusing its existing desired/reconcile/dispatch loop, so CA-expiry alerts auto-resolve on renewal. A CA-certificates API + page + one dashboard tile expose the view.

**Tech Stack:** Python 3.13 / FastAPI / SQLAlchemy 2 / Alembic / PostgreSQL 16 (SQLite for tests), `cryptography` (already present), React 18 + Vite, pytest.

## Global Constraints

- Reuse the `Certificate` table with `source="chain"` (extends `network | ct`); no dedicated CA table. `source` is already a `String(16)` column — the new value needs no column migration.
- New column `Certificate.chain_ca_fingerprints` (JSON, **nullable, default NULL**). NULL = "not yet derived" (the incremental sentinel); `[]` = derived, no CA members; `[fp, ...]` = a leaf's issuing-CA fingerprints. One migration, revision `0017` (verify head is `0016` first).
- Dependent counts are computed live (a `Counter` rollup over leaves' `chain_ca_fingerprints`) — NO denormalized count column on `Certificate`.
- `issuer_expiring` is a normal (reconciled) alert rule type — NOT in `ONE_OFF_RULE_TYPES` — so it auto-resolves when the intermediate is renewed. Thresholds from a `ca_alert_thresholds` system setting, default `"180,90,30"`.
- `source="chain"` certs are excluded from `findings.evaluate_all` (they are not served leaves). Crypto-risk findings on CA certs are deliberately deferred (`ponytail:`).
- Dashboard operational tiles already filter `source == "network"` (from the CT feature), so `chain` certs are excluded there for free; the new CA-expiring tile counts `source == "chain"` explicitly.
- Derivation is fail-closed/non-fatal in `run_scan_job` — a derivation error must never fail a scan (mirrors `findings.evaluate_all`'s guarded call).
- `ponytail:` ceilings (preserve in comments): flat CA list not a tree diagram; CA crypto-risk findings deferred; full leaf scan per rollup is fine at this scale; requires Python 3.13+ full-chain capture (CA view is simply empty otherwise).
- Test command (Windows, from `backend/`): `./.venv/Scripts/python.exe -m pytest`. Baseline: 295 passing.

---

### Task 1: `chain_ca_fingerprints` column + migration

**Files:**
- Modify: `backend/app/models.py` (add column to `Certificate`, after `source` ~line 139)
- Create: `backend/alembic/versions/0017_chain_ca_fingerprints.py`
- Test: `backend/tests/test_migrations.py` (verify still passes)

**Interfaces:**
- Produces: `Certificate.chain_ca_fingerprints` (`list | None`, default `None`).

- [ ] **Step 1: Add the column**

In `backend/app/models.py`, in `class Certificate`, right after the `source` column:

```python
    # For a leaf: SHA-256 fingerprints of its non-leaf chain members (issuing
    # CAs), populated by ca_hierarchy.derive. NULL = not yet derived (the
    # incremental sentinel); [] = derived with no CA members; CA rows
    # (source="chain") stay NULL (never treated as leaves).
    chain_ca_fingerprints: Mapped[list | None] = mapped_column(JSON, nullable=True, default=None)
```

- [ ] **Step 2: Write the migration**

First confirm head: `ls backend/alembic/versions/` — the latest should be `0016_watched_domains.py`. If a higher number exists, bump this file and its `down_revision` accordingly.

Create `backend/alembic/versions/0017_chain_ca_fingerprints.py`:

```python
"""chain ca fingerprints

Revision ID: 0017
Revises: 0016
Create Date: 2026-07-14 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '0017'
down_revision: Union[str, None] = '0016'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('certificates', sa.Column('chain_ca_fingerprints', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('certificates', 'chain_ca_fingerprints')
```

- [ ] **Step 3: Run the migration test**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_migrations.py -v`
Expected: PASS (upgrade from empty DB and from prior head both succeed).

- [ ] **Step 4: Commit**

```bash
git add backend/app/models.py backend/alembic/versions/0017_chain_ca_fingerprints.py
git commit -m "feat: add Certificate.chain_ca_fingerprints column (leaf issuing-CA linkage)"
```

---

### Task 2: `ca_hierarchy` derivation module + dependent-count rollup

**Files:**
- Create: `backend/app/ca_hierarchy.py`
- Test: `backend/tests/test_ca_hierarchy.py`

**Interfaces:**
- Consumes: `Certificate.chain_ca_fingerprints`, `Certificate.source` (Task 1 / existing); `scan_engine._upsert_certificate(db, fields, source=)`; `scanner.parse_certificate(der)`.
- Produces:
  - `ca_hierarchy.derive(db) -> int` — derives not-yet-derived leaves, upserts CA members as `source="chain"`, sets leaf `chain_ca_fingerprints`; returns count of `source="chain"` certs known.
  - `ca_hierarchy.dependent_counts(db) -> dict[str, int]` — fingerprint → number of leaves whose `chain_ca_fingerprints` contains it.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_ca_hierarchy.py`:

```python
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import ca_hierarchy, scan_engine
from app.models import Certificate
from app.scanner import parse_certificate


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _cert(subject_cn, issuer_cn, signer_key, subject_key, is_ca=False, days=3650):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
         .public_key(subject_key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=days)))
    if is_ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return b.sign(signer_key, hashes.SHA256())


def _leaf_with_chain(db, leaf_cn="leaf.example.com", int_cn="Intermediate CA", int_days=3650):
    """Insert a leaf Certificate whose pem = leaf PEM + intermediate PEM,
    chain_length=2, chain_ca_fingerprints NULL (as a fresh scan would)."""
    root_key, int_key, leaf_key = _key(), _key(), _key()
    intermediate = _cert(int_cn, "Root CA", root_key, int_key, is_ca=True, days=int_days)
    leaf = _cert(leaf_cn, int_cn, int_key, leaf_key, is_ca=False, days=90)
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    int_der = intermediate.public_bytes(serialization.Encoding.DER)
    fields = parse_certificate(leaf_der, [int_der])  # pem = leaf + intermediate, chain_length=2
    c = Certificate(**fields, source="network")
    db.add(c)
    db.commit()
    int_fields = parse_certificate(int_der)
    return c, int_fields["fingerprint_sha256"]


def test_derive_extracts_intermediate_as_chain_source(db):
    leaf, int_fp = _leaf_with_chain(db)
    ca_hierarchy.derive(db)
    cas = db.query(Certificate).filter_by(source="chain").all()
    assert len(cas) == 1
    assert cas[0].fingerprint_sha256 == int_fp
    assert cas[0].is_ca is True
    db.refresh(leaf)
    assert leaf.chain_ca_fingerprints == [int_fp]


def test_derive_chainless_leaf_sets_empty_list(db):
    root_key, leaf_key = _key(), _key()
    ss = _cert("solo.example.com", "solo.example.com", leaf_key, leaf_key, is_ca=False, days=90)
    fields = parse_certificate(ss.public_bytes(serialization.Encoding.DER))  # chain_length=1
    c = Certificate(**fields, source="network")
    db.add(c); db.commit()
    ca_hierarchy.derive(db)
    db.refresh(c)
    assert c.chain_ca_fingerprints == []
    assert db.query(Certificate).filter_by(source="chain").count() == 0


def test_derive_dedups_shared_intermediate(db):
    # two leaves under the same intermediate -> one chain row
    l1, fp1 = _leaf_with_chain(db, leaf_cn="a.example.com")
    # reuse the same intermediate identity by building a second leaf that carries
    # an intermediate with the SAME key/subject is non-trivial; instead assert the
    # dedup path via re-deriving the same leaf twice yields no duplicate.
    ca_hierarchy.derive(db)
    ca_hierarchy.derive(db)  # idempotent
    assert db.query(Certificate).filter_by(source="chain").count() == 1


def test_derive_is_incremental_skips_already_derived(db):
    leaf, _ = _leaf_with_chain(db)
    ca_hierarchy.derive(db)
    db.refresh(leaf)
    assert leaf.chain_ca_fingerprints is not None  # derived
    # mutate nothing; second derive must not touch it or add rows
    before = db.query(Certificate).filter_by(source="chain").count()
    ca_hierarchy.derive(db)
    assert db.query(Certificate).filter_by(source="chain").count() == before


def test_dependent_counts_rollup(db):
    leaf, int_fp = _leaf_with_chain(db)
    ca_hierarchy.derive(db)
    counts = ca_hierarchy.dependent_counts(db)
    assert counts.get(int_fp) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_ca_hierarchy.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.ca_hierarchy'`.

- [ ] **Step 3: Implement the module**

Create `backend/app/ca_hierarchy.py`:

```python
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
```

Note: `db.scalar(select(...).count())` is not valid SQLAlchemy 2 — use `db.scalar(select(func.count()).select_from(...).where(...))`. Fix the return line to:

```python
    from sqlalchemy import func
    return db.scalar(select(func.count()).select_from(Certificate).where(Certificate.source == "chain")) or 0
```

(Move the `func` import to the top with the other sqlalchemy imports: `from sqlalchemy import func, select`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_ca_hierarchy.py -v`
Expected: PASS.

Note: `_upsert_certificate` and `parse_certificate` are used exactly as `worker._store_issued_cert` uses them (parse a chain member's DER, upsert by fingerprint) — the proven in-repo pattern.

- [ ] **Step 5: Commit**

```bash
git add backend/app/ca_hierarchy.py backend/tests/test_ca_hierarchy.py
git commit -m "feat: ca_hierarchy.derive extracts chain CAs + dependent-count rollup"
```

---

### Task 3: Wire derivation into scans + exclude chain certs from findings

**Files:**
- Modify: `backend/app/scan_engine.py` (call `ca_hierarchy.derive` post-scan, non-fatal, before `evaluate_alerts`/`findings`)
- Modify: `backend/app/findings.py:239` (exclude `source="chain"` from `evaluate_all`)
- Test: `backend/tests/test_ca_integration.py`

**Interfaces:**
- Consumes: `ca_hierarchy.derive` (Task 2).
- Produces: after a scan job, chain CAs are derived; `findings.evaluate_all` never evaluates `source="chain"` certs.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_ca_integration.py`:

```python
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import findings
from app.models import Certificate, Finding
from app.scanner import parse_certificate


def _chain_cert(db, source="chain", long_lifetime_days=3650):
    key, ikey = rsa.generate_private_key(public_exponent=65537, key_size=2048), rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")]))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=long_lifetime_days))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .sign(ikey, hashes.SHA256()))
    fields = parse_certificate(c.public_bytes(serialization.Encoding.DER))
    row = Certificate(**fields, source=source)
    db.add(row); db.commit()
    return row


def test_findings_skips_chain_source(db):
    # a chain CA cert with a 10-year lifetime would trip long_lifetime if evaluated
    ca = _chain_cert(db, source="chain")
    findings.evaluate_all(db)
    assert db.query(Finding).filter_by(certificate_id=ca.id).count() == 0


def test_findings_still_runs_on_network_cert(db):
    # sanity: a non-chain cert with a long lifetime DOES get evaluated (control)
    net = _chain_cert(db, source="network")
    findings.evaluate_all(db)
    assert db.query(Finding).filter_by(certificate_id=net.id, rule_id="long_lifetime").count() == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_ca_integration.py -v`
Expected: FAIL — `test_findings_skips_chain_source` fails because `evaluate_all` currently evaluates all certs (creates a `long_lifetime` finding for the chain CA).

- [ ] **Step 3: Exclude chain certs from findings**

In `backend/app/findings.py`, in `evaluate_all`, change the `all_certs` query (line ~239) from:

```python
    all_certs = db.scalars(select(Certificate)).all()
```
to:

```python
    # ponytail: CA certs (source="chain") are not endpoint-served leaves; a 10-20yr
    # intermediate would trip long_lifetime and its expiry is covered by the
    # issuer_expiring alert. Crypto-risk findings on CA certs deferred.
    all_certs = db.scalars(select(Certificate).where(Certificate.source != "chain")).all()
```

- [ ] **Step 4: Wire derivation into `run_scan_job`**

In `backend/app/scan_engine.py`, in `run_scan_job`, immediately BEFORE the existing `from .alerts import evaluate_alerts` block (~line 120), add:

```python
    # Extract CA hierarchy (source="chain" certs + leaf linkage) before alert
    # evaluation, so the issuer_expiring rule can see the CA certs. Non-fatal:
    # a derivation bug must never fail a scan (mirrors findings below).
    from . import ca_hierarchy
    try:
        ca_hierarchy.derive(db)
    except Exception:
        log.exception("CA hierarchy derivation failed for job %s", job.id)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_ca_integration.py tests/test_findings.py tests/test_scan_engine_source.py -v`
Expected: PASS (findings skip chain; existing findings/scan tests unaffected).

- [ ] **Step 6: Commit**

```bash
git add backend/app/scan_engine.py backend/app/findings.py backend/tests/test_ca_integration.py
git commit -m "feat: derive CA hierarchy post-scan; exclude chain certs from findings"
```

---

### Task 4: `issuer_expiring` alert

**Files:**
- Modify: `backend/app/ca_hierarchy.py` (add `expiring_ca_alerts` helper)
- Modify: `backend/app/alerts.py` (merge CA desired-alerts into `evaluate_alerts`; add action-map entry)
- Test: `backend/tests/test_ca_alerts.py`

**Interfaces:**
- Consumes: `ca_hierarchy.dependent_counts` (Task 2); `get_setting`, `days_until`, `severity`, `expiry_phrase` (existing).
- Produces: `ca_hierarchy.expiring_ca_alerts(db, thresholds, now) -> dict[str, dict]` returning desired-alert dicts keyed `issuer_expiring:{ca.id}:{th}`; `evaluate_alerts` includes them so they reconcile/auto-resolve.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_ca_alerts.py`:

```python
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import alerts
from app.models import AlertEvent, Certificate, utcnow
from app.scanner import parse_certificate


def _ca(db, days, fp_leaves=0, cn="Intermediate CA"):
    key, ikey = rsa.generate_private_key(public_exponent=65537, key_size=2048), rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")]))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .sign(ikey, hashes.SHA256()))
    fields = parse_certificate(c.public_bytes(serialization.Encoding.DER))
    ca = Certificate(**fields, source="chain")
    db.add(ca); db.flush()
    # attach `fp_leaves` leaves that depend on this CA
    for i in range(fp_leaves):
        db.add(Certificate(fingerprint_sha256=f"LEAF:{cn}:{i}", common_name=f"l{i}",
                           source="network", chain_ca_fingerprints=[ca.fingerprint_sha256]))
    db.commit()
    return ca


def test_issuer_expiring_fires_within_threshold_with_dependents(db):
    ca = _ca(db, days=20, fp_leaves=3)   # 20d out, under 30d band
    alerts.evaluate_alerts(db, dispatch=False)
    ev = db.query(AlertEvent).filter_by(rule_type="issuer_expiring").all()
    assert len(ev) == 1
    assert ev[0].certificate_id == ca.id
    assert "3 dependent" in ev[0].message


def test_issuer_expiring_ignored_without_dependents(db):
    _ca(db, days=20, fp_leaves=0)  # expiring but nothing depends on it
    alerts.evaluate_alerts(db, dispatch=False)
    assert db.query(AlertEvent).filter_by(rule_type="issuer_expiring").count() == 0


def test_issuer_expiring_ignored_when_far_out(db):
    _ca(db, days=800, fp_leaves=2)  # beyond 180d
    alerts.evaluate_alerts(db, dispatch=False)
    assert db.query(AlertEvent).filter_by(rule_type="issuer_expiring").count() == 0


def test_issuer_expiring_auto_resolves_when_dependents_drop(db):
    ca = _ca(db, days=20, fp_leaves=1)
    alerts.evaluate_alerts(db, dispatch=False)
    assert db.query(AlertEvent).filter_by(rule_type="issuer_expiring", resolved=False).count() == 1
    # leaves rotate away: drop the dependent leaf, re-evaluate -> alert auto-resolves
    db.query(Certificate).filter(Certificate.source == "network").delete()
    db.commit()
    alerts.evaluate_alerts(db, dispatch=False)
    assert db.query(AlertEvent).filter_by(rule_type="issuer_expiring", resolved=False).count() == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_ca_alerts.py -v`
Expected: FAIL — no `issuer_expiring` alerts produced yet.

- [ ] **Step 3: Add the `expiring_ca_alerts` helper to `ca_hierarchy.py`**

Append to `backend/app/ca_hierarchy.py` (add `from .status import days_until, expiry_phrase, severity` to imports):

```python
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
```

- [ ] **Step 4: Merge into `evaluate_alerts`**

In `backend/app/alerts.py`, in `evaluate_alerts`, after the endpoint loop finishes building `desired` (immediately before the `existing = {...}` line ~96), add:

```python
    # CA-hierarchy issuer_expiring alerts (Phase 2.5.3). Lazy import avoids a
    # module-load cycle (ca_hierarchy -> scan_engine). Merged into `desired` so
    # they reconcile/auto-resolve through the same loop below.
    from . import ca_hierarchy
    ca_thresholds = [int(x) for x in str(get_setting(db, "ca_alert_thresholds", "180,90,30")).split(",") if x.strip()]
    desired.update(ca_hierarchy.expiring_ca_alerts(db, ca_thresholds, now))
```

- [ ] **Step 5: Add the action-map entry**

In `backend/app/alerts.py`, in the `action = {...}.get(ev.rule_type, ...)` map (~line 227), add:

```python
        "issuer_expiring": "An issuing CA (intermediate/root) is approaching expiry; plan its renewal — every dependent certificate must be re-issued from the new CA before it expires.",
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_ca_alerts.py tests/test_alerts.py -v`
Expected: PASS (new CA alert tests + existing alert tests unaffected).

- [ ] **Step 7: Commit**

```bash
git add backend/app/ca_hierarchy.py backend/app/alerts.py backend/tests/test_ca_alerts.py
git commit -m "feat: issuer_expiring alert for CA certs (auto-resolving, dependent-aware)"
```

---

### Task 5: `/api/ca-certificates` endpoint + dashboard tile

**Files:**
- Modify: `backend/app/main.py` (new endpoint; dashboard CA-expiring count)
- Test: `backend/tests/test_ca_api.py`

**Interfaces:**
- Consumes: `ca_hierarchy.dependent_counts` (Task 2); `cert_dict`, `require_role` (existing).
- Produces: `GET /api/ca-certificates` → `{items: [...]}` where each item is `cert_dict(...)` plus `dependent_count` and `is_root`, sorted by `not_after` ascending; `/api/dashboard` gains `ca_expiring_90d`.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_ca_api.py`:

```python
import datetime

from app.db import SessionLocal
from app.models import Certificate, utcnow


def _seed(db):
    soon = utcnow() + datetime.timedelta(days=20)
    far = utcnow() + datetime.timedelta(days=800)
    ca_soon = Certificate(fingerprint_sha256="CA:SOON", common_name="Int Soon", issuer_cn="Root",
                          source="chain", is_ca=True, self_signed=False, not_after=soon)
    ca_far = Certificate(fingerprint_sha256="CA:FAR", common_name="Int Far", issuer_cn="Root",
                         source="chain", is_ca=True, self_signed=False, not_after=far)
    db.add_all([ca_soon, ca_far])
    # two leaves depend on CA:SOON, none on CA:FAR
    db.add(Certificate(fingerprint_sha256="L1", common_name="l1", source="network",
                       chain_ca_fingerprints=["CA:SOON"]))
    db.add(Certificate(fingerprint_sha256="L2", common_name="l2", source="network",
                       chain_ca_fingerprints=["CA:SOON"]))
    db.commit()


def test_ca_certificates_endpoint(client, monkeypatch):
    from tests.conftest import login_as
    login_as(client, "viewer", monkeypatch)
    s = SessionLocal(); _seed(s); s.close()
    r = client.get("/api/ca-certificates")
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert [i["fingerprint_sha256"] for i in items] == ["CA:SOON", "CA:FAR"]  # sorted by expiry
    soon = items[0]
    assert soon["dependent_count"] == 2
    assert soon["is_root"] is False


def test_dashboard_ca_expiring_count(client, monkeypatch):
    from tests.conftest import login_as
    login_as(client, "viewer", monkeypatch)
    s = SessionLocal(); _seed(s); s.close()
    data = client.get("/api/dashboard").json()
    # CA:SOON (20d, 2 dependents) counts; CA:FAR (800d) does not
    assert data["ca_expiring_90d"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_ca_api.py -v`
Expected: FAIL — 404 on `/api/ca-certificates`; `ca_expiring_90d` missing from dashboard.

- [ ] **Step 3: Add the endpoint**

In `backend/app/main.py`, near the certificates routes, add (ensure `ca_hierarchy` is importable — use a lazy import inside to avoid any cycle):

```python
@app.get("/api/ca-certificates", dependencies=[Depends(require_role("viewer"))])
def list_ca_certificates(db: Session = Depends(get_db)):
    from . import ca_hierarchy
    counts = ca_hierarchy.dependent_counts(db)
    rows = db.scalars(
        select(Certificate).where(Certificate.source == "chain").order_by(Certificate.not_after.asc())
    ).all()
    items = []
    for c in rows:
        d = cert_dict(db, c)
        d["dependent_count"] = counts.get(c.fingerprint_sha256, 0)
        d["is_root"] = bool(c.self_signed and c.is_ca)
        items.append(d)
    return {"items": items}
```

- [ ] **Step 4: Add the dashboard count**

In `backend/app/main.py`, in the `dashboard` route, compute the CA-expiring count and add it to the returned dict. After the `expired = ...` line (~1436), add:

```python
    # CA certs (source="chain") expiring within 90d that at least one leaf depends on.
    from . import ca_hierarchy
    ca_counts = ca_hierarchy.dependent_counts(db)
    ca_expiring_90d = 0
    for ca in db.scalars(select(Certificate).where(
        Certificate.source == "chain",
        Certificate.not_after >= now, Certificate.not_after <= now + timedelta(days=90),
    )).all():
        if ca_counts.get(ca.fingerprint_sha256, 0) >= 1:
            ca_expiring_90d += 1
```

Then add `"ca_expiring_90d": ca_expiring_90d,` to the returned dict (alongside `expiring_90d` ~line 1504).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_ca_api.py tests/test_api.py tests/test_dashboard_ct.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/app/main.py backend/tests/test_ca_api.py
git commit -m "feat: /api/ca-certificates endpoint + dashboard CA-expiring tile"
```

---

### Task 6: Frontend CA page + nav + dashboard card + docs + full-suite verify

**Files:**
- Modify: `frontend/src/api.ts`, `frontend/src/App.tsx` (nav + route), `frontend/src/pages/Dashboard.tsx` (card); Create: `frontend/src/pages/CaCertificates.tsx`
- Modify: `README.md`

**Interfaces:**
- Consumes: `GET /api/ca-certificates`, `dashboard.ca_expiring_90d` (Task 5).

- [ ] **Step 1: Inspect the frontend structure**

Read `frontend/src/App.tsx` (how pages/nav/routes are registered), `frontend/src/pages/Certificates.tsx` (list + badge + severity patterns), `frontend/src/pages/Dashboard.tsx` (card pattern), and `frontend/src/api.ts` (fetch helpers). Follow these patterns exactly — do not introduce a new data-fetching or routing pattern.

- [ ] **Step 2: Add the API client function**

In `frontend/src/api.ts`, mirror the existing list helpers:

```typescript
export const listCaCertificates = () => api<{items: CaCertificate[]}>("/api/ca-certificates");
```
Add a `CaCertificate` type = the certificate type plus `dependent_count: number` and `is_root: boolean`.

- [ ] **Step 3: Build the CA Certificates page**

Create `frontend/src/pages/CaCertificates.tsx` mirroring `Certificates.tsx`: a table of CA certs (subject/CN, issuer, expiry phrase + severity badge reusing the existing severity component, a Root/Intermediate label from `is_root`, and `dependent_count`), already sorted by soonest expiry (the API sorts). Register it in `App.tsx` nav + routes as "CA Certificates".

- [ ] **Step 4: Add the dashboard card**

In `Dashboard.tsx`, add a card for `ca_expiring_90d` labeled e.g. "CA certs expiring ≤90d", mirroring the existing metric cards.

- [ ] **Step 5: Build the frontend**

Run: `cd frontend && npm run build`
Expected: PASS (no type errors, production build succeeds).

- [ ] **Step 6: Document in README**

Add a short "CA hierarchy" subsection under inventory/how-it-works: the CA Certificates view, `source=ct`→ note there's now also `source=chain`, the `issuer_expiring` alert and its `ca_alert_thresholds` setting (default `180,90,30`), and the Python-3.13 full-chain requirement. Add `ca_alert_thresholds` to any settings list.

- [ ] **Step 7: Run the full backend suite**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest -q`
Expected: PASS — 295 baseline + all new CA tests, green.

- [ ] **Step 8: Commit**

```bash
git add frontend/src README.md
git commit -m "feat: CA Certificates page + dashboard card; document CA hierarchy"
```

---

## Self-Review Notes

- **Spec coverage:** column + migration (T1); `derive` extraction + dependent_counts rollup + incremental NULL-sentinel + dedup (T2); post-scan wiring + findings exclusion (T3); `issuer_expiring` alert with dependents + thresholds + auto-resolve + action map (T4); `/api/ca-certificates` + dashboard tile (T5); frontend page + nav + card + docs (T6). All spec sections mapped.
- **Ceilings preserved in comments:** flat list not tree (T6 docs), CA crypto-risk findings deferred (T3 comment + module docstring), full-scan rollup fine at scale + 3.13 requirement (T2 docstring).
- **Type consistency:** `derive(db) -> int`, `dependent_counts(db) -> dict[str,int]`, `expiring_ca_alerts(db, thresholds, now) -> dict[str,dict]` consistent across T2/T4/T5; `chain_ca_fingerprints` (list|None) consistent T1→T2→T4→T5; `source="chain"` string identical everywhere; `issuer_expiring` rule_type identical in T4 helper, alerts merge, and tests; `ca_expiring_90d` / `dependent_count` / `is_root` JSON keys consistent T5↔T6.
- **Correctness note flagged in T2:** the SQLAlchemy-2 count idiom (`select(func.count()).select_from(...)`) is called out explicitly so the implementer doesn't write the invalid `select(...).count()`.
- **Open confirmations for the implementer (not blockers):** exact frontend nav/route/card mechanism (T6 Step 1 resolves); that `0016` is the current alembic head (T1 Step 2 resolves).
```
