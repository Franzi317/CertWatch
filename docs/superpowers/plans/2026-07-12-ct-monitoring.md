# CT Monitoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Poll a configurable Certificate Transparency source (crt.sh by default) for watched domains, ingest publicly-issued certs never seen on the network into the existing inventory with a `source=ct` marker, and raise a self-clearing `unknown_issuance` finding for them.

**Architecture:** A new `WatchedDomain` table is the poll list. A daily `ct_tick` scheduler job enqueues a `ct_check` work item per due domain. The worker's `ct_check` handler calls a thin `ct_source` client that queries crt.sh, fetches each new cert, and reuses `scan_engine._upsert_certificate` (dedup by fingerprint) to store unknowns with `source=ct`, then runs the findings engine so `unknown_issuance` fires. When a later network scan binds that fingerprint to an endpoint, the existing findings re-evaluation clears it.

**Tech Stack:** Python 3.13 / FastAPI / SQLAlchemy 2 / Alembic / PostgreSQL 16 (SQLite for tests), `httpx` (already a dependency, used by `issuers/adcs.py`), `cryptography`, React 18 + Vite.

## Global Constraints

- **No multi-tenancy.** No tenant scoping of any kind.
- All new mutation endpoints require auth (`require_role`) + write to `AuditLog` via `audit(db, principal["email"], ...)`.
- Secrets are never returned in cleartext by any API. (CT config holds no secrets, but the CT source URL is plain config, not a per-row secret.)
- PostgreSQL is the only production datastore; SQLite for dev/test only. Migrations via Alembic — every schema change is a numbered migration in `backend/alembic/versions/`, and `test_migrations.py` must still pass (upgrade from empty DB and from prior head).
- Python 3.11+ floor, 3.13 recommended.
- Fail-closed in the worker: any exception in a `ct_check` item calls `queue.fail(db, item, str(e))` and never crashes the worker loop — same pattern as every other kind in `worker.process_one`.
- `ponytail:` ceilings to preserve verbatim in code comments: crt.sh JSON only (no RFC 6962 log tailing); fixed finding severity (no environment inference); `source` is provenance-of-first-discovery, not flipped on later network observation.

**Config (add to `app/config.py` `Settings`, env prefix `CERTWATCH_`):**
- `ct_source_url: str = "https://crt.sh"` — blank/unset disables the feature and `ct_tick`.
- `ct_check_frequency_hours: int = 24`
- `ct_finding_severity: str = "warning"`

---

### Task 1: `Certificate.source` column + migration

**Files:**
- Modify: `backend/app/models.py` (add column to `Certificate`, after `chain_length` ~line 134)
- Create: `backend/alembic/versions/0015_certificate_source.py`
- Test: `backend/tests/test_migrations.py` (already exercises upgrade head; no new test file — verify it still passes)

**Interfaces:**
- Produces: `Certificate.source` (str, default `"network"`), values `"network" | "ct"`.

- [ ] **Step 1: Add the column to the model**

In `backend/app/models.py`, in `class Certificate`, immediately after the `chain_length` line:

```python
    # network = observed on our network via a scan; ct = discovered in a
    # Certificate Transparency log for a WatchedDomain. ponytail: provenance of
    # first discovery only -- NOT flipped when a ct cert is later scanned; the
    # unknown_issuance finding clears off endpoint binding instead (findings.py).
    source: Mapped[str] = mapped_column(String(16), default="network")
```

- [ ] **Step 2: Write the migration**

Create `backend/alembic/versions/0015_certificate_source.py`:

```python
"""certificate source column

Revision ID: 0015
Revises: 0014
Create Date: 2026-07-12 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '0015'
down_revision: Union[str, None] = '0014'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('certificates', sa.Column('source', sa.String(length=16),
                  nullable=False, server_default='network'))


def downgrade() -> None:
    op.drop_column('certificates', 'source')
```

Note: `server_default='network'` backfills every existing row. Confirm `0014` is the current head first: `ls backend/alembic/versions/` — if a higher number exists, set `down_revision` to that and bump this file's number.

- [ ] **Step 3: Run the migration test**

Run: `cd backend && pytest tests/test_migrations.py -v`
Expected: PASS (upgrade from empty DB and from prior head both succeed with the new column).

- [ ] **Step 4: Commit**

```bash
git add backend/app/models.py backend/alembic/versions/0015_certificate_source.py
git commit -m "feat: add Certificate.source discriminator (network|ct)"
```

---

### Task 2: Thread `source` through `_upsert_certificate`

**Files:**
- Modify: `backend/app/scan_engine.py:191-200` (`_upsert_certificate`)
- Test: `backend/tests/test_scan_engine_source.py` (create)

**Interfaces:**
- Consumes: `Certificate.source` (Task 1).
- Produces: `scan_engine._upsert_certificate(db, fields, source="network") -> Certificate`. Existing callers (scan path, `worker._store_issued_cert`) keep the default `"network"`. A CT caller passes `source="ct"`. On an existing fingerprint, `source` is left untouched (provenance of first discovery).

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_scan_engine_source.py`:

```python
from app import scan_engine
from app.models import Certificate


def _fields(fp="AA:BB:CC"):
    return {
        "fingerprint_sha256": fp, "common_name": "h.example.com", "subject": "",
        "sans": [], "issuer": "CN=CA", "issuer_cn": "CA", "serial_number": "1",
        "signature_algorithm": "sha256WithRSAEncryption", "public_key_algorithm": "RSA",
        "public_key_size": 2048, "not_before": None, "not_after": None,
        "self_signed": False, "is_wildcard": False, "is_ca": False,
        "chain_length": 1, "pem": "",
    }


def test_upsert_defaults_to_network(db):
    c = scan_engine._upsert_certificate(db, _fields())
    assert c.source == "network"


def test_upsert_accepts_ct_source(db):
    c = scan_engine._upsert_certificate(db, _fields("DD:EE"), source="ct")
    assert c.source == "ct"


def test_upsert_existing_keeps_original_source(db):
    scan_engine._upsert_certificate(db, _fields("FF:00"), source="ct")
    # a later network scan of the same fingerprint must NOT flip source to network
    again = scan_engine._upsert_certificate(db, _fields("FF:00"), source="network")
    assert again.source == "ct"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_scan_engine_source.py -v`
Expected: FAIL — `_upsert_certificate() got an unexpected keyword argument 'source'`.

- [ ] **Step 3: Implement**

Replace `backend/app/scan_engine.py` `_upsert_certificate` (lines 191-200) with:

```python
def _upsert_certificate(db, fields: dict, source: str = "network") -> Certificate:
    fp = fields["fingerprint_sha256"]
    cert = db.scalar(select(Certificate).where(Certificate.fingerprint_sha256 == fp))
    if cert is None:
        cert = Certificate(**fields, source=source)
        db.add(cert)
        db.flush()
    else:
        cert.last_seen = utcnow()  # preserve first_seen and source; only bump last_seen
    return cert
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_scan_engine_source.py tests/test_scanner.py tests/test_worker.py -v`
Expected: PASS (new tests pass; existing scan/worker tests unaffected because `source` defaults to `"network"`).

- [ ] **Step 5: Commit**

```bash
git add backend/app/scan_engine.py backend/tests/test_scan_engine_source.py
git commit -m "feat: _upsert_certificate accepts source, preserves it on re-upsert"
```

---

### Task 3: `WatchedDomain` model + migration

**Files:**
- Modify: `backend/app/models.py` (add `WatchedDomain` class near the other tables, e.g. after `ReportSchedule`)
- Create: `backend/alembic/versions/0016_watched_domains.py`
- Test: `backend/tests/test_migrations.py` (verify still passes)

**Interfaces:**
- Produces: `WatchedDomain(id, domain: str, enabled: bool, last_checked_at: datetime|None, last_crtsh_id: int|None, created_at: datetime)`.

- [ ] **Step 1: Add the model**

In `backend/app/models.py` (after `class ReportSchedule`):

```python
class WatchedDomain(Base):
    """A domain polled against a Certificate Transparency source (crt.sh) to
    find publicly-issued certs CertWatch never observed on its own network.
    Just the poll list -- discovered certs/findings are not FK'd to it.
    Ticked by `scheduler.ct_tick`, executed by `worker._process_ct_check`."""

    __tablename__ = "watched_domains"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(String(255))  # e.g. example.com; queried as %.example.com
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # high-water mark: max crt.sh entry id already processed for this domain.
    last_crtsh_id: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
```

- [ ] **Step 2: Write the migration**

Create `backend/alembic/versions/0016_watched_domains.py`:

```python
"""watched domains

Revision ID: 0016
Revises: 0015
Create Date: 2026-07-12 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '0016'
down_revision: Union[str, None] = '0015'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('watched_domains',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('last_checked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_crtsh_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('watched_domains')
```

- [ ] **Step 3: Run the migration test**

Run: `cd backend && pytest tests/test_migrations.py -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add backend/app/models.py backend/alembic/versions/0016_watched_domains.py
git commit -m "feat: WatchedDomain model + migration"
```

---

### Task 4: Config settings for CT

**Files:**
- Modify: `backend/app/config.py` (add three settings near the `finding_*` block ~line 92-95)
- Test: `backend/tests/test_ct_config.py` (create)

**Interfaces:**
- Produces: `settings.ct_source_url`, `settings.ct_check_frequency_hours`, `settings.ct_finding_severity`.

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_ct_config.py`:

```python
from app.config import Settings


def test_ct_defaults():
    s = Settings()
    assert s.ct_source_url == "https://crt.sh"
    assert s.ct_check_frequency_hours == 24
    assert s.ct_finding_severity == "warning"


def test_ct_source_url_env(monkeypatch):
    monkeypatch.setenv("CERTWATCH_CT_SOURCE_URL", "http://ct.internal")
    assert Settings().ct_source_url == "http://ct.internal"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_ct_config.py -v`
Expected: FAIL — `AttributeError: 'Settings' object has no attribute 'ct_source_url'`.

- [ ] **Step 3: Implement**

In `backend/app/config.py`, after the `finding_deprecated_sig_substrings` line (~95):

```python
    # --- Certificate Transparency monitoring (Phase 2.5) ---
    # Base URL of the CT source (crt.sh-compatible JSON API). Blank disables
    # CT monitoring entirely and makes ct_tick a no-op. Air-gapped sites can
    # point this at an internal crt.sh mirror/proxy.
    ct_source_url: str = "https://crt.sh"
    ct_check_frequency_hours: int = 24
    ct_finding_severity: str = "warning"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest tests/test_ct_config.py -v`
Expected: PASS.

- [ ] **Step 5: Update `.env.example`**

Append to `.env.example`:

```
# Certificate Transparency monitoring (Phase 2.5). Blank disables the feature.
CERTWATCH_CT_SOURCE_URL=https://crt.sh
CERTWATCH_CT_CHECK_FREQUENCY_HOURS=24
CERTWATCH_CT_FINDING_SEVERITY=warning
```

- [ ] **Step 6: Commit**

```bash
git add backend/app/config.py backend/tests/test_ct_config.py .env.example
git commit -m "feat: CT monitoring config settings"
```

---

### Task 5: `ct_source` client (crt.sh query + cert fetch)

**Files:**
- Create: `backend/app/ct_source.py`
- Test: `backend/tests/test_ct_source.py`

**Interfaces:**
- Consumes: `settings.ct_source_url`.
- Produces:
  - `ct_source.list_entries(base_url: str, domain: str) -> list[dict]` — each dict has at least `id: int` and the raw crt.sh fields. Returns `[]` if `base_url` is blank.
  - `ct_source.fetch_der(base_url: str, crtsh_id: int) -> bytes` — the cert as DER bytes.
  - Both accept an optional `client: httpx.Client | None = None` seam for tests.

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_ct_source.py`. Uses a fake httpx transport so no real network is touched:

```python
import httpx
import pytest

from app import ct_source
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime


def _self_signed_der() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "shadow.example.com")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_list_entries_parses_json():
    def handler(req):
        assert "example.com" in str(req.url)
        return httpx.Response(200, json=[
            {"id": 10, "common_name": "a.example.com"},
            {"id": 11, "common_name": "b.example.com"},
        ])
    entries = ct_source.list_entries("https://crt.sh", "example.com", client=_client(handler))
    assert [e["id"] for e in entries] == [10, 11]


def test_list_entries_blank_url_returns_empty():
    assert ct_source.list_entries("", "example.com") == []


def test_fetch_der_returns_bytes():
    der = _self_signed_der()
    def handler(req):
        assert "d=42" in str(req.url)
        return httpx.Response(200, content=der,
                              headers={"content-type": "application/pkix-cert"})
    out = ct_source.fetch_der("https://crt.sh", 42, client=_client(handler))
    # round-trips through cryptography -> same cert
    assert x509.load_der_x509_certificate(out).subject == x509.load_der_x509_certificate(der).subject
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_ct_source.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.ct_source'`.

- [ ] **Step 3: Implement**

Create `backend/app/ct_source.py`:

```python
"""Certificate Transparency source client (Phase 2.5).

Thin wrapper over a crt.sh-compatible JSON API. `list_entries` returns the
CT log entries for a domain (crt.sh gives metadata but NOT a SHA-256
fingerprint in the list output, so the caller fetches each cert via
`fetch_der` and computes the fingerprint itself). The base URL is
configurable (`settings.ct_source_url`) so air-gapped sites can use a mirror
and tests can point at a MockTransport -- no real network in tests.

ponytail: crt.sh JSON only -- no RFC 6962 log tailing / Merkle proofs.
Upgrade to direct log tailing only if crt.sh rate limits become a real
problem.
"""
from __future__ import annotations

import httpx

# crt.sh returns all historical certs; exclude=expired bounds the first sync
# to the actionable (currently-valid) shadow set.
_TIMEOUT = 30.0


def list_entries(base_url: str, domain: str, client: httpx.Client | None = None) -> list[dict]:
    if not base_url:
        return []
    url = f"{base_url.rstrip('/')}/"
    params = {"q": f"%.{domain}", "output": "json", "exclude": "expired"}
    owns = client is None
    client = client or httpx.Client(timeout=_TIMEOUT)
    try:
        resp = client.get(url, params=params)
        resp.raise_for_status()
        data = resp.json()
    finally:
        if owns:
            client.close()
    return data if isinstance(data, list) else []


def fetch_der(base_url: str, crtsh_id: int, client: httpx.Client | None = None) -> bytes:
    """Fetch one certificate's DER bytes. crt.sh's `?d=<id>` returns the raw
    certificate; handle both DER (application/pkix-cert) and PEM responses."""
    url = f"{base_url.rstrip('/')}/"
    owns = client is None
    client = client or httpx.Client(timeout=_TIMEOUT)
    try:
        resp = client.get(url, params={"d": crtsh_id})
        resp.raise_for_status()
        content = resp.content
    finally:
        if owns:
            client.close()
    if b"-----BEGIN CERTIFICATE-----" in content:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        return x509.load_pem_x509_certificate(content).public_bytes(serialization.Encoding.DER)
    return content
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_ct_source.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/ct_source.py backend/tests/test_ct_source.py
git commit -m "feat: ct_source client (crt.sh list + cert fetch)"
```

---

### Task 6: `unknown_issuance` finding rule

**Files:**
- Modify: `backend/app/findings.py` (add rule fn, register in `ALL_RULE_IDS`, add to cert-scoped candidates in `evaluate_certificate`)
- Test: `backend/tests/test_findings_ct.py` (create)

**Interfaces:**
- Consumes: `Certificate.source` (Task 1); `settings.ct_finding_severity` (Task 4).
- Produces: finding rule id `"unknown_issuance"`, cert-scoped (endpoint_id null), dedupe key `unknown_issuance:{cert.id}`. Fires when `cert.source == "ct" and endpoint is None`; clears when the cert is next evaluated with an endpoint (i.e. network-confirmed).

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_findings_ct.py`:

```python
from app import findings
from app.models import Certificate, Endpoint, Finding, Target, utcnow
import datetime


def _ct_cert(db, fp="CT:01"):
    c = Certificate(
        fingerprint_sha256=fp, common_name="shadow.example.com", issuer="CN=Public CA",
        issuer_cn="Public CA", public_key_algorithm="RSA", public_key_size=2048,
        signature_algorithm="sha256WithRSAEncryption",
        not_before=utcnow() - datetime.timedelta(days=1),
        not_after=utcnow() + datetime.timedelta(days=80),
        self_signed=False, source="ct",
    )
    db.add(c)
    db.flush()
    return c


def test_ct_only_cert_raises_unknown_issuance(db):
    c = _ct_cert(db)
    findings.evaluate_certificate(db, c, endpoint=None)
    rows = db.query(Finding).filter_by(rule_id="unknown_issuance", status="active").all()
    assert len(rows) == 1
    assert rows[0].certificate_id == c.id
    assert rows[0].endpoint_id is None


def test_network_cert_never_raises_unknown_issuance(db):
    c = _ct_cert(db, fp="NET:01")
    c.source = "network"
    db.flush()
    findings.evaluate_certificate(db, c, endpoint=None)
    assert db.query(Finding).filter_by(rule_id="unknown_issuance").count() == 0


def test_unknown_issuance_clears_when_bound_to_endpoint(db):
    c = _ct_cert(db, fp="CT:02")
    findings.evaluate_certificate(db, c, endpoint=None)
    assert db.query(Finding).filter_by(rule_id="unknown_issuance", status="active").count() == 1
    # cert is now observed on the network: bind it to an endpoint and re-evaluate
    t = Target(name="g", target_type="hostname", value="shadow.example.com",
               ports=[443], environment="prod")
    db.add(t); db.flush()
    ep = Endpoint(target_id=t.id, host="shadow.example.com", ip="10.0.0.9", port=443,
                  current_cert_id=c.id, last_status="ok")
    db.add(ep); db.flush()
    findings.evaluate_certificate(db, c, endpoint=ep)
    active = db.query(Finding).filter_by(rule_id="unknown_issuance", status="active").count()
    cleared = db.query(Finding).filter_by(rule_id="unknown_issuance", status="cleared").count()
    assert active == 0 and cleared == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_findings_ct.py -v`
Expected: FAIL — no `unknown_issuance` finding is produced.

- [ ] **Step 3: Implement**

In `backend/app/findings.py`:

(a) Add `"unknown_issuance"` to `ALL_RULE_IDS` (line ~30-32). It is NOT endpoint-scoped:

```python
ALL_RULE_IDS = ENDPOINT_SCOPED_RULE_IDS | {
    "weak_key", "deprecated_signature", "long_lifetime", "expiring", "expired",
    "unknown_issuance",
}
```

(b) Add the rule function (after `_expiring`, before `_self_signed_prod`):

```python
def _unknown_issuance(cert: Certificate, endpoint: Endpoint | None) -> dict | None:
    # Fires only for a CT-discovered cert not currently bound to any endpoint.
    # evaluate_certificate runs with endpoint=None exactly for certs no Endpoint
    # references (see evaluate_all), so "endpoint is None" == "unbound" here --
    # no extra query. When a scan later binds this fingerprint to an endpoint,
    # this cert is re-evaluated WITH an endpoint, the candidate disappears, and
    # the existing active->cleared logic clears the finding.
    if cert.source != "ct" or endpoint is not None:
        return None
    return _candidate(
        "unknown_issuance", settings.ct_finding_severity,
        f"Certificate found in CT logs but not on the network ({cert.common_name or cert.fingerprint_sha256})",
        f"Certificate {cert.common_name or cert.fingerprint_sha256} (issuer '{cert.issuer}') was "
        f"discovered in a Certificate Transparency log for a watched domain but has never been "
        f"observed on any scanned endpoint. Possible shadow IT, unsanctioned CA issuance, or a "
        f"forgotten/external service.",
    )
```

(c) In `evaluate_certificate`, add it to the cert-scoped candidates block (the first `candidates = [...]`, ~line 162-168). Pass `endpoint`:

```python
    candidates = [c for c in (
        _weak_key(cert, th),
        _deprecated_signature(cert, th),
        _long_lifetime(cert, th),
        _expired(cert, now),
        _expiring(cert, now),
        _unknown_issuance(cert, endpoint),
    ) if c]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_findings_ct.py tests/test_findings.py -v`
Expected: PASS (new CT tests pass; existing findings tests unaffected — non-CT certs never trigger the new rule).

- [ ] **Step 5: Commit**

```bash
git add backend/app/findings.py backend/tests/test_findings_ct.py
git commit -m "feat: unknown_issuance finding rule for CT-only certs"
```

---

### Task 7: Worker `ct_check` handler

**Files:**
- Modify: `backend/app/worker.py` (add `elif item.kind == "ct_check"` in `process_one`, add `_process_ct_check`, import `ct_source`, `findings`, `WatchedDomain`, `parse_certificate` already imported)
- Test: `backend/tests/test_worker_ct.py` (create)

**Interfaces:**
- Consumes: `ct_source.list_entries` / `fetch_der` (Task 5); `scan_engine._upsert_certificate(..., source="ct")` (Task 2); `findings.evaluate_certificate` (Task 6); `WatchedDomain` (Task 3); `settings.ct_source_url` (Task 4).
- Produces: `worker._process_ct_check(db, item)` — payload `{"domain_id": int}`. Ingests unknown CT certs, advances `WatchedDomain.last_crtsh_id`/`last_checked_at`, then `queue.complete`; any error → `queue.fail`.

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_worker_ct.py`. Monkeypatches `ct_source` so no network is used:

```python
import datetime

from app import worker, ct_source
from app.models import Certificate, Endpoint, Finding, Target, WatchedDomain, WorkQueue, utcnow
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _der(cn="shadow.example.com"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=90))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def _watched(db, domain="example.com", last_id=None):
    w = WatchedDomain(domain=domain, enabled=True, last_crtsh_id=last_id)
    db.add(w); db.commit()
    return w


def _enqueue_ct(db, domain_id):
    item = WorkQueue(kind="ct_check", payload={"domain_id": domain_id})
    db.add(item); db.commit()
    return worker.queue.claim(db)


def test_ct_check_ingests_unknown_cert_and_raises_finding(db, monkeypatch):
    w = _watched(db)
    der = _der()
    monkeypatch.setattr(ct_source, "list_entries", lambda base, dom, **k: [{"id": 100}])
    monkeypatch.setattr(ct_source, "fetch_der", lambda base, cid, **k: der)
    monkeypatch.setattr(worker.settings, "ct_source_url", "https://crt.sh", raising=False)

    item = _enqueue_ct(db, w.id)
    worker._process_ct_check(db, item)

    certs = db.query(Certificate).filter_by(source="ct").all()
    assert len(certs) == 1
    assert db.query(Finding).filter_by(rule_id="unknown_issuance", status="active").count() == 1
    db.refresh(w)
    assert w.last_crtsh_id == 100
    assert w.last_checked_at is not None
    assert db.get(WorkQueue, item.id).status == "done"


def test_ct_check_skips_entries_at_or_below_watermark(db, monkeypatch):
    w = _watched(db, last_id=100)
    monkeypatch.setattr(ct_source, "list_entries", lambda base, dom, **k: [{"id": 100}, {"id": 50}])
    calls = []
    monkeypatch.setattr(ct_source, "fetch_der", lambda base, cid, **k: calls.append(cid) or _der())
    item = _enqueue_ct(db, w.id)
    worker._process_ct_check(db, item)
    assert calls == []  # nothing above watermark -> no fetches
    assert db.query(Certificate).count() == 0


def test_ct_check_known_fingerprint_no_finding(db, monkeypatch):
    # a cert already in inventory (network) that also shows up in CT must NOT
    # create a finding
    der = _der("known.example.com")
    from app.scanner import parse_certificate
    fields = parse_certificate(der)
    existing = Certificate(**fields, source="network")
    db.add(existing); db.commit()
    w = _watched(db)
    monkeypatch.setattr(ct_source, "list_entries", lambda base, dom, **k: [{"id": 200}])
    monkeypatch.setattr(ct_source, "fetch_der", lambda base, cid, **k: der)
    item = _enqueue_ct(db, w.id)
    worker._process_ct_check(db, item)
    assert db.query(Finding).filter_by(rule_id="unknown_issuance").count() == 0
    assert db.query(Certificate).count() == 1  # deduped by fingerprint


def test_ct_check_fetch_error_fails_item(db, monkeypatch):
    w = _watched(db)
    monkeypatch.setattr(ct_source, "list_entries", lambda base, dom, **k: [{"id": 300}])
    def boom(base, cid, **k):
        raise RuntimeError("crt.sh unreachable")
    monkeypatch.setattr(ct_source, "fetch_der", boom)
    item = _enqueue_ct(db, w.id)
    worker._process_ct_check(db, item)
    q = db.get(WorkQueue, item.id)
    assert q.status in ("queued", "failed")  # queue.fail requeues until max_attempts
    assert "crt.sh unreachable" in (q.last_error or "")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_worker_ct.py -v`
Expected: FAIL — `AttributeError: module 'app.worker' has no attribute '_process_ct_check'`.

- [ ] **Step 3: Implement**

In `backend/app/worker.py`:

(a) Extend imports — add `ct_source`, `findings`, `scan_engine` (already imported), and `WatchedDomain` to the `.models` import and `settings`:

```python
from . import alerts, ct_source, findings, lifecycle, queue, reports, scan_engine, secrets
from .config import settings
```
and add `WatchedDomain` to the `from .models import (...)` block.

(b) Add the dispatch branch in `process_one` (after the `report` branch, before `else`):

```python
    elif item.kind == "ct_check":
        _process_ct_check(db, item)
```

(c) Add the handler (near `_process_report`):

```python
def _process_ct_check(db, item) -> None:
    """Run the `ct_check` queue step (Phase 2.5): poll the CT source for one
    WatchedDomain, ingest any cert whose fingerprint isn't already in inventory
    as source="ct", and run the findings engine so unknown_issuance fires.
    Advances the domain's crt.sh high-water mark. Fail-closed: any error fails
    the queue item (retry/backoff) and never crashes the worker."""
    domain_id = item.payload.get("domain_id")
    domain = db.get(WatchedDomain, domain_id) if domain_id is not None else None
    if domain is None:
        queue.fail(db, item, f"watched domain {domain_id!r} not found")
        return
    if not settings.ct_source_url:
        # feature disabled after this item was enqueued -- nothing to do
        queue.complete(db, item)
        return
    try:
        entries = ct_source.list_entries(settings.ct_source_url, domain.domain)
        watermark = domain.last_crtsh_id or 0
        max_id = watermark
        for entry in entries:
            eid = entry.get("id")
            if eid is None or eid <= watermark:
                continue
            max_id = max(max_id, eid)
            der = ct_source.fetch_der(settings.ct_source_url, eid)
            fields = parse_certificate(der)
            existing = db.scalar(
                select(Certificate).where(
                    Certificate.fingerprint_sha256 == fields["fingerprint_sha256"]
                )
            )
            cert = scan_engine._upsert_certificate(db, fields, source="ct")
            db.flush()
            # Only run findings for a genuinely new CT cert (unbound). A
            # fingerprint already in inventory is network-known -> no finding.
            if existing is None:
                findings.evaluate_certificate(db, cert, endpoint=None)
        domain.last_crtsh_id = max_id
        domain.last_checked_at = utcnow()
        db.commit()
    except Exception as e:  # noqa: BLE001 - any CT failure must not kill the worker
        log.exception("ct_check failed for domain %s (queue item %s)", domain_id, item.id)
        db.rollback()
        queue.fail(db, item, str(e))
    else:
        queue.complete(db, item)
```

Note: add `from sqlalchemy import select` is already imported in worker.py (line 27). `Certificate` is already imported.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_worker_ct.py tests/test_worker.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/worker.py backend/tests/test_worker_ct.py
git commit -m "feat: worker ct_check handler ingests CT certs + raises findings"
```

---

### Task 8: `ct_tick` scheduler job

**Files:**
- Modify: `backend/app/scheduler.py` (add `ct_tick`, register in `start_scheduler`, import `WatchedDomain`)
- Test: `backend/tests/test_scheduler_ct.py` (create)

**Interfaces:**
- Consumes: `WatchedDomain` (Task 3); `settings.ct_source_url`, `settings.ct_check_frequency_hours` (Task 4); `queue.enqueue` (existing).
- Produces: `scheduler.ct_tick()` — enqueues a `ct_check` for each enabled, due domain with no in-flight `ct_check` item; no-op when `ct_source_url` is blank.

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_scheduler_ct.py`:

```python
import datetime

from app import scheduler
from app.models import WatchedDomain, WorkQueue, utcnow


def _watched(db, **kw):
    w = WatchedDomain(domain=kw.pop("domain", "example.com"), enabled=kw.pop("enabled", True), **kw)
    db.add(w); db.commit()
    return w


def test_ct_tick_enqueues_due_domain(db, monkeypatch):
    monkeypatch.setattr(scheduler.settings, "ct_source_url", "https://crt.sh", raising=False)
    monkeypatch.setattr(scheduler, "SessionLocal", lambda: db)
    _watched(db, last_checked_at=None)
    scheduler.ct_tick()
    assert db.query(WorkQueue).filter_by(kind="ct_check").count() == 1


def test_ct_tick_skips_recently_checked(db, monkeypatch):
    monkeypatch.setattr(scheduler.settings, "ct_source_url", "https://crt.sh", raising=False)
    monkeypatch.setattr(scheduler.settings, "ct_check_frequency_hours", 24, raising=False)
    monkeypatch.setattr(scheduler, "SessionLocal", lambda: db)
    _watched(db, last_checked_at=utcnow() - datetime.timedelta(hours=1))
    scheduler.ct_tick()
    assert db.query(WorkQueue).filter_by(kind="ct_check").count() == 0


def test_ct_tick_noop_when_disabled(db, monkeypatch):
    monkeypatch.setattr(scheduler.settings, "ct_source_url", "", raising=False)
    monkeypatch.setattr(scheduler, "SessionLocal", lambda: db)
    _watched(db, last_checked_at=None)
    scheduler.ct_tick()
    assert db.query(WorkQueue).filter_by(kind="ct_check").count() == 0


def test_ct_tick_skips_domain_with_inflight_item(db, monkeypatch):
    monkeypatch.setattr(scheduler.settings, "ct_source_url", "https://crt.sh", raising=False)
    monkeypatch.setattr(scheduler, "SessionLocal", lambda: db)
    w = _watched(db, last_checked_at=None)
    db.add(WorkQueue(kind="ct_check", payload={"domain_id": w.id}, status="queued"))
    db.commit()
    scheduler.ct_tick()
    assert db.query(WorkQueue).filter_by(kind="ct_check").count() == 1  # not duplicated
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_scheduler_ct.py -v`
Expected: FAIL — `AttributeError: module 'app.scheduler' has no attribute 'ct_tick'`.

- [ ] **Step 3: Implement**

In `backend/app/scheduler.py`:

(a) Add `WatchedDomain` to the `from .models import (...)` block.

(b) Add the tick function (after `report_tick`):

```python
def ct_tick() -> None:
    """Phase 2.5: enqueue a `ct_check` for every enabled WatchedDomain whose
    cadence (CERTWATCH_CT_CHECK_FREQUENCY_HOURS) has elapsed and that has no
    in-flight ct_check item. No-op when CT monitoring is disabled
    (CERTWATCH_CT_SOURCE_URL blank). Mirrors report_tick's in-flight guard."""
    if not settings.ct_source_url:
        return
    db = SessionLocal()
    try:
        now = utcnow()
        cadence = timedelta(hours=settings.ct_check_frequency_hours)
        pending = db.scalars(select(WorkQueue).where(
            WorkQueue.kind == "ct_check", WorkQueue.status.in_(["queued", "leased"]),
        )).all()
        inflight_ids = {w.payload.get("domain_id") for w in pending}
        domains = db.scalars(select(WatchedDomain).where(WatchedDomain.enabled.is_(True))).all()
        for d in domains:
            last = _aware(d.last_checked_at) if d.last_checked_at else None
            if last is not None and now - last < cadence:
                continue
            if d.id in inflight_ids:
                continue
            queue.enqueue(db, "ct_check", {"domain_id": d.id})
            log.info("ct_check enqueued for watched domain %s", d.domain)
    except Exception:
        log.exception("ct tick failed")
    finally:
        db.close()
```

(c) Register it in `start_scheduler` (after the `report_tick` add_job):

```python
    _scheduler.add_job(ct_tick, "interval", hours=1, id="ct_tick", max_instances=1)
```

Note: the job runs hourly but only enqueues domains actually past their per-domain cadence — the same pattern renewal_tick/report_tick use (frequent tick, cadence gate inside).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_scheduler_ct.py tests/test_scheduler.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/scheduler.py backend/tests/test_scheduler_ct.py
git commit -m "feat: ct_tick scheduler job enqueues due watched domains"
```

---

### Task 9: Watched-domains API + `source` on cert serialization/filter

**Files:**
- Modify: `backend/app/main.py` (add watched-domain routes; add `source` filter to `list_certificates`)
- Modify: `backend/app/serialize.py:12-41` (`cert_dict` — add `"source"`)
- Test: `backend/tests/test_watched_domains_api.py` (create)

**Interfaces:**
- Consumes: `WatchedDomain` (Task 3); `require_role`, `audit` (existing); `queue.enqueue` (existing).
- Produces: `GET/POST /api/watched-domains`, `DELETE /api/watched-domains/{id}`, `POST /api/watched-domains/{id}/check`; `cert_dict(...)["source"]`; `?source=` filter on `GET /api/certificates`.

- [ ] **Step 1: Add `source` to `cert_dict` (and a failing API test)**

In `backend/app/serialize.py`, in `cert_dict`'s returned dict (after `"chain_length": cert.chain_length,`):

```python
        "source": cert.source,
```

Create `backend/tests/test_watched_domains_api.py`:

```python
def test_crud_watched_domains(client, monkeypatch):
    from tests.conftest import login_as
    login_as(client, "admin", monkeypatch)

    r = client.post("/api/watched-domains", json={"domain": "example.com"})
    assert r.status_code == 200, r.text
    did = r.json()["id"]

    r = client.get("/api/watched-domains")
    assert any(d["domain"] == "example.com" for d in r.json()["items"])

    r = client.post(f"/api/watched-domains/{did}/check")
    assert r.status_code == 200

    r = client.delete(f"/api/watched-domains/{did}")
    assert r.status_code == 200
    assert all(d["id"] != did for d in client.get("/api/watched-domains").json()["items"])


def test_watched_domains_require_admin(client, monkeypatch):
    from tests.conftest import login_as
    login_as(client, "operator", monkeypatch)
    r = client.post("/api/watched-domains", json={"domain": "x.com"})
    assert r.status_code == 403


def test_certificates_source_filter(client, monkeypatch):
    from tests.conftest import login_as
    from app.db import SessionLocal
    from app.models import Certificate
    login_as(client, "viewer", monkeypatch)
    s = SessionLocal()
    s.add(Certificate(fingerprint_sha256="Z:1", common_name="n", source="ct"))
    s.add(Certificate(fingerprint_sha256="Z:2", common_name="n", source="network"))
    s.commit(); s.close()
    r = client.get("/api/certificates?source=ct")
    items = r.json()["items"]
    assert items and all(i["source"] == "ct" for i in items)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_watched_domains_api.py -v`
Expected: FAIL — 404 on `/api/watched-domains`.

- [ ] **Step 3: Implement the routes and filter**

In `backend/app/main.py`, add the `source` filter to `list_certificates` — add a parameter and a where-clause:

```python
    source: str = "",
```
and after the `issuer` filter block (~line 353):

```python
    if source:
        stmt = stmt.where(Certificate.source == source)
```

Add the watched-domain routes (near the findings routes, ~after line 639). Use a Pydantic body or inline dict — match the file's existing style (check how `create_target` reads its body and mirror it):

```python
@app.get("/api/watched-domains", dependencies=[Depends(require_role("viewer"))])
def list_watched_domains(db: Session = Depends(get_db)):
    rows = db.scalars(select(WatchedDomain).order_by(WatchedDomain.domain.asc())).all()
    return {"items": [{
        "id": w.id, "domain": w.domain, "enabled": w.enabled,
        "last_checked_at": w.last_checked_at, "last_crtsh_id": w.last_crtsh_id,
        "created_at": w.created_at,
    } for w in rows]}


@app.post("/api/watched-domains")
def create_watched_domain(
    body: dict,
    principal: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    domain = (body.get("domain") or "").strip().lower()
    if not domain:
        raise HTTPException(status_code=422, detail="domain is required")
    w = WatchedDomain(domain=domain, enabled=bool(body.get("enabled", True)))
    db.add(w)
    db.commit()
    audit(db, principal["email"], "watched_domain.create", "watched_domain", w.id, domain)
    return {"id": w.id, "domain": w.domain, "enabled": w.enabled}


@app.delete("/api/watched-domains/{domain_id}")
def delete_watched_domain(
    domain_id: int,
    principal: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    w = db.get(WatchedDomain, domain_id)
    if w is None:
        raise HTTPException(status_code=404, detail="not found")
    db.delete(w)
    db.commit()
    audit(db, principal["email"], "watched_domain.delete", "watched_domain", domain_id, w.domain)
    return {"ok": True}


@app.post("/api/watched-domains/{domain_id}/check")
def check_watched_domain(
    domain_id: int,
    principal: dict = Depends(require_role("operator")),
    db: Session = Depends(get_db),
):
    w = db.get(WatchedDomain, domain_id)
    if w is None:
        raise HTTPException(status_code=404, detail="not found")
    queue.enqueue(db, "ct_check", {"domain_id": w.id})
    audit(db, principal["email"], "watched_domain.check", "watched_domain", w.id, w.domain)
    return {"ok": True}
```

Add `WatchedDomain` to `main.py`'s models import, and confirm `queue`, `HTTPException`, `select` are already imported (they are — used by other routes).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_watched_domains_api.py tests/test_api.py tests/test_rbac.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/main.py backend/app/serialize.py backend/tests/test_watched_domains_api.py
git commit -m "feat: watched-domains API + source filter/field on certificates"
```

---

### Task 10: Frontend — Watched Domains settings + CT badge

**Files:**
- Modify: `frontend/src/` — Settings page (add a Watched Domains section), Certificates list (render a `CT` badge on `source === "ct"`), and `api.ts` (add the endpoints). Exact filenames: inspect `frontend/src/` first — the README lists a Settings page and Certificates page plus shared `ui.tsx`, `api.ts`.
- Test: `cd frontend && npm run build` (type-check + production build is the frontend test gate per README).

**Interfaces:**
- Consumes: `GET/POST/DELETE /api/watched-domains`, `POST /api/watched-domains/{id}/check`, `source` field on certificates (Task 9).

- [ ] **Step 1: Inspect the frontend structure**

Run: `ls frontend/src frontend/src/pages 2>/dev/null` and open `frontend/src/api.ts` and the Settings + Certificates page components to learn the existing fetch/list/badge patterns. Follow them exactly — do not introduce a new data-fetching pattern.

- [ ] **Step 2: Add API client functions**

In `frontend/src/api.ts`, mirror the existing channel/target CRUD helpers:

```typescript
export const listWatchedDomains = () => api<{items: WatchedDomain[]}>("/api/watched-domains");
export const createWatchedDomain = (domain: string) =>
  api("/api/watched-domains", { method: "POST", body: JSON.stringify({ domain }) });
export const deleteWatchedDomain = (id: number) =>
  api(`/api/watched-domains/${id}`, { method: "DELETE" });
export const checkWatchedDomain = (id: number) =>
  api(`/api/watched-domains/${id}/check`, { method: "POST" });
```
Add a `WatchedDomain` type matching the API response, and add `source` to the existing Certificate type.

- [ ] **Step 3: Add the Watched Domains settings section**

In the Settings page, add a section mirroring the existing SMTP/Teams channel sections: a list of watched domains (domain, last checked, last crtsh id), an add-domain input, a remove button per row, and a "Check now" button per row calling `checkWatchedDomain`. Admin-only actions can surface a 403 the same way existing admin-only settings do.

- [ ] **Step 4: Add the CT badge**

In the Certificates list, where existing badges render (self-signed, expiring), add: `{cert.source === "ct" && <Badge>CT</Badge>}` using the existing badge component from `ui.tsx`. Optionally add a `source` filter control mirroring the existing view filters.

- [ ] **Step 5: Build**

Run: `cd frontend && npm run build`
Expected: PASS (no type errors, production build succeeds).

- [ ] **Step 6: Commit**

```bash
git add frontend/src
git commit -m "feat: Watched Domains settings section + CT badge on certificates"
```

---

### Task 11: Dashboard counts exclude CT-only certs + docs

**Files:**
- Modify: `backend/app/main.py` (the `/api/dashboard` route — scope expiry/health counts to `source == "network"`)
- Modify: `README.md` (document CT monitoring under inventory/how-it-works + the three env vars)
- Test: `backend/tests/test_dashboard_ct.py` (create)

**Interfaces:**
- Consumes: `Certificate.source` (Task 1).

- [ ] **Step 1: Locate the dashboard aggregation**

Run: `grep -n "dashboard" backend/app/main.py` and read the route. Identify each expiry/health count query over `Certificate`.

- [ ] **Step 2: Write the failing test**

Create `backend/tests/test_dashboard_ct.py`:

```python
import datetime

from app.models import Certificate, utcnow


def test_dashboard_excludes_ct_certs_from_expiry_counts(client, monkeypatch):
    from tests.conftest import login_as
    from app.db import SessionLocal
    login_as(client, "viewer", monkeypatch)
    s = SessionLocal()
    soon = utcnow() + datetime.timedelta(days=5)
    s.add(Certificate(fingerprint_sha256="N:1", common_name="n", not_after=soon, source="network"))
    s.add(Certificate(fingerprint_sha256="C:1", common_name="c", not_after=soon, source="ct"))
    s.commit(); s.close()
    data = client.get("/api/dashboard").json()
    # exactly one expiring-soon cert counted (the network one); CT one excluded.
    # adjust the key below to the dashboard's actual expiring-<=7d field name.
    assert data["expiring_7d"] == 1
```

Before running, open the dashboard route and replace `expiring_7d` with the real response key. If the dashboard has no such field, assert on whichever expiry/health count exists and is affected.

- [ ] **Step 3: Run test to verify it fails**

Run: `cd backend && pytest tests/test_dashboard_ct.py -v`
Expected: FAIL — both certs counted (returns 2, not 1).

- [ ] **Step 4: Implement**

In the `/api/dashboard` route, add `Certificate.source == "network"` to the WHERE clause of each expiry/health count over `Certificate`. Leave any "total certificates" count as-is if you want CT certs visible in the inventory total — but the expiring/expired/healthy severity tiles must filter to network. Add a short comment:

```python
    # ponytail: dashboard operational tiles count network-observed certs only;
    # CT-discovered shadow certs surface via the unknown_issuance finding, not
    # these tiles, so they don't inflate expiry/health metrics.
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd backend && pytest tests/test_dashboard_ct.py tests/test_api.py -v`
Expected: PASS.

- [ ] **Step 6: Document in README**

Add a short CT monitoring subsection under "Using CertWatch" / inventory, describing Watched Domains, the `source=ct` inventory badge, the `unknown_issuance` finding, and the fact that dashboard tiles exclude CT certs. Add the three env vars to the "Environment variables" list.

- [ ] **Step 7: Commit**

```bash
git add backend/app/main.py backend/tests/test_dashboard_ct.py README.md
git commit -m "feat: exclude CT-only certs from dashboard tiles; document CT monitoring"
```

---

### Task 12: Full suite + wiring verification

**Files:** none (verification only).

- [ ] **Step 1: Run the whole backend suite**

Run: `cd backend && pytest -q`
Expected: PASS — all pre-existing tests plus the new CT tests. Investigate any failure before proceeding.

- [ ] **Step 2: Frontend build**

Run: `cd frontend && npm run build`
Expected: PASS.

- [ ] **Step 3: End-to-end smoke (real worker path, fake CT source)**

Write a throwaway check (or a `tests/test_ct_end_to_end.py`) that: creates a `WatchedDomain`, monkeypatches `ct_source.list_entries`/`fetch_der` to return one self-signed DER, runs `scheduler.ct_tick()` then `worker.process_one(db)` in a loop until the queue drains, and asserts a `source=ct` Certificate and an active `unknown_issuance` Finding exist. This proves tick → enqueue → worker → ingest → finding is wired end to end (each unit is already tested; this guards the seams).

Run: `cd backend && pytest tests/test_ct_end_to_end.py -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add backend/tests/test_ct_end_to_end.py
git commit -m "test: CT monitoring end-to-end (tick -> worker -> ingest -> finding)"
```

---

## Self-Review Notes

- **Spec coverage:** WatchedDomain (T3), source column (T1), unknown_issuance finding + clear-on-bind (T6), ct_source configurable client (T4/T5), ct_check worker with watermark + fingerprint dedup + fail-closed (T7), ct_tick with in-flight guard + disabled no-op (T8), API + source filter (T9), inventory badge (T10), dashboard exclusion (T11), config (T4), tests incl. migration/error/disabled/dedup/clear (throughout). All spec sections mapped.
- **Deliberate ceilings preserved in code comments:** crt.sh-only (T5), fixed severity (T6), source-as-provenance (T1/T2).
- **Type consistency:** `_upsert_certificate(db, fields, source="network")` used identically in T2 and T7; `_process_ct_check(db, item)` and `ct_tick()` names consistent across T7/T8/T12; `WatchedDomain` field names consistent T3→T7/T8/T9.
- **Open confirmations for the implementer (not blockers):** exact `/api/dashboard` response keys (T11 Step 1 resolves), exact frontend filenames/badge component (T10 Step 1 resolves), and that `0014` is the current alembic head (T1 Step 2 resolves).
