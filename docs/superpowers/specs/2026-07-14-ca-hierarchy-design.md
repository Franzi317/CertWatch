# CA Hierarchy View — Design

**Phase:** 2.5, item 2.5.3 (see `docs/superpowers/plans/2026-07-03-certwatch-competitive-roadmap.md`).
**Date:** 2026-07-14
**Status:** Approved, ready for implementation planning.

## Goal

Give operators visibility into the intermediate and root CA certificates their
estate depends on, and alert when one is approaching expiry. Today CertWatch
captures the full chain (Python 3.13+ `get_unverified_chain`) but only stores
the **leaf** as a `Certificate` row — the intermediates/roots are embedded in
the leaf's concatenated `pem` blob with no independent inventory. One expiring
intermediate can be a thousand-certificate outage, and nothing surfaces it.

## Approved approach (decided)

Reuse the `Certificate` table with a new `source="chain"` discriminator rather
than a dedicated CA table. This leverages `parse_certificate`, the existing
`source` field, the dashboard-tile exclusion already built for CT (tiles filter
`source=="network"`, so `chain` certs are excluded for free), `AlertEvent.certificate_id`,
and the existing inventory serialization.

## Scope

**In:** extract CA certs from stored leaf chains into `source="chain"`
`Certificate` rows; a leaf→CA linkage column; a derivation pass; an
`issuer_expiring` alert with auto-resolve; a CA-certificates API + a dedicated
CA view page; one dashboard tile; exclusion of `chain` certs from the findings
engine.

**Out (deliberate ceilings):**
- Flat sortable CA list, **not** a leaf→intermediate→root tree/graph visualization.
- Crypto-risk **findings** on CA certs (weak-key / SHA-1 intermediate) deferred —
  only expiry is surfaced for CAs in this phase.
- Depends on full-chain capture (Python 3.13+, which the Docker image ships).
  On leaf-only runtimes there is no chain data and the CA view is simply empty —
  no special handling.

## Component 1 — extraction & data model

- **`source` discriminator** extends to `network | ct | chain`. `source` is
  already a `String(16)` column, so no column-type migration — just the new value.
- **New column `Certificate.chain_ca_fingerprints`** (JSON, default `[]`,
  nullable): for a **leaf**, the SHA-256 fingerprints of its non-leaf chain
  members (its issuing CAs); `[]` for CA rows and chainless leaves; **NULL**
  means "not yet derived". One Alembic migration, revision `0017` (current head
  is `0016` watched_domains; verify at implementation time): nullable JSON
  column, no backfill — NULL is the not-yet-derived sentinel.
- **New module `backend/app/ca_hierarchy.py`**, function `derive(db) -> int`:
  - Select leaves (`source != "chain"`) with `chain_ca_fingerprints IS NULL`.
    Leaf PEM blobs are immutable once stored (a rotation is a new fingerprint =
    a new row), so a leaf only needs deriving once — this makes the pass
    incremental and cheap after the first run.
  - For each such leaf: split `cert.pem` into PEM blocks (reuse the
    `_PEM_CERT_RE`-style splitter — currently in `worker.py`; move it to a
    shared location or duplicate the small regex), parse each **non-leaf** block
    (`parse_certificate(der)`), `scan_engine._upsert_certificate(db, fields, source="chain")`
    (dedup by fingerprint), and collect the members' fingerprints.
  - Set `leaf.chain_ca_fingerprints` to the collected list (`[]` if
    `chain_length <= 1`).
  - Returns the number of CA certs currently known. Runs post-scan in
    `scan_engine.run_scan_job` **before** `evaluate_alerts` (so CA rows exist and
    the alert section can see them), non-fatal (a derivation error must never
    fail a scan), mirroring how `findings.evaluate_all` is invoked.
  - `is_root` for a CA member = `self_signed and is_ca` (both already computed by
    `parse_certificate`).

- **Dependent counts are computed live**, not stored: a `Counter` rollup over
  all leaves' `chain_ca_fingerprints`. `ponytail:` a full leaf scan per
  view/alert pass is fine at this scale; no denormalized `dependent_count`
  column on the shared table.

## Component 2 — `issuer_expiring` alert

- A new section in `alerts.evaluate_alerts` (or a helper in `ca_hierarchy.py`
  that returns desired-alert dicts which `evaluate_alerts` merges): for each
  `source="chain"` CA cert **with ≥1 dependent leaf**, compute days-until-expiry;
  if within a configured threshold, emit a desired alert:
  `rule_type="issuer_expiring"`, `certificate_id=<CA cert id>`, `endpoint_id=None`,
  `threshold_days=<band>`, `severity=severity(days)`, message including the CA
  subject/CN, the dependent-leaf count, and the expiry phrase.
- Reuses the existing desired/existing reconcile loop in `evaluate_alerts`, so
  an `issuer_expiring` alert **auto-resolves** when the intermediate is renewed
  (the new intermediate is a different fingerprint; the old CA cert drops to 0
  dependents and is no longer in the desired set). `issuer_expiring` is a normal
  (reconciled) rule type, NOT a one-off.
- Thresholds from a `ca_alert_thresholds` system setting (read via the existing
  `get_setting`), **default `"180,90,30"`** — intermediates need long renewal
  lead time. Parsed like other comma-separated threshold settings.
- Dispatches through the existing channel machinery (email/Teams/webhook) with
  no changes; a recommended-action entry for `issuer_expiring` is added to the
  action map in `alerts.py`.

## Component 3 — findings interaction

- `findings.evaluate_all` excludes `source="chain"` certs (add
  `Certificate.source != "chain"` to its `all_certs` query). Rationale: CA certs
  are not endpoint-served leaves; `long_lifetime` would fire on every
  intermediate (CAs legitimately live 10–20 years) and `expiring`/`expired`
  would double the new `issuer_expiring` alert. `ponytail:` crypto-risk findings
  on CA certs deferred.

## Component 4 — API, view, dashboard

- **`GET /api/ca-certificates`** (viewer): returns `source="chain"` certs
  enriched with `dependent_count` (live rollup) and `is_root`, sorted by
  `not_after` ascending (soonest expiry first). Reuses `cert_dict` plus the
  computed `dependent_count`/`is_root` fields.
- **CA Certificates page** (new frontend nav entry): a sortable list — subject/CN,
  issuer, expiry phrase + severity badge, root vs intermediate, dependent-leaf
  count. Mirrors the existing Certificates list component/patterns.
- **Dashboard tile**: one card, "CA certs expiring ≤90d" — count of
  `source="chain"` certs with ≥1 dependent whose `not_after` is within 90 days.
  Added to the `/api/dashboard` response and rendered as a card.
- `issuer_expiring` alerts render on the existing Alerts page with no change
  (a `status_phrase`/action-map entry gives them a friendly label).

## Testing

- **`ca_hierarchy.derive`**: a generated leaf + intermediate chain (leaf `pem` =
  leaf+intermediate PEM) yields one `source="chain"` intermediate row and the
  leaf's `chain_ca_fingerprints` = `[intermediate fp]`; a chainless leaf →
  `chain_ca_fingerprints=[]`, no CA row; two leaves sharing one intermediate →
  a single deduped CA row; re-running `derive` is a no-op for already-derived
  leaves (idempotent, and doesn't re-parse them).
- **Dependent count**: rollup returns the correct count per CA fingerprint.
- **`issuer_expiring` alert**: an intermediate within threshold with ≥1 dependent
  raises the alert (correct rule_type/severity/message with count); an
  intermediate with 0 dependents does not; after the dependents' leaves rotate
  away, the alert auto-resolves on the next `evaluate_alerts`.
- **Findings exclusion**: a `source="chain"` cert is not evaluated by
  `findings.evaluate_all` (no `long_lifetime`/`expiring` finding created for it).
- **API**: `/api/ca-certificates` returns CAs sorted by expiry with
  `dependent_count` and `is_root`; a viewer role can read it.
- **Dashboard**: the CA-expiring count reflects only `chain` certs with
  dependents within 90 days.

## Files

- Create: `backend/app/ca_hierarchy.py`, `backend/alembic/versions/0017_chain_ca_fingerprints.py`,
  `backend/tests/test_ca_hierarchy.py`, `backend/tests/test_ca_alerts.py`,
  `backend/tests/test_ca_api.py`, a new frontend CA page under `frontend/src/pages/`.
- Modify: `backend/app/models.py` (new column), `backend/app/scan_engine.py`
  (call `ca_hierarchy.derive` post-scan; extraction helper reuse), `backend/app/alerts.py`
  (`issuer_expiring` section + action-map entry), `backend/app/findings.py`
  (exclude `source="chain"`), `backend/app/main.py` (`/api/ca-certificates`,
  dashboard tile), `backend/app/status.py` (friendly phrase if needed),
  `frontend/src/api.ts`, `frontend/src/App.tsx` (nav), `frontend/src/pages/Dashboard.tsx`
  (tile), `README.md`.
