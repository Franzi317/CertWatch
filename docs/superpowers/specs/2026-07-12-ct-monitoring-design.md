# Certificate Transparency (CT) Monitoring — Design

**Phase:** 2.5, item 2.5.1 (see `docs/superpowers/plans/2026-07-03-certwatch-competitive-roadmap.md`).
**Date:** 2026-07-12
**Status:** Approved, ready for implementation planning.

## Goal

Turn CertWatch's inventory from "what we scanned" into "what exists." Network
scanning only inventories certs on reachable ports. CT monitoring polls a
Certificate Transparency source (crt.sh by default) for the org's registered
domains and surfaces any publicly-issued certificate that CertWatch has **never
observed on its own network** — the shadow-IT, rogue/unsanctioned-CA, and
forgotten-SaaS cases.

## Scope

**In:** poll a configurable CT source per watched domain, diff against the
existing fingerprint-deduped `Certificate` inventory, ingest unknown certs with
a `source=ct` discriminator, raise a `unknown_issuance` Finding for CT-only
certs, clear it automatically once a scan confirms the cert on the network.

**Out (deferred, matches roadmap):** direct RFC 6962 CT log tailing / Merkle
proofs (crt.sh JSON only); environment-inferred finding severity (fixed
configurable severity for now); pluggable multi-provider CT abstraction (one
source, behind a configurable URL).

## Core modeling decision (Approach A)

CT-discovered certs are **full `Certificate` rows** via the existing
`scan_engine._upsert_certificate` dedup-by-fingerprint path, plus one new
`source` column. Because dedup is by SHA-256 fingerprint, a cert already seen on
the network is simply already present — so "unknown issuance" is exactly
"fingerprint not already in the table, discovered via CT." This reuses the
`Certificate` table, the dedup upsert, the `Finding` engine, and the inventory
UI wholesale.

Rejected alternatives: a separate `CtObservation` table (duplicates cert
parsing/fields and its own UI, loses auto-clear-on-scan for free); a
"pending confirmation" cert state (adds a state machine to `Certificate` nothing
else needs).

## Data model

### New table: `WatchedDomain`
Just the poll list — certs and findings are **not** FK'd to it.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `domain` | str(255) | e.g. `example.com`; queried as `%.example.com` |
| `enabled` | bool, default true | |
| `last_checked_at` | datetime, nullable | drives the cadence gate |
| `last_crtsh_id` | int, nullable | high-water mark of the max crt.sh entry `id` processed |
| `created_at` | datetime | |

### `Certificate.source`
- New column `source` str(16), default `network`.
- Values: `network` | `ct`. (Pre-figures the Phase 4 discriminator, which adds
  `keyvault` | `repo`.)
- Migration backfills all existing rows to `network`.
- `source` records **provenance of first discovery** and is not flipped on
  later observation. The finding lifecycle keys off endpoint binding, not
  `source`, so a CT-first cert later found on the network keeps `source=ct` but
  its finding clears (see below).

### New finding rule: `unknown_issuance`
- Added to `findings.py`'s rule set.
- Fires for a `source=ct` certificate that is **not bound to any endpoint**.
  Mechanically this is the cert-only evaluation path: `evaluate_certificate`
  already runs with `endpoint=None` exactly for certs no `Endpoint` references
  (see `findings.evaluate_all`), so the rule condition is simply
  `cert.source == "ct" and endpoint is None`. No new "is it bound?" query.
- Raised **declaratively by the rule engine**, not imperatively at ingest: the
  `ct_check` worker calls `evaluate_certificate(db, cert, endpoint=None)` after
  upserting a CT cert, which upserts the finding. This is what gives clearing
  for free — when a later scan binds the fingerprint to an endpoint, that cert
  is re-evaluated **with** endpoint context (the `endpoint=None` branch no
  longer runs for it), so `unknown_issuance` stops being a candidate and the
  existing active→cleared logic clears it.
- Severity: fixed, from `CERTWATCH_CT_FINDING_SEVERITY` (default `warning`).
- `ponytail:` environment-inferred severity deferred — a CT-only cert has no
  reliable environment mapping (it isn't tied to a Target).

## Fetch + diff flow

New worker kind **`ct_check`**, payload `{"domain_id": <id>}`, dispatched in
`worker.process_one` alongside the existing kinds.

New module `app/ct_source.py` — thin crt.sh client:
1. `GET {base}/?q=%25.{domain}&output=json&exclude=expired`. First sync is
   bounded to **currently-valid certs** (the actionable shadow set); expired
   historical noise is skipped by `exclude=expired`.
2. Process only entries whose crt.sh `id > last_crtsh_id`. Advance
   `last_crtsh_id` to the max id seen this run; set `last_checked_at`.
3. Per new entry: fetch the cert (`{base}/?d={id}`), parse via the existing
   `scanner.parse_certificate` (handle DER or PEM response), compute the
   fingerprint. If the fingerprint is **not** already in `Certificate`,
   `_upsert_certificate` it with `source=ct` and raise the finding. If it is
   already present (network-observed or previously CT-ingested), no finding.
4. Multiple crt.sh entries for one cert (precert + leaf, multiple logs) dedup
   naturally by fingerprint — ingested once; watermark still advances.

**Fail-closed:** any network/parse error `queue.fail`s the item (existing
retry/backoff) and never crashes the worker — same pattern as every other kind.

## Scheduler

New tick `ct_tick`, registered in `start_scheduler` on a
`CERTWATCH_CT_CHECK_FREQUENCY_HOURS` interval (default 24h), mirroring
`renewal_tick`:
- For each enabled `WatchedDomain` past its cadence with **no in-flight
  `ct_check`** queue item for it (same in-flight guard as `report_tick`),
  `queue.enqueue("ct_check", {"domain_id": id})`.
- If `CERTWATCH_CT_SOURCE_URL` is unset/blank, the tick no-ops (feature off).

## API + UI

- `GET/POST /api/watched-domains`, `DELETE /api/watched-domains/{id}` — admin,
  audited like other mutations.
- `POST /api/watched-domains/{id}/check` — enqueue an immediate `ct_check`.
- `?source=` filter added to the existing `GET /api/certificates`.
- Cert list shows a `CT` badge for `source=ct` rows.
- Settings gains a **Watched Domains** section (list / add / remove / check-now).
- Findings page renders `unknown_issuance` with no changes (existing rule
  rendering).
- Dashboard expiry/health tiles count `source=network` certs only, so shadow
  certs don't inflate operational metrics. The shadow signal is the Finding.

## Config

| Env var | Default | Purpose |
|---|---|---|
| `CERTWATCH_CT_SOURCE_URL` | `https://crt.sh` | CT source base URL; blank/unset disables the feature and `ct_tick`. Air-gapped sites point at an internal mirror/proxy. |
| `CERTWATCH_CT_CHECK_FREQUENCY_HOURS` | `24` | Per-domain poll cadence. |
| `CERTWATCH_CT_FINDING_SEVERITY` | `warning` | Severity of `unknown_issuance` findings. |

## Testing

Client tested against a **local fixture server** (the configurable URL makes
this trivial — no real network). Cases:
- Watermark advance: entries at/below `last_crtsh_id` skipped; watermark set to
  max processed.
- Fingerprint dedup: a network-known fingerprint returned by CT → ingested-check
  finds it present → **no finding**.
- Unknown cert: fingerprint absent → ingested `source=ct` + `unknown_issuance`
  finding raised.
- Finding clears: after a scan binds the fingerprint to an endpoint,
  `evaluate_certificate` clears the finding.
- Error handling: CT fetch/parse error → queue item failed, worker survives.
- Disabled: blank `CERTWATCH_CT_SOURCE_URL` → `ct_tick` enqueues nothing.
- Migration: `source` column backfills existing rows to `network`; upgrade from
  a pre-2.5 DB succeeds.

## Deliberate ceilings

- `ponytail:` crt.sh JSON only — no RFC 6962 log tailing/Merkle proofs. Upgrade
  to direct log tailing only if crt.sh rate limits become a real problem.
- `ponytail:` fixed finding severity — no environment inference for CT-only
  certs.
- `ponytail:` `source` is a plain provenance column, not flipped on later
  network observation; the finding lifecycle keys off endpoint binding instead.
