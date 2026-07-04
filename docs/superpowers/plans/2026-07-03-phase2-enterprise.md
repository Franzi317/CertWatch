# Phase 2 — Enterprise Controls Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Every task is TDD: write the failing test, watch it fail, implement, watch it pass, commit. Checkbox (`- [ ]`) syntax tracks steps.

**Goal:** Make CertWatch pass an internal security/ops review — CSV exports, scheduled reports, a crypto-risk `Finding` model with a disposition workflow, and a backup/restore + DR story — all built on the existing scanner/queue/auth infrastructure without new infra.

**Architecture:** Build on Phases 0–1. `Finding` is a new entity evaluated at scan time from data the scanner ALREADY captures on `Certificate`/`Endpoint` (key size, signature algorithm, validity dates, issuer, environment) — no new scanning. Exports are query-param format switches on existing list endpoints. Scheduled reports reuse the Phase-0 `WorkQueue`/worker + the existing SMTP notification-channel machinery. Backup/restore is `pg_dump` + a documented runbook + a restore-verification endpoint. Single-node app (no HA machinery this phase).

**Tech Stack:** Python 3.13, FastAPI, SQLAlchemy 2, Alembic, PostgreSQL/SQLite, `cryptography` (already used, for reading cert fields), stdlib `csv`. React frontend. No new dependencies.

## Global Constraints

- **No multi-tenancy.** No tenant scoping.
- **Webhook event stream is OUT of scope** (deferred per decision) — do NOT add an Event table, outbound signed events, or `/api/events`. The existing notification channels remain the only outbound path.
- **HA is backup/restore + DR drill only** (per decision) — NO advisory-lock scheduler guard, NO multi-replica machinery. The app remains single-node; document that running one API instance is required (the Phase-0 scheduler note already says this).
- **Findings rule families (ALL enabled per decision):** (1) weak keys & deprecated signatures, (2) over-long certificate lifetime, (3) self-signed / untrusted-issuer in production, (4) near/at expiry as findings. Thresholds are configurable via `SystemSetting`/env with industry-standard defaults: `min_rsa_bits=2048`, `min_ec_bits=256`, `max_lifetime_days=398`, deprecated signature substrings `{sha1, md5}`. "Production" = endpoint whose target `environment == "prod"`. "Untrusted issuer" reuses the existing `internal_ca_pattern_list` (a self-signed or non-internal issuer in prod is flagged).
- Findings are evaluated from ALREADY-CAPTURED fields — do NOT add new network scanning or handshake/cipher enumeration (that's Phase 4).
- All new mutation endpoints are `require_role`-guarded (findings disposition = operator; report schedules = operator; admin restore-check = admin) and write an actor-attributed `AuditLog` row. All new read endpoints = viewer.
- Secrets never returned cleartext (report-schedule recipients are not secret; no new secrets expected — if any, use `app.secrets`).
- Migrations continue the linear Alembic chain: next revision is `0013`, then `0014`, ... each `down_revision` at the prior. **The model must match the migration** (Phase-1 final review caught a drift — declare all indexes in `__table_args__`).
- Backend venv python: `backend/.venv/Scripts/python.exe`; tests from `backend/` with `python -m pytest -q`. Do not regress the 211 existing tests. `npm run build` must stay clean.
- Reuse existing infrastructure (`scan_engine`, `queue`, `worker`, `scheduler`, `auth.require_role`, `audit`, `notify.send_email`, `alerts`) — do not reinvent it.

## File Structure

- `backend/app/exports.py` — CSV serialization helpers (Task 1).
- `backend/app/findings.py` — findings rules engine + evaluation (Task 2).
- `backend/app/reports.py` — report rendering + scheduling helpers (Task 5).
- `backend/app/models.py` — add `Finding`, `ReportSchedule`.
- `backend/app/main.py` — export format params, findings routes, report-schedule routes, admin restore-check.
- `backend/app/scan_engine.py` — call findings evaluation after a scan (Task 2).
- `backend/app/scheduler.py` — report tick (Task 5).
- `backend/app/worker.py` — `report` kind handler (Task 5).
- `scripts/backup.sh`, `docs/operations/backup-restore.md` (Task 6).
- `frontend/src/pages/Findings.tsx`, `Reports.tsx` + api/nav wiring (Tasks 4, 5).
- Tests under `backend/tests/test_*.py` per task.

---

## Task 1: CSV export on list endpoints

**Files:**
- Create: `backend/app/exports.py`, `backend/tests/test_exports.py`
- Modify: `backend/app/main.py` (add `format` param to certificates/endpoints/lifecycle-orders/audit list routes)

**Interfaces:**
- Produces: `exports.rows_to_csv(fieldnames: list[str], rows: list[dict]) -> str` (stdlib `csv.DictWriter` into a `StringIO`, CRLF-safe, quoting minimal). Each affected list endpoint accepts `?format=csv` and returns a `Response(content=csv, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=..."})` with the SAME filter params as the JSON path; default (`format=json` or unset) returns the existing JSON unchanged.

**Details:**
- Add `format: str = "json"` to `list_certificates`, `list_endpoints`, `list_lifecycle_orders`, and `GET /api/audit`. When `format == "csv"`, project each item dict to a flat set of columns (choose sensible columns per entity; for certificates: id, common_name, issuer_cn, not_before, not_after, public_key_algorithm, public_key_size, signature_algorithm, self_signed, fingerprint_sha256; document the column set). Reuse the existing query/filter logic — only the serialization branches.
- CSV export must respect the same role guard (viewer) as the JSON endpoint.

- [ ] **Step 1: Failing test** — `test_exports.py`: `rows_to_csv(["a","b"], [{"a":1,"b":"x"}])` returns a header line `a,b` and a row `1,x`. API: seed a certificate, `GET /api/certificates?format=csv` (authenticated viewer) → 200, `text/csv`, body contains the header and the cert's common_name; `?format=json` (or unset) still returns the JSON `{total, items}` shape.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement `exports.py` + wire the four endpoints.**
- [ ] **Step 4: Run test + full suite (211 + new).**
- [ ] **Step 5: Commit** — `feat: CSV export on certificate/endpoint/order/audit lists`

---

## Task 2: Finding model + rules engine

**Files:**
- Create: `backend/app/findings.py`, `backend/tests/test_findings.py`, `backend/alembic/versions/0013_findings.py`
- Modify: `backend/app/models.py`, `backend/app/config.py`, `backend/app/scan_engine.py`

**Interfaces:**
- Produces:
  - `models.Finding`: `id`, `rule_id` (String(48): `weak_key|deprecated_signature|long_lifetime|self_signed_prod|untrusted_issuer_prod|expiring|expired`), `severity` (String(16): info|warning|critical), `certificate_id` (FK certificates, nullable), `endpoint_id` (FK endpoints, nullable), `title` (String(255)), `detail` (Text default ""), `dedupe_key` (String(255), index), `disposition` (String(16): `open|accepted|resolved`, default "open"), `status` (String(16): `active|cleared`, default "active" — `active` = condition still present, `cleared` = no longer detected), `first_seen`, `last_seen`, `created_at`, `updated_at`. Declare an `Index` on `dedupe_key` in `__table_args__`.
  - `config` additions: `finding_min_rsa_bits: int = 2048`, `finding_min_ec_bits: int = 256`, `finding_max_lifetime_days: int = 398`, `finding_deprecated_sig_substrings: str = "sha1,md5"` (env `CERTWATCH_FINDING_*`). These may be overridden by `SystemSetting` rows of the same key if present (read-through, like other settings).
  - `findings.evaluate_certificate(db, cert, endpoint=None) -> list[Finding]` — runs all rule families against the cert (and, for prod-context rules, the endpoint's target environment); upserts `Finding` rows by `dedupe_key = f"{rule_id}:{cert_id}[:endpoint_id]"`. A recurring condition updates `last_seen` + reactivates (`status="active"`); a condition no longer present marks the matching active finding `status="cleared"` (do NOT delete — history). Disposition is preserved across re-evaluation (accepted findings stay accepted).
  - `findings.evaluate_all(db) -> int` — re-evaluate every current cert/endpoint (used on-demand / when thresholds change); returns count of active findings.
- Consumes: `Certificate` fields (public_key_algorithm, public_key_size, signature_algorithm, not_before, not_after, self_signed, issuer), `Endpoint`→`Target.environment`, `settings.internal_ca_pattern_list`.

**Rule definitions (evaluate from captured fields only):**
- `weak_key` (warning): RSA `public_key_size < min_rsa_bits`, or EC key size `< min_ec_bits`. (Determine RSA vs EC from `public_key_algorithm`.)
- `deprecated_signature` (warning): `signature_algorithm` lower-cased contains any of the deprecated substrings.
- `long_lifetime` (info): `(not_after - not_before).days > max_lifetime_days`.
- `self_signed_prod` (critical): `self_signed is True` AND the endpoint's target `environment == "prod"`. (endpoint-context rule.)
- `untrusted_issuer_prod` (warning): NOT self-signed, issuer does not match any `internal_ca_pattern` AND is not a known public CA — simplify: flag when `environment == "prod"` AND the issuer matches none of `internal_ca_pattern_list` AND `self_signed is False`. Document this heuristic + `ponytail:` note that a real trust-store check is deferred.
- `expiring` (warning): `not_after` within a threshold (reuse a sensible default, e.g. 30 days) and not yet expired.
- `expired` (critical): `not_after < now`.

**Scan integration:** in `scan_engine`, after an endpoint's cert is upserted/observed (where `evaluate_alerts` is already called or nearby), call `findings.evaluate_certificate(db, cert, endpoint)`. Keep it cheap and non-fatal (wrap so a findings error never fails the scan).

- [ ] **Step 1: Failing tests** — `test_findings.py`: construct a `Certificate` with a 1024-bit RSA key + SHA-1 signature + 800-day lifetime; `evaluate_certificate` yields `weak_key`, `deprecated_signature`, `long_lifetime` findings with the right severities and dedupe_keys. A self-signed cert on a `prod` endpoint yields `self_signed_prod` (critical); on a `dev` endpoint it does NOT. Re-evaluating an unchanged cert does not duplicate rows (same dedupe_key, updated last_seen). A cert that once had a weak key but now has a strong one → the old `weak_key` finding is `status="cleared"`, and an `accepted` disposition is preserved across re-evaluation.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement model + migration 0013 + config + `findings.py` + scan_engine hook.**
- [ ] **Step 4: Run test + full suite; alembic upgrade smoke (creates `findings`); confirm model index matches migration (`alembic check` clean).**
- [ ] **Step 5: Commit** — `feat: crypto-risk Finding model and scan-time rules engine`

---

## Task 3: Findings API + disposition + dashboard

**Files:**
- Modify: `backend/app/main.py`, `backend/app/schemas.py`
- Test: `backend/tests/test_findings_api.py`

**Interfaces:**
- Produces:
  - `GET /api/findings` (viewer) — paginated `{total, items}`, filters: `rule_id`, `severity`, `disposition`, `status` (default `status=active`), `q`. Also `?format=csv`.
  - `GET /api/findings/{id}` (viewer).
  - `POST /api/findings/{id}/disposition` (operator) — body `{disposition: "open"|"accepted"|"resolved", note?: str}`; sets disposition, audited (`finding.disposition`).
  - `POST /api/findings/evaluate` (operator) — calls `findings.evaluate_all`; returns `{active}`. Audited.
  - Dashboard additions in `GET /api/dashboard`: `open_findings` (count of `status=active AND disposition=open`), `findings_by_severity` (dict severity→count for active+open).
- Consumes: Task 2.

- [ ] **Step 1: Failing test** — seed findings via `evaluate_certificate`; viewer `GET /api/findings?severity=critical` returns only criticals; operator `POST /api/findings/{id}/disposition {accepted}` sets it (and a viewer gets 403); dashboard returns `open_findings` and `findings_by_severity`.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement routes + schemas + dashboard fields.**
- [ ] **Step 4: Run test + full suite.**
- [ ] **Step 5: Commit** — `feat: findings API, disposition workflow, and dashboard risk metrics`

---

## Task 4: Findings frontend page

**Files:**
- Create: `frontend/src/pages/Findings.tsx`
- Modify: `frontend/src/App.tsx`, `frontend/src/api.ts`, `frontend/src/pages/Dashboard.tsx`

**Interfaces:**
- Produces: a Findings page (list with severity badges, rule, affected cert/endpoint, disposition control [open/accept/resolve], filter by severity/rule/disposition/status, CSV export link), a nav entry + route, `api.ts` types+methods, and dashboard cards for `open_findings` / `findings_by_severity`. Match existing style, no new UI dep.

- [ ] **Step 1:** Add findings types+methods to `api.ts`.
- [ ] **Step 2:** Build `Findings.tsx` + nav/route + dashboard cards.
- [ ] **Step 3: Build check** — `npm run build` clean.
- [ ] **Step 4: Commit** — `feat: findings frontend page and risk dashboard cards`

(No frontend test framework — build is the gate, per repo convention. Do not add one.)

---

## Task 5: Scheduled reports

**Files:**
- Create: `backend/app/reports.py`, `backend/tests/test_reports.py`, `backend/alembic/versions/0014_report_schedules.py`, `frontend/src/pages/Reports.tsx`
- Modify: `backend/app/models.py`, `backend/app/main.py`, `backend/app/schemas.py`, `backend/app/scheduler.py`, `backend/app/worker.py`, `frontend/src/App.tsx`, `frontend/src/api.ts`

**Interfaces:**
- Produces:
  - `models.ReportSchedule`: `id`, `name`, `report_type` (String(32): `certificates|expiring|findings|endpoints`), `filter_params` (JSON default dict — e.g. `{expiring_within: 30}`/`{severity:"critical"}`), `format` (String(8), default "csv"), `recipients` (JSON list of emails), `channel_id` (FK notification_channels.id — the SMTP channel to send through), `cadence` (String(16): `daily|weekly|monthly`), `schedule_time` (String(5), default "08:00"), `schedule_day` (Integer default 0), `enabled` (Boolean default True), `last_run_at` (DateTime(tz) nullable), `created_at`. Declare any index in `__table_args__`.
  - `reports.render(db, report_type, filter_params) -> tuple[str, str]` — returns `(filename, csv_text)` by running the same query logic the corresponding list endpoint uses (reuse the query helpers / `exports.rows_to_csv`).
  - `reports.run_schedule(db, schedule) -> None` — render + send via `notify.send_email` using the referenced SMTP channel's config (attach or inline the CSV), set `last_run_at`. Executed by the worker.
  - `scheduler` report tick (reuse the calendar-schedule logic already in `scheduler.py` for targets — `schedule_due`-style): find due `ReportSchedule`s and `queue.enqueue(db, "report", {"schedule_id": id})`.
  - `worker.process_one` handles kind `"report"` → `reports.run_schedule`.
  - Routes: `GET/POST /api/reports` (list viewer / create operator), `PUT/DELETE /api/reports/{id}` (operator), `POST /api/reports/{id}/run` (operator — enqueue an immediate run). Audited.
  - Frontend `Reports.tsx`: list + create/edit form (type, filters, recipients, channel, cadence) + "Run now". Nav + route.
- Consumes: Task 1 (`exports.rows_to_csv`), `notify.send_email`, Phase-0 `queue`/`worker`/`scheduler`, notification channels.

- [ ] **Step 1: Failing test** — `test_reports.py`: `reports.render(db, "certificates", {})` returns a CSV with the cert columns; create a `ReportSchedule` via API (operator; viewer 403); enqueue a run via `/api/reports/{id}/run` and process it with `worker.process_one` (monkeypatch `notify.send_email` to capture) → email sent with the CSV body/attachment and `last_run_at` set. Report tick: a due schedule enqueues a `report` item; a not-due one does not.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement model + migration 0014 + `reports.py` + routes + scheduler tick + worker handler + frontend.**
- [ ] **Step 4: Run test + full suite; alembic smoke; `alembic check` clean; `npm run build` clean.**
- [ ] **Step 5: Commit** — `feat: scheduled CSV reports delivered by email`

---

## Task 6: Backup / restore / DR

**Files:**
- Create: `scripts/backup.sh`, `scripts/restore.sh`, `docs/operations/backup-restore.md`, `backend/tests/test_restore_check.py`
- Modify: `backend/app/main.py` (restore-check endpoint)

**Interfaces:**
- Produces:
  - `scripts/backup.sh` — `pg_dump` of the CertWatch database to a timestamped file (reads `CERTWATCH_DATABASE_URL` / standard PG env), with a clear echoed reminder that `CERTWATCH_MASTER_KEY` must be backed up SEPARATELY and securely (without it, encrypted secrets are unrecoverable). `scripts/restore.sh` — documented `psql`/`pg_restore` counterpart.
  - `docs/operations/backup-restore.md` — the runbook: what to back up (DB dump + master key + session/api secrets), how to restore, how to verify, RPO/RTO notes, and the single-node HA note.
  - `POST /api/admin/restore-check` (admin) — verifies the running instance against expectations after a restore: current Alembic revision == head (schema up to date), row counts for key tables (certificates, endpoints, managed_certificates, findings), and a decrypt-ability probe (encrypt-then-decrypt a test value with the current master key to prove the key matches the data — if any encrypted `NotificationChannel`/`Issuer` secret exists, attempt to decrypt one and report ok/fail WITHOUT returning the plaintext). Returns `{schema_ok, revision, counts, secret_decrypt_ok}`. Audited.
- Consumes: `app.secrets`, Alembic, models.

**Details:**
- `restore-check` must NOT return any secret value — only booleans/counts. The decrypt probe proves the master key matches without exposing plaintext.

- [ ] **Step 1: Failing test** — `test_restore_check.py`: as admin, `POST /api/admin/restore-check` returns `schema_ok: true`, a `revision` string, a `counts` dict with the key tables, and `secret_decrypt_ok: true` (seed a channel with an encrypted secret first). A viewer → 403. No plaintext secret appears anywhere in the response.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement the endpoint + write `backup.sh`/`restore.sh`/runbook.**
- [ ] **Step 4: Run test + full suite.**
- [ ] **Step 5: Commit** — `feat: restore-check endpoint and backup/restore runbook`

---

## Self-Review Notes

- **Spec coverage vs roadmap Phase 2 (as scoped):** 2.1 reporting/exports → Tasks 1 (CSV) + 5 (scheduled reports); 2.3 backup/restore/DR → Task 6; 2.4 findings → Tasks 2 (engine) + 3 (API/dashboard) + 4 (UI). **2.2 webhook events = DROPPED per decision.** **HA active-passive = DROPPED per decision** (backup/restore only in Task 6).
- **Decisions applied:** all four findings rule families implemented (Task 2). No Event table / signed webhooks. No advisory-lock/multi-replica code. Backup/restore + restore-check + runbook only.
- **Type consistency:** `exports.rows_to_csv` (Task 1) reused by findings CSV (Task 3) and `reports.render` (Task 5). `findings.evaluate_certificate`/`evaluate_all` (Task 2) consumed by Task 3 routes and the scan_engine hook. `Finding` fields (Task 2) drive Task 3/4. `ReportSchedule` (Task 5) drives the worker `report` handler + scheduler tick.
- **Migration chain:** 0013 findings, 0014 report_schedules — linear, each down_revision at prior; both declare their indexes in the model `__table_args__` so `create_all == migration` (`alembic check` clean).
- **Reuse:** scan_engine, queue, worker, scheduler calendar logic, notify.send_email, notification channels, auth, audit — all reused, not reinvented.
