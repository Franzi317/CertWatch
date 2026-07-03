# Phase 1 — Lifecycle MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Every task is TDD: write the failing test, watch it fail, implement, watch it pass, commit. Checkbox (`- [ ]`) syntax tracks steps.

**Goal:** Turn CertWatch from "visibility + alerting" into "visibility + renewal + deployment" — issue certificates from an internal CA, renew them on an approval-gated schedule, deploy the result to real stores, and verify the deployment live with the existing scanner.

**Architecture:** Build on Phase 0. An `Issuer` abstraction with two adapters (**AD CS first**, ACME/HTTP-01 second). A `ManagedCertificate` is the logical cert CertWatch owns the lifecycle for — distinct from the existing observed-artifact `Certificate` table. A `LifecycleOrder` state machine runs on the Phase-0 `WorkQueue`/worker, **gated on operator approval** for every renewal. Deployment connectors (IIS/PFX, PEM+reload, JKS/PKCS12) write the renewed cert to stores; a post-deploy scan of the affected endpoints must observe the new fingerprint before an order reaches `complete`.

**Tech Stack:** Python 3.13, FastAPI, SQLAlchemy 2, Alembic, PostgreSQL/SQLite, `cryptography` (key + CSR generation, PKCS12), `acme` (certbot's ACME library), `httpx`/`requests-ntlm`-style seam for AD CS certsrv, PowerShell subprocess seam for IIS. React frontend.

## Global Constraints

- **No multi-tenancy.** No tenant/org scoping anywhere.
- **Primary CA is AD CS** (Windows certsrv web enrollment via a service account). Build and test the AD CS adapter FIRST; ACME (HTTP-01) second. Both implement one `IssuerAdapter` protocol — no third adapter, no plugin registry (YAGNI until a third issuer type exists).
- **ACME challenge = HTTP-01 only** in Phase 1 (built-in responder at `/.well-known/acme-challenge/{token}`). No DNS-01 this phase.
- **Renewals are approval-gated.** Every `renew` (and `issue`, `revoke`) `LifecycleOrder` starts in `pending_approval` and requires an operator (or admin) approval before it is queued for execution. Revoke additionally requires **admin** approval (two-person rule: operator creates, admin approves).
- **Deployment connector priority order:** (1) IIS/PFX, (2) PEM+reload, (3) JKS/PKCS12. No Kubernetes connector this phase.
- **Do not merge the two certificate tables.** The existing `Certificate` (deduped observed artifact) stays as-is; `ManagedCertificate` is a new logical/lifecycle entity that *references* the current `Certificate` row via `current_certificate_id`.
- All external/network operations (AD CS certsrv POST, ACME client calls, IIS PowerShell, file writes to remote paths) go through a single mockable seam per adapter so tests never touch the network or a real CA. Real-CA validation is a documented manual pass.
- All secrets (issuer service-account creds, ACME account key, connector credentials, generated private keys at rest) are Fernet-encrypted via the Phase-0 `app.secrets` helper and never returned in cleartext.
- Every new mutation endpoint is `require_role`-guarded (issue/renew/deploy config = operator; issuer create/edit + revoke approval = admin) and writes an actor-attributed `AuditLog` row.
- Migrations continue the linear Alembic chain: next revision is `0006`, then `0007`, ... each `down_revision` points at the prior. Migration schema must match the models (verified in Phase 0 — keep it so).
- Backend venv python: `backend/.venv/Scripts/python.exe`; run tests from `backend/` with `python -m pytest -q`. Do not regress the 80 existing tests.
- Follow existing code style/patterns. Reuse Phase-0 infrastructure (`queue`, `worker`, `auth.require_role`, `audit`, `secrets`, `metrics`) — do not reinvent it.

## File Structure

- `backend/app/issuers/__init__.py`, `base.py` (protocol), `adcs.py`, `acme_http01.py` — issuer adapters.
- `backend/app/crypto_keys.py` — key + CSR generation, PKCS12 packaging (pure `cryptography`).
- `backend/app/lifecycle.py` — `LifecycleOrder` state machine + transition helpers.
- `backend/app/deploy/__init__.py`, `base.py`, `pem.py`, `pfx.py`, `jks.py`, `iis.py` — deployment connectors.
- `backend/app/models.py` — add `Issuer`, `ManagedCertificate`, `RenewalPolicy`, `LifecycleOrder`, `DeploymentTarget`.
- `backend/app/main.py` — issuer/managed-cert/order/deployment routes + ACME challenge route.
- `backend/app/worker.py` — extend to process `issue|renew|revoke|deploy` queue kinds.
- `backend/app/scheduler.py` — renewal tick.
- `frontend/src/pages/Issuers.tsx`, `ManagedCerts.tsx`, `Orders.tsx` + api/nav wiring.
- Tests under `backend/tests/test_*.py` per task.

---

## Task 1: Security hardening (SEC-1 CIDR DoS, SEC-2 path traversal)

Clears the two pre-existing security findings surfaced during Phase 0 review before building on top.

**Files:**
- Modify: `backend/app/targets.py` (guard before materializing), `backend/app/main.py` (SPA path sanitization)
- Test: `backend/tests/test_security_hardening.py`

**Interfaces:**
- Produces: `targets.expand()` and `targets.validate()` reject a target whose host count exceeds `max_cidr_hosts` WITHOUT first materializing the host list. The SPA catch-all rejects/normalizes `..` path traversal, still serving `index.html` for real SPA routes.

**Details:**
- In `targets.py`, compute the count first: for CIDR use `ipaddress.ip_network(value, strict=False).num_addresses` (minus network/broadcast as the existing logic does); for range use `int(end) - int(start) + 1`. If it exceeds `max_cidr_hosts`, raise `TargetError` BEFORE calling `list(net.hosts())` / building the range list. Keep existing behavior for valid sizes identical.
- In `main.py` SPA handler, before `os.path.join(static_dir, full_path)`, reject traversal: resolve the candidate with `os.path.realpath` and confirm it is within `os.path.realpath(static_dir)`; if not (or if the joined path escapes), serve `index.html` instead of the file. Never serve a file outside `static_dir`.

- [ ] **Step 1: Failing tests** — `test_security_hardening.py`:
  - `validate("cidr", "0.0.0.0/0", max_cidr_hosts=4096)` raises `TargetError` quickly (no MemoryError / no multi-second hang) — assert it raises `targets.TargetError`.
  - a huge range `"10.0.0.0-10.255.255.255"` raises `TargetError`.
  - a normal `/29` still validates and expands to the correct host count (regression guard).
  - SPA traversal: with a temp `static_dir` containing `index.html` and a secret file outside it, a request like `GET /....%2f....` or `GET /../config` does NOT return the outside file (returns index.html or 404), while `GET /assets/app.js` (a real file) is served. (Use the `client` fixture; you may need to set `settings.static_dir` — read how Phase-0 tests handle it, or test the path-sanitization helper directly as a unit if wiring static_dir in tests is awkward. Prefer a direct unit test of a `_safe_static_path(static_dir, full_path) -> str|None` helper you extract.)
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement the count-before-materialize guard and the `_safe_static_path` helper + wire it.**
- [ ] **Step 4: Run new tests + full suite (80 + new).**
- [ ] **Step 5: Commit** — `fix: guard CIDR expansion before materializing and sanitize SPA path traversal`

---

## Task 2: Key/CSR generation + Issuer model & adapter protocol

**Files:**
- Create: `backend/app/crypto_keys.py`, `backend/app/issuers/__init__.py`, `backend/app/issuers/base.py`, `backend/tests/test_crypto_keys.py`, `backend/alembic/versions/0006_issuers.py`
- Modify: `backend/app/models.py`

**Interfaces:**
- Produces:
  - `crypto_keys.generate_private_key(algorithm: str = "rsa", size: int = 2048) -> PrivateKeyResult` where `PrivateKeyResult` has `.key_pem: str` and the key object; `algorithm ∈ {"rsa","ecdsa"}`, rsa size ∈ {2048,3072,4096}, ecdsa curve via size 256/384.
  - `crypto_keys.build_csr(key_pem: str, common_name: str, sans: list[str]) -> str` — returns CSR PEM with CN subject + SubjectAlternativeName (DNS entries); signs with the key.
  - `models.Issuer`: `id`, `name` (String(255) unique), `issuer_type` (String(16): "adcs"|"acme"), `config` (JSON — non-secret fields; secret fields stored under keys the adapter encrypts via `app.secrets`), `enabled` (bool default True), `last_test_at` (datetime|None), `last_test_ok` (bool default False), `created_at`.
  - `issuers/base.py`:
    ```python
    @dataclass
    class IssuedCert:
        certificate_pem: str
        chain_pem: str        # issuer/intermediate chain, may be ""
        serial: str
    class IssuerError(Exception): ...
    class IssuerAdapter(Protocol):
        def test_connection(self) -> None: ...          # raise IssuerError on failure
        def issue(self, csr_pem: str, profile: dict) -> IssuedCert: ...
        def revoke(self, serial: str, reason: str) -> None: ...
    def get_adapter(issuer: "Issuer") -> IssuerAdapter: ...  # dispatch on issuer_type
    ```
- Consumes: Phase-0 `app.secrets`, `models.Base`.

- [ ] **Step 1: Failing tests** — `test_crypto_keys.py`: generated RSA key PEM parses via `cryptography` and has the requested size; `build_csr` produces a CSR whose parsed subject CN and SAN DNS names match the inputs and whose signature verifies. Plus a model test: an `Issuer` row persists with defaults.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement `crypto_keys.py`, `issuers/base.py` (protocol + `get_adapter` stub raising for unknown types), `Issuer` model, migration `0006`.**
- [ ] **Step 4: Run tests + full suite; verify `alembic upgrade head` on fresh SQLite creates `issuers`.**
- [ ] **Step 5: Commit** — `feat: key/CSR generation, Issuer model and adapter protocol`

---

## Task 3: AD CS issuer adapter (primary CA)

**Files:**
- Create: `backend/app/issuers/adcs.py`, `backend/tests/test_adcs.py`
- Modify: `backend/app/issuers/base.py` (`get_adapter` dispatches "adcs")

**Interfaces:**
- Produces: `adcs.ADCSAdapter(issuer)` implementing `IssuerAdapter`. Config fields: `server_url` (e.g. `https://ca.corp.local`), `ca_config` (the `CAName\hostname` string certsrv needs), `template` (cert template name), and encrypted `username`/`password` (service account). The network seam is one method `_submit(csr_pem: str, template: str) -> str` (returns issued cert PEM) and `_retrieve(request_id)` if needed — tests monkeypatch `_submit`/`_post` to return canned certsrv responses.
- Consumes: Task 2 (`IssuerAdapter`, `IssuedCert`, `IssuerError`), `app.secrets`.

**Details:**
- certsrv flow: POST the CSR to `<server_url>/certsrv/certfnsh.asp` with NTLM/basic auth, parse the returned `ReqID`, then GET `<server_url>/certsrv/certnew.cer?ReqID=<id>&Enc=b64` for the issued cert. Implement this in `_submit`/helpers but keep the actual HTTP call isolated in a `_http_post`/`_http_get` seam that tests replace. `test_connection` does a cheap authenticated GET of the certsrv root and raises `IssuerError` on non-200/auth failure. `issue(csr_pem, profile)` returns `IssuedCert(certificate_pem=..., chain_pem=..., serial=...)` (parse serial from the issued cert via `cryptography`). `revoke` raises `IssuerError("AD CS revoke not supported via certsrv")` unless a supported path exists — document this ceiling with a `ponytail:` comment (revocation for AD CS is typically done at the CA, not via certsrv web enrollment).

- [ ] **Step 1: Failing tests** — `test_adcs.py`: monkeypatch the HTTP seam so `_http_post` returns a certsrv HTML body containing a known `ReqID`, and `_http_get` returns a fixed issued-cert PEM (use a self-signed test cert PEM as the stand-in). Assert `issue()` returns an `IssuedCert` with `certificate_pem` == that PEM and `serial` == the parsed serial. Assert `test_connection()` raises `IssuerError` when the seam returns a 401.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement `adcs.py`, wire `get_adapter`.**
- [ ] **Step 4: Run tests + full suite.**
- [ ] **Step 5: Commit** — `feat: AD CS issuer adapter (certsrv web enrollment)`

---

## Task 4: ACME (HTTP-01) issuer adapter

**Files:**
- Create: `backend/app/issuers/acme_http01.py`, `backend/tests/test_acme.py`
- Modify: `backend/app/issuers/base.py` (`get_adapter` dispatches "acme"), `backend/app/main.py` (challenge route), `backend/requirements.txt` (`acme`), `backend/app/models.py` (a small `AcmeChallenge` store) + migration `0007_acme_challenges.py`

**Interfaces:**
- Produces:
  - `acme_http01.AcmeAdapter(issuer)` implementing `IssuerAdapter`. Config: `directory_url` (e.g. Let's Encrypt staging or internal ACME), encrypted `account_key_pem` (generated + stored on first use), `contact_email`. The ACME protocol interaction is isolated behind a seam (`_new_order`, `_answer_challenge`, `_finalize`) so tests monkeypatch it; do NOT hit the network in tests.
  - HTTP-01 responder: `GET /.well-known/acme-challenge/{token}` (unauthenticated) returns the stored key authorization for that token. Tokens+authorizations stored in a small `AcmeChallenge` table (token PK, key_authorization, created_at) — cleaned up after validation.
- Consumes: Task 2, `app.secrets`, Phase-0 queue (issuance runs in worker later).

**Details:**
- `issue(csr_pem, profile)`: create order for the CSR's SANs, for each HTTP-01 challenge store `(token, key_authorization)` in `AcmeChallenge`, answer challenges, poll, finalize, download cert → `IssuedCert`. Keep every network step behind the seam. `revoke` uses the ACME revoke endpoint (also behind the seam). `test_connection` fetches the directory URL (seam) and raises `IssuerError` on failure.
- The `/.well-known/acme-challenge/{token}` route MUST be public and mounted BEFORE the SPA catch-all so it isn't swallowed.

- [ ] **Step 1: Failing tests** — `test_acme.py`: monkeypatch the seam to simulate a full order→finalize returning a canned cert PEM; assert `issue()` returns the `IssuedCert`. Assert the challenge route returns the stored key authorization for a token present in `AcmeChallenge` and 404 for an unknown token.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement adapter + challenge route + `AcmeChallenge` model + migration `0007` + dep.**
- [ ] **Step 4: Run tests + full suite; confirm challenge route precedes SPA catch-all.**
- [ ] **Step 5: Commit** — `feat: ACME HTTP-01 issuer adapter with challenge responder`

---

## Task 5: Issuer API + frontend page

**Files:**
- Modify: `backend/app/main.py` (routes), `frontend/src/pages/Issuers.tsx` (new), `frontend/src/App.tsx`, `frontend/src/api.ts`
- Test: `backend/tests/test_issuers_api.py`

**Interfaces:**
- Produces:
  - `GET /api/issuers` (viewer), `POST /api/issuers` (admin), `PUT /api/issuers/{id}` (admin), `DELETE /api/issuers/{id}` (admin), `POST /api/issuers/{id}/test` (operator) — the last calls `get_adapter(issuer).test_connection()` and updates `last_test_at/last_test_ok`, returning `{ok, detail}`. Secret config fields are encrypted on write (via `app.secrets`) and scrubbed on read (same pattern as notification channels). Every mutation audited.
  - Frontend Issuers page: list, create/edit form (type selector → AD CS fields or ACME fields), "Test" button. Match existing UI style.
- Consumes: Tasks 2–4.

- [ ] **Step 1: Failing test** — `test_issuers_api.py`: admin creates an AD CS issuer (secrets not echoed in response), viewer can list but not create (403), `POST /{id}/test` with a monkeypatched adapter returns `{ok: true}` and sets `last_test_ok`. Non-admin create → 403.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement routes + frontend page/nav.**
- [ ] **Step 4: Run tests + full suite; `npm run build` clean.**
- [ ] **Step 5: Commit** — `feat: issuer management API and UI`

---

## Task 6: ManagedCertificate + RenewalPolicy + promotion

**Files:**
- Modify: `backend/app/models.py`, `backend/app/main.py`, add migration `0008_managed_certs.py`
- Test: `backend/tests/test_managed_certs.py`

**Interfaces:**
- Produces:
  - `models.RenewalPolicy`: `id`, `name`, `renew_before_days` (int default 30), `key_algorithm` (String default "rsa"), `key_size` (int default 2048), `require_approval` (bool default **True**), `verify_after_deploy` (bool default True), `max_retries` (int default 3), `created_at`.
  - `models.ManagedCertificate`: `id`, `common_name` (String(255)), `sans` (JSON list), `issuer_id` (FK issuers), `renewal_policy_id` (FK renewal_policies), `current_certificate_id` (FK certificates, nullable), `state` (String(16): "active"|"renewing"|"error"|"retired", default "active"), `owner` (String(255) default ""), `environment` (String(64) default "prod"), `created_at`, `updated_at`.
  - `POST /api/managed-certificates` (operator) — create directly, or `POST /api/certificates/{id}/manage` to promote an observed `Certificate` (prefill CN/SANs from it, require issuer_id + renewal_policy_id). `GET /api/managed-certificates`, `GET /{id}`. `POST/GET /api/renewal-policies`.
  - Frontend: a "Manage this certificate" action on the certificate detail page (wired in a later UI pass or here if quick).
- Consumes: Tasks 2–5.

- [ ] **Step 1: Failing test** — `test_managed_certs.py`: create a RenewalPolicy; promote an existing observed Certificate via `/api/certificates/{id}/manage` (with issuer+policy) → a ManagedCertificate exists with CN/SANs copied and `state=="active"`; listing returns it. Operator required (viewer 403).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement models, migration `0008`, routes.**
- [ ] **Step 4: Run tests + full suite; alembic upgrade smoke.**
- [ ] **Step 5: Commit** — `feat: ManagedCertificate, RenewalPolicy, and promotion from inventory`

---

## Task 7: LifecycleOrder state machine + approval API

**Files:**
- Create: `backend/app/lifecycle.py`, `backend/tests/test_lifecycle.py`
- Modify: `backend/app/models.py`, `backend/app/main.py`, add migration `0009_lifecycle_orders.py`

**Interfaces:**
- Produces:
  - `models.LifecycleOrder`: `id`, `managed_certificate_id` (FK), `action` (String(8): "issue"|"renew"|"revoke"), `status` (String(20): "pending_approval"|"approved"|"queued"|"issuing"|"deploying"|"verifying"|"complete"|"failed"|"rolled_back"), `attempts` (int default 0), `approved_by` (String(255) default ""), `approved_at` (datetime|None), `error` (Text default ""), `correlation_id` (String(36)), `transitions` (JSON list of `{from,to,at,detail}`), `created_at`, `updated_at`.
  - `lifecycle.create_order(db, managed_cert, action, actor) -> LifecycleOrder` — idempotent per (managed_cert, action) while an open order exists (returns the existing one). Starts in `pending_approval`. Records a transition.
  - `lifecycle.transition(db, order, to_status, detail="")` — appends to `transitions`, sets status, commits. Rejects illegal transitions (define an allowed-map; e.g. can't go `complete`→`issuing`).
  - `lifecycle.approve(db, order, actor, is_admin) -> None` — only from `pending_approval`; for `revoke` require `is_admin` True else raise; sets `approved_by/at`, transitions to `approved`, then enqueues the work item (`queue.enqueue(db, order.action, {"order_id": order.id})`) and transitions to `queued`. `lifecycle.reject(db, order, actor)` → `failed`.
  - Routes: `POST /api/lifecycle/orders` (operator — create issue/renew; revoke also operator-created), `GET /api/lifecycle/orders`, `GET /{id}`, `POST /{id}/approve` (operator; but revoke approval requires admin — enforce inside), `POST /{id}/reject` (operator). All audited.
- Consumes: Task 6, Phase-0 `queue`, `auth`.

- [ ] **Step 1: Failing tests** — `test_lifecycle.py`: `create_order(renew)` starts `pending_approval` and is idempotent (second call returns same order); `approve` by operator on a renew → status `queued` and a WorkQueue row exists with `{"order_id": id}`; `approve` on a `revoke` order by a non-admin raises/refuses; illegal `transition(complete→issuing)` raises.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement `lifecycle.py`, model, migration `0009`, routes.**
- [ ] **Step 4: Run tests + full suite; alembic smoke.**
- [ ] **Step 5: Commit** — `feat: LifecycleOrder state machine with approval gates`

---

## Task 8: Worker issuance execution (issue/renew path)

**Files:**
- Modify: `backend/app/worker.py`, `backend/app/scheduler.py`, add `backend/tests/test_worker_issue.py`

**Interfaces:**
- Produces:
  - `worker.process_one` handles kinds `issue`/`renew`: load the `LifecycleOrder`, transition `queued→issuing`, generate key+CSR (`crypto_keys`) per the managed cert's RenewalPolicy, call `get_adapter(issuer).issue(csr_pem, profile)`, store the issued cert as a new `Certificate` row (reuse existing `_upsert_certificate` from `scan_engine`), set `ManagedCertificate.current_certificate_id`, persist the (encrypted) private key alongside the managed cert (add `ManagedCertificate.current_key_ref` encrypted column via migration `0010`), then transition `issuing→deploying` and enqueue a `deploy` work item. On any failure → `lifecycle.transition(order, "failed", error)` and `queue.fail`.
  - `scheduler` renewal tick: a daily job that finds `ManagedCertificate`s whose `current_certificate.not_after - renew_before_days <= now` and creates a `renew` order via `lifecycle.create_order` (idempotent; actor `"system"`). It does NOT auto-approve (approval-gated).
- Consumes: Tasks 2–7, Phase-0 `scan_engine._upsert_certificate`.

**Details:**
- Add `ManagedCertificate.current_key_ref` (Text, encrypted private key PEM) in migration `0010_managed_key_ref.py`. The key is generated at issuance and needed for deployment (PFX/PEM bundle).

- [ ] **Step 1: Failing test** — `test_worker_issue.py`: seed a ManagedCertificate + approved+queued renew order; monkeypatch the issuer adapter's `issue` to return a canned `IssuedCert`; run `worker.process_one` → order transitions to `deploying`, a `deploy` WorkQueue row is enqueued, `ManagedCertificate.current_certificate_id` points at the new cert, and `current_key_ref` decrypts to a valid key. A failing adapter → order `failed`.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement worker issue/renew handling, key persistence + migration `0010`, renewal tick.**
- [ ] **Step 4: Run tests + full suite.**
- [ ] **Step 5: Commit** — `feat: worker executes issuance/renewal orders`

---

## Task 9: DeploymentTarget + PEM connector + deploy worker step

**Files:**
- Create: `backend/app/deploy/__init__.py`, `backend/app/deploy/base.py`, `backend/app/deploy/pem.py`, `backend/tests/test_deploy_pem.py`
- Modify: `backend/app/models.py`, `backend/app/worker.py`, add migration `0011_deployment_targets.py`

**Interfaces:**
- Produces:
  - `models.DeploymentTarget`: `id`, `name`, `kind` (String(8): "pem"|"pfx"|"jks"|"iis"), `config` (JSON — paths, encrypted creds/passwords), `post_deploy_command` (Text default ""), `managed_certificate_id` (FK), `enabled` (bool default True), `last_deploy_at`, `last_deploy_ok`, `created_at`.
  - `deploy/base.py`: `class DeployResult: ok: bool; detail: str`; `class DeployError(Exception)`; `class DeployConnector(Protocol): def deploy(self, bundle: CertBundle) -> DeployResult`. `CertBundle` dataclass: `cert_pem, chain_pem, key_pem, pfx_bytes(password) -> bytes` (helper builds PKCS12 via `crypto_keys`). `get_connector(target) -> DeployConnector` dispatch on kind.
  - `deploy/pem.py`: writes `cert.pem`, `chain.pem`, `fullchain.pem`, `key.pem` to configured paths using **write-new-then-atomic-rename** (write to `*.tmp`, `os.replace`), sets restrictive perms on the key, then runs `post_deploy_command` (subprocess, captured, non-zero → `DeployError`). The filesystem + subprocess calls are behind seams tests can monkeypatch/point at a tmp dir.
  - `worker.process_one` handles kind `deploy`: load order, `deploying` state, for each linked `DeploymentTarget` run `get_connector(target).deploy(bundle)`; on all-ok transition `deploying→verifying` and enqueue a `verify` item; on any failure → order `failed` (keep old files — atomic rename means the old file is only replaced on success).
- Consumes: Tasks 7–8, `crypto_keys` (PKCS12 helper).

- [ ] **Step 1: Failing test** — `test_deploy_pem.py`: a `DeploymentTarget(kind="pem")` pointing at a tmp dir; `PemConnector.deploy(bundle)` writes the four files with correct contents and the key file has restrictive perms; a failing `post_deploy_command` yields `DeployError`/`DeployResult(ok=False)` and does NOT leave a half-written key. Worker step: seed a queued `deploy` order → after `process_one`, order is `verifying` and a `verify` item is enqueued.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement models, migration `0011`, `deploy/base.py`, `deploy/pem.py`, worker deploy step.**
- [ ] **Step 4: Run tests + full suite.**
- [ ] **Step 5: Commit** — `feat: deployment targets and PEM connector with deploy worker step`

---

## Task 10: PFX + JKS/PKCS12 connectors

**Files:**
- Create: `backend/app/deploy/pfx.py`, `backend/app/deploy/jks.py`, `backend/tests/test_deploy_pfx_jks.py`
- Modify: `backend/app/deploy/base.py` (`get_connector` dispatch), `backend/app/crypto_keys.py` (PKCS12 builder)

**Interfaces:**
- Produces:
  - `crypto_keys.build_pkcs12(cert_pem, chain_pem, key_pem, password: str, friendly_name="") -> bytes` using `cryptography.hazmat.primitives.serialization.pkcs12.serialize_key_and_certificates`.
  - `deploy/pfx.py`: `PfxConnector` writes a `.pfx` to the configured path (atomic rename) with the configured (encrypted) password.
  - `deploy/jks.py`: `JksConnector` writes a PKCS12 keystore to the configured path (modern Java reads PKCS12 directly). `ponytail:` comment: real JKS format only if a consumer truly requires it — PKCS12 covers current Java. Both behind the same filesystem seam.
- Consumes: Task 9, `crypto_keys`.

- [ ] **Step 1: Failing test** — `test_deploy_pfx_jks.py`: `build_pkcs12` output re-parses via `pkcs12.load_key_and_certificates` with the password and yields the same cert + key; `PfxConnector.deploy` writes a file at the path that loads back; `JksConnector` writes a PKCS12 that loads back.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement PKCS12 builder + both connectors + dispatch.**
- [ ] **Step 4: Run tests + full suite.**
- [ ] **Step 5: Commit** — `feat: PFX and JKS/PKCS12 deployment connectors`

---

## Task 11: IIS connector

**Files:**
- Create: `backend/app/deploy/iis.py`, `backend/tests/test_deploy_iis.py`
- Modify: `backend/app/deploy/base.py` (`get_connector` dispatch)

**Interfaces:**
- Produces: `deploy/iis.py` `IisConnector`. Config: `pfx_password` (encrypted), `site_name`, `binding` (e.g. `https://:443:host`), optional remote `computer_name` + creds for PowerShell remoting. `deploy(bundle)` builds a PFX (`crypto_keys.build_pkcs12`), writes it to a temp path, then invokes a PowerShell script (`Import-PfxCertificate` into `Cert:\LocalMachine\My`, then set the IIS binding cert via `netsh http` or `New-WebBinding`/`Set-Item`). The PowerShell invocation is one seam method `_run_powershell(script: str) -> tuple[int, str]` that tests monkeypatch. Non-zero exit → `DeployError`.
- Consumes: Task 10.

- [ ] **Step 1: Failing test** — `test_deploy_iis.py`: monkeypatch `_run_powershell` to return `(0, "ok")` → `deploy` returns `DeployResult(ok=True)` and the generated script contains `Import-PfxCertificate` and the configured site/binding; a `(1, "error")` return → `DeployError`/`ok=False`. Assert the pfx password is passed to the script securely (not logged in plaintext).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement `iis.py` + dispatch.**
- [ ] **Step 4: Run tests + full suite.**
- [ ] **Step 5: Commit** — `feat: IIS deployment connector via PowerShell`

---

## Task 12: Post-deploy verification loop

**Files:**
- Modify: `backend/app/worker.py`, `backend/app/scan_engine.py` (targeted scan helper if needed), add `backend/tests/test_verify.py`

**Interfaces:**
- Produces:
  - `worker.process_one` handles kind `verify`: load the order + its managed cert's linked endpoints (the endpoints observed for that CN/SANs, or endpoints configured on the DeploymentTarget), run a targeted scan of just those endpoints (reuse `scan_engine.scan_endpoint`), and compare the observed leaf fingerprint to the newly issued cert's fingerprint. If they match → `lifecycle.transition(order, "complete")` and set `ManagedCertificate.state="active"`. If mismatch or scan failure after a bounded retry → `lifecycle.transition(order, "failed", "post-deploy verification mismatch")`, set managed cert `state="error"`, and raise a `deploy_failed` alert (Task 13 rule).
  - `RenewalPolicy.verify_after_deploy=False` skips verify: the deploy step transitions straight to `complete`.
- Consumes: Tasks 8–11, Phase-0 `scan_engine`, alerts.

- [ ] **Step 1: Failing test** — `test_verify.py`: seed an order in `verifying` with a managed cert whose new fingerprint == a monkeypatched `scan_endpoint` result → order `complete`, managed cert `active`. A mismatched observed fingerprint → order `failed`, managed cert `error`.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement verify handling + policy skip.**
- [ ] **Step 4: Run tests + full suite.**
- [ ] **Step 5: Commit** — `feat: post-deploy live verification closes the renewal loop`

---

## Task 13: Lifecycle alerting + dashboard + frontend

**Files:**
- Modify: `backend/app/alerts.py` (new rule types), `backend/app/main.py` (dashboard fields), `frontend/src/pages/ManagedCerts.tsx` + `Orders.tsx` (new), `frontend/src/App.tsx`, `frontend/src/api.ts`
- Test: `backend/tests/test_lifecycle_alerts.py`

**Interfaces:**
- Produces:
  - New `AlertEvent.rule_type` values emitted by the worker/verify paths: `renewal_failed`, `deploy_failed`, `order_stuck` (an order in a non-terminal state past a threshold, detected by a scheduler tick). Reuse the existing AlertEvent/dispatch machinery — no new alert infra.
  - Dashboard additions: `managed_certificates`, `unmanaged_certificates`, `renewal_success_rate_30d`, `orders_in_flight`, `orders_pending_approval`.
  - Frontend: `ManagedCerts` page (list + detail with lifecycle state + current cert + linked deployment targets), `Orders` page (list with state timeline + approve/reject buttons for `pending_approval`). Nav entries. Match existing style.
- Consumes: all prior tasks.

- [ ] **Step 1: Failing test** — `test_lifecycle_alerts.py`: a failed verify (from Task 12 path) creates a `deploy_failed` AlertEvent; the dashboard endpoint returns the new managed/pending-approval counts.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement alert rules + dashboard fields + frontend pages/nav.**
- [ ] **Step 4: Run tests + full suite; `npm run build` clean.**
- [ ] **Step 5: Commit** — `feat: lifecycle alerts, dashboard metrics, and management UI`

---

## Self-Review Notes

- **Spec coverage vs roadmap Phase 1:** 1.1 issuer+ACME → Tasks 2,3,4,5 (AD CS first per decision); 1.2 managed certs+renewal policy → Task 6; 1.3 lifecycle orders (approval-gated per decision) → Task 7 + execution Tasks 8,12; 1.4 deployment connectors (IIS/PFX, PEM, JKS per decision; no k8s) → Tasks 9,10,11; 1.5 lifecycle alerting+dashboard → Task 13. Plus Task 1 clears the two Phase-0 security follow-ups.
- **Decisions applied:** HTTP-01 only (Task 4, no DNS-01). AD CS is primary and built first (Task 3 before Task 4). Connectors ordered IIS/PFX→PEM→JKS (but implemented PEM first as the simplest base in Task 9, then PFX/JKS Task 10, IIS Task 11 — PEM-first is an implementation-ordering choice; the *product priority* IIS is delivered within the same phase). `require_approval` defaults True and every order is approval-gated (Tasks 6,7). No Kubernetes connector.
- **Type consistency:** `IssuerAdapter`/`IssuedCert`/`IssuerError` (Task 2) used by Tasks 3,4,8. `get_adapter` dispatch extended in Tasks 3,4. `DeployConnector`/`CertBundle`/`get_connector` (Task 9) used by Tasks 10,11,12. `LifecycleOrder` statuses (Task 7) drive Tasks 8,9,12. `crypto_keys.build_pkcs12` (Task 10) used by Tasks 10,11.
- **Migration chain:** 0006 issuers, 0007 acme_challenges, 0008 managed_certs, 0009 lifecycle_orders, 0010 managed_key_ref, 0011 deployment_targets — linear, each down_revision at prior.
- **Reuse:** queue/worker/scan_engine/_upsert_certificate/alerts/secrets/auth all reused from Phase 0, not reinvented.
