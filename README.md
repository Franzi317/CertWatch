# CertWatch

**SSL/TLS certificate inventory and expiration alerting for authorized internal networks.**

CertWatch scans the targets you define — hostnames, single IPs, CIDR blocks, or IP
ranges, on one or many ports — connects to each reachable endpoint, captures the
presented TLS certificate **without requiring it to be trusted**, and builds a
deduplicated inventory keyed by SHA-256 fingerprint. It tracks every certificate
across every endpoint it is bound to, preserves a full history of observations, and
alerts via **email**, **Microsoft Teams / generic webhook**, **Slack**, and
**PagerDuty** as certificates approach expiry, expire, change unexpectedly, or when
scans persistently fail.

> ⚠️ **Authorization notice.** CertWatch is for **authorized internal inventory
> only.** Only define targets for networks and hosts you are permitted to assess.
> Scanning hosts you do not own or have authorization for may be illegal.

---

## Architecture

```
        Browser ──► React + TypeScript SPA (frontend/, served by FastAPI in prod)
                         │  REST JSON  (/api/*)
                         ▼
              FastAPI backend (backend/app)
              ├─ scanner.py      native ssl/socket TLS capture (no shelling out)
              ├─ scan_engine.py  concurrent scan jobs, dedup, observation history
              ├─ alerts.py       threshold + suppression logic, dispatch
              ├─ notify.py       SMTP + Teams/webhook/Slack/PagerDuty senders (stdlib)
              ├─ scheduler.py    in-process APScheduler (scheduled rescans)
              └─ models.py       SQLAlchemy data model
                         │
                         ▼
              SQLite (dev)  /  PostgreSQL (prod)
```

Single deployable service: FastAPI runs the API, the in-process scheduler, **and**
serves the built React app. No external broker is needed for the MVP.

**Relationship to CipherGap (the sibling project in this repo):** CipherGap is a
public-internet quantum-readiness *grading* tool (Go scanner + Next.js + Stripe).
CertWatch reuses its proven ideas — capturing untrusted certs via a no-verify TLS
handshake and a stable scan error-code taxonomy — but is a different product:
internal certificate *inventory*. The Go scanner's SSRF guard (which **blocks**
private IPs) was intentionally dropped, since CertWatch must scan internal space;
it is replaced with CIDR-size guardrails and the authorization notice above.

---

## Quick start (Docker Compose)

```bash
cp .env.example .env          # edit POSTGRES_PASSWORD etc.
docker compose up --build
```

Open <http://localhost:8000>. Postgres data persists in the `pgdata` volume.

## Local development (without Docker)

**Backend** (Python 3.11+; 3.13 recommended for full certificate-chain capture):

```bash
cd backend
python -m venv .venv && . .venv/Scripts/activate    # or .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000           # API at /api, uses SQLite by default
```

**Frontend** (Node 18+):

```bash
cd frontend
npm install
npm run dev                                          # http://localhost:5173, proxies /api → :8000
```

## Running tests

```bash
cd backend && pytest                                 # 27 tests
cd frontend && npm run build                          # type-check + production build
```

---

## Using CertWatch

### Creating scan targets

**Targets → + New target.** Supported types:

| Type | Example value |
|------|---------------|
| Hostname / FQDN | `mail.example.com` |
| Single IP | `10.10.0.20` |
| CIDR block | `10.10.0.0/24` |
| IP range | `10.10.0.10-10.10.0.50` or shorthand `10.10.0.10-50` |

Each target carries a friendly name, description, environment (prod/non-prod/dev/lab),
owner/team, tags, a port list (defaults to 443; common TLS ports 8443/9443/636/993/
995/465/587/3389/5986 are one click away, plus custom ports), scan frequency, timeout,
concurrency limit, and per-target alert thresholds (default `90, 60, 30, 14, 7, 1`
days). Use **Validate / preview size** to see how many endpoints a target expands to
before saving — CIDR blocks larger than `CERTWATCH_MAX_CIDR_HOSTS` (default 4096) are
refused.

Ports that use STARTTLS — SMTP (25, 587), IMAP (143), POP3 (110), and LDAP (389) — are
detected automatically by port number; CertWatch performs the plaintext STARTTLS
handshake before capturing the certificate. No configuration is needed.

Scans run in the background; watch live progress on the **Scan Jobs** page, where any
running job can be cancelled. Scheduled rescans fire automatically based on each
target's frequency.

### Inventory views

- **Certificates** — deduplicated by fingerprint, with All / Expiring ≤90d / ≤30d /
  Expired / Self-signed views, free-text filter, and sortable columns. Each cert's
  detail page lists every endpoint it's bound to plus its full observation history.
- **Endpoints** — every host/IP/port scanned, including failed scans (a failed scan
  is operationally useful and never discarded).

### Severity levels

| Severity | Meaning |
|----------|---------|
| **Critical** | Expired, or expires within 7 days |
| **Warning** | Expires within 30 days |
| **Info** | Expires within 90 days |
| **Healthy** | More than 90 days out |
| **Unknown** | Scan failed or data incomplete |

### Certificate Transparency monitoring

**Settings → Watched domains (CT monitoring).** Add a domain (e.g. `example.com`) and
CertWatch periodically polls a CT log source (crt.sh-compatible) for certificates
issued for that domain or its subdomains — including ones CertWatch never scanned
directly. Matching certificates are imported with `source=ct` and shown with a **CT**
badge in the Certificates inventory (filterable via the `source=ct` view); this
surfaces shadow IT or unsanctioned CA issuance that network scanning alone would miss.

A CT-discovered certificate that has never been observed on any scanned endpoint
raises an `unknown_issuance` finding instead of an expiry/health alert, since
CertWatch doesn't control or operate that certificate. Dashboard expiry/health tiles
(expiring soon, expired) only count network-observed (`source=network`) certificates,
so CT-only certs never inflate those operational counts — they're tracked via the
finding instead.

### CA hierarchy

During a scan, CertWatch captures each endpoint's full certificate chain (not just
the leaf) and stores the intermediate/root CA certificates it discovers with
`source=chain` — a third cert origin alongside `source=network` (leaf certs observed
directly on an endpoint) and `source=ct` (leaf certs discovered via CT logs above).

The **CA Certificates** page lists every CA cert seen in a captured chain — flat, not
a tree — with its subject/CN, issuer, expiry status, a **Root**/**Intermediate** label
(root = self-signed CA), and a **dependent count**: how many currently-observed leaf
certificates chain up through it. A CA nearing expiry with zero dependents is noise,
not a risk, so it's excluded from alerting (see below) but still listed for visibility.

When a CA certificate with at least one dependent leaf crosses an expiry threshold, an
`issuer_expiring` alert fires — the same anti-spam/auto-resolve alert lifecycle as
other rules, and it lists the affected leaf certificates. Thresholds are configured via
the `ca_alert_thresholds` setting (comma-separated days, default `180,90,30` — wider
than leaf-cert thresholds since replacing a CA has more downstream impact and lead
time to plan). The dashboard's **CA certs expiring ≤90d** tile applies the same
dependent-count guard.

Full chain capture (and therefore the entire CA hierarchy feature) requires
**Python 3.13+** (`get_unverified_chain`); on older runtimes only the leaf certificate
is captured, so the CA Certificates page and `issuer_expiring` alerts stay empty. See
[Known limitations](#known-limitations).

---

## How alerting works

After every scan, CertWatch evaluates alert rules against current state:

- **Expiring** — cert is within a target's configured threshold (one alert per
  threshold band crossed, so you get a 90-day heads-up *and* a 7-day escalation).
- **Expired** — cert's `notAfter` is in the past.
- **Changed** — an endpoint's certificate fingerprint changed since the previous scan.
- **Scan failure** — an endpoint has failed `scan_failure_threshold` consecutive scans.
- **Self-signed** *(optional)* — enable in Settings.
- **Issuer expiring** — a CA certificate (`source=chain`) with at least one dependent
  leaf crosses a threshold in `ca_alert_thresholds` (default `180,90,30` days). See
  [CA hierarchy](#ca-hierarchy).

**Anti-spam:** each condition maps to a stable key stored as one alert event. It
notifies once on creation, then only again after the channel's **re-alert interval**
(default 24h). Alerts can be **acknowledged** (stop notifying) or **muted** (for N
hours or indefinitely). When a cert is renewed or a scan recovers, the matching alert
**auto-resolves** — every enabled channel (Teams/webhook, email, Slack, PagerDuty)
receives a one-time "Resolved" notice; PagerDuty additionally auto-resolves the
underlying incident.

Every alert message includes the CN/SAN, endpoint host/IP and port, expiration date,
days remaining, issuer, fingerprint, target group, owner/team, environment, a link to
the certificate detail page, and a recommended action.

### Configuring SMTP

**Settings → + SMTP.** Fields: host, port, STARTTLS or implicit TLS, username,
password, from address, recipients. Use **Test** to send a test email. The password is
stored server-side and **never** returned by the API or shown in the UI (editing with a
blank password leaves the existing one untouched).

### Configuring Teams / webhook

**Settings → + Teams / Webhook.** Paste an incoming webhook URL and choose a format:
**Teams MessageCard** (rich card with an "View certificate" action) or **Generic JSON**
(`{title, text, facts, link}`) for any other consumer. Use **Test** to verify. The URL
is treated as a secret and never returned by the API.

### Configuring Slack

**Settings → + Slack.** Paste an incoming-webhook URL
(`https://hooks.slack.com/services/...`) and optionally set a **minimum severity**
floor (info/warning/critical) so low-priority alerts don't reach the channel. Use
**Test** to verify. The URL is treated as a secret and never returned by the API.

### Configuring PagerDuty

**Settings → + PagerDuty.** Paste an **Events API v2** integration/routing key from a
PagerDuty service. Defaults to **critical-only** (adjustable via minimum severity) so
routine warnings don't page anyone. CertWatch triggers an incident on alert and
**auto-resolves** it when the underlying condition clears. An optional Events API URL
override is available for non-default regions/proxies. Use **Test** to verify. The
routing key is treated as a secret and never returned by the API.

---

## REST API

All under `/api`. When `CERTWATCH_API_KEY` is set, send `Authorization: Bearer <key>`.

| Method | Path | Purpose |
|--------|------|---------|
| GET/POST | `/targets` | list / create targets |
| GET/PUT/DELETE | `/targets/{id}` | read / update / delete |
| POST | `/targets/validate` | validate + preview endpoint count |
| POST | `/targets/{id}/scan` | start a scan |
| POST | `/scans/{id}/cancel` | cancel a running scan |
| GET | `/scans`, `/scans/{id}` | list / status of scan jobs |
| GET | `/certificates`, `/certificates/{id}` | inventory + detail (filters: `q`, `expiring_within`, `expired`, `self_signed`, `issuer`, `sort`, `limit`, `offset`) |
| GET | `/ca-certificates` | CA hierarchy: `source=chain` certs with `dependent_count` + `is_root`, sorted by soonest expiry |
| GET | `/endpoints`, `/endpoints/{id}` | endpoint inventory + detail |
| GET | `/alerts` | list alerts |
| POST | `/alerts/{id}/ack` · `/mute` · `/unmute` | alert actions |
| POST | `/alerts/evaluate` | re-evaluate now |
| GET/POST | `/channels` | list / create notification channels |
| PUT/DELETE | `/channels/{id}` | update / delete |
| POST | `/channels/{id}/test` | send a test notification |
| GET/PUT | `/settings` | scan/alert defaults |
| GET | `/dashboard` | summary counts |

Interactive docs at `/docs` (Swagger UI).

---

## Security notes

- All target inputs are validated with the stdlib `ipaddress` module and a strict
  hostname regex — **no shelling out**, eliminating command-injection surface.
- TLS capture uses native `ssl`/`socket` with verification disabled *only to observe*
  untrusted certs (expired, self-signed, mismatched, incomplete-chain are all
  inventoried). CertWatch never treats observed certs as trusted.
- Secrets (SMTP password, webhook/Slack URL, PagerDuty routing key) come from
  per-channel config or env vars, are scrubbed from all API responses, and are not
  logged.
- Optional bearer-token API auth (`CERTWATCH_API_KEY`). Target and channel changes are
  written to an audit log.
- Sensible CORS defaults; configurable via `CERTWATCH_CORS_ORIGINS`.

## Environment variables

See `.env.example`. Key ones: `CERTWATCH_DATABASE_URL`, `CERTWATCH_API_KEY`,
`CERTWATCH_MAX_CIDR_HOSTS`, `CERTWATCH_DEFAULT_TIMEOUT`, `CERTWATCH_DEFAULT_CONCURRENCY`,
`CERTWATCH_ENABLE_SCHEDULER`, `CERTWATCH_STATIC_DIR`, `CERTWATCH_CT_SOURCE_URL` (CT log
source base URL; blank disables CT monitoring, default `https://crt.sh`),
`CERTWATCH_CT_CHECK_FREQUENCY_HOURS` (default `24`), `CERTWATCH_CT_FINDING_SEVERITY`
(severity of the `unknown_issuance` finding, default `warning`).

## Known limitations

- **Authentication is intentionally minimal** (optional shared bearer token). Multi-user
  auth / RBAC / SSO are future enhancements.
- Full certificate-**chain** capture requires Python 3.13+ (`get_unverified_chain`); on
  older runtimes only the leaf certificate is captured (sufficient for inventory). The
  Docker image uses 3.13.
- The scheduler is in-process — run a single API instance, or move scheduling to an
  external trigger if you scale horizontally.
- Scanning happens from wherever the backend runs; it must have network reachability to
  the targets.

## Troubleshooting scanner errors

| Status shown | Meaning / fix |
|--------------|---------------|
| `connection_failed` | Port closed/unreachable or host down. Check routing/firewall. |
| `timeout` | No response within the target's timeout. Raise the timeout or check reachability. |
| `tls_handshake_failed` | Port open but TLS negotiation failed (protocol/cipher mismatch). |
| `non_tls_service` | Port is open but speaks a non-TLS protocol (e.g. plain HTTP). |
| `starttls_failed` | Port speaks its plaintext protocol (SMTP/IMAP/POP3/LDAP) but STARTTLS was not offered or was refused. The service may have STARTTLS disabled, or requires it be enabled server-side. |
| `no_certificate` | TLS completed but no certificate was presented. |
| `dns_resolution_failed` | Hostname did not resolve. Check DNS. |

Scans never crash the worker — every failure is recorded as an observation and shown on
the endpoint's detail page.
