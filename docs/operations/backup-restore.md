# Backup, restore, and disaster recovery

CertWatch's durable state lives in two places: the Postgres database, and a
handful of secrets held only in process environment variables. Both are
required to fully recover the system.

## What to back up

1. **Database dump** — `scripts/backup.sh` (`pg_dump`, plain SQL). Contains
   all tables, including `NotificationChannel.config` and `Issuer.config`
   values, which are stored **encrypted** (see `backend/app/secrets.py`).
2. **`CERTWATCH_MASTER_KEY`** — the Fernet key used to encrypt/decrypt those
   secrets. Back this up **separately** from the database dump, in a secrets
   manager or offline vault. If it is lost, every encrypted secret in the
   dump (SMTP passwords, webhook URLs, ACME account keys, AD CS credentials)
   is **permanently unrecoverable** — there is no recovery path other than
   re-entering each secret by hand.
3. **`CERTWATCH_SESSION_SECRET`** — used to sign session cookies. Losing it
   just forces every user to log in again; not catastrophic, but back it up
   alongside the master key for a clean recovery.

Do not store #2/#3 next to the database dump (#1). Anyone who can read both
can decrypt every secret in the system.

## Backing up

```sh
./scripts/backup.sh [output-dir]
```

Reads `CERTWATCH_DATABASE_URL` (or standard `PGHOST`/`PGDATABASE`/`PGUSER`/
`PGPASSWORD` env vars) and writes `certwatch-backup-<timestamp>.sql` to
`output-dir` (default: current directory). Run this on a schedule (e.g. daily
cron / your platform's managed-Postgres snapshot feature) and copy the
resulting file to durable, access-controlled storage.

## Restoring

```sh
./scripts/restore.sh certwatch-backup-20260704-020000.sql
```

Restores the dump via `psql` into the database at `CERTWATCH_DATABASE_URL`.
After restoring:

1. Set `CERTWATCH_MASTER_KEY` to the **exact same value** used when the
   backup was taken. A mismatched key will not error loudly on startup —
   individual secrets will simply fail to decrypt when used (e.g. an SMTP
   send fails, an ACME renewal fails).
2. Set `CERTWATCH_SESSION_SECRET`.
3. Start the app.
4. Verify with the restore-check endpoint (below) before considering the
   restore complete.

## Verifying a restore

```
POST /api/admin/restore-check
```

Requires an authenticated admin session. Returns:

```json
{
  "schema_ok": true,
  "revision": "0014",
  "head": "0014",
  "counts": {"certificates": 42, "endpoints": 91, "managed_certificates": 3, "findings": 7},
  "secret_decrypt_ok": true
}
```

- `schema_ok` — the database has every table the app expects and the Alembic
  revision is at head (or the DB predates stamping, e.g. a fresh
  `create_all`).
- `revision` / `head` — current vs. expected Alembic revision, for diagnosing
  a schema drift.
- `counts` — a quick sanity check that the restored data is actually present
  (non-zero row counts for the key tables), not an empty schema.
- `secret_decrypt_ok` — proves `CERTWATCH_MASTER_KEY` matches the encrypted
  data by performing an encrypt-then-decrypt round trip, and (if any
  encrypted channel/issuer secret exists) attempting to decrypt one. This
  endpoint never returns plaintext or ciphertext secret values — only this
  boolean.

A `false` on any of these fields means: fix it (re-run migrations, re-check
`CERTWATCH_MASTER_KEY`, re-import data) before treating the restore as done.

## RPO / RTO

- **RPO (Recovery Point Objective):** bounded by backup frequency. A daily
  `backup.sh` run (or managed-Postgres continuous/point-in-time backup, which
  is recommended in production) gives an RPO of ~24h, or near-zero with PITR.
- **RTO (Recovery Time Objective):** provisioning a new Postgres instance,
  running `restore.sh`, setting the two secret env vars, and starting the app
  is a matter of minutes for a database of this scale; the bulk of RTO is
  operational (getting a replacement host/container up), not the restore
  itself.

## Single-node HA posture (deliberate, Phase 2 scope)

CertWatch's scan scheduler (`backend/app/scheduler.py`) is an in-process
APScheduler job with no distributed lock:

> `ponytail: in-process scheduler; move to a broker if you run multiple API replicas.`

Running more than one API instance would cause the scheduler to double-fire
scans and reports. **Run exactly one API instance.** Phase 2 deliberately
scopes availability to backup/restore + this verification endpoint, not
active-passive failover or multi-replica scheduling — see the roadmap
decision log (`.superpowers/sdd/`): "HA active-passive = DROPPED per
decision." If multi-replica HA is needed later, the scheduler needs to move
to an external broker (e.g. a distributed lock or a dedicated cron/queue
service) first.
