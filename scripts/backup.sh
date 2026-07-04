#!/bin/sh
# CertWatch database backup.
#
# Dumps the Postgres database to a timestamped plain-SQL file using pg_dump.
# Reads CERTWATCH_DATABASE_URL if set, otherwise falls back to standard
# PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD env vars (pg_dump's defaults).
#
# Usage: ./scripts/backup.sh [output-dir]
set -euo pipefail

OUT_DIR="${1:-.}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_FILE="${OUT_DIR}/certwatch-backup-${STAMP}.sql"

if [ -n "${CERTWATCH_DATABASE_URL:-}" ]; then
    pg_dump "${CERTWATCH_DATABASE_URL}" > "${OUT_FILE}"
else
    pg_dump > "${OUT_FILE}"
fi

echo "Backup written to ${OUT_FILE}"
echo "=================================================================="
echo "REMINDER: this dump alone is NOT enough to recover CertWatch."
echo "You MUST separately and securely back up:"
echo "  - CERTWATCH_MASTER_KEY  (without it, encrypted secrets in this"
echo "    dump -- SMTP/webhook passwords, ACME account keys, etc -- are"
echo "    PERMANENTLY UNRECOVERABLE, even with the dump in hand)"
echo "  - CERTWATCH_SESSION_SECRET"
echo "Store these in a secrets manager or offline vault, NOT next to this"
echo "dump file."
echo "=================================================================="
