#!/usr/bin/env bash
# CertWatch database restore.
#
# Restores a plain-SQL dump (produced by scripts/backup.sh) via psql.
#
# Usage: ./scripts/restore.sh <dump-file>
set -euo pipefail

DUMP_FILE="${1:?usage: restore.sh <dump-file>}"

if [ -z "${CERTWATCH_DATABASE_URL:-}" ]; then
    echo "CERTWATCH_DATABASE_URL is not set; refusing to guess a target database." >&2
    exit 1
fi

echo "Restoring ${DUMP_FILE} into the database at CERTWATCH_DATABASE_URL ..."
echo "(restore expects a fresh/empty target database; ON_ERROR_STOP aborts on the first error)"
psql -v ON_ERROR_STOP=1 -q "${CERTWATCH_DATABASE_URL}" < "${DUMP_FILE}"

echo "=================================================================="
echo "Restore complete. Before starting the app:"
echo "  1. Set CERTWATCH_MASTER_KEY to the EXACT SAME value that was in"
echo "     effect when this backup was taken. If it doesn't match, every"
echo "     encrypted secret (SMTP/webhook passwords, ACME account keys)"
echo "     will fail to decrypt and those integrations will break."
echo "  2. Set CERTWATCH_SESSION_SECRET as usual."
echo "  3. Start the app, then verify the restore:"
echo "       POST /api/admin/restore-check  (as an admin user)"
echo "     Confirm schema_ok, counts, and secret_decrypt_ok are all as"
echo "     expected before declaring the restore successful."
echo "=================================================================="
