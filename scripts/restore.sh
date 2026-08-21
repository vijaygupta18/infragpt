#!/usr/bin/env bash
#
# infragpt restore.
#
# The plan requires that this is TESTED ONCE, not merely written — an untested
# restore procedure is a hope, not a control. Test it by restoring into a scratch
# directory and confirming users and grants are intact:
#
#     INFRAGPT_DATA=/tmp/restore-test ./scripts/restore.sh gs://bucket/infragpt/20260813-020000/
#
# Usage:
#   ./scripts/restore.sh <backup-dir-or-gs-uri> [--force]
#
# Examples:
#   ./scripts/restore.sh /data/backups/20260813-020000
#   ./scripts/restore.sh gs://<BUCKET>/infragpt/20260813-020000/
#
# Environment:
#   INFRAGPT_DATA   target data dir (default /data)
#
# Idempotent: restoring the same backup twice leaves the same state. The existing
# database is never deleted — it is moved aside to a timestamped .pre-restore
# copy, so a restore of the WRONG backup is itself recoverable.
#
# IMPORTANT: stop the infragpt deployment before restoring. SQLite in WAL mode
# with a live writer will not appreciate having its file replaced underneath it:
#
#     kubectl --context <ctx> -n apps scale deploy/infragpt --replicas=0
#     ... restore ...
#     kubectl --context <ctx> -n apps scale deploy/infragpt --replicas=1
#
# Scaling the deployment is a PRODUCTION WRITE and needs approval like any other.

set -Eeuo pipefail

SOURCE="${1:-}"
FORCE="${2:-}"
DATA_DIR="${INFRAGPT_DATA:-/data}"
DB_PATH="${DATA_DIR}/infragpt.db"
AUDIT_DIR="${DATA_DIR}/audit"
TS="$(date -u +%Y%m%d-%H%M%S)"

log()  { printf '[restore %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
fail() { log "FAILED: $*"; exit 1; }

trap 'fail "aborted at line ${LINENO}"' ERR

[[ -n "${SOURCE}" ]] || {
  sed -n '2,30p' "$0" >&2
  fail "no backup source given"
}

command -v sqlite3 >/dev/null 2>&1 || fail "sqlite3 not found on PATH"

# ---- 1. Stage the backup locally ------------------------------------------

STAGE=""
cleanup() {
  if [[ -n "${STAGE}" && -d "${STAGE}" ]]; then
    rm -rf "${STAGE}"
  fi
}
trap 'cleanup' EXIT

if [[ "${SOURCE}" == gs://* ]]; then
  command -v gsutil >/dev/null 2>&1 || fail "gsutil not found on PATH"
  STAGE="$(mktemp -d)"
  log "downloading ${SOURCE} -> ${STAGE}"
  gsutil -m cp "${SOURCE%/}/*" "${STAGE}/" || fail "gsutil download failed"
  SRC_DIR="${STAGE}"
else
  [[ -d "${SOURCE}" ]] || fail "not a directory: ${SOURCE}"
  SRC_DIR="${SOURCE}"
fi

# ---- 2. Verify BEFORE touching anything -----------------------------------

DB_BACKUP="$(find "${SRC_DIR}" -maxdepth 1 -name 'infragpt-*.db' | sort | tail -1)"
[[ -n "${DB_BACKUP}" ]] || fail "no infragpt-*.db found in ${SRC_DIR}"
[[ -s "${DB_BACKUP}" ]] || fail "database backup is empty: ${DB_BACKUP}"

INTEGRITY="$(sqlite3 "${DB_BACKUP}" 'PRAGMA integrity_check;' 2>/dev/null || echo failed)"
[[ "${INTEGRITY}" == "ok" ]] || fail "integrity check failed: ${INTEGRITY}"

USER_COUNT="$(sqlite3 "${DB_BACKUP}" 'SELECT COUNT(*) FROM users;' 2>/dev/null || echo -1)"
GRANT_COUNT="$(sqlite3 "${DB_BACKUP}" 'SELECT COUNT(*) FROM grants;' 2>/dev/null || echo -1)"
SCHEMA_V="$(sqlite3 "${DB_BACKUP}" 'SELECT MAX(version) FROM schema_version;' 2>/dev/null || echo unknown)"
[[ "${USER_COUNT}" -ge 0 ]] || fail "backup has no readable users table"

log "backup verified: ${USER_COUNT} users, ${GRANT_COUNT} grants, schema v${SCHEMA_V}"

if [[ -f "${DB_PATH}" && "${FORCE}" != "--force" ]]; then
  CURRENT_USERS="$(sqlite3 "${DB_PATH}" 'SELECT COUNT(*) FROM users;' 2>/dev/null || echo 0)"
  log ""
  log "  A database already exists at ${DB_PATH} with ${CURRENT_USERS} users."
  log "  Restoring will replace it with the backup's ${USER_COUNT} users."
  log "  The current file will be kept as ${DB_PATH}.pre-restore-${TS}"
  log ""
  log "  Re-run with --force to proceed:"
  log "    $0 ${SOURCE} --force"
  exit 3
fi

# ---- 3. Move the current database aside (never delete) --------------------

mkdir -p "${DATA_DIR}"

if [[ -f "${DB_PATH}" ]]; then
  log "preserving current database as ${DB_PATH}.pre-restore-${TS}"
  mv "${DB_PATH}" "${DB_PATH}.pre-restore-${TS}"
  # WAL/SHM belong to the old file; leaving them behind would corrupt the
  # restored one. if/fi, not `[[ ]] &&` — under `set -e` a false AND-list aborts.
  if [[ -f "${DB_PATH}-wal" ]]; then
    mv "${DB_PATH}-wal" "${DB_PATH}.pre-restore-${TS}-wal"
  fi
  if [[ -f "${DB_PATH}-shm" ]]; then
    mv "${DB_PATH}-shm" "${DB_PATH}.pre-restore-${TS}-shm"
  fi
fi

# ---- 4. Restore ------------------------------------------------------------

log "restoring database -> ${DB_PATH}"
cp "${DB_BACKUP}" "${DB_PATH}"

RESTORED_USERS="$(sqlite3 "${DB_PATH}" 'SELECT COUNT(*) FROM users;' 2>/dev/null || echo -1)"
[[ "${RESTORED_USERS}" == "${USER_COUNT}" ]] \
  || fail "restored user count ${RESTORED_USERS} != expected ${USER_COUNT}"

AUDIT_TAR="$(find "${SRC_DIR}" -maxdepth 1 -name 'audit-*.tar.gz' | sort | tail -1)"
if [[ -n "${AUDIT_TAR}" ]]; then
  log "restoring audit log -> ${AUDIT_DIR}"
  # Extracted alongside existing files: the audit log is append-only per-day, so
  # re-extracting an older archive cannot destroy newer days.
  mkdir -p "${AUDIT_DIR}"
  tar -xzf "${AUDIT_TAR}" -C "${DATA_DIR}" || fail "audit extract failed"
else
  log "no audit archive in this backup"
fi

trap - ERR
log ""
log "SUCCESS"
log "  users:   ${RESTORED_USERS}"
log "  grants:  ${GRANT_COUNT}"
log "  schema:  v${SCHEMA_V}"
log ""
log "Next: start the deployment and confirm with 'infractl whoami'."
log "The previous database, if any, is at ${DB_PATH}.pre-restore-${TS}"
