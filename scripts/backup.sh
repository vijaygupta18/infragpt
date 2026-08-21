#!/usr/bin/env bash
#
# infragpt nightly backup.
#
# Backs up the SQLite database and the audit JSONL to GCS. This is the
# compensating control for the PV/RWO storage decision: the volume is
# single-replica with no HA, so without a tested backup a lost PV is a lost user
# database. Capability is never lost (the registry and connections are config in
# git) — users, grants and audit history are.
#
# READ-ONLY with respect to production infrastructure. It touches only
# infragpt's own PV and its own GCS bucket. It reads no application database.
#
# Usage:
#   INFRAGPT_BACKUP_BUCKET=gs://my-bucket ./scripts/backup.sh
#
# Environment:
#   INFRAGPT_BACKUP_BUCKET  (required) gs:// destination
#   INFRAGPT_DATA           data dir           (default /data)
#   INFRAGPT_BACKUP_KEEP    local copies kept  (default 7)
#   INFRAGPT_BACKUP_DRYRUN  set to 1 to skip the GCS upload
#
# Idempotent: each run writes its own timestamped artefacts and never mutates a
# previous backup. Safe to run repeatedly and safe to re-run after a failure.
#
# Exits non-zero if anything is missing, empty, or fails to verify. A backup
# script that exits 0 without producing a usable backup is worse than no backup
# script, because it silences the alarm that would otherwise have fired.

set -Eeuo pipefail

DATA_DIR="${INFRAGPT_DATA:-/data}"
DB_PATH="${DATA_DIR}/infragpt.db"
AUDIT_DIR="${DATA_DIR}/audit"
BACKUP_DIR="${DATA_DIR}/backups"
KEEP="${INFRAGPT_BACKUP_KEEP:-7}"
BUCKET="${INFRAGPT_BACKUP_BUCKET:-}"
DRYRUN="${INFRAGPT_BACKUP_DRYRUN:-0}"

TS="$(date -u +%Y%m%d-%H%M%S)"
STAMP_DIR="${BACKUP_DIR}/${TS}"
DB_BACKUP="${STAMP_DIR}/infragpt-${TS}.db"
AUDIT_TAR="${STAMP_DIR}/audit-${TS}.tar.gz"
MANIFEST="${STAMP_DIR}/MANIFEST.txt"

log()  { printf '[backup %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
fail() { log "FAILED: $*"; exit 1; }

trap 'fail "aborted at line ${LINENO}"' ERR

# ---- preflight -------------------------------------------------------------

command -v sqlite3 >/dev/null 2>&1 || fail "sqlite3 not found on PATH"
[[ -f "${DB_PATH}" ]]               || fail "database not found: ${DB_PATH}"

if [[ "${DRYRUN}" != "1" ]]; then
  [[ -n "${BUCKET}" ]] || fail "INFRAGPT_BACKUP_BUCKET is not set"
  command -v gsutil >/dev/null 2>&1 || fail "gsutil not found on PATH"
fi

mkdir -p "${STAMP_DIR}"

# ---- 1. SQLite ------------------------------------------------------------
#
# `.backup` (not `cp`) because the DB is in WAL mode and live: a plain copy can
# capture a torn page set plus a WAL that no longer matches it. `.backup` takes a
# consistent snapshot of a database that is being written to.

log "backing up ${DB_PATH}"
sqlite3 "${DB_PATH}" ".backup '${DB_BACKUP}'" || fail "sqlite3 .backup failed"

[[ -s "${DB_BACKUP}" ]] || fail "database backup is empty: ${DB_BACKUP}"

# Verify the snapshot actually opens and passes an integrity check. An
# unreadable backup that exists on disk is the failure mode this catches.
INTEGRITY="$(sqlite3 "${DB_BACKUP}" 'PRAGMA integrity_check;' 2>/dev/null || echo failed)"
[[ "${INTEGRITY}" == "ok" ]] || fail "integrity check on backup: ${INTEGRITY}"

USER_COUNT="$(sqlite3 "${DB_BACKUP}" 'SELECT COUNT(*) FROM users;' 2>/dev/null || echo -1)"
[[ "${USER_COUNT}" -ge 0 ]] || fail "backup has no readable users table"
log "database ok: ${USER_COUNT} users, $(wc -c <"${DB_BACKUP}") bytes"

# ---- 2. Audit log ---------------------------------------------------------

if [[ -d "${AUDIT_DIR}" ]] && [[ -n "$(ls -A "${AUDIT_DIR}" 2>/dev/null)" ]]; then
  log "archiving ${AUDIT_DIR}"
  tar -czf "${AUDIT_TAR}" -C "${DATA_DIR}" audit || fail "audit tar failed"
  [[ -s "${AUDIT_TAR}" ]] || fail "audit archive is empty: ${AUDIT_TAR}"
  tar -tzf "${AUDIT_TAR}" >/dev/null || fail "audit archive is unreadable"
  log "audit ok: $(wc -c <"${AUDIT_TAR}") bytes"
else
  log "no audit files to archive (this is normal on a fresh install)"
fi

# ---- 3. Manifest + checksums ----------------------------------------------

{
  echo "infragpt backup"
  echo "created_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host:        $(hostname)"
  echo "data_dir:    ${DATA_DIR}"
  echo "users:       ${USER_COUNT}"
  echo "schema_version: $(sqlite3 "${DB_BACKUP}" 'SELECT MAX(version) FROM schema_version;' 2>/dev/null || echo unknown)"
  echo "files:"
} >"${MANIFEST}"

# NOTE: written as if/fi rather than `[[ ... ]] && continue`. Under `set -e` a
# false AND-list is a failing command and would abort the whole backup.
( cd "${STAMP_DIR}" && for f in *; do
    if [[ "$f" != "MANIFEST.txt" ]]; then
      if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$f"
      else
        shasum -a 256 "$f"
      fi
    fi
  done ) >>"${MANIFEST}"

[[ -s "${MANIFEST}" ]] || fail "manifest is empty"

# ---- 4. Upload -------------------------------------------------------------

if [[ "${DRYRUN}" == "1" ]]; then
  log "dry run: skipping upload to GCS"
else
  DEST="${BUCKET%/}/infragpt/${TS}/"
  log "uploading to ${DEST}"
  gsutil -m cp "${STAMP_DIR}"/* "${DEST}" || fail "gsutil upload failed"

  # Verify the remote copy exists and is non-empty, rather than trusting exit 0.
  REMOTE_COUNT="$(gsutil ls "${DEST}" 2>/dev/null | wc -l | tr -d ' ')"
  [[ "${REMOTE_COUNT}" -ge 2 ]] || fail "expected >=2 objects at ${DEST}, found ${REMOTE_COUNT}"
  log "uploaded ${REMOTE_COUNT} objects"
fi

# ---- 5. Local retention ----------------------------------------------------
#
# Only ever removes whole timestamped directories older than the newest KEEP.
# Never touches the remote copies.

# `while read` rather than `mapfile`, which is bash 4+ and absent on macOS's
# stock bash 3.2 — this script should behave the same wherever it is tested.
if [[ "${KEEP}" -gt 0 ]]; then
  while IFS= read -r dir; do
    if [[ -n "${dir}" && -d "${dir}" ]]; then
      log "pruning local ${dir}"
      rm -rf "${dir}"
    fi
  done < <(ls -1d "${BACKUP_DIR}"/*/ 2>/dev/null | sort -r | tail -n +$((KEEP + 1)) || true)
fi

trap - ERR
log "SUCCESS: ${STAMP_DIR}"
echo "${STAMP_DIR}"
