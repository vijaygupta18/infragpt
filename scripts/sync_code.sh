#!/usr/bin/env sh
# Keep shallow clones of the source repositories on the data volume.
#
# WHY SHALLOW: history is not what gets read. `--depth 1` turns a ~900MB
# repository into a working tree, which is the whole value here, and makes the
# refresh cheap enough to run on every start.
#
# WHY PUBLIC ONLY: no credentials are handled anywhere in this path. If a
# private repository is ever needed, that is a deliberate decision requiring a
# token, not something to slip in by editing this list.
#
# Runs in the BACKGROUND at startup: a first clone takes minutes, and the API
# must answer infrastructure questions meanwhile. Code functions report "not
# cloned yet" until the tree lands, which is honest and self-correcting.
set -eu

CODE_DIR="${INFRAGPT_CODE:-/data/code}"
REPOS="${INFRAGPT_CODE_REPOS:-}"

[ -z "${REPOS}" ] && { echo "sync_code: INFRAGPT_CODE_REPOS unset, nothing to do"; exit 0; }
command -v git >/dev/null 2>&1 || { echo "sync_code: git not installed"; exit 0; }

mkdir -p "${CODE_DIR}"

echo "${REPOS}" | tr ',' '\n' | while read -r spec; do
  [ -z "${spec}" ] && continue
  name="${spec%%=*}"
  url="${spec#*=}"
  [ -z "${name}" ] || [ -z "${url}" ] && continue
  dest="${CODE_DIR}/${name}"

  if [ -d "${dest}/.git" ]; then
    echo "sync_code: refreshing ${name}"
    git -C "${dest}" fetch --depth 1 origin HEAD >/dev/null 2>&1 || {
      echo "sync_code: fetch failed for ${name}, keeping existing tree"; continue; }
    git -C "${dest}" reset --hard FETCH_HEAD >/dev/null 2>&1 || true
  else
    echo "sync_code: cloning ${name}"
    git clone --depth 1 --single-branch "${url}" "${dest}" >/dev/null 2>&1 || {
      echo "sync_code: clone failed for ${name}"; continue; }
  fi
  echo "sync_code: ${name} @ $(git -C "${dest}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
done

echo "sync_code: done"
