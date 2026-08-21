#!/usr/bin/env bash
# Build, push and roll out. One command, because a fix that is only on a laptop
# is not a fix — and a version bump that is skipped makes "which code is
# running?" unanswerable during an incident.
#
#   bash scripts/ship.sh            # auto-increment the patch version
#   bash scripts/ship.sh 0.2.0      # explicit version
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Deployment coordinates live OUTSIDE the repository. They are not secret, but
# a registry path, a cluster context and a namespace describe someone's
# infrastructure, and this repository is published.
#
#     cp scripts/ship.env.example scripts/ship.env   # then fill it in
#
# Environment variables win, so CI can supply them without a file.
if [[ -f "${ROOT}/scripts/ship.env" ]]; then
  # shellcheck disable=SC1091
  source "${ROOT}/scripts/ship.env"
fi

: "${REPO:?REPO is not set. Copy scripts/ship.env.example to scripts/ship.env and fill it in.}"
: "${CTX:?CTX is not set — the kubectl context to deploy into.}"
NS="${NS:-default}"

# The committed deploy/*.yaml files are TEMPLATES containing <PLACEHOLDERS>.
# The filled-in copies live in deploy/private/ (gitignored). Prefer those, and
# refuse to apply a template — a placeholder reaching the cluster fails in a
# confusing way rather than an obvious one.
MANIFEST="deploy/private/04-deployment.yaml"
if [[ ! -f "${MANIFEST}" ]]; then
  echo "ERROR: ${MANIFEST} not found."
  echo "       The committed deploy/*.yaml are templates. Create your copy:"
  echo "         mkdir -p deploy/private && cp deploy/*.yaml deploy/private/"
  echo "         \$EDITOR deploy/private/04-deployment.yaml   # fill <PLACEHOLDERS>"
  exit 1
fi
if grep -q "<[A-Z_]*>" "${MANIFEST}"; then
  echo "ERROR: ${MANIFEST} still contains <PLACEHOLDERS>. Fill them in first."
  exit 1
fi

current() { grep -oE "infragpt:[0-9]+\.[0-9]+\.[0-9]+" ${MANIFEST} | head -1 | cut -d: -f2; }

if [[ $# -ge 1 ]]; then
  VERSION="$1"
else
  IFS=. read -r MA MI PA <<< "$(current)"
  VERSION="${MA}.${MI}.$((PA + 1))"
fi

echo "==> tests + lint (a broken build must not reach the cluster)"
./.venv/bin/python -m pytest -q >/dev/null
./.venv/bin/ruff check app cli tests >/dev/null

echo "==> build ${VERSION} (linux/amd64 — the nodes are not arm64)"
docker buildx build --platform linux/amd64 -t "${REPO}:${VERSION}" --load . >/dev/null

echo "==> push"
docker push "${REPO}:${VERSION}" >/dev/null

echo "==> pin manifest to ${VERSION}"
sed -i '' -E "s|infragpt:[0-9]+\.[0-9]+\.[0-9]+|infragpt:${VERSION}|" ${MANIFEST}

echo "==> apply + rollout"
kubectl --context="${CTX}" -n "${NS}" apply -f ${MANIFEST} 2>&1 | grep -v '^Warning' || true
kubectl --context="${CTX}" -n "${NS}" rollout status deploy/infragpt --timeout=180s | tail -1

echo "==> running: $(kubectl --context="${CTX}" -n "${NS}" get deploy infragpt -o jsonpath='{.spec.template.spec.containers[0].image}')"
