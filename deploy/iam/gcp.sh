#!/usr/bin/env bash
# Create the read-only GCP identity for infragpt.
#
# PRODUCTION WRITE. Review before running. Every role granted is a *.viewer:
# if a role would let the pod change anything, it does not belong here.
set -euo pipefail

PROJECT="${PROJECT:-<GCP_PROJECT>}"
GSA_NAME="${GSA_NAME:-infragpt}"
GSA="${GSA_NAME}@${PROJECT}.iam.gserviceaccount.com"
NAMESPACE="${NAMESPACE:-apps}"
KSA="${KSA:-infragpt}"
POOL="${PROJECT}.svc.id.goog"

ROLES=(
  roles/monitoring.viewer   # Cloud Monitoring — all metric types
  roles/alloydb.viewer      # AlloyDB inventory + live node counts
  # container.clusterViewer, NOT container.viewer. Verified 2026-08-18:
  # container.viewer carries container.configMaps.get/list, which would grant
  # ConfigMap read across every cluster in the project and silently undo the
  # ConfigMap exclusion in 01-serviceaccount-rbac.yaml. An IAM grant that
  # re-opens what Kubernetes RBAC closed is the worst kind of hole, because the
  # RBAC file still *reads* as if it were shut.
  # clusterViewer is exactly: clusters.get, clusters.list, projects.get/list.
  roles/container.clusterViewer  # GKE cluster + node-pool metadata only
  roles/redis.viewer        # Memorystore instance metadata
  roles/logging.viewer      # Cloud Logging reads
)

cat <<SUMMARY
About to create a READ-ONLY GCP identity.

  project        : ${PROJECT}
  service account: ${GSA}
  bound to KSA   : ${NAMESPACE}/${KSA}  (Workload Identity, no key file)
  roles          : ${ROLES[*]}

No key is created. A JSON key on a PV is a credential that can leave the
cluster; a Workload Identity binding cannot.
SUMMARY
read -r -p "Proceed? [y/N] " ok
[[ "${ok}" == "y" || "${ok}" == "Y" ]] || { echo "aborted"; exit 1; }

# Mandatory pre-write backup: capture the CURRENT project IAM policy before
# adding any binding. Restoring is `gcloud projects set-iam-policy` with this
# file, which is the only way back if a binding is added wrongly.
BACKUP_DIR="${HOME}/infra-backups"
mkdir -p "${BACKUP_DIR}"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="${BACKUP_DIR}/gcp-${PROJECT}-iam-policy-${STAMP}.json"
gcloud projects get-iam-policy "${PROJECT}" --format=json > "${BACKUP}"
if [[ ! -s "${BACKUP}" ]]; then
  echo "ERROR: IAM policy backup is empty — refusing to continue." >&2
  exit 1
fi
echo "IAM policy backed up to: ${BACKUP}"

if ! gcloud iam service-accounts describe "${GSA}" --project="${PROJECT}" >/dev/null 2>&1; then
  gcloud iam service-accounts create "${GSA_NAME}" \
    --project="${PROJECT}" \
    --display-name="infragpt (read-only infra assistant)" \
    --description="Read-only. Monitoring/AlloyDB/GKE/Memorystore/Logging viewers only."
else
  echo "service account already exists, reusing"
fi

for role in "${ROLES[@]}"; do
  echo "granting ${role}"
  gcloud projects add-iam-policy-binding "${PROJECT}" \
    --member="serviceAccount:${GSA}" \
    --role="${role}" \
    --condition=None \
    --quiet >/dev/null
done

echo "binding Workload Identity ${NAMESPACE}/${KSA} -> ${GSA}"
gcloud iam service-accounts add-iam-policy-binding "${GSA}" \
  --project="${PROJECT}" \
  --role=roles/iam.workloadIdentityUser \
  --member="serviceAccount:${POOL}[${NAMESPACE}/${KSA}]" \
  --quiet >/dev/null

cat <<NEXT

Done. Annotate the Kubernetes ServiceAccount so the pod picks this up:

  iam.gke.io/gcp-service-account: ${GSA}

Verify what it can actually do (read-only, safe to run):

  gcloud projects get-iam-policy ${PROJECT} \\
    --flatten="bindings[].members" \\
    --filter="bindings.members:${GSA}" \\
    --format="value(bindings.role)"

Expect five *.viewer roles and nothing else. Anything ending in .admin or
.editor, or roles/iam.serviceAccountTokenCreator, is a mistake — the last one
looks harmless and is how an identity escalates into other identities.
NEXT
