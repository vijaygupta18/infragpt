#!/usr/bin/env bash
# Create the read-only AWS identity for infragpt (IRSA).
#
# PRODUCTION WRITE. Review before running. Both policies attached are AWS-managed
# ReadOnly policies; no inline policy is created, and nothing grants a write.
set -euo pipefail

export AWS_PROFILE="${AWS_PROFILE:-prod}"
REGION="${REGION:-<AWS_REGION>}"
CLUSTER="${CLUSTER:-<EKS_CLUSTER>}"
ROLE_NAME="${ROLE_NAME:-infragpt-irsa-role}"
NAMESPACE="${NAMESPACE:-apps}"
KSA="${KSA:-infragpt}"

POLICIES=(
  arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess
  arn:aws:iam::aws:policy/AmazonElastiCacheReadOnlyAccess
)

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
OIDC_URL="$(aws eks describe-cluster --name "${CLUSTER}" --region "${REGION}" \
  --query 'cluster.identity.oidc.issuer' --output text)"
OIDC_HOST="${OIDC_URL#https://}"
PROVIDER="arn:aws:iam::${ACCOUNT}:oidc-provider/${OIDC_HOST}"

cat <<SUMMARY
About to create a READ-ONLY AWS identity.

  account  : ${ACCOUNT}
  region   : ${REGION}
  role     : ${ROLE_NAME}
  assumable by ONLY: system:serviceaccount:${NAMESPACE}:${KSA}
  policies : ${POLICIES[*]}

The trust policy pins BOTH :sub and :aud. Pinning only the OIDC provider would
let ANY pod in the cluster assume this role, which turns a scoped role into a
cluster-wide one.
SUMMARY
read -r -p "Proceed? [y/N] " ok
[[ "${ok}" == "y" || "${ok}" == "Y" ]] || { echo "aborted"; exit 1; }

# Mandatory pre-write backup: if the role already exists, capture it before
# touching anything.
BACKUP_DIR="${HOME}/infra-backups"
mkdir -p "${BACKUP_DIR}"
STAMP="$(date +%Y%m%d-%H%M%S)"
if aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
  BACKUP="${BACKUP_DIR}/aws-iam-role-${ROLE_NAME}-${STAMP}.json"
  {
    aws iam get-role --role-name "${ROLE_NAME}"
    aws iam list-attached-role-policies --role-name "${ROLE_NAME}"
  } > "${BACKUP}"
  [[ -s "${BACKUP}" ]] || { echo "ERROR: backup empty — stopping." >&2; exit 1; }
  echo "existing role backed up to: ${BACKUP}"
fi

TRUST="$(cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "${PROVIDER}" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "${OIDC_HOST}:sub": "system:serviceaccount:${NAMESPACE}:${KSA}",
        "${OIDC_HOST}:aud": "sts.amazonaws.com"
      }
    }
  }]
}
JSON
)"

if aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
  echo "role exists — updating trust policy only"
  aws iam update-assume-role-policy --role-name "${ROLE_NAME}" \
    --policy-document "${TRUST}"
else
  aws iam create-role --role-name "${ROLE_NAME}" \
    --description "infragpt read-only infra assistant (CloudWatch + ElastiCache read)" \
    --assume-role-policy-document "${TRUST}" >/dev/null
fi

for p in "${POLICIES[@]}"; do
  echo "attaching ${p}"
  aws iam attach-role-policy --role-name "${ROLE_NAME}" --policy-arn "${p}"
done

cat <<NEXT

Done. Annotate the Kubernetes ServiceAccount:

  eks.amazonaws.com/role-arn: arn:aws:iam::${ACCOUNT}:role/${ROLE_NAME}

Verify what it can actually do (read-only, safe to run):

  aws iam list-attached-role-policies --role-name ${ROLE_NAME}

Expect exactly the two ReadOnly policies. Any inline policy, any *FullAccess, or
any policy allowing iam:PassRole is a mistake.

For kubectl against EKS you ALSO need an access entry mapping this role to a
read-only Kubernetes group. That is Kubernetes RBAC, not IAM — see
../01-serviceaccount-rbac.yaml for the policy it should map to.
NEXT
