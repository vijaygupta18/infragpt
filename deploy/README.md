# deploy/ — infragpt Kubernetes manifests

> ## ⚠️ Applying anything in this directory is a PRODUCTION WRITE
>
> Every `kubectl apply` here creates or mutates objects in the **GKE prod**
> cluster, namespace `apps`. Under the working agreement that means: show the
> exact command, the target context, and the blast radius, get explicit approval,
> **take a backup of anything being replaced**, and only then run it.
>
> These files were written by an agent that has **not** applied them, has not run
> `kubectl` against any cluster, and has not verified them against a live API
> server. Treat them as a reviewed starting point, not as tested manifests.
> `kubectl apply --dry-run=server` is the cheapest way to find what is wrong.

---

## Before you apply anything

Search for `TODO` and resolve every one. Nothing here ships with real values.

```bash
grep -rn "TODO" deploy/
```

The ones that will bite hardest if missed:

| TODO | Why it matters |
|---|---|
| `image:` in `04-deployment.yaml` | Placeholder registry path. **Pin a digest, not a tag** — a mutable tag means the thing you reviewed and the thing that runs can differ. |
| `secretStoreRef` in `03-externalsecrets.yaml` | Must name a `ClusterSecretStore` that actually exists, or the secrets never sync and the pod crash-loops on missing env. |
| Reader hosts / contexts in `04-deployment.yaml` | Empty strings mean every executor fails at runtime with a confusing connection error rather than a clear config error. |
| `infragpt_ro` Postgres role | **Does not exist yet.** Creating it is itself a production write needing approval. Until it exists with read-only grants, the DB surface has no credential-layer enforcement — only application-layer. |
| EKS-side RBAC | Nothing in this repo can constrain the AWS cluster. Confirm the kubeconfig's EKS identity is read-only **before** applying `03-externalsecrets.yaml`. |

## Apply order

The order matters: RBAC before the workload that assumes it, secrets before the
pod that mounts them, PVC before anything that mounts it.

```bash
CTX=<gke-prod-context>    # confirm with: kubectl config get-contexts
NS=apps

# 0. Namespace — already exists. Do NOT create or modify it.
kubectl --context "$CTX" get ns "$NS"

# 1. ServiceAccount + RBAC  (read-only: get/list/watch)
kubectl --context "$CTX" apply -f deploy/01-serviceaccount-rbac.yaml

# 2. PVC  (RWO, 20Gi)
kubectl --context "$CTX" apply -f deploy/02-pvc.yaml

# 3. ExternalSecrets  — resolve the TODOs first
kubectl --context "$CTX" apply -f deploy/03-externalsecrets.yaml
#    Wait for them to sync before continuing, or step 5 starts a pod with no secrets:
kubectl --context "$CTX" -n "$NS" get externalsecret -w

# 4. Deployment  (replicas: 1, strategy: Recreate)
#    NOTE: there is no backup CronJob. It was removed on 2026-08-19 by request.
#    The data volume is ReadWriteOnce and is not backed up by this repository — losing the PV loses
#    users, grants and conversation history. The registry, runbooks and config
#    all live in git, so capability survives; only user data does not.
kubectl --context "$CTX" apply -f deploy/04-deployment.yaml

# 6. Nightly backup CronJob

# 7. Service  (ClusterIP — Pomerium fronts it)
kubectl --context "$CTX" apply -f deploy/06-service.yaml
```

Steps 1–7 are each a separate approval under the production rules. Prior approval
for one does **not** carry to the next.

### Backup before re-applying

For a first install there is nothing to back up. For any **subsequent** apply,
capture current state first:

```bash
mkdir -p ~/infra-backups
for kind in deployment/infragpt service/infragpt pvc/infragpt-data \
            sa/infragpt role/infragpt-read; do
  name="$(echo "$kind" | tr '/' '-')"
  kubectl --context "$CTX" -n "$NS" get "$kind" -o yaml \
    > ~/infra-backups/prod-${name}-$(date +%Y%m%d-%H%M%S).yaml
done
```

Verify each file is non-empty before proceeding.

## Verify after applying

```bash
# Pod is running and ready
kubectl --context "$CTX" -n "$NS" get pods -l app.kubernetes.io/name=infragpt

# READ-ONLY PROOF — both of these MUST be denied.
# This is the verification step from the plan: it proves enforcement at the
# credential layer, not just in our own code.
kubectl --context "$CTX" -n "$NS" auth can-i delete pods \
    --as=system:serviceaccount:apps:infragpt      # expect: no
kubectl --context "$CTX" -n "$NS" auth can-i create deployments \
    --as=system:serviceaccount:apps:infragpt      # expect: no

# And these MUST be allowed.
kubectl --context "$CTX" -n "$NS" auth can-i get pods/log \
    --as=system:serviceaccount:apps:infragpt      # expect: yes
kubectl --context "$CTX" auth can-i list nodes \
    --as=system:serviceaccount:apps:infragpt      # expect: yes
```

If either "must be denied" check returns `yes`, **stop** — the RBAC is wider than
intended and the credential-layer guarantee does not hold.

Separately, prove the Postgres side by attempting a write as `infragpt_ro` and
confirming Postgres refuses it. Application-layer checks are not evidence here;
only the database refusing is.

## Test the restore before you rely on it

An untested restore procedure is a hope, not a control. Do this once, into a
scratch location, and confirm users and grants survive:

```bash
INFRAGPT_DATA=/tmp/restore-test ./scripts/restore.sh gs://<bucket>/infragpt/<timestamp>/
```

## What is in each file

| File | Contents | Note |
|---|---|---|
| `01-serviceaccount-rbac.yaml` | SA, Role, RoleBinding, ClusterRole, ClusterRoleBinding | **The real read-only enforcement.** get/list/watch only. No `pods/exec`. |
| `02-pvc.yaml` | 20Gi RWO PVC | Single replica, no HA — an accepted risk in the plan |
| `03-externalsecrets.yaml` | Grid key, PG password, Redis passwords, kubeconfig, backup bucket | **Stubs.** No secret values in git, ever |
| `04-deployment.yaml` | Deployment | `replicas: 1`, `strategy: Recreate` — both required by RWO + SQLite |
| `06-service.yaml` | ClusterIP | Pomerium fronts it; never expose directly |

## Things that are deliberately absent

- **Writer database endpoints.** Not in the config, not in the env, not
  reachable. This is how "no mutation path" stays true under a code change that
  forgets about it.
- **`pods/exec` and `pods/portforward`.** Exec is a shell into a production pod.
- **`replicas: 2`.** RWO + SQLite means a second replica cannot schedule. Moving
  storage to Postgres is the prerequisite, not a flag change.
- **An Ingress.** Pomerium owns routing; adding one here would create a second,
  unauthenticated path to the same service.

## Cloud control-plane surfaces (added 2026-08-18)

`cloud:gcp` and `cloud:aws` reach GCP Monitoring / AlloyDB Admin and AWS
CloudWatch / ElastiCache. These are **public API endpoints with IAM auth**, so
they work with no VPC route — which is the point: they still answer during an
incident where the VPC path is what is broken.

Grant the absolute minimum, because the credential is the real enforcement:

| Cloud | Identity | Roles — nothing more |
|---|---|---|
| GCP | Workload Identity SA | `roles/monitoring.viewer`, `roles/alloydb.viewer` |
| AWS | IAM user/role in `infragpt-cloud` secret | `CloudWatchReadOnlyAccess`, `AmazonElastiCacheReadOnlyAccess` |

Both env groups are marked `optional: true`, so the pod starts without them and
the cloud surfaces simply report a clear "credentials not set" error rather than
the deployment failing. Grant `cloud:gcp` / `cloud:aws` to users separately.

**Note on the AlloyDB API version:** pinned to `v1beta` deliberately. The
read-pool autoscaler block and the live `nodes` array are hidden from `v1`, and
`v1`'s `nodeCount` is the autoscaler *floor* — reading it as the live node count
produces wildly wrong per-node arithmetic.
