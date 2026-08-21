# Identities for infragpt

Everything here is a **production write**. Nothing in this directory has been run.
Review, then run them yourself.

The read-only identity is not one control among several — it is *the* control. The
registry, the parameter validation and the command guard all reduce blast radius
and make misuse visible, but only the credential makes mutation impossible. If a
guard is bypassed, or a prompt injection steers a tool call, or someone approves a
command they should not have, this layer is what is still standing.

So the rule for every grant below: **if a role would let the pod change anything,
it does not go on.**

---

## What exists already (verified 2026-08-18)

| Thing | Status |
|---|---|
| GKE Workload Identity pool | ✅ `<GCP_PROJECT>.svc.id.goog` |
| EKS OIDC issuer | ✅ `oidc.eks.<AWS_REGION>.amazonaws.com/id/<EKS_OIDC_ID>` |
| AlloyDB read-only role | ✅ `<READONLY_DB_USER>` — no CREATE ROLE needed |
| ClickHouse read-only user | ✅ `<CLICKHOUSE_RO_USER>` |
| `infragpt` GCP service account | ❌ create it (`gcp.sh`) |
| `infragpt` AWS IAM role | ❌ create it (`aws.sh`) |
| Redis read-only credential | ❌ **see the gap below** |

---

## 1. GCP — `gcp.sh`

Creates `infragpt@<GCP_PROJECT>.iam.gserviceaccount.com` and binds it to the
Kubernetes ServiceAccount `apps/infragpt` through Workload Identity, so there
is **no key file anywhere**. A key file on a PV is a credential that can walk out
of the cluster; a Workload Identity binding cannot.

| Role | Why |
|---|---|
| `roles/monitoring.viewer` | Cloud Monitoring — every metric, all clouds' worth of AlloyDB/GKE/Memorystore/LB/NAT data |
| `roles/alloydb.viewer` | AlloyDB instance inventory and live node counts |
| `roles/container.clusterViewer` | GKE cluster and node-pool metadata **only** |
| `roles/redis.viewer` | Memorystore instance metadata |
| `roles/logging.viewer` | Cloud Logging reads |

Every one is read-only. There is deliberately no `*.admin`, no `*.editor`, and no
`roles/iam.serviceAccountTokenCreator` — that last one looks harmless and is how
an identity escalates into other identities.

**Note `container.clusterViewer`, not `container.viewer`.** Verified 2026-08-18:
`container.viewer` includes `container.configMaps.get` and
`container.configMaps.list`, so granting it would hand back ConfigMap read across
every cluster in the project — silently undoing the ConfigMap exclusion in
`../01-serviceaccount-rbac.yaml`, whose values may carry credentials. An
IAM grant that re-opens what Kubernetes RBAC closed is the worst kind of hole,
because the RBAC file still reads as though it were shut. `clusterViewer` is
exactly `clusters.get`, `clusters.list`, `projects.get/list` and nothing else.

## Where pod and pod-log access actually comes from

Not from IAM. `infragpt` reads pods and pod logs through the **in-cluster
Kubernetes ServiceAccount** in `../01-serviceaccount-rbac.yaml`
(`get`/`list`/`watch` on `pods`, `pods/log`, `events`, `services`, `deployments`,
`nodes`, plus metrics). That file is the single place that defines what the pod
can see inside a cluster, which is why it must not be duplicated or widened from
the IAM side.

## 2. AWS — `aws.sh`

Creates an IAM role assumable only by the Kubernetes ServiceAccount
`apps/infragpt` via the EKS OIDC provider (IRSA), with:

- `CloudWatchReadOnlyAccess`
- `AmazonElastiCacheReadOnlyAccess`

The trust policy pins **both** `:sub` (this exact ServiceAccount) and `:aud`. A
trust policy that pins only the OIDC provider can be assumed by *any* pod in the
cluster, which quietly turns a scoped role into a cluster-wide one.

Note this covers the AWS *APIs*. For `kubectl` against EKS you also need an EKS
access entry mapping the role to a read-only Kubernetes group — that part is
Kubernetes RBAC, and `../01-serviceaccount-rbac.yaml` is the policy it should map
to. As the migration to GCP-only progresses this becomes less relevant.

---

## 🔴 3. Redis — the one real gap

**There is currently no read-only Redis credential.** Redis AUTH is a single
shared password with full privileges: the same credential that reads a key can
run `FLUSHALL`.

That means for Redis, and Redis alone, the "credentials are the backstop"
principle does **not** hold. The only thing preventing a write is our own
allowlist — the executor's `redis_op` allowlist plus the shell guard. Those are
layers we control and could get wrong, which is exactly the situation every other
surface avoids.

The fix is a Redis 6+ ACL user, e.g.:

```
ACL SETUSER infragpt on >'<password>' ~* &* +@read +info -@dangerous
```

Then a `FLUSHALL` fails at the server even if every guard above it fails.

Two caveats before you plan this:

- **Check your Redis version and whether ACLs are enabled** on both Memorystore
  and ElastiCache. Managed Redis does not always expose `ACL SETUSER`; on
  Memorystore in particular, support depends on the tier and version.
- `ACL SETUSER` is itself a **write to Redis** and needs the usual approval.

Until that exists, treat the `redis:read` grant as protected by application logic
rather than by credentials, and weigh that when deciding who gets it.

---

## Order

1. `bash gcp.sh` — creates the GCP SA and bindings
2. `bash aws.sh` — creates the AWS role and trust
3. Apply `../01-serviceaccount-rbac.yaml` (annotate the KSA with both identities —
   the scripts print the exact annotations)
4. Redis ACL user, if and when the managed services support it

Each script prints what it will do and asks for confirmation before any mutation.
