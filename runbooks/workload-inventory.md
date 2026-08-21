---
name: Workload, service and config inventory
surfaces: [k8s:gcp, k8s:aws]
functions: [list_services, list_statefulsets, list_daemonsets, list_cronjobs, list_namespaces, describe_deployment, deployment_status, list_pods]
keywords: ["what services", "list services", "statefulset", "daemonset", "cronjob", "scheduled job", "job did not run", "configmap", "namespaces", "what is deployed", "which version", "image", "rollout finished", "inventory"]
owner: infra
reviewed_on: 2026-08-18
---

"What exists, and what version is it" questions, plus the two failure modes that
look like nothing at all: a suspended CronJob and a rollout that only appears to
have finished.

- `list_services` — services, types, ports and selectors. A ClusterIP proves
  nothing: a Service whose selector matches no Ready pod has zero endpoints and
  blackholes silently. Cross-check with `list_pods`.
- `list_statefulsets` — ordered rollouts stop at the first pod that never becomes
  Ready, so a partially-updated StatefulSet is **stuck, not slow**.
- `list_daemonsets` — DESIRED is derived from matching nodes, so a falling desired
  count is a node-pool change, not a DaemonSet failure.
- `list_cronjobs` — **SUSPEND=True means it has not run and will not run**, with
  no error anywhere. LAST SCHEDULE is when a run *started*, never whether it
  succeeded. Schedules use the CronJob's timeZone (UTC when unset), not IST.
- `describe_deployment` — strategy, conditions, the new ReplicaSet and recent
  scaling events, when `deployment_status` gives counts but not the reason.
- `list_namespaces` — cluster-wide. Only `apps` is readable by this tool; a
  namespace listed here still cannot have its pods or logs inspected.

## ConfigMaps: names only, permanently

`` returns **names and nothing else**. ConfigMap values at the platform may carry credentials and connection strings that were never labelled
as secrets but function as them, so this surface never emits a value. If a
question needs a config *value*, this tool cannot answer it — say so rather than
inferring the value from context.

There is deliberately **no Secret entry at all**, not even names-only, and none
should be added.

## Interpretation notes

- A deployment's `Available` condition can be True while the newest ReplicaSet has
  zero ready pods, because the old ReplicaSet is still serving. Check the
  Progressing condition and the NewReplicaSet line before calling a rollout done.
- Compare images across both clouds. A version present in one cluster and not the
  other is a partial rollout and explains "it works for some users".

## ConfigMaps are unreachable, deliberately

There is no ConfigMap function and there will not be one. `list` returns whole
ConfigMap objects including `data`, so a "names only" entry would be protected
solely by its output flag never changing — and ConfigMap values here routinely
carry credentials and connection strings. ConfigMaps were therefore removed from
the ServiceAccount RBAC entirely, which is the layer that cannot be argued with.

If a question needs a ConfigMap value, say it is out of scope and that a human
must read it directly. Do not substitute a related answer.
