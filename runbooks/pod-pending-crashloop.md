---
name: Pod pending or crashlooping
surfaces: [k8s:gcp, k8s:aws]
functions: [pod_status, list_pods, recent_events, describe_pod, pod_logs, node_top, deployment_status, top_pods, list_pvc, list_hpa, describe_node, list_nodes]
keywords: ["pod pending", "crashloop", "crashloopbackoff", "not starting", "pod restarting", "deployment stuck", "pods not ready", "imagepullbackoff", "oomkilled", "out of memory", "pvc pending", "volume", "hpa", "autoscaler", "node full", "insufficient cpu", "insufficient memory"]
owner: infra
reviewed_on: 2026-08-18
---

## Pending

A pod stuck Pending is a **scheduling** problem, not an application one. Do not
read application logs — there are none yet.

1. `recent_events` for the namespace. The scheduler states its reason plainly
   (insufficient cpu/memory, no matching toleration, unbound PVC, node affinity).
2. `node_top` — if the cluster genuinely has no room, that is a capacity answer.
3. `describe_pod` — compare the pod's tolerations against the node taints.

**Check the taint key spelling.** A deployment here sat Pending for 149
days because it tolerated `node-type` while the nodes were tainted `service-type`.
Nothing alerted, because Pending is not Failed. If a pod has been Pending for more
than a few minutes, report the age prominently — a long-Pending pod is usually a
typo nobody has looked at, not a transient.

## CrashLoopBackOff

1. `pod_logs` with `--previous` semantics if available — the current container may
   be too young to have logged the cause.
2. `recent_events` — OOMKilled shows here rather than in the logs.
3. `describe_pod` — check the last termination reason and exit code.

Common causes seen here: missing or misnamed config/secret, a config pointing at a
decommissioned host, and OOM after a memory-limit change.

## Always state the cloud

`cloud` is required on every one of these functions. AWS and GCP run different
workload sets, and the same service name exists in both.

## Additional checks

- `top_pods` — live per-pod CPU and memory in the namespace. These are
  **instantaneous usage values, not requests or limits**: usage alone cannot tell
  you how close a pod is to OOMKill, so read the limit from `describe_pod`
  alongside it. An error here is a metrics-server problem, not evidence the pods
  are idle.
- `list_pvc` — a Pending PVC holds its pod Pending indefinitely, and CAPACITY is
  the *provisioned* size, never usage, so this cannot show a full volume. An RWO
  claim binds to one node, so a second replica of an RWO-backed workload will
  never schedule anywhere.
- `list_nodes` / `describe_node` — for Pending pods, the answer is usually here:
  taints, `SchedulingDisabled`, or pressure conditions. "Allocated resources" in
  `describe_node` is **requests, not usage**; scheduling is decided on requests
  and saturation on usage, so pair it with `node_top`.
- `list_hpa` — TARGETS showing `<unknown>` means the HPA has no metric and is not
  scaling at all, which is a broken autoscaler rather than a quiet one. Replicas
  pinned at MAXPODS means there is no headroom left for it to help.
