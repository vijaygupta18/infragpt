---
name: Stuck node drain, cluster upgrade or scale-down
surfaces: [k8s:gcp, k8s:aws]
functions: [list_pdb, list_nodes, describe_node, node_top, top_pods, list_pods, recent_events, list_pvc, list_hpa]
keywords: ["drain", "cordon", "upgrade", "eks upgrade", "node upgrade", "scale down", "autoscaler", "pdb", "poddisruptionbudget", "disruption", "node not draining", "stuck upgrade", "evict", "node pressure", "schedulingdisabled", "taint"]
owner: infra
reviewed_on: 2026-08-18
---

A drain, cluster upgrade or autoscaler scale-down that stalls almost never
reports itself as an error. Nothing is unhealthy — something is simply **not
allowed to move**.

1. `list_pdb` — first, always. **ALLOWED DISRUPTIONS = 0** means the budget is
   currently blocking every voluntary eviction of its pods. A past EKS upgrade
   here was blocked by five PDBs and nothing else in the cluster looked wrong.
2. `list_nodes` — find nodes showing `Ready,SchedulingDisabled` (cordoned) and
   look for **mixed VERSION values**, which mean a partially completed upgrade.
3. `describe_node` — taints and conditions (MemoryPressure, DiskPressure,
   PIDPressure) plus the pods still resident on the node being drained.
4. `list_pods` / `recent_events` — the pods that will not move, and why. Evictions
   blocked by a PDB appear as repeated `FailedEviction`-shaped events.
5. `node_top` and `top_pods` — whether the remaining nodes can actually absorb
   the pods once they do move.
6. `list_pvc` — an RWO claim binds to one node, so an RWO-backed pod cannot be
   rescheduled anywhere its volume is not attached.

## Interpretation notes

- A PDB whose `minAvailable` equals the replica count, or whose selector matches
  no pods, blocks drains **permanently**, not temporarily. Waiting will not help.
- `describe_node` "Allocated resources" is **requests and limits, not usage**.
  Scheduling is decided on requests; saturation is decided on usage. Read it with
  `node_top` and never quote one as the other.
- Ready does not mean schedulable: a Ready node can still repel pods via taints,
  which `list_nodes` does not show.
- `list_hpa` matters here because a drain during a scale-up fights the HPA. An
  HPA sitting at MAXPODS has no headroom to replace the capacity you are draining.
- State which cloud. GKE and EKS upgrade independently and the blocking PDB is
  usually in only one of them.
