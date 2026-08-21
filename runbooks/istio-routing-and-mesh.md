---
name: Istio routing — VirtualService / DestinationRule triage
surfaces: [k8s:gcp, k8s:aws]
functions: [istio_virtualservices, istio_destinationrules, describe_virtualservice, list_services, list_pods, recent_events, describe_pod]
keywords: ["istio", "virtualservice", "destinationrule", "mesh", "503", "no healthy upstream", "routing", "gateway", "subset", "traffic split", "canary", "envoy", "sidecar", "blackhole", "traffic not reaching"]
owner: infra
reviewed_on: 2026-08-18
---

Reach for this runbook when the workload looks **healthy and traffic still fails**:
pods Running and Ready, deployment fully rolled out, no restarts, no events — and
requests 503 or land on the wrong version. That shape is almost always mesh
routing, and it is invisible to every pod-level check.

This gap caused a real outage here: a gateway VirtualService pinned external
traffic to a DestinationRule subset, and nothing in this tool could see it.

1. `istio_virtualservices` — cluster-wide, so gateway VirtualServices in
   `istio-system` are included. Look for **two VirtualServices claiming the same
   host**; that is the usual cause of "my change had no effect".
2. `istio_destinationrules` — cluster-wide. Collect the subset names each rule
   defines for the affected host.
3. `describe_virtualservice` — the only entry that shows route rules, subsets and
   weights. Only `apps` is reachable, so a gateway VirtualService can be listed
   but not described; say so rather than implying it does not exist.
4. `list_services` then `list_pods` — confirm the destination Service exists and
   that pods matching its selector are Ready. A Service with zero endpoints
   blackholes exactly like a bad subset, and the two are easy to confuse.

## Interpretation notes

- A VirtualService route naming a subset that no DestinationRule defines produces
  **503 "no healthy upstream" (UH)** at the proxy — with no Kubernetes event, no
  restart and no unhealthy pod. Absence of evidence at the pod layer is the
  signature, not a reason to stop looking.
- A subset that *is* defined but whose labels select no Ready pod fails the same
  way. Check the subset labels against the actual pod labels before concluding
  routing is correct.
- **Route order matters.** The first matching `http` rule wins, so a broad early
  match shadows everything below it. A rule that "exists" is not a rule that runs.
- Traffic weights that sum to 100 across subsets are a deliberate split; a weight
  of 0 on the version you expected is a canary that was never promoted.
- Check the mesh in **both clouds** before concluding. Mesh config is deployed
  per-cluster and drifts, so a route present in GKE and absent in EKS is a
  partial rollout — which is a deployment problem, not a code one.
