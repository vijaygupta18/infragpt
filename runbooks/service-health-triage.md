---
name: Service health and error-rate triage
surfaces: [metrics]
functions: [service_error_rate, service_latency_p99, pod_restarts, cpu_saturation, memory_saturation, db_connection_count]
keywords: ["errors", "error rate", "5xx", "latency", "slow api", "p99", "spike", "saturation", "service unhealthy", "restarts"]
owner: infra
reviewed_on: 2026-08-13
---

Start from metrics, not logs. Logs tell you what one instance did; metrics tell you
whether the problem is one instance, one cloud, or everything.

1. `service_error_rate` — establish that there is an actual deviation and when it
   started. "When did it start" is the most useful single fact in an incident.
2. `service_latency_p99` — latency rising while error rate is flat points at a
   downstream dependency (usually the database) rather than the service itself.
3. `db_connection_count` — a plateau at the pool ceiling means requests are queuing
   for connections; the service is the victim, not the cause.
4. `cpu_saturation` / `memory_saturation` — distinguish a real capacity limit from
   a dependency stall. A saturated CPU with flat latency is fine; flat CPU with
   rising latency means the service is waiting on something.
5. `pod_restarts` — restarts coinciding with the onset means a crash loop is
   driving the errors rather than resulting from them.

## Interpretation notes

- Compare both clouds before concluding. A regression present in only one cloud
  usually means a partial rollout, which is a deployment problem rather than a
  code one.
- A morning-surge-only regression will not reproduce off-peak. If the data shows a
  time-of-day pattern, say so explicitly — that shape has previously indicated a
  connection-reuse regression that only appeared under real load.
