---
name: Data not reaching Postgres (drainer and KV write paths)
surfaces: [metrics, k8s:gcp, k8s:aws, db:read, logs]
functions: [drainer_throughput, drainer_stopped, drainer_lag, producer_throughput, pod_status, pod_logs, recent_events, logs_search]
keywords: ["drainer", "not processing", "data missing", "not in database", "stale data", "kv", "redis to postgres", "lag", "backlog", "writes missing", "drainer stopped"]
owner: infra
reviewed_on: 2026-08-19
---

Writes go to Redis first; the drainer moves them to Postgres. When that pipeline
stops, **the application keeps working normally** and the database quietly stops
receiving writes. That is what makes this class dangerous: nothing looks broken
until someone reads the database and finds old data.

Reach for this runbook whenever a write is missing from Postgres but the app
behaved as if it succeeded.

## Order

1. **`drainer_stopped`** — non-zero means the drainer reports itself stopped.
   Direct answer to "is it running".
2. **`drainer_throughput`** — flat or zero means it is not processing. Together with
   the above these separate three states that look identical from the database:
   - stopped != 0 → it is down, and Postgres is falling behind right now;
   - stopped = 0, throughput = 0 → it is up with nothing to do, so look **upstream**
     at the producer;
   - stopped = 0, throughput > 0 → it is working, so the missing write never
     entered the pipeline.
3. **`producer_throughput`** — a flat producer starves everything downstream. An
   idle consumer and a stuck one look the same from below, so check this before
   concluding the drainer is at fault.
4. **`drainer_lag`** — p99 queue latency. Rising lag *with* healthy throughput is a
   capacity problem (more arriving than can be cleared), not a fault.

**The two sides are separate drainers with separate counters.** The rider/customer
side and the driver side fail independently. One being healthy says nothing about
the other, and every answer must say which side was checked.

## When the drainer is healthy and the row is still missing

Then the write never went through the drainer, and the question becomes which path
it took. Two independent settings decide that, and they are routinely confused:

- One setting lists tables the **application** must write directly to the database,
  bypassing KV entirely. It is read from a config row in the database and refreshed
  periodically.
- A different setting lists tables the **drainer** should skip when writing to the
  database. It comes from the drainer's own startup configuration and is **not**
  refreshed while it runs.

Separately, a per-service flag decides whether a KV write *also* issues a direct
database update. It is set per deployment, and services that ought to match often
do not — a known case had one service unset while its sibling had it enabled, in
both clouds, producing direct database writes nobody expected.

The useful read-only tell: a direct `UPDATE ... RETURNING <every column>` comes from
the application's KV connector. The drainer emits a bare `UPDATE` with no
`RETURNING`. If you can see the statement shape, you know which wrote it.

## Traps

- **Zero is ambiguous.** A stopped drainer and an idle one both read as zero
  throughput. Never report "the drainer is down" from the throughput metric alone.
- **Use a wide window.** A 5m window on a bursty pipeline shows gaps that mean
  nothing. Use 1h or more before calling a drainer stopped.
- **Per-deployment flags drift.** Two services doing the same job may take different
  write paths because one deployment is missing an environment flag. When behaviour
  differs between services that should match, suspect configuration before code.
- Checking this in one cloud tells you nothing about the other.
