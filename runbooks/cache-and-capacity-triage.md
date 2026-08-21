---
name: Cache and database capacity triage (cloud APIs)
surfaces: [cloud:gcp, cloud:aws]
functions: [alloydb_instances, alloydb_connections, alloydb_connection_limit, alloydb_cpu, alloydb_memory_available, alloydb_replication_lag, alloydb_backends_by_state, elasticache_instances, elasticache_connections, elasticache_cpu, elasticache_memory, elasticache_evictions, elasticache_replication_lag, alloydb_disk_usage, elasticache_network_bytes_in, elasticache_network_bytes_out, elasticache_cache_hits, elasticache_cache_misses, elasticache_swap_usage]
keywords: ["connection limit", "near capacity", "connections", "capacity", "headroom", "evictions", "memory pressure", "cache full", "autoscale", "node count", "scaling", "redis memory", "database cpu", "storage", "disk usage", "cluster storage", "hit ratio", "cache hit rate", "cache misses", "swap", "network bytes", "bandwidth"]
owner: infra
reviewed_on: 2026-08-18
---

These functions use the **cloud control-plane APIs**, which are public endpoints
with IAM auth. They work with no VPC route — so they still answer during an
incident where the VPC path is itself what is broken, unlike the `sql` and
`redis` surfaces.

## AlloyDB: never quote a percentage without the node count

Read-pool metrics are **totals across all live nodes**, while
`alloydb_connection_limit` is **per node**. So:

    utilisation = total_connections / (limit_per_node * live_nodes)

Always call `alloydb_instances` first and use its `live_nodes`. Getting this
wrong is not a small error: 1432 connections over 20 nodes against a 1000
per-node limit is ~7%, but read naively it looks like 143% and reads as an
emergency.

`autoscale_floor` (what the v1 API calls `nodeCount`) is the scale-in floor, NOT
the live count. Only the live `nodes` array gives the current number.

## The capacity question that actually matters

`at_autoscale_ceiling` is the signal to lead with. A pool sitting at its
`autoscale_max` has **no headroom left to scale out**, regardless of how healthy
its current CPU looks. Report that prominently.

A pool pegged at its ceiling while CPU is *below* the autoscaler target is worth
calling out as an anomaly: it should be scaling in and isn't. A known cause here
is that connections pin to a node at open time and never migrate, so nodes cannot
drain. Present that as a candidate explanation, not a conclusion.

## ElastiCache

- `elasticache_instances` first — it gives the valid cluster ids. Do not guess ids.
- `elasticache_memory` alone means little: a cache is *supposed* to fill up. Pair
  it with `elasticache_evictions`. High memory **with** evictions means the
  working set no longer fits; high memory with zero evictions is normal.
- Prefer `elasticache_cpu` (EngineCPUUtilization) over host CPU — the engine is
  effectively single-threaded, so host CPU can look calm while the engine is pinned.
- `elasticache_replication_lag` is meaningful only on replicas. A primary reports
  zero or nothing, which is not the same as "healthy".

## Cloud separation

AWS and GCP caches are different, never-replicated keyspaces. Never present an
AWS figure as though it described GCP, or vice versa, and always say which cloud
a number came from.

## Storage growth (GCP)

`alloydb_disk_usage` reports billable storage per **cluster**, in bytes. Two
things it cannot do, both of which are tempting:

- It is **cluster-scoped**, so it cannot be attributed to a primary, a read pool,
  or a node. Never pair it with a per-instance number as if they described the
  same object.
- AlloyDB storage is elastic with **no provisioned disk size**, so there is no
  denominator: "percent full" and "N GB remaining" are not expressible. Report the
  absolute figure and its growth rate, and use a window of `1h` or longer — over
  `15m` storage is a flat line that says nothing.

## Cache effectiveness and node limits (AWS)

- `elasticache_cache_hits` **and** `elasticache_cache_misses` over the same
  window — never one alone. The ratio is hits / (hits + misses), and a hit count
  by itself invites "hits are high, we're fine" when misses are higher still.
- A miss is **not** an eviction. Rising misses *with* `elasticache_evictions`
  means the working set no longer fits. Rising misses with zero evictions means
  keys expired or were never written — different problem, different fix.
- `elasticache_network_bytes_in` / `_out` when the cache is slow but CPU and
  memory look fine: a node can saturate its network allowance while every other
  metric stays flat. Both are **sums per period, in bytes, not rates** — divide by
  the period and state it. Outbound far exceeding inbound points at oversized
  values being read; confirm the specific key with `redis_memory_usage`.
- `elasticache_swap_usage` should be essentially zero. Any sustained non-zero
  value is serious: a swapping Redis pays disk latency on microsecond operations,
  so tens of MB is not "low". Swap rising while memory percentage still looks
  acceptable usually means reserved-memory headroom is too small for the
  copy-on-write of a background save.
