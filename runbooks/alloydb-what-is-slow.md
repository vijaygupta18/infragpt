---
name: AlloyDB — what is slow, and what cannot be asked
surfaces: [db:read, cloud:gcp, metrics]
functions: [long_running_queries, active_connections, locks, seq_scan_heavy_tables, unused_indexes, table_indexes, replication_lag, cache_hit_ratio, db_query, alloydb_instances, alloydb_connections, alloydb_cpu]
keywords: ["slow query", "what is slow", "database slow", "reader slow", "top queries", "pg_stat_statements", "query stats", "alloydb", "read pool", "nodes", "connection limit", "cpu"]
owner: infra
reviewed_on: 2026-08-19
---

Two things about this environment change how the question must be answered. Both
have produced confidently wrong answers before.

## 1. There IS query history — via Query Insights, not Postgres

**Corrected 2026-08-20.** This runbook previously said per-query attribution was
impossible here. That was wrong, and it was stopping the tool from answering a
question it could answer.

`query_insights_top` returns the top queries by execution time, with the SQL,
over a window — the same thing `pg_stat_statements` would give you. AlloyDB
Query Insights is on by default and had been recording it all along; the earlier
attempts returned nothing because the generic metric reader aggregates the wrong
way for a per-query DELTA metric. Verified with a top query at 11,260 seconds of
execution time in one hour.

Use `query_insights_top` FIRST for any "what is slow / what is burning CPU"
question. `query_insights_io` for disk-bound work, `query_insights_locks` for
lock waits, which are invisible to every other metric here.

The totals are summed across executions, so a high row may be moderately slow
and very frequent. `long_running_queries` still answers "what is slow right
now"; Query Insights answers "what consumed the most time".

## 2. What Postgres itself cannot tell you

`pg_stat_statements` is **not installed** — not on the readers and **not on the
writer** — so nothing inside Postgres can answer it. Use Query Insights above
instead of concluding the question is unanswerable. AlloyDB's own aggregate equivalent errors out because the module it needs
is not loaded. Enabling either requires a restart, which is a production change.

So "what was slow an hour ago" cannot be answered **from inside Postgres** — but
it CAN be answered, from Query Insights above. Do not repeat the old conclusion
that the question is unanswerable; that sentence used to be here and it was
wrong.

The three views, and what each is for:

- **Historical**: `query_insights_top` / `_io` / `_locks` — what consumed the
  most time over a window, with the SQL. Start here.
- **Live**: `long_running_queries`, `active_connections`, `locks` — what is
  running *right now*. Nothing in Postgres retains this.
- **Structural**: `seq_scan_heavy_tables`, `unused_indexes`, `table_indexes` —
  which tables are shaped to be slow regardless of when. Survives the incident,
  and is often the durable fix.

## 3. Every `pg_stat_*` number is PER NODE

The readers are physical replicas — `pg_is_in_recovery()` is true, so writes are not
merely denied, they are impossible. Each node keeps its own counters and your
session lands on one of them.

Consequences that must appear in any answer:

- A `seq_scan` or `idx_scan` count describes **that replica**, not the cluster. Two
  runs can return different numbers with nothing having changed.
- **Do not divide `total_connections` by `connections_limit`.** The total is across
  live nodes; the limit is per node. That division once produced "143% of the
  connection limit", which was arithmetic, not a finding. Get the live node count
  first and compare per node.
- **`readPoolConfig.nodeCount` is the autoscaler FLOOR, not the live count.** Reading
  it as the current size once produced "1 node" when there were 13. Always get the
  live count from the instance view before saying anything about capacity.
- Read-pool size moves on its own. A single reading is not a standing condition —
  "the pool is pegged" needs two readings, not one.

## Order for "the database is slow"

1. `replication_lag` and `cache_hit_ratio` — cheap, and they rule out the two
   conditions that make everything else look slow.
2. `active_connections` — a plateau at the ceiling means requests are queuing for a
   connection, and the database is the victim rather than the cause.
3. `long_running_queries` — live offenders, if any are running *now*.
4. `seq_scan_heavy_tables` → `table_indexes` on the worst one → `unused_indexes`.
   This is the durable answer: a missing index is still missing tomorrow.
5. `alloydb_cpu` / `alloydb_connections` for the cluster view, remembering the
   per-node caveats above.

## Heavy reads belong on the non-critical pool

The critical driver reader sits in the path of drivers going online. Anything
scan-heavy — a free-form catalogue query, a wide statistics view — should go to the
non-critical pool instead. `db_query` offers it as `driver_noncrit` and it should be
the default choice; use the critical reader only when the question is specifically
about *that* reader's own state.
