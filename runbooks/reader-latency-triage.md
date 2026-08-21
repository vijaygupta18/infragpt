---
name: AlloyDB reader latency triage
surfaces: [db:read]
functions: [long_running_queries, table_indexes, index_usage, unused_indexes, seq_scan_heavy_tables, active_connections, cache_hit_ratio, pg_settings_key, installed_extensions, oldest_transaction_age]
keywords: ["reader slow", "database slow", "high latency", "db latency", "query slow", "cpu high database", "0dc", "reader wedged", "work_mem", "max_connections", "shared_buffers", "postgres settings", "statement_timeout", "extensions", "pg_stat_statements", "wraparound", "xid age", "vacuum horizon", "idle in transaction"]
owner: infra
reviewed_on: 2026-08-18
---

Reader latency here has repeatedly turned out to be a **missing index**,
not insufficient capacity. Scaling the reader first hides the cause and costs money.

## No historical query statistics are available

`pg_stat_statements` is **not installed** on these databases, and AlloyDB's
`g_agg_stat_statements` requires the columnar engine, which is not loaded. So
there is no way to ask "what was slow an hour ago". Diagnosis has to be *live* or
*structural*. Say this plainly rather than implying the data was checked.

## Order of investigation

1. `long_running_queries` — live from `pg_stat_activity`. Anything running far
   longer than its peers is the first suspect. This only sees queries running
   **right now**, so during an active incident run it repeatedly.
2. `active_connections` — if connections are pinned near the ceiling, latency is
   pool exhaustion rather than any single query. Note the active/idle split, and
   watch for `idle in transaction`, which holds both a connection and its locks.
3. `seq_scan_heavy_tables` — a large table with high sequential scans and low
   index scans is the structural signature of a missing index. This is the most
   reliable substitute for query stats.
4. `table_indexes` on the suspect table — check whether an index exists on the
   filtered or joined columns.
5. `cache_hit_ratio` — a ratio that has dropped sharply points at a working set
   that no longer fits, which is a sizing problem rather than an index one.

## Index-usage stats are per node

`index_usage` and `unused_indexes` read replica-local counters. On the driver
reader, 348 of 540 indexes showed zero scans — that reflects what *this replica*
serves, not what the cluster needs. Never present a zero-scan index as a removal
candidate from reader data alone; the writer would have to be checked too.

AlloyDB's `google_db_advisor_recommended_indexes_to_drop` view illustrates the
trap: it listed 534 of ~540 indexes, because it has no workload signal. Do not
use it.

## Known history

- A missing index on a payment-customer lookup caused a ~685x slowdown.
- A ride-table index identified during a previous incident is still outstanding.
- Connections pin per node on AlloyDB autoscale, so adding a node does not
  rebalance existing connections — new capacity only helps new connections.

## What this runbook cannot do

The database surface exposes schema and performance metadata only. It cannot look
up a specific driver, rider, ride or payment. If the question needs a business row,
say so rather than substituting a metadata answer.

## Configuration, before blaming load

`pg_settings_key` returns the settings that actually matter here — memory,
timeouts, autovacuum, standby behaviour and `shared_preload_libraries`.

- `setting` is in the units of the `unit` column, **not bytes**. `shared_buffers`
  comes back in 8kB blocks and `work_mem` in kB; a number quoted without its unit
  is how 16384 gets read as 16KB when it is 128MB.
- These are **this replica's** settings only. The writer and the other replicas
  are configured independently, so this cannot answer "what is `max_connections`
  on the primary".
- `shared_preload_libraries` is where you confirm `pg_stat_statements` is absent,
  which is why this registry has no historical query-statistics function at all.
  `installed_extensions` covers the other half: installed is not the same as
  loaded, and an extension row is necessary but not sufficient.

## Long transactions and the vacuum horizon

`oldest_transaction_age` returns two different kinds of number and they must not
be blended:

- `max_datfrozenxid_age` is **replicated**, so it describes the cluster and is
  trustworthy from a reader. Compare it against `autovacuum_freeze_max_age` (from
  `pg_settings_key`) and the 2-billion hard limit — the raw number without one of
  those denominators means nothing.
- The open-transaction rows come from `pg_stat_activity`, which is **per node**.
  These are this replica's own sessions; a long transaction on the writer does not
  appear here at all.
- With `hot_standby_feedback` on, a long read here genuinely does pin the
  primary's vacuum horizon and can be why autovacuum is not reclaiming space
  cluster-wide. With it off, the same query gets cancelled instead. Read the
  setting before assigning blame.
