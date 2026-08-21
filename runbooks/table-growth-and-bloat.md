---
name: Table growth, size and index bloat
surfaces: [db:read]
functions: [db_size, table_size, row_estimate, table_info, index_usage, unused_indexes, table_bloat_estimate, vacuum_progress, installed_extensions]
keywords: ["table size", "disk", "growing", "bloat", "storage", "how big", "row count", "index size", "unused index", "vacuum", "autovacuum", "dead tuples", "bloat estimate", "vacuum full", "reclaim space"]
owner: infra
reviewed_on: 2026-08-18
---

1. `db_size` for the overall picture, then `table_size` to find what dominates.
2. `row_estimate` rather than an exact count — this is the planner's estimate and
   is cheap. An exact count on a large table is an expensive scan and is not
   available through this tool by design.
3. `index_usage` and `unused_indexes` — indexes with zero scans cost write
   throughput and disk for nothing. They are usually the easiest reclaim, but
   confirm the index is not there to enforce a constraint before recommending a
   drop.

## Reporting

Report estimates as estimates. `row_estimate` can be significantly off on a table
with heavy churn that has not been analysed recently — say so rather than
presenting the number as exact.

Dropping an index is a **write** and is out of scope for this assistant. Report the
finding; a human decides and executes it under the normal approval process.

## Bloat, honestly

`table_bloat_estimate` is **not a bloat measurement**. Real bloat needs
`pgstattuple`, which is not installed — confirm with `installed_extensions` before
claiming otherwise. What it gives you is physical heap pages now versus the pages
recorded at the last VACUUM/ANALYZE, plus bytes per estimated row.

- A high bytes-per-row relative to the table's natural width, or a large
  `pages_grown_since_analyze`, makes a table a **candidate for investigation**. It
  is never on its own a reason to propose a `VACUUM FULL`, which takes an
  ACCESS EXCLUSIVE lock and is not something this tool should ever be used to
  justify.
- `reltuples` and `relpages` are catalogue values written by the last
  VACUUM/ANALYZE on the **writer** and physically replicated, so unlike `pg_stat_*`
  they are cluster-truthful — but only as fresh as that ANALYZE. Check
  `last_analyze` via `row_estimate` first; on a never-analysed table `reltuples`
  is -1 or 0 and bytes-per-row is meaningless.
- Wide TOAST-able columns move out of the heap, so a table full of large
  text/jsonb legitimately shows a *low* bytes-per-row.

## Vacuum

`vacuum_progress` has one trap that dominates everything else: **a read replica
does not run VACUUM**. On these reader connections it will normally return zero
rows, and zero rows means "no vacuum on this node" — not "no vacuum in the
cluster" and not "vacuum finished". Autovacuum on the writer is invisible from
here. Report the empty result as a limitation, never as reassurance.

For vacuum that is being *blocked* rather than merely unobserved, use
`oldest_transaction_age`: a long-running read on a standby with
`hot_standby_feedback` on pins the primary's vacuum horizon cluster-wide.
