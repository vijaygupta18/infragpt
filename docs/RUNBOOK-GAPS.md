# Coverage gaps

Debugging steps the production runbooks and incident history rely on that **no
current registry function can perform**. This is the roadmap, and it is kept in the
runbooks directory on purpose: when the assistant says "I cannot answer that", this
is where the reason should already be written down.

Not a bug list. Everything here is a deliberate boundary or an unbuilt capability.

Kept in `docs/` rather than `runbooks/`: everything in that directory is parsed as a
runbook and shipped into the container, so a document without runbook frontmatter
belongs outside it.

## Needs verification against live infrastructure

These are built but unproven, because they were written while the cluster was
unreachable. Each fails *silently* if wrong — an empty result reads as "healthy",
which is the worst failure mode this tool has.

1. **MCP tool names.** Every entry in `registry/mcp.yaml` was a guess. Mitigated by
   `mcp_tool_aliases` — the executor now retries under reviewed alternate names
   when a call fails as an unknown tool — but the *primary* names are still
   unconfirmed. Verify with `tools/list` against each server, then promote whichever
   name is real.
2. **Istio label values.** `destination_workload` and `response_code` are confirmed
   from production usage; `request_operation` and `request_protocol` (used by
   `api_error_routes`) are not. If that entry returns one `unknown` bucket, the mesh
   is not labelling routes and the entry should be dropped rather than left to
   mislead.
3. **`db:entity` column names.** Taken from the Beam schemas in the backend repo,
   not from the deployed tables. A column that exists in Haskell but not in
   production will fail the whole lookup.
4. **ClickHouse table and column names.** The schema-introspection entries are safe;
   any assumption about *which* tables hold rides or logs is not.
5. **Log index and field names.** `istio-*` for access logs and `request_id` /
   `x_request_id` are recorded in production knowledge but unverified here.

## Missing capabilities

6. **No trace backend.** The request-id chain reconstructs a trace from logs. Where
   distributed tracing exists, a real trace would be faster and more complete.
7. **No code lookup from a stack trace.** The established flow ends at "find the
   handler in the backend repo", which needs a code-search surface this tool does
   not have. Today it stops at the error text.
8. **Cannot inspect KV/drainer config directly.** The runbooks reason about
   `disableForKV`, `dontEnableForDb` and per-service recaching flags, but reading
   them means reading a config row and deployment environment variables — and the
   ServiceAccount deliberately cannot read ConfigMaps or Secrets. Currently
   inferred, never confirmed.
9. **No historical query statistics, and this is unfixable here.**
   `pg_stat_statements` is not installed anywhere in prod AlloyDB, so "what was slow
   an hour ago" cannot be answered. Enabling it needs `shared_preload_libraries` and
   a restart. See `alloydb-what-is-slow.md`.
10. **No rider-side entity lookups.** `db:entity` covers drivers only. The same
    class of ticket exists for riders and would need its own reviewed entries.
11. **Cannot compare a value across clouds in one call.** Cross-cloud staleness
    diagnosis requires two Redis reads and a manual comparison. A single function
    returning both copies with their timestamps would make the most common
    cross-cloud bug a one-step answer.
12. **No deployment/rollout history.** Several incidents were "what changed?", and
    the honest answer usually came from rollout history. Readable in principle with
    the current k8s grants, not currently exposed as a function.
13. **No Kafka surface.** Referenced by the drainer runbooks as the place streamed
    entries go; nothing here can look at it.

## Known landmines the tool should not be trusted on

14. **Redis endpoints may not be distinct per cloud.** If both named connections
    resolve to the same instance, every cross-cloud staleness answer is wrong in a
    way that looks right. Verify before trusting `cross-cloud-write-staleness.md`.
15. **`analytics` returns real business data.** It is on its own surface and its own
    role for that reason. Widening it to Engineer would quietly turn an infra tool
    into a customer-data tool.
