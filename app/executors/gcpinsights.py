"""AlloyDB Query Insights — per-query time attribution.

WHY THIS EXISTS, and why it is not just another metric query.

"Which queries are burning CPU" was previously unanswerable here: this AlloyDB
has no `pg_stat_statements` (not on the readers and not on the writer), and
AlloyDB's own `g_agg_stat_statements` errors out. So the runbooks said the
question could only be answered live, by catching a slow query in the act.

That was wrong. Query Insights records per-query execution, I/O and lock time
and publishes it to Cloud Monitoring, labelled with the normalised SQL. It is on
by default, and it was carrying data the whole time — verified 2026-08-20, with
the top query showing 11,260 seconds of execution time in one hour.

WHY IT LOOKED EMPTY. The generic metric reader aligns with ALIGN_MEAN and does
not group, which for a DELTA metric spread across hundreds of query series
returns nothing useful. The shape that works, and the reason this is its own
executor rather than more parameters on the generic one:

    perSeriesAligner   ALIGN_DELTA        (it is a cumulative counter)
    alignmentPeriod    300s               (shorter buckets return sparse points)
    crossSeriesReducer REDUCE_SUM
    groupByFields      metric.label.querystring

Making those knobs model-supplied would mean the model can produce a query that
returns nothing and reads it as "no slow queries" — the exact false-negative
this codebase keeps having to design against. They are fixed here instead.
"""

from __future__ import annotations

import datetime as dt
import urllib.parse
from typing import Any

import httpx

from app import config
from app.executors.base import ExecResult, Executor, ExecutorError
from app.executors.gcpapi import _token
from app.registry.schema import RegistryEntry

_BASE = "https://monitoring.googleapis.com/v3/projects"

#: The per-query metrics Query Insights publishes. The entry names one.
_METRICS = {
    "execution_time": "alloydb.googleapis.com/database/postgresql/insights/perquery/execution_time",
    "io_time": "alloydb.googleapis.com/database/postgresql/insights/perquery/io_time",
    "lock_time": "alloydb.googleapis.com/database/postgresql/insights/perquery/lock_time",
}

_WINDOW_SECONDS = {"15m": 900, "30m": 1800, "1h": 3600, "6h": 21600, "24h": 86400}


def _collapse(sql: str, limit: int = 240) -> str:
    """One line of SQL, trimmed. The raw text is long and mostly column lists."""
    flat = " ".join(str(sql).split())
    return flat if len(flat) <= limit else flat[:limit] + " …"


class GcpInsightsExecutor(Executor):
    kind = "gcpinsights"

    async def run(
        self, entry: RegistryEntry, params: dict[str, Any], target: str
    ) -> ExecResult:
        metric_key = entry.metric or "execution_time"
        metric_type = _METRICS.get(metric_key)
        if metric_type is None:
            raise ExecutorError(
                f"{entry.name}: unknown insights metric '{metric_key}' "
                f"(known: {sorted(_METRICS)})"
            )

        window = str(params.get("window") or "1h")
        seconds = _WINDOW_SECONDS.get(window, 3600)
        top = int(params.get("top") or 10)

        end = dt.datetime.now(dt.UTC)
        start = end - dt.timedelta(seconds=seconds)
        query = {
            "filter": f'metric.type="{metric_type}"',
            "interval.startTime": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "interval.endTime": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "aggregation.alignmentPeriod": "300s",
            "aggregation.perSeriesAligner": "ALIGN_DELTA",
            "aggregation.crossSeriesReducer": "REDUCE_SUM",
            "aggregation.groupByFields": "metric.label.querystring",
        }

        started = self._timed()
        url = f"{_BASE}/{config.GCP_PROJECT}/timeSeries?{urllib.parse.urlencode(query)}"
        try:
            async with httpx.AsyncClient(timeout=entry.timeout_s) as client:
                response = await client.get(
                    url, headers={"Authorization": f"Bearer {_token()}"}
                )
        except httpx.HTTPError as exc:
            raise ExecutorError(f"{entry.name}: monitoring API unreachable: {exc}") from exc
        if response.status_code >= 400:
            raise ExecutorError(
                f"{entry.name}: monitoring API HTTP {response.status_code}: "
                f"{response.text[:200]}"
            )

        series = response.json().get("timeSeries", [])
        totals: list[tuple[float, str]] = []
        for item in series:
            total = 0.0
            for point in item.get("points", []):
                value = point.get("value", {})
                total += float(
                    value.get("doubleValue") or value.get("int64Value") or 0
                )
            sql = item.get("metric", {}).get("labels", {}).get("querystring", "")
            if sql:
                totals.append((total, sql))
        totals.sort(reverse=True)

        # Microseconds in the API; seconds is what anyone reasons in.
        rows = [
            {"total_seconds": round(v / 1_000_000, 1), "query": _collapse(q)}
            for v, q in totals[:top]
        ]

        if not rows:
            text = (
                "(no per-query data in this window. Query Insights is on by "
                "default, so this usually means the window is too short or the "
                "instances were idle — widen it before concluding anything.)"
            )
        else:
            unit = metric_key.replace("_", " ")
            lines = [f"top queries by {unit} over {window} (seconds, summed):"]
            lines += [f"{r['total_seconds']:>12}  {r['query']}" for r in rows]
            text = "\n".join(lines)

        return ExecResult(
            ok=True,
            entry_name=entry.name,
            target=target,
            rows=rows,
            text=text,
            duration_ms=int((self._timed() - started) * 1000),
        )
