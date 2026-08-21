"""VictoriaMetrics metadata: metric names, label values, active alerts.

WHY THIS EXISTS RATHER THAN THE MCP SERVER.

These capabilities were registered against `mcp-victoriametrics` and
`mcp-grafana`. Both were verified dead on 2026-08-19: they speak the LEGACY SSE
transport (an open stream from ``GET /sse``), while this client speaks
streamable HTTP, so every call returned 404. Implementing SSE would be a
substantial second transport for tools whose data is already one HTTP GET away
on the metrics connection this process uses successfully for every PromQL query.

So these read the VictoriaMetrics HTTP API directly. Fewer moving parts, one
fewer service that can be down during an incident, and no transport to keep in
step with an upstream server's version.

Read-only by construction: the only endpoints reachable are the three named
here, all GET, all metadata. There is no query parameter that can reach a write
path, because VictoriaMetrics has none on this port.

`metric_names` matters more than it looks. Every metric name in the registry is
a possible silent false negative — a name that does not exist returns an empty
series, an empty series looks like zero, and zero looks like health. This is how
the model checks what the store actually holds instead of trusting a name.
"""

from __future__ import annotations

from typing import Any

import httpx

from app import config
from app.executors.base import ExecResult, Executor, ExecutorError
from app.registry.schema import RegistryEntry

#: The only paths this executor may request, keyed by entry kind payload.
_ENDPOINTS = {
    "metric_names": "/api/v1/label/__name__/values",
    "label_names": "/api/v1/labels",
    "label_values": "/api/v1/label/{label}/values",
    "active_alerts": "/api/v1/alerts",
    "alert_rules": "/api/v1/rules",
}


class VmMetaExecutor(Executor):
    kind = "vmmeta"

    def __init__(self, base_url: str | None = None, client: Any = None) -> None:
        self._base_url = base_url or config.METRICS_URL
        self._client = client

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=self._base_url)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def run(
        self, entry: RegistryEntry, params: dict[str, Any], target: str
    ) -> ExecResult:
        if entry.kind != "vmmeta" or not entry.metric:
            raise ExecutorError(f"{entry.name}: not a vmmeta entry")

        path = _ENDPOINTS.get(entry.metric)
        if path is None:
            # Fail closed: an unknown endpoint name is a registry bug, and
            # guessing a URL here would be exactly the "assistant builds its own
            # request" path this design exists to prevent.
            raise ExecutorError(
                f"{entry.name}: unknown metadata endpoint '{entry.metric}' "
                f"(known: {sorted(_ENDPOINTS)})"
            )

        query: dict[str, str] = {}
        if "{label}" in path:
            label = str(params.get("label") or "")
            if not label:
                raise ExecutorError(f"{entry.name}: `label` is required")
            path = path.replace("{label}", label)
        match = params.get("match")
        if match:
            # VictoriaMetrics filters the metadata by series selector. Passing
            # the whole store back is useless during an incident — there are
            # thousands of names.
            query["match[]"] = str(match)

        started = self._timed()
        client = await self._get_client()
        try:
            response = await client.get(path, params=query, timeout=entry.timeout_s)
        except httpx.HTTPError as exc:
            raise ExecutorError(f"{entry.name}: metrics store unreachable: {exc}") from exc
        if response.status_code >= 400:
            raise ExecutorError(
                f"{entry.name}: metrics store returned HTTP {response.status_code}: "
                f"{response.text[:200]}"
            )

        payload = response.json()
        if payload.get("status") != "success":
            raise ExecutorError(f"{entry.name}: metrics error: {payload.get('error')}")

        data = payload.get("data")
        rows: list[dict[str, Any]] = []
        if isinstance(data, list):
            rows = [{"value": v} for v in data[: entry.row_limit]]
            body = "\n".join(str(v) for v in data[: entry.row_limit])
            if not data:
                # An empty list is the answer to "does this exist?", and it is
                # the answer that matters most — say it, do not return blank.
                body = "(nothing matched — the name or selector does not exist in this store)"
        elif isinstance(data, dict):
            alerts = data.get("alerts")
            groups = data.get("groups")
            items = alerts if isinstance(alerts, list) else (groups or [])
            rows = [i for i in items[: entry.row_limit] if isinstance(i, dict)]
            # Different empties mean different things, and saying the wrong one
            # is worse than saying nothing: no alerts FIRING is good news, no
            # rules DEFINED means nothing here can ever alert.
            if rows:
                body = "\n".join(str(i) for i in rows)
            elif isinstance(groups, list):
                body = (
                    "(no alert rules are defined in this store — nothing here "
                    "can fire. Rules may live in a separate alerting component; "
                    "this is not evidence that alerting exists.)"
                )
            else:
                body = "(no alerts currently firing)"
        else:
            body = str(data)

        return ExecResult(
            ok=True,
            entry_name=entry.name,
            target=target,
            rows=rows,
            text=body,
            duration_ms=int((self._timed() - started) * 1000),
        )
