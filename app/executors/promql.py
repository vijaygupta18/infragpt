"""PromQL executor — named templates against VictoriaMetrics.

The registry holds *templates*, not expressions, so the LLM cannot write PromQL.
What remains is the substitution step, and that is where a label value could in
principle close its own quote and append a selector. So substituted values are
re-checked here against a strict label-value pattern and **rejected** rather than
escaped: if a value would need quoting to be safe, it is not a value we want.

VictoriaMetrics' ``/api/v1/query`` endpoint is read-only by construction; there
is no write path on this surface at all.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from app import config
from app.executors.base import ExecResult, Executor, ExecutorError
from app.registry.loader import PLACEHOLDER_RE
from app.registry.schema import RegistryEntry

#: A substituted PromQL label value may contain only these characters. No
#: quotes, no braces, no backslashes, no commas — nothing that could terminate a
#: label matcher or start a new one.
LABEL_VALUE_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")

#: Duration slots (rate windows) are stricter still.
DURATION_RE = re.compile(r"^\d{1,4}[smhdw]$")

_DURATION_SLOTS = frozenset({"window", "range", "lookback"})


def substitute_promql(template: str, params: dict[str, Any]) -> str:
    """Fill template slots after re-validating each value. Never escapes."""

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in params or params[name] is None:
            raise ExecutorError(f"promql template slot '{name}' has no value")
        value = str(params[name])
        pattern = DURATION_RE if name in _DURATION_SLOTS else LABEL_VALUE_RE
        if not pattern.match(value):
            raise ExecutorError(
                f"refused: promql slot '{name}' value {value!r} is not a safe "
                f"label value"
            )
        return value

    rendered = PLACEHOLDER_RE.sub(repl, template)
    if "$" in rendered:
        raise ExecutorError("refused: unresolved slot remains in promql expression")
    return rendered


class PromQLExecutor(Executor):
    kind = "promql"

    def __init__(self, base_url: str | None = None, client: Any = None) -> None:
        self._base_url = (base_url or config.METRICS_URL or "").rstrip("/")
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
        if entry.kind != "promql" or not entry.promql:
            raise ExecutorError(f"{entry.name}: not a promql entry")
        if not self._base_url and self._client is None:
            raise ExecutorError("metrics URL is not configured")

        expr = substitute_promql(entry.promql, params)
        client = await self._get_client()

        started = self._timed()
        try:
            response = await client.get(
                "/api/v1/query",
                params={"query": expr},
                timeout=entry.timeout_s,
            )
        except httpx.HTTPError as exc:
            raise ExecutorError(f"{entry.name}: metrics request failed: {exc}") from exc

        if response.status_code != 200:
            raise ExecutorError(
                f"{entry.name}: metrics returned HTTP {response.status_code}: "
                f"{response.text[:500]}"
            )

        payload = response.json()
        if payload.get("status") != "success":
            raise ExecutorError(f"{entry.name}: metrics error: {payload.get('error')}")

        rows: list[dict[str, Any]] = []
        for series in payload.get("data", {}).get("result", [])[: entry.row_limit]:
            row: dict[str, Any] = dict(series.get("metric", {}))
            value = series.get("value")
            if isinstance(value, list) and len(value) == 2:
                row["timestamp"] = value[0]
                row["value"] = value[1]
            rows.append(row)

        # The RESULTS, with the query kept as a header line.
        #
        # This previously returned only `query: <expr>`. Downstream, evidence is
        # built as `result.text or rows`, so a non-empty text SUPPRESSED the
        # rows — every metrics answer reached the model as the query it had just
        # asked for, with the numbers dropped. The model then had nothing to
        # report and no way to know why.
        #
        # The query stays because an answer should be able to show what it
        # measured, but it can never again stand in for the measurement.
        lines = [f"query: {expr}"]
        if rows:
            keys: list[str] = []
            for row in rows:
                for key in row:
                    if key not in keys:
                        keys.append(key)
            lines.append(" | ".join(keys))
            for row in rows:
                lines.append(" | ".join(str(row.get(k, "")) for k in keys))
        else:
            # Said explicitly: an empty metrics result means the selector
            # matched nothing, which is nearly always a wrong label value rather
            # than a healthy system.
            lines.append(
                "(no series matched — this is NOT the same as a value of zero; "
                "the label values in the query probably match nothing)"
            )

        return ExecResult(
            ok=True,
            entry_name=entry.name,
            target=target,
            rows=rows,
            text="\n".join(lines),
            duration_ms=int((self._timed() - started) * 1000),
        )
