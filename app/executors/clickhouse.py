"""ClickHouse executor — the analytics warehouse, over the HTTP interface.

This is the one surface that answers questions about DATA (rides, bookings,
events) rather than about infrastructure. That makes it the widest-blast-radius
*read* in the system, so the containment is layered exactly like the Postgres
side, and every layer is independent of the others:

1. **Credentials.** The intended account is a ClickHouse user whose PROFILE sets
   ``readonly = 1``. A write is denied by the server before any of our code is
   consulted. This is the only layer that is not our responsibility to get right.
2. **``readonly=1`` on every request.** Sent as a URL setting by
   :meth:`ClickHouseExecutor._settings`, which no registry entry can reach or
   override — the entry supplies a statement, never a setting. Under
   ``readonly=1`` ClickHouse also refuses ``SET`` and any ``SETTINGS`` clause
   that would relax it, so the statement cannot lift its own restriction.
3. **The load-time gate.** ``app/registry/readonly.py`` refuses a mutating
   ``clickhouse`` entry at startup, so a bad registry PR stops the deploy rather
   than surfacing as a refused call mid-incident.
4. **This executor's own check.** :func:`assert_read_only` re-checks the
   statement immediately before it is sent, whether it came from a reviewed
   entry or from the model via ``clickhousefree``. The check is on the
   STATEMENT, so its origin does not change what is allowed.

Two ClickHouse-specific notes that are easy to get wrong:

* **Setting order in the URL matters.** ClickHouse applies query-string settings
  left to right, and once ``readonly=1`` is applied, *changing any further
  setting in the same request is itself refused*. So the bounds
  (``max_execution_time``, ``max_result_rows``) are placed BEFORE ``readonly``
  and ``readonly`` is placed last. Reversing this produces "Cannot modify
  'max_execution_time' setting in readonly mode" on every single query.
* **``readonly=1`` is not the whole story.** ``SELECT * FROM url('http://...')``
  is a perfectly well-formed read that turns this process into an outbound HTTP
  client, and ``INTO OUTFILE`` writes a file from a SELECT. Those are blocked by
  name, here and at load time, not by the readonly setting.

Parameters are never interpolated. Registry SQL uses ClickHouse's own
placeholder syntax — ``{table:String}`` — and the values travel as ``param_*``
query-string arguments, so the server binds them and no value is ever spliced
into the statement text.

Transport is httpx over the HTTP interface (port 8123). No ClickHouse client
library is pulled in: the wire protocol here is "POST a string, read JSON".
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from app import config
from app.executors.base import (
    ExecResult,
    Executor,
    ExecutorError,
    safe_exception_text,  # noqa: F401
)
from app.registry.loader import PLACEHOLDER_RE
from app.registry.schema import RegistryEntry

#: ``{name:Type}`` — ClickHouse's server-side bind syntax. The executor sends
#: each of these as ``param_<name>=<value>``; nothing is substituted locally.
BIND_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*):[A-Za-z0-9_()' ,]+\}")

#: A statement must begin with one of these. Matched at the start only.
ALLOWED_LEADING = ("select", "with", "show", "describe", "desc", "explain")

#: Denied verbs, matched at the START of a statement (or of a chained one).
DENIED_LEADING = re.compile(
    r"\b(insert|alter|drop|create|attach|detach|rename|truncate|optimize|"
    r"system|kill|grant|revoke|set|use|exchange|delete|update|move|freeze|"
    r"unfreeze|restore|backup|watch)\b",
    re.IGNORECASE,
)

#: Table functions / clauses that read the filesystem, reach a remote endpoint,
#: or write output. Scanned ANYWHERE. Kept in step with the identically-named
#: pattern in app/registry/readonly.py; both must hold.
DENIED_FUNCTIONS = re.compile(
    r"\b(file|url|urlCluster|s3|s3Cluster|remote|remoteSecure|cluster|"
    r"clusterAllReplicas|hdfs|hdfsCluster|mysql|postgresql|mongodb|jdbc|odbc|"
    r"sqlite|redis|executable|input|infile|azureBlobStorage|deltaLake|"
    r"iceberg|hudi)\s*\(|\binto\s+outfile\b",
    re.IGNORECASE,
)

#: A statement may not set `readonly` itself, whatever value it asks for. Under
#: `readonly=1` the server would refuse anyway; refusing here means the model is
#: told WHY rather than getting a ClickHouse error it will try to work around.
DENIED_SETTING = re.compile(r"\breadonly\s*=", re.IGNORECASE)

#: The executor chooses the wire format, so a statement may not append its own
#: FORMAT clause — the response would no longer parse as JSONCompact.
TRAILING_FORMAT = re.compile(r"\bformat\s+[a-zA-Z0-9_]+\s*$", re.IGNORECASE)

_HAS_LIMIT_RE = re.compile(r"\blimit\s+\d+\s*$", re.IGNORECASE)

#: Hard ceiling on the response we will even read, before row/column capping.
#: The assistant truncates evidence anyway, so a 200MB result is not a better
#: answer — it is the same answer plus an OOM risk on this pod.
MAX_RESPONSE_BYTES = 4_000_000

#: Ceiling on the rendered text table handed back as evidence.
MAX_TEXT_CHARS = 60_000

#: Longest single cell rendered in the text table.
MAX_CELL_CHARS = 200


def assert_read_only(statement: str) -> None:
    """Reject anything that is not a single, self-contained ClickHouse read.

    Defence in depth, not the primary control — the account's ``readonly = 1``
    profile and the per-request ``readonly=1`` setting are. This exists so that
    a bad registry entry, or a statement the model composed, fails here with an
    explanation rather than as a server-side error the model then tries to
    route around.
    """
    stripped = statement.strip().lstrip("(").lstrip()
    if not stripped:
        raise ExecutorError("refused: empty statement")
    if not stripped.lower().startswith(ALLOWED_LEADING):
        raise ExecutorError(f"refused: statement is not a read: {stripped[:60]!r}")

    # Strip string literals first, so a query merely MENTIONING a verb inside
    # quoted text is not falsely rejected.
    without_literals = re.sub(r"'[^']*'", "''", stripped)

    for chunk in without_literals.split(";"):
        chunk = chunk.strip()
        if chunk and DENIED_LEADING.match(chunk):
            raise ExecutorError(f"refused: mutating statement detected: {chunk[:60]!r}")
    if ";" in without_literals.rstrip(";").rstrip():
        raise ExecutorError("refused: multiple statements in one call")

    hit = DENIED_FUNCTIONS.search(without_literals)
    if hit:
        raise ExecutorError(
            f"refused: {hit.group(0).strip()!r} reads the filesystem or a remote "
            "endpoint. A statement beginning with SELECT is not automatically a "
            "read of this warehouse."
        )
    if DENIED_SETTING.search(without_literals):
        raise ExecutorError(
            "refused: a statement may not set `readonly`. It is set to 1 on every "
            "request and is not negotiable from a query."
        )
    if TRAILING_FORMAT.search(without_literals):
        raise ExecutorError(
            "refused: do not append a FORMAT clause — the output format is chosen "
            "by the executor."
        )


def append_limit(statement: str, row_limit: int) -> str:
    """Append a LIMIT unless the statement already ends with one.

    SHOW / DESCRIBE take a LIMIT in ClickHouse too, so this is unconditional
    apart from the already-limited case.
    """
    body = statement.strip().rstrip(";").rstrip()
    if _HAS_LIMIT_RE.search(body):
        return body
    return f"{body}\nLIMIT {int(row_limit)}"


def render_table(columns: list[str], rows: list[list[Any]]) -> tuple[str, bool]:
    """Render a compact text table. Returns (text, truncated)."""
    if not columns:
        return "(no columns)", False

    def cell(value: Any) -> str:
        if value is None:
            return ""
        text = value if isinstance(value, str) else json.dumps(value, default=str)
        text = text.replace("\n", " ").replace("\t", " ")
        if len(text) > MAX_CELL_CHARS:
            text = text[:MAX_CELL_CHARS] + "…"
        return text

    body = [[cell(v) for v in row] for row in rows]
    widths = [len(c) for c in columns]
    for row in body:
        for i, value in enumerate(row[: len(widths)]):
            widths[i] = max(widths[i], len(value))

    lines = [
        "  ".join(c.ljust(widths[i]) for i, c in enumerate(columns)),
        "  ".join("-" * w for w in widths),
    ]
    truncated = False
    for row in body:
        line = "  ".join(
            (row[i] if i < len(row) else "").ljust(widths[i])
            for i in range(len(columns))
        )
        if sum(len(x) + 1 for x in lines) + len(line) > MAX_TEXT_CHARS:
            truncated = True
            break
        lines.append(line.rstrip())
    if truncated:
        lines.append("… output truncated")
    return "\n".join(lines), truncated


class ClickHouseExecutor(Executor):
    """Runs ``clickhouse`` (fixed SQL) and ``clickhousefree`` (SQL as a param)."""

    kind = "clickhouse"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    # -- connection ---------------------------------------------------------

    @staticmethod
    def _connection(target: str) -> config.ClickHouseConnection:
        try:
            return config.CLICKHOUSE_CONNECTIONS[target]
        except KeyError:
            raise ExecutorError(f"unknown clickhouse connection: {target}") from None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient()
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # -- settings -----------------------------------------------------------

    @staticmethod
    def _settings(
        conn: config.ClickHouseConnection, entry: RegistryEntry
    ) -> dict[str, str]:
        """The SETTINGS sent with EVERY request. Not reachable from a registry
        entry, which supplies a statement and nothing else.

        ORDER IS LOAD-BEARING: ClickHouse applies query-string settings left to
        right and refuses to change any setting once ``readonly=1`` has been
        applied, so ``readonly`` must be LAST. Python dicts preserve insertion
        order and httpx encodes them in that order.
        """
        timeout = max(1, min(int(entry.timeout_s), conn.max_execution_time_s))
        rows = max(1, min(int(entry.row_limit), conn.max_result_rows))
        settings = {
            "max_execution_time": str(timeout),
            "max_result_rows": str(rows),
            # Stop at the row cap and return what was gathered, rather than
            # failing the whole query at the boundary — a capped answer is far
            # more useful mid-incident than an exception.
            "result_overflow_mode": "break",
            "max_result_bytes": str(MAX_RESPONSE_BYTES),
            "default_format": "JSONCompact",
            # LAST, deliberately. See the docstring.
            "readonly": "1",
        }
        if conn.database:
            # `database` is not a setting, but it must also precede readonly.
            return {"database": conn.database, **settings}
        return settings

    # -- run ----------------------------------------------------------------

    def _statement(self, entry: RegistryEntry, params: dict[str, Any]) -> str:
        if entry.kind == "clickhouse":
            if not entry.sql:
                raise ExecutorError(f"{entry.name}: clickhouse entry has no statement")
            return entry.sql
        if entry.kind == "clickhousefree":
            statement = str(params.get("sql") or "").strip()
            if not statement:
                raise ExecutorError(f"{entry.name}: `sql` is required")
            return statement
        raise ExecutorError(f"{entry.name}: not a clickhouse entry")

    async def run(
        self, entry: RegistryEntry, params: dict[str, Any], target: str
    ) -> ExecResult:
        statement = self._statement(entry, params)

        # Layer 4. Applied identically to a reviewed statement and to one the
        # model supplied: the check is on the statement, not on its origin.
        assert_read_only(statement)
        statement = append_limit(statement, entry.row_limit)

        conn = self._connection(target)
        if not conn.host:
            raise ExecutorError(
                f"{entry.name}: clickhouse connection '{target}' has no host "
                "configured (INFRAGPT_CLICKHOUSE_HOST is unset). This is a "
                "configuration failure, not a fact about the warehouse."
            )

        query = self._settings(conn, entry)
        # Server-side binds for every {name:Type} placeholder the statement
        # declares. Values are sent separately; nothing is interpolated.
        for name in set(BIND_RE.findall(statement)):
            if name not in params:
                raise ExecutorError(
                    f"{entry.name}: statement binds undeclared param '{name}'"
                )
            query[f"param_{name}"] = str(params[name])
        if PLACEHOLDER_RE.search(statement):
            raise ExecutorError(
                f"{entry.name}: statement contains a '$' template slot. ClickHouse "
                "parameters must be bound as {name:Type}, never interpolated."
            )

        headers = {
            "X-ClickHouse-User": conn.user,
            "X-ClickHouse-Key": config.secret_from_env(conn.password_env),
        }

        started = self._timed()
        client = await self._get_client()
        try:
            response = await client.post(
                conn.base_url,
                params=query,
                content=statement.encode(),
                headers=headers,
                timeout=httpx.Timeout(
                    entry.timeout_s + 5, connect=conn.connect_timeout_s
                ),
            )
        except httpx.HTTPError as exc:
            raise ExecutorError(
                f"{entry.name}: cannot reach clickhouse at {conn.host}:{conn.port} — "
                f"{safe_exception_text(exc)}. This is a connectivity failure, NOT "
                "evidence about the warehouse's load or contents."
            ) from exc

        if response.status_code != 200:
            detail = response.text[:800].strip()
            raise ExecutorError(
                f"{entry.name}: clickhouse returned HTTP {response.status_code}: "
                f"{detail}"
            )

        raw = response.content[:MAX_RESPONSE_BYTES]
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise ExecutorError(
                f"{entry.name}: clickhouse response was not JSON "
                f"({len(raw)} bytes): {raw[:200]!r}"
            ) from exc

        columns = [str(m.get("name", "")) for m in payload.get("meta", [])]
        data = payload.get("data", [])[: entry.row_limit]
        rows = [
            dict(zip(columns, values, strict=False))
            for values in data
            if isinstance(values, list)
        ]
        text, truncated = render_table(columns, [r for r in data if isinstance(r, list)])

        return ExecResult(
            ok=True,
            entry_name=entry.name,
            target=target,
            rows=rows,
            text=text,
            truncated=truncated or len(payload.get("data", [])) > entry.row_limit,
            duration_ms=int((self._timed() - started) * 1000),
        )


__all__ = [
    "ALLOWED_LEADING",
    "DENIED_FUNCTIONS",
    "DENIED_LEADING",
    "MAX_TEXT_CHARS",
    "ClickHouseExecutor",
    "append_limit",
    "assert_read_only",
    "render_table",
]
