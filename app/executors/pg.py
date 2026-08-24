"""Postgres executor — AlloyDB readers, metadata queries only.

Safety properties, in the order they matter:

1. **Credentials.** The pool connects as a SELECT-only role (``readonly_db_user`` in
   prod) against *reader* endpoints. Verified 2026-08-17: those readers report
   ``pg_is_in_recovery() = t``, so they are physical replicas where a write is not
   merely denied but impossible. This is the only enforcement that is not our
   code's responsibility to get right.
2. **Read-only session.** Each connection sets ``default_transaction_read_only``
   so a write attempt fails at the session level too.
3. **Bind params.** ``:name`` slots are rewritten to psycopg's ``%(name)s`` and
   passed as a values mapping. No SQL string is ever built from a param value.
4. **Identifier existence.** ``identifier`` params (``table``) are checked
   against ``pg_catalog`` before the real query runs. A regex says a string
   *looks* like an identifier; only the catalogue says it *is* one.
5. **Bounded cost.** ``statement_timeout`` and
   ``idle_in_transaction_session_timeout`` are set per session from the entry's
   own timeout, the pool is capped at 5 connections so this process cannot
   exhaust a reader, and a LIMIT is appended when the entry declares one.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from psycopg import AsyncConnection, sql
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from app import config
from app.executors.base import ExecResult, Executor, ExecutorError
from app.registry.schema import ParamType, RegistryEntry


async def _direct_connect_error(conn: config.PgConnection) -> str | None:
    """Open one connection outside the pool to recover the real failure.

    ``psycopg_pool`` surfaces every connect failure as PoolTimeout, so the
    genuinely useful message — `database "x" does not exist`, `password
    authentication failed`, `no pg_hba.conf entry` — never reaches the caller.
    Returns None when the connection succeeds, i.e. the pool really is
    saturated rather than misconfigured.
    """
    password = config.secret_from_env(conn.password_env)
    try:
        async with await AsyncConnection.connect(
            host=conn.host,
            port=conn.port,
            dbname=conn.database,
            user=conn.user,
            password=password,
            sslmode=conn.sslmode,
            connect_timeout=8,
        ):
            return None
    except Exception as exc:  # noqa: BLE001 - reported verbatim, that is the point
        detail = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
        return (
            f"{detail} (host={conn.host} db={conn.database} user={conn.user}). "
            "This is a connection/configuration failure, not evidence about "
            "database load."
        )


async def _tcp_reachable(host: str, port: int, timeout_s: float = 3.0) -> bool:
    """Can we open a TCP socket at all? Used only to disambiguate a PoolTimeout."""
    if not host:
        return False
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout_s
        )
    except (TimeoutError, OSError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True

# ``:name`` -> ``%(name)s``. Lookbehind keeps ``::type`` casts intact.
_BIND_RE = re.compile(r"(?<![:\w]):([a-zA-Z_][a-zA-Z0-9_]*)")

# Detects a top-level LIMIT so we do not append a second one.
_HAS_LIMIT_RE = re.compile(r"\blimit\s+\d+\s*$", re.IGNORECASE)

# Belt and braces: metadata queries are SELECTs. Anything else in the registry
# is a review failure, and this catches it before it reaches a connection.
_ALLOWED_LEADING = ("select", "with", "table", "explain")

_DENY_RE = re.compile(
    r"\b(insert|update|delete|drop|alter|truncate|create|grant|revoke|"
    r"vacuum|reindex|cluster|copy|call|do|set|reset|lock|refresh|"
    r"comment|security|listen|notify|prepare|execute)\b",
    re.IGNORECASE,
)


def to_psycopg_sql(raw: str) -> str:
    """Rewrite registry ``:name`` binds into psycopg's ``%(name)s`` form.

    Literal ``%`` must be doubled first, or psycopg will treat it as the start
    of its own placeholder.
    """
    return _BIND_RE.sub(lambda m: f"%({m.group(1)})s", raw.replace("%", "%%"))


def assert_read_only(statement: str) -> None:
    """Reject anything that is not a plain read.

    This is defence in depth, not the primary control — the RO role is. It
    exists so that a bad registry PR fails in tests rather than in production.
    """
    stripped = statement.strip().lstrip("(").lstrip()
    lowered = stripped.lower()
    if not lowered.startswith(_ALLOWED_LEADING):
        raise ExecutorError(f"refused: statement is not a read: {stripped[:60]!r}")
    # Strip string literals before scanning for verbs, so a query that merely
    # mentions 'update' inside quoted text is not falsely rejected.
    without_literals = re.sub(r"'[^']*'", "''", stripped)
    # Ignore column/alias words: only flag a denied verb at statement start or
    # after a semicolon (i.e. a second, chained statement).
    for chunk in without_literals.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if _DENY_RE.match(chunk):
            raise ExecutorError(f"refused: mutating statement detected: {chunk[:60]!r}")
    if ";" in without_literals.rstrip(";"):
        raise ExecutorError("refused: multiple statements in one registry entry")


# Relations a free-form statement may read. Catalogue and statistics only:
# everything here describes the DATABASE, and none of it describes a person.
_CATALOGUE_PREFIXES = ("pg_", "information_schema.")

# `FROM x`, `JOIN x` — the relations a statement actually reads. Subquery and
# CTE aliases are handled by allowing anything defined as a CTE in the same
# statement, below.
_RELATION_RE = re.compile(
    r"\b(?:from|join)\s+(?:only\s+)?([a-zA-Z_][a-zA-Z0-9_$.]*)",
    re.IGNORECASE,
)
_CTE_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s+as\s*\(", re.IGNORECASE)


def assert_catalogue_only(statement: str) -> None:
    """Restrict a MODEL-SUPPLIED statement to catalogue and statistics views.

    Read-only is not the same as in-scope. The db:read surface exists to answer
    questions about the database — indexes, bloat, locks, replication, plans —
    and deliberately does not expose business rows: a driver's record is
    reachable only through the curated db:entity lookups, which are audited
    per subject and sit behind their own grant.

    Without this, a free-form SELECT would quietly become an unaudited path to
    every table in production, which is precisely the boundary the db:entity
    split was drawn to hold. Stating the rule in the tool description is not
    enough — a description is a request, and this needs to be a guarantee.

    Fixed registry entries do NOT go through this: their SQL was reviewed in a
    PR, and a few of them read application tables on purpose.
    """
    without_literals = re.sub(r"'[^']*'", "''", statement)
    local = {name.lower() for name in _CTE_RE.findall(without_literals)}
    for raw in _RELATION_RE.findall(without_literals):
        rel = raw.lower().lstrip("(")
        if rel in local or rel.startswith("("):
            continue
        # `public.foo` and bare `foo` are both application tables; only the
        # catalogue schemas and pg_* relations are in scope.
        if rel.startswith(_CATALOGUE_PREFIXES):
            continue
        raise ExecutorError(
            f"refused: '{raw}' is an application table. This surface answers "
            f"questions about the DATABASE — pg_catalog and information_schema "
            f"only. Business records for a specific driver, rider, ride or "
            f"payment are out of scope here; they are reachable only through "
            f"the curated per-subject lookups, which need their own grant."
        )


def append_limit(statement: str, row_limit: int) -> str:
    if _HAS_LIMIT_RE.search(statement.rstrip().rstrip(";")):
        return statement
    return f"{statement.rstrip().rstrip(';')}\nLIMIT {int(row_limit)}"


class PgExecutor(Executor):
    kind = "sql"

    def __init__(self) -> None:
        self._pools: dict[str, AsyncConnectionPool] = {}
        self._lock = asyncio.Lock()

    # -- pool management ----------------------------------------------------

    def _conninfo(self, name: str) -> str:
        try:
            conn = config.PG_CONNECTIONS[name]
        except KeyError:
            raise ExecutorError(f"unknown pg connection: {name}") from None
        password = config.secret_from_env(conn.password_env)
        # Bounds set on the CONNECTION, not per session.
        #
        # `SET statement_timeout` after connecting only protects code paths that
        # remember to call it. Put in the connection options they apply to every
        # statement on every connection from this pool, including paths added
        # later — which matters now that free-form SELECTs are possible.
        #
        # `default_transaction_read_only=on` is belt to the credential's braces:
        # the role is SELECT-only and the endpoint is a physical replica where
        # writes are impossible, and this makes a write fail a third time, at
        # the session level, with a clear message.
        #
        # `connect_timeout` bounds the connect itself: without it a
        # network-level hang shows up as a pool timeout minutes later, which
        # reads as database load rather than as a connectivity problem.
        options = " ".join(
            (
                f"-c statement_timeout={conn.statement_timeout_ms}",
                f"-c idle_in_transaction_session_timeout={conn.statement_timeout_ms}",
                "-c default_transaction_read_only=on",
            )
        )
        return (
            f"host={conn.host} port={conn.port} dbname={conn.database} "
            f"user={conn.user} password={password} sslmode={conn.sslmode} "
            f"connect_timeout={conn.connect_timeout_s} "
            f"options='{options}' "
            f"application_name=infragpt"
        )

    async def _pool(self, name: str) -> AsyncConnectionPool:
        async with self._lock:
            pool = self._pools.get(name)
            if pool is None:
                conn = config.PG_CONNECTIONS[name]
                pool = AsyncConnectionPool(
                    self._conninfo(name),
                    min_size=0,
                    max_size=conn.max_pool,  # hard cap — cannot exhaust a reader
                    open=False,
                    kwargs={"row_factory": dict_row, "autocommit": True},
                )
                await pool.open()
                self._pools[name] = pool
            return pool

    async def close(self) -> None:
        for pool in self._pools.values():
            await pool.close()
        self._pools.clear()

    # -- session setup ------------------------------------------------------

    @staticmethod
    async def _prepare_session(conn: AsyncConnection, timeout_s: int) -> None:
        ms = max(1, int(timeout_s)) * 1000
        async with conn.cursor() as cur:
            await cur.execute(
                sql.SQL("SET statement_timeout = {}").format(sql.Literal(ms))
            )
            await cur.execute(
                sql.SQL("SET idle_in_transaction_session_timeout = {}").format(
                    sql.Literal(ms)
                )
            )
            await cur.execute(sql.SQL("SET default_transaction_read_only = on"))

    # -- identifier verification -------------------------------------------

    @staticmethod
    async def _assert_relation_exists(conn: AsyncConnection, relname: str) -> None:
        """Verify an identifier against pg_catalog. A regex is not sufficient."""
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT 1 FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                "WHERE c.relname = %(relname)s "
                "AND n.nspname NOT IN ('pg_toast') "
                "AND c.relkind IN ('r','p','m','v','f') LIMIT 1",
                {"relname": relname},
            )
            if await cur.fetchone() is None:
                raise ExecutorError(f"no such relation: {relname}")

    # -- run ----------------------------------------------------------------

    async def run(
        self, entry: RegistryEntry, params: dict[str, Any], target: str
    ) -> ExecResult:
        # The statement is either fixed on the entry (the reviewed catalogue) or
        # supplied as a parameter (db_query, for catalogue questions no fixed
        # entry covers). Both go through assert_read_only below — the check is
        # on the STATEMENT, so where it came from does not change what is
        # allowed. A model-supplied INSERT is refused exactly as a bad registry
        # PR would be.
        if entry.sql:
            statement = entry.sql
        elif entry.kind == "sqlfree":
            statement = str(params.get("sql") or "").strip()
            if not statement:
                raise ExecutorError(f"{entry.name}: `sql` is required")
        else:
            raise ExecutorError(f"{entry.name}: not a sql entry")

        assert_read_only(statement)
        if not entry.sql:
            # Model-supplied: additionally confined to the catalogue. A reviewed
            # entry is not, since a few read application tables deliberately.
            assert_catalogue_only(statement)
        statement = append_limit(statement, entry.row_limit)
        rendered = to_psycopg_sql(statement)

        # Only params actually bound in the SQL are passed; `db` selects the
        # connection and must not leak into the values mapping.
        bound_names = set(_BIND_RE.findall(statement))
        values = {k: v for k, v in params.items() if k in bound_names}

        identifiers = [
            name
            for name, spec in entry.params.items()
            if spec.type is ParamType.IDENTIFIER and params.get(name) is not None
        ]

        started = self._timed()
        pool = await self._pool(target)
        try:
            # Acquire with a SHORT timeout, separately from the query. The
            # default acquire timeout equals the statement timeout, so during a
            # parallel burst the queued call ate its whole 30s budget waiting
            # for a slot and then failed — measured live: every one of these
            # queries is sub-second alone, and every audited 30s failure was
            # the wait, not the work. Ten seconds is dozens of query-lengths of
            # queueing; not getting a slot by then IS the finding, and saying
            # so after 10s beats a misleading timeout after 30.
            async with pool.connection(timeout=min(10.0, float(entry.timeout_s))) as conn:
                await self._prepare_session(conn, entry.timeout_s)
                for name in identifiers:
                    await self._assert_relation_exists(conn, str(params[name]))
                async with conn.cursor() as cur:
                    await asyncio.wait_for(
                        cur.execute(rendered, values), timeout=entry.timeout_s + 5
                    )
                    rows = await cur.fetchall()
        except ExecutorError:
            raise
        except TimeoutError as exc:
            raise ExecutorError(
                f"{entry.name}: timed out after {entry.timeout_s}s on {target}"
            ) from exc
        except Exception as exc:  # noqa: BLE001 - surfaced verbatim, never hidden
            # A pool timeout is ambiguous, and the ambiguity is dangerous: an
            # unreachable host and a genuinely saturated reader produce the same
            # PoolTimeout, and a reader "at its connection ceiling" is a very
            # plausible-sounding wrong answer to hand someone mid-incident.
            # Probe the socket so the error states which one it actually was.
            if type(exc).__name__ == "PoolTimeout":
                conn_cfg = config.PG_CONNECTIONS.get(target)
                if conn_cfg and not await _tcp_reachable(conn_cfg.host, conn_cfg.port):
                    raise ExecutorError(
                        f"{entry.name}: cannot reach {conn_cfg.host}:{conn_cfg.port} — "
                        "no network route from this host (AlloyDB is VPC-internal). "
                        "This is a connectivity failure, NOT evidence of connection "
                        "pool exhaustion on the database."
                    ) from exc
                # The pool reports a timeout for ANY connect failure — wrong
                # database, wrong password, TLS rejection — so guessing at the
                # cause produces a confident wrong story. Observed: a nonexistent
                # database name was reported as "the reader is at its connection
                # ceiling". Make one direct connection to get the real error.
                real = await _direct_connect_error(conn_cfg) if conn_cfg else None
                if real:
                    raise ExecutorError(f"{entry.name}: {real}") from exc
                raise ExecutorError(
                    f"{entry.name}: all pooled connections to {target} were busy "
                    "for 10s, and a direct connection then succeeded — which "
                    "PROVES the database is accepting connections and is NOT at "
                    "its ceiling. THIS TOOL's own pool (capped small on purpose) "
                    "was saturated by other calls in this question. Re-run the "
                    "call alone; do not report database connection exhaustion "
                    "on this evidence."
                ) from exc
            raise ExecutorError(f"{entry.name}: {type(exc).__name__}: {exc}") from exc

        rows = [dict(r) for r in rows][: entry.row_limit]
        return ExecResult(
            ok=True,
            entry_name=entry.name,
            target=target,
            rows=rows,
            duration_ms=int((self._timed() - started) * 1000),
        )
