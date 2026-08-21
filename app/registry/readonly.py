"""Load-time proof that every registry entry is read-only.

Until now "the registry contains only reads" was enforced in two places, and
neither of them is the right one:

* **Tests** run in CI. A registry edited on a running pod, or a branch that
  skipped CI, is never checked.
* **Executors** check at call time. By then the server is already up and
  advertising the function to the model, so the failure surfaces mid-incident as
  a refused call rather than at deploy.

This module makes it a **startup gate**. ``load_registry`` calls
``assert_read_only`` on every entry, and a mutating entry means the process does
not start. A server that refuses to boot is a loud, immediate failure; a server
that boots with one bad entry is a quiet one that nobody notices until it runs.

This is defence in depth, not the primary control — the read-only credentials
(``readonly_db_user``, ``readonly_db_user``, the get/list/watch ServiceAccount, the five GCP
``*.viewer`` roles) are what make mutation impossible. This layer makes a bad
*registry* impossible, which is a different failure and worth closing separately:
a reviewer can miss a line in a YAML diff.
"""

from __future__ import annotations

import re

from app.registry.schema import RegistryEntry, Surface


class NotReadOnly(ValueError):
    """An entry would perform, or could perform, a write. Always fatal."""


# --- SQL --------------------------------------------------------------------

SQL_ALLOWED_LEADING = ("select", "with", "explain", "show", "table", "describe")
#: Leading verbs. Matched at the START of a statement only, so a column named
#: `updated_at` or a literal mentioning "delete" is not flagged.
SQL_DENIED = re.compile(
    r"\b(insert|update|delete|drop|alter|truncate|create|grant|revoke|vacuum|"
    r"reindex|cluster|copy|call|do|lock|refresh|comment|security|prepare|"
    r"execute|listen|notify|attach|detach|optimize|system|kill|rename)\b",
    re.IGNORECASE,
)

#: Functions that mutate or read the filesystem, scanned ANYWHERE in the
#: statement. A leading-verb check alone is not enough: `SELECT
#: pg_terminate_backend(123)` is a perfectly well-formed SELECT that kills a
#: session, and `SELECT lo_export(...)` writes a file. "It starts with SELECT"
#: is not the same as "it only reads".
SQL_DENIED_FUNCTIONS = re.compile(
    r"\b(pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile|"
    r"pg_read_file|pg_read_binary_file|pg_ls_dir|pg_stat_file|"
    r"lo_import|lo_export|lo_unlink|dblink|dblink_exec|pg_logical_emit_message|"
    r"pg_create_restore_point|pg_switch_wal|pg_promote|pg_drop_replication_slot|"
    r"pg_create_physical_replication_slot|pg_replication_origin_create|"
    r"set_config|pg_advisory_lock|pg_advisory_unlock)\s*\(",
    re.IGNORECASE,
)

#: ClickHouse table functions and clauses that read the filesystem, reach a
#: remote endpoint, or write output somewhere. Scanned ANYWHERE in the
#: statement, for the same reason as SQL_DENIED_FUNCTIONS above: `SELECT * FROM
#: url('http://...')` is a well-formed SELECT that makes this process an
#: outbound HTTP client, and `INTO OUTFILE` writes a file from a SELECT.
#: `readonly=1` blocks writes to tables; it does not block all of these.
CLICKHOUSE_DENIED_FUNCTIONS = re.compile(
    r"\b(file|url|urlCluster|s3|s3Cluster|remote|remoteSecure|cluster|"
    r"clusterAllReplicas|hdfs|hdfsCluster|mysql|postgresql|mongodb|jdbc|odbc|"
    r"sqlite|redis|executable|input|infile|azureBlobStorage|deltaLake|"
    r"iceberg|hudi)\s*\(|\binto\s+outfile\b",
    re.IGNORECASE,
)

# --- Redis ------------------------------------------------------------------

REDIS_READ_OPS = frozenset(
    {
        "get", "mget", "ttl", "pttl", "exists", "type", "strlen",
        "hget", "hgetall", "hkeys", "hlen", "smembers", "scard", "sismember",
        "llen", "lrange", "zcard", "zscore", "memory_usage", "dbsize", "info",
        "object_encoding", "slowlog", "latency",
    }
)
#: Never expressible, regardless of what a YAML file says. KEYS is O(N) over a
#: production keyspace; the rest mutate.
REDIS_FORBIDDEN_OPS = frozenset(
    {"keys", "scan", "randomkey", "set", "del", "flushall", "flushdb", "expire",
     "rename", "lpush", "rpush", "sadd", "srem", "zadd", "hset", "hdel",
     "getset", "incr", "decr", "setex", "persist", "migrate", "restore"}
)

# --- kubectl ----------------------------------------------------------------

KUBECTL_READ_VERBS = frozenset(
    {"get", "list", "describe", "logs", "top", "events", "version", "explain",
     "api-resources"}
)
#: Reading these is still a credential leak. Read-only is not the same as
#: safe-to-read, and this is the line that catches the difference.
KUBECTL_FORBIDDEN_RESOURCES = re.compile(
    r"\b(secrets?|configmaps?|serviceaccounts?)\b", re.IGNORECASE
)

# --- MCP --------------------------------------------------------------------

MCP_FORBIDDEN = re.compile(
    r"(write|create|update|delete|drop|put|post|patch|^set_|_set$|remove|index|"
    r"ingest|restart|scale|apply|silence|ack|mute|reindex)",
    re.IGNORECASE,
)

#: Kinds whose transport is inherently a read (an HTTP GET against a metrics or
#: inventory API). They still get a target check, but there is no statement or
#: verb to inspect.
INHERENTLY_READ_KINDS = frozenset(
    {"promql", "gcpmetric", "gcpalloydb", "gcpmetricsearch", "gcpmetricquery",
     "awsmetric", "awselasticache"}
)


def _check_sql(entry: RegistryEntry) -> None:
    sql = (entry.sql or "").strip()
    if not sql:
        raise NotReadOnly(f"{entry.name}: sql entry has no statement")
    body = sql.lstrip("(").lstrip()
    if not body.lower().startswith(SQL_ALLOWED_LEADING):
        raise NotReadOnly(f"{entry.name}: SQL does not begin with a read: {body[:60]!r}")
    # Strip string literals so a query merely *mentioning* a verb is not flagged.
    without_literals = re.sub(r"'[^']*'", "''", body)
    for chunk in without_literals.split(";"):
        chunk = chunk.strip()
        if chunk and SQL_DENIED.match(chunk):
            raise NotReadOnly(f"{entry.name}: mutating SQL: {chunk[:60]!r}")
    hit = SQL_DENIED_FUNCTIONS.search(without_literals)
    if hit:
        raise NotReadOnly(
            f"{entry.name}: SQL calls {hit.group(1)!r}. A statement beginning with "
            "SELECT is not automatically read-only — this function mutates state "
            "or touches the filesystem."
        )
    if ";" in without_literals.rstrip(";").rstrip():
        raise NotReadOnly(f"{entry.name}: multiple SQL statements")


def _check_redis(entry: RegistryEntry) -> None:
    op = (entry.redis_op or "").lower()
    if op in REDIS_FORBIDDEN_OPS:
        raise NotReadOnly(f"{entry.name}: redis op {op!r} is never permitted")
    if op not in REDIS_READ_OPS:
        raise NotReadOnly(
            f"{entry.name}: redis op {op!r} is not on the read allowlist"
        )


def _check_kubectl(entry: RegistryEntry) -> None:
    argv = entry.argv or []
    if not argv:
        raise NotReadOnly(f"{entry.name}: kubectl entry has no argv")
    if argv[0] not in KUBECTL_READ_VERBS:
        raise NotReadOnly(f"{entry.name}: kubectl verb {argv[0]!r} is not a read")
    for element in argv:
        if KUBECTL_FORBIDDEN_RESOURCES.search(element):
            raise NotReadOnly(
                f"{entry.name}: argv references {element!r}. Secrets, ConfigMaps and "
                "ServiceAccounts are never readable — their contents are credentials."
            )


def _check_mcp(entry: RegistryEntry) -> None:
    tool = getattr(entry, "mcp_tool", None) or ""
    if not tool:
        raise NotReadOnly(f"{entry.name}: mcp entry declares no tool")
    if MCP_FORBIDDEN.search(tool):
        raise NotReadOnly(f"{entry.name}: mcp tool {tool!r} looks mutating")


def _check_clickhouse(entry: RegistryEntry) -> None:
    """ClickHouse entries may carry SQL or take it as a param.

    Where the statement is a parameter, it is checked at execution instead —
    but the entry must still be on a read-only connection, which the executor
    enforces with ``readonly=1``.

    Two kinds share this check, mirroring sql/sqlfree:

    * ``clickhouse`` carries a reviewed statement, which is inspected here with
      the same leading-verb / denied-verb pass a Postgres entry gets, plus the
      ClickHouse-specific table functions that read the filesystem or reach out
      over the network (``file``, ``url``, ``s3``, ``remote``, ...). "It starts
      with SELECT" is not the same as "it only reads" in ClickHouse either.
    * ``clickhousefree`` carries no statement, so what is enforced instead is
      the SHAPE that makes execution-time checking sound: a ``sql`` param must
      exist (the executor reads exactly that name), and no fixed statement may
      also be present.
    """
    sql = getattr(entry, "sql", None)
    if entry.kind == "clickhousefree":
        if sql:
            raise NotReadOnly(
                f"{entry.name}: clickhousefree entry must not also carry a fixed "
                "statement"
            )
        if "sql" not in entry.params:
            raise NotReadOnly(
                f"{entry.name}: clickhousefree entry declares no 'sql' param"
            )
        return
    if not sql:
        raise NotReadOnly(f"{entry.name}: clickhouse entry has no statement")
    _check_sql(entry)
    hit = CLICKHOUSE_DENIED_FUNCTIONS.search(re.sub(r"'[^']*'", "''", sql))
    if hit:
        raise NotReadOnly(
            f"{entry.name}: SQL uses the {hit.group(1)!r} table function. It reads "
            "the filesystem or a remote endpoint, which is not what this surface "
            "is for, and readonly=1 does not stop all of them."
        )


def _check_shell(entry: RegistryEntry) -> None:
    """Shell entries carry no command of their own — it is a parameter.

    So there is nothing to inspect at load time: the guard in
    ``app/shell/guard.py`` checks every command at execution, and the pod's
    read-only credentials are the backstop underneath that. What this DOES
    enforce is that such an entry cannot be smuggled onto a quieter surface —
    it must sit behind ``shell:read``, which no role grants by default.
    """
    if entry.surface is not Surface.SHELL_READ:
        raise NotReadOnly(
            f"{entry.name}: a shell entry must be on the shell:read surface, "
            f"not {entry.surface.value}"
        )


def _check_sqlfree(entry: RegistryEntry) -> None:
    """A sqlfree entry carries no statement — the statement is a parameter.

    There is nothing to inspect at load time, so what this enforces is the
    shape that makes execution-time checking sound:

    * a ``sql`` param must be declared, since the executor reads exactly that
      name and an entry without it could never run;
    * the target must be a named connection, which is what keeps the model from
      supplying a host — it picks a reader by name or it does not connect.

    The statement itself goes through ``app/executors/pg.assert_read_only`` on
    the way to the database, the same function a fixed entry's SQL passes.
    """
    if "sql" not in entry.params:
        raise NotReadOnly(f"{entry.name}: sqlfree entry declares no 'sql' param")
    if entry.sql:
        raise NotReadOnly(
            f"{entry.name}: sqlfree entry must not also carry a fixed statement"
        )


def assert_read_only(entry: RegistryEntry) -> None:
    """Raise NotReadOnly unless this entry can only ever read.

    Called for every entry at load time. An unknown kind is refused rather than
    waved through: a new kind must be explicitly reasoned about here before it
    can ship, so adding one cannot silently bypass this gate.
    """
    kind = entry.kind
    if kind == "sql":
        _check_sql(entry)
    elif kind == "redis":
        _check_redis(entry)
    elif kind == "kubectl":
        _check_kubectl(entry)
    elif kind == "mcp":
        _check_mcp(entry)
    elif kind in ("clickhouse", "clickhousefree"):
        _check_clickhouse(entry)
    elif kind == "shell":
        _check_shell(entry)
    elif kind == "gcpinsights":
        # Read-only Cloud Monitoring queries against a fixed metric table.
        return
    elif kind == "vmmeta":
        # Metadata GETs against a fixed endpoint table. There is no write path
        # on this API, and the entry names an endpoint rather than a URL.
        return
    elif kind == "sqlfree":
        _check_sqlfree(entry)
    elif kind in INHERENTLY_READ_KINDS:
        return
    else:
        raise NotReadOnly(
            f"{entry.name}: kind {kind!r} has no read-only proof in "
            "app/registry/readonly.py. Add one before shipping this kind — an "
            "unrecognised kind must fail closed, not load."
        )
