"""Redis executor — read primitives only, per cloud.

The allowlist below is the real control on this surface, and it is deliberately
duplicated with the registry: an op that appears in YAML but not here is
refused. Two independent places would have to be wrong for a new command to
become reachable.

``KEYS`` is absent and must stay absent. It is O(N) over a production keyspace
and blocks the server for the duration. ``SCAN`` is also absent in v1; adding it
needs a hard COUNT cap and a prefix that is not attacker-chosen.

Redis is per-cloud and never replicated. The connection is selected from the
validated ``cloud`` param, and the result records which one was read so the
answer can state it.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import redis.asyncio as aioredis

from app import config
from app.executors.base import ExecResult, Executor, ExecutorError
from app.registry.schema import RegistryEntry

#: The complete set of Redis operations this system can perform. Read-only,
#: O(1) or bounded-by-key-size. Nothing here can mutate or scan the keyspace.
ALLOWED_OPS: frozenset[str] = frozenset(
    {
        "exists",
        "ttl",
        "get",
        "type",
        "smembers",
        "hgetall",
        "scard",
        "llen",
        "memory_usage",
        "info",
    }
)

#: Explicitly refused, with a reason, so the error is educational rather than a
#: generic "not allowed" when someone inevitably tries.
FORBIDDEN_OPS: dict[str, str] = {
    "keys": "KEYS is O(N) over the whole keyspace and blocks the server",
    "scan": "SCAN is not available in v1 (needs a hard COUNT cap first)",
    "flushall": "mutating",
    "flushdb": "mutating",
    "set": "mutating",
    "del": "mutating",
    "expire": "mutating",
    "eval": "arbitrary Lua execution",
    "config": "exposes credentials and permits mutation",
    "shutdown": "mutating",
    "client": "permits killing connections",
}


class RedisExecutor(Executor):
    kind = "redis"

    def __init__(self) -> None:
        self._clients: dict[str, aioredis.Redis] = {}

    def _client(self, target: str) -> aioredis.Redis:
        client = self._clients.get(target)
        if client is None:
            try:
                conn = config.REDIS_CONNECTIONS[target]
            except KeyError:
                raise ExecutorError(f"unknown redis connection: {target}") from None
            password = (
                config.secret_from_env(conn.password_env) or None
                if conn.password_env
                else None
            )
            client = aioredis.Redis(
                host=conn.host,
                port=conn.port,
                password=password,
                decode_responses=True,
                socket_connect_timeout=5,
                client_name="infragpt",
            )
            self._clients[target] = client
        return client

    async def close(self) -> None:
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()

    @staticmethod
    def _check_op(op: str | None) -> str:
        """Independent allowlist check. Runs even though the loader validated
        the YAML — the YAML is not trusted to be the last word."""
        if not op:
            raise ExecutorError("registry entry declares no redis_op")
        normalised = op.strip().lower()
        if normalised in FORBIDDEN_OPS:
            raise ExecutorError(
                f"refused redis op '{normalised}': {FORBIDDEN_OPS[normalised]}"
            )
        if normalised not in ALLOWED_OPS:
            raise ExecutorError(
                f"refused redis op '{normalised}': not in the read-only allowlist"
            )
        return normalised

    def _bind(
        self, client: aioredis.Redis, op: str, params: dict[str, Any]
    ) -> Callable[[], Any]:
        """Map an allowlisted op to a concrete, argument-checked coroutine."""
        if op == "info":
            section = str(params["section"])
            return lambda: client.info(section)

        key = params.get("key")
        if not isinstance(key, str) or not key:
            raise ExecutorError(f"redis op '{op}' requires a validated key param")
        if "*" in key or "?" in key or "[" in key:
            # Belt and braces: ParamSpec already rejects globs on KEY params.
            raise ExecutorError("refused: glob patterns are not permitted in keys")

        match op:
            case "exists":
                return lambda: client.exists(key)
            case "ttl":
                return lambda: client.ttl(key)
            case "get":
                return lambda: client.get(key)
            case "type":
                return lambda: client.type(key)
            case "smembers":
                return lambda: client.smembers(key)
            case "hgetall":
                return lambda: client.hgetall(key)
            case "scard":
                return lambda: client.scard(key)
            case "llen":
                return lambda: client.llen(key)
            case "memory_usage":
                return lambda: client.memory_usage(key)
        raise ExecutorError(f"unbound redis op: {op}")

    @staticmethod
    def _to_rows(op: str, value: Any, row_limit: int) -> list[dict[str, Any]]:
        if op == "info" and isinstance(value, dict):
            return [{"field": k, "value": v} for k, v in list(value.items())[:row_limit]]
        if op == "hgetall" and isinstance(value, dict):
            return [{"field": k, "value": v} for k, v in list(value.items())[:row_limit]]
        if op == "smembers" and isinstance(value, (set, frozenset, list, tuple)):
            members = sorted(str(m) for m in value)
            return [{"member": m} for m in members[:row_limit]]
        return [{"result": value}]

    async def run(
        self, entry: RegistryEntry, params: dict[str, Any], target: str
    ) -> ExecResult:
        if entry.kind != "redis":
            raise ExecutorError(f"{entry.name}: not a redis entry")
        op = self._check_op(entry.redis_op)

        client = self._client(target)
        call = self._bind(client, op, params)

        started = self._timed()
        try:
            value = await asyncio.wait_for(call(), timeout=entry.timeout_s)
        except TimeoutError as exc:
            raise ExecutorError(
                f"{entry.name}: timed out after {entry.timeout_s}s on {target}"
            ) from exc
        except Exception as exc:  # noqa: BLE001 - surfaced verbatim, never hidden
            raise ExecutorError(f"{entry.name}: {type(exc).__name__}: {exc}") from exc

        truncated = False
        if op in ("smembers", "hgetall") and value is not None:
            truncated = len(value) > entry.row_limit

        rows = self._to_rows(op, value, entry.row_limit)

        # If the two clouds share one Redis, say so ON EVERY READ.
        #
        # Verified in this deployment: `redis_gcp` and `redis_aws` resolve to the
        # same endpoint. A caller comparing the clouds would otherwise read the
        # same instance twice, find no difference, and report "the caches agree"
        # — a false negative dressed as a clean result. The note rides with the
        # data because the comparison happens in the model's head, where no
        # amount of documentation elsewhere can reach it.
        note = ""
        if not config.redis_clouds_are_distinct():
            note = (
                "NOTE: redis_gcp and redis_aws are THE SAME instance in this "
                "deployment. Reading both is one read, not two. You cannot "
                "compare clouds or detect cross-cloud staleness here — say that "
                "plainly instead of reporting that the clouds agree."
            )

        return ExecResult(
            ok=True,
            entry_name=entry.name,
            target=target,
            rows=rows,
            text=(f"{self._rows_text(rows)}\n\n{note}".strip() if note else ""),
            truncated=truncated,
            duration_ms=int((self._timed() - started) * 1000),
        )

    @staticmethod
    def _rows_text(rows: list[dict[str, object]]) -> str:
        if not rows:
            return "(no value)"
        keys: list[str] = []
        for row in rows:
            for key in row:
                if key not in keys:
                    keys.append(key)
        lines = [" | ".join(keys)]
        lines += [" | ".join(str(r.get(k, "")) for k in keys) for r in rows]
        return "\n".join(lines)
