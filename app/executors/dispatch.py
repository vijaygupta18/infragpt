"""Dispatch — the single door between a selected function and infrastructure.

Everything funnels through :func:`dispatch`, and the ordering here is the point:

    resolve entry -> validate params -> check grant -> resolve target
        -> execute -> cap output -> REDACT -> return

``redact_result`` is called in a ``finally``-equivalent position on the success
path, and every error path returns an ExecResult that has also been redacted.
There is deliberately **no** return statement in this module that skips
redaction — an error message can quote a Redis value or a log line, so an
unredacted error is an unredacted leak.

Callers pass a function *name* and a params dict. They cannot pass SQL, argv, or
a PromQL expression: the only executable strings in the process come from the
registry.
"""

from __future__ import annotations

from typing import Any

from app.executors.awsapi import AwsElastiCacheExecutor, AwsMetricExecutor
from app.executors.base import ExecResult, Executor, ExecutorError
from app.executors.clickhouse import ClickHouseExecutor
from app.executors.gcpapi import (
    GcpAlloyDbExecutor,
    GcpMetricExecutor,
    GcpMetricQueryExecutor,
    GcpMetricSearchExecutor,
)
from app.executors.gcpinsights import GcpInsightsExecutor
from app.executors.k8s import K8sExecutor
from app.executors.mcpapi import McpExecutor
from app.executors.pg import PgExecutor
from app.executors.promql import PromQLExecutor
from app.executors.redis import RedisExecutor
from app.executors.shell_exec import ShellExecutor
from app.executors.vmmeta import VmMetaExecutor
from app.redactor import redact_result
from app.registry.loader import Registry, get_registry, required_surface, resolve_target
from app.registry.schema import ParamValidationError, RegistryEntry, Surface


class GrantError(PermissionError):
    """Raised when the caller lacks the surface grant this call requires."""


class ExecutorRegistry:
    """Holds one executor instance per kind, so pools/clients are reused."""

    def __init__(self, **overrides: Executor) -> None:
        # sqlfree shares the SAME instance as sql, deliberately: it must draw
        # from the same 5-connection pool, or free-form queries would get their
        # own pool and the cap that stops this from exhausting a reader would
        # quietly become 10.
        pg = PgExecutor()
        clickhouse = ClickHouseExecutor()
        self._executors: dict[str, Executor] = {
            "sql": pg,
            "sqlfree": pg,
            "redis": RedisExecutor(),
            "kubectl": K8sExecutor(),
            "promql": PromQLExecutor(),
            "vmmeta": VmMetaExecutor(),
            "gcpinsights": GcpInsightsExecutor(),
            "gcpmetric": GcpMetricExecutor(),
            "gcpalloydb": GcpAlloyDbExecutor(),
            "gcpmetricsearch": GcpMetricSearchExecutor(),
            "gcpmetricquery": GcpMetricQueryExecutor(),
            "awsmetric": AwsMetricExecutor(),
            "awselasticache": AwsElastiCacheExecutor(),
            # Both ClickHouse kinds share one instance, and therefore one httpx
            # client, for the same reason sql/sqlfree share a pool: a free-form
            # query must not get its own connection budget.
            "clickhouse": clickhouse,
            "clickhousefree": clickhouse,
            "shell": ShellExecutor(),
            "mcp": McpExecutor(),
        }
        self._executors.update(overrides)

    def for_kind(self, kind: str) -> Executor:
        try:
            return self._executors[kind]
        except KeyError:
            raise ExecutorError(f"no executor for kind '{kind}'") from None

    async def close(self) -> None:
        for executor in self._executors.values():
            closer = getattr(executor, "close", None)
            if closer is not None:
                await closer()


_EXECUTORS: ExecutorRegistry | None = None


def get_executors() -> ExecutorRegistry:
    global _EXECUTORS
    if _EXECUTORS is None:
        _EXECUTORS = ExecutorRegistry()
    return _EXECUTORS


def _failure(entry_name: str, target: str, message: str) -> ExecResult:
    """Build a failed result. Redacted like any other, because error text can
    quote infrastructure output."""
    result = ExecResult(ok=False, entry_name=entry_name, target=target, error=message)
    result.cap_output()
    return redact_result(result)


# Reserved params, handled by dispatch rather than by any executor.
GREP_PARAM = "grep"
GREP_CONTEXT_PARAM = "grep_context"
MAX_GREP_LINES = 500


def apply_grep(result: ExecResult, needle: str, context: int = 0) -> ExecResult:
    """Keep only lines containing `needle`, plus optional context lines.

    Three deliberate choices:

    * **Post-filter, not a pipe.** This runs in Python on output already
      returned. There is no shell, so no `|`, no subshell, and no new way to
      compose a command — the containment property is untouched.
    * **Literal substring, not a regex.** An LLM-supplied regex is a ReDoS
      waiting to happen against a large log, and "find the specific thing" is a
      substring search in practice. Predictable beats clever here.
    * **Runs before redaction** (dispatch calls it first), so a search for a
      phone number cannot be used to confirm a value that redaction would then
      hide. The filter sees what the executor returned; the caller still only
      ever sees the redacted result.
    """
    if not result.text or not needle:
        return result
    lines = result.text.splitlines()
    keep: set[int] = set()
    for i, line in enumerate(lines):
        if needle in line:
            lo = max(0, i - context)
            hi = min(len(lines), i + context + 1)
            keep.update(range(lo, hi))
    if not keep:
        result.text = (
            f"No lines matched {needle!r} in {len(lines)} lines of output. "
            "The output was searched and genuinely contained no match — this is "
            "not a failed call."
        )
        return result
    ordered = sorted(keep)
    truncated = len(ordered) > MAX_GREP_LINES
    shown = ordered[:MAX_GREP_LINES]
    out = [lines[i] for i in shown]
    header = f"[{len(ordered)} of {len(lines)} lines matched {needle!r}]"
    if truncated:
        header += f" [showing first {MAX_GREP_LINES}]"
        result.truncated = True
    result.text = header + "\n" + "\n".join(out)
    return result


async def dispatch(
    name: str,
    params: dict[str, Any] | None = None,
    *,
    granted_surfaces: set[Surface] | None = None,
    registry: Registry | None = None,
    executors: ExecutorRegistry | None = None,
) -> ExecResult:
    """Run one registry function. The only path from a name to infrastructure.

    `granted_surfaces` is re-checked here even though selection already filtered
    the LLM's options — grants are enforced twice on purpose, because the first
    check is about what gets *offered* and this one is about what gets *run*.
    Pass ``None`` only for trusted internal callers (e.g. the `infractl call`
    admin path), never for an LLM-selected call.

    Returns an ExecResult that is ALWAYS redacted, on success and on failure.
    """
    registry = registry or get_registry()
    executors = executors or get_executors()
    params = dict(params or {})

    try:
        entry: RegistryEntry = registry.get(name)
    except KeyError as exc:
        return _failure(name, "", str(exc))

    try:
        validated = entry.validate_params(params)
    except ParamValidationError as exc:
        return _failure(entry.name, entry.target, f"parameter rejected: {exc}")

    if granted_surfaces is not None:
        try:
            needed = required_surface(entry, validated)
        except Exception as exc:  # noqa: BLE001 - registry bug, reported not raised
            return _failure(entry.name, entry.target, str(exc))
        if needed not in granted_surfaces:
            # WHY it is unavailable decides what the user should do, and getting
            # it wrong wastes their time: this reported "requires the
            # 'k8s:aws' grant" to someone who HELD that grant — the surface was
            # simply not configured in this deployment. They would have gone and
            # asked an admin for access they already had.
            from app.registry.loader import unavailable_surfaces

            if needed in unavailable_surfaces():
                return _failure(
                    entry.name,
                    entry.target,
                    f"unavailable: the '{needed.value}' surface is not configured "
                    f"in this deployment, so nothing can reach it. This is not a "
                    f"permissions problem and asking for access will not help. "
                    f"Report it as unavailable and answer for the surfaces that "
                    f"do work, naming which one you could not check.",
                )
            return _failure(
                entry.name,
                entry.target,
                f"denied: this call requires the '{needed.value}' grant, which "
                f"this user does not hold. An admin can grant it.",
            )

    try:
        target = resolve_target(entry, validated)
    except Exception as exc:  # noqa: BLE001 - surfaced, never hidden
        return _failure(entry.name, entry.target, str(exc))

    # Reserved filter params never reach an executor: they describe what to do
    # with output, not what to run.
    needle = validated.pop(GREP_PARAM, None)
    context = validated.pop(GREP_CONTEXT_PARAM, None) or 0

    try:
        executor = executors.for_kind(entry.kind)
        result = await executor.run(entry, validated, target)
        if needle:
            result = apply_grep(result, str(needle), int(context))
    except ExecutorError as exc:
        return _failure(entry.name, target, str(exc))
    except Exception as exc:  # noqa: BLE001 - never let a raw traceback escape
        return _failure(entry.name, target, f"{type(exc).__name__}: {exc}")

    result.cap_output()
    return redact_result(result)


__all__ = ["ExecutorRegistry", "GrantError", "dispatch", "get_executors"]
