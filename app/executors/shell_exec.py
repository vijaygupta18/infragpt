"""Read-only command execution — the agentic escape hatch.

Everything else here is a pre-registered function. This is the one place the
model composes a command itself, and it exists because a registry can never
cover every question. The observed failure: asked which errors were frequent in
the driver app, it listed the pods, ran out of registered ways to proceed, and
asked the user to paste the logs in — with `pod_logs` sitting unused.

WHY THIS IS DEFENSIBLE HERE, having been argued against elsewhere:

1. **The pod cannot write.** Five ``*.viewer`` GCP roles, a ``get/list/watch``
   ServiceAccount excluding Secrets and ConfigMaps, and ``readonly_db_user``
   (SELECT-only) against physical replicas where writes are impossible. Even
   total failure of everything below cannot mutate infrastructure. That is the
   control that matters; the rest reduce blast radius.
2. **No shell.** The command is split with ``shlex`` and run via
   ``create_subprocess_exec`` as an argv list. There is no ``|``, ``;``,
   ``$( )``, redirection or globbing, because no shell interprets it.
3. **The guard** (``app/shell/guard.py``, 94 adversarial tests) permits six
   binaries and only their read verbs, and refuses reads that leak credentials —
   ``kubectl get secret`` is a read, and it is blocked.
4. **Grant-gated and audited.** Requires ``shell:read``, which no role carries
   by default, and every invocation is audited like any other call.

The model is expected to get commands wrong and correct them. A refusal or a
non-zero exit comes back as a normal failed result **with the tool's own error
text attached**, so the next round can fix it. That feedback loop is the whole
point of composing commands rather than selecting them.
"""

from __future__ import annotations

import asyncio
import shlex
from typing import Any

from app.executors.base import MAX_OUTPUT_BYTES, ExecResult, Executor, ExecutorError
from app.registry.schema import RegistryEntry
from app.shell.guard import CommandRefused, check

#: Exit codes whose meaning is worth stating when a command produced no output.
#: Only the ones that actually occur here, each with the next step rather than
#: just a definition — the point is to make the failure correctable.
_CURL_EXITS = {
    3: "malformed URL.",
    6: (
        "could not resolve the host. That service name does not exist in this "
        "cluster. Do NOT guess hostnames — use a registered function for this "
        "data, or find the real name first. Metrics are served by "
        "VictoriaMetrics, not by a host called `prometheus`."
    ),
    7: "connected to nothing at that host and port — wrong port, or nothing listening.",
    22: "the server returned an HTTP error (>=400). Re-run without -f to see the body.",
    28: "timed out. The endpoint is reachable but slow, or the port is filtered.",
    35: "TLS handshake failed — likely http vs https, or an untrusted certificate.",
    60: "certificate could not be verified.",
}

_GENERIC_EXITS = {
    1: "general error, and the command printed nothing. Re-run without -q/-s to see why.",
    2: "usage error — a flag or argument is wrong for this version of the tool.",
    126: "found but not executable.",
    127: "command not found in this container.",
    130: "interrupted.",
}


#: Where to go when a CLI is not installed. The capability usually EXISTS — it
#: is reached through the cloud REST APIs directly, which needs no CLI — so a
#: bare "not available" sends the model away from something it can do.
#:
#: Verified in this container 2026-08-21: kubectl, psql, redis-cli and curl are
#: present; gcloud and aws are NOT. The model reaches for them anyway, because
#: they are the obvious tools, and every attempt costs a call.
_MISSING_ALTERNATIVES = {
    "gcloud": (
        "GCP is reached through the REST API instead, and those functions are "
        "already in your list: alloydb_instances / alloydb_cpu / "
        "alloydb_connections for AlloyDB, gcp_metric_search + gcp_metric_query "
        "for any metric, query_insights_top / _io / _locks for per-query "
        "database time. Use those — do not try another gcloud form."
    ),
    "aws": (
        "AWS is reached through the REST API instead: elasticache_instances and "
        "the elasticache_* metric functions are in your list and work. Do not "
        "retry with a different aws subcommand."
    ),
}


def _missing_binary(binary: str) -> str:
    name = binary.rsplit("/", 1)[-1]
    hint = _MISSING_ALTERNATIVES.get(name)
    base = f"{name} is not installed in this container"
    return f"{base}. {hint}" if hint else (
        f"{base}, and there is no equivalent function. Say so plainly rather "
        f"than retrying — the command cannot succeed here."
    )


def _explain_exit(binary: str, code: int) -> str:
    """Say what a silent non-zero exit means, and what to do about it.

    Quiet flags (`curl -s`, `kubectl -q`) suppress the tool's own diagnostics,
    so without this the model receives an integer and nothing else.
    """
    name = binary.rsplit("/", 1)[-1]
    if name == "curl" and code in _CURL_EXITS:
        return f"curl: {_CURL_EXITS[code]} (no output — `-s` suppresses curl's own message)"
    if code in _GENERIC_EXITS:
        return f"{name}: {_GENERIC_EXITS[code]}"
    return f"{name} failed with no output. Re-run without quiet flags to see the error."


class ShellExecutor(Executor):
    kind = "shell"

    async def run(
        self, entry: RegistryEntry, params: dict[str, Any], target: str
    ) -> ExecResult:
        started = self._timed()
        raw = str(params.get("command") or "").strip()
        if not raw:
            raise ExecutorError(f"{entry.name}: `command` is required")

        def failed(error: str) -> ExecResult:
            return ExecResult(
                ok=False,
                entry_name=entry.name,
                target=target,
                error=error,
                duration_ms=int((self._timed() - started) * 1000),
            )

        try:
            # shlex quotes WITHOUT a shell: `-o "custom-columns=A:.x"` survives as
            # one argv element, while `a; rm -rf /` becomes literal arguments that
            # the guard then rejects.
            argv = shlex.split(raw)
        except ValueError as exc:
            return failed(f"could not parse the command ({exc}). Check the quoting.")

        try:
            check(argv)
        except CommandRefused as exc:
            # A refusal is a RESULT, not an exception. The model needs to see why
            # so the next round can propose something permitted; raising would
            # abandon the whole question over a fixable mistake.
            return failed(
                f"refused: {exc}\n"
                "This tool is read-only. Rewrite using a read verb, or use a "
                "registered function instead."
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except FileNotFoundError:
            return failed(_missing_binary(argv[0]))

        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=entry.timeout_s)
        except TimeoutError:
            proc.kill()
            return failed(
                f"timed out after {entry.timeout_s}s. Narrow the command — add a "
                "namespace, a label selector, or a smaller --since."
            )

        text = (out or b"").decode(errors="replace")
        if proc.returncode != 0:
            # Keep the tool's own words. "context does not exist", "NotFound",
            # "unknown flag" are precisely what lets the next round self-correct.
            detail = text.strip()[:400]
            if not detail:
                # A SILENT failure is the worst kind here. Observed live: the
                # model ran `curl -s` against a host that does not exist; -s
                # suppressed curl's own message, so the only signal was
                # "exited 6: (no output)" — a bare number it could not act on.
                # It retried the same idea and gave up. Translating the exit
                # code is what turns a dead end back into something correctable.
                detail = _explain_exit(argv[0], proc.returncode)
            return failed(f"exited {proc.returncode}: {detail}")

        oversized = len(text.encode()) > MAX_OUTPUT_BYTES
        result = ExecResult(
            ok=True,
            entry_name=entry.name,
            target=target,
            text=text,
            duration_ms=int((self._timed() - started) * 1000),
        )
        result.cap_output()
        if oversized:
            result.text += "\n[output truncated — narrow the command for the full picture]"
        return result
