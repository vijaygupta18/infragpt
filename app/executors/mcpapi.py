"""MCP executor — named tool calls against the in-cluster MCP servers.

The team already runs MCP servers for VictoriaMetrics, Grafana and OpenSearch in
both clouds. Those servers advertise a full tool catalogue, and several of those
tools mutate. This executor deliberately does **not** consume that catalogue.

Two independent containment rules:

1. **Registry allowlist.** An MCP call is permitted only if some reviewed
   registry entry names that exact tool (``mcp_tool:``). The set of callable
   tools is therefore a property of this repo's git history, not of whatever the
   server happens to expose today. An MCP server upgrade that ships
   ``delete_index`` cannot widen what infragpt can do.
2. **Read-only denylist.** A hard pattern list of mutating verbs is refused
   regardless of registry contents — defence in depth, so that a careless
   registry edit still cannot produce a write.

Params are validated by us (``RegistryEntry.validate_params``) against the
entry's own ParamSpecs before anything is sent. Arbitrary JSON authored by the
LLM never reaches an MCP server.

Transport is streamable-http JSON-RPC 2.0: a POST whose response is either a
plain JSON body or an SSE-framed stream of ``data:`` lines. Both are handled.
"""

from __future__ import annotations

import json
import re
from itertools import count
from typing import Any

import httpx

from app import config
from app.executors.base import ExecResult, Executor, ExecutorError
from app.registry.schema import RegistryEntry

#: Tool-name substrings that must never be invoked, whatever the registry says.
#: Matched case-insensitively against the whole tool name.
DENY_PATTERN = re.compile(
    r"(write|create|update|delete|drop|put|post|patch|set|remove|index|ingest|"
    r"restart|scale|apply|silence|ack)",
    re.IGNORECASE,
)

#: Params that select the connection rather than describe the query, and so are
#: never forwarded to the server as tool arguments.
_TARGET_ONLY_PARAMS = frozenset({"cloud"})

_ids = count(1)


def _conn(target: str) -> config.McpConnection:
    try:
        return config.MCP_CONNECTIONS[target]
    except KeyError:
        raise ExecutorError(f"unknown mcp connection: {target}") from None


def assert_read_only(tool: str) -> None:
    """Refuse any tool whose name matches a mutating verb.

    Deliberately blunt: a false positive is a registry entry that must be
    renamed upstream or dropped, which is a far cheaper outcome than a write
    reaching production.
    """
    match = DENY_PATTERN.search(tool)
    if match:
        raise ExecutorError(
            f"refused: mcp tool '{tool}' matches the read-only denylist "
            f"('{match.group(1)}'). infragpt has no mutation path."
        )


def allowed_tools(registry: Any = None) -> set[str]:
    """Every tool name any loaded entry declares, primary names and aliases.

    Aliases are included deliberately: they are reviewed registry content, not
    something a server can introduce. The invariant is unchanged — the registry
    decides what is callable, and a tool a server advertises but no entry names
    stays uncallable.
    """
    # Imported here, not at module scope: the registry loader imports executors
    # to resolve kinds, so a top-level import closes the cycle.
    from app.registry.loader import get_registry

    reg = registry if registry is not None else get_registry()
    names: set[str] = set()
    for entry in reg.all_entries():
        if entry.kind != "mcp":
            continue
        if entry.mcp_tool:
            names.add(entry.mcp_tool)
        names.update(entry.mcp_tool_aliases or [])
    return names


# MCP servers have no standard code for "no such tool", so this matches on the
# message. Deliberately narrow: a false positive costs one extra tools/list and
# a retry under a name the registry already declares, and a false negative just
# means the original error is reported, which is the current behaviour anyway.
_PROTOCOL_VERSION = "2025-03-26"
_BASE_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "MCP-Protocol-Version": _PROTOCOL_VERSION,
}

_UNKNOWN_TOOL_RE = re.compile(
    r"(unknown|unsupported|not found|no such|unrecognized|invalid)[^.]{0,40}tool"
    r"|tool[^.]{0,40}(not found|unknown|does not exist|not supported)"
    r"|method not found",
    re.IGNORECASE,
)


def _looks_like_unknown_tool(message: str) -> bool:
    return bool(_UNKNOWN_TOOL_RE.search(message))


def _render(node: Any, params: dict[str, Any]) -> Any:
    """Fill "$param" placeholders in a template, by whole value.

    A string that is EXACTLY "$name" is replaced by that param's value, keeping
    its type — so an int stays an int and a nested object stays an object.
    Placeholders are never spliced into surrounding text, which is what stops a
    param from injecting structure into the query it sits inside.

    A branch whose placeholder resolves to None is dropped, so optional params
    simply omit their clause instead of sending a null the server rejects.
    """
    if isinstance(node, str) and node.startswith("$"):
        return params.get(node[1:])
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            rendered = _render(value, params)
            if rendered is not None:
                out[key] = rendered
        return out or None
    if isinstance(node, list):
        items = [_render(v, params) for v in node]
        return [i for i in items if i is not None]
    return node


def _tool_arguments(entry: RegistryEntry, params: dict[str, Any]) -> dict[str, Any]:
    """Build the arguments object from *validated* params only.

    Only params the entry itself declares can appear, because ``params`` has
    already passed ``validate_params`` (which rejects unknown keys). Unset
    optionals are dropped rather than sent as null — an explicit null means
    something different to several of these servers.
    """
    if entry.mcp_arguments is not None:
        return _render(entry.mcp_arguments, params) or {}
    return {
        name: value
        for name, value in params.items()
        if name in entry.params
        and name not in _TARGET_ONLY_PARAMS
        and value is not None
    }


def _rows_from_text(text: str, limit: int) -> list[dict[str, Any]]:
    """Extract row-shaped data from a JSON text payload.

    Handles the shapes these servers actually return, and gives up quietly on
    anything else — a failure to parse must leave the text untouched rather than
    lose the result.

    Elasticsearch hits are FLATTENED out of ``_source``: the fields worth
    reading (request_id, response_code, path, log_message) live inside it, and
    leaving them nested means every one is quoted twice in the output.
    """
    stripped = (text or "").strip()
    if not stripped.startswith(("{", "[")):
        return []
    try:
        data = json.loads(stripped)
    except (ValueError, TypeError):
        return []

    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)][:limit]
    if not isinstance(data, dict):
        return []

    for key in ("hits", "indices", "rows", "results", "data", "items"):
        candidate = data.get(key)
        if isinstance(candidate, dict):  # e.g. {"hits": {"hits": [...]}}
            candidate = candidate.get("hits")
        if isinstance(candidate, list):
            out: list[dict[str, Any]] = []
            for item in candidate[:limit]:
                if not isinstance(item, dict):
                    continue
                source = item.get("_source")
                if isinstance(source, dict):
                    merged = dict(source)
                    if "_index" in item:
                        merged["_index"] = item["_index"]
                    out.append(merged)
                else:
                    out.append(item)
            return out
    return []


def parse_body(text: str, content_type: str) -> dict[str, Any]:
    """Parse a JSON-RPC response body, plain JSON or SSE-framed.

    Streamable-http servers may answer the same POST either way, so the caller
    cannot assume. For SSE the LAST complete ``data:`` payload carrying a
    JSON-RPC ``result``/``error`` is the response.
    """
    if "text/event-stream" in (content_type or "").lower() or text.lstrip().startswith(
        "event:"
    ):
        payload: dict[str, Any] | None = None
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            chunk = line[len("data:") :].strip()
            if not chunk or chunk == "[DONE]":
                continue
            try:
                parsed = json.loads(chunk)
            except ValueError:
                continue
            if isinstance(parsed, dict) and ("result" in parsed or "error" in parsed):
                payload = parsed
        if payload is None:
            raise ExecutorError("mcp server returned an SSE stream with no JSON-RPC result")
        return payload

    try:
        parsed = json.loads(text)
    except ValueError as exc:
        raise ExecutorError(f"mcp server returned non-JSON: {text[:200]}") from exc
    if not isinstance(parsed, dict):
        raise ExecutorError("mcp server returned a non-object JSON-RPC body")
    return parsed


def _content_text(result: dict[str, Any]) -> str:
    """Flatten ``result.content[]`` text blocks into one string."""
    blocks = result.get("content")
    if not isinstance(blocks, list):
        return ""
    parts: list[str] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        if block.get("type") in (None, "text") and isinstance(block.get("text"), str):
            parts.append(block["text"])
        elif isinstance(block.get("json"), (dict, list)):
            parts.append(json.dumps(block["json"], default=str))
    return "\n".join(parts).strip()


class McpExecutor(Executor):
    """JSON-RPC ``tools/call`` against a named MCP connection."""

    kind = "mcp"

    def __init__(self, registry: Any = None, client: httpx.AsyncClient | None = None) -> None:
        self._registry = registry
        # (target, entry name) -> the tool name that server actually has.
        self._resolved: dict[tuple[str, str], str] = {}
        # Connection name -> MCP session id (None where the server is sessionless).
        self._sessions: dict[str, str | None] = {}
        self._client = client

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient()
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _initialize(self, conn: config.McpConnection, timeout_s: int) -> str | None:
        """Perform the MCP handshake and return the session id, if any.

        REQUIRED, not optional. A streamable-http server answers anything sent
        before `initialize` with "Bad Request: first request must be an
        initialize request" — which is what every log call was getting in
        production, so the entire logs surface was dead while looking merely
        misconfigured.

        The session id comes back as a header and must be echoed on every
        subsequent request. Servers that do not use sessions return none, and
        omitting the header is then correct.

        Cached per connection for the process. Re-handshaking on every call
        would double the request count for no benefit.
        """
        if conn.name in self._sessions:
            return self._sessions[conn.name]

        client = await self._get_client()
        handshake = {
            "jsonrpc": "2.0",
            "id": next(_ids),
            "method": "initialize",
            "params": {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "infragpt", "version": "1"},
            },
        }
        try:
            response = await client.post(
                conn.endpoint, json=handshake, headers=_BASE_HEADERS, timeout=timeout_s
            )
        except httpx.HTTPError as exc:
            raise ExecutorError(f"mcp server {conn.name} unreachable: {exc}") from exc
        if response.status_code >= 400:
            raise ExecutorError(
                f"mcp server {conn.name} refused initialize: HTTP "
                f"{response.status_code}: {response.text[:200]}"
            )

        session = response.headers.get("mcp-session-id")
        headers = dict(_BASE_HEADERS)
        if session:
            headers["Mcp-Session-Id"] = session
        # Best-effort: some servers require the notification, others ignore it,
        # and none of them fail the session if it does not arrive.
        try:
            await client.post(
                conn.endpoint,
                json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                headers=headers,
                timeout=timeout_s,
            )
        except httpx.HTTPError:
            pass

        self._sessions[conn.name] = session
        return session

    async def _rpc(
        self, conn: config.McpConnection, method: str, params: dict[str, Any], timeout_s: int
    ) -> dict[str, Any]:
        session = (
            await self._initialize(conn, timeout_s) if method != "initialize" else None
        )
        body = {
            "jsonrpc": "2.0",
            "id": next(_ids),
            "method": method,
            "params": params,
        }
        client = await self._get_client()
        try:
            response = await client.post(
                conn.endpoint,
                json=body,
                headers=(
                    {**_BASE_HEADERS, "Mcp-Session-Id": session}
                    if session
                    else dict(_BASE_HEADERS)
                ),
                timeout=timeout_s,
            )
        except httpx.HTTPError as exc:
            raise ExecutorError(f"mcp server {conn.name} unreachable: {exc}") from exc

        if response.status_code >= 400:
            raise ExecutorError(
                f"mcp server {conn.name} returned HTTP {response.status_code}: "
                f"{response.text[:300]}"
            )

        payload = parse_body(response.text, response.headers.get("content-type", ""))
        if "error" in payload and payload["error"] is not None:
            err = payload["error"]
            message = err.get("message") if isinstance(err, dict) else str(err)
            raise ExecutorError(f"mcp server {conn.name} error: {message}")
        result = payload.get("result")
        if not isinstance(result, dict):
            raise ExecutorError(f"mcp server {conn.name} returned no result object")
        return result

    async def list_tools(self, target: str, timeout_s: int = 20) -> list[dict[str, Any]]:
        """Diagnostic ONLY — never on the LLM path.

        What a server advertises is not what infragpt may call; that is decided
        by the registry. This exists so an operator can compare the two and see
        which registry tool names have drifted.
        """
        conn = _conn(target)
        result = await self._rpc(conn, "tools/list", {}, timeout_s)
        tools = result.get("tools")
        return tools if isinstance(tools, list) else []

    async def _alias_for(
        self, entry: RegistryEntry, target: str, timeout_s: int
    ) -> str | None:
        """Find a declared alias the server actually advertises.

        Consulted ONLY after a call has already failed as an unknown tool, so
        the common path costs nothing. Resolution is then cached per
        (target, entry): servers do not rename tools mid-incident, and paying a
        round trip per call would be worse than the problem it solves.
        """
        aliases = [a for a in (entry.mcp_tool_aliases or []) if a]
        if not aliases:
            return None
        key = (target, entry.name)
        if key in self._resolved:
            return self._resolved[key]
        try:
            advertised = {
                str(t.get("name"))
                for t in await self.list_tools(target, timeout_s=timeout_s)
                if isinstance(t, dict) and t.get("name")
            }
        except ExecutorError:
            return None
        for candidate in aliases:
            if candidate in advertised:
                # Re-checked: an alias is reviewed registry content, but the
                # denylist must hold regardless of what the registry says.
                assert_read_only(candidate)
                self._resolved[key] = candidate
                return candidate
        return None

    async def run(
        self, entry: RegistryEntry, params: dict[str, Any], target: str
    ) -> ExecResult:
        if entry.kind != "mcp" or not entry.mcp_tool:
            raise ExecutorError(f"{entry.name}: not an mcp entry")

        tool = entry.mcp_tool
        # Denylist first: it must hold even if the registry says otherwise.
        assert_read_only(tool)
        permitted = allowed_tools(self._registry)
        if tool not in permitted:
            raise ExecutorError(
                f"refused: mcp tool '{tool}' is not declared by any loaded registry "
                f"entry. The registry, not the MCP server, decides what is callable."
            )

        conn = _conn(target)
        arguments = _tool_arguments(entry, params)

        started = self._timed()
        # Cached rename, if this entry has already been resolved once.
        tool = self._resolved.get((target, entry.name), tool)
        try:
            result = await self._rpc(
                conn,
                "tools/call",
                {"name": tool, "arguments": arguments},
                entry.timeout_s,
            )
        except ExecutorError as exc:
            # A rename is the one failure worth retrying: the capability is
            # there, under a name this entry also declares. Anything else —
            # unreachable, bad arguments, server error — is surfaced as-is,
            # because retrying it would just be slower and no more correct.
            alias = (
                await self._alias_for(entry, target, entry.timeout_s)
                if _looks_like_unknown_tool(str(exc))
                else None
            )
            if not alias or alias == tool:
                raise
            tool = alias
            result = await self._rpc(
                conn,
                "tools/call",
                {"name": tool, "arguments": arguments},
                entry.timeout_s,
            )
        duration_ms = int((self._timed() - started) * 1000)

        text = _content_text(result)
        if result.get("isError"):
            # Surfaced, never swallowed: an assistant that hides a failed tool
            # call answers from model memory instead.
            failed = ExecResult(
                ok=False,
                entry_name=entry.name,
                target=target,
                text=text,
                error=f"mcp tool '{tool}' reported an error: {text or '(no message)'}",
                duration_ms=duration_ms,
            )
            failed.cap_output()
            return failed

        rows: list[dict[str, Any]] = []
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            candidate = structured.get("result", structured)
            if isinstance(candidate, list):
                rows = [r for r in candidate if isinstance(r, dict)][: entry.row_limit]
            elif isinstance(candidate, dict):
                rows = [candidate]
        if not rows:
            # Fall back to parsing the TEXT content. Servers are not obliged to
            # send structuredContent and this one does not — it returns JSON as
            # text, so rows was always empty. The model still received the data,
            # but as a raw blob: row_limit did not apply, output was several
            # times larger than it needed to be, and a handful of log hits could
            # crowd the decisive later call out of the evidence budget.
            rows = _rows_from_text(text, entry.row_limit)

        ok = ExecResult(
            ok=True,
            entry_name=entry.name,
            target=target,
            rows=rows,
            text=text or "(mcp tool returned no text content)",
            duration_ms=duration_ms,
        )
        ok.cap_output()
        return ok


__all__ = [
    "DENY_PATTERN",
    "McpExecutor",
    "allowed_tools",
    "assert_read_only",
    "parse_body",
]
