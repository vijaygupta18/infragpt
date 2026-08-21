"""MCP executor tests — mocked HTTP, no network.

The assertions that matter are the containment ones: a tool the registry does
not name is refused, a mutating tool name is refused even when a registry entry
declares it, and a params failure never reaches the server.
"""

from __future__ import annotations

import json as _json
from pathlib import Path
from typing import Any

import httpx
import pytest

from app import config
from app.executors.base import ExecutorError
from app.executors.dispatch import ExecutorRegistry, dispatch
from app.executors.mcpapi import (
    McpExecutor,
    allowed_tools,
    assert_read_only,
    parse_body,
)
from app.registry.loader import load_registry
from app.registry.schema import RegistryEntry, Surface

REGISTRY_DIR = Path(__file__).resolve().parents[1] / "registry"


@pytest.fixture(scope="module")
def registry():
    return load_registry(REGISTRY_DIR)


def _entry(registry, name: str) -> RegistryEntry:
    return registry.get(name)


class _FakeClient:
    """Minimal httpx.AsyncClient stand-in recording what was POSTed."""

    #: Every real exchange now begins with an `initialize` handshake, so the
    #: fake answers that automatically and the queued responses line up with the
    #: calls a test actually cares about. Tests select by method via `sent()`.
    def __init__(self, *responses: httpx.Response | Exception) -> None:
        # Several responses may be queued, for the paths that make more than
        # one call (a rename retry does tools/call, tools/list, tools/call).
        # The last one repeats, so single-response tests are unaffected.
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    async def post(self, url, json=None, headers=None, timeout=None):  # noqa: ANN001
        self.calls.append({"url": url, "json": json, "headers": headers, "timeout": timeout})
        method = (json or {}).get("method")
        if method == "initialize":
            return _json_response({"jsonrpc": "2.0", "id": 0, "result": {}})
        if method == "notifications/initialized":
            return _json_response({"jsonrpc": "2.0", "id": 0, "result": {}})
        index = len(self.sent()) - 1
        response = (
            self._responses[index]
            if 0 <= index < len(self._responses)
            else self._responses[-1]
        )
        if isinstance(response, Exception):
            raise response
        return response

    def sent(self, method: str | None = None) -> list[dict[str, Any]]:
        """Requests excluding handshake traffic, optionally filtered by method."""
        out = [
            c
            for c in self.calls
            if (c["json"] or {}).get("method")
            not in ("initialize", "notifications/initialized")
        ]
        if method is not None:
            out = [c for c in out if (c["json"] or {}).get("method") == method]
        return out

    async def aclose(self) -> None:
        return None


def json_dumps(obj) -> str:
    return _json.dumps(obj)


def _json_response(payload: dict[str, Any], status: int = 200) -> httpx.Response:
    return httpx.Response(
        status,
        json=payload,
        request=httpx.Request("POST", "http://mcp.test/mcp"),
    )


def _text_result(text: str, *, is_error: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if is_error:
        result["isError"] = True
    return {"jsonrpc": "2.0", "id": 1, "result": result}


# ---- registry wiring -------------------------------------------------------


def test_mcp_entries_load_and_declare_cloud(registry) -> None:
    mcp = [e for e in registry.all_entries() if e.kind == "mcp"]
    assert mcp, "registry/mcp.yaml did not load"
    for entry in mcp:
        assert entry.mcp_tool
        spec = entry.params["cloud"]
        # Defaults to gcp rather than being required — see
        # test_every_cloud_scoped_entry_defaults_to_gcp.
        assert spec.default == "gcp"
        assert spec.required is False
        assert set(spec.values or []) == {"gcp", "aws"}
        assert entry.surface in {Surface.LOGS, Surface.METRICS}


def test_every_mcp_target_is_a_known_connection(registry) -> None:
    for entry in registry.all_entries():
        if entry.kind != "mcp":
            continue
        for cloud in ("gcp", "aws"):
            assert entry.target.replace("$cloud", cloud) in config.MCP_CONNECTIONS


def test_shipped_mcp_tool_names_pass_the_denylist(registry) -> None:
    for entry in registry.all_entries():
        if entry.kind == "mcp":
            assert_read_only(entry.mcp_tool or "")


# ---- containment: denylist -------------------------------------------------


@pytest.mark.parametrize(
    "tool",
    [
        "delete_index",
        "create_dashboard",
        "update_alert_rule",
        "put_document",
        "set_silence",
        "restart_pod",
        "scale_deployment",
        "silence_alert",
        "ingest_docs",
    ],
)
def test_mutating_tool_names_are_refused(tool: str) -> None:
    with pytest.raises(ExecutorError, match="read-only denylist"):
        assert_read_only(tool)


async def test_denylisted_tool_is_refused_even_when_the_registry_declares_it(
    registry,
) -> None:
    """Defence in depth: a careless registry edit still cannot produce a write."""
    entry = _entry(registry, "list_log_indices").model_copy(update={"mcp_tool": "delete_index"})

    class _OneOff:
        def all_entries(self):
            return [entry]

    client = _FakeClient(_json_response(_text_result("should never be sent")))
    executor = McpExecutor(registry=_OneOff(), client=client)
    with pytest.raises(ExecutorError, match="read-only denylist"):
        await executor.run(entry, {"cloud": "gcp"}, "opensearch_gcp")
    assert client.calls == []


async def test_tool_not_in_the_registry_is_refused(registry) -> None:
    entry = _entry(registry, "logs_search").model_copy(
        update={"mcp_tool": "some_new_server_tool"}
    )
    client = _FakeClient(_json_response(_text_result("should never be sent")))
    executor = McpExecutor(registry=registry, client=client)
    with pytest.raises(ExecutorError, match="not declared by any loaded registry entry"):
        await executor.run(
            entry,
            {"cloud": "gcp", "query": "boom", "window": "now-15m", "size": 5},
            "opensearch_gcp",
        )
    assert client.calls == []


def test_allowed_tools_is_exactly_the_registry(registry) -> None:
    """Primary names AND declared aliases — and nothing else.

    Aliases widen the set of NAMES, not the set of capabilities: each one is
    reviewed registry content naming the same tool under a different server's
    spelling. The invariant that matters is unchanged and asserted below — a
    tool the server advertises but no entry declares is still uncallable.
    """
    expected: set[str] = set()
    for e in registry.all_entries():
        if e.kind != "mcp":
            continue
        if e.mcp_tool:
            expected.add(e.mcp_tool)
        expected.update(e.mcp_tool_aliases or [])
    assert allowed_tools(registry) == expected


def test_aliases_never_include_a_mutating_name(registry) -> None:
    """An alias is a name the executor may call, so the denylist covers it."""
    from app.executors.mcpapi import assert_read_only

    for e in registry.all_entries():
        for alias in e.mcp_tool_aliases or []:
            assert_read_only(alias)


@pytest.mark.asyncio
async def test_a_renamed_tool_is_recovered_via_a_declared_alias(registry) -> None:
    """The failure this exists for: the server has the capability under a
    different name, and without recovery the whole surface is dead."""
    unknown = _json_response(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32602, "message": "unknown tool: search"},
        }
    )
    listing = _json_response(
        {"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "cat_indices"}]}}
    )
    ok = _json_response(_text_result("42"))
    client = _FakeClient(unknown, listing, ok)
    executor = McpExecutor(registry=registry, client=client)
    entry = _entry(registry, "list_log_indices")

    result = await executor.run(entry, {"cloud": "gcp"}, "opensearch_gcp")

    assert result.ok is True
    assert result.text == "42"
    sent = client.sent()
    assert sent[0]["json"]["params"]["name"] == "list_indices"
    assert sent[1]["json"]["method"] == "tools/list"
    assert sent[2]["json"]["params"]["name"] == "cat_indices"


@pytest.mark.asyncio
async def test_an_ordinary_error_is_not_retried(registry) -> None:
    """Only a rename is worth retrying. Retrying bad arguments is just slower."""
    boom = _json_response(
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "invalid window"}}
    )
    client = _FakeClient(boom)
    executor = McpExecutor(registry=registry, client=client)
    entry = _entry(registry, "list_log_indices")

    with pytest.raises(ExecutorError, match="invalid window"):
        await executor.run(entry, {"cloud": "gcp"}, "opensearch_gcp")
    assert len(client.sent()) == 1


# ---- protocol --------------------------------------------------------------


async def test_tools_call_shape_and_arguments(registry) -> None:
    client = _FakeClient(_json_response(_text_result("2 hits")))
    executor = McpExecutor(registry=registry, client=client)
    entry = _entry(registry, "logs_search")
    # Through validate_params, as the real path does — that is what applies
    # declared defaults, and the rendered body depends on them.
    result = await executor.run(
        entry,
        entry.validate_params(
            {"cloud": "aws", "query": "NullPointer", "window": "now-1h", "size": 10}
        ),
        "opensearch_aws",
    )
    assert result.ok is True
    assert result.text == "2 hits"
    body = client.sent()[0]["json"]
    assert body["jsonrpc"] == "2.0"
    assert body["method"] == "tools/call"
    assert isinstance(body["id"], int)
    assert body["params"]["name"] == entry.mcp_tool
    # `cloud` selects the connection; it is never a server-side argument.
    # The arguments are a rendered Query DSL, not flat params: this entry
    # targets the log server's real `search` tool, which takes an index and a
    # DSL object. The model fills slots; the template builds the body.
    args = body["params"]["arguments"]
    assert args["index"] == "app-logs-*"
    assert args["size"] == 10
    # Objects, not strings: the live server rejects the "field:dir" form.
    assert args["sort"] == [{"@timestamp": {"order": "desc"}}]
    filters = args["query"]["bool"]["filter"]
    assert {"range": {"@timestamp": {"gte": "now-1h"}}} in filters
    assert {
        "query_string": {"query": "NullPointer", "analyze_wildcard": True}
    } in filters
    # `cloud` must not leak into the body.
    assert "cloud" not in json_dumps(args)
    assert client.sent()[0]["url"].endswith("/mcp")
    assert client.sent()[0]["timeout"] == entry.timeout_s


async def test_unset_optional_params_are_not_sent(registry) -> None:
    client = _FakeClient(_json_response(_text_result("names")))
    executor = McpExecutor(registry=registry, client=client)
    entry = _entry(registry, "list_log_indices")
    await executor.run(entry, {"cloud": "gcp", "pattern": None}, "opensearch_gcp")
    assert client.sent()[0]["json"]["params"]["arguments"] == {}


async def test_sse_framed_body_is_parsed(registry) -> None:
    sse = (
        "event: message\n"
        'data: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text",'
        '"text":"from sse"}]}}\n\n'
    )
    response = httpx.Response(
        200,
        text=sse,
        headers={"content-type": "text/event-stream"},
        request=httpx.Request("POST", "http://mcp.test/mcp"),
    )
    executor = McpExecutor(registry=registry, client=_FakeClient(response))
    result = await executor.run(
        _entry(registry, "list_log_indices"), {"cloud": "gcp"}, "opensearch_gcp"
    )
    assert result.ok is True
    assert result.text == "from sse"


def test_parse_body_rejects_an_sse_stream_with_no_result() -> None:
    with pytest.raises(ExecutorError, match="no JSON-RPC result"):
        parse_body("event: ping\ndata: {}\n\n", "text/event-stream")


def test_parse_body_rejects_non_json() -> None:
    with pytest.raises(ExecutorError, match="non-JSON"):
        parse_body("<html>gateway</html>", "text/html")


async def test_is_error_becomes_a_failed_result(registry) -> None:
    client = _FakeClient(_json_response(_text_result("index_not_found", is_error=True)))
    executor = McpExecutor(registry=registry, client=client)
    result = await executor.run(_entry(registry, "list_log_indices"), {"cloud": "gcp"},
                                "opensearch_gcp")
    assert result.ok is False
    assert "index_not_found" in (result.error or "")


async def test_jsonrpc_error_is_surfaced(registry) -> None:
    payload = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "no such tool"}}
    executor = McpExecutor(registry=registry, client=_FakeClient(_json_response(payload)))
    with pytest.raises(ExecutorError, match="no such tool"):
        await executor.run(_entry(registry, "list_log_indices"), {"cloud": "gcp"}, "opensearch_gcp")


async def test_http_error_status_is_surfaced(registry) -> None:
    response = httpx.Response(
        503, text="upstream down", request=httpx.Request("POST", "http://mcp.test/mcp")
    )
    executor = McpExecutor(registry=registry, client=_FakeClient(response))
    with pytest.raises(ExecutorError, match="503"):
        await executor.run(_entry(registry, "list_log_indices"), {"cloud": "gcp"}, "opensearch_gcp")


async def test_transport_failure_is_surfaced(registry) -> None:
    executor = McpExecutor(
        registry=registry, client=_FakeClient(httpx.ConnectError("no route"))
    )
    with pytest.raises(ExecutorError, match="unreachable"):
        await executor.run(_entry(registry, "list_log_indices"), {"cloud": "gcp"}, "opensearch_gcp")


async def test_unknown_connection_is_rejected(registry) -> None:
    client = _FakeClient(_json_response(_text_result("x")))
    executor = McpExecutor(registry=registry, client=client)
    with pytest.raises(ExecutorError, match="unknown mcp connection"):
        await executor.run(
            _entry(registry, "list_log_indices"), {"cloud": "gcp"}, "opensearch_nope"
        )
    assert client.calls == []


async def test_list_tools_is_a_diagnostic(registry) -> None:
    payload = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "delete_index"}]}}
    client = _FakeClient(_json_response(payload))
    tools = await McpExecutor(registry=registry, client=client).list_tools("vm_gcp")
    assert [t["name"] for t in tools] == ["delete_index"]
    assert client.sent()[0]["json"]["method"] == "tools/list"
    # Advertised is not callable: the registry still refuses it.
    assert "delete_index" not in allowed_tools(registry)


# ---- dispatch integration --------------------------------------------------


async def test_bad_params_never_reach_the_server(registry) -> None:
    client = _FakeClient(_json_response(_text_result("x")))
    executors = ExecutorRegistry(mcp=McpExecutor(registry=registry, client=client))
    result = await dispatch(
        "logs_search",
        {"cloud": "mars", "query": "boom"},
        registry=registry,
        executors=executors,
    )
    assert result.ok is False
    assert "parameter rejected" in (result.error or "")
    assert client.calls == []


async def test_unknown_param_never_reaches_the_server(registry) -> None:
    client = _FakeClient(_json_response(_text_result("x")))
    executors = ExecutorRegistry(mcp=McpExecutor(registry=registry, client=client))
    result = await dispatch(
        "active_alerts",
        {"cloud": "gcp", "index": "anything"},
        registry=registry,
        executors=executors,
    )
    assert result.ok is False
    assert "unknown params" in (result.error or "")
    assert client.calls == []


async def test_dispatch_enforces_the_logs_grant(registry) -> None:
    client = _FakeClient(_json_response(_text_result("hits")))
    executors = ExecutorRegistry(mcp=McpExecutor(registry=registry, client=client))
    denied = await dispatch(
        "logs_search",
        {"cloud": "gcp", "query": "boom"},
        granted_surfaces={Surface.METRICS},
        registry=registry,
        executors=executors,
    )
    assert denied.ok is False
    assert "logs" in (denied.error or "")
    assert client.calls == []

    allowed = await dispatch(
        "logs_search",
        {"cloud": "gcp", "query": "boom"},
        granted_surfaces={Surface.LOGS},
        registry=registry,
        executors=executors,
    )
    assert allowed.ok is True
    assert allowed.target == "opensearch_gcp"
