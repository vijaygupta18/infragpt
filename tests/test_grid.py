"""Grid client tests — all against a mocked gateway, no network."""

from __future__ import annotations

from typing import Any

import pytest

from app.grid.client import GridClient, GridError, ToolCall

TOOLS = [{"name": "pod_status", "description": "d", "parameters": {"type": "object"}}]


def _reply(message: dict[str, Any], usage: dict[str, int] | None = None) -> dict[str, Any]:
    return {
        "choices": [{"message": message}],
        "usage": usage or {"prompt_tokens": 10, "completion_tokens": 5},
    }


def _client(monkeypatch, reply: dict[str, Any] | Exception) -> GridClient:
    monkeypatch.setenv("GRID_API_KEY", "test-key")
    c = GridClient(base_url="https://grid.invalid", selector_model="sel", synth_model="syn")

    async def fake_post(payload: dict[str, Any]) -> dict[str, Any]:
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(c, "_post", fake_post)
    return c


async def test_select_parses_tool_calls(monkeypatch) -> None:
    c = _client(
        monkeypatch,
        _reply(
            {
                "tool_calls": [
                    {
                        "function": {
                            "name": "pod_status",
                            "arguments": '{"service": "rider-app", "cloud": "gcp"}',
                        }
                    }
                ]
            }
        ),
    )
    sel = await c.select("are pods healthy?", TOOLS)
    assert sel.calls == [ToolCall("pod_status", {"service": "rider-app", "cloud": "gcp"})]
    assert sel.refusal is None
    assert sel.usage.tokens_in == 10


async def test_no_tool_call_is_a_refusal_not_an_error(monkeypatch) -> None:
    """Nothing in the registry covering the question is a first-class outcome."""
    c = _client(monkeypatch, _reply({"content": "I'd need access to business rows."}))
    sel = await c.select("why is driver X blocked?", TOOLS)
    assert sel.calls == []
    assert "business rows" in (sel.refusal or "")


async def test_malformed_arguments_are_rejected_not_repaired(monkeypatch) -> None:
    c = _client(
        monkeypatch,
        _reply({"tool_calls": [{"function": {"name": "pod_status", "arguments": "{not json"}}]}),
    )
    with pytest.raises(GridError, match="not valid JSON"):
        await c.select("q", TOOLS)


async def test_tool_call_without_a_name_is_rejected(monkeypatch) -> None:
    c = _client(monkeypatch, _reply({"tool_calls": [{"function": {"arguments": "{}"}}]}))
    with pytest.raises(GridError, match="function name"):
        await c.select("q", TOOLS)


async def test_calls_are_capped(monkeypatch) -> None:
    many = [{"function": {"name": "pod_status", "arguments": "{}"}} for _ in range(20)]
    c = _client(monkeypatch, _reply({"tool_calls": many}))
    sel = await c.select("q", TOOLS, max_calls=5)
    assert len(sel.calls) == 5


async def test_missing_api_key_refuses_to_call(monkeypatch) -> None:
    monkeypatch.delenv("GRID_API_KEY", raising=False)
    c = GridClient(base_url="https://grid.invalid", selector_model="sel", synth_model="syn")
    with pytest.raises(GridError, match="GRID_API_KEY"):
        await c.select("q", TOOLS)


async def test_no_granted_surfaces_short_circuits(monkeypatch) -> None:
    """No tools to offer means we never call the gateway at all."""
    monkeypatch.setenv("GRID_API_KEY", "test-key")
    c = GridClient(base_url="https://grid.invalid", selector_model="sel", synth_model="syn")

    async def explode(payload: dict[str, Any]) -> dict[str, Any]:
        raise AssertionError("gateway must not be called when there are no tools")

    monkeypatch.setattr(c, "_post", explode)
    sel = await c.select("q", [])
    assert sel.calls == []
    assert sel.refusal


async def test_missing_model_config_is_an_error(monkeypatch) -> None:
    monkeypatch.setenv("GRID_API_KEY", "test-key")
    c = GridClient(base_url="https://grid.invalid", selector_model="", synth_model="")
    with pytest.raises(GridError, match="GRID_SELECTOR_MODEL"):
        await c.select("q", TOOLS)


async def test_synthesize_returns_text_and_usage(monkeypatch) -> None:
    c = _client(monkeypatch, _reply({"content": "  All pods healthy in gcp.  "}))
    answer, usage = await c.synthesize("q", "evidence")
    assert answer == "All pods healthy in gcp."
    assert usage.tokens_out == 5


async def test_synthesize_sends_no_tools(monkeypatch) -> None:
    """The synthesizer must not be able to cause anything to run."""
    monkeypatch.setenv("GRID_API_KEY", "test-key")
    c = GridClient(base_url="https://grid.invalid", selector_model="sel", synth_model="syn")
    seen: dict[str, Any] = {}

    async def capture(payload: dict[str, Any]) -> dict[str, Any]:
        seen.update(payload)
        return _reply({"content": "ok"})

    monkeypatch.setattr(c, "_post", capture)
    await c.synthesize("q", "evidence")
    assert "tools" not in seen
    assert "tool_choice" not in seen
