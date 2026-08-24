"""LLM gateway client — OpenAI-compatible chat completions.

Two calls per question, deliberately separated:

  * **select**    — cheap model, function-calling only. Its entire output surface
                    is ``{name, arguments}`` chosen from the tool specs we hand
                    it. It cannot emit a command, a hostname, or SQL.
  * **synthesize** — stronger model, prose only. It sees *already-executed,
                    already-redacted* output and has no tools at all, so it
                    cannot cause anything to run.

ASSUMPTION: the gateway speaks the OpenAI-compatible ``/v1/chat/completions``
shape with ``tools``/``tool_calls``. That is the common case for LLM gateways and
is what this client targets. If Grid differs, ``_post`` and the two parse helpers
are the only places that need to change — everything above them is shape-agnostic.
Set ``GRID_BASE_URL``/``GRID_SELECTOR_MODEL``/``GRID_SYNTH_MODEL`` to point at it.
"""

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from app import config


class GridError(RuntimeError):
    """Gateway failure. Always surfaced to the user — never silently swallowed,
    because a hidden selector failure produces an answer from model memory."""


@dataclass
class Usage:
    tokens_in: int = 0
    tokens_out: int = 0

    def __add__(self, other: Usage) -> Usage:
        return Usage(self.tokens_in + other.tokens_in, self.tokens_out + other.tokens_out)


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class Selection:
    calls: list[ToolCall] = field(default_factory=list)
    # Set when the model declines to call anything — i.e. nothing in the registry
    # covers the question. This is a first-class outcome, not an error.
    refusal: str | None = None
    usage: Usage = field(default_factory=Usage)


def _api_key() -> str:
    key = os.getenv(config.GRID_API_KEY_ENV, "")
    if not key:
        raise GridError(
            f"{config.GRID_API_KEY_ENV} is not set — refusing to call the gateway"
        )
    return key


class GridClient:
    def __init__(
        self,
        base_url: str | None = None,
        selector_model: str | None = None,
        synth_model: str | None = None,
        timeout_s: float = 180.0,
    ) -> None:
        self.base_url = (base_url or config.GRID_BASE_URL).rstrip("/")
        self.selector_model = selector_model or config.GRID_SELECTOR_MODEL
        self.synth_model = synth_model or config.GRID_SYNTH_MODEL
        self.timeout_s = timeout_s

    async def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {_api_key()}",
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout_s) as client:
                resp = await client.post(url, json=payload, headers=headers)
        except httpx.TimeoutException as exc:
            # str(ReadTimeout) is EMPTY, so "gateway unreachable: " with nothing
            # after it was the entire message — which reads as a network problem
            # when it is really "the model took too long on a large prompt".
            raise GridError(
                f"gateway timed out after {self.timeout_s:.0f}s "
                f"({type(exc).__name__}). The prompt may be large: a namespace "
                "listing can run to tens of thousands of tokens. Narrow the "
                "question, or use a `grep` parameter to filter the output."
            ) from exc
        except httpx.HTTPError as exc:
            detail = str(exc) or type(exc).__name__
            raise GridError(f"gateway unreachable: {detail}") from exc
        if resp.status_code >= 400:
            # Body may echo the prompt; keep it short and do not log the key.
            raise GridError(f"gateway returned {resp.status_code}: {resp.text[:400]}")
        try:
            return resp.json()
        except ValueError as exc:
            raise GridError("gateway returned non-JSON") from exc

    @staticmethod
    def _usage(body: dict[str, Any]) -> Usage:
        u = body.get("usage") or {}
        return Usage(int(u.get("prompt_tokens", 0)), int(u.get("completion_tokens", 0)))

    # ---- selection --------------------------------------------------------

    async def select(
        self,
        question: str,
        tool_specs: list[dict[str, Any]],
        context: str = "",
        # Parse sanity for ONE model response, not a policy: the question's
        # real bound is the time budget in the ask loop. A response carrying
        # hundreds of tool calls is a malformed generation, not a plan.
        max_calls: int = 200,
    ) -> Selection:
        """Choose registry functions to run. Never returns a command."""
        # Checked before model config on purpose: a caller with no grants should
        # get a clear answer, not a gateway error about configuration they can do
        # nothing about. There is also nothing to ask the gateway.
        if not tool_specs:
            return Selection(refusal="You have no granted surfaces, so I cannot look anything up.")
        if not self.selector_model:
            raise GridError("GRID_SELECTOR_MODEL is not configured")

        from app.grid.prompts import SELECTOR_SYSTEM

        payload = {
            "model": self.selector_model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": SELECTOR_SYSTEM},
                {"role": "user", "content": _selector_user_msg(question, context)},
            ],
            "tools": [{"type": "function", "function": spec} for spec in tool_specs],
            "tool_choice": "auto",
        }
        body = await self._post(payload)
        usage = self._usage(body)

        try:
            message = body["choices"][0]["message"]
        except (KeyError, IndexError) as exc:
            raise GridError("gateway response missing choices[0].message") from exc

        raw_calls = message.get("tool_calls") or []
        if not raw_calls:
            # No tool call = the model believes nothing covers this. Keep its
            # words; the caller logs this to the coverage backlog.
            return Selection(
                refusal=(message.get("content") or "").strip()
                or "I don't have a way to answer that yet.",
                usage=usage,
            )

        calls: list[ToolCall] = []
        for raw in raw_calls[:max_calls]:
            fn = raw.get("function") or {}
            name = fn.get("name")
            if not isinstance(name, str) or not name:
                raise GridError("tool call missing a function name")
            args_raw = fn.get("arguments", "{}")
            if isinstance(args_raw, str):
                try:
                    args = json.loads(args_raw or "{}")
                except json.JSONDecodeError as exc:
                    # Malformed arguments are REJECTED, never repaired.
                    raise GridError(f"tool call {name}: arguments were not valid JSON") from exc
            elif isinstance(args_raw, dict):
                args = args_raw
            else:
                raise GridError(f"tool call {name}: unexpected arguments type")
            if not isinstance(args, dict):
                raise GridError(f"tool call {name}: arguments were not an object")
            calls.append(ToolCall(name=name, arguments=args))

        return Selection(calls=calls, usage=usage)

    # ---- synthesis --------------------------------------------------------

    async def synthesize(
        self,
        question: str,
        evidence: str,
        context: str = "",
    ) -> tuple[str, Usage]:
        """Turn already-redacted tool output into an answer. No tools attached."""
        if not self.synth_model:
            raise GridError("GRID_SYNTH_MODEL is not configured")

        from app.grid.prompts import SYNTH_SYSTEM

        payload = {
            "model": self.synth_model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": SYNTH_SYSTEM},
                {
                    "role": "user",
                    "content": (
                        f"Question:\n{question}\n\n"
                        + (f"Reference material:\n{context}\n\n" if context else "")
                        + f"Tool output (already redacted):\n{evidence}"
                    ),
                },
            ],
        }
        body = await self._post(payload)
        usage = self._usage(body)
        try:
            content = body["choices"][0]["message"].get("content") or ""
        except (KeyError, IndexError) as exc:
            raise GridError("gateway response missing choices[0].message") from exc
        return content.strip(), usage

    async def synthesize_stream(
        self,
        question: str,
        evidence: str,
        context: str = "",
        on_token: Callable[[str], Awaitable[None]] | None = None,
    ) -> tuple[str, Usage]:
        """Same answer as `synthesize`, delivered as it is written.

        Synthesis is the longest single wait in a question — the evidence is
        already gathered, and the user watches a spinner while a large model
        writes several paragraphs. Streaming does not make it faster; it makes
        it legible, which is the part that matters when someone is waiting.

        The full text is still returned and stored, so the streamed turn and the
        same turn on reload are the same text. If streaming fails for any
        reason, the caller falls back to the non-streaming path rather than
        losing the answer.
        """
        if not self.synth_model:
            raise GridError("GRID_SYNTH_MODEL is not configured")

        from app.grid.prompts import SYNTH_SYSTEM

        payload = {
            "model": self.synth_model,
            "temperature": 0,
            "stream": True,
            # Ask for usage on the final chunk; gateways that don't support the
            # option ignore it, and we fall back to a zero Usage.
            "stream_options": {"include_usage": True},
            "messages": [
                {"role": "system", "content": SYNTH_SYSTEM},
                {
                    "role": "user",
                    "content": (
                        f"Question:\n{question}\n\n"
                        + (f"Reference material:\n{context}\n\n" if context else "")
                        + f"Tool output (already redacted):\n{evidence}"
                    ),
                },
            ],
        }

        url = f"{self.base_url}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {_api_key()}",
            "Content-Type": "application/json",
        }
        parts: list[str] = []
        usage = Usage(0, 0)
        try:
            async with httpx.AsyncClient(timeout=self.timeout_s) as client:
                async with client.stream(
                    "POST", url, json=payload, headers=headers
                ) as resp:
                    if resp.status_code >= 400:
                        await resp.aread()
                        raise GridError(
                            f"gateway returned {resp.status_code}: {resp.text[:400]}"
                        )
                    async for line in resp.aiter_lines():
                        if not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if not data or data == "[DONE]":
                            continue
                        try:
                            chunk = json.loads(data)
                        except ValueError:
                            # One malformed chunk must not discard an answer
                            # that is otherwise arriving fine.
                            continue
                        if chunk.get("usage"):
                            usage = self._usage(chunk)
                        for choice in chunk.get("choices") or []:
                            piece = (choice.get("delta") or {}).get("content") or ""
                            if piece:
                                parts.append(piece)
                                if on_token is not None:
                                    await on_token(piece)
        except httpx.TimeoutException as exc:
            raise GridError(
                f"gateway timed out after {self.timeout_s:.0f}s while writing "
                f"the answer ({type(exc).__name__})."
            ) from exc
        except httpx.HTTPError as exc:
            raise GridError(f"gateway unreachable: {str(exc) or type(exc).__name__}") from exc

        text = "".join(parts).strip()
        if not text:
            raise GridError("gateway streamed no content")
        return text, usage


def _selector_user_msg(question: str, context: str) -> str:
    parts = [f"Question: {question}"]
    if context:
        parts.append(f"\nRelevant runbooks:\n{context}")
    return "\n".join(parts)


_client: GridClient | None = None


def get_grid_client() -> GridClient:
    global _client
    if _client is None:
        _client = GridClient()
    return _client
