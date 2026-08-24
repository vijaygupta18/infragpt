"""/ask orchestration — Grid and the executors are mocked; no network, no infra."""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jose import jwk, jwt

from app import audit, config
from app.auth.pomerium import POMERIUM_HEADER, PomeriumVerifier, set_verifier
from app.executors.base import ExecResult
from app.grid.client import GridError, Selection, ToolCall, Usage
from app.main import create_app
from app.registry.schema import Surface
from app.storage import get_storage

AUDIENCE = "infragpt.example.com"
REPO = Path(__file__).resolve().parent.parent


def _new_key(kid: str) -> tuple[str, dict]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public = jwk.construct(pem, algorithm="ES256").public_key().to_dict()
    public = {k: (v.decode() if isinstance(v, bytes) else v) for k, v in public.items()}
    public["kid"] = kid
    return pem, public


@pytest.fixture(scope="module")
def key() -> tuple[str, dict]:
    return _new_key("real")


def _assertion(pem: str, email: str) -> str:
    return jwt.encode(
        {
            "email": email,
            "name": email.split("@")[0],
            "sub": email,
            "aud": AUDIENCE,
            "iss": "pomerium",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
        },
        pem,
        algorithm="ES256",
    )


class FakeGrid:
    """Stands in for the gateway. Records what it was offered."""

    def __init__(
        self, selection: Selection | Exception, answer: str = "Synthesized answer."
    ) -> None:
        self.selection = selection
        self.answer = answer
        self.offered_tools: list[str] = []
        self.evidence: str = ""

    async def select(self, question, tool_specs, context="", max_calls=5):  # noqa: ANN001,ANN201
        self.offered_tools = [t["name"] for t in tool_specs]
        if isinstance(self.selection, Exception):
            raise self.selection
        return self.selection

    async def synthesize_stream(self, question, evidence, context="", on_token=None):  # noqa: ANN001,ANN201
        """Stream the same text the non-streaming stub returns, in pieces."""
        text, usage = await self.synthesize(question, evidence, context)
        if on_token is not None:
            for word in text.split(" "):
                await on_token(word + " ")
        return text, usage

    async def synthesize(self, question, evidence, context=""):  # noqa: ANN001,ANN201
        self.evidence = evidence
        return self.answer, Usage(7, 3)


@pytest.fixture()
def env(tmp_path, monkeypatch, key):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "ask.db")
    monkeypatch.setattr(config, "REGISTRY_DIR", REPO / "registry")
    monkeypatch.setattr(config, "RUNBOOK_DIR", REPO / "runbooks")
    monkeypatch.setenv("INFRAGPT_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.setenv("INFRAGPT_RUNBOOKS", str(REPO / "runbooks"))
    monkeypatch.delenv("INFRAGPT_BOOTSTRAP_ADMINS", raising=False)

    verifier = PomeriumVerifier(jwks_url="https://pomerium.invalid/jwks.json", audience=AUDIENCE)
    verifier.set_jwks({"keys": [key[1]]})
    set_verifier(verifier)

    from app import runbooks as runbooks_mod
    from app.limits.service import reset_limits
    from app.registry import loader as loader_mod

    loader_mod.get_registry(REPO / "registry", reload=True)
    runbooks_mod.get_runbooks(REPO / "runbooks", reload=True)
    # The Limits singleton binds a database on first use; without this reset it
    # leaks rate-limit counters (and a stale db handle) between tests.
    reset_limits(None)

    with TestClient(create_app()) as client:
        yield client, tmp_path


def _headers(pem: str, email: str) -> dict[str, str]:
    return {POMERIUM_HEADER: _assertion(pem, email)}


def _activate(email: str, *surfaces: Surface) -> None:
    storage = get_storage()
    user = storage.users.get_or_create(email, email.split("@")[0])
    storage.users.set_status(user.id, "active", "test")
    for s in surfaces:
        storage.grants.grant(user.id, s, "test")


def _install_grid(monkeypatch, fake: FakeGrid) -> None:
    monkeypatch.setattr("app.api.ask.get_grid_client", lambda: fake)


def _install_dispatch(monkeypatch, results: dict[str, ExecResult]) -> list[tuple[str, dict]]:
    seen: list[tuple[str, dict]] = []

    async def fake_dispatch(name, params=None, *, granted_surfaces=None, **kw):  # noqa: ANN001,ANN202
        seen.append((name, dict(params or {})))
        return results.get(
            name, ExecResult(ok=True, entry_name=name, target="k8s_gcp", text="output")
        )

    monkeypatch.setattr("app.api.ask.dispatch", fake_dispatch)
    return seen


# ---- happy path ------------------------------------------------------------


def test_answer_includes_calls_and_evidence(env, key, monkeypatch) -> None:
    client, _ = env
    _activate("eng@example.com", Surface.K8S_GCP)
    fake = FakeGrid(
        Selection(calls=[ToolCall("pod_status", {"service": "rider-app", "cloud": "gcp"})],
                  usage=Usage(11, 4))
    )
    _install_grid(monkeypatch, fake)
    _install_dispatch(
        monkeypatch,
        {"pod_status": ExecResult(ok=True, entry_name="pod_status", target="k8s_gcp",
                                  text="rider-app 3/3 Running")},
    )

    resp = client.post("/ask", json={"question": "are rider-app pods healthy in gcp?"},
                       headers=_headers(key[0], "eng@example.com"))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["answer"] == "Synthesized answer."
    assert len(data["calls"]) == 1
    call = data["calls"][0]
    assert call["entry_name"] == "pod_status"
    assert call["cloud"] == "gcp"
    assert call["ok"] is True
    # The evidence handed to the synthesizer must contain the real output.
    assert "rider-app 3/3 Running" in fake.evidence


def test_failed_call_is_surfaced_not_dropped(env, key, monkeypatch) -> None:
    """A hidden failure is how the assistant ends up answering from memory."""
    client, _ = env
    _activate("eng@example.com", Surface.K8S_GCP)
    fake = FakeGrid(Selection(calls=[ToolCall("pod_status", {"service": "x", "cloud": "gcp"})]))
    _install_grid(monkeypatch, fake)
    _install_dispatch(
        monkeypatch,
        {"pod_status": ExecResult(ok=False, entry_name="pod_status", target="k8s_gcp",
                                  error="context deadline exceeded")},
    )

    data = client.post("/ask", json={"question": "pods?"},
                       headers=_headers(key[0], "eng@example.com")).json()
    assert data["calls"][0]["ok"] is False
    assert "context deadline exceeded" in data["calls"][0]["error"]
    assert "FAILED" in fake.evidence


# ---- refusal / coverage ----------------------------------------------------


def test_refusal_returns_answer_with_no_calls(env, key, monkeypatch) -> None:
    client, _ = env
    _activate("eng@example.com", Surface.DB_READ)
    _install_grid(monkeypatch, FakeGrid(Selection(refusal="I can't reach business rows.")))
    seen = _install_dispatch(monkeypatch, {})

    data = client.post("/ask", json={"question": "why is driver 123 blocked?"},
                       headers=_headers(key[0], "eng@example.com")).json()
    assert data["calls"] == []
    assert "business rows" in data["answer"]
    assert seen == [], "nothing may execute when the selector declines"


# ---- grants ----------------------------------------------------------------


def test_selector_is_only_offered_granted_surfaces(env, key, monkeypatch) -> None:
    client, _ = env
    _activate("ops@example.com", Surface.REDIS_READ)
    fake = FakeGrid(Selection(refusal="nothing to do"))
    _install_grid(monkeypatch, fake)
    _install_dispatch(monkeypatch, {})

    client.post("/ask", json={"question": "check a key"}, headers=_headers(key[0], "ops@example.com"))
    assert fake.offered_tools, "expected redis tools to be offered"
    assert all(t.startswith("redis_") for t in fake.offered_tools), fake.offered_tools


def test_dispatch_receives_the_granted_surfaces(env, key, monkeypatch) -> None:
    """Grants are enforced twice on purpose — this asserts the second check gets
    the real set rather than None."""
    client, _ = env
    _activate("eng@example.com", Surface.K8S_GCP)
    sel = Selection(calls=[ToolCall("pod_status", {"cloud": "gcp"})])
    _install_grid(monkeypatch, FakeGrid(sel))

    captured: dict[str, Any] = {}

    async def fake_dispatch(name, params=None, *, granted_surfaces=None, **kw):  # noqa: ANN001,ANN202
        captured["surfaces"] = granted_surfaces
        return ExecResult(ok=True, entry_name=name, target="k8s_gcp", text="ok")

    monkeypatch.setattr("app.api.ask.dispatch", fake_dispatch)
    client.post("/ask", json={"question": "pods?"}, headers=_headers(key[0], "eng@example.com"))
    assert captured["surfaces"] == {Surface.K8S_GCP}


def test_pending_user_cannot_ask(env, key) -> None:
    client, _ = env
    resp = client.post("/ask", json={"question": "hi"}, headers=_headers(key[0], "new@example.com"))
    assert resp.status_code == 403


# ---- gateway failures ------------------------------------------------------


def test_selector_failure_is_reported_not_answered(env, key, monkeypatch) -> None:
    client, _ = env
    _activate("eng@example.com", Surface.K8S_GCP)
    _install_grid(monkeypatch, FakeGrid(GridError("gateway unreachable")))
    _install_dispatch(monkeypatch, {})

    resp = client.post("/ask", json={"question": "pods?"}, headers=_headers(key[0], "eng@example.com"))
    assert resp.status_code == 502
    assert "selector failed" in resp.json()["detail"]


# ---- audit -----------------------------------------------------------------


def test_question_and_calls_are_audited(env, key, monkeypatch) -> None:
    client, tmp_path = env
    _activate("eng@example.com", Surface.K8S_GCP)
    sel = Selection(calls=[ToolCall("pod_status", {"cloud": "gcp"})])
    _install_grid(monkeypatch, FakeGrid(sel))
    _install_dispatch(monkeypatch, {})

    client.post("/ask", json={"question": "pods healthy?"}, headers=_headers(key[0], "eng@example.com"))

    records = [json.loads(line) for line in audit.audit_path().read_text().splitlines() if line]
    kinds = {r.get("kind") or r.get("type") for r in records}
    assert any("call" in str(k) for k in kinds)
    assert any("question" in str(k) for k in kinds)
    assert all(r.get("user_email") == "eng@example.com" for r in records)


# ---- limits are actually attached ------------------------------------------


def test_hourly_question_limit_returns_429(env, key, monkeypatch) -> None:
    """The limiter exists in app/limits; this asserts /ask actually uses it."""
    client, _ = env
    monkeypatch.setattr(config, "QUESTIONS_PER_HOUR", 1)
    _activate("eng@example.com", Surface.K8S_GCP)
    _install_grid(monkeypatch, FakeGrid(Selection(refusal="no")))
    _install_dispatch(monkeypatch, {})

    hdr = _headers(key[0], "eng@example.com")
    assert client.post("/ask", json={"question": "one"}, headers=hdr).status_code == 200
    second = client.post("/ask", json={"question": "two"}, headers=hdr)
    assert second.status_code == 429
    assert "Retry-After" in second.headers


def test_conversation_is_persisted(env, key, monkeypatch) -> None:
    client, _ = env
    _activate("eng@example.com", Surface.K8S_GCP)
    _install_grid(monkeypatch, FakeGrid(Selection(refusal="no")))
    _install_dispatch(monkeypatch, {})

    hdr = _headers(key[0], "eng@example.com")
    first = client.post("/ask", json={"question": "first?"}, headers=hdr).json()
    conv_id = first["conversation_id"]
    client.post("/ask", json={"question": "second?", "conversation_id": conv_id}, headers=hdr)

    msgs = client.get(f"/conversations/{conv_id}", headers=hdr).json()["messages"]
    assert [m["content"] for m in msgs if m["role"] == "user"] == ["first?", "second?"]


# ---- conversation isolation -------------------------------------------------
# History is per-user. These cover the paths the existing web test does not:
# the JSON API, the list endpoint, and — the one that matters most — whether a
# question can be APPENDED to someone else's thread by passing its id.


def test_cannot_append_to_another_users_conversation(env, key, monkeypatch) -> None:
    """Passing a foreign conversation_id must not write into their history."""
    client, _ = env
    _activate("alice@example.com", Surface.K8S_GCP)
    _activate("mallory@example.com", Surface.K8S_GCP)
    _install_grid(monkeypatch, FakeGrid(Selection(refusal="no")))
    _install_dispatch(monkeypatch, {})

    alice = _headers(key[0], "alice@example.com")
    conv_id = client.post("/ask", json={"question": "alice's"}, headers=alice).json()[
        "conversation_id"
    ]

    resp = client.post(
        "/ask",
        json={"question": "mallory's", "conversation_id": conv_id},
        headers=_headers(key[0], "mallory@example.com"),
    )
    assert resp.status_code == 404

    msgs = client.get(f"/conversations/{conv_id}", headers=alice).json()["messages"]
    assert all("mallory" not in m["content"] for m in msgs)


def test_conversation_list_is_scoped_to_the_caller(env, key, monkeypatch) -> None:
    client, _ = env
    _activate("alice@example.com", Surface.K8S_GCP)
    _activate("bob@example.com", Surface.K8S_GCP)
    _install_grid(monkeypatch, FakeGrid(Selection(refusal="no")))
    _install_dispatch(monkeypatch, {})

    client.post("/ask", json={"question": "alice only"}, headers=_headers(key[0], "alice@example.com"))
    bob_list = client.get("/conversations", headers=_headers(key[0], "bob@example.com")).json()
    assert bob_list == []


def test_reading_another_users_conversation_is_404_not_403(env, key, monkeypatch) -> None:
    """404, not 403: a 403 confirms the id exists, which is an enumeration oracle."""
    client, _ = env
    _activate("alice@example.com", Surface.K8S_GCP)
    _activate("bob@example.com", Surface.K8S_GCP)
    _install_grid(monkeypatch, FakeGrid(Selection(refusal="no")))
    _install_dispatch(monkeypatch, {})

    conv_id = client.post(
        "/ask", json={"question": "private"}, headers=_headers(key[0], "alice@example.com")
    ).json()["conversation_id"]

    resp = client.get(f"/conversations/{conv_id}", headers=_headers(key[0], "bob@example.com"))
    assert resp.status_code == 404
    # A non-existent id must look identical.
    assert resp.json() == client.get(
        "/conversations/999999", headers=_headers(key[0], "bob@example.com")
    ).json()


# ---- conversation memory ----------------------------------------------------
# Follow-ups ("check again", "what about aws?") are the normal way people use
# this. Without history the model correctly but uselessly asks for clarification.


def test_history_is_passed_to_the_selector(env, key, monkeypatch) -> None:
    client, _ = env
    _activate("eng@example.com", Surface.K8S_GCP)
    fake = FakeGrid(Selection(refusal="no"))

    seen_contexts: list[str] = []

    async def capture(question, tool_specs, context="", max_calls=5):  # noqa: ANN001,ANN202
        seen_contexts.append(context)
        return Selection(refusal="no")

    monkeypatch.setattr(fake, "select", capture)
    _install_grid(monkeypatch, fake)
    _install_dispatch(monkeypatch, {})

    hdr = _headers(key[0], "eng@example.com")
    conv = client.post("/ask", json={"question": "how many pods in gcp?"},
                       headers=hdr).json()["conversation_id"]
    client.post("/ask", json={"question": "check again", "conversation_id": conv}, headers=hdr)

    assert "how many pods in gcp?" in seen_contexts[-1]
    assert "Earlier in this conversation" in seen_contexts[-1]


def test_first_question_has_no_history_preamble(env, key, monkeypatch) -> None:
    client, _ = env
    _activate("eng@example.com", Surface.K8S_GCP)
    fake = FakeGrid(Selection(refusal="no"))
    seen: list[str] = []

    async def capture(question, tool_specs, context="", max_calls=5):  # noqa: ANN001,ANN202
        seen.append(context)
        return Selection(refusal="no")

    monkeypatch.setattr(fake, "select", capture)
    _install_grid(monkeypatch, fake)
    _install_dispatch(monkeypatch, {})

    client.post("/ask", json={"question": "first ever"}, headers=_headers(key[0], "eng@example.com"))
    assert "Earlier in this conversation" not in seen[0]


def test_history_is_bounded(env, key, monkeypatch) -> None:
    """A long thread must not quietly triple the cost of every later question."""
    from app.api.ask import MAX_HISTORY_CHARS, _history
    from app.storage import get_storage

    client, _ = env
    _activate("eng@example.com", Surface.K8S_GCP)
    _install_grid(monkeypatch, FakeGrid(Selection(refusal="no")))
    _install_dispatch(monkeypatch, {})

    storage = get_storage()
    conv = storage.conversations.create(
        storage.users.get_or_create("eng@example.com").id
    )
    for i in range(40):
        storage.conversations.add_message(conv.id, "user", f"question {i} " + "x" * 400)
        storage.conversations.add_message(conv.id, "assistant", "answer " + "y" * 2000)

    text = _history(storage, conv.id)
    assert len(text) <= MAX_HISTORY_CHARS + 200
    assert "truncated" in text or "omitted" in text


# ---- streaming + deletion ---------------------------------------------------


def test_stream_emits_stages_calls_and_answer(env, key, monkeypatch) -> None:
    """Progress events are the same facts the evidence spine shows afterwards —
    which function, which cloud, did it succeed — reported as they happen."""
    client, _ = env
    _activate("eng@example.com", Surface.K8S_GCP)
    sel = Selection(calls=[ToolCall("pod_status", {"cloud": "gcp"})])
    _install_grid(monkeypatch, FakeGrid(sel))
    _install_dispatch(monkeypatch, {})

    with client.stream("POST", "/ask/stream", json={"question": "pods?"},
                       headers=_headers(key[0], "eng@example.com")) as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        events = [
            json.loads(line[len("data: "):])
            for line in resp.iter_lines()
            if line.startswith("data: ")
        ]

    kinds = [e["type"] for e in events]
    assert "stage" in kinds
    assert "call" in kinds
    assert kinds[-1] == "answer"
    stages = [e["stage"] for e in events if e["type"] == "stage"]
    assert "selecting" in stages and "running" in stages and "synthesizing" in stages
    call = next(e for e in events if e["type"] == "call")
    assert call["entry_name"] == "pod_status"
    assert call["ok"] is True


def test_stream_reports_failure_rather_than_going_silent(env, key, monkeypatch) -> None:
    client, _ = env
    _activate("eng@example.com", Surface.K8S_GCP)
    _install_grid(monkeypatch, FakeGrid(GridError("gateway exploded")))
    _install_dispatch(monkeypatch, {})

    with client.stream("POST", "/ask/stream", json={"question": "pods?"},
                       headers=_headers(key[0], "eng@example.com")) as resp:
        events = [
            json.loads(line[len("data: "):])
            for line in resp.iter_lines()
            if line.startswith("data: ")
        ]
    assert events[-1]["type"] == "error"
    assert "gateway exploded" in events[-1]["detail"]


def test_stream_and_ask_produce_the_same_answer(env, key, monkeypatch) -> None:
    """One code path serves both endpoints; two would drift, and the streaming
    one is where a divergence would be least visible."""
    client, _ = env
    _activate("eng@example.com", Surface.K8S_GCP)
    _install_grid(monkeypatch, FakeGrid(Selection(refusal="nothing to do")))
    _install_dispatch(monkeypatch, {})
    hdr = _headers(key[0], "eng@example.com")

    plain = client.post("/ask", json={"question": "x"}, headers=hdr).json()
    with client.stream("POST", "/ask/stream", json={"question": "x"}, headers=hdr) as resp:
        events = [
            json.loads(line[len("data: "):])
            for line in resp.iter_lines()
            if line.startswith("data: ")
        ]
    assert events[-1]["answer"] == plain["answer"]


def test_can_delete_own_conversation(env, key, monkeypatch) -> None:
    client, _ = env
    _activate("eng@example.com", Surface.K8S_GCP)
    _install_grid(monkeypatch, FakeGrid(Selection(refusal="no")))
    _install_dispatch(monkeypatch, {})
    hdr = _headers(key[0], "eng@example.com")

    conv = client.post("/ask", json={"question": "bye"}, headers=hdr).json()["conversation_id"]
    assert client.delete(f"/conversations/{conv}", headers=hdr).status_code == 204
    assert client.get(f"/conversations/{conv}", headers=hdr).status_code == 404
    assert client.get("/conversations", headers=hdr).json() == []


def test_cannot_delete_another_users_conversation(env, key, monkeypatch) -> None:
    """Ownership is in the WHERE clause, so a caller who skipped a check still
    cannot delete someone else's thread."""
    client, _ = env
    _activate("alice@example.com", Surface.K8S_GCP)
    _activate("mallory@example.com", Surface.K8S_GCP)
    _install_grid(monkeypatch, FakeGrid(Selection(refusal="no")))
    _install_dispatch(monkeypatch, {})

    alice = _headers(key[0], "alice@example.com")
    conv = client.post("/ask", json={"question": "mine"}, headers=alice).json()["conversation_id"]

    resp = client.delete(f"/conversations/{conv}", headers=_headers(key[0], "mallory@example.com"))
    assert resp.status_code == 404
    # And it is still there for its owner.
    assert client.get(f"/conversations/{conv}", headers=alice).status_code == 200


def test_evidence_budget_is_per_call_not_a_tail_cut() -> None:
    """A verbose early call must not crowd out a decisive later one.

    Observed live 2026-08-19: the model ran the full error-triage chain, and the
    final `logs_for_request_id` results — the ones holding the actual exception
    — were cut off by a global tail truncation, so the answer reported them as
    "not included". The last call in a chain is usually the answer.
    """
    from app.api.ask import MAX_EVIDENCE_CHARS, ToolCallOut, _evidence

    noisy = ToolCallOut(
        entry_name="error_request_ids",
        params={},
        target="opensearch_gcp",
        ok=True,
        output="X" * (MAX_EVIDENCE_CHARS * 3),
    )
    decisive = ToolCallOut(
        entry_name="logs_for_request_id",
        params={},
        target="opensearch_gcp",
        ok=True,
        output="NullPointerException in the payment handler",
    )

    text = _evidence([noisy, decisive])

    assert "logs_for_request_id" in text, "the last call must survive truncation"
    assert "NullPointerException in the payment handler" in text
    assert "THIS RESULT TRUNCATED" in text, "the trimmed call must say it is partial"


def test_a_failed_call_keeps_its_error_intact() -> None:
    """Failures are short and diagnostic — never worth truncating."""
    from app.api.ask import ToolCallOut, _evidence

    text = _evidence(
        [
            ToolCallOut(
                entry_name="ch_query",
                params={},
                target="ch_prod",
                ok=False,
                error="clickhouse connection has no host configured",
            )
        ]
    )
    assert "no host configured" in text


def test_calls_in_a_round_run_concurrently() -> None:
    """A round of reads against different backends took the SUM of their
    latencies for no reason: nothing in a round depends on anything else in it,
    because the model only sees results at the end of the round. A live question
    used 14 calls — serially that is 14 latencies stacked inside a 300s budget.
    """
    import inspect

    from app.api import ask

    source = inspect.getsource(ask._run_calls)
    assert "asyncio.gather" in source, "round execution must be concurrent"
    assert "return_exceptions=True" in source, (
        "one backend raising must not discard the results that succeeded"
    )


def test_call_order_survives_concurrency() -> None:
    """Results must read as the sequence the model ASKED for, not the order
    backends happened to answer in — otherwise the same question renders
    differently each run and the evidence stops being reproducible."""
    import inspect

    from app.api import ask

    source = inspect.getsource(ask._run_calls)
    assert "zip(calls, results" in source


@pytest.mark.anyio
async def test_call_start_precedes_result_and_ids_match(monkeypatch):
    """Every call announces itself BEFORE it runs, and settles under the same id.

    This is the whole basis of the live UI: a row is created on `call_start`
    and found again on `call`. If the ids drifted, rows would spin forever
    while duplicates piled up underneath — and the failure would only ever
    appear in a browser, never in a test.
    """
    from app.api import ask as ask_mod

    events: list[tuple[str, dict]] = []

    async def say(kind, **payload):
        events.append((kind, payload))

    class _Call:
        def __init__(self, name):
            self.name = name
            self.arguments = {"query": f"select from {name}"}

    async def fake_dispatch(name, args, granted_surfaces=None):
        from app.executors.base import ExecResult
        return ExecResult(ok=True, entry_name=name, target="t",
                          rows=[{"a": 1}], text="x", duration_ms=1)

    monkeypatch.setattr(ask_mod, "dispatch", fake_dispatch)
    monkeypatch.setattr(ask_mod.audit, "audit_call", lambda **kw: None)

    out: list = []
    calls = [_Call("one"), _Call("two"), _Call("three")]
    await ask_mod._run_calls(
        calls, out, registry=SimpleNamespace(get=lambda n: None),
        surfaces=set(), email="e@x", conversation_id=1, question="q",
        say=say, first_index=0,
    )

    starts = [p for k, p in events if k == "call_start"]
    ends = [p for k, p in events if k == "call"]
    assert len(starts) == len(ends) == 3
    assert {s["id"] for s in starts} == {e["id"] for e in ends} == {0, 1, 2}

    # Ordering: a call's start must be on the wire before its own result.
    order = [(k, p["id"]) for k, p in events if k in ("call_start", "call")]
    for cid in (0, 1, 2):
        assert order.index(("call_start", cid)) < order.index(("call", cid))

    # Params ride along on the start event — that is what the row expands to.
    assert all("query" in s["params"] for s in starts)
    # Results are ordered as the model asked, regardless of completion order.
    assert [c.entry_name for c in out] == ["one", "two", "three"]


class EndlessGrid(FakeGrid):
    """A selector that always wants one more, different call.

    Under a round or call cap this grid was un-writable-against — the cap
    stopped it. Now only the clock can, which is exactly what this proves.
    """

    def __init__(self) -> None:
        super().__init__(Selection(calls=[]))
        self.round = 0
        self.contexts: list[str] = []

    async def select(self, question, tool_specs, context="", max_calls=200):  # noqa: ANN001,ANN201
        self.round += 1
        self.contexts.append(context)
        # Different args every round, so dedupe never ends the loop for us.
        call = ToolCall("pod_status", {"service": f"svc-{self.round}", "cloud": "gcp"})
        return Selection(calls=[call])

    async def synthesize(self, question, evidence, context=""):  # noqa: ANN001,ANN201
        self.evidence = evidence
        self.synth_context = context
        return self.answer, Usage(7, 3)


def test_time_budget_ends_the_loop_and_admits_it(env, key, monkeypatch) -> None:
    """An expired budget stops SELECTION and the answer says it is partial.

    Zero budget on purpose: the deadline is already behind us after round one,
    so with a selector that would go forever, exactly one round runs. The
    synthesiser must be told the picture is partial — an incomplete answer that
    says so is useful; one that pretends to be complete is dangerous.
    """
    client, _ = env
    _activate("eng@example.com", Surface.K8S_GCP)
    monkeypatch.setattr(config, "ANSWER_TIME_BUDGET_S", 0)
    fake = EndlessGrid()
    _install_grid(monkeypatch, fake)
    _install_dispatch(
        monkeypatch,
        {"pod_status": ExecResult(ok=True, entry_name="pod_status", target="k8s_gcp",
                                  text="ok")},
    )

    data = client.post("/ask", json={"question": "sweep everything"},
                       headers=_headers(key[0], "eng@example.com")).json()

    assert fake.round == 1, "selection kept going after the budget expired"
    assert len(data["calls"]) == 1
    assert "PARTIAL" in fake.synth_context
    assert "time budget" in fake.synth_context


def test_within_budget_the_loop_is_not_capped_by_a_count(env, key, monkeypatch) -> None:
    """Many rounds are fine while there is time.

    The old MAX_SELECTION_ROUNDS/MAX_CALLS_PER_QUESTION pair would have cut
    this off; the clock does not care how many calls thoroughness takes.
    """
    client, _ = env
    _activate("eng@example.com", Surface.K8S_GCP)
    monkeypatch.setattr(config, "ANSWER_TIME_BUDGET_S", 600)

    class FortyRounds(EndlessGrid):
        async def select(self, question, tool_specs, context="", max_calls=200):  # noqa: ANN001,ANN201
            self.round += 1
            if self.round > 40:
                return Selection(calls=[])
            call = ToolCall("pod_status", {"service": f"svc-{self.round}", "cloud": "gcp"})
            return Selection(calls=[call])

    fake = FortyRounds()
    _install_grid(monkeypatch, fake)
    _install_dispatch(
        monkeypatch,
        {"pod_status": ExecResult(ok=True, entry_name="pod_status", target="k8s_gcp",
                                  text="ok")},
    )

    data = client.post("/ask", json={"question": "deep sweep"},
                       headers=_headers(key[0], "eng@example.com")).json()
    assert len(data["calls"]) == 40, "a count limit is back"
    assert "PARTIAL" not in getattr(fake, "synth_context", "")
