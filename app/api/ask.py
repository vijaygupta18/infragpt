"""Chat endpoint — the orchestration loop.

    authenticate -> retrieve runbooks -> Grid select ({function, params}, limited
    to the caller's granted surfaces) -> validate params (reject, never repair)
    -> execute -> redact -> Grid synthesize -> respond with the answer, the exact
    functions called, and the redacted raw output -> audit.

Two properties this file is responsible for preserving:

* **Nothing runs that the caller isn't granted.** Grants filter what the selector
  is even shown, and ``dispatch`` re-checks them at execution. Both, always.
* **Failures stay visible.** A failed call is passed to the synthesizer as a
  failure and surfaced in the response, never dropped. Silently discarding a
  failed call is how an assistant ends up answering from model memory.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field

from app import audit, config, experience
from app.auth.deps import Principal, current_user
from app.executors.dispatch import dispatch
from app.grid.client import GridError, get_grid_client
from app.limits.deps import check_token_budget, enforce_question_rate, record_question_tokens
from app.registry.loader import get_registry, resolve_target, unavailable_surfaces
from app.registry.schema import Surface
from app.runbooks import get_runbooks
from app.runs import Run, get_run_registry
from app.storage import Storage, get_storage

router = APIRouter(tags=["ask"])

# 40k characters of evidence is roughly 10k tokens, and a namespace listing
# alone reached 22k input tokens in practice — enough to push the synthesis call
# past its timeout. Capping harder trades a little detail for an answer that
# actually arrives, and the full output is still one click away in the UI.
# Raised with the call budget. ~60k chars is roughly 15k tokens of evidence,
# which the synthesis model handles comfortably, and it is what lets a 30-call
# investigation still give each result room to be read rather than trimmed to a
# stub. Raising the call count without this makes answers worse, not better.
MAX_EVIDENCE_CHARS = 60_000
#: Floor on each call's share, so a long chain cannot squeeze every result down
#: to something useless. A chain of 12 calls is normal for error triage.
MIN_EVIDENCE_PER_CALL = 2_000

#: How much prior conversation to replay into the model. Follow-ups like "check
#: again", "what about aws?" or "and the rider side?" are the normal way people
#: talk to this, and without history they are unanswerable — the model correctly
#: but uselessly replies that it needs more context.
#:
#: Bounded on both axes: enough turns to carry a thread, few enough that a long
#: conversation cannot quietly triple the cost of every question or push the
#: runbooks out of the selector's context.
MAX_HISTORY_TURNS = 6
MAX_HISTORY_CHARS = 6_000


def _history(storage: Storage, conversation_id: int, exclude_last: bool = True) -> str:
    """Recent turns, oldest first, as plain text for the prompt.

    Answers are truncated harder than questions: a question is short and carries
    the intent, whereas a full prior answer is mostly evidence that has already
    served its purpose. What matters for a follow-up is what was ASKED and
    roughly what came back.
    """
    messages = storage.conversations.messages(conversation_id)
    if exclude_last and messages:
        messages = messages[:-1]  # the current question is already in the prompt
    if not messages:
        return ""
    recent = messages[-(MAX_HISTORY_TURNS * 2):]
    lines: list[str] = []
    for m in recent:
        who = "User" if m.role == "user" else "Assistant"
        body = m.content.strip()
        if m.role != "user" and len(body) > 700:
            body = body[:700] + " […truncated]"
        lines.append(f"{who}: {body}")
    text = "\n\n".join(lines)
    if len(text) > MAX_HISTORY_CHARS:
        text = "[…earlier turns omitted]\n\n" + text[-MAX_HISTORY_CHARS:]
    return text

# Selection happens in rounds so a question like "list the caches, then check each
# for evictions" can work: round 1 discovers the identifiers, round 2 uses them.
#
# The loop is bounded by TIME (config.ANSWER_TIME_BUDGET_S), not by a round or
# call count. Every count chosen here was wrong within a week — 2 rounds
# stranded an investigation with pod_logs unused, 30 calls cut off an
# error-triage chain one read short — because a count is a proxy for the thing
# that actually matters, which is how long someone is left waiting. So the wait
# is what is capped. Within the window the selector may keep going; when the
# window closes, the loop stops selecting and synthesises from what it has,
# and the answer says the picture is partial rather than passing it off as
# complete.
#
# What stops a runaway is unchanged: each call has its own timeout, the DB pool
# is capped, credentials cannot write, duplicate calls are dropped, and the
# loop ends the moment a follow-up selection asks for nothing.


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4000)
    conversation_id: int | None = None


class ToolCallOut(BaseModel):
    entry_name: str
    params: dict[str, Any]
    target: str
    cloud: str | None = None
    ok: bool
    error: str | None = None
    output: str = ""


def _evidence_json(calls: list[ToolCallOut]) -> str:
    """Serialise the calls behind an answer, for storage alongside it.

    Outputs are dropped and only their size kept. The full output was already
    redacted and shown live, and a conversation database that accumulates every
    pod log and Redis value ever read becomes a second copy of production data
    on a volume with a weaker claim to holding it. What survives is what makes
    the answer checkable later: what ran, against which cloud, and whether it
    worked.
    """
    return json.dumps(
        [
            {
                "entry_name": c.entry_name,
                "params": c.params,
                "target": c.target,
                "cloud": c.cloud,
                "ok": c.ok,
                "error": c.error,
                "output_chars": len(c.output),
            }
            for c in calls
        ],
        separators=(",", ":"),
    )


class AskResponse(BaseModel):
    conversation_id: int
    answer: str
    calls: list[ToolCallOut] = Field(default_factory=list)


def _surfaces(principal: Principal) -> set[Surface]:
    out: set[Surface] = set()
    for raw in principal.surfaces:
        try:
            out.add(Surface(raw))
        except ValueError:
            continue  # unknown grant string: ignore rather than trust
    return out


def _log_uncovered(email: str, question: str, reason: str) -> None:
    """Feed the registry backlog. Optional dependency: the coverage module is
    owned by another workstream, so its absence must not break /ask."""
    try:
        from app import coverage
    except ImportError:
        return
    recorder = getattr(coverage, "record_uncovered", None)
    if callable(recorder):
        recorder(email=email, question=question, reason=reason)


def _evidence(calls: list[ToolCallOut]) -> str:
    """Render the calls for the synthesiser, with a PER-CALL budget.

    Truncation used to append every call and cut the tail. That dropped the
    LAST calls, which are the ones that answer the question: an error-triage
    chain ends with the application log holding the actual exception, and the
    access-log dumps earlier in the chain are far more verbose. Observed live —
    the model correctly ran the whole chain, then reported the final step as
    "not included", because its output had been cut off.

    So the budget is divided between calls instead. Every call is guaranteed a
    share, each is truncated within its own share, and a verbose early call can
    no longer crowd out a decisive later one. Where a call is trimmed it says so
    in place, so the synthesiser knows that specific result is partial rather
    than inferring the whole picture is complete.
    """
    if not calls:
        return ""

    # Failures are cheap and diagnostic; they keep their whole text. The rest
    # split what is left, so the share reflects what actually competes for room.
    heavy = [c for c in calls if c.ok] or list(calls)
    share = max(MAX_EVIDENCE_CHARS // max(len(heavy), 1), MIN_EVIDENCE_PER_CALL)

    blocks: list[str] = []
    for call in calls:
        header = f"### {call.entry_name} (target={call.target}"
        if call.cloud:
            header += f", cloud={call.cloud}"
        header += ")"

        if not call.ok:
            body = f"FAILED: {call.error}"
        else:
            body = call.output or "(returned no rows)"
            if len(body) > share:
                dropped = len(body) - share
                body = (
                    body[:share]
                    + f"\n[THIS RESULT TRUNCATED: {dropped} more characters. Any "
                    "count or total from THIS call is a LOWER BOUND — say so. "
                    "Other calls below are unaffected.]"
                )
        blocks.append(f"{header}\nparams: {call.params}\n{body}")

    return "\n\n".join(blocks)


async def _answer(
    body: AskRequest,
    principal: Principal,
    storage: Storage,
    emit: Callable[[str, dict[str, Any]], Awaitable[None]] | None = None,
) -> AskResponse:
    """Run one question. `emit` receives progress events as they happen.

    The same code path serves both endpoints: /ask discards the events and
    returns once, /ask/stream forwards them as SSE. Two implementations would
    drift, and the streaming one is exactly where a divergence would be least
    visible.
    """

    async def _say(kind: str, **payload: Any) -> None:
        if emit is not None:
            await emit(kind, payload)

    # Budget is checked before the rate limit is *consumed*, so a caller who is
    # already over budget doesn't also lose a question from their hourly
    # allowance for a request that was never going to run.
    started = time.monotonic()
    question = body.question.strip()
    email = principal.email

    conv = None
    if body.conversation_id is not None:
        conv = storage.conversations.get(body.conversation_id)
        if conv is None or conv.user_id != principal.user.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="no such conversation"
            )
    if conv is None:
        conv = storage.conversations.create(principal.user.id)
    storage.conversations.add_message(conv.id, "user", question)

    surfaces = _surfaces(principal) - unavailable_surfaces()
    registry = get_registry()
    tool_specs = registry.llm_tool_specs(surfaces)

    runbook_context = get_runbooks().context_for(question)
    history = _history(storage, conv.id)
    # History first: it tells the selector what "it", "that" and "check again"
    # refer to, which the runbooks cannot.
    # What this tool has actually observed lately, counted from its own audit
    # log. This is the only part of the context that is LEARNED rather than
    # written by a person — see app/experience.py for why it is limited to
    # counts, and never to anything a model authored.
    try:
        learned = experience.hints({e.name for e in registry.entries_for_surfaces(surfaces)})
    except Exception:  # noqa: BLE001 - never let the learning layer break a question
        learned = ""

    selector_context = "\n\n".join(
        part
        for part in (
            f"Earlier in this conversation:\n{history}" if history else "",
            runbook_context,
            learned,
        )
        if part
    )
    grid = get_grid_client()

    def _fail(detail: str, code: int = status.HTTP_502_BAD_GATEWAY) -> HTTPException:
        audit.audit_question(
            user_email=email,
            conversation_id=conv.id,
            question=question,
            ok=False,
            error=detail,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return HTTPException(status_code=code, detail=detail)

    await _say("stage", stage="selecting",
               detail=f"choosing from {len(tool_specs)} available functions")
    try:
        selection = await grid.select(question, tool_specs, context=selector_context)
    except GridError as exc:
        raise _fail(f"selector failed: {exc}") from exc

    usage = selection.usage

    # No tool call: nothing in the registry covers this. A first-class outcome.
    if not selection.calls:
        answer = selection.refusal or "I don't have a way to answer that yet."
        _log_uncovered(email, question, answer)
        # "[]" not None: this answer ran nothing, and the UI says so out loud.
        # Recording it as "not captured" would let an unsupported answer pass
        # for an ordinary one.
        storage.conversations.add_message(conv.id, "assistant", answer, evidence="[]")
        audit.audit_question(
            user_email=email,
            conversation_id=conv.id,
            question=question,
            ok=True,
            answer=answer,
            answer_sha256=audit.sha256_text(answer),
            entry_names=[],
            duration_ms=int((time.monotonic() - started) * 1000),
            tokens_in=usage.tokens_in,
            tokens_out=usage.tokens_out,
        )
        # A declined answer still cost selector tokens, so it still counts.
        record_question_tokens(
            principal.user.id, usage.tokens_in, usage.tokens_out, db=storage.db
        )
        return AskResponse(conversation_id=conv.id, answer=answer, calls=[])

    calls_out: list[ToolCallOut] = []
    deadline = started + config.ANSWER_TIME_BUDGET_S
    out_of_time = False
    pending = list(selection.calls)
    while pending:
        await _say("stage", stage="running",
                   detail=", ".join(c.name for c in pending))
        before = len(calls_out)
        await _run_calls(
            pending, calls_out, registry, surfaces, email, conv.id, question,
            say=_say, first_index=before,
        )
        pending = []
        if time.monotonic() >= deadline:
            # The window has closed. Stop SELECTING — never stop mid-round, so
            # every result the model asked for is either complete or absent,
            # and answer from what is in hand.
            out_of_time = True
            break
        # Give the selector what came back and let it ask for follow-ups. It
        # returns nothing when the question is already answered, which is the
        # common case and costs one cheap call.
        try:
            follow = await grid.select(
                question,
                tool_specs,
                context=(
                    f"{selector_context}\n\nAlready gathered:\n{_evidence(calls_out)}\n\n"
                    "If this fully answers the question, call nothing.\n"
                    "Otherwise CONTINUE THE INVESTIGATION rather than restating it. "
                    "If the results above gave you identifiers you did not have "
                    "before — pod names, table names, cluster ids, cache keys — "
                    "call the function that USES them now. Listing something and "
                    "then asking the user to supply the next step is a failure: "
                    "you have the identifiers and the functions to act on them. "
                    "Do not repeat a call you already made with the same arguments."
                ),
            )
        except GridError:
            break  # a failed follow-up must not lose the answer we already have
        usage = usage + follow.usage
        already = {(c.entry_name, str(c.params)) for c in calls_out}
        pending = [
            c for c in follow.calls if (c.name, str(c.arguments)) not in already
        ]

    if out_of_time:
        elapsed = int(time.monotonic() - started)
        await _say("stage", stage="synthesizing",
                   detail=f"time budget reached after {elapsed}s — "
                          f"summarising {len(calls_out)} result(s)")
        selector_context += (
            "\n\nIMPORTANT: the investigation hit its time budget before it "
            "finished. Answer from the evidence above, state clearly that the "
            "picture is PARTIAL, and name what you would have checked next — "
            "an incomplete answer that says so is useful; one that pretends to "
            "be complete is dangerous."
        )
    else:
        await _say("stage", stage="synthesizing",
                   detail=f"reading {len(calls_out)} result(s)")
    # Stream the answer when someone is watching. Synthesis is the longest
    # single wait in a question, and a spinner for twenty seconds after the
    # evidence is already in reads as a hang. Streaming changes nothing about
    # the answer, only about how long it FEELS.
    #
    # The fallback is deliberate and silent: a gateway that does not support
    # SSE, or a stream that dies mid-flight, must cost a little latency and not
    # the answer. Same call, same prompt, non-streaming.
    try:
        if emit is not None:
            try:
                async def _token(piece: str) -> None:
                    await _say("token", text=piece)

                answer, synth_usage = await grid.synthesize_stream(
                    question, _evidence(calls_out),
                    context=selector_context, on_token=_token,
                )
            except Exception:  # noqa: BLE001
                # ANY streaming failure falls back, not just GridError: a
                # gateway that does not implement SSE fails in whatever way it
                # likes, and this path exists precisely to survive that. The
                # retry is the real attempt — if the answer cannot be written
                # at all, the non-streaming call raises and the user is told.
                await _say("token_reset")
                answer, synth_usage = await grid.synthesize(
                    question, _evidence(calls_out), context=selector_context
                )
        else:
            answer, synth_usage = await grid.synthesize(
                question, _evidence(calls_out), context=selector_context
            )
    except GridError as exc:
        raise _fail(f"synthesis failed: {exc}") from exc
    usage = usage + synth_usage

    storage.conversations.add_message(
        conv.id, "assistant", answer, evidence=_evidence_json(calls_out)
    )
    audit.audit_question(
        user_email=email,
        conversation_id=conv.id,
        question=question,
        ok=True,
        answer=answer,
        answer_sha256=audit.sha256_text(answer),
        entry_names=[c.entry_name for c in calls_out],
        duration_ms=int((time.monotonic() - started) * 1000),
        tokens_in=usage.tokens_in,
        tokens_out=usage.tokens_out,
    )
    record_question_tokens(principal.user.id, usage.tokens_in, usage.tokens_out, db=storage.db)
    return AskResponse(conversation_id=conv.id, answer=answer, calls=calls_out)


async def _run_calls(
    calls: list[Any],
    calls_out: list[ToolCallOut],
    registry: Any,
    surfaces: set[Surface],
    email: str,
    conversation_id: int,
    question: str,
    say: Callable[..., Awaitable[None]] | None = None,
    first_index: int = 0,
) -> None:
    """Execute one round of selected calls, appending to `calls_out`.

    Calls in a round run CONCURRENTLY. They were serial, and a round of five
    reads that each wait on a different backend took the sum of five round trips
    for no reason — nothing in a round depends on anything else in it, because
    the model only learns the results at the end of the round. A live question
    used 14 calls; serially that is 14 latencies stacked inside a 300s budget.

    Order is preserved regardless of completion order: the evidence and the UI
    read as the sequence the model asked for, not the order backends happened to
    answer in, which would make the same question look different each run.

    Every call is audited, and a failure is recorded as a failed ToolCallOut
    rather than raised — the synthesiser must see failures, not be shielded
    from them.

    PROGRESS IS EMITTED TWICE PER CALL: once when it STARTS and again when it
    finishes. Emitting only on completion made the concurrency invisible — the
    screen sat still for as long as the slowest backend took, then printed a
    burst of finished rows, so a working parallel round looked like a hung
    serial one. The start event is what lets the UI show four things running at
    once, which is both truthful and the only honest way to explain a 30s wait.
    """

    async def _one(index: int, call: Any) -> ToolCallOut:
        call_started = time.monotonic()
        if say is not None:
            # Before the await, so it is on the wire while the backend works.
            await say(
                "call_start",
                id=index,
                entry_name=call.name,
                params=call.arguments,
                cloud=call.arguments.get("cloud"),
            )
        result = await dispatch(call.name, call.arguments, granted_surfaces=surfaces)

        cloud = call.arguments.get("cloud")
        target = result.target
        if not target:
            try:
                entry = registry.get(call.name)
                target = resolve_target(entry, call.arguments)
            except Exception:  # noqa: BLE001 - display only, never fatal
                target = ""

        out_text = result.text or _rows_to_text(result.rows)
        audit.audit_call(
            user_email=email,
            conversation_id=conversation_id,
            question=question,
            entry_name=call.name,
            params=call.arguments,
            target=target,
            cloud=str(cloud) if cloud else None,
            validation_verdict="accepted" if result.ok else "rejected",
            ok=result.ok,
            error=result.error,
            output_sha256=audit.sha256_text(out_text),
            rows=len(result.rows or []),
            # Recorded because ROWS ALONE UNDERSTATE USEFULNESS: the kubectl and
            # shell executors return text and no rows at all, so counting only
            # rows would teach the experience layer that every k8s function
            # returns nothing — the precise false negative it exists to catch.
            chars=len(out_text or ""),
            duration_ms=int((time.monotonic() - call_started) * 1000),
        )
        out = ToolCallOut(
            entry_name=call.name,
            params=call.arguments,
            target=target,
            cloud=str(cloud) if cloud else None,
            ok=result.ok,
            error=result.error,
            output=out_text,
        )
        if say is not None:
            await say(
                "call",
                id=index,
                entry_name=out.entry_name,
                params=out.params,
                cloud=out.cloud,
                target=target,
                ok=out.ok,
                error=out.error,
                rows=len(result.rows or []),
                chars=len(out_text or ""),
                duration_ms=int((time.monotonic() - call_started) * 1000),
            )
        return out

    # return_exceptions: one backend raising must not discard the results of
    # the calls that succeeded alongside it.
    results = await asyncio.gather(
        *(_one(first_index + i, c) for i, c in enumerate(calls)),
        return_exceptions=True,
    )
    for call, outcome in zip(calls, results, strict=True):
        if isinstance(outcome, BaseException):
            calls_out.append(
                ToolCallOut(
                    entry_name=call.name,
                    params=call.arguments,
                    target="",
                    ok=False,
                    error=f"{type(outcome).__name__}: {outcome}"[:300],
                    output="",
                )
            )
        else:
            calls_out.append(outcome)


def _rows_to_text(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return ""
    headers = list(rows[0].keys())
    lines = [" | ".join(headers), "-" * 40]
    lines += [" | ".join(str(row.get(h, "")) for h in headers) for row in rows]
    return "\n".join(lines)


@router.post("/ask", response_model=AskResponse)
async def ask_endpoint(
    body: AskRequest,
    principal: Annotated[Principal, Depends(check_token_budget)],
    storage: Annotated[Storage, Depends(get_storage)],
    _rate: Annotated[Principal, Depends(enforce_question_rate)] = None,  # noqa: RUF013
) -> AskResponse:
    return await _answer(body, principal, storage)


@router.post("/ask/stream")
async def ask_stream(
    body: AskRequest,
    principal: Annotated[Principal, Depends(check_token_budget)],
    storage: Annotated[Storage, Depends(get_storage)],
    _rate: Annotated[Principal, Depends(enforce_question_rate)] = None,  # noqa: RUF013
) -> StreamingResponse:
    """Start a question and stream it. The work outlives this connection.

    The run is created first and the connection merely attaches to it, so
    closing the tab, reloading, or losing the network stops the STREAM and not
    the WORK. Previously the task was cancelled in a `finally` when the
    generator closed, which meant a reload threw away a minute of gathering and
    left nothing to come back to.

    The first event carries the run id, so a client that reloads can reattach.
    """
    registry = get_run_registry()
    run = registry.create(principal.email, body.question.strip())

    async def emit(kind: str, payload: dict[str, Any]) -> None:
        run.publish(kind, payload)

    async def work() -> None:
        try:
            result = await _answer(body, principal, storage, emit=emit)
            run.conversation_id = result.conversation_id
            run.publish("answer", result.model_dump())
            run.finish("done")
        except asyncio.CancelledError:
            # Stopping is a decision, and `stop` has already recorded it.
            raise
        except HTTPException as exc:
            run.publish("error", {"detail": str(exc.detail)})
            run.finish("error")
        except Exception as exc:  # noqa: BLE001 - surfaced, never swallowed
            run.publish("error", {"detail": f"{type(exc).__name__}: {exc}"})
            run.finish("error")

    run.task = asyncio.create_task(work())
    # The run id is NOT published into the buffer — _attach sends it as a
    # preamble on every attach. Publishing it too would put an event in the
    # buffer that the client must not count, and the client's event count is
    # what makes `after=` line up with the buffer on reattach. One source.
    return _attach(run, from_index=0)


@router.get("/ask/runs/{run_id}/stream")
async def ask_reattach(
    run_id: str,
    principal: Annotated[Principal, Depends(current_user)],
    after: int = 0,
) -> StreamingResponse:
    """Reattach to a run already in progress, replaying what was missed."""
    run = get_run_registry().get(run_id, principal.email)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such run")
    return _attach(run, from_index=after)


@router.post("/ask/runs/{run_id}/stop")
async def ask_stop(
    run_id: str,
    principal: Annotated[Principal, Depends(current_user)],
) -> dict[str, Any]:
    """Stop a run the caller started.

    Separate from detaching on purpose: leaving the page must not cancel work,
    so cancelling has to be something a person asks for.
    """
    registry = get_run_registry()
    run = registry.get(run_id, principal.email)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such run")
    if run.live:
        registry.stop(run)
    return {"run_id": run.id, "status": run.status}


@router.get("/ask/runs")
async def ask_runs(
    principal: Annotated[Principal, Depends(current_user)],
) -> list[dict[str, Any]]:
    """Runs of the caller's that are still going — what to reattach to."""
    return [
        {
            "run_id": r.id,
            "question": r.question,
            "events": len(r.events) + r.dropped,
            "conversation_id": r.conversation_id,
        }
        for r in get_run_registry().active_for(principal.email)
    ]


def _attach(run: Run, from_index: int) -> StreamingResponse:
    """Stream one run's events. Detaching never touches the run."""

    async def events() -> AsyncIterator[str]:
        # The id goes first on every attach, including reattaches, so the client
        # never has to remember which run it is watching.
        yield f'data: {json.dumps({"type": "run", "run_id": run.id})}\n\n'
        # Heartbeat during quiet stretches. A slow call can hold the stream
        # silent for 30s+, and every idle-timeout between here and the browser
        # (mesh sidecar, proxy, LB) is entitled to kill a silent stream. An SSE
        # comment is invisible to the parser and resets those clocks. It does
        # NOT extend the load balancer's total-duration cap — nothing can; the
        # client survives that one by reattaching.
        sub = run.subscribe(from_index)
        nxt = asyncio.ensure_future(anext(sub))
        try:
            while True:
                done, _ = await asyncio.wait({nxt}, timeout=15)
                if not done:
                    yield ": keepalive\n\n"
                    continue
                try:
                    item = nxt.result()
                except StopAsyncIteration:
                    break
                yield f"data: {item}\n\n"
                nxt = asyncio.ensure_future(anext(sub))
        finally:
            nxt.cancel()
            await sub.aclose()

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/conversations")
async def list_conversations(
    principal: Annotated[Principal, Depends(current_user)],
    storage: Annotated[Storage, Depends(get_storage)],
) -> list[dict[str, Any]]:
    return [
        {"id": c.id, "created_at": c.created_at}
        for c in storage.conversations.list_for_user(principal.user.id)
    ]


@router.delete("/conversations/{conversation_id}", status_code=204)
async def delete_conversation(
    conversation_id: int,
    principal: Annotated[Principal, Depends(current_user)],
    storage: Annotated[Storage, Depends(get_storage)],
) -> Response:
    """Delete one of YOUR conversations, and its messages.

    Ownership is enforced in the query, not by a prior check. 404 for both
    "missing" and "someone else's", so this cannot be used to discover which
    conversation ids exist.

    Note the audit log is NOT touched: it is append-only and records who asked
    what and which functions ran. Deleting a thread removes it from your history;
    it does not erase the record that the queries happened.
    """
    if not storage.conversations.delete(conversation_id, principal.user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such conversation")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/conversations/{conversation_id}")
async def get_conversation(
    conversation_id: int,
    principal: Annotated[Principal, Depends(current_user)],
    storage: Annotated[Storage, Depends(get_storage)],
) -> dict[str, Any]:
    conv = storage.conversations.get(conversation_id)
    if conv is None or conv.user_id != principal.user.id:
        # Same response for "missing" and "someone else's" — no enumeration.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such conversation")
    return {
        "id": conv.id,
        "created_at": conv.created_at,
        "messages": [
            {"role": m.role, "content": m.content, "created_at": m.created_at}
            for m in storage.conversations.messages(conv.id)
        ],
    }
