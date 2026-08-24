"""A run outlives the connection that started it."""

from __future__ import annotations

import asyncio

import pytest

from app.runs import MAX_BUFFERED_EVENTS, RunRegistry


@pytest.mark.anyio
async def test_detaching_does_not_stop_the_run():
    """The whole point: a closed stream must not cancel the work.

    This was the bug — the SSE generator cancelled its task in a `finally`, so
    a page reload threw away a minute of gathering and left nothing behind.
    """
    reg = RunRegistry()
    run = reg.create("a@x", "q")
    ticked = asyncio.Event()

    async def work():
        run.publish("stage", {"stage": "selecting"})
        await ticked.wait()
        run.publish("answer", {"answer": "done"})
        run.finish("done")

    run.task = asyncio.create_task(work())

    # Attach, take one event, walk away mid-run.
    got = []
    agen = run.subscribe(0)
    got.append(await agen.__anext__())
    await agen.aclose()

    assert run.live, "closing a subscriber must not end the run"
    ticked.set()
    await run.task
    assert run.status == "done"

    # Reattaching from zero replays everything, including what was missed.
    replay = [e async for e in run.subscribe(0)]
    assert len(replay) == 2
    assert "answer" in replay[-1]


@pytest.mark.anyio
async def test_reattach_after_index_returns_only_the_gap():
    reg = RunRegistry()
    run = reg.create("a@x", "q")
    for i in range(5):
        run.publish("call", {"id": i})
    run.finish("done")

    seen = [e async for e in run.subscribe(3)]
    assert len(seen) == 2
    assert '"id": 3' in seen[0]


@pytest.mark.anyio
async def test_stop_cancels_the_task_and_records_it():
    reg = RunRegistry()
    run = reg.create("a@x", "q")

    async def forever():
        await asyncio.sleep(60)

    run.task = asyncio.create_task(forever())
    await asyncio.sleep(0)
    reg.stop(run)

    assert run.status == "stopped"
    assert not run.live
    assert any("stopped" in e for e in run.events)
    await asyncio.sleep(0)
    assert run.task.cancelled() or run.task.done()


@pytest.mark.anyio
async def test_a_run_belongs_to_the_person_who_started_it():
    """An unguessable id is not an authorisation model."""
    reg = RunRegistry()
    run = reg.create("owner@x", "q")
    assert reg.get(run.id, "owner@x") is not None
    assert reg.get(run.id, "someone.else@x") is None


@pytest.mark.anyio
async def test_the_buffer_is_bounded_and_drops_from_the_front():
    """A pathological run must not grow without limit.

    The tail is what a late viewer needs, so the front is what goes — and the
    count of what went is kept, so a reattaching client's index still lands in
    the right place instead of silently skipping events.
    """
    reg = RunRegistry()
    run = reg.create("a@x", "q")
    for i in range(MAX_BUFFERED_EVENTS + 50):
        run.publish("call", {"id": i})
    run.finish("done")

    assert len(run.events) == MAX_BUFFERED_EVENTS
    assert run.dropped == 50
    assert f'"id": {MAX_BUFFERED_EVENTS + 49}' in run.events[-1]

    # An index inside the dropped range clamps to the oldest kept event rather
    # than running off the end.
    seen = [e async for e in run.subscribe(10)]
    assert len(seen) == MAX_BUFFERED_EVENTS


@pytest.mark.anyio
async def test_reattach_index_lines_up_with_the_buffer_exactly():
    """A client that counted N events and reattaches with after=N misses
    nothing and repeats nothing.

    This is the contract the whole reattach design leans on, and it is easy to
    break from either side — the server once published the run id into the
    buffer while also sending it as an attach preamble, so a counting client
    was one ahead and silently skipped a real event per reattach.
    """
    reg = RunRegistry()
    run = reg.create("a@x", "q")
    for i in range(7):
        run.publish("call", {"id": i})

    # Client saw 4, drops, reattaches.
    seen = []
    agen = run.subscribe(0)
    for _ in range(4):
        seen.append(await agen.__anext__())
    await agen.aclose()

    run.publish("call", {"id": 7})
    run.finish("done")

    rest = [e async for e in run.subscribe(len(seen))]
    ids = [int(e.split('"id": ')[1].rstrip("}")) for e in seen + rest]
    assert ids == [0, 1, 2, 3, 4, 5, 6, 7], f"gap or repeat: {ids}"
