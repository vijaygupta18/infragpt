"""Questions that outlive the connection that asked them.

A question can take a minute. Until now the work lived inside the HTTP
response: reloading the page, following a link, or a laptop sleeping closed the
connection, the generator was closed, and the task was cancelled in a `finally`.
The user came back to nothing — not a partial answer, not an error, just a lost
minute and no way to tell whether it had ever been running.

So a run is now a thing with an identity. Starting a question creates a Run and
returns its id immediately; the SSE endpoint ATTACHES to that run rather than
being the run. Detaching does nothing to the work. Re-attaching replays
everything that happened while nobody was looking and then continues live, so
the reloaded page shows the same thing it would have shown had the user stayed.

STOPPING is explicit and separate. A run ends when it finishes, when the user
asks it to stop, or when it exceeds its own deadline — never merely because a
socket closed. Cancelling has to be something a person chose.

SCOPE, honestly: runs live in this process. A pod restart loses them, and the
deployment is a single replica, so there is no cross-process case to get wrong.
Persisting them would buy resumption across restarts and cost a queue and a
schema; the answer itself is already written to the conversation before the run
ends, so what is lost on restart is a progress feed, not a result.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

#: Buffered events per run. Long enough to replay a full question, bounded so a
#: pathological run cannot grow without limit. Older events are dropped from the
#: front; a reattaching client is told when that happened rather than being
#: quietly handed a gap.
MAX_BUFFERED_EVENTS = 2_000

#: A run with nobody attached still finishes, but it must not live forever.
MAX_RUN_SECONDS = 900

#: How long a finished run stays readable, so a page that reloads after the
#: answer arrived still finds it.
KEEP_FINISHED_SECONDS = 900


@dataclass
class Run:
    id: str
    user_email: str
    question: str
    conversation_id: int | None = None
    status: str = "running"          # running | done | error | stopped
    events: list[str] = field(default_factory=list)
    dropped: int = 0
    started_at: float = field(default_factory=time.monotonic)
    finished_at: float | None = None
    task: asyncio.Task[Any] | None = None
    _bell: asyncio.Event = field(default_factory=asyncio.Event)

    def publish(self, kind: str, payload: dict[str, Any]) -> None:
        """Record an event and wake every attached listener."""
        self.events.append(json.dumps({"type": kind, **payload}))
        if len(self.events) > MAX_BUFFERED_EVENTS:
            # Drop from the front: the tail is what a late viewer needs.
            excess = len(self.events) - MAX_BUFFERED_EVENTS
            del self.events[:excess]
            self.dropped += excess
        self._bell.set()

    def finish(self, status: str) -> None:
        self.status = status
        self.finished_at = time.monotonic()
        self._bell.set()

    @property
    def live(self) -> bool:
        return self.status == "running"

    async def subscribe(self, from_index: int = 0) -> AsyncIterator[str]:
        """Replay from `from_index`, then follow live until the run ends.

        A reattaching client passes the number of events it already has, so a
        reload replays the whole run and a flaky connection replays only the
        gap. Both are the same code path — there is no separate "resume"
        behaviour to get subtly different.
        """
        i = max(0, from_index - self.dropped)
        while True:
            while i < len(self.events):
                yield self.events[i]
                i += 1
            if not self.live:
                return
            self._bell.clear()
            # The timeout is a liveness floor, not a poll: it guarantees the
            # loop rechecks `live` even if `finish` raced with `clear`.
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._bell.wait(), timeout=15)


class RunRegistry:
    def __init__(self) -> None:
        self._runs: dict[str, Run] = {}

    def create(self, user_email: str, question: str) -> Run:
        self._sweep()
        run = Run(id=uuid.uuid4().hex, user_email=user_email, question=question)
        self._runs[run.id] = run
        return run

    def get(self, run_id: str, user_email: str) -> Run | None:
        """Fetch a run, but only for the person who started it.

        Ownership is checked HERE rather than at the endpoint, so a new caller
        cannot reach a run by forgetting the check. A run id is unguessable, but
        an unguessable id is not an authorisation model.
        """
        run = self._runs.get(run_id)
        if run is None or run.user_email != user_email:
            return None
        return run

    def active_for(self, user_email: str) -> list[Run]:
        self._sweep()
        return [
            r for r in self._runs.values()
            if r.user_email == user_email and r.live
        ]

    def stop(self, run: Run) -> None:
        if run.task is not None and not run.task.done():
            run.task.cancel()
        run.publish("stopped", {"detail": "Stopped."})
        run.finish("stopped")

    def _sweep(self) -> None:
        now = time.monotonic()
        for rid, run in list(self._runs.items()):
            if run.live and now - run.started_at > MAX_RUN_SECONDS:
                self.stop(run)
            elif run.finished_at and now - run.finished_at > KEEP_FINISHED_SECONDS:
                self._runs.pop(rid, None)


_registry = RunRegistry()


def get_run_registry() -> RunRegistry:
    return _registry
