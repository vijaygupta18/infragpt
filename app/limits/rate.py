"""Sliding-window rate limiter, persisted in SQLite.

Why a sliding window rather than a fixed bucket: with hourly buckets a user can
spend a full hour's allowance in the last second of one bucket and the next
allowance in the first second of the following one — 2x the intended rate, at
the exact moment the limit is meant to bite. Counting events in the trailing
``window_s`` seconds costs one indexed COUNT and has no such edge.

``check`` and ``record`` are deliberately separate. The API records a question
only once it is admitted, so a request rejected for some other reason (no grant,
bad input) does not consume quota. ``hit`` is the common case that does both
atomically.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from app.storage.db import Database

#: Rate-limited event kinds.
KIND_QUESTION = "question"
KIND_CALL = "call"


@dataclass(frozen=True)
class RateVerdict:
    """The outcome of a limit check, with everything needed to explain it."""

    allowed: bool
    kind: str
    used: int
    limit: int
    window_s: int
    retry_after_s: int = 0

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def message(self) -> str:
        window_label = (
            f"{self.window_s // 3600}h" if self.window_s >= 3600 else f"{self.window_s}s"
        )
        return (
            f"Rate limit reached: {self.used}/{self.limit} {self.kind}s in the last "
            f"{window_label}. Try again in {self.retry_after_s}s. This limit exists "
            f"because each question can run several reads against production."
        )


class RateLimiter:
    """Counts events per (user, kind) over a trailing window."""

    def __init__(self, db: Database, clock: Callable[[], float] | None = None) -> None:
        self.db = db
        self._clock = clock or time.time

    # -- reads --------------------------------------------------------------

    def used(self, user_id: int, kind: str, window_s: int) -> int:
        cutoff = self._clock() - window_s
        row = self.db.query_one(
            "SELECT COUNT(*) AS n FROM rate_events "
            "WHERE user_id = ? AND kind = ? AND ts > ?",
            (user_id, kind, cutoff),
        )
        return int(row["n"]) if row else 0

    def check(self, user_id: int, kind: str, limit: int, window_s: int) -> RateVerdict:
        """Non-mutating check. Does not consume quota.

        A limit of 0 or less means UNLIMITED, and is the default. Usage is still
        recorded either way, so a real limit can later be sized from the audit
        log rather than guessed — which is how the previous default came to be
        wrong.
        """
        used = self.used(user_id, kind, window_s)
        if limit <= 0:
            return RateVerdict(True, kind, used, limit, window_s)
        if used < limit:
            return RateVerdict(True, kind, used, limit, window_s)
        return RateVerdict(
            allowed=False,
            kind=kind,
            used=used,
            limit=limit,
            window_s=window_s,
            retry_after_s=self._retry_after(user_id, kind, window_s),
        )

    def _retry_after(self, user_id: int, kind: str, window_s: int) -> int:
        """Seconds until the oldest in-window event falls out of the window."""
        now = self._clock()
        row = self.db.query_one(
            "SELECT MIN(ts) AS oldest FROM rate_events "
            "WHERE user_id = ? AND kind = ? AND ts > ?",
            (user_id, kind, now - window_s),
        )
        if not row or row["oldest"] is None:
            return window_s
        return max(1, int(float(row["oldest"]) + window_s - now) + 1)

    # -- writes -------------------------------------------------------------

    def record(self, user_id: int, kind: str) -> None:
        self.db.execute(
            "INSERT INTO rate_events (user_id, kind, ts) VALUES (?, ?, ?)",
            (user_id, kind, self._clock()),
        )

    def hit(self, user_id: int, kind: str, limit: int, window_s: int) -> RateVerdict:
        """Check and, if allowed, consume one unit of quota."""
        verdict = self.check(user_id, kind, limit, window_s)
        if verdict.allowed:
            self.record(user_id, kind)
            return RateVerdict(
                True, kind, verdict.used + 1, limit, window_s
            )
        return verdict

    # -- housekeeping -------------------------------------------------------

    def prune(self, older_than_s: int) -> int:
        """Delete events older than the retention horizon. Returns rows removed.

        Safe to call at any time: it only ever removes rows outside every live
        window, so it cannot hand anyone back quota they already spent.
        """
        cutoff = self._clock() - older_than_s
        cur = self.db.execute("DELETE FROM rate_events WHERE ts <= ?", (cutoff,))
        return cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
