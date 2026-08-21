"""Throttling for unauthenticated endpoints.

The existing rate limiter keys on ``user_id``, which a failed login does not
have — a wrong email has no user at all. So this is separate and keys on
whatever identifies the *attempt*.

TWO THINGS IT PREVENTS, and the second is the one that is easy to miss:

1. **Password guessing.** Unlimited attempts against a login form is unlimited
   attempts against every password behind it.

2. **Memory exhaustion.** scrypt is deliberately memory-hard — each verification
   allocates ~32MB. That cost is the point when someone is guessing passwords,
   and a liability when someone is not: without a throttle, an unauthenticated
   attacker can make the process allocate 32MB per request as fast as they can
   send them. The KDF that protects the passwords becomes the cheapest way to
   kill the pod. The throttle is what keeps the first property from creating the
   second.

IN-PROCESS, deliberately. This deployment is a single replica by design (RWO
volume, Recreate strategy), so a shared store would add a dependency and buy
nothing. The consequence is honest and bounded: counters reset if the process
restarts, so a determined attacker gains a fresh window per restart. That is
acceptable for a service that is not reachable from the internet; it would not
be if this were ever exposed directly.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Callable


class Throttled(Exception):
    """Raised when an attempt is refused. ``retry_after_s`` is user-facing."""

    def __init__(self, retry_after_s: int) -> None:
        self.retry_after_s = retry_after_s
        super().__init__(f"too many attempts; try again in {retry_after_s}s")


class AttemptThrottle:
    """Sliding-window counter over arbitrary string keys."""

    def __init__(
        self,
        limit: int,
        window_s: int,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.limit = limit
        self.window_s = window_s
        self._clock = clock or time.monotonic
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str, now: float) -> deque[float]:
        hits = self._hits[key]
        cutoff = now - self.window_s
        while hits and hits[0] <= cutoff:
            hits.popleft()
        return hits

    def check(self, *keys: str) -> None:
        """Raise Throttled if ANY key is over its limit. Does not record.

        Checked before the expensive work, so a refused attempt never reaches
        the KDF — which is the whole point.
        """
        now = self._clock()
        for key in keys:
            if not key:
                continue
            hits = self._prune(key, now)
            if len(hits) >= self.limit:
                raise Throttled(max(1, int(self.window_s - (now - hits[0]))))

    def record(self, *keys: str) -> None:
        """Record one FAILED attempt against each key.

        Only failures are recorded. Counting successes would lock out the
        legitimate user of a shared address on a busy day, which is a support
        ticket rather than a defence.
        """
        now = self._clock()
        for key in keys:
            if key:
                self._prune(key, now).append(now)

    def reset(self, *keys: str) -> None:
        """Clear on success, so one typo does not count toward a lockout."""
        for key in keys:
            self._hits.pop(key, None)


#: Login: generous enough for a person mistyping, far too slow to guess with.
#: 10 failures per 15 minutes per email, and the same per source address.
LOGIN_THROTTLE = AttemptThrottle(limit=10, window_s=900)

#: Registration is throttled per SOURCE only — throttling by email would let
#: anyone lock a colleague out of registering by burning their address.
REGISTER_THROTTLE = AttemptThrottle(limit=5, window_s=900)


def client_key(request: object) -> str:
    """Best-effort source identity for throttling.

    Prefers the first hop of X-Forwarded-For, because in this deployment the
    only path in is through a proxy and the socket address is therefore always
    the proxy. NOT used for authorisation or audit — a header a client can set
    must never decide access. Here the worst case of a spoofed value is that an
    attacker spreads their own attempts across keys, which the per-email limit
    still catches.
    """
    headers = getattr(request, "headers", {})
    forwarded = ""
    try:
        forwarded = headers.get("x-forwarded-for", "") or ""
    except AttributeError:  # pragma: no cover - defensive
        forwarded = ""
    if forwarded:
        return forwarded.split(",")[0].strip()
    client = getattr(request, "client", None)
    return getattr(client, "host", "") or "unknown"
