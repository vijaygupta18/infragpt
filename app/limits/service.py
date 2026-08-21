"""Aggregate handle over the rate limiter and the token budget.

One object to hold, mirroring ``app.storage.Storage``. It is built from the same
``Database`` that ``Storage`` owns, so limits share the connection, the WAL and
the lock — no second file, no second consistency story.
"""

from __future__ import annotations

from collections.abc import Callable

from app import config
from app.limits.budget import BudgetVerdict, TokenBudget
from app.limits.rate import KIND_CALL, KIND_QUESTION, RateLimiter, RateVerdict
from app.storage.db import Database

_HOUR = 3600


class CallBudgetExceeded(RuntimeError):
    """Raised when one question tries to make more calls than it may."""


class Limits:
    def __init__(
        self,
        db: Database,
        *,
        default_daily_tokens: int | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        from app.limits import DEFAULT_DAILY_TOKEN_BUDGET

        self.db = db
        self.rate = RateLimiter(db, clock=clock)
        self.tokens = TokenBudget(
            db,
            default_limit=(
                DEFAULT_DAILY_TOKEN_BUDGET
                if default_daily_tokens is None
                else default_daily_tokens
            ),
        )

    # -- questions ----------------------------------------------------------

    def check_question_rate(self, user_id: int) -> RateVerdict:
        return self.rate.check(
            user_id, KIND_QUESTION, config.QUESTIONS_PER_HOUR, _HOUR
        )

    def consume_question(self, user_id: int) -> RateVerdict:
        return self.rate.hit(user_id, KIND_QUESTION, config.QUESTIONS_PER_HOUR, _HOUR)

    # -- registry calls -----------------------------------------------------

    def check_call_rate(self, user_id: int) -> RateVerdict:
        return self.rate.check(user_id, KIND_CALL, config.CALLS_PER_HOUR, _HOUR)

    def consume_call(self, user_id: int) -> RateVerdict:
        return self.rate.hit(user_id, KIND_CALL, config.CALLS_PER_HOUR, _HOUR)

    @staticmethod
    def assert_calls_within_question(count: int) -> None:
        """Guard the per-question fan-out.

        This is the limit that stops one question from turning into an
        unbounded sweep of production readers, so it raises rather than
        returning a verdict — there is no sensible "carry on with fewer calls"
        branch for a caller to ignore.
        """
        if count > config.MAX_CALLS_PER_QUESTION:
            raise CallBudgetExceeded(
                f"a single question may make at most "
                f"{config.MAX_CALLS_PER_QUESTION} registry calls; "
                f"{count} were selected"
            )

    # -- tokens -------------------------------------------------------------

    def check_tokens(self, user_id: int) -> BudgetVerdict:
        return self.tokens.check(user_id)

    def record_tokens(self, user_id: int, tokens_in: int, tokens_out: int) -> None:
        self.tokens.record(user_id, tokens_in, tokens_out)


_limits: Limits | None = None


def get_limits(db: Database | None = None) -> Limits:
    """Process-wide singleton, built lazily from the app database."""
    global _limits
    if _limits is None:
        if db is None:
            from app.storage import get_storage

            db = get_storage().db
        _limits = Limits(db)
    return _limits


def reset_limits(limits: Limits | None = None) -> None:
    """Replace the singleton. For tests and for startup wiring."""
    global _limits
    _limits = limits


__all__ = [
    "CallBudgetExceeded",
    "Limits",
    "get_limits",
    "reset_limits",
]
