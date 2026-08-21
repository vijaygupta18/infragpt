"""Per-user daily token budgets.

The rule from the plan is explicit: **refuse over budget rather than truncating
silently.** So the only two outcomes here are "you have budget, proceed" and "you
are out of budget, here is exactly where you stand". There is no path that
shortens a prompt, drops runbooks, or downgrades a model to squeeze under a cap —
each of those produces a worse answer that still *looks* like a normal answer.

Budgets are checked *before* a question runs and recorded *after* it finishes.
That means the last question of a day may overshoot its allowance, because token
counts are only known once the model has replied. Overshoot is bounded by one
question and is the right trade: the alternative is refusing questions based on a
guess at their cost.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from app.storage.db import Database, utcnow


def utc_day(when: datetime | None = None) -> str:
    return (when or datetime.now(UTC)).strftime("%Y-%m-%d")


@dataclass(frozen=True)
class TokenUsage:
    user_id: int
    day: str
    tokens_in: int = 0
    tokens_out: int = 0
    questions: int = 0

    @property
    def total(self) -> int:
        return self.tokens_in + self.tokens_out


@dataclass(frozen=True)
class BudgetVerdict:
    allowed: bool
    used: int
    limit: int
    day: str

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def message(self) -> str:
        return (
            f"Daily token budget exhausted: {self.used:,}/{self.limit:,} tokens used "
            f"on {self.day} (UTC). The budget resets at 00:00 UTC. Ask an admin to "
            f"raise it if you need more today — infragpt refuses rather than "
            f"returning a truncated answer, because a shortened answer looks "
            f"exactly like a complete one."
        )


class TokenBudget:
    """Reads and writes daily token spend, plus per-user overrides."""

    def __init__(
        self,
        db: Database,
        default_limit: int,
        today: Callable[[], str] = utc_day,
    ) -> None:
        self.db = db
        self.default_limit = default_limit
        self._today = today

    # -- limits -------------------------------------------------------------

    def limit_for(self, user_id: int) -> int:
        """The user's effective daily limit: their override, else the default."""
        row = self.db.query_one(
            "SELECT daily_tokens FROM token_budgets WHERE user_id = ?", (user_id,)
        )
        return int(row["daily_tokens"]) if row else self.default_limit

    def set_limit(self, user_id: int, daily_tokens: int, updated_by: str) -> int:
        """Set a per-user override.

        Authorization is NOT decided here — the caller must already hold
        ``Surface.ADMIN`` (enforced by the admin route's dependency). Keeping the
        check at the edge means there is exactly one place to audit it.
        """
        if daily_tokens < 0:
            raise ValueError("daily token budget cannot be negative")
        self.db.execute(
            "INSERT INTO token_budgets (user_id, daily_tokens, updated_at, updated_by) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET "
            "  daily_tokens = excluded.daily_tokens,"
            "  updated_at   = excluded.updated_at,"
            "  updated_by   = excluded.updated_by",
            (user_id, daily_tokens, utcnow(), updated_by),
        )
        return daily_tokens

    def clear_limit(self, user_id: int) -> None:
        """Drop the override so the process default applies again."""
        self.db.execute("DELETE FROM token_budgets WHERE user_id = ?", (user_id,))

    # -- usage --------------------------------------------------------------

    def usage(self, user_id: int, day: str | None = None) -> TokenUsage:
        day = day or self._today()
        row = self.db.query_one(
            "SELECT tokens_in, tokens_out, questions FROM token_usage "
            "WHERE user_id = ? AND day = ?",
            (user_id, day),
        )
        if row is None:
            return TokenUsage(user_id=user_id, day=day)
        return TokenUsage(
            user_id=user_id,
            day=day,
            tokens_in=int(row["tokens_in"]),
            tokens_out=int(row["tokens_out"]),
            questions=int(row["questions"]),
        )

    def record(
        self,
        user_id: int,
        tokens_in: int,
        tokens_out: int,
        *,
        questions: int = 1,
        day: str | None = None,
    ) -> TokenUsage:
        """Add a question's token spend. Called after the answer is produced."""
        if tokens_in < 0 or tokens_out < 0:
            raise ValueError("token counts cannot be negative")
        day = day or self._today()
        self.db.execute(
            "INSERT INTO token_usage (user_id, day, tokens_in, tokens_out, questions, "
            "updated_at) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(user_id, day) DO UPDATE SET "
            "  tokens_in  = token_usage.tokens_in  + excluded.tokens_in,"
            "  tokens_out = token_usage.tokens_out + excluded.tokens_out,"
            "  questions  = token_usage.questions  + excluded.questions,"
            "  updated_at = excluded.updated_at",
            (user_id, day, tokens_in, tokens_out, questions, utcnow()),
        )
        return self.usage(user_id, day)

    # -- the decision -------------------------------------------------------

    def check(self, user_id: int, day: str | None = None) -> BudgetVerdict:
        day = day or self._today()
        limit = self.limit_for(user_id)
        used = self.usage(user_id, day).total
        # limit <= 0 means unlimited, and is the default. Usage is still recorded
        # so the audit log can tell you what a sensible cap would be — you cannot
        # size a budget you have never measured.
        if limit <= 0:
            return BudgetVerdict(allowed=True, used=used, limit=0, day=day)
        return BudgetVerdict(allowed=used < limit, used=used, limit=limit, day=day)
