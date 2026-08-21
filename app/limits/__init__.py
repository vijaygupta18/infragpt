"""Rate limits and token budgets.

Two separate controls with two different jobs:

* **Rate limits** protect *infrastructure*. A question fans out to as many as
  ``MAX_CALLS_PER_QUESTION`` reads against production readers, so an unbounded
  question rate is an unbounded query rate against AlloyDB.
* **Token budgets** protect *spend*. They are per-user and per-UTC-day.

Both **refuse** when exceeded. Neither degrades, truncates, or silently drops
calls. A truncated answer is indistinguishable from a complete one to the reader
— which makes silent truncation the more dangerous failure of the two, since the
user acts on a partial picture believing it is whole.

Everything here is persisted in SQLite so limits survive a pod restart. The
deployment is a single replica by design (see the plan's storage section), so a
process-local counter would be *almost* correct — and "almost correct, until the
node drains" is exactly the kind of control that fails when it matters.
"""

from __future__ import annotations

import os

from app.limits.budget import BudgetVerdict, TokenBudget, TokenUsage
from app.limits.rate import RateLimiter, RateVerdict
from app.limits.service import Limits, get_limits, reset_limits


def _int_env(name: str, default: int) -> int:
    """Read an int from env, falling back rather than crashing on garbage.

    A malformed budget env var must not take the API down; it falls back to the
    default and the value is visible in ``/admin`` either way.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= 0 else default


#: Default per-user, per-UTC-day token allowance across selection + synthesis.
#: Overridable per user by an admin (``token_budgets`` table).
#:
#: **0 means unlimited, and it is the default.** A hard daily cap that blocks a
#: real user mid-incident is a worse failure than an unexpected gateway bill: the
#: whole point of this tool is to be reachable at 3am. A single question costs
#: ~10-25k tokens, so a 200k cap ran out after roughly ten questions — which it
#: duly did, to the admin building the thing.
#:
#: The mechanism is kept because runaway loops are real; it is the *default* that
#: was wrong. Set INFRAGPT_DAILY_TOKEN_BUDGET to enable it, and expect to size
#: it from observed usage in the audit log rather than from a guess.
#: Rate limiting (questions/hour) is unchanged and remains on — that is the
#: control that actually stops a loop, and it does so without a daily cliff.
DEFAULT_DAILY_TOKEN_BUDGET = _int_env("INFRAGPT_DAILY_TOKEN_BUDGET", 0)

#: How long rate events are retained before pruning. Must exceed the largest
#: window in use, or the sliding window loses history it still needs.
RATE_EVENT_RETENTION_S = _int_env("INFRAGPT_RATE_RETENTION_S", 7 * 24 * 3600)

__all__ = [
    "DEFAULT_DAILY_TOKEN_BUDGET",
    "RATE_EVENT_RETENTION_S",
    "BudgetVerdict",
    "Limits",
    "RateLimiter",
    "RateVerdict",
    "TokenBudget",
    "TokenUsage",
    "get_limits",
    "reset_limits",
]
