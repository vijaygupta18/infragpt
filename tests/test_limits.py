"""Rate limit, token budget and coverage-log tests.

All offline: an in-memory SQLite database and an injectable clock, so the
sliding-window behaviour is tested at real boundaries rather than by sleeping.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app import config, coverage
from app.limits.budget import TokenBudget
from app.limits.rate import KIND_CALL, KIND_QUESTION, RateLimiter
from app.limits.service import CallBudgetExceeded, Limits, get_limits, reset_limits
from app.storage.db import Database


class FakeClock:
    """Controllable monotonic-ish clock. Tests advance time explicitly."""

    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def db() -> Database:
    database = Database(":memory:")
    database.migrate()
    database.execute(
        "INSERT INTO users (id, email, name, status, created_at) "
        "VALUES (1, 'a@example.com', 'A', 'active', '2026-01-01T00:00:00+00:00')"
    )
    database.execute(
        "INSERT INTO users (id, email, name, status, created_at) "
        "VALUES (2, 'b@example.com', 'B', 'active', '2026-01-01T00:00:00+00:00')"
    )
    return database


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


# ===========================================================================
# Migrations
# ===========================================================================


def test_limit_tables_exist(db: Database) -> None:
    for table in ("rate_events", "token_usage", "token_budgets"):
        assert db.query_one(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ), table


def test_migrations_are_idempotent(db: Database) -> None:
    """Re-running migrate() must be a no-op, not a duplicate-table error."""
    first = db.migrate()
    second = db.migrate()
    assert first == second


# ===========================================================================
# Sliding-window rate limiter
# ===========================================================================


def test_allows_up_to_the_limit(db: Database, clock: FakeClock) -> None:
    limiter = RateLimiter(db, clock=clock)
    for i in range(5):
        verdict = limiter.hit(1, KIND_QUESTION, limit=5, window_s=3600)
        assert verdict.allowed, i
    assert not limiter.hit(1, KIND_QUESTION, limit=5, window_s=3600).allowed


def test_refused_attempts_do_not_consume_quota(db: Database, clock: FakeClock) -> None:
    """A rejected request must not push the reset further away."""
    limiter = RateLimiter(db, clock=clock)
    for _ in range(3):
        limiter.hit(1, KIND_QUESTION, limit=3, window_s=3600)
    for _ in range(10):
        limiter.hit(1, KIND_QUESTION, limit=3, window_s=3600)
    assert limiter.used(1, KIND_QUESTION, 3600) == 3


def test_window_slides(db: Database, clock: FakeClock) -> None:
    limiter = RateLimiter(db, clock=clock)
    for _ in range(3):
        limiter.hit(1, KIND_QUESTION, limit=3, window_s=3600)
    assert not limiter.check(1, KIND_QUESTION, 3, 3600).allowed

    clock.advance(3601)  # every event has now aged out
    assert limiter.check(1, KIND_QUESTION, 3, 3600).allowed


def test_window_is_sliding_not_a_fixed_bucket(db: Database, clock: FakeClock) -> None:
    """The property a fixed hourly bucket would fail.

    Spend the allowance late in one hour, then step just past the hour: a fixed
    bucket resets and permits a full second allowance immediately (2x the rate).
    A sliding window still sees the recent events.
    """
    limiter = RateLimiter(db, clock=clock)
    for _ in range(5):
        limiter.hit(1, KIND_QUESTION, limit=5, window_s=3600)

    clock.advance(60)  # one minute later — a fixed bucket may have rolled over
    assert not limiter.check(1, KIND_QUESTION, 5, 3600).allowed
    assert limiter.used(1, KIND_QUESTION, 3600) == 5


def test_partial_expiry_frees_exactly_one_slot(db: Database, clock: FakeClock) -> None:
    limiter = RateLimiter(db, clock=clock)
    limiter.hit(1, KIND_QUESTION, limit=2, window_s=100)
    clock.advance(50)
    limiter.hit(1, KIND_QUESTION, limit=2, window_s=100)
    assert not limiter.check(1, KIND_QUESTION, 2, 100).allowed

    clock.advance(51)  # only the first event has aged out
    verdict = limiter.check(1, KIND_QUESTION, 2, 100)
    assert verdict.allowed
    assert verdict.used == 1


def test_retry_after_points_at_the_oldest_event(db: Database, clock: FakeClock) -> None:
    limiter = RateLimiter(db, clock=clock)
    limiter.hit(1, KIND_QUESTION, limit=1, window_s=3600)
    clock.advance(600)
    verdict = limiter.check(1, KIND_QUESTION, 1, 3600)
    assert not verdict.allowed
    assert 2999 <= verdict.retry_after_s <= 3002


def test_limits_are_per_user(db: Database, clock: FakeClock) -> None:
    limiter = RateLimiter(db, clock=clock)
    for _ in range(3):
        limiter.hit(1, KIND_QUESTION, limit=3, window_s=3600)
    assert not limiter.check(1, KIND_QUESTION, 3, 3600).allowed
    assert limiter.check(2, KIND_QUESTION, 3, 3600).allowed


def test_limits_are_per_kind(db: Database, clock: FakeClock) -> None:
    limiter = RateLimiter(db, clock=clock)
    for _ in range(3):
        limiter.hit(1, KIND_QUESTION, limit=3, window_s=3600)
    assert not limiter.check(1, KIND_QUESTION, 3, 3600).allowed
    assert limiter.check(1, KIND_CALL, 3, 3600).allowed


def test_check_does_not_consume(db: Database, clock: FakeClock) -> None:
    limiter = RateLimiter(db, clock=clock)
    for _ in range(20):
        limiter.check(1, KIND_QUESTION, 5, 3600)
    assert limiter.used(1, KIND_QUESTION, 3600) == 0


def test_prune_never_returns_spent_quota(db: Database, clock: FakeClock) -> None:
    """Pruning must only remove events outside every live window."""
    limiter = RateLimiter(db, clock=clock)
    for _ in range(5):
        limiter.hit(1, KIND_QUESTION, limit=5, window_s=3600)
    limiter.prune(older_than_s=7 * 24 * 3600)
    assert limiter.used(1, KIND_QUESTION, 3600) == 5
    assert not limiter.check(1, KIND_QUESTION, 5, 3600).allowed


def test_prune_removes_ancient_events(db: Database, clock: FakeClock) -> None:
    limiter = RateLimiter(db, clock=clock)
    limiter.hit(1, KIND_QUESTION, limit=5, window_s=3600)
    clock.advance(10 * 24 * 3600)
    assert limiter.prune(older_than_s=7 * 24 * 3600) == 1
    assert limiter.used(1, KIND_QUESTION, 3600) == 0


def test_rate_verdict_message_is_actionable(db: Database, clock: FakeClock) -> None:
    limiter = RateLimiter(db, clock=clock)
    limiter.hit(1, KIND_QUESTION, limit=1, window_s=3600)
    message = limiter.check(1, KIND_QUESTION, 1, 3600).message()
    assert "1/1" in message
    assert "Try again in" in message


# ===========================================================================
# Token budgets
# ===========================================================================


def test_fresh_user_has_full_budget(db: Database) -> None:
    budget = TokenBudget(db, default_limit=1000)
    verdict = budget.check(1)
    assert verdict.allowed
    assert verdict.used == 0
    assert verdict.remaining == 1000


def test_usage_accumulates_across_questions(db: Database) -> None:
    budget = TokenBudget(db, default_limit=1000)
    budget.record(1, 100, 50)
    budget.record(1, 200, 25)
    usage = budget.usage(1)
    assert usage.tokens_in == 300
    assert usage.tokens_out == 75
    assert usage.total == 375
    assert usage.questions == 2


def test_over_budget_is_refused(db: Database) -> None:
    budget = TokenBudget(db, default_limit=500)
    budget.record(1, 400, 150)
    verdict = budget.check(1)
    assert not verdict.allowed
    assert verdict.remaining == 0


def test_refusal_message_says_refused_not_truncated(db: Database) -> None:
    """The plan is explicit: refuse, never silently truncate."""
    budget = TokenBudget(db, default_limit=100)
    budget.record(1, 100, 50)
    message = budget.check(1).message()
    assert "refuses" in message
    assert "truncated" in message
    assert "00:00 UTC" in message


def test_budget_is_per_user(db: Database) -> None:
    budget = TokenBudget(db, default_limit=100)
    budget.record(1, 100, 50)
    assert not budget.check(1).allowed
    assert budget.check(2).allowed


def test_budget_is_per_day(db: Database) -> None:
    budget = TokenBudget(db, default_limit=100)
    budget.record(1, 200, 0, day="2026-08-12")
    assert not budget.check(1, day="2026-08-12").allowed
    assert budget.check(1, day="2026-08-13").allowed


def test_admin_override_raises_the_limit(db: Database) -> None:
    budget = TokenBudget(db, default_limit=100)
    budget.record(1, 150, 0)
    assert not budget.check(1).allowed

    budget.set_limit(1, 1000, updated_by="admin@example.com")
    verdict = budget.check(1)
    assert verdict.allowed
    assert verdict.limit == 1000
    assert verdict.remaining == 850


def test_override_is_recorded_with_who_set_it(db: Database) -> None:
    budget = TokenBudget(db, default_limit=100)
    budget.set_limit(1, 5000, updated_by="admin@example.com")
    row = db.query_one("SELECT updated_by FROM token_budgets WHERE user_id = 1")
    assert row is not None
    assert row["updated_by"] == "admin@example.com"


def test_override_is_idempotent(db: Database) -> None:
    budget = TokenBudget(db, default_limit=100)
    budget.set_limit(1, 5000, updated_by="a@b.c")
    budget.set_limit(1, 7000, updated_by="a@b.c")
    assert budget.limit_for(1) == 7000
    rows = db.query_all("SELECT * FROM token_budgets WHERE user_id = 1")
    assert len(rows) == 1


def test_clearing_override_restores_the_default(db: Database) -> None:
    budget = TokenBudget(db, default_limit=100)
    budget.set_limit(1, 5000, updated_by="a@b.c")
    budget.clear_limit(1)
    assert budget.limit_for(1) == 100


def test_zero_budget_means_unlimited(db: Database) -> None:
    """0 means UNLIMITED, and is the default.

    Changed 2026-08-18. A hard daily cap that blocks a real user mid-incident is
    a worse failure than an unexpected gateway bill — and the 200k default duly
    locked out the admin building the tool after ~10 questions. Suspending a
    user is what `status = disabled` is for, so 0 is better spent meaning
    unlimited. Usage is still recorded, so a cap can be sized from evidence.
    """
    budget = TokenBudget(db, default_limit=1000)
    budget.set_limit(1, 0, updated_by="admin@example.com")
    verdict = budget.check(1)
    assert verdict.allowed
    assert verdict.limit == 0


def test_a_positive_budget_still_blocks(db: Database) -> None:
    """The mechanism is intact — only the default changed."""
    budget = TokenBudget(db, default_limit=100)
    budget.record(1, tokens_in=80, tokens_out=40)
    assert not budget.check(1).allowed


def test_negative_values_are_rejected(db: Database) -> None:
    budget = TokenBudget(db, default_limit=100)
    with pytest.raises(ValueError, match="negative"):
        budget.set_limit(1, -1, updated_by="a@b.c")
    with pytest.raises(ValueError, match="negative"):
        budget.record(1, -5, 0)


def test_budget_overshoot_is_bounded_to_one_question(db: Database) -> None:
    """Spend is only known after the answer, so the last question may overshoot.

    That is the accepted trade — the alternative is refusing based on a guess at
    a question's cost. What must NOT happen is a second question after the
    overshoot.
    """
    budget = TokenBudget(db, default_limit=1000)
    budget.record(1, 900, 50)
    assert budget.check(1).allowed  # 950 < 1000 — this question is admitted
    budget.record(1, 400, 400)  # ...and turns out to cost 800
    assert budget.usage(1).total == 1750
    assert not budget.check(1).allowed  # the next one is refused


# ===========================================================================
# Limits service
# ===========================================================================


def test_unlimited_is_the_default(db: Database) -> None:
    """0 means unlimited, and both rate limits default to it.

    Changed 2026-08-18. A limit sized against a hypothetical runaway blocked the
    real user: 20 questions/hour sounds generous until someone is genuinely
    debugging, and then the tool refuses at exactly the moment it is most wanted.
    The real protections are elsewhere and always on — per-call timeouts, row
    caps, a 5-connection DB pool, and credentials that cannot write.
    """
    assert config.QUESTIONS_PER_HOUR == 0
    limits = Limits(db)
    for _ in range(50):
        assert limits.consume_question(1).allowed
    assert limits.check_question_rate(1).allowed


def test_a_configured_limit_still_applies(db: Database) -> None:
    """The mechanism is intact — only the default changed."""
    limits = Limits(db)
    for _ in range(3):
        assert limits.rate.hit(1, "question", 3, 3600).allowed
    assert not limits.rate.check(1, "question", 3, 3600).allowed


def test_per_question_call_fanout_is_capped() -> None:
    Limits.assert_calls_within_question(config.MAX_CALLS_PER_QUESTION)
    with pytest.raises(CallBudgetExceeded, match="at most"):
        Limits.assert_calls_within_question(config.MAX_CALLS_PER_QUESTION + 1)


def test_get_limits_singleton_is_resettable(db: Database) -> None:
    reset_limits(None)
    first = get_limits(db)
    assert get_limits(db) is first
    reset_limits(None)
    assert get_limits(db) is not first
    reset_limits(None)


def test_limits_survive_a_process_restart(tmp_path: Path) -> None:
    """Persistence is the point: an in-memory counter resets on reschedule, and
    a limit that resets when a pod moves is not a limit."""
    path = tmp_path / "limits.db"
    database = Database(path)
    database.migrate()
    database.execute(
        "INSERT INTO users (id, email, name, status, created_at) "
        "VALUES (1, 'a@b.c', 'A', 'active', '2026-01-01T00:00:00+00:00')"
    )
    first = Limits(database)
    # An explicit limit, since the default is now unlimited — what is being
    # tested is that the COUNTERS persist, not what the default happens to be.
    for _ in range(3):
        first.rate.hit(1, "question", 3, 3600)
    first.tokens.record(1, 500, 500)
    database.close()

    reopened = Database(path)
    reopened.migrate()
    second = Limits(reopened)
    assert not second.rate.check(1, "question", 3, 3600).allowed
    assert second.tokens.usage(1).total == 1000


# ===========================================================================
# Coverage log
# ===========================================================================


@pytest.fixture
def coverage_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("INFRAGPT_COVERAGE_DIR", str(tmp_path / "coverage"))
    return tmp_path / "coverage"


def test_gap_is_recorded(coverage_dir: Path) -> None:
    coverage.record_gap(question="Why is driver X not getting rides?", user_email="a@b.c")
    gaps = coverage.report()
    assert len(gaps) == 1
    assert gaps[0].count == 1


def test_gaps_group_by_normalised_question(coverage_dir: Path) -> None:
    """Otherwise the top-10 is ten spellings of one request."""
    for question in (
        "Which index is missing on booking?",
        "which index is missing on booking",
        "Which  index is missing on booking!!",
    ):
        coverage.record_gap(question=question)
    gaps = coverage.report()
    assert len(gaps) == 1
    assert gaps[0].count == 3


def test_report_ranks_by_frequency(coverage_dir: Path) -> None:
    for _ in range(5):
        coverage.record_gap(question="common question")
    coverage.record_gap(question="rare question")
    gaps = coverage.report()
    assert gaps[0].question == "common question"
    assert gaps[0].count == 5


def test_ties_break_towards_more_distinct_users(coverage_dir: Path) -> None:
    """Two people asking once is a stronger signal than one person asking twice."""
    coverage.record_gap(question="asked by two people", user_email="a@b.c")
    coverage.record_gap(question="asked by two people", user_email="b@b.c")
    coverage.record_gap(question="asked by one person", user_email="c@b.c")
    coverage.record_gap(question="asked by one person", user_email="c@b.c")
    gaps = coverage.report()
    assert gaps[0].question == "asked by two people"
    assert gaps[0].users == 2


def test_pii_in_a_question_is_redacted_before_it_is_written(coverage_dir: Path) -> None:
    """The coverage log exists to be read by the whole team — a phone number
    pasted into a question must not be planted in it."""
    coverage.record_gap(question="why is 9876543210 not getting rides")
    raw = coverage.coverage_path().read_text()
    assert "9876543210" not in raw
    assert "phone:" in raw


def test_reasons_are_tracked_separately(coverage_dir: Path) -> None:
    """no_function is a backlog item; out_of_scope is a boundary decision."""
    coverage.record_gap(question="q1", reason=coverage.REASON_NO_FUNCTION)
    coverage.record_gap(question="q2", reason=coverage.REASON_OUT_OF_SCOPE)
    assert len(coverage.report(reason=coverage.REASON_NO_FUNCTION)) == 1
    assert len(coverage.report(reason=coverage.REASON_OUT_OF_SCOPE)) == 1


def test_unknown_reason_falls_back(coverage_dir: Path) -> None:
    coverage.record_gap(question="q", reason="not-a-real-reason")
    gaps = coverage.report()
    assert gaps[0].reasons == {coverage.REASON_NO_FUNCTION: 1}


def test_recording_never_raises_into_the_request_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A failure to log a gap must not turn a graceful refusal into a 500."""
    monkeypatch.setenv("INFRAGPT_COVERAGE_DIR", str(tmp_path / "nope"))

    def boom(*args: object, **kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("pathlib.Path.mkdir", boom)
    coverage.record_gap(question="anything")  # must not raise


def test_report_on_empty_log_is_empty(coverage_dir: Path) -> None:
    assert coverage.report() == []
    assert "No coverage gaps" in coverage.format_report([])


def test_format_report_renders(coverage_dir: Path) -> None:
    coverage.record_gap(question="why is driver X stuck", user_email="a@b.c")
    text = coverage.format_report(coverage.report())
    assert "count" in text
    assert "driver" in text


def test_torn_line_is_skipped_not_fatal(coverage_dir: Path) -> None:
    coverage.record_gap(question="good record")
    with open(coverage.coverage_path(), "a", encoding="utf-8") as fh:
        fh.write('{"ts": "2026-08-13", "quest\n')  # torn tail
    assert len(coverage.report()) == 1
