"""The learning layer: what has actually worked, counted from the audit log.

These fixtures write records with the SAME discriminator the audit writer uses
("kind"). The first version used "event" and every test still passed while the
module read nothing in production — a fixture that agrees with the code instead
of with the data proves nothing.

The property that matters is that nothing here is a claim. Every line it
produces is a count over recorded calls, which is what makes it safe to feed
straight back into the selector prompt without a human reviewing it first.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from app import config, experience


@pytest.fixture
def audit_dir(tmp_path, monkeypatch):
    d = tmp_path / "audit"
    d.mkdir()
    monkeypatch.setattr(config, "AUDIT_DIR", d)
    return d


def _write(audit_dir, records: list[dict]) -> None:
    today = datetime.now(UTC).date().isoformat()
    (audit_dir / f"{today}.jsonl").write_text(
        "\n".join(json.dumps({"kind": "call", **r}) for r in records) + "\n"
    )


def test_an_entry_that_always_fails_is_flagged(audit_dir) -> None:
    _write(audit_dir, [
        {"entry_name": "list_pdb", "ok": False, "error": "context does not exist"}
        for _ in range(4)
    ])
    text = experience.hints({"list_pdb"})
    assert "ALWAYS FAILS" in text
    assert "context does not exist" in text


def test_an_entry_that_always_returns_nothing_is_flagged(audit_dir) -> None:
    """The important one. A call that succeeds and answers nothing renders as
    zero, and zero reads as health — so it must be called out explicitly."""
    _write(audit_dir, [
        {"entry_name": "logs_search", "ok": True, "rows": 0} for _ in range(5)
    ])
    text = experience.hints({"logs_search"})
    assert "ALWAYS RETURNS NOTHING" in text
    assert "UNPROVEN" in text


def test_a_working_entry_is_not_flagged_as_broken(audit_dir) -> None:
    _write(audit_dir, [
        {"entry_name": "api_error_rates", "ok": True, "rows": 5} for _ in range(5)
    ])
    text = experience.hints({"api_error_rates"})
    assert "ALWAYS FAILS" not in text
    assert "ALWAYS RETURNS NOTHING" not in text


def test_one_bad_call_is_not_a_pattern(audit_dir) -> None:
    """Below the observation threshold, a failure is coincidence. Flagging it
    would train the model to avoid a function that works."""
    _write(audit_dir, [{"entry_name": "list_pdb", "ok": False, "error": "blip"}])
    assert experience.hints({"list_pdb"}) == ""


def test_entries_the_user_cannot_call_are_never_mentioned(audit_dir) -> None:
    """The hint block must not advertise a capability the caller lacks."""
    _write(audit_dir, [
        {"entry_name": "secret_thing", "ok": False, "error": "nope"} for _ in range(4)
    ])
    assert experience.hints({"api_error_rates"}) == ""


def test_nothing_worth_saying_produces_no_section(audit_dir) -> None:
    """An empty section is noise in a prompt that is already long."""
    _write(audit_dir, [
        {"entry_name": "api_error_rates", "ok": True, "rows": 3} for _ in range(4)
    ])
    assert "OBSERVED" not in experience.hints({"api_error_rates"})


def test_a_corrupt_audit_line_does_not_break_a_question(audit_dir) -> None:
    today = datetime.now(UTC).date().isoformat()
    (audit_dir / f"{today}.jsonl").write_text(
        "not json\n"
        + json.dumps({"kind": "call", "entry_name": "x", "ok": True, "rows": 1})
        + "\n"
    )
    experience.hints({"x"})  # must not raise


def test_a_missing_audit_directory_is_survivable(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(config, "AUDIT_DIR", tmp_path / "nope")
    assert experience.hints({"anything"}) == ""


def test_records_without_a_row_count_are_unknown_not_empty(audit_dir) -> None:
    """Row counting was added after these records were written.

    Folding "not recorded" into "returned nothing" made this module's first live
    run announce that alloydb_cpu and api_error_rates never return data — both
    of which demonstrably do. The module would have been manufacturing exactly
    the false negative it exists to catch.
    """
    _write(audit_dir, [{"entry_name": "alloydb_cpu", "ok": True} for _ in range(6)])
    assert experience.hints({"alloydb_cpu"}) == ""

    stats = experience.collect()
    assert stats["alloydb_cpu"].unknown_rows == 6
    assert stats["alloydb_cpu"].empty == 0


def test_a_genuinely_empty_call_is_still_flagged(audit_dir) -> None:
    """The fix must not silence the real signal."""
    _write(audit_dir, [
        {"entry_name": "logs_search", "ok": True, "rows": 0} for _ in range(4)
    ])
    assert "ALWAYS RETURNS NOTHING" in experience.hints({"logs_search"})


def test_mixed_old_and_new_records_judge_only_on_what_is_known(audit_dir) -> None:
    _write(audit_dir, [
        {"entry_name": "m", "ok": True},                 # unknown
        {"entry_name": "m", "ok": True},                 # unknown
        {"entry_name": "m", "ok": True, "rows": 4},      # has rows
        {"entry_name": "m", "ok": True, "rows": 2},
        {"entry_name": "m", "ok": True, "rows": 7},
    ])
    assert "ALWAYS RETURNS NOTHING" not in experience.hints({"m"})


def test_a_capability_that_has_since_recovered_is_not_called_broken(audit_dir) -> None:
    """With a multi-day lookback, a fix this morning would otherwise be reported
    as broken until the old records age out — steering the model away from
    something that works."""
    _write(audit_dir, [
        {"entry_name": "active_connections", "ok": False, "error": "pool timeout",
         "ts": "2026-08-19T09:00:00.000+00:00"},
        {"entry_name": "active_connections", "ok": False, "error": "pool timeout",
         "ts": "2026-08-19T10:00:00.000+00:00"},
        {"entry_name": "active_connections", "ok": False, "error": "pool timeout",
         "ts": "2026-08-19T11:00:00.000+00:00"},
        {"entry_name": "active_connections", "ok": True, "rows": 20,
         "ts": "2026-08-20T09:00:00.000+00:00"},
    ])
    assert "ALWAYS FAILS" not in experience.hints({"active_connections"})


def test_something_still_broken_is_still_flagged(audit_dir) -> None:
    """Recency must not silence a real, ongoing failure."""
    _write(audit_dir, [
        {"entry_name": "ch_query", "ok": False, "error": "no host configured",
         "ts": f"2026-08-2{i}T09:00:00.000+00:00"}
        for i in range(3)
    ])
    assert "ALWAYS FAILS" in experience.hints({"ch_query"})


def test_a_failed_call_is_never_counted_as_an_empty_result(audit_dir) -> None:
    """They mean different things and drive different advice."""
    _write(audit_dir, [
        {"entry_name": "x", "ok": False, "error": "boom", "ts": "2026-08-20T09:00:00Z"}
        for _ in range(4)
    ])
    stats = experience.collect()
    assert stats["x"].failed == 4
    assert stats["x"].empty == 0
    assert stats["x"].with_rows == 0


def test_text_output_with_no_rows_counts_as_useful(audit_dir) -> None:
    """kubectl and shell entries return text and no rows.

    Counting only rows would have taught the model that every k8s function
    returns nothing — the exact false negative this module exists to catch,
    manufactured by the module itself. Caught by a live sweep flagging 12
    working k8s entries as EMPTY.
    """
    _write(audit_dir, [
        {"entry_name": "list_pods", "ok": True, "rows": 0, "chars": 4200}
        for _ in range(5)
    ])
    assert "ALWAYS RETURNS NOTHING" not in experience.hints({"list_pods"})
    assert experience.collect()["list_pods"].with_rows == 5


def test_genuinely_no_output_is_still_flagged(audit_dir) -> None:
    _write(audit_dir, [
        {"entry_name": "quiet", "ok": True, "rows": 0, "chars": 0} for _ in range(4)
    ])
    assert "ALWAYS RETURNS NOTHING" in experience.hints({"quiet"})
