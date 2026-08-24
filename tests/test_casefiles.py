"""The tool's memory of its own investigations."""

from __future__ import annotations

import time

from app.casefiles import MAX_AGE_DAYS, CaseFiles
from app.storage.db import Database


def _cf(tmp_path) -> CaseFiles:
    return CaseFiles(Database(tmp_path / "cases.db"))


def test_a_similar_question_recalls_the_case(tmp_path):
    cf = _cf(tmp_path)
    cf.record(
        user_email="a@x",
        question="why is the driver reader at max nodes",
        answer="The driver read pool was pinned by a dashboard running wide aggregates.",
        functions=["alloydb_instances", "query_insights_top"],
    )
    ctx = cf.context_for("driver reader pegged at max again")
    assert "dashboard" in ctx
    assert "alloydb_instances" in ctx
    # The warning is not optional — a stale conclusion presented as current
    # state is the exact failure this tool exists to avoid.
    assert "re-verify" in ctx


def test_an_unrelated_question_recalls_nothing(tmp_path):
    """One shared common word must not attach a precedent.

    'driver' alone appears in half the questions this tool will ever get; a
    single-word match would decorate them all with an irrelevant old case.
    """
    cf = _cf(tmp_path)
    cf.record(
        user_email="a@x",
        question="why is the driver reader at max nodes",
        answer="Dashboard load.",
        functions=["alloydb_instances"],
    )
    assert cf.context_for("how many kafka topics exist") == ""
    assert cf.context_for("driver") == ""


def test_answers_without_evidence_are_not_remembered(tmp_path):
    """No calls, no case. Remembering model talk as precedent would launder it
    into evidence on the next question."""
    cf = _cf(tmp_path)
    cf.record(user_email="a@x", question="q", answer="Some talk.", functions=[])
    assert cf.similar("q talk") == []


def test_old_cases_age_out(tmp_path):
    cf = _cf(tmp_path)
    cf.record(
        user_email="a@x",
        question="redis evictions spiking in gcp",
        answer="Old finding.",
        functions=["redis_memory_usage"],
    )
    future = time.time() + (MAX_AGE_DAYS + 1) * 86400
    assert cf.similar("redis evictions spiking in gcp", now=future) == []


def test_newer_case_wins_a_near_tie(tmp_path):
    cf = _cf(tmp_path)
    db = cf.db
    now = time.time()
    import json
    db.execute(
        "INSERT INTO casefiles (ts,user_email,question,summary,functions) VALUES (?,?,?,?,?)",
        (now - 60 * 86400, "a@x", "drainer lag rising on gcp", "old take",
         json.dumps(["drainer_lag"])),
    )
    db.execute(
        "INSERT INTO casefiles (ts,user_email,question,summary,functions) VALUES (?,?,?,?,?)",
        (now - 1 * 86400, "a@x", "drainer lag rising on gcp", "fresh take",
         json.dumps(["drainer_lag"])),
    )
    cases = cf.similar("drainer lag rising on gcp")
    assert cases[0].summary == "fresh take"
