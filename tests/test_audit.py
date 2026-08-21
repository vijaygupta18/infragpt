"""Audit writer tests.

The two properties that matter: every call lands as one parseable JSONL record,
and result bodies never do.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from app import audit


@pytest.fixture(autouse=True)
def audit_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("INFRAGPT_AUDIT_DIR", str(tmp_path / "audit"))
    return tmp_path / "audit"


def _records(audit_dir) -> list[dict]:
    path = audit.audit_path()
    assert path.parent == audit_dir
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_call_record_shape(audit_dir) -> None:
    audit.audit_call(
        user_email="ops@example.com",
        conversation_id=7,
        question="which indexes are unused on booking?",
        entry_name="unused_indexes",
        params={"table": "booking", "db": "driver_ro"},
        target="driver_ro",
        cloud="gcp",
        validation_verdict="ok",
        ok=True,
        output="rows...",
        duration_ms=42,
        tokens_in=120,
        tokens_out=30,
    )
    (rec,) = _records(audit_dir)
    for field in (
        "ts", "user_email", "conversation_id", "question", "entry_name", "params",
        "target", "cloud", "validation_verdict", "ok", "error", "output_sha256",
        "duration_ms", "tokens_in", "tokens_out",
    ):
        assert field in rec, field
    assert rec["kind"] == "call"
    assert rec["params"] == {"table": "booking", "db": "driver_ro"}
    assert rec["output_sha256"] == hashlib.sha256(b"rows...").hexdigest()


def test_output_body_is_never_written(audit_dir) -> None:
    secret = "driver 9876543210 at 12.971598,77.594566"  # noqa: S105 - fixture PII
    audit.audit_call(
        user_email="ops@example.com",
        entry_name="pod_logs",
        params={},
        target="k8s_gcp",
        validation_verdict="ok",
        ok=True,
        output=secret,
    )
    raw = audit.audit_path().read_text()
    assert secret not in raw
    assert "9876543210" not in raw
    assert hashlib.sha256(secret.encode()).hexdigest() in raw


def test_question_text_is_redacted(audit_dir) -> None:
    audit.audit_question(
        user_email="ops@example.com",
        question="why is driver 9876543210 (foo@bar.com) not getting rides?",
        ok=False,
        error="no registry function covers this",
    )
    (rec,) = _records(audit_dir)
    assert "9876543210" not in rec["question"]
    assert "foo@bar.com" not in rec["question"]
    assert "phone:" in rec["question"]
    assert rec["ok"] is False
    assert rec["error"] == "no registry function covers this"


def test_params_are_redacted(audit_dir) -> None:
    audit.audit_call(
        user_email="ops@example.com",
        entry_name="redis_get",
        params={"key": "driver:9876543210:loc"},
        target="redis_gcp",
        validation_verdict="ok",
        ok=True,
    )
    (rec,) = _records(audit_dir)
    assert "9876543210" not in json.dumps(rec["params"])


def test_appends_one_line_per_record(audit_dir) -> None:
    for i in range(25):
        audit.audit_call(
            user_email="ops@example.com",
            entry_name=f"entry_{i}",
            params={},
            target="driver_ro",
            validation_verdict="ok",
            ok=True,
        )
    recs = _records(audit_dir)
    assert len(recs) == 25
    assert [r["entry_name"] for r in recs] == [f"entry_{i}" for i in range(25)]


def test_read_audit_tail_and_missing_day(audit_dir) -> None:
    assert audit.read_audit(day="1999-01-01") == []
    for i in range(5):
        audit.audit_question(
            user_email="ops@example.com", question=f"q{i}", ok=True, answer="a"
        )
    tail = audit.read_audit(limit=2)
    assert [r["question"] for r in tail] == ["q3", "q4"]


def test_torn_trailing_record_is_skipped(audit_dir) -> None:
    audit.audit_question(user_email="ops@example.com", question="good", ok=True)
    with open(audit.audit_path(), "a") as fh:
        fh.write('{"ts": "2026-01-01T00:00:0')  # crash mid-write
    recs = audit.read_audit()
    assert [r["question"] for r in recs] == ["good"]
