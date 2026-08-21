"""Append-only JSONL audit log.

One record per question and one per tool call, at ``AUDIT_DIR/YYYY-MM-DD.jsonl``.

Design constraints:

* **Crash-safe**: every record is a single ``write()`` of one line to a file
  opened in append mode, then flushed. A torn process loses at most the record
  in flight, never the file.
* **No result bodies.** Only ``output_sha256`` of the output is recorded. The
  audit trail proves what ran and that the answer matched a given output; it is
  not a second copy of production data (which would re-import every DPDP problem
  the redactor exists to remove).
* Params are recorded, and may contain identifiers like a driver id — that is
  intentional and is what makes an audit trail useful. Free-text values are
  passed through the redactor first so a pasted phone number cannot land here.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app import config
from app.redactor import redact_value

_lock = threading.Lock()


def _audit_dir() -> Path:
    return Path(os.getenv("INFRAGPT_AUDIT_DIR") or config.AUDIT_DIR)


def audit_path(when: datetime | None = None) -> Path:
    day = (when or datetime.now(UTC)).strftime("%Y-%m-%d")
    return _audit_dir() / f"{day}.jsonl"


def sha256_text(text: str | None) -> str | None:
    if text is None:
        return None
    return hashlib.sha256(text.encode()).hexdigest()


def _write(record: dict[str, Any]) -> None:
    path = audit_path()
    line = json.dumps(record, default=str, ensure_ascii=False, sort_keys=True) + "\n"
    with _lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Append mode + flush + fsync-free single small write: an interrupted
        # process cannot leave a half-record ahead of a good one.
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()


def _base(
    kind: str,
    user_email: str,
    conversation_id: int | str | None,
    question: str | None,
) -> dict[str, Any]:
    return {
        "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "kind": kind,
        "user_email": user_email,
        "conversation_id": conversation_id,
        "question": redact_value(question) if question else None,
    }


def audit_call(
    *,
    user_email: str,
    conversation_id: int | str | None = None,
    question: str | None = None,
    entry_name: str,
    params: dict[str, Any] | None = None,
    target: str | None = None,
    cloud: str | None = None,
    validation_verdict: str,
    ok: bool,
    error: str | None = None,
    output: str | None = None,
    output_sha256: str | None = None,
    rows: int | None = None,
    chars: int | None = None,
    duration_ms: int = 0,
    tokens_in: int = 0,
    tokens_out: int = 0,
) -> None:
    """Record one registry-entry execution.

    ``rows`` is recorded because ok/failed is not enough to know whether a call
    was USEFUL. A call that succeeds and returns nothing is the failure mode
    this system keeps having to design against — it renders as zero, and zero
    reads as health. Counting rows is what lets the experience layer tell "this
    function works" from "this function always comes back empty".

    Pass ``output`` (hashed here) or a precomputed ``output_sha256`` — never both
    the body and an expectation that it will be stored. The body is not written.
    """
    record = _base("call", user_email, conversation_id, question)
    if rows is not None:
        record["rows"] = int(rows)
    if chars is not None:
        record["chars"] = int(chars)
    record.update(
        {
            "entry_name": entry_name,
            "params": redact_value(params or {}),
            "target": target,
            "cloud": cloud,
            "validation_verdict": validation_verdict,
            "ok": ok,
            "error": error,
            "output_sha256": output_sha256 or sha256_text(output),
            "duration_ms": duration_ms,
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
        }
    )
    _write(record)


def audit_question(
    *,
    user_email: str,
    conversation_id: int | str | None = None,
    question: str,
    ok: bool,
    error: str | None = None,
    answer: str | None = None,
    answer_sha256: str | None = None,
    entry_names: list[str] | None = None,
    duration_ms: int = 0,
    tokens_in: int = 0,
    tokens_out: int = 0,
) -> None:
    """Record one end-to-end question. The answer text itself is not stored."""
    record = _base("question", user_email, conversation_id, question)
    record.update(
        {
            "entry_name": None,
            "entry_names": entry_names or [],
            "params": {},
            "target": None,
            "cloud": None,
            "validation_verdict": "n/a",
            "ok": ok,
            "error": error,
            "output_sha256": answer_sha256 or sha256_text(answer),
            "duration_ms": duration_ms,
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
        }
    )
    _write(record)


def read_audit(day: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    """Read back a day's records, newest last. Used by the admin audit view."""
    when = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=UTC) if day else None
    path = audit_path(when)
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    out: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            # A torn tail record is skipped, never fatal.
            continue
    return out
