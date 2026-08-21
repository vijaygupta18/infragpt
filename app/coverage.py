"""Coverage log — the questions infragpt could not answer.

From the plan: *"Coverage, not safety, is now the main risk."* Because the LLM
can only call what the registry declares, the failure mode is never a dangerous
answer — it is no answer. This file is the mechanism that turns that failure into
a roadmap: every "I can't do that" is appended here, and :func:`report` ranks the
gaps by how often people hit them.

Two deliberate choices:

* **Questions are redacted before they are written.** A user asking "why is
  9876543210 not getting rides" would otherwise plant a phone number in a file
  that exists to be read by the whole team.
* **Grouping is by normalised question**, so "which index is missing on booking"
  and "Which index is missing on Booking?" count as the same gap. Without that,
  the top-10 is ten spellings of one request.

Format is JSONL for the same reason as the audit log: one line per record, append
mode, crash-safe, greppable without a parser.
"""

from __future__ import annotations

import json
import os
import re
import threading
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app import config
from app.redactor import redact_text

_lock = threading.Lock()

#: Why a question went unanswered. Distinguishing these matters: NO_FUNCTION is a
#: registry gap, NO_GRANT is a permissions problem, and OUT_OF_SCOPE is the
#: metadata-only DB boundary working as designed. Only the first is a backlog item.
REASON_NO_FUNCTION = "no_function"
REASON_NO_GRANT = "no_grant"
REASON_OUT_OF_SCOPE = "out_of_scope"
REASON_EXECUTION_FAILED = "execution_failed"

REASONS = (
    REASON_NO_FUNCTION,
    REASON_NO_GRANT,
    REASON_OUT_OF_SCOPE,
    REASON_EXECUTION_FAILED,
)

_WHITESPACE_RE = re.compile(r"\s+")
_PUNCT_RE = re.compile(r"[^\w\s]")


def coverage_dir() -> Path:
    return Path(os.getenv("INFRAGPT_COVERAGE_DIR") or (config.DATA_DIR / "coverage"))


def coverage_path(when: datetime | None = None) -> Path:
    month = (when or datetime.now(UTC)).strftime("%Y-%m")
    return coverage_dir() / f"{month}.jsonl"


def normalise(question: str) -> str:
    """Collapse a question to a grouping key: lowercase, unpunctuated, single-spaced."""
    return _WHITESPACE_RE.sub(" ", _PUNCT_RE.sub(" ", question.lower())).strip()


@dataclass
class Gap:
    """One aggregated uncovered question."""

    question: str
    count: int
    reasons: dict[str, int] = field(default_factory=dict)
    users: int = 0
    first_seen: str = ""
    last_seen: str = ""


def record_gap(
    *,
    question: str,
    reason: str = REASON_NO_FUNCTION,
    user_email: str = "",
    surfaces: list[str] | None = None,
    detail: str = "",
) -> None:
    """Append one uncovered question. Never raises into the request path.

    A failure to log a coverage gap must not turn a graceful "I can't answer
    that" into a 500 — the user's experience of the gap is bad enough already.
    """
    if reason not in REASONS:
        reason = REASON_NO_FUNCTION
    record = {
        "ts": datetime.now(UTC).isoformat(timespec="seconds"),
        "question": redact_text(question.strip()),
        "normalised": normalise(redact_text(question)),
        "reason": reason,
        "user_email": user_email,
        "surfaces": sorted(surfaces or []),
        "detail": redact_text(detail) if detail else "",
    }
    line = json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
    try:
        path = coverage_path()
        with _lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
    except OSError:
        return


def read_records(months: int = 6) -> list[dict[str, Any]]:
    """Read the most recent months of coverage records, oldest first."""
    directory = coverage_dir()
    if not directory.is_dir():
        return []
    files = sorted(directory.glob("*.jsonl"))[-months:]
    records: list[dict[str, Any]] = []
    for path in files:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # a torn tail record is skipped, never fatal
    return records


def report(
    limit: int = 20,
    reason: str | None = None,
    months: int = 6,
) -> list[Gap]:
    """Most-requested uncovered questions, most frequent first.

    This is the registry backlog. A gap near the top with reason
    ``no_function`` is a function someone should write; one with
    ``out_of_scope`` is a boundary decision to revisit deliberately, not a bug.
    """
    grouped: dict[str, dict[str, Any]] = {}
    for record in read_records(months=months):
        if reason and record.get("reason") != reason:
            continue
        key = record.get("normalised") or normalise(record.get("question", ""))
        if not key:
            continue
        bucket = grouped.setdefault(
            key,
            {
                "question": record.get("question", ""),
                "count": 0,
                "reasons": Counter(),
                "users": set(),
                "first_seen": record.get("ts", ""),
                "last_seen": record.get("ts", ""),
            },
        )
        bucket["count"] += 1
        bucket["reasons"][record.get("reason", REASON_NO_FUNCTION)] += 1
        if record.get("user_email"):
            bucket["users"].add(record["user_email"])
        ts = record.get("ts", "")
        if ts:
            bucket["first_seen"] = min(bucket["first_seen"] or ts, ts)
            bucket["last_seen"] = max(bucket["last_seen"] or ts, ts)

    gaps = [
        Gap(
            question=b["question"],
            count=b["count"],
            reasons=dict(b["reasons"]),
            users=len(b["users"]),
            first_seen=b["first_seen"],
            last_seen=b["last_seen"],
        )
        for b in grouped.values()
    ]
    # Ties broken by distinct users: two people asking once is a stronger signal
    # than one person asking twice.
    gaps.sort(key=lambda g: (g.count, g.users), reverse=True)
    return gaps[:limit]


def format_report(gaps: list[Gap]) -> str:
    """Render the backlog as text, for the CLI and the admin view."""
    if not gaps:
        return "No coverage gaps recorded. Either everything is covered, or nobody asked."
    width = max(len(g.question) for g in gaps[:20])
    width = min(max(width, 20), 80)
    lines = [
        f"{'count':>5}  {'users':>5}  {'question'.ljust(width)}  reasons",
        f"{'-' * 5}  {'-' * 5}  {'-' * width}  {'-' * 20}",
    ]
    for gap in gaps:
        question = gap.question if len(gap.question) <= width else gap.question[: width - 1] + "…"
        reasons = ", ".join(f"{k}={v}" for k, v in sorted(gap.reasons.items()))
        lines.append(f"{gap.count:>5}  {gap.users:>5}  {question.ljust(width)}  {reasons}")
    return "\n".join(lines)


__all__ = [
    "REASONS",
    "REASON_EXECUTION_FAILED",
    "REASON_NO_FUNCTION",
    "REASON_NO_GRANT",
    "REASON_OUT_OF_SCOPE",
    "Gap",
    "coverage_path",
    "format_report",
    "normalise",
    "read_records",
    "record_gap",
    "report",
]
