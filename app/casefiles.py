"""Case files — the tool's memory of its own investigations.

Runbooks are what a person wrote down in advance; the experience layer is
counts of what fails. Neither remembers what an actual investigation FOUND.
So the same incident shape gets debugged from scratch every time: the reader
CPU question someone answered on Tuesday is re-derived on Thursday, calls and
all, because nothing carried Tuesday's conclusion forward.

A case file is that carry. When a question is answered from real evidence, the
question, the answer's opening, and the functions that produced it are stored.
A later question that resembles it gets the old case put in front of the
selector: what was asked, when, what was concluded, and WHICH FUNCTIONS got
there — so the selector can go straight to the calls that worked last time and
the synthesiser can say "this also happened on the 21st".

TRUST BOUNDARY, stated plainly: a case file contains model-written text, so it
is context, never fact. Every retrieval is wrapped in a warning that findings
were true THEN and must be re-verified now — a stale conclusion presented as
current state is precisely the confident-wrong answer this tool is built to
avoid. The functions list is the safest part (it is only names); the summary
is the useful part; neither is authority.

Retrieval is lexical overlap, deliberately. An embedding index would retrieve
better and cost a model dependency plus an opaque failure mode; overlap on
distinctive words retrieves well enough for infra questions, which are dense
with identifiers ("driver reader", "0dc", "seq scan") that either match or do
not, and is inspectable when it misbehaves.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass

from app.storage.db import Database

#: Words too common to signal similarity between infra questions.
_STOP = frozenset(
    "the a an is are was were what which why how many much when where who "
    "do does did can could should would will in on at of for to from with "
    "and or not no it its this that these those there here now then än än "
    "me my we our you your show me get list find check tell give us any "
    "please pls right also".split()
)

_WORD_RE = re.compile(r"[a-z0-9_\-:.]{2,}")

MAX_CASES = 3
MAX_SUMMARY_CHARS = 700
#: A case older than this is dropped from retrieval entirely. Infra changes;
#: a six-month-old conclusion is more likely to mislead than to help.
MAX_AGE_DAYS = 90


def _tokens(text: str) -> set[str]:
    return {w for w in _WORD_RE.findall(text.lower()) if w not in _STOP}


@dataclass(frozen=True)
class Case:
    id: int
    ts: float
    question: str
    summary: str
    functions: list[str]
    age_days: int


class CaseFiles:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS casefiles ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  ts REAL NOT NULL,"
            "  user_email TEXT NOT NULL,"
            "  question TEXT NOT NULL,"
            "  summary TEXT NOT NULL,"
            "  functions TEXT NOT NULL DEFAULT '[]'"
            ")"
        )

    def record(
        self,
        user_email: str,
        question: str,
        answer: str,
        functions: list[str],
    ) -> None:
        """Store one answered investigation.

        Only worth storing when there was an investigation: an answer with no
        calls behind it is the model talking, and remembering model talk as a
        precedent would launder it into evidence on the next question.
        """
        if not functions or not answer.strip():
            return
        summary = answer.strip()[:MAX_SUMMARY_CHARS]
        # Keep the distinct function names in first-use order — the ORDER is
        # part of what a future investigation wants to copy.
        seen: dict[str, None] = {}
        for f in functions:
            seen.setdefault(f, None)
        self.db.execute(
            "INSERT INTO casefiles (ts, user_email, question, summary, functions) "
            "VALUES (?, ?, ?, ?, ?)",
            (time.time(), user_email, question, summary, json.dumps(list(seen))),
        )

    def similar(self, question: str, now: float | None = None) -> list[Case]:
        """The most similar past cases, newest-favoured, none older than 90d.

        Similarity is overlap of distinctive words; ties and near-ties go to
        the newer case because infra facts decay. A case must share at least
        two distinctive words — one shared word ("driver") matches half the
        questions ever asked and would attach an irrelevant precedent to them.
        """
        now = now or time.time()
        q = _tokens(question)
        if not q:
            return []
        cutoff = now - MAX_AGE_DAYS * 86400
        rows = self.db.query_all(
            "SELECT id, ts, question, summary, functions FROM casefiles "
            "WHERE ts >= ? ORDER BY ts DESC LIMIT 400",
            (cutoff,),
        )
        scored: list[tuple[float, Case]] = []
        for r in rows:
            overlap = q & _tokens(r["question"] + " " + r["summary"])
            if len(overlap) < 2:
                continue
            age_days = int((now - r["ts"]) / 86400)
            score = len(overlap) / (1 + age_days / 30)
            scored.append(
                (
                    score,
                    Case(
                        id=r["id"],
                        ts=r["ts"],
                        question=r["question"],
                        summary=r["summary"],
                        functions=json.loads(r["functions"] or "[]"),
                        age_days=age_days,
                    ),
                )
            )
        scored.sort(key=lambda t: -t[0])
        return [c for _, c in scored[:MAX_CASES]]

    def context_for(self, question: str) -> str:
        """Render similar cases as selector context, warnings included."""
        cases = self.similar(question)
        if not cases:
            return ""
        parts = [
            "PAST INVESTIGATIONS on this infrastructure that resemble this "
            "question. These are what was found THEN — the situation may have "
            "changed, so re-verify with live calls rather than repeating the "
            "old conclusion. The function lists show which calls produced the "
            "answer last time; starting with those is usually the fastest path."
        ]
        for c in cases:
            when = f"{c.age_days}d ago" if c.age_days else "today"
            parts.append(
                f"[{when}] Q: {c.question}\n"
                f"Functions that answered it: {', '.join(c.functions)}\n"
                f"Finding at the time: {c.summary}"
            )
        return "\n\n".join(parts)


_instance: CaseFiles | None = None


def get_casefiles(db: Database | None = None) -> CaseFiles:
    global _instance  # noqa: PLW0603
    if _instance is None or db is not None:
        from app.storage import get_storage

        _instance = CaseFiles(db if db is not None else get_storage().db)
    return _instance


def reset_casefiles() -> None:
    global _instance  # noqa: PLW0603
    _instance = None
