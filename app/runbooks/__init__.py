"""Runbook store and retrieval.

Runbooks are how the selector learns *which* registry function answers a class of
question. They are the main determinant of answer quality — without them the
model guesses at near-miss functions.

Retrieval is deliberately keyword-based rather than embedding-based: the corpus is
small (tens of documents), the vocabulary is highly specific ("crashloop",
"replication lag", "0DC"), and a lexical match is both cheaper and far easier to
debug when a wrong runbook gets pulled. Swap in embeddings when the corpus grows
past the point where this stops working.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from app import config

STALE_AFTER = timedelta(days=180)
_WORD_RE = re.compile(r"[a-z0-9_]+")


@dataclass
class Runbook:
    name: str
    body: str
    surfaces: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    owner: str = ""
    reviewed_on: date | None = None
    path: Path | None = None

    @property
    def is_stale(self) -> bool:
        if self.reviewed_on is None:
            return True
        return datetime.now().date() - self.reviewed_on > STALE_AFTER

    def score(self, question: str) -> float:
        """Lexical overlap between the question and this runbook's keywords/name.

        Keywords are weighted far above body text so that a runbook is pulled for
        the reason its author intended, not because a common word appears in its
        prose.
        """
        tokens = set(_WORD_RE.findall(question.lower()))
        if not tokens:
            return 0.0
        score = 0.0
        for kw in self.keywords:
            kw_tokens = set(_WORD_RE.findall(kw.lower()))
            if kw_tokens and kw_tokens <= tokens:
                score += 3.0
        name_tokens = set(_WORD_RE.findall(self.name.lower()))
        score += 2.0 * len(name_tokens & tokens)
        body_tokens = set(_WORD_RE.findall(self.body.lower()))
        score += 0.25 * len(body_tokens & tokens)
        if self.is_stale:
            score *= 0.5  # de-prioritised, never silently dropped
        return score


def _parse(path: Path) -> Runbook:
    raw = path.read_text(encoding="utf-8")
    meta: dict[str, Any] = {}
    body = raw
    if raw.startswith("---"):
        _, _, rest = raw.partition("---")
        front, sep, body = rest.partition("---")
        if sep:
            meta = yaml.safe_load(front) or {}
        else:
            body = rest
    reviewed = meta.get("reviewed_on")
    if isinstance(reviewed, datetime):
        reviewed = reviewed.date()
    elif isinstance(reviewed, str):
        try:
            reviewed = date.fromisoformat(reviewed)
        except ValueError:
            reviewed = None
    elif not isinstance(reviewed, date):
        reviewed = None
    return Runbook(
        name=str(meta.get("name") or path.stem),
        body=body.strip(),
        surfaces=list(meta.get("surfaces") or []),
        functions=list(meta.get("functions") or []),
        keywords=list(meta.get("keywords") or []),
        owner=str(meta.get("owner") or ""),
        reviewed_on=reviewed,
        path=path,
    )


class RunbookStore:
    def __init__(self, runbooks: list[Runbook]) -> None:
        self._runbooks = runbooks

    def __len__(self) -> int:
        return len(self._runbooks)

    def all(self) -> list[Runbook]:
        return list(self._runbooks)

    def stale(self) -> list[Runbook]:
        return [r for r in self._runbooks if r.is_stale]

    def retrieve(self, question: str, limit: int = 3, min_score: float = 1.0) -> list[Runbook]:
        scored = [(rb.score(question), rb) for rb in self._runbooks]
        hits = [(s, rb) for s, rb in scored if s >= min_score]
        hits.sort(key=lambda pair: pair[0], reverse=True)
        return [rb for _, rb in hits[:limit]]

    def context_for(self, question: str, limit: int = 3) -> str:
        """Runbook text to inject into the selector prompt."""
        chosen = self.retrieve(question, limit=limit)
        if not chosen:
            return ""
        blocks = []
        for rb in chosen:
            fns = ", ".join(rb.functions) if rb.functions else "—"
            stale = "  (STALE — verify before relying on this)" if rb.is_stale else ""
            blocks.append(f"## {rb.name}{stale}\nRelevant functions: {fns}\n\n{rb.body}")
        return "\n\n".join(blocks)


def load_runbooks(directory: Path | None = None) -> RunbookStore:
    directory = directory or config.RUNBOOK_DIR
    if not directory.exists():
        return RunbookStore([])
    return RunbookStore([_parse(p) for p in sorted(directory.glob("*.md"))])


_store: RunbookStore | None = None


def get_runbooks(directory: Path | None = None, *, reload: bool = False) -> RunbookStore:
    global _store
    if _store is None or reload:
        _store = load_runbooks(directory)
    return _store
