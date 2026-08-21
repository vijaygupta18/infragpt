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


# --- authoring --------------------------------------------------------------
#
# Runbooks are the ONE thing this tool writes, and the exception is deliberate.
#
# Everything else here is read-only against infrastructure. A runbook is not
# infrastructure — it is the tool's own knowledge, and the whole value of the
# feature is that an operator can add what they know without shipping a release.
# Nothing written here can reach a cluster: it is text, retrieved and put in
# front of a model as context.
#
# It also solves a problem the published repository created. Environment
# specifics — which ClickHouse database holds rides, which workload names are
# real — are exactly what makes answers good and exactly what must not be
# committed. Keeping them on the volume, authored here, puts them where they
# help and out of git.

_SLUG_RE = re.compile(r"[^a-z0-9]+")

#: A runbook is context for a model, not an essay. The cap is generous enough
#: for a real procedure and small enough that one entry cannot crowd out the
#: rest of the prompt.
MAX_BODY_CHARS = 20_000


class RunbookError(ValueError):
    """Raised when a runbook cannot be saved. The message is shown to the user."""


def slugify(name: str) -> str:
    """A filename from a title.

    Derived rather than accepted from the caller: a user-supplied filename is a
    path-traversal question, and there is no reason to ask it. "../../etc/x"
    slugifies to "etc-x" and lands in the runbook directory like anything else.
    """
    slug = _SLUG_RE.sub("-", name.strip().lower()).strip("-")
    if not slug:
        raise RunbookError("Give the runbook a name with some letters in it.")
    return slug[:80]


def save_runbook(
    *,
    name: str,
    body: str,
    keywords: list[str] | None = None,
    surfaces: list[str] | None = None,
    functions: list[str] | None = None,
    owner: str = "",
    directory: Path | None = None,
) -> Path:
    """Write a runbook to the volume and return its path.

    Frontmatter is generated, never parsed from user input: hand-written YAML
    that fails to parse would make the file invisible at load, which looks
    exactly like a runbook that was never saved.
    """
    directory = directory or config.RUNBOOK_DIR
    name = name.strip()
    if not name:
        raise RunbookError("A runbook needs a name.")
    if not body.strip():
        raise RunbookError("A runbook with no content cannot help anyone.")
    if len(body) > MAX_BODY_CHARS:
        raise RunbookError(
            f"Too long ({len(body):,} characters; the limit is "
            f"{MAX_BODY_CHARS:,}). Split it into two runbooks — retrieval works "
            f"better on focused ones anyway."
        )

    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{slugify(name)}.md"

    front = {
        "name": name,
        "surfaces": surfaces or [],
        "functions": functions or [],
        "keywords": keywords or [],
        "owner": owner or "unknown",
        "reviewed_on": datetime.now().date().isoformat(),
    }
    rendered = yaml.safe_dump(front, sort_keys=False, default_flow_style=False)
    path.write_text(f"---\n{rendered}---\n\n{body.strip()}\n")

    # The in-process store is cached; a save that is not visible until the next
    # restart reads as a save that did not happen.
    get_runbooks(directory, reload=True)
    return path


def delete_runbook(slug: str, directory: Path | None = None) -> bool:
    """Remove a runbook by slug. Returns False if it was not there."""
    directory = directory or config.RUNBOOK_DIR
    # Re-slugified, so a crafted value cannot point outside the directory.
    path = directory / f"{slugify(slug)}.md"
    resolved = path.resolve()
    if directory.resolve() not in resolved.parents:
        raise RunbookError("that runbook name is not valid")
    if not resolved.is_file():
        return False
    resolved.unlink()
    get_runbooks(directory, reload=True)
    return True
