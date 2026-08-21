"""Selectors for the eval harness.

A *selector* is any callable ``(question, tool_specs) -> list[Selection]``. That
is the whole interface, and it is what makes the harness runnable in CI: the live
Grid selector satisfies it, and so does the offline keyword baseline below. No
network, no API key, no flake.

``KeywordSelector`` is not a toy — it is the **floor**. It reads the same tool
specs the LLM is given and scores them by term overlap. If the Grid selector
cannot beat a bag-of-words matcher on this case set, the LLM is not adding
anything and the prompt needs work. Committing that floor as a baseline is how
that stays measurable rather than assumed.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

_TOKEN_RE = re.compile(r"[a-z0-9]+")

#: Words that carry no signal about which function to call.
_STOPWORDS = frozenset(
    """
    a an the is are was were be been being do does did doing have has had having
    i me my we our you your it its this that these those what which who whom
    how why when where can could should would will shall may might must
    show me tell give get list find see look check on in at to for of and or
    from with about right now please any some all there here
    """.split()
)

#: Question terms that name a cloud, mapped to the param value.
CLOUD_TERMS: dict[str, str] = {
    "gcp": "gcp",
    "gke": "gcp",
    "google": "gcp",
    "aws": "aws",
    "eks": "aws",
    "amazon": "aws",
}

#: Question terms that name a database connection.
DB_TERMS: dict[str, str] = {
    "driver": "driver_ro",
    "bpp": "driver_ro",
    "rider": "rider_ro",
    "bap": "rider_ro",
}


@dataclass
class Selection:
    """One chosen call. Mirrors what the Grid selector must emit."""

    function: str
    params: dict[str, Any] = field(default_factory=dict)


Selector = Callable[[str, Sequence[dict[str, Any]]], list[Selection]]


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS]


def refusing_selector(question: str, tool_specs: Sequence[dict[str, Any]]) -> list[Selection]:
    """Selects nothing, ever. The trivial lower bound.

    Useful as a control: it scores 100% on the refusal cases and 0% everywhere
    else, which is exactly what a scorecard that only reported overall accuracy
    would hide.
    """
    return []


@dataclass
class KeywordSelector:
    """Offline bag-of-words baseline.

    Scores each offered tool by overlap between the question's terms and the
    tool's name and description, then fills the obvious params (cloud, db, key,
    pod) from the question. Refuses when nothing scores above ``threshold``.
    """

    threshold: float = 2.0
    max_calls: int = 2

    def __call__(
        self, question: str, tool_specs: Sequence[dict[str, Any]]
    ) -> list[Selection]:
        terms = set(tokenize(question))
        if not terms or not tool_specs:
            return []

        scored: list[tuple[float, dict[str, Any]]] = []
        for spec in tool_specs:
            score = self._score(terms, spec)
            if score >= self.threshold:
                scored.append((score, spec))

        scored.sort(key=lambda pair: (-pair[0], pair[1]["name"]))
        chosen = scored[: self.max_calls]
        if not chosen:
            return []
        # Only keep runners-up that are close to the leader; otherwise a single
        # good match drags an unrelated function along with it.
        best = chosen[0][0]
        return [
            Selection(spec["name"], self._params(question, spec))
            for score, spec in chosen
            if score >= best
        ]

    @staticmethod
    def _score(terms: set[str], spec: dict[str, Any]) -> float:
        name_terms = set(tokenize(spec["name"].replace("_", " ")))
        desc_terms = set(tokenize(spec.get("description", "")))
        # A name hit is worth far more than a description hit: descriptions are
        # prose and share filler vocabulary across every entry on a surface.
        return 3.0 * len(terms & name_terms) + 0.5 * len(terms & desc_terms)

    @staticmethod
    def _params(question: str, spec: dict[str, Any]) -> dict[str, Any]:
        props: dict[str, Any] = spec.get("parameters", {}).get("properties", {})
        lowered = question.lower()
        params: dict[str, Any] = {}

        if "cloud" in props:
            found = {v for k, v in CLOUD_TERMS.items() if re.search(rf"\b{k}\b", lowered)}
            if len(found) == 1:
                params["cloud"] = found.pop()

        if "db" in props:
            found_db = {v for k, v in DB_TERMS.items() if re.search(rf"\b{k}\b", lowered)}
            if len(found_db) == 1:
                params["db"] = found_db.pop()

        if "key" in props:
            match = re.search(r"\b([a-z0-9_]+(?::[a-z0-9_*-]+)+)\b", question, re.I)
            if match:
                params["key"] = match.group(1)

        for slot in ("pod", "deployment", "service"):
            if slot in props:
                match = re.search(rf"{slot}\s+([a-z0-9][a-z0-9.-]{{2,}})", lowered)
                if match:
                    params[slot] = match.group(1)

        return params


def from_callable(fn: Callable[[str, Sequence[dict[str, Any]]], Any]) -> Selector:
    """Adapt a selector that returns dicts into one that returns Selections.

    The live Grid selector will return ``{"function": ..., "params": {...}}``
    dicts straight from a structured-output call; this normalises them so the
    scorer sees one shape.
    """

    def _wrapped(
        question: str, tool_specs: Sequence[dict[str, Any]]
    ) -> list[Selection]:
        out: list[Selection] = []
        for item in fn(question, tool_specs) or []:
            if isinstance(item, Selection):
                out.append(item)
            elif isinstance(item, dict):
                name = item.get("function") or item.get("name")
                if name:
                    out.append(Selection(str(name), dict(item.get("params") or {})))
        return out

    return _wrapped


__all__ = [
    "CLOUD_TERMS",
    "DB_TERMS",
    "KeywordSelector",
    "Selection",
    "Selector",
    "from_callable",
    "refusing_selector",
    "tokenize",
]


def grid_selector(
    question: str, tool_specs: Sequence[dict[str, Any]]
) -> list[Selection]:
    """The LIVE selector — calls the Grid gateway.

    Not in OFFLINE_SELECTORS on purpose: it needs a network and an API key, so it
    must never be what CI silently scores. Use it deliberately, with
    ``python -m app.eval --selector grid``, to measure the thing that actually
    ships. The keyword baseline is the floor this must beat to be worth its cost.
    """
    import asyncio

    from app.grid.client import get_grid_client

    async def _run() -> list[Selection]:
        sel = await get_grid_client().select(question, list(tool_specs))
        return [Selection(function=c.name, params=c.arguments) for c in sel.calls]

    return asyncio.run(_run())
