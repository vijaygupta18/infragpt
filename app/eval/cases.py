"""Eval case loading and validation.

Cases are validated against the live registry at load time: an
``expected_functions`` entry naming a function that does not exist is a broken
case, and a broken case silently scores as a miss forever. Loudly refusing to
load is the only way that stays visible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.registry.loader import Registry, get_registry
from app.registry.schema import Surface

CASES_PATH = Path(__file__).with_name("cases.yaml")


class EvalCaseError(ValueError):
    """Raised when a case is malformed or references a non-existent function."""


@dataclass(frozen=True)
class EvalCase:
    id: str
    question: str
    surfaces: frozenset[Surface]
    expected_functions: tuple[str, ...] = ()
    expected_params: dict[str, Any] = field(default_factory=dict)
    expected_substrings: tuple[str, ...] = ()
    must_refuse: bool = False
    tags: tuple[str, ...] = ()
    note: str = ""

    @property
    def is_refusal(self) -> bool:
        """A case whose only correct outcome is selecting nothing."""
        return self.must_refuse or not self.expected_functions


def _parse_surfaces(case_id: str, raw: list[str] | None) -> frozenset[Surface]:
    surfaces: set[Surface] = set()
    for name in raw or []:
        try:
            surfaces.add(Surface(name))
        except ValueError:
            raise EvalCaseError(f"{case_id}: unknown surface '{name}'") from None
    return frozenset(surfaces)


def load_cases(
    path: Path | None = None, registry: Registry | None = None
) -> list[EvalCase]:
    """Load and validate every case. Raises on the first bad one."""
    path = path or CASES_PATH
    registry = registry or get_registry()
    raw = yaml.safe_load(path.read_text()) or {}
    items = raw.get("cases") if isinstance(raw, dict) else raw
    if not isinstance(items, list) or not items:
        raise EvalCaseError(f"{path}: expected a non-empty 'cases' list")

    known = set(registry.names())
    cases: list[EvalCase] = []
    seen: set[str] = set()

    for item in items:
        if not isinstance(item, dict):
            raise EvalCaseError(f"{path}: each case must be a mapping")
        case_id = str(item.get("id") or "")
        if not case_id:
            raise EvalCaseError(f"{path}: a case is missing an id")
        if case_id in seen:
            raise EvalCaseError(f"{path}: duplicate case id '{case_id}'")
        seen.add(case_id)

        question = str(item.get("question") or "").strip()
        if not question:
            raise EvalCaseError(f"{case_id}: missing question")

        expected = tuple(item.get("expected_functions") or ())
        unknown = sorted(set(expected) - known)
        if unknown:
            raise EvalCaseError(
                f"{case_id}: expected_functions reference unknown registry "
                f"entries {unknown}"
            )

        surfaces = _parse_surfaces(case_id, item.get("surfaces"))
        # A case that expects a function the notional user cannot see is not a
        # test of the selector, it is a bug in the case.
        offered = {e.name for e in registry.entries_for_surfaces(set(surfaces))}
        unreachable = sorted(set(expected) - offered)
        if unreachable:
            raise EvalCaseError(
                f"{case_id}: expects {unreachable} but the declared surfaces "
                f"{sorted(s.value for s in surfaces)} do not offer them"
            )

        cases.append(
            EvalCase(
                id=case_id,
                question=question,
                surfaces=surfaces,
                expected_functions=expected,
                expected_params=dict(item.get("expected_params") or {}),
                expected_substrings=tuple(item.get("expected_substrings") or ()),
                must_refuse=bool(item.get("must_refuse", False)),
                tags=tuple(item.get("tags") or ()),
                note=str(item.get("note") or "").strip(),
            )
        )
    return cases


__all__ = ["CASES_PATH", "EvalCase", "EvalCaseError", "load_cases"]
