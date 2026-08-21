"""Eval runner and scorecard.

Scores **function selection**, which is the decision that determines whether an
answer can be right at all. Everything downstream (execution, redaction,
synthesis) is covered by unit tests; this is the part that depends on a model and
therefore needs a regression gate.

Two scoring subtleties worth knowing:

* **Refusal cases are scored separately and reported separately.** They are ~19%
  of the set, so a selector that refuses everything would score ~19% overall —
  which looks like a bad selector, not like the specific pathology it is. Split
  metrics make that visible instead of averaging it away.
* **Expected functions are a multiset.** ``redis_cross_cloud_staleness`` expects
  ``redis_exists`` *twice* (once per cloud); collapsing to a set would score a
  single-cloud answer as perfect, which is exactly the cross-cloud mistake the
  plan warns about.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.eval.cases import EvalCase, load_cases
from app.eval.selectors import KeywordSelector, Selection, Selector
from app.registry.loader import Registry, get_registry
from app.registry.schema import ParamValidationError

BASELINE_PATH = Path(__file__).with_name("baseline.json")

#: How far the score may drop before the run is treated as a regression.
#: Non-zero because the live selector is a model and is not bit-reproducible;
#: zero for the offline baseline selector, which is deterministic.
DEFAULT_TOLERANCE = 0.0

#: Decimal places used for every persisted and compared score. Must be the same
#: on both sides of the comparison — see compare_to_baseline.
_BASELINE_PRECISION = 4


@dataclass
class CaseResult:
    case_id: str
    question: str
    expected: list[str]
    selected: list[str]
    is_refusal: bool
    exact: bool
    params_ok: bool
    params_error: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.exact and self.params_ok


@dataclass
class Scorecard:
    total: int = 0
    passed: int = 0
    exact: int = 0
    refusal_total: int = 0
    refusal_passed: int = 0
    answerable_total: int = 0
    answerable_passed: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    by_tag: dict[str, dict[str, int]] = field(default_factory=dict)
    results: list[CaseResult] = field(default_factory=list)

    @property
    def score(self) -> float:
        return self.passed / self.total if self.total else 0.0

    @property
    def refusal_score(self) -> float:
        return self.refusal_passed / self.refusal_total if self.refusal_total else 0.0

    @property
    def answerable_score(self) -> float:
        return (
            self.answerable_passed / self.answerable_total
            if self.answerable_total
            else 0.0
        )

    def summary(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "passed": self.passed,
            "score": round(self.score, _BASELINE_PRECISION),
            "answerable_score": round(self.answerable_score, 4),
            "refusal_score": round(self.refusal_score, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


def _check_params(
    case: EvalCase, selections: list[Selection], registry: Registry
) -> tuple[bool, str]:
    """Every selected call must validate, and expected params must match.

    Validating through ``RegistryEntry.validate_params`` means the eval catches a
    selector that emits a well-named function with an unusable argument — which
    in production is a rejected call, i.e. a non-answer.
    """
    for selection in selections:
        try:
            entry = registry.get(selection.function)
        except KeyError:
            return False, f"hallucinated function '{selection.function}'"
        try:
            entry.validate_params(selection.params)
        except ParamValidationError as exc:
            return False, f"{selection.function}: {exc}"

    if not case.expected_params:
        return True, ""

    merged: dict[str, Any] = {}
    for selection in selections:
        merged.update({k: v for k, v in selection.params.items() if v is not None})
    for key, expected_value in case.expected_params.items():
        if merged.get(key) != expected_value:
            return False, (
                f"param '{key}': expected {expected_value!r}, got {merged.get(key)!r}"
            )
    return True, ""


def run_case(
    case: EvalCase, selector: Selector, registry: Registry | None = None
) -> CaseResult:
    registry = registry or get_registry()
    tool_specs = registry.llm_tool_specs(set(case.surfaces))
    selections = list(selector(case.question, tool_specs) or [])
    selected_names = [s.function for s in selections]

    exact = Counter(selected_names) == Counter(case.expected_functions)
    params_ok, params_error = _check_params(case, selections, registry)

    return CaseResult(
        case_id=case.id,
        question=case.question,
        expected=list(case.expected_functions),
        selected=selected_names,
        is_refusal=case.is_refusal,
        exact=exact,
        params_ok=params_ok,
        params_error=params_error,
        tags=list(case.tags),
    )


def run_eval(
    selector: Selector | None = None,
    cases: list[EvalCase] | None = None,
    registry: Registry | None = None,
) -> Scorecard:
    """Score a selector against the golden set. No infrastructure required."""
    registry = registry or get_registry()
    cases = cases if cases is not None else load_cases(registry=registry)
    selector = selector or KeywordSelector()

    card = Scorecard()
    true_positives = selected_total = expected_total = 0

    for case in cases:
        result = run_case(case, selector, registry)
        card.results.append(result)
        card.total += 1
        card.exact += int(result.exact)
        card.passed += int(result.passed)

        if case.is_refusal:
            card.refusal_total += 1
            card.refusal_passed += int(result.passed)
        else:
            card.answerable_total += 1
            card.answerable_passed += int(result.passed)

        expected_counter = Counter(result.expected)
        selected_counter = Counter(result.selected)
        true_positives += sum((expected_counter & selected_counter).values())
        selected_total += sum(selected_counter.values())
        expected_total += sum(expected_counter.values())

        for tag in result.tags:
            bucket = card.by_tag.setdefault(tag, {"total": 0, "passed": 0})
            bucket["total"] += 1
            bucket["passed"] += int(result.passed)

    card.precision = true_positives / selected_total if selected_total else 0.0
    card.recall = true_positives / expected_total if expected_total else 0.0
    card.f1 = (
        2 * card.precision * card.recall / (card.precision + card.recall)
        if (card.precision + card.recall)
        else 0.0
    )
    return card


# ---------------------------------------------------------------------------
# Reporting and the regression gate
# ---------------------------------------------------------------------------


def format_scorecard(card: Scorecard, show_failures: bool = True) -> str:
    lines = [
        "infragpt eval scorecard",
        "=" * 60,
        f"overall          {card.passed}/{card.total}  ({card.score:.1%})",
        f"  answerable     {card.answerable_passed}/{card.answerable_total}  "
        f"({card.answerable_score:.1%})",
        f"  refusals       {card.refusal_passed}/{card.refusal_total}  "
        f"({card.refusal_score:.1%})",
        f"precision {card.precision:.3f}   recall {card.recall:.3f}   f1 {card.f1:.3f}",
        "",
        "by tag",
        "-" * 60,
    ]
    for tag, bucket in sorted(card.by_tag.items()):
        lines.append(
            f"  {tag:<18} {bucket['passed']:>3}/{bucket['total']:<3} "
            f"({bucket['passed'] / bucket['total']:.0%})"
        )

    if show_failures:
        failures = [r for r in card.results if not r.passed]
        if failures:
            lines += ["", f"failures ({len(failures)})", "-" * 60]
            for result in failures:
                lines.append(f"  {result.case_id}")
                lines.append(f"    expected: {result.expected or '(refuse)'}")
                lines.append(f"    selected: {result.selected or '(nothing)'}")
                if result.params_error:
                    lines.append(f"    params:   {result.params_error}")
    return "\n".join(lines)


def load_baseline(path: Path | None = None) -> dict[str, Any]:
    path = path or BASELINE_PATH
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def write_baseline(card: Scorecard, path: Path | None = None) -> Path:
    """Freeze the current scorecard as the regression gate.

    Only run this deliberately: overwriting the baseline after a drop is how a
    regression gets ratified instead of fixed.
    """
    path = path or BASELINE_PATH
    payload = {
        "summary": card.summary(),
        "cases": {r.case_id: r.passed for r in sorted(card.results, key=lambda r: r.case_id)},
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


@dataclass
class RegressionReport:
    ok: bool
    reasons: list[str] = field(default_factory=list)
    newly_failing: list[str] = field(default_factory=list)
    newly_passing: list[str] = field(default_factory=list)

    def format(self) -> str:
        lines: list[str] = []
        if self.newly_passing:
            lines.append(f"improved: {', '.join(sorted(self.newly_passing))}")
        if self.newly_failing:
            lines.append(f"REGRESSED: {', '.join(sorted(self.newly_failing))}")
        lines.extend(self.reasons)
        if self.ok and not lines:
            lines.append("no regression against baseline")
        return "\n".join(lines)


def compare_to_baseline(
    card: Scorecard,
    baseline: dict[str, Any] | None = None,
    tolerance: float = DEFAULT_TOLERANCE,
) -> RegressionReport:
    """Fail when the score drops, or when a previously passing case now fails.

    The per-case check matters as much as the aggregate: swapping one newly
    passing case for one newly failing case leaves the score identical while
    breaking something that used to work.
    """
    baseline = baseline if baseline is not None else load_baseline()
    if not baseline:
        return RegressionReport(
            ok=True,
            reasons=["no baseline committed yet — run `python -m app.eval --write-baseline`"],
        )

    report = RegressionReport(ok=True)
    previous_score = float(baseline.get("summary", {}).get("score", 0.0))
    # Compare at the SAME precision the baseline was persisted with. Comparing a
    # full-precision score against a rounded one makes an unchanged run fail its
    # own baseline (25/46 = 0.543478 < stored 0.5435), which is a CI failure that
    # teaches people to ignore CI.
    current_score = round(card.score, _BASELINE_PRECISION)
    if current_score + tolerance < previous_score:
        report.ok = False
        report.reasons.append(
            f"score dropped: {current_score:.1%} < baseline {previous_score:.1%} "
            f"(tolerance {tolerance:.1%})"
        )

    previous_cases: dict[str, bool] = baseline.get("cases", {})
    current = {r.case_id: r.passed for r in card.results}
    for case_id, was_passing in previous_cases.items():
        now = current.get(case_id)
        if now is None:
            report.ok = False
            report.reasons.append(f"case '{case_id}' disappeared from the set")
        elif was_passing and not now:
            report.ok = False
            report.newly_failing.append(case_id)
        elif not was_passing and now:
            report.newly_passing.append(case_id)
    return report


__all__ = [
    "BASELINE_PATH",
    "DEFAULT_TOLERANCE",
    "CaseResult",
    "RegressionReport",
    "Scorecard",
    "compare_to_baseline",
    "format_scorecard",
    "load_baseline",
    "run_case",
    "run_eval",
    "write_baseline",
]
