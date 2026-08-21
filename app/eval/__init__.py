"""Golden eval set for the selector.

Run it::

    python -m app.eval                    # offline baseline selector, CI-safe
    python -m app.eval --write-baseline   # freeze the current scorecard

Exits non-zero on regression against ``baseline.json``, so it can gate a deploy.
"""

from __future__ import annotations

from app.eval.cases import CASES_PATH, EvalCase, EvalCaseError, load_cases
from app.eval.runner import (
    BASELINE_PATH,
    CaseResult,
    RegressionReport,
    Scorecard,
    compare_to_baseline,
    format_scorecard,
    load_baseline,
    run_case,
    run_eval,
    write_baseline,
)
from app.eval.selectors import (
    KeywordSelector,
    Selection,
    Selector,
    from_callable,
    refusing_selector,
)

__all__ = [
    "BASELINE_PATH",
    "CASES_PATH",
    "CaseResult",
    "EvalCase",
    "EvalCaseError",
    "KeywordSelector",
    "RegressionReport",
    "Scorecard",
    "Selection",
    "Selector",
    "compare_to_baseline",
    "format_scorecard",
    "from_callable",
    "load_baseline",
    "load_cases",
    "refusing_selector",
    "run_case",
    "run_eval",
    "write_baseline",
]
