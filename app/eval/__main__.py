"""``python -m app.eval`` — run the golden set and gate on regression."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.eval.cases import load_cases
from app.eval.runner import (
    DEFAULT_TOLERANCE,
    compare_to_baseline,
    format_scorecard,
    load_baseline,
    run_eval,
    write_baseline,
)
from app.eval.selectors import (
    KeywordSelector,
    Selector,
    grid_selector,
    refusing_selector,
)

#: Selectors runnable without a network. The live Grid selector is injected by
#: the caller (see ``run_eval(selector=...)``) rather than named here, so this
#: module never imports app.grid and stays usable in CI.
OFFLINE_SELECTORS: dict[str, Selector] = {
    "keyword": KeywordSelector(),
    "refuse-all": refusing_selector,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.eval",
        description="Score the selector against the golden eval set.",
    )
    parser.add_argument(
        "--selector",
        default="keyword",
        choices=[*sorted(OFFLINE_SELECTORS), "grid"],
        help=(
            "selector to score (default: keyword). 'grid' calls the LIVE gateway "
            "and needs GRID_API_KEY — never the CI default."
        ),
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="freeze this run as the regression baseline (do this deliberately)",
    )
    parser.add_argument(
        "--baseline", type=Path, default=None, help="path to baseline.json"
    )
    parser.add_argument(
        "--tolerance",
        type=float,
        default=DEFAULT_TOLERANCE,
        help="allowed score drop before failing (default: %(default)s)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON, not text")
    parser.add_argument(
        "--tag", default=None, help="only run cases carrying this tag"
    )
    args = parser.parse_args(argv)

    cases = load_cases()
    if args.tag:
        cases = [c for c in cases if args.tag in c.tags]
        if not cases:
            print(f"no cases with tag '{args.tag}'", file=sys.stderr)
            return 2

    selector = (
        grid_selector if args.selector == "grid" else OFFLINE_SELECTORS[args.selector]
    )
    card = run_eval(selector=selector, cases=cases)

    if args.write_baseline:
        path = write_baseline(card, args.baseline)
        print(format_scorecard(card))
        print(f"\nbaseline written to {path}")
        return 0

    report = compare_to_baseline(
        card,
        baseline=load_baseline(args.baseline),
        tolerance=args.tolerance,
    )

    if args.json:
        print(
            json.dumps(
                {
                    "summary": card.summary(),
                    "ok": report.ok,
                    "newly_failing": report.newly_failing,
                    "newly_passing": report.newly_passing,
                    "reasons": report.reasons,
                },
                indent=2,
            )
        )
    else:
        print(format_scorecard(card))
        print()
        print(report.format())

    # A filtered run cannot judge the whole-set baseline.
    if args.tag:
        return 0
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
