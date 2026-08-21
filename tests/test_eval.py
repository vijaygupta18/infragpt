"""Eval harness tests.

Two jobs here:

1. **Case integrity.** A broken case scores as a permanent miss and nobody
   notices, so the cases are validated as hard as the code is.
2. **The regression gate actually gates.** A gate that cannot fail is worse than
   no gate, because it is believed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.eval.cases import EvalCase, EvalCaseError, load_cases
from app.eval.runner import (
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
    from_callable,
    refusing_selector,
    tokenize,
)
from app.registry.loader import Registry, load_registry
from app.registry.schema import Surface

REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_DIR = REPO_ROOT / "registry"


@pytest.fixture(scope="module")
def registry() -> Registry:
    return load_registry(REGISTRY_DIR)


@pytest.fixture(scope="module")
def cases(registry: Registry) -> list[EvalCase]:
    return load_cases(registry=registry)


# ===========================================================================
# Case integrity
# ===========================================================================


def test_case_set_is_large_enough(cases: list[EvalCase]) -> None:
    """The plan called for 30-50; the floor is what matters.

    The ceiling was raised from 50 when the cloud surfaces landed: growing the
    case set is the desired direction, and a cap that fails the build for having
    MORE coverage is the wrong incentive. The floor stays, so the set cannot
    quietly shrink.
    """
    assert len(cases) >= 30


def test_all_four_surfaces_are_covered(cases: list[EvalCase]) -> None:
    covered = {s for case in cases for s in case.surfaces}
    assert {
        Surface.DB_READ,
        Surface.REDIS_READ,
        Surface.K8S_GCP,
        Surface.K8S_AWS,
        Surface.METRICS,
    } <= covered


def test_enough_refusal_cases(cases: list[EvalCase]) -> None:
    """At least 5 'should refuse' cases, per the brief."""
    assert len([c for c in cases if c.is_refusal]) >= 5


def test_cloud_defaulting_cases_exist(cases: list[EvalCase]) -> None:
    """An unstated cloud must resolve to GCP — silently, without asking.

    This requirement has now changed twice, and the history is the point: it
    first demanded a REFUSAL, then demanded checking BOTH clouds. Neither was
    wrong at the time. What changed is the platform: it is migrating to GCP,
    AWS is not reachable for k8s or logs from this deployment, and both Redis
    connections resolve to the same instance so there is no divergence left to
    detect. Checking both now doubles the cost of every question and surfaces
    connection errors that read like facts about production.

    What must NOT regress is that a question naming a cloud still gets it.
    """
    defaulting = [c for c in cases if "defaulting" in c.tags]
    assert len(defaulting) >= 2

    unstated = [c for c in defaulting if "aws" not in c.question.lower()]
    assert unstated, "there must be a case where no cloud is named"
    for case in unstated:
        assert case.expected_params.get("cloud") == "gcp", (
            f"{case.id}: an unstated cloud must default to gcp"
        )
        assert len(case.expected_functions) == 1, (
            f"{case.id}: one call, not one per cloud"
        )

    named = [c for c in defaulting if "aws" in c.question.lower()]
    assert named, "defaulting must not make AWS unreachable — keep a named-cloud case"
    for case in named:
        assert case.expected_params.get("cloud") == "aws", case.id


def test_mutation_requests_are_all_refusals(cases: list[EvalCase]) -> None:
    """infragpt has no mutation path; every such case must expect a refusal."""
    mutation = [c for c in cases if "mutation" in c.tags]
    assert mutation
    for case in mutation:
        assert case.is_refusal, case.id
        assert case.expected_functions == ()


def test_every_expected_function_exists(
    cases: list[EvalCase], registry: Registry
) -> None:
    known = set(registry.names())
    for case in cases:
        for name in case.expected_functions:
            assert name in known, f"{case.id} -> {name}"


def test_every_expected_param_validates(
    cases: list[EvalCase], registry: Registry
) -> None:
    """An expected_params value that the registry would reject makes a case
    unpassable — the selector could be perfect and still fail it."""
    for case in cases:
        if not case.expected_params or not case.expected_functions:
            continue
        for name in set(case.expected_functions):
            entry = registry.get(name)
            relevant = {
                k: v for k, v in case.expected_params.items() if k in entry.params
            }
            entry.validate_params(
                {
                    **{
                        p: spec.default
                        for p, spec in entry.params.items()
                        if spec.required and spec.default is not None
                    },
                    **relevant,
                }
                if not relevant
                else {**relevant, **_fill_required(entry, relevant)}
            )


def _fill_required(entry: Any, supplied: dict[str, Any]) -> dict[str, Any]:
    """Minimal stand-ins for required params a case did not pin."""
    filler: dict[str, Any] = {}
    for name, spec in entry.params.items():
        if name in supplied or not spec.required:
            continue
        filler[name] = spec.values[0] if spec.values else "placeholder"
    return filler


def test_duplicate_case_ids_are_rejected(tmp_path: Path, registry: Registry) -> None:
    path = tmp_path / "dupes.yaml"
    path.write_text(
        "cases:\n"
        "  - id: same\n    question: q\n    surfaces: [db:read]\n    expected_functions: []\n"
        "  - id: same\n    question: q\n    surfaces: [db:read]\n    expected_functions: []\n"
    )
    with pytest.raises(EvalCaseError, match="duplicate"):
        load_cases(path, registry=registry)


def test_unknown_function_in_a_case_is_rejected(
    tmp_path: Path, registry: Registry
) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        "cases:\n  - id: bad\n    question: q\n    surfaces: [db:read]\n"
        "    expected_functions: [not_a_real_function]\n"
    )
    with pytest.raises(EvalCaseError, match="unknown registry"):
        load_cases(path, registry=registry)


def test_case_expecting_an_ungranted_function_is_rejected(
    tmp_path: Path, registry: Registry
) -> None:
    """The selector is only shown what the grants expose, so a case expecting a
    function outside them tests nothing — it is a bug in the case."""
    path = tmp_path / "ungranted.yaml"
    path.write_text(
        "cases:\n  - id: ungranted\n    question: q\n    surfaces: [metrics]\n"
        "    expected_functions: [table_info]\n"
    )
    with pytest.raises(EvalCaseError, match="do not offer"):
        load_cases(path, registry=registry)


# ===========================================================================
# Scoring
# ===========================================================================


def test_perfect_selector_scores_100(
    cases: list[EvalCase], registry: Registry
) -> None:
    """A selector that replays each case's expected answer must score 1.0.
    If it does not, the scorer is wrong, not the selector.

    The oracle fills any required param the case did not pin. Cases pin only the
    params whose value is the point of the test (which cloud, which db); a real
    selector still has to supply the rest, and an incomplete call is a rejected
    call. Two cases rely on this: `redis_cross_cloud_staleness` (two calls that
    differ only by cloud, so a single merged expected_params cannot express it)
    and `metrics_db_connections_trend`.
    """
    by_question = {c.question: c for c in cases}

    def oracle(question: str, tool_specs: Any) -> list[Selection]:
        case = by_question[question]
        out: list[Selection] = []
        for name in case.expected_functions:
            params = dict(case.expected_params)
            params.update(_fill_required(registry.get(name), params))
            out.append(Selection(name, params))
        return out

    card = run_eval(selector=oracle, cases=cases, registry=registry)
    assert card.score == 1.0
    assert card.refusal_score == 1.0
    assert card.answerable_score == 1.0


def test_refuse_all_scores_refusals_only(
    cases: list[EvalCase], registry: Registry
) -> None:
    """The split metrics exist so this pathology is visible rather than averaged
    into a mediocre-looking overall number."""
    card = run_eval(selector=refusing_selector, cases=cases, registry=registry)
    assert card.refusal_score == 1.0
    assert card.answerable_score == 0.0
    assert 0.0 < card.score < 0.5


def test_keyword_baseline_is_a_real_floor(
    cases: list[EvalCase], registry: Registry
) -> None:
    """The offline baseline must be meaningfully better than refusing
    everything and meaningfully worse than perfect — otherwise it is not a
    useful floor for judging the live selector."""
    card = run_eval(selector=KeywordSelector(), cases=cases, registry=registry)
    assert 0.3 < card.score < 0.9
    assert card.answerable_score > 0.0


def test_baseline_selector_is_deterministic(
    cases: list[EvalCase], registry: Registry
) -> None:
    first = run_eval(selector=KeywordSelector(), cases=cases, registry=registry)
    second = run_eval(selector=KeywordSelector(), cases=cases, registry=registry)
    assert first.summary() == second.summary()


def test_wrong_function_fails_the_case(
    cases: list[EvalCase], registry: Registry
) -> None:
    case = next(c for c in cases if c.expected_functions == ("table_info",))
    result = run_case(
        case,
        lambda q, t: [Selection("table_indexes", {"table": "person", "db": "rider_ro"})],
        registry,
    )
    assert not result.passed


def test_hallucinated_function_fails(
    cases: list[EvalCase], registry: Registry
) -> None:
    case = cases[0]
    result = run_case(case, lambda q, t: [Selection("no_such_function", {})], registry)
    assert not result.passed
    assert "hallucinated" in result.params_error


def test_right_function_wrong_params_fails(
    cases: list[EvalCase], registry: Registry
) -> None:
    """A well-named call with an unusable argument is a rejected call in
    production, i.e. a non-answer — so it must not score as a pass."""
    case = next(c for c in cases if c.id == "redis_ttl_aws")
    result = run_case(
        case,
        lambda q, t: [
            Selection("redis_ttl", {"key": "driver:location:98765", "cloud": "gcp"})
        ],
        registry,
    )
    assert not result.passed
    assert "cloud" in result.params_error


def test_invalid_params_are_caught_by_the_registry_validator(
    cases: list[EvalCase], registry: Registry
) -> None:
    case = next(c for c in cases if c.id == "redis_get_value")
    result = run_case(
        case,
        lambda q, t: [Selection("redis_get", {"key": "config:*", "cloud": "gcp"})],
        registry,
    )
    assert not result.passed


def test_cross_cloud_case_needs_both_calls(
    cases: list[EvalCase], registry: Registry
) -> None:
    """Expected functions are a MULTISET: answering the cross-cloud staleness
    question with one cloud must not score as correct."""
    case = next(c for c in cases if c.id == "redis_cross_cloud_staleness")
    assert len(case.expected_functions) == 2

    one_cloud = run_case(
        case,
        lambda q, t: [
            Selection("redis_exists", {"key": "driver:availability:12345", "cloud": "gcp"})
        ],
        registry,
    )
    assert not one_cloud.passed

    both = run_case(
        case,
        lambda q, t: [
            Selection("redis_exists", {"key": "driver:availability:12345", "cloud": "gcp"}),
            Selection("redis_exists", {"key": "driver:availability:12345", "cloud": "aws"}),
        ],
        registry,
    )
    assert both.exact


def test_extra_call_fails_a_refusal_case(
    cases: list[EvalCase], registry: Registry
) -> None:
    case = next(c for c in cases if c.id == "refuse_driver_360")
    result = run_case(
        case,
        lambda q, t: [Selection("table_info", {"table": "person", "db": "rider_ro"})],
        registry,
    )
    assert not result.passed


def test_selector_only_sees_permitted_tools(
    cases: list[EvalCase], registry: Registry
) -> None:
    """Grants are enforced before selection: the LLM cannot propose what it is
    never shown."""
    case = next(c for c in cases if c.id == "refuse_without_grant")
    seen: list[str] = []

    def spy(question: str, tool_specs: Any) -> list[Selection]:
        seen.extend(spec["name"] for spec in tool_specs)
        return []

    run_case(case, spy, registry)
    assert seen
    assert "table_indexes" not in seen
    assert all(not n.startswith("redis_") for n in seen)


# ===========================================================================
# Selector adapter
# ===========================================================================


def test_from_callable_normalises_dicts(registry: Registry) -> None:
    """The live Grid selector returns dicts from a structured-output call."""
    selector = from_callable(
        lambda q, t: [{"function": "redis_ttl", "params": {"key": "a:b", "cloud": "gcp"}}]
    )
    out = selector("q", [])
    assert out == [Selection("redis_ttl", {"key": "a:b", "cloud": "gcp"})]


def test_from_callable_tolerates_none(registry: Registry) -> None:
    assert from_callable(lambda q, t: None)("q", []) == []


def test_from_callable_drops_malformed_entries(registry: Registry) -> None:
    """Malformed selector output is rejected, not leniently parsed."""
    selector = from_callable(lambda q, t: [{"params": {}}, "garbage", 42])
    assert selector("q", []) == []


def test_tokenize_strips_stopwords() -> None:
    assert "the" not in tokenize("What is the cache hit ratio")
    assert "cache" in tokenize("What is the cache hit ratio")


# ===========================================================================
# The regression gate
# ===========================================================================


def test_committed_baseline_matches_the_current_run(
    cases: list[EvalCase], registry: Registry
) -> None:
    """The committed baseline must reflect reality, or CI is red on arrival."""
    card = run_eval(selector=KeywordSelector(), cases=cases, registry=registry)
    report = compare_to_baseline(card, baseline=load_baseline())
    assert report.ok, report.format()


def test_unchanged_run_does_not_report_a_regression(
    tmp_path: Path, cases: list[EvalCase], registry: Registry
) -> None:
    """Guards the rounding bug: a full-precision score compared against a
    rounded stored one made an unchanged run fail its own baseline."""
    card = run_eval(selector=KeywordSelector(), cases=cases, registry=registry)
    path = tmp_path / "baseline.json"
    write_baseline(card, path)
    again = run_eval(selector=KeywordSelector(), cases=cases, registry=registry)
    assert compare_to_baseline(again, baseline=json.loads(path.read_text())).ok


def test_score_drop_is_a_regression(
    tmp_path: Path, cases: list[EvalCase], registry: Registry
) -> None:
    good = run_eval(selector=KeywordSelector(), cases=cases, registry=registry)
    path = tmp_path / "baseline.json"
    write_baseline(good, path)

    worse = run_eval(selector=refusing_selector, cases=cases, registry=registry)
    report = compare_to_baseline(worse, baseline=json.loads(path.read_text()))
    assert not report.ok
    assert any("dropped" in r for r in report.reasons)


def test_swapping_a_pass_for_a_fail_is_a_regression(cases: list[EvalCase]) -> None:
    """Same aggregate score, different cases passing. The per-case check is what
    catches this; the aggregate alone would call it unchanged."""
    baseline = {
        "summary": {"score": 0.5},
        "cases": {"case_a": True, "case_b": False},
    }
    card = Scorecard(total=2, passed=1)
    card.results = [
        _result("case_a", passed=False),
        _result("case_b", passed=True),
    ]
    report = compare_to_baseline(card, baseline=baseline)
    assert not report.ok
    assert report.newly_failing == ["case_a"]
    assert report.newly_passing == ["case_b"]


def test_disappearing_case_is_a_regression() -> None:
    """A deleted case is a regression you stopped being able to see."""
    baseline = {"summary": {"score": 1.0}, "cases": {"gone": True}}
    card = Scorecard(total=0, passed=0)
    report = compare_to_baseline(card, baseline=baseline)
    assert not report.ok
    assert any("disappeared" in r for r in report.reasons)


def test_missing_baseline_is_not_a_failure() -> None:
    card = Scorecard(total=1, passed=1)
    report = compare_to_baseline(card, baseline={})
    assert report.ok
    assert any("no baseline" in r for r in report.reasons)


def test_improvement_is_not_a_regression() -> None:
    baseline = {"summary": {"score": 0.5}, "cases": {"case_a": False}}
    card = Scorecard(total=1, passed=1)
    card.results = [_result("case_a", passed=True)]
    report = compare_to_baseline(card, baseline=baseline)
    assert report.ok
    assert report.newly_passing == ["case_a"]


def _result(case_id: str, passed: bool) -> Any:
    from app.eval.runner import CaseResult

    return CaseResult(
        case_id=case_id,
        question="q",
        expected=[],
        selected=[] if passed else ["x"],
        is_refusal=True,
        exact=passed,
        params_ok=passed,
    )


# ===========================================================================
# CLI
# ===========================================================================


def test_cli_exits_zero_on_no_regression() -> None:
    from app.eval.__main__ import main

    assert main([]) == 0


def test_cli_exits_nonzero_on_regression() -> None:
    from app.eval.__main__ import main

    assert main(["--selector", "refuse-all"]) == 1


def test_cli_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    from app.eval.__main__ import main

    main(["--json"])
    payload = json.loads(capsys.readouterr().out)
    assert "summary" in payload
    assert payload["summary"]["total"] >= 30


def test_cli_tag_filter(capsys: pytest.CaptureFixture[str]) -> None:
    from app.eval.__main__ import main

    assert main(["--tag", "redis"]) == 0
    assert "scorecard" in capsys.readouterr().out


def test_scorecard_formats(cases: list[EvalCase], registry: Registry) -> None:
    card = run_eval(selector=KeywordSelector(), cases=cases, registry=registry)
    text = format_scorecard(card)
    assert "overall" in text
    assert "refusals" in text
    assert "by tag" in text
