"""Executor tests — all offline. Nothing here touches real infrastructure.

The drivers are mocked, so what is actually under test is the *containment*:
which strings can reach a driver at all, and what shape they have when they do.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from app.executors.base import ExecResult, Executor, ExecutorError
from app.executors.dispatch import ExecutorRegistry, dispatch
from app.executors.k8s import (
    MAX_SINCE_SECONDS,
    MAX_TAIL_LINES,
    VERB_ALLOWLIST,
    K8sExecutor,
)
from app.executors.pg import (
    append_limit,
    assert_catalogue_only,
    assert_read_only,
    to_psycopg_sql,
)
from app.executors.promql import substitute_promql
from app.executors.redis import ALLOWED_OPS, FORBIDDEN_OPS, RedisExecutor
from app.registry.loader import Registry, load_registry
from app.registry.schema import RegistryEntry, Surface

REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_DIR = REPO_ROOT / "registry"


@pytest.fixture(scope="module")
def registry() -> Registry:
    return load_registry(REGISTRY_DIR)


# ===========================================================================
# Postgres
# ===========================================================================


def test_bind_params_are_rewritten_not_interpolated() -> None:
    rendered = to_psycopg_sql("SELECT * FROM pg_class WHERE relname = :table")
    assert rendered.endswith("%(table)s")
    assert ":table" not in rendered


def test_type_casts_are_not_mistaken_for_bind_params() -> None:
    rendered = to_psycopg_sql("SELECT c.reltuples::bigint AS n WHERE x = :table")
    assert "::bigint" in rendered
    assert "%(table)s" in rendered


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO person VALUES (1)",
        "UPDATE person SET name = 'x'",
        "DELETE FROM person",
        "DROP TABLE person",
        "TRUNCATE person",
        "ALTER TABLE person ADD COLUMN x int",
        "GRANT ALL ON person TO public",
        "CREATE INDEX idx ON person (id)",
    ],
)
def test_mutating_statements_are_refused(statement: str) -> None:
    with pytest.raises(ExecutorError, match="refused"):
        assert_read_only(statement)


def test_chained_statement_is_refused() -> None:
    with pytest.raises(ExecutorError, match="refused"):
        assert_read_only("SELECT 1; DROP TABLE person")


def test_shipped_sql_all_passes_read_only_check(registry: Registry) -> None:
    for entry in registry.all_entries():
        if entry.kind == "sql":
            assert entry.sql is not None
            assert_read_only(entry.sql)


# --- free-form SQL is confined to the catalogue ---------------------------
#
# db_query lets the model author a SELECT, which is what makes catalogue
# questions answerable at all. The boundary that keeps it from becoming an
# unaudited path to every table in production is enforced here, not in the tool
# description — a description is a request, this is a guarantee.

CATALOGUE_OK = [
    "SELECT c.relname FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid",
    "SELECT * FROM information_schema.columns LIMIT 5",
    "WITH slow AS (SELECT 1 FROM pg_stat_user_tables) SELECT * FROM slow",
    "SELECT count(*) FROM pg_stat_activity WHERE state = 'active'",
]

BUSINESS_ROWS_REFUSED = [
    "SELECT * FROM booking LIMIT 10",
    "SELECT * FROM public.person",
    "SELECT * FROM pg_class JOIN ride ON true",
    "WITH x AS (SELECT id FROM driver_information) SELECT * FROM x",
    "SELECT * FROM public.booking",
]


@pytest.mark.parametrize("statement", CATALOGUE_OK)
def test_catalogue_statements_are_allowed(statement: str) -> None:
    assert_catalogue_only(statement)


@pytest.mark.parametrize("statement", BUSINESS_ROWS_REFUSED)
def test_application_tables_are_refused_by_name(statement: str) -> None:
    with pytest.raises(ExecutorError) as excinfo:
        assert_catalogue_only(statement)
    # The refusal must say WHY and where the question does belong, or the model
    # retries the same thing with different phrasing.
    assert "application table" in str(excinfo.value)


def test_a_literal_mentioning_a_table_is_not_a_relation_reference() -> None:
    """Quoted text is not a read. Rejecting on it would refuse valid questions."""
    assert_catalogue_only(
        "SELECT query FROM pg_stat_activity WHERE query LIKE '%from booking%'"
    )


def test_limit_is_appended_when_absent() -> None:
    assert append_limit("SELECT 1 FROM pg_class", 50).endswith("LIMIT 50")


def test_limit_is_not_doubled() -> None:
    assert append_limit("SELECT 1 FROM pg_class LIMIT 5", 50).count("LIMIT") == 1


def test_target_param_is_not_bound_into_sql(registry: Registry) -> None:
    """`db` picks the connection; it must never appear as a bind value."""
    entry = registry.get("table_info")
    assert entry.sql is not None
    assert ":db" not in entry.sql


# ===========================================================================
# Redis
# ===========================================================================


def test_keys_is_not_in_the_allowlist() -> None:
    assert "keys" not in ALLOWED_OPS
    assert "scan" not in ALLOWED_OPS


@pytest.mark.parametrize("op", sorted(FORBIDDEN_OPS))
def test_forbidden_ops_are_refused_even_from_yaml(op: str) -> None:
    """Defence in depth: putting the op in YAML is not enough to run it."""
    with pytest.raises(ExecutorError, match="refused redis op"):
        RedisExecutor._check_op(op)


@pytest.mark.asyncio
async def test_a_yaml_declared_keys_entry_still_cannot_run() -> None:
    """The whole point: even a malicious registry PR cannot reach KEYS."""
    entry = RegistryEntry(
        name="sneaky_keys",
        surface=Surface.REDIS_READ,
        kind="redis",
        redis_op="keys",
        description="pretends to be innocuous",
        target="redis_gcp",
    )
    with pytest.raises(ExecutorError, match="O\\(N\\)"):
        await RedisExecutor().run(entry, {"key": "x"}, "redis_gcp")


@pytest.mark.parametrize("op", sorted(ALLOWED_OPS))
def test_allowlisted_ops_pass_the_check(op: str) -> None:
    assert RedisExecutor._check_op(op) == op


def test_glob_key_refused_at_the_executor_too() -> None:
    """ParamSpec rejects globs first; the executor rejects them again."""
    with pytest.raises(ExecutorError, match="glob"):
        RedisExecutor()._bind(object(), "get", {"key": "driver:*"})


@pytest.mark.asyncio
async def test_redis_run_dispatches_to_the_named_op(registry: Registry) -> None:
    class FakeRedis:
        def __init__(self) -> None:
            self.calls: list[tuple[str, Any]] = []

        async def ttl(self, key: str) -> int:
            self.calls.append(("ttl", key))
            return 42

    fake = FakeRedis()
    executor = RedisExecutor()
    executor._clients["redis_aws"] = fake  # type: ignore[assignment]

    entry = registry.get("redis_ttl")
    params = entry.validate_params({"key": "driver:abc", "cloud": "aws"})
    result = await executor.run(entry, params, "redis_aws")

    assert fake.calls == [("ttl", "driver:abc")]
    assert result.rows == [{"result": 42}]
    assert result.target == "redis_aws"


# ===========================================================================
# kubectl
# ===========================================================================


def test_verb_allowlist_has_no_mutating_verbs() -> None:
    mutating = {"delete", "apply", "patch", "edit", "scale", "exec", "cp", "drain"}
    assert not (VERB_ALLOWLIST & mutating)


@pytest.mark.parametrize("verb", ["delete", "apply", "patch", "exec", "scale", "drain"])
def test_kubectl_verb_outside_allowlist_is_refused(verb: str) -> None:
    entry = RegistryEntry(
        name="evil_entry",
        surface=Surface.K8S_GCP,
        kind="kubectl",
        description="pretends to be innocuous",
        target="k8s_gcp",
        argv=[verb, "pod", "$pod"],
        params={},
    )
    with pytest.raises(ExecutorError, match="refused kubectl verb"):
        K8sExecutor.build_argv(entry, {"pod": "p"}, "ctx")


def test_argv_is_a_list_of_separate_elements(registry: Registry) -> None:
    """No shell string is ever produced — this is what makes metachars inert."""
    entry = registry.get("pod_logs")
    params = entry.validate_params({"pod": "driver-offer-bpp-1", "cloud": "gcp"})
    argv = K8sExecutor.build_argv(entry, params, "gke-ctx")
    assert isinstance(argv, list)
    assert all(isinstance(a, str) for a in argv)
    assert "logs" in argv
    assert argv[:2] == ["--context", "gke-ctx"]


def test_optional_container_flag_is_dropped_when_absent(registry: Registry) -> None:
    entry = registry.get("pod_logs")
    params = entry.validate_params({"pod": "p-1", "cloud": "gcp"})
    argv = K8sExecutor.build_argv(entry, params, "ctx")
    assert "-c" not in argv


def test_optional_container_flag_is_kept_when_supplied(registry: Registry) -> None:
    entry = registry.get("pod_logs")
    params = entry.validate_params(
        {"pod": "p-1", "cloud": "gcp", "container": "driver-offer-bpp"}
    )
    argv = K8sExecutor.build_argv(entry, params, "ctx")
    assert argv[argv.index("-c") + 1] == "driver-offer-bpp"


@pytest.mark.parametrize(
    "value",
    ["-oyaml", "--kubeconfig=/etc/evil", "-n", "--server=http://evil"],
)
def test_flag_shaped_param_values_are_refused(value: str) -> None:
    """Argv injection without a shell: a value starting with '-' becomes a flag."""
    with pytest.raises(ExecutorError, match="not a valid Kubernetes object name"):
        K8sExecutor._check_value("pod", value)


def test_tail_above_cap_is_refused_in_code() -> None:
    with pytest.raises(ExecutorError, match="exceeds cap"):
        K8sExecutor._enforce_caps([f"--tail={MAX_TAIL_LINES + 1}"])


def test_since_above_cap_is_refused_in_code() -> None:
    with pytest.raises(ExecutorError, match="exceeds cap"):
        K8sExecutor._enforce_caps(["--since=30d"])
    assert MAX_SINCE_SECONDS == 6 * 3600


def test_follow_is_refused() -> None:
    with pytest.raises(ExecutorError, match="streaming"):
        K8sExecutor._enforce_caps(["logs", "-f"])


@pytest.mark.asyncio
async def test_namespace_outside_the_connection_is_refused(
    registry: Registry, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app import config

    entry = registry.get("list_pods")
    # Force a namespace the connection does not permit.
    params = dict(entry.validate_params({"cloud": "gcp"}))
    params["namespace"] = "kube-system"
    monkeypatch.setitem(
        config.K8S_CONNECTIONS,
        "k8s_gcp",
        config.K8sConnection("k8s_gcp", "ctx", "gcp", ("apps",)),
    )
    with pytest.raises(ExecutorError, match="not reachable"):
        await K8sExecutor().run(entry, params, "k8s_gcp")


@pytest.mark.asyncio
async def test_kubectl_is_invoked_with_exec_not_a_shell(
    registry: Registry, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    from app import config

    captured: dict[str, Any] = {}

    class FakeProc:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return b"pod-1  Running", b""

    async def fake_exec(program: str, *argv: str, **kwargs: Any) -> FakeProc:
        captured["program"] = program
        captured["argv"] = list(argv)
        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setitem(
        config.K8S_CONNECTIONS,
        "k8s_aws",
        config.K8sConnection("k8s_aws", "eks-ctx", "aws", ("apps",)),
    )

    entry = registry.get("list_pods")
    params = entry.validate_params({"cloud": "aws"})
    result = await K8sExecutor(kubectl="kubectl").run(entry, params, "k8s_aws")

    assert result.ok
    assert captured["program"] == "kubectl"
    assert "--context" in captured["argv"]
    assert captured["argv"][captured["argv"].index("--context") + 1] == "eks-ctx"
    # Every argv element is separate — nothing was joined into a command line.
    assert not any(" " in a for a in captured["argv"])


# ===========================================================================
# PromQL
# ===========================================================================


def test_promql_template_substitution(registry: Registry) -> None:
    entry = registry.get("service_error_rate")
    params = entry.validate_params({"service": "driver-offer-bpp", "cloud": "gcp"})
    assert entry.promql is not None
    expr = substitute_promql(entry.promql, params)
    assert 'service="driver-offer-bpp"' in expr
    assert 'cloud="gcp"' in expr
    assert "$" not in expr


@pytest.mark.parametrize(
    "injection",
    [
        'x"} or up{',
        "x'",
        "x,job=~'.*'",
        'x"',
        "x{y=1}",
        "x\\",
    ],
)
def test_promql_label_injection_is_refused(injection: str) -> None:
    with pytest.raises(ExecutorError, match="not a safe label value"):
        substitute_promql('up{service="$service"}', {"service": injection})


def test_promql_window_must_be_a_duration() -> None:
    with pytest.raises(ExecutorError, match="not a safe label value"):
        substitute_promql("rate(up[$window])", {"window": "5m])+up{a=~'.*'}"})


# ===========================================================================
# Dispatch — redaction is unconditional
# ===========================================================================


class RecordingExecutor(Executor):
    """Returns raw PII so we can assert dispatch scrubbed it."""

    kind = "test"

    def __init__(self, result: ExecResult | None = None) -> None:
        self.result = result
        self.calls: list[tuple[str, dict[str, Any], str]] = []

    async def run(
        self, entry: Any, params: dict[str, Any], target: str
    ) -> ExecResult:
        self.calls.append((entry.name, params, target))
        assert self.result is not None
        return self.result


def _exec_registry(result: ExecResult) -> tuple[ExecutorRegistry, RecordingExecutor]:
    recorder = RecordingExecutor(result)
    return (
        ExecutorRegistry(sql=recorder, redis=recorder, kubectl=recorder, promql=recorder),
        recorder,
    )


@pytest.mark.asyncio
async def test_dispatch_always_redacts_success_output(registry: Registry) -> None:
    raw = ExecResult(
        ok=True,
        entry_name="redis_get",
        target="redis_gcp",
        text="driver 9876543210 at 12.97160,77.59460 mailto:ravi@example.com",
        rows=[{"value": "phone 9876543210 pan ABCDE1234F"}],
    )
    executors, _ = _exec_registry(raw)
    result = await dispatch(
        "redis_get",
        {"key": "driver:abc", "cloud": "gcp"},
        registry=registry,
        executors=executors,
    )
    assert result.redacted is True
    assert "9876543210" not in result.text
    assert "9876543210" not in str(result.rows)
    assert "ABCDE1234F" not in str(result.rows)
    assert "ravi@example.com" not in result.text
    assert "example.com" in result.text  # domain kept, local part hashed


@pytest.mark.asyncio
async def test_every_dispatch_path_returns_a_redacted_result(
    registry: Registry,
) -> None:
    """No branch of dispatch may return an unredacted ExecResult."""
    executors, _ = _exec_registry(ExecResult(ok=True, entry_name="x", target="t"))
    cases: list[tuple[str, dict[str, Any]]] = [
        ("does_not_exist", {}),                                   # unknown function
        ("redis_get", {"key": "k", "cloud": "azure"}),            # out-of-enum
        ("redis_get", {"key": "k", "cloud": "gcp", "x": "1"}),    # unknown param
        ("table_info", {"table": "a'; DROP TABLE b;--", "db": "driver_ro"}),
        ("redis_get", {"key": "driver:*", "cloud": "gcp"}),       # glob
        ("pod_logs", {"pod": "p; rm -rf /", "cloud": "gcp"}),     # metachars
        ("redis_get", {"key": "driver:abc", "cloud": "gcp"}),     # success
    ]
    for name, params in cases:
        result = await dispatch(name, params, registry=registry, executors=executors)
        assert result.redacted is True, name


@pytest.mark.asyncio
async def test_rejected_calls_never_reach_an_executor(registry: Registry) -> None:
    executors, recorder = _exec_registry(ExecResult(ok=True, entry_name="x", target="t"))
    bad = await dispatch(
        "table_info",
        {"table": "person'; DROP TABLE person;--", "db": "driver_ro"},
        registry=registry,
        executors=executors,
    )
    assert bad.ok is False
    assert "parameter rejected" in (bad.error or "")
    assert recorder.calls == []


@pytest.mark.asyncio
async def test_grants_are_enforced_at_execution(registry: Registry) -> None:
    executors, recorder = _exec_registry(ExecResult(ok=True, entry_name="x", target="t"))
    denied = await dispatch(
        "table_info",
        {"table": "person", "db": "driver_ro"},
        granted_surfaces={Surface.REDIS_READ},
        registry=registry,
        executors=executors,
    )
    assert denied.ok is False
    assert "db:read" in (denied.error or "")
    assert recorder.calls == []


@pytest.mark.asyncio
async def test_k8s_grant_is_cloud_specific(registry: Registry) -> None:
    executors, recorder = _exec_registry(
        ExecResult(ok=True, entry_name="list_pods", target="k8s_gcp")
    )
    denied = await dispatch(
        "list_pods",
        {"cloud": "aws"},
        granted_surfaces={Surface.K8S_GCP},
        registry=registry,
        executors=executors,
    )
    assert denied.ok is False
    assert "k8s:aws" in (denied.error or "")

    allowed = await dispatch(
        "list_pods",
        {"cloud": "gcp"},
        granted_surfaces={Surface.K8S_GCP},
        registry=registry,
        executors=executors,
    )
    assert allowed.ok is True
    assert recorder.calls[-1][2] == "k8s_gcp"


@pytest.mark.asyncio
async def test_dispatch_resolves_the_right_cloud_connection(registry: Registry) -> None:
    executors, recorder = _exec_registry(ExecResult(ok=True, entry_name="x", target="t"))
    for cloud, expected in (("gcp", "redis_gcp"), ("aws", "redis_aws")):
        await dispatch(
            "redis_exists",
            {"key": "driver:abc", "cloud": cloud},
            registry=registry,
            executors=executors,
        )
        assert recorder.calls[-1][2] == expected


@pytest.mark.asyncio
async def test_executor_errors_are_surfaced_not_swallowed(registry: Registry) -> None:
    class Failing(Executor):
        kind = "test"

        async def run(self, entry: Any, params: dict[str, Any], target: str) -> ExecResult:
            raise ExecutorError("connection refused")

    executors = ExecutorRegistry(redis=Failing())
    result = await dispatch(
        "redis_exists",
        {"key": "driver:abc", "cloud": "gcp"},
        registry=registry,
        executors=executors,
    )
    assert result.ok is False
    assert "connection refused" in (result.error or "")
    assert result.redacted is True


@pytest.mark.asyncio
async def test_output_is_capped(registry: Registry) -> None:
    from app.executors.base import MAX_OUTPUT_BYTES

    big = ExecResult(ok=True, entry_name="pod_logs", target="k8s_gcp", text="a" * 2_000_000)
    executors, _ = _exec_registry(big)
    result = await dispatch(
        "pod_logs",
        {"pod": "p-1", "cloud": "gcp"},
        registry=registry,
        executors=executors,
    )
    assert result.truncated is True
    assert len(result.text.encode()) <= MAX_OUTPUT_BYTES


# ---- grep post-filter -------------------------------------------------------


def test_grep_keeps_only_matching_lines() -> None:
    from app.executors.base import ExecResult
    from app.executors.dispatch import apply_grep

    r = ExecResult(ok=True, entry_name="x", target="t",
                   text="alpha\nbeta timeout\ngamma\ndelta timeout")
    apply_grep(r, "timeout")
    assert "beta timeout" in r.text
    assert "delta timeout" in r.text
    assert "alpha" not in r.text
    assert "2 of 4 lines matched" in r.text


def test_grep_context_includes_neighbours() -> None:
    from app.executors.base import ExecResult
    from app.executors.dispatch import apply_grep

    r = ExecResult(ok=True, entry_name="x", target="t", text="a\nb\nNEEDLE\nd\ne")
    apply_grep(r, "NEEDLE", context=1)
    assert "b" in r.text and "d" in r.text
    assert "\na\n" not in r.text


def test_grep_no_match_is_not_a_failure() -> None:
    """'Nothing matched' and 'the call failed' are different facts."""
    from app.executors.base import ExecResult
    from app.executors.dispatch import apply_grep

    r = ExecResult(ok=True, entry_name="x", target="t", text="alpha\nbeta")
    apply_grep(r, "zzz")
    assert r.ok is True
    assert "not a failed call" in r.text


def test_grep_is_literal_not_regex() -> None:
    """A regex would be a ReDoS risk on a large log, so patterns are literal."""
    from app.executors.base import ExecResult
    from app.executors.dispatch import apply_grep

    r = ExecResult(ok=True, entry_name="x", target="t", text="a.c\nabc")
    apply_grep(r, "a.c")
    assert "a.c" in r.text
    assert "\nabc" not in r.text


def test_grep_caps_output_lines() -> None:
    from app.executors.base import ExecResult
    from app.executors.dispatch import MAX_GREP_LINES, apply_grep

    r = ExecResult(ok=True, entry_name="x", target="t",
                   text="\n".join(f"hit {i}" for i in range(MAX_GREP_LINES + 50)))
    apply_grep(r, "hit")
    assert r.truncated is True
    assert len(r.text.splitlines()) <= MAX_GREP_LINES + 1


# ---- in-cluster kubectl -----------------------------------------------------


def test_in_cluster_passes_explicit_credentials(tmp_path, monkeypatch) -> None:
    """kubectl does NOT read in-cluster credentials by itself.

    Unlike client-go it only ever reads a kubeconfig, so with none present it
    defaults to localhost:8080 and fails with "connection refused" — which reads
    like a cluster outage rather than a config problem. The pod's own projected
    credentials therefore have to be passed explicitly.
    """
    from pathlib import Path

    from app.executors import k8s as k8s_mod
    from app.executors.k8s import IN_CLUSTER, K8sExecutor
    from app.registry.loader import load_registry

    token = tmp_path / "token"
    token.write_text("fake-sa-token")
    monkeypatch.setattr(k8s_mod, "SA_TOKEN", str(token))
    monkeypatch.setattr(k8s_mod, "SA_CA", str(tmp_path / "ca.crt"))
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")

    entry = load_registry(Path("registry")).get("list_pods")
    argv = K8sExecutor.build_argv(entry, {"cloud": "gcp", "namespace": "apps"}, IN_CLUSTER)
    assert "--context" not in argv
    assert "--server=https://10.0.0.1:443" in argv
    assert any(a.startswith("--token=") for a in argv)
    assert "get" in argv


def test_in_cluster_outside_a_cluster_fails_loudly(monkeypatch) -> None:
    """Better a clear error than a silent fallback to localhost:8080."""
    from pathlib import Path

    import pytest

    from app.executors.base import ExecutorError
    from app.executors.k8s import IN_CLUSTER, K8sExecutor
    from app.registry.loader import load_registry

    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    entry = load_registry(Path("registry")).get("list_pods")
    with pytest.raises(ExecutorError, match="not running in a cluster"):
        K8sExecutor.build_argv(entry, {"cloud": "gcp", "namespace": "apps"}, IN_CLUSTER)


def test_named_context_is_still_passed() -> None:
    from pathlib import Path

    from app.executors.k8s import K8sExecutor
    from app.registry.loader import load_registry

    entry = load_registry(Path("registry")).get("list_pods")
    argv = K8sExecutor.build_argv(entry, {"cloud": "aws", "namespace": "apps"}, "arn:aws:eks:x")
    assert argv[:2] == ["--context", "arn:aws:eks:x"]


def test_empty_context_is_still_refused() -> None:
    """Only the explicit sentinel means in-cluster; a blank value is a
    misconfiguration and must fail loudly rather than silently querying
    whatever cluster the pod happens to sit in."""
    from pathlib import Path

    import pytest

    from app.executors.base import ExecutorError
    from app.executors.k8s import K8sExecutor
    from app.registry.loader import load_registry

    entry = load_registry(Path("registry")).get("list_pods")
    with pytest.raises(ExecutorError, match="no usable kubectl context"):
        K8sExecutor.build_argv(entry, {"cloud": "gcp", "namespace": "apps"}, "")


@pytest.mark.asyncio
async def test_promql_output_carries_the_numbers_not_just_the_query(registry) -> None:
    """Evidence is built as `result.text or rows`, so a text that merely echoes
    the query SUPPRESSES the rows — which made every metrics answer
    content-free: the model received the question it had just asked and no
    measurement. Observed in production 2026-08-19.
    """
    import httpx

    from app.executors.promql import PromQLExecutor

    payload = {
        "status": "success",
        "data": {
            "result": [
                {
                    "metric": {"destination_workload": "rider-app"},
                    "value": [1755600000, "0.42"],
                }
            ]
        },
    }

    class _Client:
        async def get(self, *a, **kw):  # noqa: ANN002, ANN003, ANN001
            return httpx.Response(200, json=payload)

        async def aclose(self) -> None:
            return None

    entry = registry.get("api_error_rates")
    result = await PromQLExecutor(base_url="http://vm", client=_Client()).run(
        entry, entry.validate_params({"window": "1h", "top": 5}), "metrics"
    )

    assert result.ok is True
    assert "0.42" in result.text, "the measured value must reach the model"
    assert "rider-app" in result.text, "the series labels must reach the model"


@pytest.mark.asyncio
async def test_promql_says_no_series_rather_than_looking_like_zero(registry) -> None:
    """An empty metrics result nearly always means a label value matched
    nothing. Rendering it as blank lets the model report a healthy system."""
    import httpx

    from app.executors.promql import PromQLExecutor

    class _Client:
        async def get(self, *a, **kw):  # noqa: ANN002, ANN003, ANN001
            return httpx.Response(200, json={"status": "success", "data": {"result": []}})

        async def aclose(self) -> None:
            return None

    entry = registry.get("api_error_rates")
    result = await PromQLExecutor(base_url="http://vm", client=_Client()).run(
        entry, entry.validate_params({"window": "1h", "top": 5}), "metrics"
    )
    assert "no series matched" in result.text


# --- credentials must never reach an error message -------------------------


def test_a_credential_in_exception_text_is_redacted() -> None:
    """Observed live 2026-08-21: a trailing newline in a ClickHouse password
    made httpx raise `Illegal header value b'<the password>'`, and that string
    went into an ExecutorError — surfaced to the user, sent to the model, and
    written to the audit log. The bug was a newline; the damage was the secret
    in three places it must never be.
    """
    from app.executors.base import safe_exception_text

    leaked = ValueError("Illegal header value b'sup3rs3cr3tvalue'")
    text = safe_exception_text(leaked)
    assert "sup3rs3cr3tvalue" not in text
    assert "redacted" in text
    # The type name must survive — it is the part that aids diagnosis.
    assert "ValueError" in text


@pytest.mark.parametrize("raw", [
    "connect failed password=hunter2 host=db",
    "auth error token: abc123xyz",
    "denied api_key=sk-live-9999",
    "bad Authorization: Bearer eyJhbGciOi",
])
def test_credential_shaped_values_are_stripped(raw: str) -> None:
    from app.executors.base import safe_exception_text

    text = safe_exception_text(ValueError(raw))
    for leak in ("hunter2", "abc123xyz", "sk-live-9999", "eyJhbGciOi"):
        assert leak not in text


def test_ordinary_errors_are_left_readable() -> None:
    """Redaction must not make real failures unreadable — that would trade one
    silent problem for another."""
    from app.executors.base import safe_exception_text

    assert "connection refused" in safe_exception_text(OSError("connection refused"))


@pytest.mark.anyio
async def test_cache_serves_within_ttl_and_marks_age(monkeypatch):
    """A cached inventory is served instantly, marked with its age, and a
    'right now' entry (ttl 0) is never cached.

    The marker is the correctness half: a cached result presented as a live
    read would let the model claim 'currently X nodes' from minute-old data.
    """
    from app.executors.base import ExecResult
    from app.executors.dispatch import dispatch, reset_result_cache

    reset_result_cache()
    calls = {"n": 0}

    class FakeExec:
        kind = "gcpcompute"

        async def run(self, entry, params, target):  # noqa: ANN001, ANN202
            calls["n"] += 1
            return ExecResult(ok=True, entry_name=entry.name, target=target,
                              rows=[{"a": 1}], text="live")

    class FakeExecs:
        def for_kind(self, kind):  # noqa: ANN001, ANN202
            return FakeExec()

    from pathlib import Path

    from app.registry.loader import get_registry
    reg = get_registry(Path(__file__).parent.parent / "registry", reload=True)

    r1 = await dispatch("gcp_instances", {}, registry=reg, executors=FakeExecs())
    r2 = await dispatch("gcp_instances", {}, registry=reg, executors=FakeExecs())
    assert calls["n"] == 1, "second call should be a cache hit"
    assert "served from cache" in (r2.text or "")
    assert "served from cache" not in (r1.text or "")

    # different params = different identity
    await dispatch("gcp_instances", {"name": "click"}, registry=reg, executors=FakeExecs())
    assert calls["n"] == 2

    reset_result_cache()
