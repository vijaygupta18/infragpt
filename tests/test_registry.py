"""Registry tests.

The load-bearing assertion in this file is that an invalid registry raises
instead of loading a subset. A registry that silently drops a bad entry is worse
than one that refuses to start: the missing function is discovered at 3am.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.registry.loader import (
    Registry,
    RegistryError,
    load_registry,
    required_surface,
    resolve_target,
)
from app.registry.schema import ParamValidationError, RegistryEntry, Surface

REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_DIR = REPO_ROOT / "registry"


@pytest.fixture(scope="module")
def registry() -> Registry:
    return load_registry(REGISTRY_DIR)


# ---------------------------------------------------------------------------
# The shipped registry
# ---------------------------------------------------------------------------


def test_shipped_registry_loads(registry: Registry) -> None:
    assert len(registry) >= 70


def test_expected_functions_present(registry: Registry) -> None:
    expected = {
        # db
        "table_info", "table_indexes", "index_usage", "unused_indexes",
        # NB: no top_queries — pg_stat_statements is not installed in prod, so the
        # entry was removed rather than shipped as a guaranteed runtime failure.
        "table_size", "row_estimate", "active_connections",
        "long_running_queries", "locks", "replication_lag", "cache_hit_ratio",
        "seq_scan_heavy_tables", "db_size",
        # redis
        "redis_exists", "redis_ttl", "redis_get", "redis_smembers", "redis_type",
        "redis_hgetall", "redis_scard", "redis_llen", "redis_memory_usage",
        # NB: no redis_info — this surface is key-level reads only. Server-level
        # Redis health lives on the metrics surface.
        # k8s
        "pod_logs", "pod_status", "list_pods", "recent_events", "describe_pod",
        "node_top", "deployment_status",
        # metrics
        "service_error_rate", "service_latency_p99", "pod_restarts",
        "cpu_saturation", "memory_saturation", "db_connection_count",
        # istio — added after the gateway-VirtualService outage, where subset
        # pinning broke traffic with every pod-level check looking healthy.
        "istio_virtualservices", "istio_destinationrules",
        "describe_virtualservice",
        # k8s capacity / inventory
        "top_pods", "list_pdb", "list_services", "list_statefulsets",
        "list_daemonsets", "list_cronjobs", "list_hpa", "list_pvc",
        "list_nodes", "describe_node", "describe_deployment",
        "list_namespaces",
        # db metadata
        "pg_settings_key", "installed_extensions", "oldest_transaction_age",
        "vacuum_progress", "table_bloat_estimate",
        # cloud
        "alloydb_disk_usage", "elasticache_network_bytes_in",
        "elasticache_network_bytes_out", "elasticache_cache_hits",
        "elasticache_cache_misses", "elasticache_swap_usage",
    }
    assert expected <= set(registry.names())


def test_no_keys_command_is_expressible(registry: Registry) -> None:
    """KEYS must not exist in the registry, under any entry name."""
    for entry in registry.all_entries():
        if entry.kind == "redis":
            assert entry.redis_op not in {"keys", "scan", "randomkey"}


def test_db_read_surface_reads_no_business_tables(registry: Registry) -> None:
    """db:read answers questions about the DATABASE, never about a person.

    Scoped to db:read on purpose. db:entity exists precisely to read business
    rows, under the much tighter constraints asserted below — the split is only
    meaningful if this side of it stays metadata-only.
    """
    allowed_sources = (
        "pg_catalog", "information_schema", "pg_stat", "pg_statio", "pg_class",
        "pg_index", "pg_indexes", "pg_namespace", "pg_database", "pg_locks",
    )
    for entry in registry.all_entries():
        if entry.kind != "sql" or entry.surface is not Surface.DB_READ:
            continue
        assert entry.sql is not None
        assert any(src in entry.sql for src in allowed_sources), entry.name


def test_every_db_entry_is_bounded(registry: Registry) -> None:
    for entry in registry.all_entries():
        if entry.kind == "sql" and entry.surface is Surface.DB_READ:
            assert entry.row_limit > 0
            assert 0 < entry.timeout_s <= 20, entry.name
            # driver_noncrit included: heavy reads must have somewhere to go
            # that is not the reader drivers depend on to go online.
            assert set(entry.params["db"].values or []) == {
                "driver_noncrit",
                "driver_ro",
                "rider_ro",
            }


def test_entity_lookups_are_confined_to_one_subject(registry: Registry) -> None:
    """A per-subject lookup that can return a population is an export.

    This is the whole containment story for db:entity: the statements read real
    people's records, so what keeps them from being a bulk extract is that each
    one filters to a single identified subject and returns few rows.
    """
    subject_params = {"driver_id", "phone_hash", "rider_id"}
    for entry in registry.all_entries():
        if entry.surface is not Surface.DB_ENTITY:
            continue
        assert entry.sql is not None
        # Filtered to a subject the caller had to already know...
        used = subject_params & set(entry.params)
        assert used, f"{entry.name}: no subject param"
        for param in used:
            assert f":{param}" in entry.sql, f"{entry.name}: {param} not bound in WHERE"
        # ...and small enough that it cannot be walked into a listing.
        assert entry.row_limit <= 50, entry.name
        assert 0 < entry.timeout_s <= 20, entry.name
        # PII-bearing by definition — the tag is what the audit log and the UI
        # key off, so an untagged entry would be handled as ordinary output.
        assert "pii" in entry.tags, entry.name


def test_free_form_sql_is_never_allowed_over_business_rows(registry: Registry) -> None:
    """sqlfree must stay on db:read, where the catalogue guard applies.

    A sqlfree entry on db:entity would hand the model arbitrary SELECTs over
    application tables, which is exactly what splitting the surfaces prevents.
    """
    for entry in registry.all_entries():
        if entry.kind == "sqlfree":
            assert entry.surface is Surface.DB_READ, entry.name


def test_no_sql_uses_string_interpolation(registry: Registry) -> None:
    for entry in registry.all_entries():
        if entry.kind == "sql":
            assert entry.sql is not None
            assert "$" not in entry.sql
            assert "{" not in entry.sql


def test_kubectl_entries_are_argv_lists(registry: Registry) -> None:
    for entry in registry.all_entries():
        if entry.kind == "kubectl":
            assert isinstance(entry.argv, list)
            assert all(isinstance(a, str) for a in entry.argv)
            assert entry.argv[0] in {
                "get", "list", "describe", "logs", "top", "events", "version"
            }


def test_pod_logs_caps_tail_and_since(registry: Registry) -> None:
    entry = registry.get("pod_logs")
    assert entry.argv is not None
    assert any(a.startswith("--tail=") for a in entry.argv)
    assert any(a.startswith("--since=") for a in entry.argv)
    assert entry.params["tail"].max == 1000
    # `since` is an enum, so an unbounded lookback is not even representable.
    assert entry.params["since"].values == ["5m", "15m", "30m", "1h", "3h", "6h"]


def test_every_cloud_scoped_entry_defaults_to_gcp(registry: Registry) -> None:
    """GCP-first, consistently — a default that applies to some entries and not
    others is worse than none, because the behaviour becomes unpredictable.

    AWS stays selectable everywhere it was before; it is simply never the
    assumption. Superseded the previous rule that a cloud must always be stated
    explicitly, which made sense while the two clouds were equals.
    """
    for entry in registry.all_entries():
        if entry.kind in ("redis", "kubectl"):
            spec = entry.params["cloud"]
            assert spec.default == "gcp", entry.name
            assert spec.required is False, entry.name
            assert set(spec.values or []) == {"gcp", "aws"}, entry.name


# ---------------------------------------------------------------------------
# Grants / surfaces
# ---------------------------------------------------------------------------


def test_entries_for_surfaces_filters(registry: Registry) -> None:
    db_only = registry.entries_for_surfaces({Surface.DB_READ})
    names = {e.name for e in db_only}
    assert "table_info" in names
    assert "redis_get" not in names
    assert "pod_logs" not in names


def test_no_surfaces_offers_nothing(registry: Registry) -> None:
    assert registry.entries_for_surfaces(set()) == []


def test_admin_is_not_a_wildcard(registry: Registry) -> None:
    assert registry.entries_for_surfaces({Surface.ADMIN}) == []


def test_kubectl_required_surface_follows_cloud(registry: Registry) -> None:
    entry = registry.get("pod_logs")
    assert required_surface(entry, {"cloud": "gcp"}) is Surface.K8S_GCP
    assert required_surface(entry, {"cloud": "aws"}) is Surface.K8S_AWS


def test_llm_tool_specs_only_show_permitted(registry: Registry) -> None:
    specs = registry.llm_tool_specs({Surface.REDIS_READ})
    assert specs
    assert all(s["name"].startswith("redis_") for s in specs)
    spec = next(s for s in specs if s["name"] == "redis_get")
    assert spec["parameters"]["properties"]["cloud"]["enum"] == ["gcp", "aws"]
    # `cloud` is NOT required any more: it defaults to gcp. The platform is
    # migrating to GCP, so asking the user which cloud they meant — or checking
    # both "to be safe" — is friction on every single question. AWS is queried
    # only when a question names it.
    assert "cloud" not in spec["parameters"]["required"]


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------


def test_target_resolution(registry: Registry) -> None:
    assert resolve_target(registry.get("table_info"), {"db": "driver_ro"}) == "driver_ro"
    assert resolve_target(registry.get("redis_get"), {"cloud": "aws"}) == "redis_aws"
    assert resolve_target(registry.get("pod_logs"), {"cloud": "gcp"}) == "k8s_gcp"
    assert resolve_target(registry.get("pod_restarts"), {}) == "metrics"


def test_unresolvable_target_is_rejected(registry: Registry) -> None:
    with pytest.raises(RegistryError):
        resolve_target(registry.get("redis_get"), {"cloud": "azure"})


# ---------------------------------------------------------------------------
# Parameter validation — rejection, never repair
# ---------------------------------------------------------------------------


def test_unknown_param_is_rejected(registry: Registry) -> None:
    entry = registry.get("table_info")
    with pytest.raises(ParamValidationError, match="unknown params"):
        entry.validate_params({"table": "person", "db": "driver_ro", "evil": "1"})


def test_out_of_enum_cloud_is_rejected(registry: Registry) -> None:
    entry = registry.get("redis_exists")
    with pytest.raises(ParamValidationError):
        entry.validate_params({"key": "driver:1", "cloud": "azure"})


def test_an_unstated_cloud_defaults_to_gcp(registry: Registry) -> None:
    """GCP is the default because the platform is migrating to it.

    This used to require an explicit cloud, on the reasoning that guessing was
    dangerous. That was right when the two clouds were equals; it is now just a
    question the user has to answer every time to get the same answer.
    """
    entry = registry.get("redis_exists")
    assert entry.validate_params({"key": "driver:1"})["cloud"] == "gcp"


def test_aws_is_still_reachable_when_explicitly_asked(registry: Registry) -> None:
    """Defaulting must not mean AWS became unreachable — only unvolunteered."""
    entry = registry.get("redis_exists")
    assert entry.validate_params({"key": "driver:1", "cloud": "aws"})["cloud"] == "aws"


@pytest.mark.parametrize(
    "injection",
    [
        "person'; DROP TABLE person;--",
        "person; SELECT 1",
        "person UNION SELECT password FROM users",
        "pg_class WHERE 1=1",
        "$(whoami)",
        "../../etc/passwd",
        "person`id`",
        "person\nDROP TABLE x",
    ],
)
def test_sql_injection_strings_are_rejected(registry: Registry, injection: str) -> None:
    entry = registry.get("table_info")
    with pytest.raises(ParamValidationError):
        entry.validate_params({"table": injection, "db": "driver_ro"})


@pytest.mark.parametrize(
    "glob",
    ["driver:*", "*", "beckn:*:cache", "driver:12*"],
)
def test_glob_in_key_param_is_rejected(registry: Registry, glob: str) -> None:
    """A glob in a KEY param is how KEYS-shaped scanning sneaks back in.

    Rejected twice over: `*` is outside the key charset, and even if it were
    allowed there, `allow_glob` is False on every shipped entry.
    """
    entry = registry.get("redis_get")
    with pytest.raises(ParamValidationError, match="not a valid redis key|globs"):
        entry.validate_params({"key": glob, "cloud": "gcp"})


@pytest.mark.parametrize(
    "metachar_value",
    ["pod; rm -rf /", "pod && curl evil", "pod`id`", "pod$(id)", "pod|cat", "pod\nx"],
)
def test_shell_metachars_rejected_in_k8s_params(
    registry: Registry, metachar_value: str
) -> None:
    entry = registry.get("pod_status")
    with pytest.raises(ParamValidationError):
        entry.validate_params({"pod": metachar_value, "cloud": "gcp"})


def test_oversized_param_is_rejected(registry: Registry) -> None:
    entry = registry.get("redis_get")
    with pytest.raises(ParamValidationError, match="max_length"):
        entry.validate_params({"key": "a" * 5000, "cloud": "gcp"})


def test_int_bounds_enforced(registry: Registry) -> None:
    entry = registry.get("pod_logs")
    with pytest.raises(ParamValidationError, match="above max"):
        entry.validate_params({"pod": "p-1", "cloud": "gcp", "tail": 100000})


def test_defaults_applied_when_omitted(registry: Registry) -> None:
    entry = registry.get("pod_logs")
    params = entry.validate_params({"pod": "driver-offer-bpp-1", "cloud": "gcp"})
    assert params["tail"] == 200
    assert params["since"] == "15m"
    assert params["namespace"] == "apps"
    assert params["container"] is None


# ---------------------------------------------------------------------------
# A bad registry must be fatal at load time
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, entry: dict) -> Path:
    (tmp_path / "bad.yaml").write_text(yaml.safe_dump({"entries": [entry]}))
    return tmp_path


_GOOD_SQL_ENTRY = {
    "name": "ok_entry",
    "surface": "db:read",
    "kind": "sql",
    "description": "fine",
    "target": "$db",
    "params": {"db": {"type": "enum", "required": True, "values": ["driver_ro"]}},
    "sql": "SELECT 1 FROM pg_class",
    "row_limit": 10,
    "timeout_s": 5,
}


def test_good_synthetic_entry_loads(tmp_path: Path) -> None:
    assert len(load_registry(_write(tmp_path, dict(_GOOD_SQL_ENTRY)))) == 1


def test_unknown_target_is_fatal(tmp_path: Path) -> None:
    bad = dict(_GOOD_SQL_ENTRY, target="writer_primary", params={})
    with pytest.raises(RegistryError, match="unknown connection"):
        load_registry(_write(tmp_path, bad))


def test_kind_payload_mismatch_is_fatal(tmp_path: Path) -> None:
    bad = dict(_GOOD_SQL_ENTRY, kind="redis", redis_op="get")
    with pytest.raises(RegistryError, match="requires exactly"):
        load_registry(_write(tmp_path, bad))


def test_undeclared_bind_param_is_fatal(tmp_path: Path) -> None:
    bad = dict(_GOOD_SQL_ENTRY, sql="SELECT 1 FROM pg_class WHERE relname = :nope")
    with pytest.raises(RegistryError, match="undeclared params"):
        load_registry(_write(tmp_path, bad))


def test_dollar_interpolation_in_sql_is_fatal(tmp_path: Path) -> None:
    bad = dict(_GOOD_SQL_ENTRY, sql="SELECT 1 FROM $table")
    with pytest.raises(RegistryError, match=r"\$"):
        load_registry(_write(tmp_path, bad))


def test_wrong_surface_for_kind_is_fatal(tmp_path: Path) -> None:
    bad = dict(_GOOD_SQL_ENTRY, surface="redis:read")
    with pytest.raises(RegistryError, match="not valid for kind"):
        load_registry(_write(tmp_path, bad))


def test_excessive_timeout_is_fatal(tmp_path: Path) -> None:
    bad = dict(_GOOD_SQL_ENTRY, timeout_s=600)
    with pytest.raises(RegistryError, match="timeout_s"):
        load_registry(_write(tmp_path, bad))


def test_glob_allowing_key_param_is_fatal(tmp_path: Path) -> None:
    bad = {
        "name": "sneaky_scan",
        "surface": "redis:read",
        "kind": "redis",
        "redis_op": "get",
        "description": "no",
        "target": "redis_$cloud",
        "params": {
            "key": {"type": "key", "required": True, "allow_glob": True},
            "cloud": {"type": "enum", "required": True, "values": ["gcp", "aws"]},
        },
    }
    with pytest.raises(RegistryError, match="globs"):
        load_registry(_write(tmp_path, bad))


def test_kubectl_without_cloud_param_is_fatal(tmp_path: Path) -> None:
    bad = {
        "name": "no_cloud",
        "surface": "k8s:gcp",
        "kind": "kubectl",
        "description": "no",
        "target": "k8s_gcp",
        "argv": ["get", "pods"],
    }
    with pytest.raises(RegistryError, match="cloud"):
        load_registry(_write(tmp_path, bad))


def test_duplicate_names_are_fatal(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text(
        yaml.safe_dump({"entries": [dict(_GOOD_SQL_ENTRY), dict(_GOOD_SQL_ENTRY)]})
    )
    with pytest.raises(RegistryError, match="duplicate"):
        load_registry(tmp_path)


def test_empty_registry_dir_is_fatal(tmp_path: Path) -> None:
    with pytest.raises(RegistryError, match="no YAML"):
        load_registry(tmp_path)


def test_entry_name_must_be_an_identifier() -> None:
    with pytest.raises(ValueError, match="identifier"):
        RegistryEntry(
            name="drop table; --",
            surface=Surface.DB_READ,
            kind="sql",
            description="x",
            target="driver_ro",
            sql="SELECT 1",
        )


# ---------------------------------------------------------------------------
# Secrets, ConfigMap values, and other things that must stay unreachable
# ---------------------------------------------------------------------------


def test_no_entry_touches_secrets(registry: Registry) -> None:
    """No Secret entry, not even names-only.

    Listing Secret names leaks the shape of the credential inventory, and
    ``-o name`` on Secrets is one flag away from ``-o yaml``.
    """
    for entry in registry.all_entries():
        if entry.kind != "kubectl":
            continue
        assert entry.argv is not None
        for element in entry.argv:
            assert "secret" not in element.lower(), entry.name


def test_no_entry_touches_configmaps_at_all(registry: Registry) -> None:
    """ConfigMaps are unreachable, not merely name-limited.

    Changed 2026-08-18: a names-only entry looked safe but was not durable.
    `list` returns whole ConfigMap objects including `data`, so the protection
    rested entirely on the output flag staying `-o name` forever. ConfigMap
    values may carry credentials, so configmaps were removed from the
    ServiceAccount RBAC instead — which also makes any such entry a guaranteed
    403. Shipping a function that always fails is worse than not having it.
    """
    for entry in registry.all_entries():
        if entry.kind != "kubectl" or not entry.argv:
            continue
        assert not any("configmap" in a.lower() for a in entry.argv), entry.name


def test_no_kubectl_entry_dumps_object_bodies_for_config(registry: Registry) -> None:
    for entry in registry.all_entries():
        if entry.kind != "kubectl" or not entry.argv:
            continue
        if any("configmap" in a.lower() for a in entry.argv):
            assert "yaml" not in entry.argv and "json" not in entry.argv, entry.name


def test_no_kubectl_entry_streams_or_mutates(registry: Registry) -> None:
    banned = {
        "-f", "--follow", "--watch", "-w",
        "exec", "port-forward", "cp", "edit", "apply", "patch", "delete",
        "scale", "rollout", "attach", "proxy", "drain", "cordon", "uncordon",
        "annotate", "label", "replace", "create", "run", "taint",
    }
    for entry in registry.all_entries():
        if entry.kind != "kubectl" or not entry.argv:
            continue
        assert not (set(entry.argv) & banned), entry.name


def test_istio_listings_are_cluster_wide(registry: Registry) -> None:
    """Gateway VirtualServices live outside `apps`, so a namespace-scoped list
    would miss exactly the objects that caused the outage."""
    for name in ("istio_virtualservices", "istio_destinationrules"):
        entry = registry.get(name)
        assert entry.argv is not None
        assert "--all-namespaces" in entry.argv, name
        assert "-n" not in entry.argv, name
        assert "namespace" not in entry.params, name


def test_namespaced_kubectl_entries_only_reach_atlas(registry: Registry) -> None:
    for entry in registry.all_entries():
        if entry.kind != "kubectl":
            continue
        spec = entry.params.get("namespace")
        if spec is None:
            continue
        assert set(spec.values or []) == {"apps"}, entry.name
        assert spec.default == "apps", entry.name


# ---------------------------------------------------------------------------
# Redis: the registry may not outrun the executor
# ---------------------------------------------------------------------------


def test_every_redis_op_is_runnable_by_the_executor(registry: Registry) -> None:
    """A redis entry the executor cannot bind is a guaranteed runtime failure.

    This is the `top_queries` lesson generalised: the worst outcome is an entry
    the selector confidently picks and the executor then refuses. DBSIZE,
    SLOWLOG and LATENCY belong on this surface but need an executor change
    first — this test is what forces the two to land together.
    """
    from app.executors.redis import ALLOWED_OPS

    for entry in registry.all_entries():
        if entry.kind == "redis":
            assert entry.redis_op in ALLOWED_OPS, entry.name


# ---------------------------------------------------------------------------
# SQL shape
# ---------------------------------------------------------------------------


def test_every_sql_entry_is_a_single_read(registry: Registry) -> None:
    from app.executors.pg import assert_read_only, to_psycopg_sql

    for entry in registry.all_entries():
        if entry.kind != "sql":
            continue
        assert entry.sql is not None
        assert_read_only(entry.sql)
        assert ";" not in entry.sql, entry.name
        # Every :name bind must round-trip into psycopg's %(name)s form.
        rewritten = to_psycopg_sql(entry.sql)
        assert ":" not in rewritten.replace("::", ""), entry.name


def test_sql_params_are_bound_not_interpolated(registry: Registry) -> None:
    """Every declared param that appears in the SQL appears as a :bind."""
    from app.registry.loader import BIND_PARAM_RE

    for entry in registry.all_entries():
        if entry.kind != "sql" or entry.sql is None:
            continue
        bound = set(BIND_PARAM_RE.findall(entry.sql))
        for pname in entry.params:
            if pname == "db":
                continue  # resolves the target, never appears in the statement
            assert pname in bound or f"%({pname})s" not in entry.sql, entry.name


# ---------------------------------------------------------------------------
# Cloud metric entries
# ---------------------------------------------------------------------------


def test_aws_metric_entries_declare_a_namespace(registry: Registry) -> None:
    for entry in registry.all_entries():
        if entry.kind == "awsmetric":
            assert entry.namespace, entry.name
            assert entry.metric, entry.name


def test_gcp_metric_types_are_fully_qualified(registry: Registry) -> None:
    for entry in registry.all_entries():
        if entry.kind == "gcpmetric":
            assert entry.metric is not None
            assert entry.metric.startswith("alloydb.googleapis.com/"), entry.name


def test_alloydb_disk_usage_is_the_verified_cluster_metric(registry: Registry) -> None:
    """Cluster-scoped, and deliberately so — there is no instance-level AlloyDB
    storage metric, and quoting one as if there were is how a read pool gets a
    per-node storage figure it does not have."""
    entry = registry.get("alloydb_disk_usage")
    assert entry.metric == "alloydb.googleapis.com/cluster/storage/usage"


# ---------------------------------------------------------------------------
# Descriptions are the model's only guide to choosing correctly
# ---------------------------------------------------------------------------


def test_every_entry_has_a_substantive_description(registry: Registry) -> None:
    for entry in registry.all_entries():
        assert len(entry.description.strip()) >= 45, entry.name


def test_every_param_is_described(registry: Registry) -> None:
    for entry in registry.all_entries():
        for pname, spec in entry.params.items():
            assert spec.description.strip(), f"{entry.name}.{pname}"


def test_env_values_tolerate_a_trailing_newline() -> None:
    """Secrets routinely carry one — `base64` of "value\\n" round-trips it
    invisibly — and it surfaces far from the cause: a username with a newline
    produced "Illegal header value" from the HTTP client, which reads as a
    network fault rather than a malformed credential.
    """
    import os

    from app.config import _env

    os.environ["INFRAGPT_TEST_VALUE"] = "readonly_user\n"
    try:
        assert _env("INFRAGPT_TEST_VALUE") == "readonly_user"
    finally:
        del os.environ["INFRAGPT_TEST_VALUE"]


def test_a_trailing_space_is_preserved() -> None:
    """A password may legitimately end in a space. Trimming it would turn a
    working credential into an unexplainable auth failure."""
    import os

    from app.config import _env

    os.environ["INFRAGPT_TEST_VALUE"] = "secret \n"
    try:
        assert _env("INFRAGPT_TEST_VALUE") == "secret "
    finally:
        del os.environ["INFRAGPT_TEST_VALUE"]
