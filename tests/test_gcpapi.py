"""GCP control-plane executors — mocked HTTP, no network."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from app.executors.base import ExecutorError
from app.executors.gcpapi import (
    GcpAlloyDbExecutor,
    GcpMetricExecutor,
    GcpMetricQueryExecutor,
    GcpMetricSearchExecutor,
    _window_seconds,
)
from app.registry.loader import load_registry
from app.registry.schema import Surface

REGISTRY_DIR = Path(__file__).resolve().parent.parent / "registry"


@pytest.fixture()
def token(monkeypatch):
    monkeypatch.setenv("GCP_ACCESS_TOKEN", "test-token")


def _entry(name: str):
    return load_registry(REGISTRY_DIR).get(name)


# ---- window parsing --------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "seconds"), [("15m", 900), ("1h", 3600), ("7d", 604800), ("30s", 30)]
)
def test_window_parsing(raw: str, seconds: int) -> None:
    assert _window_seconds(raw) == seconds


def test_bad_window_is_rejected() -> None:
    with pytest.raises(ExecutorError):
        _window_seconds("1 week")


# ---- auth ------------------------------------------------------------------


async def test_missing_token_is_a_clear_error(monkeypatch) -> None:
    monkeypatch.delenv("GCP_ACCESS_TOKEN", raising=False)
    with pytest.raises(ExecutorError, match="GCP_ACCESS_TOKEN"):
        await GcpMetricExecutor().run(_entry("alloydb_connections"), {}, "gcp_monitoring")


async def test_unknown_connection_is_rejected(token) -> None:
    with pytest.raises(ExecutorError, match="unknown gcp connection"):
        await GcpMetricExecutor().run(_entry("alloydb_connections"), {}, "nope")


# ---- metrics ---------------------------------------------------------------


def _install_get(monkeypatch, payload: dict[str, Any] | Exception) -> dict[str, Any]:
    seen: dict[str, Any] = {}

    async def fake_get(url, params, timeout_s):  # noqa: ANN001, ANN202
        seen["url"] = url
        seen["params"] = params
        if isinstance(payload, Exception):
            raise payload
        return payload

    monkeypatch.setattr("app.executors.gcpapi._get", fake_get)
    return seen


async def test_metric_rows_include_instance_and_unit(token, monkeypatch) -> None:
    _install_get(
        monkeypatch,
        {
            "unit": "1",
            "timeSeries": [
                {
                    "resource": {"labels": {"instance_id": "rider-reader", "project_id": "p"}},
                    "points": [{"value": {"doubleValue": 1432.6}}],
                }
            ],
        },
    )
    res = await GcpMetricExecutor().run(
        _entry("alloydb_connections"), {"window": "15m"}, "gcp_monitoring"
    )
    assert res.ok
    assert res.rows[0]["instance"] == "rider-reader"
    assert res.rows[0]["value"] == 1432.6
    # The unit must travel with the number — a bare value invites a wrong reading.
    assert res.rows[0]["unit"] == "1"
    assert "project_id" not in res.rows[0]


async def test_empty_result_says_no_data_not_zero(token, monkeypatch) -> None:
    """'No series' and 'the value is zero' are different facts."""
    _install_get(monkeypatch, {"timeSeries": []})
    res = await GcpMetricExecutor().run(_entry("alloydb_cpu"), {}, "gcp_monitoring")
    assert res.rows == []
    assert "not zero" in res.text


async def test_metric_filter_is_built_from_the_entry_not_the_caller(
    token, monkeypatch
) -> None:
    """The LLM supplies only a window; the metric type comes from the registry."""
    seen = _install_get(monkeypatch, {"timeSeries": []})
    await GcpMetricExecutor().run(
        _entry("alloydb_replication_lag"), {"window": "1h"}, "gcp_monitoring"
    )
    assert seen["params"]["filter"] == (
        'metric.type="alloydb.googleapis.com/instance/postgres/replication/maximum_lag"'
    )


async def test_int64_values_are_read(token, monkeypatch) -> None:
    _install_get(
        monkeypatch,
        {
            "timeSeries": [
                {
                    "resource": {"labels": {"instance_id": "a"}},
                    "points": [{"value": {"int64Value": "1000"}}],
                }
            ]
        },
    )
    res = await GcpMetricExecutor().run(_entry("alloydb_connection_limit"), {}, "gcp_monitoring")
    assert res.rows[0]["value"] == "1000"


# ---- alloydb inventory -----------------------------------------------------


async def test_instance_inventory_parses(token, monkeypatch) -> None:
    _install_get(
        monkeypatch,
        {
            "instances": [
                {
                    "name": (
                        "projects/p/locations/us-central1/clusters/"
                        "db-cluster/instances/reader"
                    ),
                    "instanceType": "READ_POOL",
                    "state": "READY",
                    "machineConfig": {"cpuCount": 4},
                    "nodes": [{"id": "n1"}],
                }
            ]
        },
    )
    res = await GcpAlloyDbExecutor().run(_entry("alloydb_instances"), {}, "gcp_alloydb")
    row = res.rows[0]
    assert row["cluster"] == "db-cluster"
    assert row["instance"] == "reader"
    assert row["type"] == "READ_POOL"
    assert row["vcpus"] == 4


# ---- registry / grants -----------------------------------------------------


def test_cloud_entries_require_the_cloud_gcp_grant() -> None:
    registry = load_registry(REGISTRY_DIR)
    cloud = [e for e in registry.all_entries() if e.kind in ("gcpmetric", "gcpalloydb")]
    assert cloud, "expected cloud entries"
    assert all(e.surface is Surface.CLOUD_GCP for e in cloud)
    # A caller without the grant must not even be offered them.
    offered = {e.name for e in registry.entries_for_surfaces({Surface.DB_READ})}
    assert not offered & {e.name for e in cloud}


# ---- metric discovery + generic query ---------------------------------------
# These two make every GCP metric reachable without an entry per metric. There
# are ~2000 descriptors in the project; enumerating them was never viable.


async def test_metric_search_builds_a_contains_filter(token, monkeypatch) -> None:
    seen = _install_get(monkeypatch, {"metricDescriptors": []})
    await GcpMetricSearchExecutor().run(
        _entry("gcp_metric_search"), {"contains": "nat", "limit": 5}, "gcp_monitoring"
    )
    assert seen["params"]["filter"] == 'metric.type : "nat"'


async def test_metric_search_returns_names_not_values(token, monkeypatch) -> None:
    _install_get(
        monkeypatch,
        {
            "metricDescriptors": [
                {
                    "type": "redis.googleapis.com/stats/memory/usage",
                    "displayName": "Memory usage",
                    "metricKind": "GAUGE",
                    "valueType": "INT64",
                    "unit": "By",
                    # A list of plain STRINGS — this shape was confirmed live
                    # after an earlier assumption that they were objects.
                    "monitoredResourceTypes": ["redis_instance"],
                }
            ]
        },
    )
    res = await GcpMetricSearchExecutor().run(
        _entry("gcp_metric_search"), {"contains": "memory"}, "gcp_monitoring"
    )
    row = res.rows[0]
    assert row["metric_type"] == "redis.googleapis.com/stats/memory/usage"
    assert row["applies_to"] == "redis_instance"
    assert "value" not in row  # discovery returns names, never readings


async def test_metric_search_empty_says_try_another_substring(token, monkeypatch) -> None:
    _install_get(monkeypatch, {"metricDescriptors": []})
    res = await GcpMetricSearchExecutor().run(
        _entry("gcp_metric_search"), {"contains": "zzz"}, "gcp_monitoring"
    )
    assert res.rows == []
    assert "shorter or different" in res.text


async def test_metric_search_requires_a_substring(token, monkeypatch) -> None:
    _install_get(monkeypatch, {"metricDescriptors": []})
    with pytest.raises(ExecutorError, match="contains"):
        await GcpMetricSearchExecutor().run(
            _entry("gcp_metric_search"), {"contains": "  "}, "gcp_monitoring"
        )


async def test_metric_query_uses_the_supplied_metric_type(token, monkeypatch) -> None:
    seen = _install_get(monkeypatch, {"timeSeries": []})
    await GcpMetricQueryExecutor().run(
        _entry("gcp_metric_query"),
        {"metric_type": "kubernetes.io/node/cpu/core_usage_time", "window": "1h"},
        "gcp_monitoring",
    )
    assert seen["params"]["filter"] == (
        'metric.type="kubernetes.io/node/cpu/core_usage_time"'
    )


async def test_metric_query_does_not_mutate_the_registry_entry(token, monkeypatch) -> None:
    """The loaded catalogue must stay immutable — it is shared process-wide."""
    _install_get(monkeypatch, {"timeSeries": []})
    entry = _entry("gcp_metric_query")
    await GcpMetricQueryExecutor().run(
        entry, {"metric_type": "some.metric/type"}, "gcp_monitoring"
    )
    assert entry.metric is None


async def test_metric_query_requires_a_metric_type(token, monkeypatch) -> None:
    _install_get(monkeypatch, {"timeSeries": []})
    with pytest.raises(ExecutorError, match="metric_type"):
        await GcpMetricQueryExecutor().run(
            _entry("gcp_metric_query"), {}, "gcp_monitoring"
        )


async def test_series_label_prefers_the_most_specific_identifier(token, monkeypatch) -> None:
    """GKE series carry node/pod names, not instance_id. Falling back to '?'
    made every Kubernetes result anonymous."""
    _install_get(
        monkeypatch,
        {
            "timeSeries": [
                {
                    "resource": {"labels": {"node_name": "gke-node-abc", "project_id": "p"}},
                    "points": [{"value": {"doubleValue": 0.42}}],
                }
            ]
        },
    )
    res = await GcpMetricQueryExecutor().run(
        _entry("gcp_metric_query"), {"metric_type": "kubernetes.io/node/cpu/x"},
        "gcp_monitoring",
    )
    assert res.rows[0]["instance"] == "gke-node-abc"
