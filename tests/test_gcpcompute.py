"""The typed compute inventory — flattening and trimming, no network."""

from __future__ import annotations

import pytest

from app.executors.gcpapi import GcpComputeExecutor


def test_aggregated_scopes_flatten_to_rows():
    body = {
        "items": {
            "zones/us-central1-a": {"instances": [{"name": "clickhouse-1", "status": "RUNNING"}]},
            "zones/us-central1-b": {
                "warning": {"code": "NO_RESULTS_ON_PAGE"},
                "instances": [],
            },
            "zones/us-central1-c": {"instances": [{"name": "jump-1", "status": "TERMINATED"}]},
        }
    }
    rows = GcpComputeExecutor._flatten_aggregated(body, "instances")
    assert [r["name"] for r in rows] == ["clickhouse-1", "jump-1"]
    assert rows[0]["_scope"] == "us-central1-a"


def test_instance_trim_keeps_the_debugging_facts():
    row = GcpComputeExecutor._trim(
        "instances",
        {
            "name": "clickhouse-1",
            "_scope": "us-central1-b",
            "status": "RUNNING",
            "machineType": "https://.../machineTypes/n2-standard-16",
            "networkInterfaces": [
                {"networkIP": "10.60.1.5",
                 "accessConfigs": [{"natIP": "34.1.2.3"}]}
            ],
            "fingerprint": "xxxx", "selfLink": "https://...", "kind": "compute#instance",
        },
    )
    assert row == {
        "name": "clickhouse-1", "zone": "us-central1-b", "status": "RUNNING",
        "machine_type": "n2-standard-16",
        "internal_ip": "10.60.1.5", "external_ip": "34.1.2.3",
    }
    assert "selfLink" not in row


def test_nodepool_rows_carry_autoscaling_and_spot():
    body = {
        "clusters": [
            {
                "name": "gke-main",
                "nodePools": [
                    {
                        "name": "spot-pool",
                        "status": "RUNNING",
                        "version": "1.30",
                        "config": {"machineType": "n2-standard-8", "spot": True},
                        "autoscaling": {"minNodeCount": 1, "maxNodeCount": 10},
                    }
                ],
            }
        ]
    }
    rows = GcpComputeExecutor._nodepool_rows(body)
    assert rows[0]["spot"] is True
    assert rows[0]["autoscaling_max"] == 10
    assert rows[0]["cluster"] == "gke-main"


@pytest.mark.anyio
async def test_unknown_operation_is_refused():
    from app.executors.base import ExecutorError
    from app.registry.schema import RegistryEntry

    entry = RegistryEntry.model_validate(
        {"name": "x", "surface": "cloud:gcp", "kind": "gcpcompute",
         "description": "d", "target": "gcp_compute", "metric": "reboot",
         "params": {}}
    )
    with pytest.raises(ExecutorError, match="unknown compute operation"):
        await GcpComputeExecutor().run(entry, {}, "gcp_compute")
