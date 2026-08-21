"""GCP control-plane executors — Cloud Monitoring and AlloyDB Admin, over REST.

Why REST rather than shelling out to `gcloud`:

* No ~1GB CLI in the container, and no second subprocess surface in a tool whose
  whole safety story is "the model cannot run arbitrary commands".
* Auth is a bearer token from Workload Identity, so there is no `gcloud auth`
  state to keep on the PV.
* A pinned API version is a contract. Beta CLI flags get renamed and promoted.

Read-only by construction: this module issues GET requests only. There is no
code path here that can POST, PATCH or DELETE, and the service account should be
granted `roles/monitoring.viewer` + `roles/alloydb.viewer` and nothing more —
the credential remains the real enforcement, as everywhere else in this system.
"""

from __future__ import annotations

import os
import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from app import config
from app.executors.base import ExecResult, Executor, ExecutorError
from app.registry.schema import RegistryEntry

_DURATION_RE = re.compile(r"^(\d{1,4})([smhd])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _window_seconds(raw: str) -> int:
    m = _DURATION_RE.match(raw or "15m")
    if not m:
        raise ExecutorError(f"bad window: {raw!r}")
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2)]


#: Workload Identity hands the pod a token via the GKE metadata server, not via
#: an environment variable. Cached until shortly before expiry — the endpoint is
#: cheap but not free, and every registry call would otherwise hit it.
_METADATA_HOST = "http://metadata.google.internal/computeMetadata/v1"
_METADATA_TOKEN_PATH = "/instance/service-accounts/default/token"  # noqa: S105
_METADATA_TOKEN_URL = _METADATA_HOST + _METADATA_TOKEN_PATH
_token_cache: tuple[str, float] | None = None


def _metadata_token() -> str | None:
    """Fetch a token from the GKE metadata server, or None if not on GKE."""
    global _token_cache
    if _token_cache and _token_cache[1] > time.time() + 60:
        return _token_cache[0]
    try:
        resp = httpx.get(
            _METADATA_TOKEN_URL,
            headers={"Metadata-Flavor": "Google"},
            timeout=3.0,
        )
    except httpx.HTTPError:
        return None  # not running on GCP
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
        token = str(body["access_token"])
        ttl = float(body.get("expires_in", 3600))
    except (ValueError, KeyError):
        return None
    _token_cache = (token, time.time() + ttl)
    return token


def _token() -> str:
    """Access token, preferring an explicit env var, else Workload Identity.

    The env var exists for local development (`gcloud auth print-access-token`).
    In-cluster there is deliberately NO token in a Secret: Workload Identity
    mints a short-lived one per pod, so there is no long-lived credential to
    leak, rotate or forget to revoke.
    """
    token = os.getenv(config.GCP_TOKEN_ENV, "")
    if token:
        return token
    token = _metadata_token()
    if token:
        return token
    raise ExecutorError(
        f"No GCP credentials. In-cluster this comes from Workload Identity via "
        f"the metadata server — check the ServiceAccount annotation "
        f"iam.gke.io/gcp-service-account. Locally, set {config.GCP_TOKEN_ENV} "
        "from `gcloud auth print-access-token`."
    )


def _conn(target: str) -> config.GcpApiConnection:
    try:
        return config.GCP_CONNECTIONS[target]
    except KeyError:
        raise ExecutorError(f"unknown gcp connection: {target}") from None


async def _get(url: str, params: dict[str, Any] | None, timeout_s: int) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.get(
                url,
                params=params,
                headers={"Authorization": f"Bearer {_token()}"},
            )
    except httpx.HTTPError as exc:
        raise ExecutorError(f"GCP API unreachable: {exc}") from exc
    if resp.status_code == 401:
        raise ExecutorError("GCP API rejected the token (401) — it may have expired.")
    if resp.status_code == 403:
        raise ExecutorError(
            "GCP API returned 403 — the service account lacks the viewer role for "
            "this resource. This is a permissions problem, not an outage."
        )
    if resp.status_code >= 400:
        raise ExecutorError(f"GCP API returned {resp.status_code}: {resp.text[:300]}")
    try:
        return resp.json()
    except ValueError as exc:
        raise ExecutorError("GCP API returned non-JSON") from exc


_LABEL_PRIORITY = (
    "instance_id", "node_name", "pod_name", "container_name", "cluster_name",
    "database_id", "instance_name", "backend_target_name", "gateway_name",
    "router_id", "topic_id", "subscription_id", "bucket_name", "job_id",
)


def _series_label(labels: dict[str, Any]) -> str:
    """The most specific identifier available for a time series."""
    for key in _LABEL_PRIORITY:
        if labels.get(key):
            return str(labels[key])
    ignored = {"project_id", "location", "zone", "region"}
    rest = {k: v for k, v in labels.items() if k not in ignored and v}
    if rest:
        return ", ".join(f"{k}={v}" for k, v in sorted(rest.items())[:2])
    return "(unlabelled)"


class GcpMetricExecutor(Executor):
    """Cloud Monitoring time series. Works without a VPC route."""

    kind = "gcpmetric"

    async def run(
        self, entry: RegistryEntry, params: dict[str, Any], target: str
    ) -> ExecResult:
        started = self._timed()
        conn = _conn(target)
        if not entry.metric:
            raise ExecutorError(f"{entry.name}: entry declares no metric")

        seconds = _window_seconds(str(params.get("window") or "15m"))
        end = datetime.now(UTC)
        start = end - timedelta(seconds=seconds)
        # Align to the whole window so a single representative point comes back
        # per series; the caller wants "what is it now", not a chart.
        query = {
            "filter": f'metric.type="{entry.metric}"',
            "interval.startTime": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "interval.endTime": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "aggregation.alignmentPeriod": f"{max(60, seconds)}s",
            "aggregation.perSeriesAligner": "ALIGN_MEAN",
        }
        body = await _get(
            f"{conn.base_url}/projects/{conn.project}/timeSeries",
            query,
            entry.timeout_s,
        )

        rows: list[dict[str, Any]] = []
        for series in body.get("timeSeries", []):
            labels = {
                **(series.get("resource", {}).get("labels") or {}),
                **(series.get("metric", {}).get("labels") or {}),
            }
            points = series.get("points") or []
            value = None
            if points:
                v = points[0].get("value", {})
                value = (
                    v.get("doubleValue")
                    if v.get("doubleValue") is not None
                    else v.get("int64Value")
                )
            rows.append(
                {
                    # Which label identifies a series depends on the metric
                    # family: AlloyDB uses instance_id, kubernetes.io uses
                    # node/pod/container names, load balancing uses others again.
                    # Falling back to "?" made every GKE result anonymous, so try
                    # the known identifiers in order and only then give up.
                    "instance": _series_label(labels),
                    "value": value,
                    # The unit is reported so an answer cannot present a bare
                    # number as if its scale were self-evident.
                    "unit": body.get("unit") or series.get("unit") or "(unit not reported)",
                    **{
                        k: v
                        for k, v in labels.items()
                        if k not in {"instance_id", "cluster_id", "project_id"}
                    },
                }
            )
        rows.sort(key=lambda r: str(r.get("instance")))

        result = ExecResult(
            ok=True,
            entry_name=entry.name,
            target=target,
            rows=rows[: entry.row_limit],
            duration_ms=int((self._timed() - started) * 1000),
        )
        if not rows:
            result.text = (
                f"No time series returned for {entry.metric} in the last "
                f"{params.get('window') or '15m'}. This means no data, not zero."
            )
        return result


class GcpAlloyDbExecutor(Executor):
    """AlloyDB Admin API — instance inventory."""

    kind = "gcpalloydb"

    async def run(
        self, entry: RegistryEntry, params: dict[str, Any], target: str
    ) -> ExecResult:
        started = self._timed()
        conn = _conn(target)
        parent = f"projects/{conn.project}/locations/{conn.region}"

        # Two-step, and it has to be:
        #   1. list  — `clusters/-` is the wildcard for every cluster in the region.
        #              It does NOT accept `view`; passing it returns 400
        #              INVALID_ARGUMENT ("Unknown name \"view\"").
        #   2. get?view=INSTANCE_VIEW_FULL — only this returns the live `nodes`
        #              array. Without it you get readPoolConfig.nodeCount, which
        #              is the autoscaler FLOOR, not the live count.
        # Only read pools need step 2, so the extra calls are bounded by the
        # number of read pools (currently 2), not by total instances.
        url = f"{conn.base_url}/{parent}/clusters/-/instances"
        listing = await _get(url, None, entry.timeout_s)

        rows: list[dict[str, Any]] = []
        for inst in listing.get("instances", []):
            name = inst.get("name", "")
            cluster = name.split("/clusters/")[-1].split("/")[0] if "/clusters/" in name else "?"
            pool = inst.get("readPoolConfig") or {}
            live_nodes = None
            if inst.get("instanceType") == "READ_POOL" and name:
                try:
                    full = await _get(
                        f"{conn.base_url}/{name}",
                        {"view": "INSTANCE_VIEW_FULL"},
                        entry.timeout_s,
                    )
                except ExecutorError:
                    full = {}
                live_nodes = len(full.get("nodes") or []) or None
                pool = full.get("readPoolConfig") or pool
            autoscale = (pool.get("autoScalingConfig") or {}).get("policy") or {}
            max_nodes = autoscale.get("maxNodeCount")
            rows.append(
                {
                    "cluster": cluster,
                    "instance": name.rsplit("/", 1)[-1],
                    "type": inst.get("instanceType"),
                    "state": inst.get("state"),
                    "vcpus": (inst.get("machineConfig") or {}).get("cpuCount"),
                    "live_nodes": live_nodes,
                    "autoscale_floor": pool.get("nodeCount"),
                    "autoscale_max": max_nodes,
                    "at_autoscale_ceiling": (
                        bool(live_nodes and max_nodes and int(live_nodes) >= int(max_nodes))
                    ),
                }
            )
        rows.sort(key=lambda r: (str(r.get("cluster")), str(r.get("instance"))))

        return ExecResult(
            ok=True,
            entry_name=entry.name,
            target=target,
            rows=rows[: entry.row_limit],
            duration_ms=int((self._timed() - started) * 1000),
        )

class GcpMetricSearchExecutor(Executor):
    """Discovery: find a metric TYPE by substring.

    There are ~2000 metric descriptors in this project and only a handful are
    worth enumerating as registry entries. Rather than guess a metric name — the
    failure mode that produced a 404 the first time this surface was built — the
    model searches for one, then queries it. Returns names, never values.
    """

    kind = "gcpmetricsearch"

    async def run(
        self, entry: RegistryEntry, params: dict[str, Any], target: str
    ) -> ExecResult:
        started = self._timed()
        conn = _conn(target)
        needle = str(params.get("contains") or "").strip()
        if not needle:
            raise ExecutorError(f"{entry.name}: `contains` is required")
        limit = int(params.get("limit") or 40)

        # `metric.type : "x"` is the contains form. Verified against the live API
        # alongside starts_with() and has_substring(); this one is the least
        # surprising for a substring the model picked out of a question.
        body = await _get(
            f"{conn.base_url}/projects/{conn.project}/metricDescriptors",
            {"filter": f'metric.type : "{needle}"', "pageSize": min(limit, 200)},
            entry.timeout_s,
        )
        rows = [
            {
                "metric_type": m.get("type"),
                "display_name": m.get("displayName"),
                "kind": m.get("metricKind"),
                "value_type": m.get("valueType"),
                "unit": m.get("unit") or "(none)",
                # A list of plain strings, not objects — confirmed against the
                # live API, which is why this is not `r.get("type")`.
                "applies_to": ",".join(
                    str(r) for r in (m.get("monitoredResourceTypes") or [])[:3]
                ),
            }
            for m in body.get("metricDescriptors", [])
        ]
        result = ExecResult(
            ok=True, entry_name=entry.name, target=target,
            rows=rows[:limit],
            duration_ms=int((self._timed() - started) * 1000),
        )
        if not rows:
            result.text = (
                f"No metric type contains {needle!r}. Try a shorter or different "
                "substring — this searched names only, so a metric may exist "
                "under wording you have not guessed."
            )
        return result


class GcpMetricQueryExecutor(GcpMetricExecutor):
    """Query ANY metric type by name, rather than one fixed per registry entry.

    Same request shape and parsing as GcpMetricExecutor; the only difference is
    that the metric type is a validated parameter instead of a field on the
    entry. That single change makes every GCP metric reachable — GKE, Memorystore,
    load balancers, Cloud NAT, PSC — without enumerating any of them.
    """

    kind = "gcpmetricquery"

    async def run(
        self, entry: RegistryEntry, params: dict[str, Any], target: str
    ) -> ExecResult:
        metric_type = str(params.get("metric_type") or "").strip()
        if not metric_type:
            raise ExecutorError(f"{entry.name}: `metric_type` is required")

        # Borrow the parent's implementation by presenting the param as if it
        # were the entry's own metric. `model_copy` keeps the registry entry
        # itself immutable — the loaded catalogue must never be mutated at runtime.
        effective = entry.model_copy(update={"metric": metric_type})
        rest = {k: v for k, v in params.items() if k != "metric_type"}
        aligner = str(rest.pop("aligner", "") or "")
        result = await super().run(effective, rest, target)
        if aligner:
            result.text = (result.text + f"\n[aligner: {aligner}]").strip()
        return result
