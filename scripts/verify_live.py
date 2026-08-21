"""Run every registry entry against the real cluster and report what works.

WHY THIS EXISTS. Every failure found on 2026-08-19 was SILENT. The MCP layer
was completely dead (missing handshake), the Istio label was wrong
(`destination_service_name` matches nothing here), the log indices did not
exist, and the metrics executor returned the query instead of the numbers. None
of it raised. Each produced an empty result, and an empty result renders as
zero, and zero reads as health.

Unit tests cannot catch that class — they mock the very thing that is wrong.
Asking the assistant a question cannot either: a confident answer built on an
empty series looks exactly like a correct one. The only check that works is to
run each entry against the real thing and look at what comes back.

THREE OUTCOMES, and the middle one is the point:

  OK      returned rows. The capability works.
  EMPTY   succeeded and returned NOTHING. Might be a genuinely quiet system,
          might be a name that matches nothing. THIS IS THE DANGEROUS ONE and
          it is reported separately rather than counted as a pass.
  FAIL    errored. Loud, and therefore the least dangerous.
  SKIP    needs an identifier only a real incident provides (a request id, a
          driver id). Reported so coverage is never overstated.

Read-only throughout: it runs registry entries, which are the same read-only
functions the assistant is limited to. It cannot mutate anything.

    kubectl -n apps exec deploy/infragpt -c api -- python scripts/verify_live.py
    ... --surface metrics      # one surface
    ... --json                 # machine-readable, for CI
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

from app.executors.dispatch import get_executors
from app.registry.loader import get_registry, resolve_target

#: Probe parameters per entry. Anything not listed is called with its declared
#: defaults; anything still missing a required param is SKIPPED, not guessed —
#: a made-up driver id would produce a confident EMPTY that means nothing.
PROBES: dict[str, dict[str, Any]] = {
    # metrics
    "api_error_rates": {"window": "1h", "top": 5},
    "api_error_counts": {"window": "1h", "min_count": 0},
    "api_request_counts": {"window": "1h", "top": 5},
    "api_error_ratio": {"service": "$workload", "window": "1h"},
    "api_error_codes": {"service": "$workload", "window": "1h"},
    "api_error_routes": {"service": "$workload", "window": "1h"},
    "api_error_callers": {"service": "$workload", "window": "1h"},
    "metric_names": {"match": '{__name__=~"istio.*"}'},
    "metric_labels": {},
    "metric_label_values": {"label": "destination_workload"},
    "active_alerts": {},
    "alert_rules": {},
    "drainer_throughput": {"metric": "driver_drainer_query_executes", "window": "1h"},
    "drainer_stopped": {"metric": "driver_drainer_stop_status"},
    "drainer_lag": {"window": "1h"},
    "producer_throughput": {"window": "1h"},
    "ride_to_search_ratio": {"window": "1h"},
    "search_volume": {"window": "1h"},
    "config_decode_failures": {"metric": "driver_kv_config_decode_failure", "window": "1h"},
    "app_request_latency_p99": {"window": "1h"},
    # logs
    "list_log_indices": {"cloud": "gcp"},
    "log_field_mapping": {"cloud": "gcp", "index": "istio-*"},
    "logs_search": {"cloud": "gcp", "query": "*", "window": "now-1h", "size": 2},
    "error_request_ids": {"cloud": "gcp", "window": "now-6h", "size": 2},
    # db
    "db_query": {"db": "driver_noncrit", "sql": "SELECT 1 AS ok"},
}

#: Entries that cannot be probed without something only an incident supplies.
SKIP = {
    "logs_for_request_id": "needs a real request id",
    "driver_account_state": "needs a real driver id",
    "driver_dues_summary": "needs a real driver id",
    "driver_plan_state": "needs a real driver id",
    "driver_id_from_phone_hash": "needs a real phone hash",
    "run_read_command": "composes its own command; nothing to probe",
}


async def _discover_workload(executors: Any, registry: Any) -> str:
    """Find a workload name that really exists, for the per-service entries.

    Probing those with a guessed name would return EMPTY and prove nothing —
    which is the exact failure mode this script exists to detect.
    """
    try:
        entry = registry.get("api_error_rates")
        params = entry.validate_params({"window": "6h", "top": 1})
        result = await executors.for_kind(entry.kind).run(
            entry, params, resolve_target(entry, params)
        )
        for row in result.rows or []:
            name = row.get("destination_workload")
            if name and name != "unknown":
                return str(name)
    except Exception as exc:  # noqa: BLE001 - discovery is best-effort
        # Not fatal and not silent: if discovery fails, the per-service entries
        # are reported SKIP rather than probed with a guessed name, and this
        # line says why.
        print(f"(workload discovery failed: {type(exc).__name__}: {exc})", file=sys.stderr)
    return ""


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--surface", default="", help="only this surface")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    registry = get_registry()
    executors = get_executors()
    workload = await _discover_workload(executors, registry)

    results: list[dict[str, Any]] = []
    for entry in sorted(registry.all_entries(), key=lambda e: (str(e.surface), e.name)):
        if args.surface and str(entry.surface) != args.surface:
            continue
        row: dict[str, Any] = {"name": entry.name, "surface": str(entry.surface)}

        if entry.name in SKIP:
            results.append({**row, "state": "SKIP", "detail": SKIP[entry.name]})
            continue

        probe = dict(PROBES.get(entry.name, {}))
        if probe.get("service") == "$workload":
            if not workload:
                results.append(
                    {**row, "state": "SKIP", "detail": "no live workload to probe with"}
                )
                continue
            probe["service"] = workload

        missing = [
            n
            for n, spec in entry.params.items()
            if spec.required and n not in probe and spec.default is None
        ]
        if missing:
            results.append(
                {**row, "state": "SKIP", "detail": f"needs {', '.join(missing)}"}
            )
            continue

        try:
            params = entry.validate_params(probe)
            result = await executors.for_kind(entry.kind).run(
                entry, params, resolve_target(entry, params)
            )
        except Exception as exc:  # noqa: BLE001 - a broken entry must not stop the sweep
            results.append(
                {**row, "state": "FAIL", "detail": f"{type(exc).__name__}: {exc}"[:180]}
            )
            continue

        if not result.ok:
            results.append({**row, "state": "FAIL", "detail": (result.error or "")[:180]})
        elif result.rows or (result.text or "").strip():
            # Rows OR text. kubectl and shell entries return text and no rows,
            # and calling those EMPTY produced 12 false alarms in one sweep —
            # which is how a checker that cries wolf gets ignored.
            detail = (
                f"{len(result.rows)} rows"
                if result.rows
                else f"{len((result.text or '').splitlines())} lines"
            )
            results.append({**row, "state": "OK", "detail": detail})
        else:
            results.append(
                {
                    **row,
                    "state": "EMPTY",
                    "detail": (result.text or "")[:120].replace("\n", " ") or "no rows",
                }
            )

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        order = {"FAIL": 0, "EMPTY": 1, "SKIP": 2, "OK": 3}
        for r in sorted(results, key=lambda r: (order[r["state"]], r["surface"], r["name"])):
            print(f"{r['state']:6} {r['surface']:12} {r['name']:26} {r['detail']}")
        counts = {s: sum(1 for r in results if r["state"] == s) for s in order}
        print(
            f"\n{counts['OK']} ok · {counts['EMPTY']} empty · "
            f"{counts['FAIL']} failed · {counts['SKIP']} skipped"
        )
        if counts["EMPTY"]:
            print(
                "\nEMPTY is the one to read. A capability that returns nothing "
                "looks identical to a healthy system, and that is how a wrong "
                "label or a dead endpoint hides. Check each one is genuinely quiet."
            )

    # Only FAIL is a non-zero exit: EMPTY needs a human to judge, and failing CI
    # on a quiet Sunday would train people to ignore this.
    return 1 if any(r["state"] == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
