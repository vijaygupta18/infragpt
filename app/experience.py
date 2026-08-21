"""What has actually worked here — learned from this tool's own history.

THE GAP THIS CLOSES. Everything else in this system is static: the registry, the
runbooks, the prompt. They encode what someone knew when they wrote them. So the
tool rediscovers the same dead ends forever — it learns during a conversation
and forgets at the end of it, and the next person asking the same question walks
into the same empty results.

Three discoveries on 2026-08-19/20 make the point. The Istio label is
`destination_workload`, not `destination_service_name`. The log indices are
`app-logs-*` and `istio-*`, not `logstash-*`. Query Insights needs
`ALIGN_DELTA`, not `ALIGN_MEAN`. Each was found by an investigation, each was
then hand-written into a runbook by a human. Without that, every one would have
been rediscovered from scratch, or worse, reported as "no data".

WHAT IS LEARNED, AND WHY IT CANNOT HALLUCINATE. Only MECHANICAL facts, derived
by counting audit records:

  * which entries have recently returned rows        -> these work
  * which entries succeed but return NOTHING         -> the dangerous ones
  * which entries fail consistently, and the error   -> do not burn a call

No model writes any of this, and none of it is interpretation. A learned note
is a count, not a claim, which is what makes it safe to feed straight back into
the selector prompt. Anything requiring judgement stays in the runbooks, where a
person reviews it.

The audit log was already recording all of it. Nothing ever read it back.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app import config

#: How far back to learn from. Long enough to survive a quiet weekend, short
#: enough that a capability fixed on Monday is not still described as broken.
LOOKBACK_DAYS = 3

#: Below this, a pattern is coincidence rather than evidence.
MIN_OBSERVATIONS = 3


@dataclass
class EntryExperience:
    name: str
    calls: int = 0
    failed: int = 0
    empty: int = 0
    with_rows: int = 0
    #: Succeeded, but the record predates row counting. NOT empty — see below.
    unknown_rows: int = 0
    last_error: str = ""
    errors: set[str] = field(default_factory=set)
    #: Timestamps of the most recent success and failure, so a capability that
    #: has since been FIXED stops being described as broken.
    last_ok_ts: str = ""
    last_fail_ts: str = ""

    @property
    def always_fails(self) -> bool:
        """Fails consistently AND has not succeeded since.

        The recency half matters: with a multi-day lookback, a capability fixed
        this morning would otherwise be reported as broken until the old records
        age out — actively steering the model away from something that works.
        A success after the last failure means it is fixed, whatever the totals
        say.
        """
        if self.calls < MIN_OBSERVATIONS or self.failed != self.calls:
            return False
        return not (self.last_ok_ts and self.last_ok_ts > self.last_fail_ts)

    @property
    def always_empty(self) -> bool:
        """Succeeds every time and is KNOWN to have returned nothing.

        The most useful thing this module finds: a call that looks healthy and
        answers nothing. Left unflagged, the model reads it as evidence of a
        quiet system.

        Counted only over records that actually carry a row count. Row counting
        was added later, so older records say nothing about emptiness — and
        treating "not recorded" as "returned nothing" made this layer's FIRST
        live run declare that alloydb_cpu and api_error_rates never return data,
        both of which demonstrably do. That is the exact false negative this
        module exists to warn about, produced by the module itself.
        """
        observed = self.empty + self.with_rows
        return (
            observed >= MIN_OBSERVATIONS
            and self.failed == 0
            and self.with_rows == 0
        )

    @property
    def reliable(self) -> bool:
        observed = self.empty + self.with_rows
        return observed >= MIN_OBSERVATIONS and self.with_rows >= observed / 2


def _audit_files(days: int) -> list[Path]:
    if not config.AUDIT_DIR.exists():
        return []
    today = datetime.now(UTC).date()
    wanted = {(today - timedelta(days=d)).isoformat() for d in range(days + 1)}
    return sorted(p for p in config.AUDIT_DIR.glob("*.jsonl") if p.stem in wanted)


def collect(days: int = LOOKBACK_DAYS) -> dict[str, EntryExperience]:
    """Aggregate recent call outcomes per registry entry."""
    out: dict[str, EntryExperience] = defaultdict(lambda: EntryExperience(name=""))
    for path in _audit_files(days):
        try:
            content = path.read_text(errors="replace")
        except OSError:
            # A missing or unreadable audit file must never break a question.
            continue
        for line in content.splitlines():
            if not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            # The audit record's discriminator is "kind", not "event". Getting
            # this wrong is silent — every record is skipped and the layer
            # reports "nothing learned yet", which is indistinguishable from a
            # genuinely quiet log. Caught only by reading a real record.
            if record.get("kind") != "call":
                continue
            name = record.get("entry_name")
            if not name:
                continue
            exp = out[name]
            exp.name = name
            exp.calls += 1
            ts = str(record.get("ts") or "")

            if not record.get("ok"):
                exp.failed += 1
                if ts > exp.last_fail_ts:
                    exp.last_fail_ts = ts
                error = str(record.get("error") or "")[:160]
                if error:
                    exp.last_error = error
                    exp.errors.add(error)
                continue

            if ts > exp.last_ok_ts:
                exp.last_ok_ts = ts
            has_rows = "rows" in record
            has_chars = "chars" in record
            if not (has_rows or has_chars):
                # Predates output counting. Unknown, and unknown must never be
                # folded into "empty" — see always_empty.
                exp.unknown_rows += 1
            elif int(record.get("rows") or 0) > 0 or int(record.get("chars") or 0) > 0:
                # Either shape counts. kubectl and shell return text with no
                # rows; treating those as empty would condemn every k8s
                # function as useless.
                exp.with_rows += 1
            else:
                exp.empty += 1

    return dict(out)


def hints(available: set[str], days: int = LOOKBACK_DAYS) -> str:
    """A compact note for the selector: what has and has not worked lately.

    Scoped to the entries this user can actually call, so it never advertises a
    capability they do not hold. Returns "" when there is nothing worth saying —
    an empty section is noise in a prompt that is already long.
    """
    stats = collect(days)
    broken: list[str] = []
    silent: list[str] = []
    working: list[str] = []

    for name, exp in sorted(stats.items()):
        if name not in available:
            continue
        if exp.always_fails:
            broken.append(f"{name} ({exp.last_error or 'fails every time'})")
        elif exp.always_empty:
            silent.append(f"{name} ({exp.calls}x, never any rows)")
        elif exp.reliable:
            working.append(name)

    if not (broken or silent):
        return ""

    lines = [
        "OBSERVED IN THE LAST FEW DAYS (counted from this tool's own call log, "
        "not an opinion):",
    ]
    if broken:
        lines.append(
            "- ALWAYS FAILS, do not spend a call on it unless the question "
            "specifically needs it: " + "; ".join(broken[:8])
        )
    if silent:
        lines.append(
            "- SUCCEEDS BUT ALWAYS RETURNS NOTHING. Treat an empty result from "
            "these as UNPROVEN, not as 'nothing is wrong' — check the argument "
            "names another way before reporting all-clear: " + "; ".join(silent[:8])
        )
    if working:
        lines.append("- Returning data reliably: " + ", ".join(working[:14]))
    return "\n".join(lines)
