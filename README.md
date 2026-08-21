<div align="center">
  <img src="docs/assets/hero.svg" alt="infragpt — a question flows through the registry, executors and evidence to an answer" width="100%">
</div>

<p align="center">
  <img alt="read-only" src="https://img.shields.io/badge/access-read--only-1f7a4d?style=flat-square">
  <img alt="python" src="https://img.shields.io/badge/python-3.13-3776ab?style=flat-square">
  <img alt="tests" src="https://img.shields.io/badge/tests-771-1a6ad4?style=flat-square">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-8a837a?style=flat-square">
</p>

Ask an infrastructure question in English. The assistant picks from a catalogue of
pre-registered read-only functions, runs them against live infrastructure, and
answers **with the evidence attached** — every call it made, what each returned,
and whether any failed.

Two front doors, one backend: an SSO-authenticated web chat and a `infractl` CLI.

```
which APIs are throwing 5xx, and what are the actual errors?

  ✓ api_error_rates      5 workloads ranked by error rate
  ✓ api_error_codes      500s dominate, not 502 — the app is raising
  ✓ error_request_ids    3 request ids from the mesh access log
  ✓ logs_for_request_id  the exception, in a service further down

  driver-offer-bpp returns 500 on /quote/respond because it cannot find a
  search try with id "dummyFromLocation" — ~2.35/sec, not a one-off.
```

---

## The safety model

The design rests on one decision: **the model never authors a command.** Its
entire output surface is `{function_name, typed_params}`, chosen from a
catalogue in `registry/*.yaml` that is code-reviewed like any other change.
There is no SQL to parse, no shell to escape, and no query nobody has read.

<div align="center">
  <img src="docs/assets/layers.svg" alt="Four independent layers must all fail before a write is possible" width="100%">
</div>

Three of those layers are this repository's own code, and could in principle be
wrong. The fourth is not: the database role is `SELECT`-only on a **physical
replica**, where `pg_is_in_recovery()` is true and a write is not merely denied
but impossible. Kubernetes access is a `get`/`list`/`watch` ServiceAccount with
**Secrets excluded**; cloud access is viewer-only IAM with an explicit `Deny` on
every credential-returning API.

> A tool that can only read is a tool you can give to the whole team. That is
> the point of the constraint, not a limitation of it.

## What it can answer

| Surface | Examples |
|---|---|
| **Metrics** | which APIs are failing, error rates and counts, p99 latency, drainer health, ride-to-search ratio |
| **Logs** | search app and mesh logs, get request ids for failures, **follow one request across every service** |
| **Database** | schema, indexes, bloat, locks, replication lag, live queries, and per-query time attribution |
| **Kubernetes** | pods, deployments, events, nodes, HPAs, PDBs, Istio objects — cluster-wide read |
| **Cache** | key existence, TTL, type, members |
| **Cloud** | AlloyDB instances and capacity, CloudWatch metrics, alert rules |
| **Analytics** | ClickHouse, for business data rather than infrastructure metadata |

The flagship is the **error-triage chain**: metrics rank the failing services,
response codes decide where to look next, the mesh access log yields request
ids, and the application logs are searched for one of those ids across every
service that touched it. That last join is what turns *"service X is throwing
5xx"* into *"it is throwing 5xx because this call to that dependency failed"*.

## Designed against silent failure

The recurring hazard in a tool like this is not a wrong answer — it is a
**confident empty one**. A wrong metric label returns no series; no series
renders as zero; zero reads as health. Several deliberate choices exist only to
prevent that:

- Executors distinguish *"returned nothing"* from *"could not be reached"*, and
  say which.
- An empty metric result states that no series matched, rather than rendering
  blank.
- The selector is told, in as many words, that an empty result is not an answer.
- `scripts/verify_live.py` sweeps every registry entry against real
  infrastructure and reports **OK / EMPTY / FAIL** separately — `EMPTY` being the
  state a human must judge.
- `app/experience.py` learns from the tool's own audit log which functions have
  been failing or silently returning nothing, and feeds that back into the next
  question. It learns **counts, never claims** — nothing a model wrote is
  persisted as fact.

## Getting started

```bash
uv sync                      # or: pip install -e .
cp scripts/ship.env.example scripts/ship.env      # deployment coordinates
mkdir -p deploy/private && cp deploy/*.yaml deploy/private/
$EDITOR deploy/private/*.yaml                     # fill in <PLACEHOLDERS>

pytest -q                    # 771 tests, no infrastructure required
python -m app.eval           # score the selector against the golden set
```

Everything identifying a deployment — project ids, account numbers, cluster
names, hostnames, credentials — lives outside the repository, in
`deploy/private/` and `scripts/ship.env`, both gitignored. The committed
manifests are templates.

## Layout

```
app/
  registry/     the contract: schema, loader, and the load-time read-only gate
  executors/    one per backend; each re-checks read-only before it runs
  grid/         LLM client — selection and synthesis are separate calls
  shell/        command guard for the one surface that composes its own commands
  experience.py learns from the audit log what actually works
registry/       the catalogue, as reviewed YAML
runbooks/       how to reason about a class of question, with the traps named
scripts/        ship.sh, verify_live.py
deploy/         templates; real values live in deploy/private/ (gitignored)
```

## Reading the code

Three files carry most of the design, and each explains its reasoning:

- **`app/registry/schema.py`** — the contract everything else depends on.
- **`app/registry/readonly.py`** — the load-time gate. An unknown kind fails
  closed, so a new capability must be reasoned about before it can ship.
- **`app/executors/pg.py`** — the safety properties in the order they matter,
  starting with the one that is not this code's responsibility.

Comments throughout record *why* a decision was made, and several record where
an earlier version was wrong and what it cost. Those are the useful ones.

## Licence

MIT.
