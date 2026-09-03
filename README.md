<div align="center">
  <img src="docs/assets/hero.svg" alt="infragpt: a question flows through the registry, executors and evidence to an answer" width="100%">
</div>

<p align="center">
  <img alt="read-only by construction" src="https://img.shields.io/badge/access-read--only-1f7a4d?style=flat-square">
  <img alt="128 registry functions" src="https://img.shields.io/badge/registry-128_functions-1a6ad4?style=flat-square">
  <img alt="796 tests" src="https://img.shields.io/badge/tests-796_passing-1a6ad4?style=flat-square">
  <img alt="python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-3776ab?style=flat-square">
  <img alt="MIT licence" src="https://img.shields.io/badge/licence-MIT-8a837a?style=flat-square">
</p>

<p align="center">
  <b>Ask your infrastructure a question in plain English.<br>Get an answer with the evidence attached.</b>
</p>

**infragpt** is a read-only AI assistant for the people who run production. It
turns a question like *"which APIs are throwing 5xx, and why?"* into a chain of
pre-registered, code-reviewed, read-only function calls against your live
systems, and answers with **every call it made, what each returned, and whether
any failed**.

It reaches metrics, logs, Postgres, Kubernetes, Redis, cloud control planes and
ClickHouse. It cannot change any of them. That is not a policy. It is how the
credentials are cut.

<div align="center">
  <img src="docs/assets/terminal.svg" alt="A terminal session: a question is typed, four read-only functions run, and an answer is given with its evidence" width="100%">
</div>

Two front doors share one backend: an SSO-protected **web chat** for the team,
and the **`infractl`** command line for the terminal you already have open.

---

## Why it exists

Every on-call engineer has the same twenty questions, and answering each one
means remembering the right PromQL, the right label, the right `kubectl`
incantation, the right log index, and which cluster to look in. Under pressure
that recall is the slowest, most error-prone step of an incident.

infragpt puts that recall in a catalogue instead of a person. The catalogue is
reviewed in git like any other change. The model's only job is to choose from
it. The result is a tool you can hand to the whole team, including the newest
joiner at 3 a.m., because there is nothing it can break.

## How it works

1. **You ask.** In the chat or the CLI, in your own words.
2. **The model selects.** Its entire output surface is `{function_name, typed_params}`,
   chosen from `registry/*.yaml`. It never writes SQL, PromQL, shell, or a URL.
3. **Executors run.** One per backend. Each re-checks that the call is read-only
   before it runs it, using credentials that are themselves read-only.
4. **Evidence comes back.** Redacted, audited, and attached to the answer, so you
   can see exactly what was looked at and judge it yourself.
5. **The model explains.** Selection and synthesis are separate calls, so the
   explanation is grounded in the evidence rather than in the question.

Runbooks in `runbooks/` teach the selector how to reason about a *class* of
question, with the traps named, so that "reader latency" becomes "check the
missing index first" rather than a random walk across dashboards.

## The safety model

The design rests on one decision: **the model never authors a command.** There is
no SQL to parse, no shell to escape, and no query nobody has read.

<div align="center">
  <img src="docs/assets/layers.svg" alt="Four independent layers must all fail before a write is possible" width="100%">
</div>

Three of those layers are this repository's own code and could in principle be
wrong. The fourth is not. The database role is `SELECT`-only on a **physical
replica**, where `pg_is_in_recovery()` is true and a write is not merely denied
but impossible. Kubernetes access is a `get` / `list` / `watch` ServiceAccount
with **Secrets excluded**. Cloud access is viewer-only IAM with an explicit
`Deny` on every credential-returning API. Redis is limited to read verbs.
ClickHouse runs with `readonly=1`.

The one surface that composes its own commands, the shell guard, allowlists
binaries and read verbs, tokenises with `shlex`, and executes with `execve`.
No shell is ever spawned.

> A tool that can only read is a tool you can give to the whole team. That is
> the point of the constraint, not a limitation of it.

## What it can reach

<div align="center">
  <img src="docs/assets/surfaces.svg" alt="Seven read-only surfaces: metrics, logs, database, kubernetes, cache, cloud, analytics, and the shell guard" width="100%">
</div>

| Surface | What you can ask |
|---|---|
| **Metrics** | which APIs are failing, error rates and counts, p99 latency, queue and drainer health, alert rules, metric discovery |
| **Logs** | search application and mesh logs, pull request ids for failures, **follow one request across every service it touched** |
| **Database** | schema, indexes, bloat, locks, replication lag, live queries, per-query time attribution |
| **Kubernetes** | pods, deployments, events, nodes, HPAs, PDBs, Istio objects, cluster-wide |
| **Cache** | key existence, TTL, type, members, compared across clouds |
| **Cloud** | managed database instances and capacity, node pools, CloudWatch metrics, monitoring queries |
| **Analytics** | ClickHouse, for business data rather than infrastructure metadata |

The flagship is the **error-triage chain**. Metrics rank the failing services,
response codes decide where to look next, the mesh access log yields request
ids, and the application logs are searched for one of those ids across every
service that touched it. That last join is what turns *"service X is throwing
5xx"* into *"it is throwing 5xx because this call to that dependency failed"*.

## Designed against silent failure

The recurring hazard in a tool like this is not a wrong answer. It is a
**confident empty one**.

<div align="center">
  <img src="docs/assets/silent-failure.svg" alt="Two lanes: a naive tool renders an empty result as zero and reports healthy; infragpt labels it EMPTY and hands it to a human" width="100%">
</div>

Several deliberate choices exist only to prevent that:

- Executors distinguish *"returned nothing"* from *"could not be reached"*, and say which.
- An empty metric result states that no series matched, rather than rendering blank.
- The selector is told, in as many words, that an empty result is not an answer.
- `scripts/verify_live.py` sweeps every registry entry against real infrastructure
  and reports **OK / EMPTY / FAIL** separately. `EMPTY` is the state a human must judge.
- `app/experience.py` learns from the tool's own audit log which functions have
  been failing or silently returning nothing, and feeds that back into the next
  question. It learns **counts, never claims**. Nothing a model wrote is persisted as fact.

## Getting started

```bash
git clone https://github.com/vijaygupta18/infragpt.git && cd infragpt
uv sync                      # or: pip install -e ".[dev]"

pytest -q                    # 796 tests, no infrastructure required
python -m app.eval           # score the selector against the golden question set
```

Run the server locally against whatever you have credentials for. Every
connection is configured by environment variable. Nothing has a
deployment-specific default.

```bash
export GRID_BASE_URL=...                 # your LLM gateway
export VICTORIAMETRICS_URL=...           # metrics
export INFRAGPT_NAMESPACES=default,apps  # namespaces the k8s surface may read
uvicorn app.main:app --reload
```

Then, from another terminal:

```bash
infractl login                            # opens the browser for SSO, stores a scoped token
infractl ask "what is pending in the default namespace, and why?"
infractl ask -c <conversation-id> "and which node are they trying to land on?"
infractl ask -q "p99 for the checkout API over the last hour"   # answer only, no evidence
infractl whoami
```

Admins manage access from the same CLI:

```bash
infractl admin users
infractl admin activate <user-id>
infractl admin grant <user-id> k8s:gcp --expires-at 2026-12-31T00:00:00Z
infractl admin audit --day 2026-09-01
```

Access is by surface and by grant. A user with no grants can sign in and see
nothing. Grants can expire. Every question, every call, and every admin action
lands in an audit log that the tool itself reads back to improve.

## Deploying

The `deploy/` directory holds Kubernetes manifests and IAM bootstrap scripts as
**templates** with `<PLACEHOLDERS>`. Copy them into `deploy/private/`, fill them
in, and apply from there. That directory is gitignored, along with
`scripts/ship.env`, so project ids, account numbers, cluster names and hostnames
never enter the repository.

```bash
mkdir -p deploy/private && cp deploy/*.yaml deploy/private/
$EDITOR deploy/private/*.yaml
kubectl apply -f deploy/private/
```

`deploy/README.md` walks through the read-only ServiceAccount, the External
Secrets wiring, workload identity on GCP and IRSA on AWS, and why each IAM role
is exactly as narrow as it is.

## Layout

```
app/
  registry/     the contract: schema, loader, and the load-time read-only gate
  executors/    one per backend; each re-checks read-only before it runs
  grid/         LLM client. selection and synthesis are separate calls
  shell/        the command guard for the one surface that composes its own commands
  auth/         SSO assertion verification, CLI tokens, throttling
  access/       surfaces, grants, and the roles that compose them
  limits/       per-user rate and time budgets
  eval/         the golden question set and the selector scorer
  experience.py learns from the audit log what actually works
  redactor/     scrubs secrets and identifiers from evidence before it is shown
  web/          the chat, admin, audit and runbook pages
cli/            infractl
registry/       the catalogue: 128 functions across 15 files, as reviewed YAML
runbooks/       how to reason about a class of question, with the traps named
scripts/        ship.sh, verify_live.py, backup and restore
deploy/         templates. real values live in deploy/private/ (gitignored)
```

## Reading the code

Three files carry most of the design, and each explains its reasoning:

- **`app/registry/schema.py`** is the contract everything else depends on.
- **`app/registry/readonly.py`** is the load-time gate. An unknown kind fails
  closed, so a new capability must be reasoned about before it can ship.
- **`app/executors/pg.py`** lists the safety properties in the order they matter,
  starting with the one that is not this code's responsibility.

Comments throughout record *why* a decision was made, and several record where
an earlier version was wrong and what it cost. Those are the useful ones.

## Adding a capability

1. Add an entry to the right `registry/*.yaml`: a name, a description the model
   will read, typed parameters, and the executor `kind`.
2. If the kind is new, teach `app/registry/readonly.py` why it is read-only.
   Until you do, the registry refuses to load it.
3. Add a golden question to `app/eval/cases.yaml` and run `python -m app.eval`.
4. Run `scripts/verify_live.py` against a real environment and make sure the
   entry comes back **OK**, not **EMPTY**.

## Licence

MIT. See `LICENSE`.
