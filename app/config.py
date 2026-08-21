"""Configuration and named connections.

Named connections are the reason the LLM never sees a hostname: registry entries
reference a connection by name, and the mapping lives here, sourced from env.

WRITER ENDPOINTS ARE DELIBERATELY ABSENT. Do not add them. infragpt has no
mutation path, and the way that stays true is that write targets are not
reachable from this process at all.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DATA_DIR = Path(os.getenv("INFRAGPT_DATA", "/data"))
DB_PATH = DATA_DIR / "infragpt.db"
AUDIT_DIR = DATA_DIR / "audit"
# Seeds live in the repo at ./runbooks and are copied onto the PV at deploy time.
# INFRAGPT_RUNBOOKS lets dev and tests read them straight from the repo.
RUNBOOK_DIR = Path(os.getenv("INFRAGPT_RUNBOOKS", str(DATA_DIR / "runbooks")))
BACKUP_DIR = DATA_DIR / "backups"

REGISTRY_DIR = Path(os.getenv("INFRAGPT_REGISTRY", "registry"))


@dataclass(frozen=True)
class PgConnection:
    name: str
    host: str
    database: str
    user: str
    password_env: str  # NAME of the env var holding the password, never the value
    port: int = 5432
    sslmode: str = "require"  # AlloyDB is ENCRYPTED_ONLY
    max_pool: int = 5         # hard cap: must not be able to exhaust a reader
    # Applied in the connection options, so they hold for EVERY statement on
    # every connection rather than only where code remembers to SET them.
    connect_timeout_s: int = 5
    statement_timeout_ms: int = 30_000


@dataclass(frozen=True)
class RedisConnection:
    name: str
    host: str
    port: int
    cloud: str
    password_env: str | None = None


@dataclass(frozen=True)
class K8sConnection:
    name: str
    context: str
    cloud: str
    # Which namespaces this deployment may read. Supplied, never defaulted: the
    # namespace layout is deployment information, and an empty tuple correctly
    # means "nothing is reachable" rather than quietly allowing a namespace that
    # happens to be named the same as ours.
    namespaces: tuple[str, ...] = ()


def secret_from_env(key: str, default: str = "") -> str:
    """Read a CREDENTIAL from the environment, stripping trailing newlines.

    Same reasoning as _env, and the same bug bit twice: a ClickHouse password
    carrying "\n" produced "Illegal header value" — and the client put the
    credential IN THE EXCEPTION TEXT, which then flowed into logs and the audit
    trail. Both halves are fixed: the newline here, the leak in
    app/executors/base.redact_exception.
    """
    return os.getenv(key, default).strip("\r\n")


def _env(key: str, default: str = "") -> str:
    """Read an env var, stripping trailing newlines.

    Secrets routinely carry one: `echo -n` is easy to forget, and `base64` of
    "value\n" round-trips the newline invisibly. It then breaks things far from
    the cause — a username with a trailing newline produced
    "LocalProtocolError: Illegal header value" from an HTTP client, which reads
    as a network fault rather than as a malformed credential.

    Only \r and \n are stripped, never spaces: a password may legitimately end
    in a space, and silently trimming it would turn a working credential into an
    authentication failure nobody could explain.
    """
    return os.getenv(key, default).strip("\r\n")


# ---- Named connections (READER ENDPOINTS ONLY) ----------------------------
#
# NOTHING HERE HAS AN ENVIRONMENT-SPECIFIC DEFAULT.
#
# This repository is published, so no hostname, database name, role, project,
# region or vendor URL belongs in it. Every such value arrives from the
# ConfigMap or Secret at run time; the code only names the variables.
#
# The defaults that are kept are structural (port 5432, `require` TLS, a pool
# ceiling) — true of any deployment, and carrying no information about ours.
#
# This is also a correctness property, not only a disclosure one. Two database
# names were previously hardcoded and both were wrong, and the failure surfaced
# as a connection-pool timeout that read as "the reader is at its connection
# ceiling" — a plausible, entirely fictional story about load. A value that must
# be supplied cannot silently be stale.
PG_USER = _env("INFRAGPT_PG_USER")
PG_PORT = int(_env("INFRAGPT_PG_PORT", "5432"))

PG_DRIVER_DB = _env("INFRAGPT_DRIVER_DB") or _env("GCP_PROD_DRIVER_DB")
PG_RIDER_DB = _env("INFRAGPT_RIDER_DB") or _env("GCP_PROD_RIDER_DB")

PG_CONNECTIONS: dict[str, PgConnection] = {
    "driver_ro": PgConnection(
        name="driver_ro",
        host=_env("INFRAGPT_DRIVER_HOST") or _env("GCP_PROD_DRIVER_RO_HOST"),
        database=PG_DRIVER_DB,
        user=PG_USER,
        password_env="INFRAGPT_PG_PASSWORD",  # noqa: S106 - env var name, not a secret
        port=PG_PORT,
    ),
    "rider_ro": PgConnection(
        name="rider_ro",
        host=_env("INFRAGPT_RIDER_HOST") or _env("GCP_PROD_RIDER_RO_HOST"),
        database=PG_RIDER_DB,
        user=PG_USER,
        password_env="INFRAGPT_PG_PASSWORD",  # noqa: S106 - env var name, not a secret
        port=PG_PORT,
    ),
    # The non-critical driver read pool. Same database, a read pool that does
    # not serve the driver app's live traffic.
    #
    # This is where anything heavy belongs — a free-form catalogue query, a
    # scan-heavy statistics view, an analyst poking around. The critical reader
    # is in the path of drivers going online, and an assistant that anyone in
    # the org can ask anything must not be able to make that reader slower by
    # being used as intended.
    #
    # Falls back to the critical reader only if unset, so a deployment that has
    # not been given the endpoint degrades to "works, but shares the pool"
    # rather than to "driver questions fail".
    "driver_noncrit": PgConnection(
        name="driver_noncrit",
        host=(
            _env("INFRAGPT_DRIVER_NONCRIT_HOST")
            or _env("GCP_PROD_DRIVER_NONCRIT_HOST")
            or _env("INFRAGPT_DRIVER_HOST")
            or _env("GCP_PROD_DRIVER_RO_HOST")
        ),
        database=PG_DRIVER_DB,
        user=PG_USER,
        password_env="INFRAGPT_PG_PASSWORD",  # noqa: S106 - env var name, not a secret
        port=PG_PORT,
    ),
}

REDIS_CONNECTIONS: dict[str, RedisConnection] = {
    "redis_gcp": RedisConnection("redis_gcp", _env("GCP_REDIS_HOST"), 6379, "gcp"),
    "redis_aws": RedisConnection("redis_aws", _env("AWS_REDIS_HOST"), 6379, "aws"),
}


def redis_clouds_are_distinct() -> bool:
    """Whether the two named Redis connections are actually different instances.

    They may not be. Verified in this deployment on 2026-08-19: both resolve to
    the SAME ElastiCache endpoint, and there is no Memorystore instance in the
    project at all — the two clouds genuinely share one Redis.

    This matters because the most-requested Redis question is "does this key
    differ between the clouds?". Against a single shared instance the two reads
    are the same read, so the answer is always "no divergence" — a false
    negative that looks like a clean bill of health. Anything comparing clouds
    must check this first and say so instead of reporting a comparison it did
    not make.
    """
    gcp = REDIS_CONNECTIONS["redis_gcp"].host
    aws = REDIS_CONNECTIONS["redis_aws"].host
    return bool(gcp) and bool(aws) and gcp != aws

def _namespaces() -> tuple[str, ...]:
    """Readable namespaces, from INFRAGPT_NAMESPACES (comma-separated).

    Also drives the `namespace` enum offered to the model, so the registry YAML
    carries no deployment's namespace names either.
    """
    raw = _env("INFRAGPT_NAMESPACES")
    return tuple(n.strip() for n in raw.split(",") if n.strip())


NAMESPACES = _namespaces()

K8S_CONNECTIONS: dict[str, K8sConnection] = {
    "k8s_gcp": K8sConnection("k8s_gcp", _env("GKE_PROD_CONTEXT"), "gcp", NAMESPACES),
    "k8s_aws": K8sConnection("k8s_aws", _env("EKS_PROD_CONTEXT"), "aws", NAMESPACES),
}

METRICS_URL = _env("VICTORIAMETRICS_URL")


# ---- Cloud control-plane (public APIs, no VPC route needed) ----------------
#
# Reachable during an incident even when the VPC path is what is broken. Both
# endpoints below are read-only from this process: only GET/list is ever issued.

@dataclass(frozen=True)
class GcpApiConnection:
    name: str
    project: str
    region: str
    base_url: str


# Project and region carry no default: they identify a specific deployment.
# The base URLs do, because they are Google's public API endpoints — the same
# for every user of the product, and therefore not deployment information.
GCP_PROJECT = _env("GCP_PROJECT")
GCP_REGION = _env("GCP_REGION")

GCP_CONNECTIONS: dict[str, GcpApiConnection] = {
    "gcp_monitoring": GcpApiConnection(
        name="gcp_monitoring",
        project=GCP_PROJECT,
        region=GCP_REGION,
        base_url="https://monitoring.googleapis.com/v3",
    ),
    "gcp_alloydb": GcpApiConnection(
        name="gcp_alloydb",
        project=GCP_PROJECT,
        region=GCP_REGION,
        # v1beta, pinned deliberately: the read-pool autoscaler block and the
        # live `nodes` array are HIDDEN from the v1 API. Without them you only
        # see readPoolConfig.nodeCount, which is the autoscaler *floor*, not the
        # live count — reading it as the live count produces badly wrong
        # per-node arithmetic (see registry/cloud.yaml).
        base_url="https://alloydb.googleapis.com/v1beta",
    ),
}

# Access token for the GCP APIs. In-cluster this comes from Workload Identity;
# locally, `gcloud auth print-access-token`. Never a long-lived key file.
GCP_TOKEN_ENV = "GCP_ACCESS_TOKEN"  # noqa: S105 - env var name, not a secret


@dataclass(frozen=True)
class AwsApiConnection:
    name: str
    region: str


AWS_REGION = _env("AWS_REGION")

AWS_CONNECTIONS: dict[str, AwsApiConnection] = {
    "aws_cloudwatch": AwsApiConnection("aws_cloudwatch", AWS_REGION),
    "aws_elasticache": AwsApiConnection("aws_elasticache", AWS_REGION),
}

# AWS credentials come from the standard env vars. See app/executors/awsapi.py
# for why boto3 (and therefore IRSA's STS exchange) is deliberately not used.


# ---- ClickHouse (analytics warehouse, HTTP interface, READ-ONLY) -----------
#
# The one surface that returns BUSINESS data rather than infrastructure
# metadata. Same rule as everything above: no host, database, user or password
# has a default, because this repository is published — the code names the
# variables and the ConfigMap/Secret supplies the values.
#
# `user` matters more here than elsewhere: the intended account is a ClickHouse
# profile with `readonly = 1` set on the PROFILE, so the credential itself
# cannot write. The `readonly=1` the executor sends on every request is the
# layer underneath that, for the case where the deployment was handed a wider
# account than it should have been.

@dataclass(frozen=True)
class ClickHouseConnection:
    name: str
    host: str                 # host only; the executor builds the URL
    user: str
    password_env: str         # NAME of the env var holding the password
    database: str = ""        # empty = the server's default database
    port: int = 8123
    scheme: str = "http"      # https where the deployment terminates TLS
    # Bounds sent as ClickHouse SETTINGS on EVERY request, so they hold for any
    # statement rather than only where the caller remembers them. An entry's own
    # timeout_s / row_limit narrows these; neither can widen them.
    max_execution_time_s: int = 30
    max_result_rows: int = 10_000
    connect_timeout_s: int = 5

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


CLICKHOUSE_CONNECTIONS: dict[str, ClickHouseConnection] = {
    "ch_prod": ClickHouseConnection(
        name="ch_prod",
        host=_env("INFRAGPT_CLICKHOUSE_HOST"),
        user=_env("INFRAGPT_CLICKHOUSE_USER"),
        password_env="INFRAGPT_CLICKHOUSE_PASSWORD",  # noqa: S106 - env var name, not a secret
        database=_env("INFRAGPT_CLICKHOUSE_DB"),
        port=int(_env("INFRAGPT_CLICKHOUSE_PORT", "8123")),
        scheme=_env("INFRAGPT_CLICKHOUSE_SCHEME", "http"),
    ),
}



# ---- MCP servers (in-cluster, read-only tool calls) ------------------------
#
# The team already runs MCP servers for VictoriaMetrics, Grafana and OpenSearch
# in BOTH clouds. infragpt talks to them over streamable-http JSON-RPC and
# calls ONLY the tools named by a reviewed registry entry — a server upgrade
# that ships new tools does not widen what this process can do.
#
# ClusterIP services, so these are reachable only from inside the cluster.

@dataclass(frozen=True)
class McpConnection:
    name: str
    url: str            # base URL of the MCP server
    cloud: str
    server: str         # victoriametrics | grafana | opensearch
    path: str = "/mcp"  # streamable-http endpoint path

    @property
    def endpoint(self) -> str:
        return f"{self.url.rstrip('/')}/{self.path.lstrip('/')}"


MCP_CONNECTIONS: dict[str, McpConnection] = {
    "vm_gcp": McpConnection(
        "vm_gcp",
        _env("MCP_VM_GCP_URL"),
        "gcp",
        "victoriametrics",
        _env("MCP_VM_PATH", "/mcp"),
    ),
    "vm_aws": McpConnection(
        "vm_aws",
        _env("MCP_VM_AWS_URL"),
        "aws",
        "victoriametrics",
        _env("MCP_VM_PATH", "/mcp"),
    ),
    "grafana_gcp": McpConnection(
        "grafana_gcp",
        _env("MCP_GRAFANA_GCP_URL"),
        "gcp",
        "grafana",
        _env("MCP_GRAFANA_PATH", "/mcp"),
    ),
    "grafana_aws": McpConnection(
        "grafana_aws",
        _env("MCP_GRAFANA_AWS_URL"),
        "aws",
        "grafana",
        _env("MCP_GRAFANA_PATH", "/mcp"),
    ),
    "opensearch_gcp": McpConnection(
        "opensearch_gcp",
        _env("MCP_OPENSEARCH_GCP_URL"),
        "gcp",
        "opensearch",
        _env("MCP_OPENSEARCH_PATH", "/mcp"),
    ),
    "opensearch_aws": McpConnection(
        "opensearch_aws",
        _env("MCP_OPENSEARCH_AWS_URL"),
        "aws",
        "opensearch",
        _env("MCP_OPENSEARCH_PATH", "/mcp"),
    ),
}


# ---- Grid LLM gateway ------------------------------------------------------

# No default: the gateway is an internal endpoint, and the client targets the
# OpenAI-compatible /v1/chat/completions shape, so this is deliberately not
# tied to any one provider.
GRID_BASE_URL = _env("GRID_BASE_URL")
GRID_API_KEY_ENV = "GRID_API_KEY"   # never hardcode the key
GRID_SELECTOR_MODEL = _env("GRID_SELECTOR_MODEL", "")   # cheap model
GRID_SYNTH_MODEL = _env("GRID_SYNTH_MODEL", "")         # stronger model


# ---- Auth ------------------------------------------------------------------

#: Only addresses at this domain may self-register. Empty disables the check.
#: Set from config, never hardcoded — this repository is open-source, and the
#: organisation it happens to be deployed for is not part of the code.
ALLOWED_EMAIL_DOMAIN = _env("INFRAGPT_EMAIL_DOMAIN")

#: EKS cluster name, for reaching the AWS cluster without a kubeconfig. The
#: endpoint and CA are fetched with eks:DescribeCluster and the bearer token is
#: minted per call, so this is the only thing that has to be configured.
EKS_CLUSTER_NAME = _env("INFRAGPT_EKS_CLUSTER")

POMERIUM_JWKS_URL = _env("POMERIUM_JWKS_URL")
POMERIUM_AUDIENCE = _env("POMERIUM_AUDIENCE")
CLI_TOKEN_TTL_HOURS = int(_env("CLI_TOKEN_TTL_HOURS", "12"))


# ---- Limits ----------------------------------------------------------------

# 14, not 8. A discover-then-inspect question fans out over every item found (6
# ElastiCache clusters plus the inventory call already exceeded 5), and once the
# model can compose commands it also spends calls CORRECTING them — a wrong flag
# costs a call and teaches it the right one. Too low a budget shows up as an
# answer that stops halfway and asks the user to finish the job.
#
# Still a hard ceiling: this is a bounded loop, not an open-ended agent.
# Raised 14 -> 30 on 2026-08-20, and the ceiling is now set by REAL limits
# rather than caution:
#
#   * The Pomerium/GCLB route timeout is 300s. A question must finish inside it
#     or the connection is severed mid-answer, so wall clock — not this number —
#     is the binding constraint on a long investigation.
#   * Evidence is budgeted per call, so raising this without raising
#     MAX_EVIDENCE_CHARS would make every result thinner and the answers worse.
#     Both were raised together.
#
# Original note: A real investigation costs calls: the live
# error-triage chain used 12, and a database question that has to establish what
# is NOT true before it can say what is used 14 and ran out mid-answer. The
# ceiling exists to stop a runaway loop, not to cut short a thorough one — and
# evidence is now budgeted per call, so a long chain degrades by trimming each
# result rather than by dropping the last and most decisive one.
MAX_CALLS_PER_QUESTION = 30
# 0 = UNLIMITED, and that is the default for both.
#
# Same lesson as the daily token budget: a limit sized against a hypothetical
# runaway blocked the actual user. 20 questions/hour sounds generous until
# someone is genuinely debugging — the tool then refuses at exactly the moment
# it is most wanted, which is the worst possible time for it to be unavailable.
#
# The mechanism stays, because a runaway loop is real. It is the DEFAULT that was
# wrong. Set these from observed usage in the audit log rather than from a guess,
# and note the real protections are elsewhere and always on: every call is
# bounded by its own timeout and row cap, the DB pool is capped at 5 connections
# so nothing here can exhaust a reader, and the credentials cannot write.
QUESTIONS_PER_HOUR = int(_env("INFRAGPT_QUESTIONS_PER_HOUR", "0"))
CALLS_PER_HOUR = int(_env("INFRAGPT_CALLS_PER_HOUR", "0"))
DEFAULT_TIMEOUT_S = 30
