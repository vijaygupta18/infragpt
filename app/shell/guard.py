"""Guarded command runner for the confirm-before-run escape hatch.

This is the ONLY place in infragpt where a command that is not a registry entry
can execute, and it exists under one non-negotiable condition: **a human reads
the exact command and clicks Run.** The model proposes; it never executes.

Four layers, in the order they actually protect you:

1. **The pod's credentials.** The ServiceAccount is get/list/watch and excludes
   Secrets and ConfigMaps; the Postgres role is SELECT-only against physical
   replicas where writes are impossible. Even a total failure of everything
   below cannot mutate infrastructure. This is the backstop, and it is why this
   feature is defensible at all.
2. **A human.** Nothing here runs without an explicit confirmation of the exact
   argv, by a user holding a separate admin-only grant.
3. **argv, never a shell.** Commands are argv lists passed to
   ``create_subprocess_exec``. No shell means no pipes, no `;`, no `$( )`, no
   globbing, no redirection — the usual ways a "read-only" allowlist is escaped
   simply do not exist.
4. **Allowlists here.** Binary and verb allowlists, plus a denylist for reads
   that leak credentials.

Layer 4 is the weakest and is treated as such. Note especially that read-only is
NOT the same as safe-to-read: `kubectl get secret -o yaml` is a read that dumps
credentials, which is why it is blocked here *and* excluded from the RBAC.
"""

from __future__ import annotations

import asyncio
import re
import shlex
from dataclasses import dataclass, field

MAX_OUTPUT_BYTES = 200_000
DEFAULT_TIMEOUT_S = 30

#: Only these binaries may ever be invoked.
ALLOWED_BINARIES = frozenset(
    {"kubectl", "psql", "redis-cli", "aws", "gcloud", "gsutil", "bq", "curl"}
)

#: gsutil: listing and metadata only. `cat`/`cp` read OBJECT CONTENTS, and a
#: bucket object can hold anything — including the credentials this tool is
#: forbidden to read. Listing what exists is inventory; reading it is not.
GSUTIL_READ_VERBS = frozenset({"ls", "du", "stat", "hash", "version", "help"})

#: bq: metadata and bounded reads. `query` is excluded even though most queries
#: are SELECTs — `bq query` also executes DML and DDL, and the guard cannot tell
#: them apart without parsing SQL it was not given. `head` reads rows from a
#: named table, which is bounded and cannot mutate.
BQ_READ_VERBS = frozenset({"ls", "show", "head", "version", "help"})

#: aws/gcloud: allowlist the READ verbs rather than denylisting writes. A
#: denylist over a CLI with thousands of subcommands is a losing game — one
#: unlisted `modify-*` and the guarantee is gone. Anything not matching these
#: prefixes is refused, including subcommands that do not exist yet.
AWS_READ_PREFIXES = ("describe-", "list-", "get-", "lookup-", "search-", "scan-")
AWS_READ_EXACT = frozenset({"ls", "help"})
#: `read` is here for `gcloud logging read`, which is the only way to reach GCP
#: Cloud Logging from this tool. Its absence refused a command that is read-only
#: by name and left an entire log source unreachable — the kind of gap that
#: reads as "the tool cannot answer that" rather than as a missing allowlist
#: entry. No gcloud surface uses `read` for anything mutating.
GCLOUD_READ_VERBS = frozenset(
    {"describe", "list", "info", "version", "help", "read"}
)
GCLOUD_READ_PREFIXES = ("get-",)

#: curl: GET only. -d/-F/-T imply a body, and a body implies a write even when
#: the method is not spelled out — curl silently upgrades to POST for -d.
CURL_BODY_FLAGS = (
    "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
    "-F", "--form", "-T", "--upload-file", "--json",
)
CURL_ALLOWED_METHODS = frozenset({"GET", "HEAD"})

#: kubectl verbs that only read. Everything else is refused, including verbs that
#: look harmless: `exec` runs arbitrary code in a pod, `port-forward` opens a
#: tunnel, `cp` moves files, `proxy` exposes the API server.
KUBECTL_READ_VERBS = frozenset(
    {"get", "describe", "logs", "top", "events", "version", "explain", "api-resources"}
)

#: Resources whose *contents* are credentials. Reading them is still a leak, so
#: they are blocked here as well as being absent from the ServiceAccount.
KUBECTL_DENIED_RESOURCES = re.compile(
    r"^(secrets?|configmaps?|serviceaccounts?/token|.*\.secrets?\..*)$", re.IGNORECASE
)

#: Output formats that can dump whole objects including credential fields.
KUBECTL_DENIED_FLAGS = ("--token", "--kubeconfig", "--as", "--as-group", "--server")

#: redis-cli commands that only read.
REDIS_READ_COMMANDS = frozenset(
    {
        "get", "mget", "ttl", "pttl", "exists", "type", "strlen",
        "hget", "hgetall", "hkeys", "hlen", "smembers", "scard", "sismember",
        "llen", "lrange", "zcard", "zrange", "dbsize", "info", "memory",
        "object", "slowlog", "latency", "client", "config",
    }
)
#: Even among reads, these leak or reconfigure.
REDIS_DENIED_SUBCOMMANDS = {("config", "set"), ("client", "kill"), ("config", "rewrite")}

#: A single read statement. Anything else — including a CTE that writes — refused.
SQL_ALLOWED_LEADING = ("select", "with", "explain", "show", "table")
SQL_DENIED = re.compile(
    r"\b(insert|update|delete|drop|alter|truncate|create|grant|revoke|vacuum|"
    r"reindex|cluster|copy|call|do|lock|refresh|comment|security|prepare|"
    r"execute|listen|notify|pg_read_file|pg_read_binary_file|lo_import|lo_export)\b",
    re.IGNORECASE,
)


class CommandRefused(ValueError):
    """The proposed command is not permitted. Never softened into a warning."""


@dataclass
class Proposal:
    argv: list[str]
    rationale: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def display(self) -> str:
        return shlex.join(self.argv)


def _check_kubectl(argv: list[str]) -> None:
    args = [a for a in argv[1:] if a]
    verb = next((a for a in args if not a.startswith("-")), None)
    if verb is None:
        raise CommandRefused("kubectl: no verb given")
    if verb not in KUBECTL_READ_VERBS:
        raise CommandRefused(
            f"kubectl {verb!r} is not a read verb. Allowed: "
            f"{', '.join(sorted(KUBECTL_READ_VERBS))}"
        )
    for a in args:
        if any(a.startswith(f) for f in KUBECTL_DENIED_FLAGS):
            raise CommandRefused(f"kubectl flag {a.split('=')[0]!r} is not permitted")
    # The resource is the token after the verb.
    try:
        resource = args[args.index(verb) + 1]
    except IndexError:
        resource = ""
    target = resource.split("/", 1)[0]
    if target and KUBECTL_DENIED_RESOURCES.match(target):
        raise CommandRefused(
            f"reading {target!r} is not permitted: its contents are credentials. "
            "Read-only is not the same as safe to read."
        )


def _check_redis(argv: list[str]) -> None:
    args = [a for a in argv[1:] if not a.startswith("-")]
    # Skip host/port values that follow flags.
    cmd = next((a.lower() for a in args if a.lower() in REDIS_READ_COMMANDS), None)
    if cmd is None:
        raise CommandRefused(
            "redis-cli: no read command recognised. KEYS, FLUSHALL, SET, DEL and "
            "anything else that writes or scans the whole keyspace are refused."
        )
    idx = [a.lower() for a in args].index(cmd)
    sub = args[idx + 1].lower() if len(args) > idx + 1 else ""
    if (cmd, sub) in REDIS_DENIED_SUBCOMMANDS:
        raise CommandRefused(f"redis-cli {cmd} {sub} is not permitted")


def _check_psql(argv: list[str]) -> None:
    try:
        stmt = argv[argv.index("-c") + 1]
    except (ValueError, IndexError):
        raise CommandRefused("psql: only `-c <single SELECT>` is permitted") from None
    body = stmt.strip().lstrip("(").lstrip()
    if not body.lower().startswith(SQL_ALLOWED_LEADING):
        raise CommandRefused(f"psql: not a read statement: {body[:60]!r}")
    without_literals = re.sub(r"'[^']*'", "''", body)
    for chunk in without_literals.split(";"):
        if chunk.strip() and SQL_DENIED.match(chunk.strip()):
            raise CommandRefused(f"psql: mutating statement: {chunk.strip()[:60]!r}")
    if ";" in without_literals.rstrip(";").rstrip():
        raise CommandRefused("psql: multiple statements are not permitted")


def _check_aws(argv: list[str]) -> None:
    args = [a for a in argv[1:] if not a.startswith("-")]
    if not args:
        raise CommandRefused("aws: no subcommand given")
    # args[0] is the service (ec2, elasticache...), args[1] the operation.
    op = args[1] if len(args) > 1 else ""
    if not op:
        raise CommandRefused("aws: no operation given")
    if op in AWS_READ_EXACT or op.startswith(AWS_READ_PREFIXES):
        return
    raise CommandRefused(
        f"aws {args[0]} {op!r} is not a read operation. Only describe-*, list-*, "
        "get-*, lookup-*, search-*, scan-* and ls are permitted."
    )


def _check_gcloud(argv: list[str]) -> None:
    args = [a for a in argv[1:] if not a.startswith("-")]
    if not args:
        raise CommandRefused("gcloud: no subcommand given")
    # The verb is the last positional token: `gcloud alloydb instances describe X`
    # puts a resource name after it, so scan for any read verb in the chain.
    verbs = [a for a in args if a in GCLOUD_READ_VERBS or a.startswith(GCLOUD_READ_PREFIXES)]
    if not verbs:
        raise CommandRefused(
            f"gcloud {' '.join(args[:3])!r} is not a read command. Only describe, "
            "list, info, version and get-* are permitted."
        )
    # `gcloud ... delete` alongside a read verb must still be refused.
    forbidden = {
        "create", "delete", "update", "patch", "set", "add", "remove", "deploy",
        "apply", "scale", "resize", "restart", "start", "stop", "ssh", "scp",
        "enable", "disable", "import", "export", "migrate", "promote", "failover",
    }
    hit = forbidden.intersection(args)
    if hit:
        raise CommandRefused(f"gcloud: {sorted(hit)[0]!r} is a mutating verb")


def _check_gsutil(argv: list[str]) -> None:
    verb = next((a for a in argv[1:] if not a.startswith("-")), "")
    if verb not in GSUTIL_READ_VERBS:
        raise CommandRefused(
            f"gsutil '{verb or '(none)'}' is not a read verb. Allowed: "
            f"{', '.join(sorted(GSUTIL_READ_VERBS))}. `cat` and `cp` read object "
            f"CONTENTS, which may be anything — including credentials — so they "
            f"are refused even though they do not write."
        )


def _check_bq(argv: list[str]) -> None:
    verb = next((a for a in argv[1:] if not a.startswith("-")), "")
    if verb not in BQ_READ_VERBS:
        raise CommandRefused(
            f"bq '{verb or '(none)'}' is not a read verb. Allowed: "
            f"{', '.join(sorted(BQ_READ_VERBS))}. `query` is excluded because it "
            f"also executes DML and DDL, and this guard cannot tell those from a "
            f"SELECT. Use `bq head` to read rows, or the ClickHouse functions."
        )


def _check_curl(argv: list[str]) -> None:
    args = argv[1:]
    for i, a in enumerate(args):
        if a in ("-X", "--request"):
            method = (args[i + 1] if len(args) > i + 1 else "").upper()
            if method not in CURL_ALLOWED_METHODS:
                raise CommandRefused(
                    f"curl -X {method or '?'} is not permitted. GET and HEAD only."
                )
        if a.startswith(CURL_BODY_FLAGS):
            raise CommandRefused(
                f"curl {a.split('=')[0]!r} sends a request body, which makes this a "
                "write regardless of the method. GET and HEAD only."
            )
        if a.startswith("@") or a.startswith("file://"):
            raise CommandRefused("curl: local file access is not permitted")
    urls = [a for a in args if a.startswith(("http://", "https://"))]
    if not urls:
        raise CommandRefused("curl: an explicit http(s) URL is required")


def check(argv: list[str]) -> None:
    """Raise CommandRefused unless every guard passes."""
    if not argv:
        raise CommandRefused("empty command")
    if any(not isinstance(a, str) for a in argv):
        raise CommandRefused("command must be a list of strings")

    binary = argv[0].rsplit("/", 1)[-1]
    if binary not in ALLOWED_BINARIES:
        raise CommandRefused(
            f"{binary!r} is not an allowed binary. Allowed: "
            f"{', '.join(sorted(ALLOWED_BINARIES))}"
        )

    # Belt and braces. There is no shell, so these cannot compose anything — but
    # their presence means the model was *trying* to, which is worth refusing on.
    #
    # The psql statement is exempt and handled by _check_psql instead: `||` is
    # Postgres string concatenation and `;` is statement structure, so scanning
    # them as shell metacharacters rejects legitimate reads. A SQL argument needs
    # a SQL-aware check, not a shell-aware one.
    sql_stmt_index = argv.index("-c") + 1 if "-c" in argv and binary == "psql" else -1
    for i, a in enumerate(argv):
        if i == sql_stmt_index:
            continue
        if any(ch in a for ch in ("|", ";", "&&", "`", "$(", "\n")):
            raise CommandRefused(f"shell metacharacter in argument: {a[:40]!r}")

    match binary:
        case "kubectl":
            _check_kubectl(argv)
        case "redis-cli":
            _check_redis(argv)
        case "psql":
            _check_psql(argv)
        case "aws":
            _check_aws(argv)
        case "gcloud":
            _check_gcloud(argv)
        case "gsutil":
            _check_gsutil(argv)
        case "bq":
            _check_bq(argv)
        case "curl":
            _check_curl(argv)


async def run(argv: list[str], timeout_s: int = DEFAULT_TIMEOUT_S) -> tuple[bool, str]:
    """Execute an already-checked, already-human-confirmed command.

    Re-checks the guards first: this function must be safe to call even if a
    caller forgot, because "the caller validated it" is exactly the assumption
    that fails.
    """
    check(argv)
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError:
        return False, f"{argv[0]}: not found in this container"
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except TimeoutError:
        proc.kill()
        return False, f"timed out after {timeout_s}s"
    text = (out or b"")[:MAX_OUTPUT_BYTES].decode(errors="replace")
    return proc.returncode == 0, text
