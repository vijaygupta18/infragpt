"""Registry schema — the core contract of infragpt.

Everything the assistant can execute is declared here as data. The LLM's entire
output surface is ``{function_name, params}``; it never authors a command.

Two invariants that the rest of the codebase depends on:

1. The executor MUST NOT run any string that did not originate from a registry
   entry loaded through this module.
2. Every parameter reaching an executor MUST have passed ``ParamSpec.validate``.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class Surface(StrEnum):
    """Grant-bearing capability domains. A user holds zero or more."""

    K8S_GCP = "k8s:gcp"
    K8S_AWS = "k8s:aws"
    METRICS = "metrics"
    LOGS = "logs"
    DB_READ = "db:read"
    # Curated business-row lookups — the "why is this driver stuck" class of
    # ticket, which db:read deliberately cannot answer. Separate from db:read
    # because it returns real people's data: needing database metadata to debug
    # a slow reader is not a reason to be able to read driver records.
    DB_ENTITY = "db:entity"
    REDIS_READ = "redis:read"
    # ClickHouse — the analytics warehouse. This is BUSINESS DATA (rides,
    # bookings, events), not infrastructure metadata, which is why it is its own
    # surface rather than part of db:read: needing to debug a slow reader is not
    # a reason to be able to read ride history. Held by the `analyst` role, which
    # is deliberately off the viewer -> engineer ladder.
    ANALYTICS = "analytics"
    # Cloud control-plane (Monitoring / AlloyDB Admin / CloudWatch). Public
    # endpoints with IAM auth, so these work without a VPC route — which is often
    # exactly what is broken during an incident.
    CLOUD_GCP = "cloud:gcp"
    CLOUD_AWS = "cloud:aws"
    # Composes read-only commands rather than choosing registered ones. In no
    # role by default: it is the widest grant in the system, and the only one
    # whose safety rests on the pod's credentials rather than on a narrow,
    # reviewed catalogue.
    SHELL_READ = "shell:read"
    ADMIN = "admin"


class Cloud(StrEnum):
    GCP = "gcp"
    AWS = "aws"


class ParamType(StrEnum):
    STRING = "string"          # free text, length-capped, no shell metachars
    IDENTIFIER = "identifier"  # SQL/redis identifier; validated against catalogue
    UUID = "uuid"
    INT = "int"
    ENUM = "enum"
    DURATION = "duration"      # e.g. 30m, 2h, 7d
    KEY = "key"                # redis key pattern; no globs unless allow_glob
    # Free text that legitimately contains characters the generic shell-metachar
    # screen rejects — a SQL statement needs `;`, `'`, `$`; a command needs
    # quotes and `=`. NOT unvalidated: these are checked by something that
    # understands the language (app/shell/guard.py for commands, the SQL guard
    # for statements), which is a stronger check than a character blocklist.
    # Screening them here only produced "contains forbidden character" on
    # perfectly valid commands, with no way for the model to comply.
    STATEMENT = "statement"


# Characters that must never survive validation on any string-ish param.
_SHELL_METACHARS = re.compile(r"[;&|`$><\n\r\\]")
_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
_DURATION_RE = re.compile(r"^\d{1,4}[smhd]$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_KEY_RE = re.compile(r"^[a-zA-Z0-9_:.\-{}]{1,256}$")


class ParamValidationError(ValueError):
    """Raised when a param fails validation. Never repaired — always rejected."""


class ParamSpec(BaseModel):
    type: ParamType
    required: bool = True
    values: list[str] | None = None        # for ENUM
    default: Any | None = None
    max_length: int = 256
    min: int | None = None                 # for INT
    max: int | None = None
    allow_glob: bool = False               # for KEY
    description: str = ""

    def validate_value(self, name: str, raw: Any) -> Any:
        """Validate and coerce a single parameter.

        Rejects outright on any mismatch. Never coerces a bad value into a good
        one — a malformed param from the LLM is a rejected call, not a repaired
        one.
        """
        if raw is None:
            if self.required:
                raise ParamValidationError(f"{name}: required")
            return self.default

        if self.type is ParamType.INT:
            try:
                val = int(raw)
            except (TypeError, ValueError):
                raise ParamValidationError(f"{name}: not an integer") from None
            if self.min is not None and val < self.min:
                raise ParamValidationError(f"{name}: below min {self.min}")
            if self.max is not None and val > self.max:
                raise ParamValidationError(f"{name}: above max {self.max}")
            return val

        if not isinstance(raw, str):
            raise ParamValidationError(f"{name}: expected string, got {type(raw).__name__}")
        if len(raw) > self.max_length:
            raise ParamValidationError(f"{name}: exceeds max_length {self.max_length}")

        # Applies to every string-ish type, including ENUM members — EXCEPT
        # STATEMENT, where these characters are part of the language rather than
        # an attack. A SQL statement needs `;` and `'`; a command needs quotes.
        # Those are validated by something that parses them properly, which
        # catches strictly more than a character blocklist does.
        if self.type is not ParamType.STATEMENT and _SHELL_METACHARS.search(raw):
            raise ParamValidationError(f"{name}: contains forbidden character")

        match self.type:
            case ParamType.ENUM:
                if not self.values or raw not in self.values:
                    raise ParamValidationError(f"{name}: not in {self.values}")
            case ParamType.IDENTIFIER:
                # Shape check only. Existence is verified against pg_catalog by
                # the DB executor before the query runs — a regex is not enough.
                if not _IDENTIFIER_RE.match(raw):
                    raise ParamValidationError(f"{name}: not a valid identifier")
            case ParamType.UUID:
                if not _UUID_RE.match(raw):
                    raise ParamValidationError(f"{name}: not a valid uuid")
            case ParamType.DURATION:
                if not _DURATION_RE.match(raw):
                    raise ParamValidationError(f"{name}: not a duration (e.g. 30m, 2h)")
            case ParamType.KEY:
                if not _KEY_RE.match(raw):
                    raise ParamValidationError(f"{name}: not a valid redis key")
                if "*" in raw and not self.allow_glob:
                    raise ParamValidationError(f"{name}: globs not permitted")
            case ParamType.STRING | ParamType.STATEMENT:
                # STATEMENT is checked by a language-aware guard downstream, not
                # here. See the note on ParamType.STATEMENT.
                pass

        return raw


class RegistryEntry(BaseModel):
    """One executable capability. Reviewed in git; never created at runtime."""

    name: str
    surface: Surface
    kind: Literal[
        "sql", "redis", "kubectl", "promql",
        "gcpmetric", "gcpalloydb", "gcpmetricsearch", "gcpmetricquery",
        "awsmetric", "awselasticache", "mcp", "shell", "sqlfree", "vmmeta",
        "gcpinsights",
        # ClickHouse, split the same way sql/sqlfree is: `clickhouse` carries a
        # reviewed statement, `clickhousefree` takes the statement as a param.
        "clickhouse", "clickhousefree",
    ]
    description: str                       # shown to the LLM — make it precise
    params: dict[str, ParamSpec] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)   # e.g. pii, heavy

    # Execution target: a *named* connection. The LLM never supplies a host.
    target: str

    # Exactly one of these is set, per `kind`.
    sql: str | None = None
    redis_op: str | None = None            # exists|ttl|get|smembers|type|hgetall|...
    argv: list[str] | None = None          # kubectl, as argv — never a shell string
    promql: str | None = None
    metric: str | None = None              # gcp/aws metric: metric type or name
    namespace: str | None = None           # awsmetric: CloudWatch namespace
    # mcp: the ONE tool name this entry may invoke on the MCP server. The
    # executor refuses any tool not named by a loaded entry, so a server that
    # ships new tools never widens what infragpt can call.
    mcp_tool: str | None = None
    # Reviewed ALTERNATE names for the same tool.
    #
    # MCP servers name the same capability differently and rename across
    # versions — `promql_query` here is `query` there and `vm_query_range`
    # somewhere else. Without this, one rename silently removes a capability
    # mid-incident, with the model unable to do anything about it.
    #
    # This does NOT widen what can be called: every name here is written in the
    # registry and reviewed like any other, and the executor still refuses
    # anything not declared. It resolves against the tools the server actually
    # advertises and calls the first declared name that exists.
    mcp_tool_aliases: list[str] = Field(default_factory=list)
    # Structured argument template for an MCP tool, with "$param" placeholders
    # filled from VALIDATED params.
    #
    # Needed because real servers take structured arguments, not flat strings:
    # the log server's search takes an index plus an Elasticsearch Query DSL
    # object. Without a template the only options are to send flat params the
    # server rejects, or to let the model author the JSON body — and letting it
    # author the call is exactly what this registry exists to prevent.
    #
    # Substitution is by whole value: a string that is exactly "$name" becomes
    # that param's value. It never splices text, so a param cannot inject
    # structure into the surrounding object.
    mcp_arguments: dict[str, Any] | None = None

    row_limit: int = 100
    timeout_s: int = 20

    @field_validator("name")
    @classmethod
    def _name_shape(cls, v: str) -> str:
        if not _IDENTIFIER_RE.match(v):
            raise ValueError(f"registry entry name must be an identifier: {v}")
        return v

    def validate_params(self, supplied: dict[str, Any]) -> dict[str, Any]:
        """Validate every supplied param; reject unknown ones."""
        unknown = set(supplied) - set(self.params)
        if unknown:
            raise ParamValidationError(f"unknown params: {sorted(unknown)}")
        return {
            name: spec.validate_value(name, supplied.get(name))
            for name, spec in self.params.items()
        }

    def llm_tool_spec(self) -> dict[str, Any]:
        """JSON-schema view handed to the Grid selector call."""
        props: dict[str, Any] = {}
        required: list[str] = []
        for pname, spec in self.params.items():
            prop: dict[str, Any] = {"description": spec.description}
            if spec.type is ParamType.ENUM:
                prop["type"] = "string"
                prop["enum"] = spec.values or []
            elif spec.type is ParamType.INT:
                prop["type"] = "integer"
            else:
                prop["type"] = "string"
            props[pname] = prop
            if spec.required:
                required.append(pname)
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": props,
                "required": required,
            },
        }
