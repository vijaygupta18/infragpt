"""Registry loader — turns reviewed YAML into RegistryEntry objects.

Two things make this file load-bearing:

1. **It fails loudly.** A registry that does not fully validate raises at import
   time, so the server does not start. A half-valid registry is worse than no
   server: it looks like it works, and the entry that silently dropped is the
   one someone will need at 3am.
2. **It is the only source of executable strings.** Executors accept a
   RegistryEntry, never raw SQL/argv from a caller. Anything not loaded here is
   not runnable, which is the containment property the whole design rests on.

Target templating
-----------------
``target`` is either a literal named connection (``metrics``) or a template over
validated enum params (``$db``, ``redis_$cloud``, ``k8s_$cloud``). At load time
every possible expansion is enumerated across the enum members and each one must
resolve to a connection declared in ``app.config`` — so an unresolvable target is
a startup failure, not a runtime 500.
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path
from typing import Any

import yaml

from app import config
from app.registry.readonly import assert_read_only
from app.registry.schema import ParamType, RegistryEntry, Surface

# ``$name`` slots in target / argv / promql templates.
PLACEHOLDER_RE = re.compile(r"\$([a-zA-Z_][a-zA-Z0-9_]*)")

# ``:name`` bind params in SQL. The lookbehind keeps ``::type`` casts out.
BIND_PARAM_RE = re.compile(r"(?<![:\w]):([a-zA-Z_][a-zA-Z0-9_]*)")

# Exactly one payload field must be set, keyed by kind.
_PAYLOAD_FIELD: dict[str, str] = {
    "sql": "sql",
    "redis": "redis_op",
    "kubectl": "argv",
    "promql": "promql",
    "gcpmetric": "metric",
    # The AlloyDB inventory call takes no payload — the entry name IS the
    # operation, so there is nothing to template.
    "gcpalloydb": "",
    "gcpmetricsearch": "",
    "gcpmetricquery": "",
    "awsmetric": "metric",
    # The endpoint NAME, resolved against a fixed table in the executor. Not a
    # URL — the registry never carries one.
    "vmmeta": "metric",
    # Names which per-query insights metric to read; the aggregation shape is
    # fixed in the executor because getting it wrong returns an empty result
    # that reads as "no slow queries".
    "gcpinsights": "metric",
    # The operation name (read/search/find/repos); paths and queries are params.
    "code": "metric",
    "awselasticache": "",
    # The command is a PARAM, not a field on the entry — so there is nothing to
    # validate at load time. app/shell/guard.py checks every command at
    # execution, and the pod's read-only credentials sit underneath that.
    "shell": "",
    # Same as shell: the statement is a PARAM, so there is no payload field to
    # validate at load. The read-only SQL guard runs on the supplied statement
    # at execution, which is the same check a fixed entry gets.
    "sqlfree": "",
    "mcp": "mcp_tool",
    # Mirrors sql/sqlfree: a reviewed ClickHouse entry carries its statement,
    # a free-form one takes it as a param and so has no payload to validate at
    # load. Both are re-checked by app/executors/clickhouse.assert_read_only on
    # the way out, and both run under readonly=1.
    "clickhouse": "sql",
    "clickhousefree": "",
}

# The single named metrics connection. Unlike pg/redis/k8s there is only one.
METRICS_TARGET = "metrics"


class RegistryError(RuntimeError):
    """Raised when the registry itself is invalid. Always fatal at startup."""


def _known_targets(kind: str) -> set[str]:
    match kind:
        case "sql" | "sqlfree":
            return set(config.PG_CONNECTIONS)
        case "redis":
            return set(config.REDIS_CONNECTIONS)
        case "kubectl":
            return set(config.K8S_CONNECTIONS)
        case "promql" | "vmmeta":
            return {METRICS_TARGET}
        case "code":
            return {"local"}
        case "gcpmetric" | "gcpalloydb" | "gcpmetricsearch" | "gcpmetricquery" | "gcpinsights":
            return set(config.GCP_CONNECTIONS)
        case "awsmetric" | "awselasticache":
            return set(config.AWS_CONNECTIONS)
        case "shell":
            # Runs in this container, so there is no remote connection to name.
            return {"local"}
        case "mcp":
            return set(config.MCP_CONNECTIONS)
        case "clickhouse" | "clickhousefree":
            return set(config.CLICKHOUSE_CONNECTIONS)
    raise RegistryError(f"unknown kind: {kind}")


def _template_slots(template: str) -> list[str]:
    return PLACEHOLDER_RE.findall(template)


def _expand_target(entry: RegistryEntry) -> set[str]:
    """Every connection name this entry could ever resolve to."""
    slots = _template_slots(entry.target)
    if not slots:
        return {entry.target}

    choices: list[list[str]] = []
    for slot in slots:
        spec = entry.params.get(slot)
        if spec is None:
            raise RegistryError(
                f"{entry.name}: target references undeclared param '{slot}'"
            )
        if spec.type is not ParamType.ENUM or not spec.values:
            raise RegistryError(
                f"{entry.name}: target slot '{slot}' must be an enum param so every "
                f"expansion can be checked at load time"
            )
        choices.append(list(spec.values))

    expansions: set[str] = set()
    for combo in itertools.product(*choices):
        mapping = dict(zip(slots, combo, strict=True))
        expansions.add(_substitute(entry.target, mapping))
    return expansions


def _substitute(template: str, values: dict[str, Any]) -> str:
    def repl(m: re.Match[str]) -> str:
        return str(values[m.group(1)])

    return PLACEHOLDER_RE.sub(repl, template)


def _check_entry(entry: RegistryEntry) -> None:
    """Structural validation beyond what pydantic can express."""
    # --- kind must match the populated payload field -------------------------
    populated = {
        field
        for field in ("sql", "redis_op", "argv", "promql", "metric", "mcp_tool")
        if getattr(entry, field) not in (None, "", [])
    }
    expected = _PAYLOAD_FIELD[entry.kind]
    if expected == "":
        if populated:
            raise RegistryError(
                f"{entry.name}: kind '{entry.kind}' takes no payload field, "
                f"found {sorted(populated)}"
            )
    elif populated != {expected}:
        raise RegistryError(
            f"{entry.name}: kind '{entry.kind}' requires exactly '{expected}' to be "
            f"set, found {sorted(populated) or 'nothing'}"
        )

    # --- the entry must be provably read-only --------------------------------
    # Runs at LOAD time, so a mutating entry stops the server from starting
    # rather than surfacing as a refused call mid-incident.
    assert_read_only(entry)

    # --- surface must be consistent with kind --------------------------------
    _check_surface(entry)

    # --- target must resolve to a real named connection ----------------------
    known = _known_targets(entry.kind)
    for resolved in _expand_target(entry):
        if resolved not in known:
            raise RegistryError(
                f"{entry.name}: target '{entry.target}' resolves to unknown "
                f"connection '{resolved}' (known: {sorted(known)})"
            )

    # --- every slot / bind param must be a declared param --------------------
    if entry.kind == "sql":
        assert entry.sql is not None
        referenced = set(BIND_PARAM_RE.findall(entry.sql))
        undeclared = referenced - set(entry.params)
        if undeclared:
            raise RegistryError(
                f"{entry.name}: SQL binds undeclared params {sorted(undeclared)}"
            )
        if PLACEHOLDER_RE.search(entry.sql):
            raise RegistryError(
                f"{entry.name}: SQL contains a '$' template slot. SQL parameters must "
                f"be bound (:name), never interpolated."
            )
    elif entry.kind == "clickhouse":
        assert entry.sql is not None
        # ClickHouse binds server-side with `{name:Type}` rather than `:name`,
        # and the executor sends each as `param_<name>`. An undeclared one could
        # never be supplied, so it is a startup failure, not a runtime one.
        from app.executors.clickhouse import BIND_RE as CH_BIND_RE

        undeclared = set(CH_BIND_RE.findall(entry.sql)) - set(entry.params)
        if undeclared:
            raise RegistryError(
                f"{entry.name}: SQL binds undeclared params {sorted(undeclared)}"
            )
        if PLACEHOLDER_RE.search(entry.sql):
            raise RegistryError(
                f"{entry.name}: SQL contains a '$' template slot. ClickHouse "
                f"parameters must be bound ({{name:Type}}), never interpolated."
            )
    elif entry.kind == "kubectl":
        assert entry.argv is not None
        for element in entry.argv:
            for slot in _template_slots(element):
                if slot not in entry.params:
                    raise RegistryError(
                        f"{entry.name}: argv references undeclared param '{slot}'"
                    )
    elif entry.kind == "promql":
        assert entry.promql is not None
        for slot in _template_slots(entry.promql):
            if slot not in entry.params:
                raise RegistryError(
                    f"{entry.name}: promql references undeclared param '{slot}'"
                )

    # --- bounds --------------------------------------------------------------
    if entry.timeout_s <= 0 or entry.timeout_s > config.DEFAULT_TIMEOUT_S:
        raise RegistryError(
            f"{entry.name}: timeout_s must be in 1..{config.DEFAULT_TIMEOUT_S}"
        )
    if entry.row_limit <= 0:
        raise RegistryError(f"{entry.name}: row_limit must be positive")

    # --- enum params must actually declare members ---------------------------
    for pname, spec in entry.params.items():
        if spec.type is ParamType.ENUM and not spec.values:
            raise RegistryError(f"{entry.name}: enum param '{pname}' declares no values")
        if spec.type is ParamType.KEY and spec.allow_glob:
            raise RegistryError(
                f"{entry.name}: param '{pname}' allows globs. Glob keys are not "
                f"permitted — they are how KEYS-shaped scans get reintroduced."
            )
        if spec.default is not None:
            # A default must itself be valid, or it is a validation bypass.
            spec.validate_value(pname, spec.default)


def _check_surface(entry: RegistryEntry) -> None:
    expected_by_kind: dict[str, set[Surface]] = {
        # db:entity shares the sql kind but not the surface's scope: those
        # entries are fixed, single-subject and separately granted. sqlfree is
        # deliberately NOT allowed on db:entity — free-form SQL over business
        # rows is the thing the split exists to prevent.
        "sql": {Surface.DB_READ, Surface.DB_ENTITY},
        "redis": {Surface.REDIS_READ},
        "kubectl": {Surface.K8S_GCP, Surface.K8S_AWS},
        "promql": {Surface.METRICS},
        "vmmeta": {Surface.METRICS},
        "gcpmetric": {Surface.CLOUD_GCP},
        "gcpalloydb": {Surface.CLOUD_GCP},
        "gcpmetricsearch": {Surface.CLOUD_GCP},
        "gcpmetricquery": {Surface.CLOUD_GCP},
        "gcpinsights": {Surface.CLOUD_GCP},
        "code": {Surface.CODE},
        "awsmetric": {Surface.CLOUD_AWS},
        "awselasticache": {Surface.CLOUD_AWS},
        "shell": {Surface.SHELL_READ},
        "sqlfree": {Surface.DB_READ},
        # Business data, not infrastructure metadata — its own grant, held only
        # by the analyst role. See Surface.ANALYTICS.
        "clickhouse": {Surface.ANALYTICS},
        "clickhousefree": {Surface.ANALYTICS},
        # An MCP entry reads either logs or metrics; the grant follows the data
        # it returns, not the transport it arrives over.
        "mcp": {Surface.LOGS, Surface.METRICS},
    }
    if entry.surface not in expected_by_kind[entry.kind]:
        raise RegistryError(
            f"{entry.name}: surface '{entry.surface.value}' is not valid for kind "
            f"'{entry.kind}'"
        )
    if entry.kind == "kubectl":
        spec = entry.params.get("cloud")
        if spec is None or spec.type is not ParamType.ENUM or not spec.values:
            raise RegistryError(
                f"{entry.name}: kubectl entries must declare a 'cloud' enum param — "
                f"it selects both the context and the required grant"
            )
    if entry.kind == "mcp":
        # Logs and metrics differ per cloud, and an answer that does not say
        # which cloud it read is worse than no answer.
        spec = entry.params.get("cloud")
        if spec is None or spec.type is not ParamType.ENUM or not spec.values:
            raise RegistryError(
                f"{entry.name}: mcp entries must declare a 'cloud' enum param — "
                f"it selects which cloud's MCP server is queried"
            )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class Registry:
    """An immutable, validated catalogue of everything the system can run."""

    def __init__(self, entries: list[RegistryEntry]) -> None:
        self._by_name: dict[str, RegistryEntry] = {}
        for entry in entries:
            if entry.name in self._by_name:
                raise RegistryError(f"duplicate registry entry name: {entry.name}")
            self._by_name[entry.name] = entry

    def __len__(self) -> int:
        return len(self._by_name)

    def all_entries(self) -> list[RegistryEntry]:
        return list(self._by_name.values())

    def names(self) -> list[str]:
        return sorted(self._by_name)

    def get(self, name: str) -> RegistryEntry:
        try:
            return self._by_name[name]
        except KeyError:
            raise KeyError(f"no such registry function: {name}") from None

    def entries_for_surfaces(self, surfaces: set[Surface]) -> list[RegistryEntry]:
        """Entries the holder of `surfaces` may call.

        ADMIN is not a wildcard — it grants the admin API, not every data
        surface — so it is deliberately not expanded here.

        kubectl entries carry a nominal surface but their *effective* surface
        depends on the `cloud` param, so an entry is offered when the caller
        holds either k8s grant and the specific one is re-checked at dispatch
        against `required_surface`.
        """
        offered: list[RegistryEntry] = []
        for entry in self._by_name.values():
            if entry.kind == "kubectl":
                if surfaces & {Surface.K8S_GCP, Surface.K8S_AWS}:
                    offered.append(entry)
            elif entry.surface in surfaces:
                offered.append(entry)
        return offered

    def llm_tool_specs(self, surfaces: set[Surface]) -> list[dict[str, Any]]:
        """Tool schemas for the selector call — only what the caller may run.

        The LLM cannot propose a function it is not permitted to call, because
        it is never shown one. Execution re-checks anyway.
        """
        return [e.llm_tool_spec() for e in self.entries_for_surfaces(surfaces)]


def required_surface(entry: RegistryEntry, params: dict[str, Any]) -> Surface:
    """The grant a caller must hold to run this entry *with these params*.

    For kubectl this is cloud-dependent: the same function reads GKE prod or EKS
    prod, and those are separate grants.
    """
    if entry.kind == "kubectl":
        cloud = params.get("cloud")
        if cloud == "aws":
            return Surface.K8S_AWS
        if cloud == "gcp":
            return Surface.K8S_GCP
        raise RegistryError(f"{entry.name}: unresolvable cloud param {cloud!r}")
    return entry.surface


def resolve_target(entry: RegistryEntry, params: dict[str, Any]) -> str:
    """Resolve the entry's target template against validated params.

    Params must already have passed ``RegistryEntry.validate_params``; this
    function assumes typed, bounded values and re-checks only that the result is
    a known connection.
    """
    slots = _template_slots(entry.target)
    missing = [s for s in slots if params.get(s) is None]
    if missing:
        raise RegistryError(f"{entry.name}: cannot resolve target, missing {missing}")
    resolved = _substitute(entry.target, params)
    if resolved not in _known_targets(entry.kind):
        raise RegistryError(f"{entry.name}: resolved unknown target '{resolved}'")
    return resolved


def _inject_namespaces(item: dict[str, Any]) -> None:
    """Resolve the `$NAMESPACES` placeholder from config at load time.

    The registry YAML ships inside the published image, so it must not name any
    deployment's namespaces. Entries declare the placeholder and the real values
    arrive from INFRAGPT_NAMESPACES via the ConfigMap.

    With none configured the enum is empty, which pydantic rejects — so a
    misconfigured deployment fails to start rather than starting with a
    kubectl surface that can reach nothing and reports it as "no pods found".
    """
    params = item.get("params")
    if not isinstance(params, dict):
        return
    spec = params.get("namespace")
    if not isinstance(spec, dict):
        return
    if spec.get("values") == "$NAMESPACES":
        spec["values"] = list(config.NAMESPACES)
    if spec.get("default") == "$NAMESPACE_DEFAULT":
        spec["default"] = config.NAMESPACES[0] if config.NAMESPACES else None


def load_registry(directory: Path | None = None) -> Registry:
    """Load and validate every YAML file in `directory`. Raises on any problem."""
    directory = Path(directory or config.REGISTRY_DIR)
    if not directory.is_dir():
        raise RegistryError(f"registry directory not found: {directory}")

    entries: list[RegistryEntry] = []
    files = sorted(p for p in directory.iterdir() if p.suffix in (".yaml", ".yml"))
    if not files:
        raise RegistryError(f"registry directory contains no YAML: {directory}")

    for path in files:
        raw = yaml.safe_load(path.read_text()) or {}
        if isinstance(raw, dict):
            raw_entries = raw.get("entries", [])
        elif isinstance(raw, list):
            raw_entries = raw
        else:
            raise RegistryError(f"{path}: expected a mapping or a list at the top level")
        if not isinstance(raw_entries, list):
            raise RegistryError(f"{path}: 'entries' must be a list")

        for item in raw_entries:
            if not isinstance(item, dict):
                raise RegistryError(f"{path}: each entry must be a mapping")
            _inject_namespaces(item)
            name = item.get("name", "<unnamed>")
            try:
                entry = RegistryEntry.model_validate(item)
            except Exception as exc:  # noqa: BLE001 - re-raised as fatal
                raise RegistryError(f"{path}: entry '{name}' is invalid: {exc}") from exc
            if entry.sql:
                # Trailing semicolons break LIMIT appending; normalise once here.
                entry.sql = entry.sql.strip().rstrip(";").strip()
            try:
                _check_entry(entry)
            except RegistryError as exc:
                raise RegistryError(f"{path}: {exc}") from exc
            entries.append(entry)

    return Registry(entries)


_REGISTRY: Registry | None = None


def get_registry(directory: Path | None = None, *, reload: bool = False) -> Registry:
    """Process-wide singleton. Loaded once at startup; a bad registry is fatal."""
    global _REGISTRY
    if _REGISTRY is None or reload:
        _REGISTRY = load_registry(directory)
    return _REGISTRY


# Convenience module-level accessors mirroring the brief's API.
def unavailable_surfaces() -> set[Surface]:
    """Surfaces whose backing connection is not configured in this deployment.

    Offering a function that is certain to fail is worse than not offering it:
    it burns the per-question call budget, and the model reads the failure as a
    fact about production rather than about configuration. Observed live — every
    k8s:aws call returned `context "arn:aws:eks:..." does not exist` because the
    kubeconfig for the remote cluster is absent, so half of every cross-cloud
    question was wasted.
    """
    from app.executors.k8s import IN_CLUSTER, KUBECONFIG_PATH

    out: set[Surface] = set()
    aws = config.K8S_CONNECTIONS.get("k8s_aws")
    if aws is not None:
        needs_kubeconfig = bool(aws.context) and aws.context != IN_CLUSTER
        if needs_kubeconfig and not Path(KUBECONFIG_PATH).exists():
            out.add(Surface.K8S_AWS)
    return out


def all_entries() -> list[RegistryEntry]:
    return get_registry().all_entries()


def get(name: str) -> RegistryEntry:
    return get_registry().get(name)


def entries_for_surfaces(surfaces: set[Surface]) -> list[RegistryEntry]:
    return get_registry().entries_for_surfaces(surfaces)


def llm_tool_specs(surfaces: set[Surface]) -> list[dict[str, Any]]:
    return get_registry().llm_tool_specs(surfaces)


__all__ = [
    "METRICS_TARGET",
    "Registry",
    "RegistryError",
    "all_entries",
    "entries_for_surfaces",
    "get",
    "get_registry",
    "llm_tool_specs",
    "load_registry",
    "required_surface",
    "resolve_target",
]
