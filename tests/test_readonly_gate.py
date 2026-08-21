"""The load-time read-only gate.

Every case here is a mutating entry that must stop the SERVER FROM STARTING.
That is the point: a refused call at 3am is a worse failure than a deploy that
never happened.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.registry.loader import RegistryError, load_registry
from app.registry.readonly import NotReadOnly, assert_read_only
from app.registry.schema import RegistryEntry

REGISTRY_DIR = Path(__file__).resolve().parents[1] / "registry"


def entry(**kw) -> RegistryEntry:
    base = {
        "name": "probe", "surface": "db:read", "kind": "sql",
        "description": "d", "target": "driver_ro",
    }
    base.update(kw)
    return RegistryEntry.model_validate(base)


def test_the_shipped_registry_passes_the_gate() -> None:
    """If this ever fails, something mutating was merged."""
    registry = load_registry(REGISTRY_DIR)
    for e in registry.all_entries():
        assert_read_only(e)


# ---- SQL --------------------------------------------------------------------


@pytest.mark.parametrize("sql", [
    "UPDATE person SET blocked = true",
    "DELETE FROM booking",
    "DROP TABLE ride",
    "INSERT INTO x VALUES (1)",
    "TRUNCATE x",
    "CREATE INDEX i ON t (c)",
    "GRANT SELECT ON x TO y",
    "SELECT pg_terminate_backend(123)",
])
def test_mutating_sql_is_refused(sql: str) -> None:
    with pytest.raises(NotReadOnly):
        assert_read_only(entry(sql=sql))


def test_chained_sql_is_refused() -> None:
    with pytest.raises(NotReadOnly):
        assert_read_only(entry(sql="SELECT 1; DROP TABLE ride"))


def test_select_mentioning_a_verb_in_a_literal_is_allowed() -> None:
    """A query about the word 'delete' is not a delete."""
    assert_read_only(entry(sql="SELECT 'delete' FROM pg_class"))


# ---- Redis ------------------------------------------------------------------


@pytest.mark.parametrize("op", ["set", "del", "flushall", "expire", "keys",
                                "scan", "randomkey", "rename", "migrate"])
def test_forbidden_redis_ops_are_refused(op: str) -> None:
    with pytest.raises(NotReadOnly):
        assert_read_only(entry(kind="redis", surface="redis:read",
                               redis_op=op, target="redis_gcp"))


def test_unknown_redis_op_fails_closed() -> None:
    """Not on the allowlist is refused, even if it is harmless."""
    with pytest.raises(NotReadOnly, match="not on the read allowlist"):
        assert_read_only(entry(kind="redis", surface="redis:read",
                               redis_op="wait", target="redis_gcp"))


# ---- kubectl ----------------------------------------------------------------


@pytest.mark.parametrize("verb", ["delete", "apply", "patch", "scale", "exec",
                                  "port-forward", "cp", "edit", "drain"])
def test_mutating_kubectl_verbs_are_refused(verb: str) -> None:
    with pytest.raises(NotReadOnly):
        assert_read_only(entry(kind="kubectl", surface="k8s:gcp",
                               argv=[verb, "pods"], target="k8s_gcp"))


@pytest.mark.parametrize("resource", ["secret", "secrets", "configmap",
                                      "configmaps", "serviceaccount"])
def test_credential_bearing_resources_are_refused_even_for_get(resource: str) -> None:
    """Read-only is not the same as safe to read."""
    with pytest.raises(NotReadOnly, match="credentials"):
        assert_read_only(entry(kind="kubectl", surface="k8s:gcp",
                               argv=["get", resource], target="k8s_gcp"))


# ---- MCP --------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["delete_index", "create_dashboard",
                                  "update_alert", "silence_alert", "reindex"])
def test_mutating_mcp_tools_are_refused(tool: str) -> None:
    with pytest.raises(NotReadOnly):
        assert_read_only(entry(kind="mcp", surface="logs",
                               mcp_tool=tool, target="opensearch_gcp"))


# ---- fail closed ------------------------------------------------------------


def test_an_unknown_kind_fails_closed(monkeypatch) -> None:
    """A new kind must be reasoned about here before it can ship."""
    e = entry()
    object.__setattr__(e, "kind", "some_new_transport")
    with pytest.raises(NotReadOnly, match="no read-only proof"):
        assert_read_only(e)


def test_a_mutating_entry_stops_the_registry_loading(tmp_path: Path) -> None:
    """End to end: the server does not start, rather than refusing a call later."""
    (tmp_path / "bad.yaml").write_text(
        "entries:\n"
        "  - name: bad_entry\n"
        "    surface: db:read\n"
        "    kind: sql\n"
        "    description: looks fine\n"
        "    target: driver_ro\n"
        "    params:\n"
        "      db: {type: enum, required: true, values: [driver_ro, rider_ro],\n"
        "           description: db}\n"
        "    sql: DELETE FROM booking WHERE id = :db\n",
        encoding="utf-8",
    )
    with pytest.raises((RegistryError, NotReadOnly)):
        load_registry(tmp_path)
