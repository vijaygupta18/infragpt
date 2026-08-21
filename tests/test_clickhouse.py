"""ClickHouse executor tests — mocked HTTP, no network.

Nothing here touches a real warehouse. What is under test is the containment:
which statements can reach the server at all, that ``readonly=1`` is on every
request that does, and that the output handed back is bounded.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from app import config
from app.executors.base import ExecutorError
from app.executors.clickhouse import (
    MAX_TEXT_CHARS,
    ClickHouseExecutor,
    append_limit,
    assert_read_only,
    render_table,
)
from app.executors.dispatch import ExecutorRegistry, dispatch
from app.registry.loader import Registry, RegistryError, load_registry
from app.registry.readonly import NotReadOnly
from app.registry.readonly import assert_read_only as gate_assert_read_only
from app.registry.schema import RegistryEntry, Surface

REGISTRY_DIR = Path(__file__).resolve().parents[1] / "registry"


@pytest.fixture(scope="module")
def registry() -> Registry:
    return load_registry(REGISTRY_DIR)


class _FakeClient:
    """httpx.AsyncClient stand-in that records what was POSTed."""

    def __init__(self, response: httpx.Response | Exception | None = None) -> None:
        self._response = response
        self.calls: list[dict[str, Any]] = []

    async def post(self, url, params=None, content=None, headers=None, timeout=None):  # noqa: ANN001
        self.calls.append(
            {
                "url": url,
                "params": params,
                "content": content,
                "headers": headers,
                "timeout": timeout,
            }
        )
        if isinstance(self._response, Exception):
            raise self._response
        return self._response or _ok({"meta": [], "data": []})

    async def aclose(self) -> None:
        return None


def _ok(payload: dict[str, Any]) -> httpx.Response:
    return httpx.Response(
        200,
        content=json.dumps(payload).encode(),
        request=httpx.Request("POST", "http://clickhouse.invalid:8123"),
    )


def _entry(**kw: Any) -> RegistryEntry:
    base = {
        "name": "probe",
        "surface": "analytics",
        "kind": "clickhouse",
        "description": "d",
        "target": "ch_prod",
        "sql": "SELECT 1",
    }
    base.update(kw)
    return RegistryEntry.model_validate(base)


# ===========================================================================
# readonly=1 is sent on every request — the layer nothing in the registry
# can reach.
# ===========================================================================


@pytest.mark.asyncio
async def test_readonly_is_always_sent() -> None:
    client = _FakeClient(_ok({"meta": [{"name": "x"}], "data": [[1]]}))
    executor = ClickHouseExecutor(client=client)  # type: ignore[arg-type]
    result = await executor.run(_entry(), {}, "ch_prod")
    assert result.ok
    assert client.calls[0]["params"]["readonly"] == "1"


@pytest.mark.asyncio
async def test_readonly_is_the_last_setting_in_the_url() -> None:
    """ORDER MATTERS. ClickHouse applies query-string settings left to right and
    refuses to change any setting once readonly=1 has been applied — so bounds
    placed after it would fail every query with 'Cannot modify ... in readonly
    mode'."""
    client = _FakeClient()
    executor = ClickHouseExecutor(client=client)  # type: ignore[arg-type]
    await executor.run(_entry(), {}, "ch_prod")
    keys = list(client.calls[0]["params"])
    assert keys[-1] == "readonly"
    assert keys.index("max_execution_time") < keys.index("readonly")
    assert keys.index("max_result_rows") < keys.index("readonly")


@pytest.mark.asyncio
async def test_free_form_queries_are_also_sent_with_readonly() -> None:
    client = _FakeClient()
    executor = ClickHouseExecutor(client=client)  # type: ignore[arg-type]
    entry = _entry(
        kind="clickhousefree",
        sql=None,
        params={"sql": {"type": "statement", "required": True}},
    )
    await executor.run(entry, {"sql": "SELECT count() FROM rides"}, "ch_prod")
    assert client.calls[0]["params"]["readonly"] == "1"


@pytest.mark.asyncio
async def test_bounds_are_clamped_by_the_connection_not_the_entry() -> None:
    """An entry may narrow the connection's ceilings, never widen them."""
    client = _FakeClient()
    executor = ClickHouseExecutor(client=client)  # type: ignore[arg-type]
    conn = config.CLICKHOUSE_CONNECTIONS["ch_prod"]
    await executor.run(_entry(row_limit=999_999, timeout_s=30), {}, "ch_prod")
    params = client.calls[0]["params"]
    assert int(params["max_result_rows"]) <= conn.max_result_rows
    assert int(params["max_execution_time"]) <= conn.max_execution_time_s


@pytest.mark.asyncio
async def test_credentials_travel_in_headers_not_the_url() -> None:
    client = _FakeClient()
    executor = ClickHouseExecutor(client=client)  # type: ignore[arg-type]
    await executor.run(_entry(), {}, "ch_prod")
    call = client.calls[0]
    assert "X-ClickHouse-User" in call["headers"]
    assert "password" not in call["params"]
    assert "user" not in call["params"]


# ===========================================================================
# Write statements are refused — before anything is sent.
# ===========================================================================


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO rides VALUES (1)",
        "ALTER TABLE rides DELETE WHERE id = 1",
        "DROP TABLE rides",
        "TRUNCATE TABLE rides",
        "CREATE TABLE t (a Int)",
        "OPTIMIZE TABLE rides FINAL",
        "SYSTEM DROP MARK CACHE",
        "KILL QUERY WHERE query_id = 'x'",
        "SET max_threads = 1",
        "GRANT SELECT ON *.* TO bob",
        "ATTACH TABLE t",
        "RENAME TABLE a TO b",
    ],
)
def test_mutating_statements_are_refused(statement: str) -> None:
    with pytest.raises(ExecutorError, match="refused"):
        assert_read_only(statement)


def test_chained_statement_is_refused() -> None:
    with pytest.raises(ExecutorError, match="refused"):
        assert_read_only("SELECT 1; DROP TABLE rides")


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT * FROM url('http://evil.invalid/x', JSONEachRow)",
        "SELECT * FROM s3('https://b/x', 'CSV')",
        "SELECT * FROM file('/etc/passwd', 'CSV')",
        "SELECT * FROM remote('other:9000', system.tables)",
        "SELECT * FROM mysql('h:3306', 'db', 't', 'u', 'p')",
        "SELECT 1 INTO OUTFILE '/tmp/x'",
    ],
)
def test_statements_reaching_outside_the_warehouse_are_refused(statement: str) -> None:
    """readonly=1 blocks writes to tables. It does not stop a SELECT from making
    this process an outbound HTTP client or reading a local file."""
    with pytest.raises(ExecutorError, match="refused"):
        assert_read_only(statement)


def test_a_statement_may_not_relax_readonly() -> None:
    with pytest.raises(ExecutorError, match="readonly"):
        assert_read_only("SELECT 1 SETTINGS readonly=0")


def test_a_statement_may_not_choose_the_wire_format() -> None:
    with pytest.raises(ExecutorError, match="FORMAT"):
        assert_read_only("SELECT 1 FORMAT CSV")


def test_reads_are_allowed() -> None:
    for statement in (
        "SELECT count() FROM rides",
        "WITH x AS (SELECT 1) SELECT * FROM x",
        "SHOW TABLES",
        "DESCRIBE TABLE rides",
        "SELECT 'we do not drop tables' AS note",
    ):
        assert_read_only(statement)


@pytest.mark.asyncio
async def test_a_write_never_reaches_the_server() -> None:
    client = _FakeClient()
    executor = ClickHouseExecutor(client=client)  # type: ignore[arg-type]
    entry = _entry(
        kind="clickhousefree",
        sql=None,
        params={"sql": {"type": "statement", "required": True}},
    )
    with pytest.raises(ExecutorError, match="refused"):
        await executor.run(entry, {"sql": "DROP TABLE rides"}, "ch_prod")
    assert client.calls == []


@pytest.mark.asyncio
async def test_a_write_through_dispatch_is_refused_not_raised(registry: Registry) -> None:
    executors = ExecutorRegistry(
        clickhousefree=ClickHouseExecutor(client=_FakeClient()),  # type: ignore[arg-type]
    )
    result = await dispatch(
        "ch_query",
        {"sql": "ALTER TABLE rides DELETE WHERE 1"},
        granted_surfaces={Surface.ANALYTICS},
        registry=registry,
        executors=executors,
    )
    assert not result.ok
    assert "refused" in (result.error or "")


@pytest.mark.asyncio
async def test_the_analytics_grant_is_required(registry: Registry) -> None:
    result = await dispatch(
        "ch_query",
        {"sql": "SELECT 1"},
        granted_surfaces={Surface.DB_READ},
        registry=registry,
        executors=ExecutorRegistry(),
    )
    assert not result.ok
    assert "analytics" in (result.error or "")


# ===========================================================================
# Params are bound server-side, never interpolated.
# ===========================================================================


@pytest.mark.asyncio
async def test_params_are_sent_as_bind_values_not_spliced_in() -> None:
    client = _FakeClient()
    executor = ClickHouseExecutor(client=client)  # type: ignore[arg-type]
    entry = _entry(
        sql="SELECT name FROM system.tables WHERE database = {database:String}",
        params={"database": {"type": "identifier", "required": True}},
    )
    await executor.run(entry, {"database": "analytics"}, "ch_prod")
    call = client.calls[0]
    assert call["params"]["param_database"] == "analytics"
    assert b"{database:String}" in call["content"]
    assert b"analytics" not in call["content"]


@pytest.mark.asyncio
async def test_an_undeclared_bind_is_refused() -> None:
    executor = ClickHouseExecutor(client=_FakeClient())  # type: ignore[arg-type]
    entry = _entry(sql="SELECT * FROM system.tables WHERE database = {nope:String}")
    with pytest.raises(ExecutorError, match="undeclared"):
        await executor.run(entry, {}, "ch_prod")


# ===========================================================================
# Output is bounded.
# ===========================================================================


def test_a_limit_is_appended_when_absent() -> None:
    assert append_limit("SELECT 1", 50).endswith("LIMIT 50")


def test_an_existing_limit_is_not_doubled() -> None:
    assert append_limit("SELECT 1 LIMIT 5", 50).count("LIMIT") == 1


@pytest.mark.asyncio
async def test_rows_are_capped_at_the_entry_row_limit() -> None:
    payload = {"meta": [{"name": "n"}], "data": [[i] for i in range(500)]}
    executor = ClickHouseExecutor(client=_FakeClient(_ok(payload)))  # type: ignore[arg-type]
    result = await executor.run(_entry(row_limit=10), {}, "ch_prod")
    assert len(result.rows) == 10
    assert result.truncated


@pytest.mark.asyncio
async def test_rendered_text_is_bounded() -> None:
    payload = {
        "meta": [{"name": "blob"}],
        "data": [["x" * 5_000] for _ in range(500)],
    }
    executor = ClickHouseExecutor(client=_FakeClient(_ok(payload)))  # type: ignore[arg-type]
    result = await executor.run(_entry(row_limit=500), {}, "ch_prod")
    assert len(result.text) <= MAX_TEXT_CHARS + 1_000
    assert result.truncated


def test_render_table_truncates_wide_cells() -> None:
    text, _ = render_table(["c"], [["y" * 10_000]])
    assert "…" in text
    assert len(text) < 1_000


def test_render_table_shapes_a_compact_table() -> None:
    text, truncated = render_table(["a", "bb"], [[1, "x"], [2, "yy"]])
    assert not truncated
    assert text.splitlines()[0].startswith("a")
    assert len(text.splitlines()) == 4  # header, rule, two rows


# ===========================================================================
# The load-time gate.
# ===========================================================================


def test_the_shipped_clickhouse_entries_pass_the_gate(registry: Registry) -> None:
    entries = [
        e for e in registry.all_entries()
        if e.kind in ("clickhouse", "clickhousefree")
    ]
    assert len(entries) >= 5
    for entry in entries:
        gate_assert_read_only(entry)
        assert entry.surface is Surface.ANALYTICS
        assert entry.target in config.CLICKHOUSE_CONNECTIONS


def test_the_shipped_fixed_statements_pass_the_executor_check(
    registry: Registry,
) -> None:
    for entry in registry.all_entries():
        if entry.kind == "clickhouse":
            assert entry.sql is not None
            assert_read_only(entry.sql)


@pytest.mark.parametrize("sql", [
    "INSERT INTO rides VALUES (1)",
    "ALTER TABLE rides DELETE WHERE 1",
    "DROP TABLE rides",
    "OPTIMIZE TABLE rides",
    "SYSTEM RELOAD CONFIG",
])
def test_a_mutating_clickhouse_entry_stops_the_server_starting(sql: str) -> None:
    with pytest.raises(NotReadOnly):
        gate_assert_read_only(_entry(sql=sql))


def test_an_entry_reaching_a_remote_endpoint_is_refused_at_load() -> None:
    with pytest.raises(NotReadOnly, match="table function"):
        gate_assert_read_only(_entry(sql="SELECT * FROM url('http://x', JSON)"))


def test_a_free_form_entry_without_a_sql_param_is_refused_at_load() -> None:
    with pytest.raises(NotReadOnly, match="sql"):
        gate_assert_read_only(_entry(kind="clickhousefree", sql=None))


def test_a_free_form_entry_may_not_also_carry_a_statement() -> None:
    with pytest.raises(NotReadOnly):
        gate_assert_read_only(
            _entry(
                kind="clickhousefree",
                sql="SELECT 1",
                params={"sql": {"type": "statement"}},
            )
        )


def test_clickhouse_entries_may_not_sit_on_a_quieter_surface(tmp_path: Path) -> None:
    """A ClickHouse entry smuggled onto db:read would silently widen every
    existing db:read holder to the warehouse's business rows."""
    yaml_text = """
entries:
  - name: sneaky
    surface: db:read
    kind: clickhouse
    description: d
    target: ch_prod
    sql: SELECT 1
"""
    (tmp_path / "x.yaml").write_text(yaml_text)
    with pytest.raises(RegistryError, match="surface"):
        load_registry(tmp_path)


def test_an_unknown_clickhouse_target_is_refused_at_load(tmp_path: Path) -> None:
    yaml_text = """
entries:
  - name: elsewhere
    surface: analytics
    kind: clickhouse
    description: d
    target: some_other_cluster
    sql: SELECT 1
"""
    (tmp_path / "x.yaml").write_text(yaml_text)
    with pytest.raises(RegistryError, match="unknown connection"):
        load_registry(tmp_path)
