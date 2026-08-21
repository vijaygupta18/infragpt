"""Runbook parsing and retrieval."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

from app.runbooks import load_runbooks

REPO_RUNBOOKS = Path(__file__).resolve().parent.parent / "runbooks"


def _write(tmp_path: Path, name: str, front: str, body: str) -> None:
    (tmp_path / name).write_text(f"---\n{front}\n---\n{body}\n", encoding="utf-8")


def test_shipped_runbooks_all_parse() -> None:
    store = load_runbooks(REPO_RUNBOOKS)
    assert len(store) >= 6
    for rb in store.all():
        assert rb.name
        assert rb.body
        assert rb.functions, f"{rb.name} declares no functions"
        assert rb.keywords, f"{rb.name} declares no keywords"


def test_shipped_runbooks_reference_real_registry_functions() -> None:
    """A runbook pointing at a function that doesn't exist teaches the selector
    to hallucinate a tool name."""
    from app.registry.loader import load_registry

    registry = load_registry(Path(__file__).resolve().parent.parent / "registry")
    known = set(registry.names())
    for rb in load_runbooks(REPO_RUNBOOKS).all():
        unknown = [f for f in rb.functions if f not in known]
        assert not unknown, f"{rb.name} references unknown functions: {unknown}"


def test_shipped_runbooks_are_not_stale() -> None:
    for rb in load_runbooks(REPO_RUNBOOKS).all():
        assert not rb.is_stale, f"{rb.name} is past its review date"


def test_retrieval_prefers_keyword_match(tmp_path: Path) -> None:
    _write(tmp_path, "a.md", "name: Redis staleness\nkeywords: ['cache stale']", "redis body")
    _write(tmp_path, "b.md", "name: Table growth\nkeywords: ['table size']", "disk body")
    store = load_runbooks(tmp_path)
    hits = store.retrieve("why is the cache stale")
    assert hits and hits[0].name == "Redis staleness"


def test_no_match_returns_nothing(tmp_path: Path) -> None:
    _write(tmp_path, "a.md", "name: Redis\nkeywords: ['cache stale']", "body")
    assert load_runbooks(tmp_path).retrieve("unrelated aardvark question") == []


def test_stale_runbook_is_deprioritised_but_kept(tmp_path: Path) -> None:
    old = (date.today() - timedelta(days=400)).isoformat()
    new = date.today().isoformat()
    _write(tmp_path, "old.md", f"name: Old\nkeywords: ['pod pending']\nreviewed_on: {old}", "x")
    _write(tmp_path, "new.md", f"name: New\nkeywords: ['pod pending']\nreviewed_on: {new}", "x")
    store = load_runbooks(tmp_path)
    hits = store.retrieve("pod pending")
    assert [h.name for h in hits] == ["New", "Old"]
    assert len(store.stale()) == 1


def test_context_flags_stale_runbooks(tmp_path: Path) -> None:
    old = (date.today() - timedelta(days=400)).isoformat()
    _write(tmp_path, "old.md", f"name: Old\nkeywords: ['pod pending']\nreviewed_on: {old}", "x")
    assert "STALE" in load_runbooks(tmp_path).context_for("pod pending")


def test_missing_directory_is_empty_not_an_error(tmp_path: Path) -> None:
    assert len(load_runbooks(tmp_path / "nope")) == 0


def test_file_without_frontmatter_still_loads(tmp_path: Path) -> None:
    (tmp_path / "plain.md").write_text("just prose about pods", encoding="utf-8")
    store = load_runbooks(tmp_path)
    assert len(store) == 1
    assert store.all()[0].name == "plain"
