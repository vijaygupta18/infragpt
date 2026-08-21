"""Source-code reading, and the one property that has to hold: confinement.

The executor reads bytes from a clone on disk. There is no write, checkout or
execute path. What must be proven is that a caller-supplied path cannot escape
the clone root — including via a symlink, which a string check for ".." would
happily allow through.
"""

from __future__ import annotations

import pytest

from app import config
from app.executors.base import ExecutorError
from app.executors.code import _resolve_within, available_repos


@pytest.fixture
def tree(tmp_path, monkeypatch):
    root = tmp_path / "code"
    (root / "repo" / "sub").mkdir(parents=True)
    (root / "repo" / "sub" / "Thing.hs").write_text("module Thing where\nfoo = 1\n")
    (tmp_path / "outside.txt").write_text("SECRET")
    monkeypatch.setattr(config, "CODE_DIR", root)
    return root


def test_a_normal_path_resolves(tree) -> None:
    assert _resolve_within(tree, "repo/sub/Thing.hs").is_file()


@pytest.mark.parametrize("escape", [
    "../outside.txt",
    "repo/../../outside.txt",
    "repo/sub/../../../outside.txt",
    "/etc/passwd",
    "/data/infragpt.db",
])
def test_paths_leaving_the_root_are_refused(tree, escape: str) -> None:
    with pytest.raises(ExecutorError):
        _resolve_within(tree, escape)


def test_a_symlink_pointing_outside_is_refused(tree) -> None:
    """The reason confinement is enforced by RESOLUTION, not inspection.

    A string check for ".." passes this: the path contains no traversal at all.
    Only resolving it reveals where it actually lands — and a repository can
    contain a symlink like this.
    """
    (tree / "repo" / "escape").symlink_to(tree.parent / "outside.txt")
    with pytest.raises(ExecutorError, match="outside"):
        _resolve_within(tree, "repo/escape")


def test_a_symlink_staying_inside_is_allowed(tree) -> None:
    """Confinement must not break ordinary repository layouts — vendored
    directories and shared modules are commonly symlinked within a tree."""
    (tree / "repo" / "alias").symlink_to(tree / "repo" / "sub")
    assert _resolve_within(tree, "repo/alias/Thing.hs").is_file()


def test_an_absolute_path_is_refused_with_a_usable_message(tree) -> None:
    with pytest.raises(ExecutorError, match="relative"):
        _resolve_within(tree, "/etc/hosts")


def test_an_empty_path_is_refused(tree) -> None:
    with pytest.raises(ExecutorError):
        _resolve_within(tree, "")


def test_repos_are_listed_when_present(tree) -> None:
    names = [r["repo"] for r in available_repos()]
    assert names == ["repo"]


def test_a_missing_code_root_is_survivable(tmp_path, monkeypatch) -> None:
    """No clone yet must never raise into a question — code functions report
    'not cloned yet', which is honest and self-correcting."""
    monkeypatch.setattr(config, "CODE_DIR", tmp_path / "nope")
    assert available_repos() == []
