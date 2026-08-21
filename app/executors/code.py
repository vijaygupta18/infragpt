"""Source code reading — the layer that answers WHY.

Metrics say what is failing. Logs say where. Neither says why, and the answer to
"why" is usually in the code: which handler raised, what that error constant
means, which write path a flow takes. Every root cause in this project's own
history came from reading source — a cross-cloud cache bug that was one function
call choosing the wrong write path, an error string that only made sense next to
its definition.

WHAT THIS IS. Read-only access to shallow clones of PUBLIC repositories, kept on
the data volume. No credentials are involved: the repositories are open source,
which is what makes this cheap and uncontroversial.

WHAT IT IS NOT. There is no write path, no checkout, no branch switching, no
running of anything found in the tree. The executor reads bytes and returns
them.

PATH CONFINEMENT is the only interesting safety property, and it is enforced by
resolution rather than by inspection: every path is resolved to an absolute real
path and must still be under the clone root afterwards. That catches `..`,
absolute paths, and symlinks pointing out of the tree — including a symlink
committed to a repository specifically to escape, which a string check for ".."
would happily allow.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from app import config
from app.executors.base import MAX_OUTPUT_BYTES, ExecResult, Executor, ExecutorError
from app.registry.schema import RegistryEntry

#: Extensions worth searching. A source tree carries lock files, vendored
#: dependencies and generated artefacts that bury real matches — and a match in
#: a 40,000-line generated file is noise, not evidence.
SEARCHABLE = (
    ".hs", ".purs", ".py", ".sql", ".yaml", ".yml", ".json", ".dhall",
    ".ts", ".tsx", ".js", ".sh", ".md", ".toml", ".cabal", ".nix",
)

#: Never searched or listed. Not a security boundary — a signal-to-noise one.
SKIP_DIRS = (
    ".git", "node_modules", "dist", "build", "target", ".stack-work",
    "dist-newstyle", "__pycache__", ".mypy_cache", "vendor", "result",
)


def code_root() -> Path:
    return Path(config.CODE_DIR)


def _resolve_within(root: Path, candidate: str) -> Path:
    """Resolve a caller-supplied path and prove it stays inside the root.

    Resolution first, check second. Checking the string for ".." before
    resolving would pass a symlink that points outside the tree — and a
    repository can contain one.
    """
    if not candidate or candidate.startswith("/"):
        raise ExecutorError(
            "path must be relative to a repository root, e.g. "
            "'<repo>/path/to/file'"
        )
    root_real = root.resolve()
    target = (root_real / candidate).resolve()
    if target != root_real and root_real not in target.parents:
        raise ExecutorError(
            f"refused: '{candidate}' resolves outside the code root. Only files "
            f"inside the cloned repositories are readable."
        )
    return target


def available_repos() -> list[dict[str, str]]:
    """Which repositories are present, and at which commit."""
    root = code_root()
    if not root.exists():
        return []
    out: list[dict[str, str]] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        head = entry / ".git" / "HEAD"
        commit = ""
        try:
            raw = head.read_text().strip() if head.exists() else ""
            if raw.startswith("ref: "):
                ref = entry / ".git" / raw[5:]
                commit = ref.read_text().strip()[:12] if ref.exists() else ""
            else:
                commit = raw[:12]
        except OSError:
            commit = ""
        out.append({"repo": entry.name, "commit": commit or "unknown"})
    return out


def _not_ready() -> ExecutorError:
    return ExecutorError(
        "the source clones are not present yet. They are fetched on startup and "
        "a large repository takes a few minutes. This says nothing about the "
        "code — retry shortly, or answer from metrics and logs and say the "
        "source was unavailable."
    )


class CodeExecutor(Executor):
    kind = "code"

    async def run(
        self, entry: RegistryEntry, params: dict[str, Any], target: str
    ) -> ExecResult:
        op = entry.metric or ""
        root = code_root()
        started = self._timed()

        if op == "repos":
            repos = available_repos()
            text = (
                "\n".join(f"{r['repo']}  @{r['commit']}" for r in repos)
                if repos
                else "(no repositories cloned yet)"
            )
            return ExecResult(
                ok=True, entry_name=entry.name, target=target,
                rows=repos, text=text,
                duration_ms=int((self._timed() - started) * 1000),
            )

        if not root.exists() or not any(root.iterdir()):
            raise _not_ready()

        if op == "read":
            return await self._read(entry, params, target, root, started)
        if op == "search":
            return await self._search(entry, params, target, root, started)
        if op == "find":
            return await self._find(entry, params, target, root, started)
        raise ExecutorError(f"{entry.name}: unknown code operation '{op}'")

    async def _read(self, entry, params, target, root, started) -> ExecResult:  # noqa: ANN001
        path = _resolve_within(root, str(params.get("file") or ""))
        if not path.is_file():
            raise ExecutorError(
                f"no such file: {params.get('file')}. Use code_find to locate it "
                f"— the path is relative to the code root and includes the "
                f"repository name."
            )
        start = max(1, int(params.get("start") or 1))
        count = min(int(params.get("lines") or 200), 400)
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError as exc:
            raise ExecutorError(f"could not read {params.get('file')}: {exc}") from exc

        window = lines[start - 1 : start - 1 + count]
        body = "\n".join(f"{start + i:>6}  {line}" for i, line in enumerate(window))
        note = ""
        if start - 1 + count < len(lines):
            note = (
                f"\n… {len(lines) - (start - 1 + count)} more lines. "
                f"Re-read with start={start + count} to continue."
            )
        return ExecResult(
            ok=True, entry_name=entry.name, target=target,
            rows=[{"file": str(path.relative_to(root.resolve())), "lines": len(lines)}],
            text=f"{path.relative_to(root.resolve())} ({len(lines)} lines)\n{body}{note}",
            duration_ms=int((self._timed() - started) * 1000),
        )

    async def _search(self, entry, params, target, root, started) -> ExecResult:  # noqa: ANN001
        query = str(params.get("query") or "").strip()
        if not query:
            raise ExecutorError("query is required")
        scope = str(params.get("path") or "").strip()
        base = _resolve_within(root, scope) if scope else root.resolve()

        # grep, via argv — no shell, so no substitution or globbing. -F when the
        # caller asked for a literal, which is the common case and avoids a
        # regex error on a string containing brackets.
        argv = ["grep", "-rn", "--binary-files=without-match"]
        for skip in SKIP_DIRS:
            argv += [f"--exclude-dir={skip}"]
        if params.get("regex"):
            argv += ["-E"]
        else:
            argv += ["-F"]
        ext = str(params.get("ext") or "").strip().lstrip(".")
        if ext:
            argv += [f"--include=*.{ext}"]
        argv += ["--", query, str(base)]

        limit = min(int(params.get("limit") or 40), 200)
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            raw, _ = await asyncio.wait_for(proc.communicate(), timeout=entry.timeout_s)
        except TimeoutError:
            raise ExecutorError(
                f"search timed out after {entry.timeout_s}s. Narrow it with a "
                f"`path` prefix or an `ext` filter — the tree is large."
            ) from None
        except FileNotFoundError as exc:
            raise ExecutorError("grep is not available in this container") from exc

        prefix = str(root.resolve()) + "/"
        hits = [
            line.replace(prefix, "", 1)
            for line in raw.decode(errors="replace").splitlines()
            if line.strip()
        ]
        shown, truncated = hits[:limit], len(hits) > limit
        text = "\n".join(shown) if shown else (
            f"no matches for {query!r}"
            + (f" under {scope}" if scope else "")
            + ". This means the text is absent, NOT that the behaviour is — try "
            "a shorter fragment, a different casing, or regex=true."
        )
        if truncated:
            text += f"\n… {len(hits) - limit} more matches. Narrow with path= or ext=."
        return ExecResult(
            ok=True, entry_name=entry.name, target=target,
            rows=[{"match": h} for h in shown],
            text=text[:MAX_OUTPUT_BYTES],
            truncated=truncated,
            duration_ms=int((self._timed() - started) * 1000),
        )

    async def _find(self, entry, params, target, root, started) -> ExecResult:  # noqa: ANN001
        pattern = str(params.get("name") or "").strip()
        if not pattern:
            raise ExecutorError("name is required, e.g. 'DriverInformation.hs'")
        limit = min(int(params.get("limit") or 40), 200)
        matches: list[str] = []
        root_real = root.resolve()
        for dirpath, dirnames, filenames in os.walk(root_real):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if pattern.lower() in name.lower():
                    matches.append(str(Path(dirpath, name).relative_to(root_real)))
                    if len(matches) >= limit * 3:
                        break
            if len(matches) >= limit * 3:
                break
        shown = sorted(matches)[:limit]
        text = "\n".join(shown) if shown else (
            f"no file matching {pattern!r}. The match is a case-insensitive "
            f"substring of the FILE NAME, not a path."
        )
        return ExecResult(
            ok=True, entry_name=entry.name, target=target,
            rows=[{"file": f} for f in shown], text=text,
            truncated=len(matches) > len(shown),
            duration_ms=int((self._timed() - started) * 1000),
        )
