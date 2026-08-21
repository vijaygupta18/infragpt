"""Executor contract.

Every executor takes a *validated* registry entry plus validated params and
returns an ExecResult. Executors are the only place in the system that talk to
infrastructure, and they may only do so read-only.

Enforcement layering (all four must hold independently):
  1. Registry     — only declared capabilities exist.
  2. Validation   — params are typed and bounded before they get here.
  3. Executor     — op allowlists, timeouts, row/output caps (this file's kin).
  4. Credentials  — the RO Postgres role / read-only k8s ServiceAccount.

Layer 4 is the one that actually protects production. The others reduce blast
radius and make misuse visible; only credentials make mutation impossible.
"""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

MAX_OUTPUT_BYTES = 1_000_000


@dataclass
class ExecResult:
    ok: bool
    entry_name: str
    target: str
    rows: list[dict[str, Any]] = field(default_factory=list)
    text: str = ""
    error: str | None = None
    truncated: bool = False
    duration_ms: int = 0
    # Populated by the redactor; the audit trail records whether it ran.
    redacted: bool = False

    def cap_output(self) -> None:
        if len(self.text.encode()) > MAX_OUTPUT_BYTES:
            self.text = self.text.encode()[:MAX_OUTPUT_BYTES].decode(errors="ignore")
            self.truncated = True


class ExecutorError(RuntimeError):
    """Raised for infrastructure failures. Never swallowed — surfaced to the
    user verbatim, because an assistant that hides a failed call will answer
    from model memory instead, which is the worst possible failure mode."""


class Executor(ABC):
    kind: str

    @abstractmethod
    async def run(self, entry: Any, params: dict[str, Any], target: str) -> ExecResult:
        """Execute a registry entry. `entry` is a RegistryEntry; `params` have
        already passed RegistryEntry.validate_params."""

    @staticmethod
    def _timed() -> float:
        return time.monotonic()


def safe_exception_text(exc: BaseException, limit: int = 200) -> str:
    """Exception text with anything credential-shaped removed.

    An HTTP client raised `Illegal header value b'<the actual password>'`, and
    that string went into an ExecutorError — which is surfaced to the user, sent
    to the model, and written to the audit log. The failure was a trailing
    newline in a secret; the consequence was the secret in three places it must
    never be.

    So exception text from a layer that has seen a credential is never trusted
    verbatim. Byte-literals and anything after an auth-ish key are dropped, and
    the type name is always kept because that is the part that aids diagnosis.
    """
    text = str(exc)
    # b'...' — how httpx reports an offending header value.
    text = re.sub(r"b['\"][^'\"]*['\"]", "b'<redacted>'", text)
    # key=value / key: value where the key looks like a credential.
    # The optional scheme matters: `Authorization: Bearer <token>` would
    # otherwise stop at "Bearer" and leave the token in the clear.
    text = re.sub(
        r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|"
        r"x-clickhouse-key)\b\s*[:=]\s*(?:bearer|basic|token)?\s*\S+",
        r"\1=<redacted>",
        text,
    )
    text = text.strip().splitlines()[0] if text.strip() else ""
    return f"{type(exc).__name__}: {text[:limit]}" if text else type(exc).__name__
