"""SQLite connection handling and migrations.

Single replica by design (see the plan's storage section): WAL mode, one process,
one connection guarded by a lock. No ORM — the schema is small and explicit, and
keeping it as plain DDL is what makes the SQLite -> Postgres escape hatch cheap.

Migrations are an ordered list of DDL statements. ``schema_version`` records how
many have been applied, so startup is idempotent: only the tail runs. Statements
already in the list must NEVER be edited in place — append a new one instead.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Append-only. Editing an existing entry silently skips it on deployed replicas.
MIGRATIONS: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        email         TEXT NOT NULL UNIQUE,
        name          TEXT NOT NULL DEFAULT '',
        status        TEXT NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'active', 'disabled')),
        created_at    TEXT NOT NULL,
        activated_at  TEXT,
        activated_by  TEXT,
        last_seen_at  TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS grants (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        surface     TEXT NOT NULL,
        granted_at  TEXT NOT NULL,
        granted_by  TEXT NOT NULL,
        expires_at  TEXT,
        UNIQUE (user_id, surface)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS cli_tokens (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash  TEXT NOT NULL UNIQUE,
        created_at  TEXT NOT NULL,
        expires_at  TEXT NOT NULL,
        revoked_at  TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS device_codes (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        device_code_hash  TEXT NOT NULL UNIQUE,
        user_code         TEXT NOT NULL UNIQUE,
        user_id           INTEGER REFERENCES users(id) ON DELETE CASCADE,
        status            TEXT NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending','approved','claimed','expired')),
        created_at        TEXT NOT NULL,
        expires_at        TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS conversations (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at  TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS messages (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        conversation_id  INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        role             TEXT NOT NULL,
        content          TEXT NOT NULL,
        created_at       TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_cli_tokens_user ON cli_tokens(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conversation_id)",
    # -- M5: rate limiting and token budgets (app/limits) --------------------
    # One row per rate-limited event. A sliding window is a COUNT over the last
    # N seconds, which needs the individual timestamps — a bucketed counter
    # would let a user spend a whole hour's quota in the last second of one
    # bucket and again in the first second of the next.
    """
    CREATE TABLE IF NOT EXISTS rate_events (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        kind     TEXT NOT NULL,
        ts       REAL NOT NULL
    )
    """,
    # Daily token spend, one row per user per UTC day.
    """
    CREATE TABLE IF NOT EXISTS token_usage (
        user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        day         TEXT NOT NULL,
        tokens_in   INTEGER NOT NULL DEFAULT 0,
        tokens_out  INTEGER NOT NULL DEFAULT 0,
        questions   INTEGER NOT NULL DEFAULT 0,
        updated_at  TEXT NOT NULL,
        PRIMARY KEY (user_id, day)
    )
    """,
    # Per-user budget override. Absent row = the process default applies.
    """
    CREATE TABLE IF NOT EXISTS token_budgets (
        user_id       INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        daily_tokens  INTEGER NOT NULL CHECK (daily_tokens >= 0),
        updated_at    TEXT NOT NULL,
        updated_by    TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_rate_events_lookup ON rate_events(user_id, kind, ts)",
    # Evidence, stored with the answer it supports.
    #
    # Until now the calls behind an answer existed only in the live response, so
    # reopening a conversation showed conclusions with nothing under them. For a
    # tool whose entire claim is "every statement traces to a command that ran",
    # provenance that disappears on reload is the one thing that must not happen.
    #
    # JSON in a TEXT column rather than a table: it is written once, read whole,
    # and never queried by field. A join would buy nothing.
    "ALTER TABLE messages ADD COLUMN evidence TEXT",
    # Self-registration: a password set by the user, hashed with scrypt.
    #
    # NULL for accounts that never set one (created by an SSO assertion or by an
    # admin). NULL must never verify — app/auth/passwords.verify returns False
    # for it — so an account without a password cannot be logged into, rather
    # than being logged into with an empty one.
    "ALTER TABLE users ADD COLUMN password_hash TEXT",
]


def utcnow() -> str:
    """Single source of 'now' so every timestamp in the DB is comparable."""
    return datetime.now(UTC).isoformat(timespec="seconds")


class Database:
    """Thin sqlite3 wrapper. One connection, one lock, WAL."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    # -- lifecycle ---------------------------------------------------------

    def connect(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        self._conn = conn
        return conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def migrate(self) -> int:
        """Apply any unapplied migrations. Returns the resulting version."""
        conn = self.connect()
        with self._lock:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_version ("
                "  version INTEGER NOT NULL,"
                "  applied_at TEXT NOT NULL)"
            )
            row = conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
            current = row["v"] or 0
            for idx, ddl in enumerate(MIGRATIONS[current:], start=current + 1):
                conn.execute(ddl)
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (idx, utcnow()),
                )
            conn.commit()
            return len(MIGRATIONS)

    # -- query helpers -----------------------------------------------------

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        with self._lock:
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        with self.tx() as conn:
            return conn.execute(sql, params)

    def query_one(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        conn = self.connect()
        with self._lock:
            return conn.execute(sql, params).fetchone()

    def query_all(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        conn = self.connect()
        with self._lock:
            return conn.execute(sql, params).fetchall()
