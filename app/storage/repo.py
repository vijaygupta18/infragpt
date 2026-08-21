"""Repositories — typed access to every table.

Nothing outside this module writes SQL against the app database. Two rules that
hold throughout:

* Tokens are stored as sha256 hashes only. A raw CLI token or device code exists
  in memory and on the client's disk, never in a row.
* Reads never auto-elevate: a user's status and grants are returned as stored,
  and the authorization decision lives in ``app.auth.deps``.
"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta

from app.registry.schema import Surface
from app.storage.db import Database, utcnow
from app.storage.models import (
    CliToken,
    Conversation,
    DeviceCode,
    Grant,
    Message,
    User,
    UserStatus,
)


def hash_token(raw: str) -> str:
    """sha256 of a secret. The only representation that ever reaches storage."""
    return hashlib.sha256(raw.encode()).hexdigest()


def _iso_in(hours: float = 0, minutes: float = 0) -> str:
    return (datetime.now(UTC) + timedelta(hours=hours, minutes=minutes)).isoformat(
        timespec="seconds"
    )


def _expired(iso_ts: str | None) -> bool:
    if not iso_ts:
        return False
    try:
        return datetime.fromisoformat(iso_ts) <= datetime.now(UTC)
    except ValueError:
        return True


class UserRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    @staticmethod
    def _row(row: sqlite3.Row | None) -> User | None:
        if row is None:
            return None
        return User(
            id=row["id"],
            email=row["email"],
            name=row["name"],
            status=row["status"],
            created_at=row["created_at"],
            activated_at=row["activated_at"],
            activated_by=row["activated_by"],
            last_seen_at=row["last_seen_at"],
            password_hash=row["password_hash"],
        )

    def set_password(self, user_id: int, password_hash: str) -> None:
        """Store a scrypt hash. The caller hashes; this never sees a plaintext."""
        self.db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id)
        )

    def get_by_email(self, email: str) -> User | None:
        return self._row(
            self.db.query_one("SELECT * FROM users WHERE email = ?", (email.lower(),))
        )

    def get(self, user_id: int) -> User | None:
        return self._row(self.db.query_one("SELECT * FROM users WHERE id = ?", (user_id,)))

    def list_all(self) -> list[User]:
        rows = self.db.query_all("SELECT * FROM users ORDER BY created_at DESC")
        return [u for u in (self._row(r) for r in rows) if u is not None]

    def get_or_create(self, email: str, name: str = "") -> User:
        """First login creates a PENDING user. No access until an admin activates."""
        email = email.lower()
        existing = self.get_by_email(email)
        if existing is not None:
            return existing
        self.db.execute(
            "INSERT OR IGNORE INTO users (email, name, status, created_at) "
            "VALUES (?, ?, 'pending', ?)",
            (email, name, utcnow()),
        )
        created = self.get_by_email(email)
        if created is None:  # pragma: no cover - insert cannot silently vanish
            raise RuntimeError(f"failed to create user {email}")
        return created

    def set_status(self, user_id: int, status: UserStatus, actor_email: str) -> None:
        if status == "active":
            self.db.execute(
                "UPDATE users SET status = ?, activated_at = ?, activated_by = ? WHERE id = ?",
                (status, utcnow(), actor_email, user_id),
            )
        else:
            self.db.execute("UPDATE users SET status = ? WHERE id = ?", (status, user_id))

    def touch(self, user_id: int) -> None:
        self.db.execute("UPDATE users SET last_seen_at = ? WHERE id = ?", (utcnow(), user_id))


class GrantRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    def list_for_user(self, user_id: int) -> list[Grant]:
        rows = self.db.query_all("SELECT * FROM grants WHERE user_id = ?", (user_id,))
        return [
            Grant(
                id=r["id"],
                user_id=r["user_id"],
                surface=r["surface"],
                granted_at=r["granted_at"],
                granted_by=r["granted_by"],
                expires_at=r["expires_at"],
            )
            for r in rows
        ]

    def surfaces_for_user(self, user_id: int) -> set[str]:
        """Unexpired surfaces only. Expiry is enforced here, not by a sweeper."""
        return {g.surface for g in self.list_for_user(user_id) if not _expired(g.expires_at)}

    def has_surface(self, user_id: int, surface: Surface | str) -> bool:
        wanted = surface.value if isinstance(surface, Surface) else surface
        return wanted in self.surfaces_for_user(user_id)

    def grant(
        self,
        user_id: int,
        surface: Surface | str,
        granted_by: str,
        expires_at: str | None = None,
    ) -> None:
        value = surface.value if isinstance(surface, Surface) else surface
        if value not in {s.value for s in Surface}:
            raise ValueError(f"unknown surface: {value}")
        self.db.execute(
            "INSERT INTO grants (user_id, surface, granted_at, granted_by, expires_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(user_id, surface) DO UPDATE SET "
            "  granted_at = excluded.granted_at,"
            "  granted_by = excluded.granted_by,"
            "  expires_at = excluded.expires_at",
            (user_id, value, utcnow(), granted_by, expires_at),
        )

    def revoke(self, user_id: int, surface: Surface | str) -> None:
        value = surface.value if isinstance(surface, Surface) else surface
        self.db.execute(
            "DELETE FROM grants WHERE user_id = ? AND surface = ?", (user_id, value)
        )


class CliTokenRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    def issue(self, user_id: int, raw_token: str, ttl_hours: int) -> CliToken:
        token_hash = hash_token(raw_token)
        created, expires = utcnow(), _iso_in(hours=ttl_hours)
        self.db.execute(
            "INSERT INTO cli_tokens (user_id, token_hash, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (user_id, token_hash, created, expires),
        )
        row = self.db.query_one(
            "SELECT * FROM cli_tokens WHERE token_hash = ?", (token_hash,)
        )
        assert row is not None
        return CliToken(
            id=row["id"],
            user_id=row["user_id"],
            token_hash=row["token_hash"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            revoked_at=row["revoked_at"],
        )

    def resolve(self, raw_token: str) -> int | None:
        """Return the user_id for a live token, or None. Deny by default."""
        row = self.db.query_one(
            "SELECT * FROM cli_tokens WHERE token_hash = ?", (hash_token(raw_token),)
        )
        if row is None or row["revoked_at"] is not None:
            return None
        if _expired(row["expires_at"]):
            return None
        return int(row["user_id"])

    def revoke(self, raw_token: str) -> None:
        self.db.execute(
            "UPDATE cli_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
            (utcnow(), hash_token(raw_token)),
        )

    def revoke_all_for_user(self, user_id: int) -> None:
        self.db.execute(
            "UPDATE cli_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (utcnow(), user_id),
        )


class DeviceCodeRepo:
    """Device-code flow state. Codes are single-use and expire in 10 minutes."""

    TTL_MINUTES = 10

    def __init__(self, db: Database) -> None:
        self.db = db

    @staticmethod
    def _row(row: sqlite3.Row | None) -> DeviceCode | None:
        if row is None:
            return None
        return DeviceCode(
            id=row["id"],
            device_code_hash=row["device_code_hash"],
            user_code=row["user_code"],
            user_id=row["user_id"],
            status=row["status"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
        )

    def create(self, raw_device_code: str, user_code: str) -> DeviceCode:
        self.db.execute(
            "INSERT INTO device_codes (device_code_hash, user_code, status, created_at, "
            "expires_at) VALUES (?, ?, 'pending', ?, ?)",
            (
                hash_token(raw_device_code),
                user_code,
                utcnow(),
                _iso_in(minutes=self.TTL_MINUTES),
            ),
        )
        created = self._row(
            self.db.query_one(
                "SELECT * FROM device_codes WHERE device_code_hash = ?",
                (hash_token(raw_device_code),),
            )
        )
        assert created is not None
        return created

    def get_by_user_code(self, user_code: str) -> DeviceCode | None:
        return self._row(
            self.db.query_one(
                "SELECT * FROM device_codes WHERE user_code = ?", (user_code.upper(),)
            )
        )

    def get_by_device_code(self, raw_device_code: str) -> DeviceCode | None:
        return self._row(
            self.db.query_one(
                "SELECT * FROM device_codes WHERE device_code_hash = ?",
                (hash_token(raw_device_code),),
            )
        )

    def approve(self, user_code: str, user_id: int) -> bool:
        """Bind an authenticated identity to a pending code. False if unusable."""
        code = self.get_by_user_code(user_code)
        if code is None or code.status != "pending" or _expired(code.expires_at):
            return False
        self.db.execute(
            "UPDATE device_codes SET status = 'approved', user_id = ? "
            "WHERE id = ? AND status = 'pending'",
            (user_id, code.id),
        )
        return True

    def claim(self, raw_device_code: str) -> DeviceCode | None:
        """Single-use consumption of an approved code. None unless approved+live."""
        code = self.get_by_device_code(raw_device_code)
        if code is None or code.status != "approved" or _expired(code.expires_at):
            return None
        cur = self.db.execute(
            "UPDATE device_codes SET status = 'claimed' WHERE id = ? AND status = 'approved'",
            (code.id,),
        )
        if cur.rowcount != 1:  # lost a race with another poller
            return None
        return code

    def purge_expired(self) -> None:
        self.db.execute(
            "DELETE FROM device_codes WHERE expires_at <= ?", (utcnow(),)
        )


class ConversationRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, user_id: int) -> Conversation:
        cur = self.db.execute(
            "INSERT INTO conversations (user_id, created_at) VALUES (?, ?)",
            (user_id, utcnow()),
        )
        return Conversation(id=int(cur.lastrowid or 0), user_id=user_id, created_at=utcnow())

    def get(self, conversation_id: int) -> Conversation | None:
        row = self.db.query_one(
            "SELECT * FROM conversations WHERE id = ?", (conversation_id,)
        )
        if row is None:
            return None
        return Conversation(
            id=row["id"], user_id=row["user_id"], created_at=row["created_at"]
        )

    def list_for_user(self, user_id: int, limit: int = 50) -> list[Conversation]:
        """Recent conversations, each carrying its first question as a title.

        A sidebar of timestamps is unusable — you cannot find the conversation you
        want without opening several. The first user message is what people
        actually remember a thread by.
        """
        rows = self.db.query_all(
            """
            SELECT c.id, c.user_id, c.created_at,
                   (SELECT m.content FROM messages m
                     WHERE m.conversation_id = c.id AND m.role = 'user'
                     ORDER BY m.id LIMIT 1) AS title
            FROM conversations c
            WHERE c.user_id = ?
            ORDER BY c.id DESC
            LIMIT ?
            """,
            (user_id, limit),
        )
        return [
            Conversation(
                id=r["id"],
                user_id=r["user_id"],
                created_at=r["created_at"],
                title=(r["title"] or "").strip() or None,
            )
            for r in rows
        ]

    def delete(self, conversation_id: int, user_id: int) -> bool:
        """Delete a conversation and its messages. Scoped to the owner.

        The user_id is part of the WHERE clause rather than checked beforehand:
        a check-then-delete leaves a window, and more importantly it means a
        caller who forgets the check still cannot delete someone else's thread.
        Returns False when nothing matched — which covers both "no such
        conversation" and "not yours", deliberately indistinguishable.
        """
        row = self.db.query_one(
            "SELECT id FROM conversations WHERE id = ? AND user_id = ?",
            (conversation_id, user_id),
        )
        if row is None:
            return False
        self.db.execute("DELETE FROM messages WHERE conversation_id = ?", (conversation_id,))
        self.db.execute(
            "DELETE FROM conversations WHERE id = ? AND user_id = ?",
            (conversation_id, user_id),
        )
        return True

    def add_message(
        self,
        conversation_id: int,
        role: str,
        content: str,
        evidence: str | None = None,
    ) -> Message:
        """Store one message, and for an answer the evidence it rests on.

        ``evidence`` is the JSON list of calls. It is stored with the answer so
        that reopening a conversation shows what was actually run — an answer
        whose provenance is only in the live response is unverifiable five
        minutes later.
        """
        cur = self.db.execute(
            "INSERT INTO messages (conversation_id, role, content, created_at, evidence) "
            "VALUES (?, ?, ?, ?, ?)",
            (conversation_id, role, content, utcnow(), evidence),
        )
        return Message(
            id=int(cur.lastrowid or 0),
            conversation_id=conversation_id,
            role=role,
            content=content,
            created_at=utcnow(),
            evidence=evidence,
        )

    def messages(self, conversation_id: int) -> list[Message]:
        rows = self.db.query_all(
            "SELECT * FROM messages WHERE conversation_id = ? ORDER BY id", (conversation_id,)
        )
        return [
            Message(
                id=r["id"],
                conversation_id=r["conversation_id"],
                role=r["role"],
                content=r["content"],
                created_at=r["created_at"],
                evidence=r["evidence"],
            )
            for r in rows
        ]


class Storage:
    """Aggregate handle: one object to pass around, one per process."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self.users = UserRepo(db)
        self.grants = GrantRepo(db)
        self.tokens = CliTokenRepo(db)
        self.device_codes = DeviceCodeRepo(db)
        self.conversations = ConversationRepo(db)
