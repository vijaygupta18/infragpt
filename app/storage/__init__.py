"""SQLite storage layer: users, grants, CLI tokens, device codes, conversations."""

from __future__ import annotations

from pathlib import Path

from app import config
from app.storage.db import MIGRATIONS, Database, utcnow
from app.storage.models import (
    CliToken,
    Conversation,
    DeviceCode,
    Grant,
    Message,
    User,
)
from app.storage.repo import (
    CliTokenRepo,
    ConversationRepo,
    DeviceCodeRepo,
    GrantRepo,
    Storage,
    UserRepo,
    hash_token,
)

__all__ = [
    "MIGRATIONS",
    "CliToken",
    "CliTokenRepo",
    "Conversation",
    "ConversationRepo",
    "Database",
    "DeviceCode",
    "DeviceCodeRepo",
    "Grant",
    "GrantRepo",
    "Message",
    "Storage",
    "User",
    "UserRepo",
    "get_storage",
    "hash_token",
    "init_storage",
    "utcnow",
]

_storage: Storage | None = None


def init_storage(path: Path | str | None = None) -> Storage:
    """Open the database and apply migrations. Called once at startup."""
    global _storage
    db = Database(path or config.DB_PATH)
    db.migrate()
    _storage = Storage(db)
    return _storage


def get_storage() -> Storage:
    """FastAPI dependency. Fails loudly rather than lazily opening a stray DB."""
    if _storage is None:
        raise RuntimeError("storage not initialised; call init_storage() at startup")
    return _storage
