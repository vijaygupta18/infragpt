"""Storage layer tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.registry.schema import Surface
from app.storage import Database, Storage, hash_token
from app.storage.db import MIGRATIONS


@pytest.fixture()
def storage(tmp_path) -> Storage:
    db = Database(tmp_path / "test.db")
    db.migrate()
    return Storage(db)


def _iso(**delta) -> str:
    return (datetime.now(UTC) + timedelta(**delta)).isoformat(timespec="seconds")


def test_migrations_are_idempotent(tmp_path) -> None:
    db = Database(tmp_path / "m.db")
    assert db.migrate() == len(MIGRATIONS)
    assert db.migrate() == len(MIGRATIONS)
    rows = db.query_all("SELECT version FROM schema_version ORDER BY version")
    assert [r["version"] for r in rows] == list(range(1, len(MIGRATIONS) + 1))


def test_wal_mode_enabled(storage: Storage) -> None:
    row = storage.db.query_one("PRAGMA journal_mode")
    assert row[0].lower() == "wal"


def test_first_login_creates_pending_user(storage: Storage) -> None:
    user = storage.users.get_or_create("Ops.Person@example.com", "Ops Person")
    assert user.email == "ops.person@example.com"  # normalised
    assert user.status == "pending"
    assert not user.is_active
    # Idempotent: a second login must not create a second row or reset status.
    storage.users.set_status(user.id, "active", "admin@example.com")
    again = storage.users.get_or_create("ops.person@example.com")
    assert again.id == user.id
    assert again.status == "active"
    assert again.activated_by == "admin@example.com"


def test_grants_deny_by_default(storage: Storage) -> None:
    user = storage.users.get_or_create("a@example.com")
    assert storage.grants.surfaces_for_user(user.id) == set()
    assert not storage.grants.has_surface(user.id, Surface.DB_READ)

    storage.grants.grant(user.id, Surface.DB_READ, "admin@example.com")
    assert storage.grants.has_surface(user.id, Surface.DB_READ)
    assert not storage.grants.has_surface(user.id, Surface.ADMIN)

    storage.grants.revoke(user.id, Surface.DB_READ)
    assert not storage.grants.has_surface(user.id, Surface.DB_READ)


def test_expired_grant_is_not_effective(storage: Storage) -> None:
    user = storage.users.get_or_create("b@example.com")
    storage.grants.grant(user.id, Surface.METRICS, "admin", expires_at=_iso(hours=-1))
    assert not storage.grants.has_surface(user.id, Surface.METRICS)
    storage.grants.grant(user.id, Surface.METRICS, "admin", expires_at=_iso(hours=1))
    assert storage.grants.has_surface(user.id, Surface.METRICS)


def test_unknown_surface_rejected(storage: Storage) -> None:
    user = storage.users.get_or_create("c@example.com")
    with pytest.raises(ValueError):
        storage.grants.grant(user.id, "k8s:azure", "admin")


def test_tokens_stored_only_as_hashes(storage: Storage) -> None:
    user = storage.users.get_or_create("d@example.com")
    raw = "nyc_super_secret_value"  # noqa: S105 - fixture, not a real credential
    storage.tokens.issue(user.id, raw, ttl_hours=12)

    rows = storage.db.query_all("SELECT token_hash FROM cli_tokens")
    assert [r["token_hash"] for r in rows] == [hash_token(raw)]
    assert all(raw not in r["token_hash"] for r in rows)
    assert storage.tokens.resolve(raw) == user.id
    assert storage.tokens.resolve("nyc_wrong") is None


def test_token_revocation_and_expiry(storage: Storage) -> None:
    user = storage.users.get_or_create("e@example.com")
    raw = "nyc_live"  # noqa: S105
    storage.tokens.issue(user.id, raw, ttl_hours=12)
    storage.tokens.revoke(raw)
    assert storage.tokens.resolve(raw) is None

    expired = "nyc_expired"  # noqa: S105
    storage.tokens.issue(user.id, expired, ttl_hours=-1)
    assert storage.tokens.resolve(expired) is None


def test_device_code_is_single_use(storage: Storage) -> None:
    user = storage.users.get_or_create("f@example.com")
    device_code, user_code = "dev-code-1", "AAAA-BBBB"
    storage.device_codes.create(device_code, user_code)

    # Not approved yet -> cannot be claimed.
    assert storage.device_codes.claim(device_code) is None
    assert storage.device_codes.approve(user_code, user.id)
    claimed = storage.device_codes.claim(device_code)
    assert claimed is not None and claimed.user_id == user.id
    # Second claim of the same code must fail.
    assert storage.device_codes.claim(device_code) is None
    # And re-approving a consumed code must fail too.
    assert not storage.device_codes.approve(user_code, user.id)


def test_device_code_stored_hashed(storage: Storage) -> None:
    storage.device_codes.create("raw-device-code", "CCCC-DDDD")
    rows = storage.db.query_all("SELECT device_code_hash FROM device_codes")
    assert rows[0]["device_code_hash"] == hash_token("raw-device-code")


def test_conversations_and_messages(storage: Storage) -> None:
    user = storage.users.get_or_create("g@example.com")
    conv = storage.conversations.create(user.id)
    storage.conversations.add_message(conv.id, "user", "why is the reader slow?")
    storage.conversations.add_message(conv.id, "assistant", "checking top_queries")
    msgs = storage.conversations.messages(conv.id)
    assert [m.role for m in msgs] == ["user", "assistant"]
    assert [c.id for c in storage.conversations.list_for_user(user.id)] == [conv.id]
