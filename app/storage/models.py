"""Row types for the SQLite layer.

Plain dataclasses, not an ORM. The schema is deliberately portable (SQLite ->
Postgres is a mechanical move) because the PV/RWO storage decision is one of the
accepted risks in the plan.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

UserStatus = Literal["pending", "active", "disabled"]
DeviceStatus = Literal["pending", "approved", "claimed", "expired"]


@dataclass(frozen=True)
class User:
    id: int
    email: str
    name: str
    status: UserStatus
    created_at: str
    activated_at: str | None = None
    activated_by: str | None = None
    last_seen_at: str | None = None
    #: scrypt hash for self-registered accounts; None where none was ever set.
    #: None never verifies — see app/auth/passwords.verify.
    password_hash: str | None = None

    @property
    def is_active(self) -> bool:
        return self.status == "active"


@dataclass(frozen=True)
class Grant:
    id: int
    user_id: int
    surface: str
    granted_at: str
    granted_by: str
    expires_at: str | None = None


@dataclass(frozen=True)
class CliToken:
    id: int
    user_id: int
    token_hash: str
    created_at: str
    expires_at: str
    revoked_at: str | None = None


@dataclass(frozen=True)
class DeviceCode:
    id: int
    device_code_hash: str
    user_code: str
    user_id: int | None
    status: DeviceStatus
    created_at: str
    expires_at: str


@dataclass(frozen=True)
class Conversation:
    id: int
    user_id: int
    created_at: str
    # First user message, populated by list_for_user so the sidebar can show
    # something recognisable instead of a timestamp. None on a fresh thread.
    title: str | None = None


@dataclass(frozen=True)
class Message:
    id: int
    conversation_id: int
    role: str
    content: str
    created_at: str
    # The calls this answer rests on, as stored JSON (a list of call records) or
    # None for user messages and for answers written before evidence was kept.
    # None and [] mean different things and must not be collapsed: None is "not
    # recorded", [] is "answered without running anything", which the UI flags.
    evidence: str | None = None
