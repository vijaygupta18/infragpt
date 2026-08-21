"""Admin routes — user activation, grants, audit viewing.

Every route requires the ``admin`` surface. Note what is absent: there is no
endpoint that writes to any infrastructure, and no endpoint that reads a user's
raw tokens. Admin power stops at infragpt's own account model.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.access.roles import BY_KEY, ROLES
from app.audit import read_audit
from app.auth.deps import Principal, require_admin
from app.registry.schema import Surface
from app.storage import Storage, get_storage

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])


class UserOut(BaseModel):
    id: int
    email: str
    name: str
    status: str
    created_at: str
    activated_at: str | None = None
    activated_by: str | None = None
    last_seen_at: str | None = None
    grants: list[str] = Field(default_factory=list)


class GrantRequest(BaseModel):
    surface: Surface
    expires_at: str | None = None


def _user_out(storage: Storage, user_id: int) -> UserOut:
    user = storage.users.get(user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such user")
    return UserOut(
        id=user.id,
        email=user.email,
        name=user.name,
        status=user.status,
        created_at=user.created_at,
        activated_at=user.activated_at,
        activated_by=user.activated_by,
        last_seen_at=user.last_seen_at,
        grants=sorted(storage.grants.surfaces_for_user(user.id)),
    )


@router.get("/users", response_model=list[UserOut])
async def list_users(storage: Annotated[Storage, Depends(get_storage)]) -> list[UserOut]:
    return [_user_out(storage, u.id) for u in storage.users.list_all()]


@router.get("/users/{user_id}", response_model=UserOut)
async def get_user(
    user_id: int, storage: Annotated[Storage, Depends(get_storage)]
) -> UserOut:
    return _user_out(storage, user_id)


@router.post("/users/{user_id}/activate", response_model=UserOut)
async def activate_user(
    user_id: int,
    storage: Annotated[Storage, Depends(get_storage)],
    admin: Annotated[Principal, Depends(require_admin)],
) -> UserOut:
    _user_out(storage, user_id)  # 404 before mutating
    storage.users.set_status(user_id, "active", admin.email)
    return _user_out(storage, user_id)


@router.post("/users/{user_id}/disable", response_model=UserOut)
async def disable_user(
    user_id: int,
    storage: Annotated[Storage, Depends(get_storage)],
    admin: Annotated[Principal, Depends(require_admin)],
) -> UserOut:
    _user_out(storage, user_id)
    storage.users.set_status(user_id, "disabled", admin.email)
    # A disabled account must lose its CLI sessions immediately, not at TTL.
    storage.tokens.revoke_all_for_user(user_id)
    return _user_out(storage, user_id)


@router.post("/users/{user_id}/grants", response_model=UserOut)
async def grant_surface(
    user_id: int,
    body: GrantRequest,
    storage: Annotated[Storage, Depends(get_storage)],
    admin: Annotated[Principal, Depends(require_admin)],
) -> UserOut:
    _user_out(storage, user_id)
    storage.grants.grant(user_id, body.surface, admin.email, body.expires_at)
    return _user_out(storage, user_id)


@router.delete("/users/{user_id}/grants/{surface}", response_model=UserOut)
async def revoke_surface(
    user_id: int,
    surface: Surface,
    storage: Annotated[Storage, Depends(get_storage)],
) -> UserOut:
    _user_out(storage, user_id)
    storage.grants.revoke(user_id, surface)
    return _user_out(storage, user_id)


@router.get("/audit")
async def list_audit(
    day: Annotated[str | None, Query(pattern=r"^\d{4}-\d{2}-\d{2}$")] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> list[dict[str, Any]]:
    return read_audit(day=day, limit=limit)


@router.get("/surfaces")
async def list_surfaces() -> list[str]:
    return [s.value for s in Surface]

class ApproveIn(BaseModel):
    role: str


@router.post("/users/{user_id}/approve", response_model=UserOut)
async def approve_user(
    user_id: int,
    body: ApproveIn,
    storage: Annotated[Storage, Depends(get_storage)],
    admin: Annotated[Principal, Depends(require_admin)],
) -> UserOut:
    """Activate a user AND grant a role in one step.

    One action, because they are one decision. Splitting them produces the
    failure this is designed to avoid: an account activated "for now" with
    grants to be sorted out later, which either never happens or gets settled by
    ticking everything.
    """
    role = BY_KEY.get(body.role)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown role {body.role!r}",
        )
    _user_out(storage, user_id)  # 404 before mutating
    for surface in role.surfaces:
        storage.grants.grant(user_id, surface, admin.email)
    storage.users.set_status(user_id, "active", admin.email)
    return _user_out(storage, user_id)


@router.post("/users/{user_id}/enable", response_model=UserOut)
async def enable_user(
    user_id: int,
    storage: Annotated[Storage, Depends(get_storage)],
    admin: Annotated[Principal, Depends(require_admin)],
) -> UserOut:
    """Re-enable a previously disabled account, leaving its grants as they were."""
    _user_out(storage, user_id)
    storage.users.set_status(user_id, "active", admin.email)
    return _user_out(storage, user_id)


@router.get("/roles")
async def list_roles(
    admin: Annotated[Principal, Depends(require_admin)],
) -> list[dict[str, object]]:
    return [
        {
            "key": r.key,
            "label": r.label,
            "summary": r.summary,
            "surfaces": [s.value for s in r.surfaces],
            "caution": r.caution,
        }
        for r in sorted(ROLES, key=lambda r: r.order)
    ]
