"""Routes serving the web UI.

Every route here is a GET that renders HTML. All mutations the UI performs go
through the existing JSON APIs (`/ask`, `/admin/*`) via ``fetch`` with a JSON
content type — which is not a CORS "simple request", so a cross-site form cannot
forge one against a Pomerium-authenticated browser session. That is why this
module adds no form-POST endpoints: doing so would open a CSRF hole that the
JSON API does not have.

Authorization mirrors the API exactly (``current_principal`` -> active check ->
surface check); the only difference is that a refusal renders a page explaining
why instead of returning JSON.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.access.roles import ROLES, infer_roles
from app.audit import read_audit
from app.auth.deps import DISABLED_MESSAGE, PENDING_MESSAGE, Principal, current_principal
from app.registry.schema import Surface
from app.runbooks import get_runbooks
from app.storage import Storage, get_storage
from app.web import render

_SURFACE_VALUES = {s.value for s in Surface}

router = APIRouter(include_in_schema=False)


def _is_admin(principal: Principal) -> bool:
    return principal.has(Surface.ADMIN)


def _base_ctx(principal: Principal) -> dict[str, Any]:
    return {"principal": principal, "is_admin": _is_admin(principal)}


def _gate_active(request: Request, principal: Principal) -> HTMLResponse | None:
    """Render the awaiting-approval / disabled page instead of a JSON 403.

    Returns None when the user may proceed. Same decision as ``current_user``;
    only the presentation differs.
    """
    if principal.user.status == "active":
        return None
    pending = principal.user.status == "pending"
    return render(
        request,
        "pending.html",
        {
            **_base_ctx(principal),
            "heading": "Awaiting approval" if pending else "Account disabled",
            "message": PENDING_MESSAGE if pending else DISABLED_MESSAGE,
        },
        status_code=403,
    )


def _needs_signin(request: Request) -> RedirectResponse | None:
    """Send an unauthenticated BROWSER to the sign-in page.

    API clients still get a 401: they set Accept: application/json and a
    redirect would be a confusing 200-shaped failure for them.
    """
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return RedirectResponse(url="/auth/login", status_code=303)
    return None


def _gate_admin(request: Request, principal: Principal) -> HTMLResponse | None:
    blocked = _gate_active(request, principal)
    if blocked is not None:
        return blocked
    if _is_admin(principal):
        return None
    return render(
        request,
        "forbidden.html",
        {
            **_base_ctx(principal),
            "message": "This screen requires the admin grant.",
            "needed": Surface.ADMIN.value,
        },
        status_code=403,
    )


# ---- chat -----------------------------------------------------------------


def _chat_page(
    request: Request,
    principal: Principal,
    storage: Storage,
    conversation_id: int | None,
) -> HTMLResponse:
    messages: list[Any] = []
    if conversation_id is not None:
        conv = storage.conversations.get(conversation_id)
        if conv is None or conv.user_id != principal.user.id:
            # Someone else's conversation is indistinguishable from a missing
            # one: no enumeration through the UI either.
            conversation_id = None
        else:
            messages = storage.conversations.messages(conv.id)
    return render(
        request,
        "chat.html",
        {
            **_base_ctx(principal),
            "conversations": storage.conversations.list_for_user(principal.user.id),
            "conversation_id": conversation_id,
            "messages": messages,
        },
    )


@router.get("/", response_class=HTMLResponse)
async def chat_home(
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
    storage: Annotated[Storage, Depends(get_storage)],
) -> HTMLResponse:
    return _gate_active(request, principal) or _chat_page(request, principal, storage, None)


@router.get("/c/{conversation_id}", response_class=HTMLResponse)
async def chat_conversation(
    conversation_id: int,
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
    storage: Annotated[Storage, Depends(get_storage)],
) -> HTMLResponse:
    return _gate_active(request, principal) or _chat_page(
        request, principal, storage, conversation_id
    )


# ---- admin ----------------------------------------------------------------


@router.get("/admin", response_class=HTMLResponse)
async def admin_console(
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
    storage: Annotated[Storage, Depends(get_storage)],
) -> HTMLResponse:
    blocked = _gate_admin(request, principal)
    if blocked is not None:
        return blocked

    users = [
        {
            "id": u.id,
            "email": u.email,
            "name": u.name,
            "status": u.status,
            "created_at": u.created_at,
            "last_seen_at": u.last_seen_at,
            "grants": sorted(storage.grants.surfaces_for_user(u.id)),
            "roles": [
                r.label
                for r in infer_roles(
                    {
                        Surface(g)
                        for g in storage.grants.surfaces_for_user(u.id)
                        if g in _SURFACE_VALUES
                    }
                )
            ],
        }
        for u in storage.users.list_all()
    ]
    return render(
        request,
        "admin.html",
        {
            **_base_ctx(principal),
            "users": users,
            "pending_users": [u for u in users if u["status"] == "pending"],
            "surfaces": [s.value for s in Surface],
            "roles": sorted(ROLES, key=lambda r: r.order),
        },
    )


@router.get("/admin/audit-log", response_class=HTMLResponse)
async def admin_audit_log(
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
    day: Annotated[str, Query(pattern=r"^(\d{4}-\d{2}-\d{2})?$")] = "",
    user: Annotated[str, Query(max_length=120)] = "",
    entry: Annotated[str, Query(max_length=120)] = "",
    outcome: Annotated[str, Query(pattern=r"^(ok|failed)?$")] = "",
    kind: Annotated[str, Query(pattern=r"^(question|call)?$")] = "",
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> HTMLResponse:
    blocked = _gate_admin(request, principal)
    if blocked is not None:
        return blocked

    # Over-read, then filter, so a narrow filter still finds matches deep in the
    # day rather than only within the last `limit` lines.
    records = read_audit(day=day or None, limit=1000)
    total = len(records)

    def matches(record: dict[str, Any]) -> bool:
        if user and user.lower() not in str(record.get("user_email", "")).lower():
            return False
        if entry:
            names = [str(record.get("entry_name") or "")] + [
                str(n) for n in record.get("entry_names", [])
            ]
            if not any(entry.lower() in n.lower() for n in names):
                return False
        if outcome == "ok" and not record.get("ok"):
            return False
        if outcome == "failed" and record.get("ok"):
            return False
        if kind and record.get("kind") != kind:
            return False
        return True

    filtered = [r for r in records if matches(r)]
    shown = filtered[-limit:]
    return render(
        request,
        "audit.html",
        {
            **_base_ctx(principal),
            "records": list(reversed(shown)),
            "truncated": len(filtered) > len(shown) or total >= 1000,
            "filters": {
                "day": day,
                "user": user,
                "entry": entry,
                "outcome": outcome,
                "kind": kind,
                "limit": limit,
            },
        },
    )


@router.get("/admin/runbooks", response_class=HTMLResponse)
async def admin_runbooks(
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
) -> HTMLResponse:
    """Author the tool's own knowledge.

    This is where environment-specific context belongs: which database holds
    rides, what a workload is really called, the trap that makes a metric
    misleading. It is what turns a correct-but-useless "I have no function for
    that" into an answer — and it is exactly the material that must not be
    committed to a published repository, which is why it lives on the volume
    rather than in git.
    """
    blocked = _gate_admin(request, principal)
    if blocked is not None:
        return blocked

    store = get_runbooks(reload=True)
    return render(
        request,
        "runbooks.html",
        {
            "principal": principal,
            "is_admin": True,
            "runbooks": sorted(store.all(), key=lambda r: r.name.lower()),
            "surfaces": [s.value for s in Surface],
        },
    )
