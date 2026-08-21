"""Identity endpoints and the CLI device-code flow.

`infractl` cannot complete a browser SSO redirect, so it uses a device-code flow:

    CLI  ──POST /auth/device/start──▶  {device_code, user_code, verification_uri}
    user ──opens verification_uri───▶  Pomerium SSO ──▶ POST /auth/device/approve
    CLI  ──POST /auth/device/token──▶  {access_token}     (polls, single-use)

The device_code is the CLI's secret and is stored hashed; the user_code is the
short string the human transcribes. Approval requires a *verified* Pomerium
assertion, so the identity bound to a code is never self-asserted.
"""

from __future__ import annotations

import os
import urllib.parse
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from app import config
from app.auth import passwords
from app.auth.deps import Principal, current_principal
from app.auth.throttle import (
    LOGIN_THROTTLE,
    REGISTER_THROTTLE,
    Throttled,
    client_key,
)
from app.auth.tokens import new_cli_token, new_device_code, new_user_code, normalize_user_code
from app.storage import Storage, get_storage
from app.web import render

router = APIRouter(prefix="/auth", tags=["auth"])

DEVICE_POLL_INTERVAL_S = 5
DEVICE_EXPIRES_IN_S = 600  # matches DeviceCodeRepo.TTL_MINUTES


def _public_base_url(request: Request) -> str:
    configured = os.getenv("INFRAGPT_PUBLIC_URL", "").rstrip("/")
    return configured or str(request.base_url).rstrip("/")


# ---- models ---------------------------------------------------------------


class DeviceStartResponse(BaseModel):
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    interval: int = DEVICE_POLL_INTERVAL_S
    expires_in: int = DEVICE_EXPIRES_IN_S


class DeviceApproveRequest(BaseModel):
    user_code: str = Field(min_length=4, max_length=32)


class DeviceTokenRequest(BaseModel):
    device_code: str = Field(min_length=8, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - a type name, not a credential
    expires_in: int


class WhoAmI(BaseModel):
    email: str
    name: str
    status: str
    grants: list[str]
    via: str
    created_at: str
    last_seen_at: str | None = None


# ---- identity -------------------------------------------------------------


@router.get("/me", response_model=WhoAmI)
async def me(principal: Annotated[Principal, Depends(current_principal)]) -> WhoAmI:
    """Deliberately reachable while pending: a user must be able to see *why*
    they are being refused everywhere else."""
    return WhoAmI(
        email=principal.user.email,
        name=principal.user.name,
        status=principal.user.status,
        grants=sorted(principal.surfaces),
        via=principal.via,
        created_at=principal.user.created_at,
        last_seen_at=principal.user.last_seen_at,
    )


@router.post("/logout")
async def logout(
    storage: Annotated[Storage, Depends(get_storage)],
    principal: Annotated[Principal, Depends(current_principal)],
    request: Request,
) -> dict[str, Any]:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        storage.tokens.revoke(header.split(" ", 1)[1].strip())
        return {"revoked": "current"}
    storage.tokens.revoke_all_for_user(principal.user.id)
    return {"revoked": "all"}


# ---- device flow ----------------------------------------------------------


@router.post("/device/start", response_model=DeviceStartResponse)
async def device_start(
    storage: Annotated[Storage, Depends(get_storage)],
    request: Request,
) -> DeviceStartResponse:
    """Unauthenticated by necessity — the CLI has no identity yet. Issuing a
    code grants nothing until a Pomerium-authenticated browser approves it."""
    storage.device_codes.purge_expired()
    device_code = new_device_code()
    user_code = new_user_code()
    storage.device_codes.create(device_code, user_code)
    base = _public_base_url(request)
    return DeviceStartResponse(
        device_code=device_code,
        user_code=user_code,
        verification_uri=f"{base}/auth/device",
        verification_uri_complete=f"{base}/auth/device?user_code={user_code}",
    )


@router.post("/device/approve")
async def device_approve(
    body: DeviceApproveRequest,
    storage: Annotated[Storage, Depends(get_storage)],
    principal: Annotated[Principal, Depends(current_principal)],
) -> dict[str, Any]:
    """Bind the *verified* browser identity to a pending user_code."""
    user_code = normalize_user_code(body.user_code)
    if not storage.device_codes.approve(user_code, principal.user.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="unknown, already-used or expired code",
        )
    return {"approved": True, "email": principal.user.email, "status": principal.user.status}


@router.post("/device/token", response_model=TokenResponse)
async def device_token(
    body: DeviceTokenRequest,
    storage: Annotated[Storage, Depends(get_storage)],
) -> TokenResponse:
    """CLI polling endpoint. 428 = keep polling; 400 = the code is dead."""
    code = storage.device_codes.get_by_device_code(body.device_code)
    if code is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_grant")
    if code.status == "pending":
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail="authorization_pending",
        )
    claimed = storage.device_codes.claim(body.device_code)
    if claimed is None or claimed.user_id is None:
        # Already claimed, or expired between approval and poll. Single-use.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expired_token")

    raw = new_cli_token()
    storage.tokens.issue(claimed.user_id, raw, config.CLI_TOKEN_TTL_HOURS)
    return TokenResponse(access_token=raw, expires_in=config.CLI_TOKEN_TTL_HOURS * 3600)


_VERIFY_PAGE = """<!doctype html>
<meta charset="utf-8"><title>infractl device login</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem}
 input{font-size:1.25rem;padding:.5rem;letter-spacing:.1em;text-transform:uppercase}
 button{font-size:1rem;padding:.6rem 1.2rem;margin-left:.5rem;cursor:pointer}
 #out{margin-top:1.5rem;white-space:pre-wrap}
</style>
<h1>Approve infractl login</h1>
<p>Enter the code shown in your terminal.</p>
<form id="f"><input id="c" name="user_code" value="__CODE__" autofocus>
<button type="submit">Approve</button></form>
<div id="out"></div>
<script>
document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const r = await fetch('/auth/device/approve', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({user_code: document.getElementById('c').value})
  });
  const b = await r.json().catch(() => ({}));
  document.getElementById('out').textContent = r.ok
    ? 'Approved as ' + b.email + ' (account status: ' + b.status + '). Return to your terminal.'
    : 'Failed: ' + (b.detail || r.status);
});
</script>
"""


@router.get("/device", response_class=HTMLResponse)
async def device_verify_page(request: Request, user_code: str = "") -> HTMLResponse:
    """The page the human opens. Pomerium authenticates the GET; the approval
    POST it makes carries the same verified assertion."""
    safe = normalize_user_code(user_code) if user_code else ""
    safe = "".join(ch for ch in safe if ch.isalnum() or ch == "-")[:9]
    return HTMLResponse(_VERIFY_PAGE.replace("__CODE__", safe))

# ---------------------------------------------------------------------------
# Token sign-in
# ---------------------------------------------------------------------------
# Where Pomerium fronts the app it injects a verified identity assertion and
# this is never reached. Where it does not — a port-forward, a cluster without
# the route yet, or break-glass — a browser still cannot send an Authorization
# header, so a token has to reach the server some other way.
#
# It is a POST form, not a query parameter. A token in a URL leaks into browser
# history, proxy logs and Referer headers; a POST body does none of that. That
# is why this needs no dev-only flag and is safe to leave enabled in production:
# it accepts an ALREADY-ISSUED token, resolves it through the same store with
# the same expiry, and only moves it into an httponly cookie. It mints nothing
# and grants nothing.


def _form(raw: str) -> dict[str, str]:
    """Parse one urlencoded body.

    By hand rather than via fastapi.Form, which pulls in python-multipart. A
    handful of fields does not justify a dependency in a container that is
    deliberately kept thin.
    """
    parsed = urllib.parse.parse_qs(raw)
    return {k: v[0] if v else "" for k, v in parsed.items()}


def _pomerium_email(request: Request) -> str:
    """The email Pomerium says this person is, if it told us.

    Used ONLY to prefill the registration form. It is not trusted as
    authentication — the account still has to be created, given a password, and
    approved by an admin before it can do anything.
    """
    for header in ("x-pomerium-claim-email", "x-forwarded-email"):
        value = request.headers.get(header, "").strip().lower()
        if value:
            return value
    return ""


@router.get("/register", include_in_schema=False)
async def register_form(request: Request) -> HTMLResponse:
    return render(
        request,
        "register.html",
        {
            "path": "/auth/register",
            "error": None,
            "email": _pomerium_email(request),
            "min_length": passwords.MIN_LENGTH,
        },
    )


@router.post("/register", include_in_schema=False)
async def register_submit(
    request: Request,
    storage: Annotated[Storage, Depends(get_storage)],
) -> Response:
    """Create an account, PENDING. It can do nothing until an admin approves.

    Registration is deliberately not sign-in: a new account holds no grants and
    is refused everywhere until approved, so self-service registration adds no
    access on its own.
    """
    form = _form((await request.body()).decode("utf-8", errors="replace"))
    email = form.get("email", "").strip().lower()
    password = form.get("password", "")
    confirm = form.get("confirm", "")
    name = form.get("name", "").strip()
    source = client_key(request)

    def fail(message: str) -> Response:
        return render(
            request,
            "register.html",
            {
                "path": "/auth/register",
                "error": message,
                "email": email,
                "min_length": passwords.MIN_LENGTH,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Before any hashing: scrypt allocates ~32MB per call, so an unthrottled
    # registration form is a memory-exhaustion lever as much as a spam one.
    try:
        REGISTER_THROTTLE.check(source)
    except Throttled as exc:
        return fail(f"Too many attempts. Try again in {exc.retry_after_s}s.")

    if not email or "@" not in email:
        REGISTER_THROTTLE.record(source)
        return fail("Enter the email address you use at work.")
    if config.ALLOWED_EMAIL_DOMAIN and not email.endswith(
        f"@{config.ALLOWED_EMAIL_DOMAIN}"
    ):
        return fail(f"Only @{config.ALLOWED_EMAIL_DOMAIN} addresses can register here.")
    if password != confirm:
        return fail("The two passwords do not match.")
    try:
        passwords.validate(password)
    except passwords.PasswordError as exc:
        return fail(str(exc))

    existing = storage.users.get_by_email(email)
    if existing is not None and existing.password_hash:
        # Not "that account exists": an unauthenticated page must not confirm
        # who has an account here. The instruction is the same either way.
        return fail(
            "That address cannot be registered. If you already have an account, "
            "sign in instead; if you have forgotten the password, ask an admin "
            "to reset it."
        )

    REGISTER_THROTTLE.record(source)
    user = existing or storage.users.get_or_create(email, name)
    storage.users.set_password(user.id, passwords.hash_password(password))
    return render(
        request,
        "pending.html",
        {"path": "/auth/register", "email": email, "just_registered": True},
    )


@router.get("/login", include_in_schema=False)
async def login_form(request: Request) -> HTMLResponse:
    return render(
        request,
        "login.html",
        {"path": "/auth/login", "error": None, "email": _pomerium_email(request)},
    )


@router.post("/login", include_in_schema=False)
async def login_submit(
    request: Request,
    storage: Annotated[Storage, Depends(get_storage)],
) -> Response:
    """Sign in with email + password, or with a `infractl` token.

    Both end in the same place: a session cookie holding a CLI token, resolved
    through the same store with the same expiry. The password path is not a
    second, weaker way in — it mints exactly the credential the CLI would.
    """
    form = _form((await request.body()).decode("utf-8", errors="replace"))
    email = form.get("email", "").strip().lower()
    password = form.get("password", "")
    token = form.get("token", "").strip()
    source = client_key(request)

    def fail(message: str) -> Response:
        return render(
            request,
            "login.html",
            {"path": "/auth/login", "error": message, "email": email},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    if token:
        try:
            LOGIN_THROTTLE.check(source)
        except Throttled as exc:
            return fail(f"Too many failed attempts. Try again in {exc.retry_after_s}s.")
        if storage.tokens.resolve(token) is None:
            # A token is a bearer secret; guessing it must cost the same as
            # guessing a password.
            LOGIN_THROTTLE.record(source)
            return fail("That token is not valid, or it has expired.")
        LOGIN_THROTTLE.reset(source)
        return _session_response(request, token)

    # Checked BEFORE the KDF runs. Refusing after hashing would still let an
    # attacker spend the server's memory on every request.
    try:
        LOGIN_THROTTLE.check(email, source)
    except Throttled as exc:
        return fail(
            f"Too many failed attempts. Try again in {exc.retry_after_s}s."
        )

    user = storage.users.get_by_email(email) if email else None
    # verify() is called even when there is no such user, against None — it
    # returns False and costs the same, so a wrong address and a wrong password
    # are indistinguishable in both response and timing.
    if not passwords.verify(password, user.password_hash if user else None):
        LOGIN_THROTTLE.record(email, source)
        return fail("Email or password is incorrect.")
    assert user is not None
    # Cleared on success so one mistyped password never counts toward a lockout.
    LOGIN_THROTTLE.reset(email, source)

    if user.status == "disabled":
        return fail("That account has been disabled. Ask an admin.")
    if user.status != "active":
        # Not an error — the expected state for a new account, and the page says
        # what happens next rather than leaving them at a failed login.
        return render(
            request,
            "pending.html",
            {"path": "/auth/login", "email": email, "just_registered": False},
        )

    raw = new_cli_token()
    storage.tokens.issue(user.id, raw, config.CLI_TOKEN_TTL_HOURS)
    return _session_response(request, raw)


def _session_response(request: Request, token: str) -> Response:
    """Set the session cookie and go to the app.

    httponly so page scripts cannot read it, samesite=lax so it is not sent on
    cross-site requests, and secure whenever the request arrived over TLS. Never
    a URL parameter, which would put it in browser history and proxy logs.
    """
    # X-Forwarded-Proto, not request.url.scheme. TLS terminates at the proxy,
    # so the scheme this process sees is http even when the browser is on
    # https — and the cookie would then be sent unencrypted on any downgrade.
    # Trusting the header here is safe: the worst an attacker can do by forging
    # it is mark their OWN cookie secure.
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
    is_https = (forwarded_proto or request.url.scheme) == "https"
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        "infractl_token",
        token,
        httponly=True,
        samesite="lax",
        secure=is_https,
        max_age=config.CLI_TOKEN_TTL_HOURS * 3600,
    )
    return response


@router.post("/logout-web", include_in_schema=False)
async def logout_web(
    request: Request,
    storage: Annotated[Storage, Depends(get_storage)],
) -> Response:
    """Sign out, and REVOKE the token server-side.

    Deleting the cookie only made the browser forget it; the token stayed valid
    for its full TTL, so anything that had captured it — a shared machine, a
    proxy log, a screenshot — kept working after the user believed they had
    signed out. Signing out must end the session, not hide it.
    """
    token = request.cookies.get("infractl_token", "")
    if token:
        storage.tokens.revoke(token)
    response = RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("infractl_token")
    return response
