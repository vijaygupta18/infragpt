"""FastAPI authentication and authorization dependencies.

Three layers, each of which must be passed independently:

1. ``current_principal`` — *who* you are. Either a signature-verified Pomerium
   assertion or a live CLI bearer token. Nothing else authenticates.
2. ``current_user`` — *whether you may be here at all*. A ``pending`` or
   ``disabled`` user is 403'd on every route except /health and the identity
   endpoints that let them see why.
3. ``require_surface`` — *whether you may do this*. Deny by default: no grant,
   no access. Admin holds no implicit surfaces beyond ``admin``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Cookie, Depends, Header, HTTPException, status

from app.auth.pomerium import POMERIUM_HEADER, AuthError, Identity, get_verifier
from app.registry.schema import Surface
from app.storage import Storage, get_storage
from app.storage.models import User

PENDING_MESSAGE = (
    "Your account is awaiting admin approval. Ask an infragpt admin to activate "
    "it, then run `infractl whoami` to confirm."
)
DISABLED_MESSAGE = "Your infragpt account has been disabled. Contact an admin."


@dataclass(frozen=True)
class Principal:
    """An authenticated identity plus its resolved account and grants."""

    user: User
    surfaces: frozenset[str]
    via: str  # "pomerium" | "cli"

    @property
    def email(self) -> str:
        return self.user.email

    def has(self, surface: Surface | str) -> bool:
        return (surface.value if isinstance(surface, Surface) else surface) in self.surfaces


def _unauthorized(detail: str = "authentication required") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


async def _identity_from_pomerium(assertion: str) -> Identity:
    """Verify a Pomerium assertion, or treat the caller as unauthenticated.

    EVERY failure lands on 401, including "jwks not configured". That case is
    not a misconfiguration to shout about: where Pomerium is used only as a
    network gate and this app owns identity through its own accounts, there is
    no JWKS to verify against and the assertion is simply not an identity here.
    Raising instead produced `{"detail":"pomerium jwks not configured"}` for
    every visitor the moment the SSO route went live — an error page where a
    sign-in page belongs.

    What must never happen is the other direction: an assertion that cannot be
    verified is never trusted for its contents.
    """
    try:
        return await get_verifier().verify(assertion)
    except AuthError as exc:
        raise _unauthorized(str(exc)) from exc


async def current_principal(
    storage: Annotated[Storage, Depends(get_storage)],
    authorization: Annotated[str | None, Header()] = None,
    x_pomerium_jwt_assertion: Annotated[str | None, Header()] = None,
    infractl_token: Annotated[str | None, Cookie()] = None,
) -> Principal:
    """Authenticate via CLI bearer token OR verified Pomerium assertion.

    Returns the principal regardless of account status — status is enforced by
    ``current_user``, so a pending user can still read their own /auth/me.
    """
    user: User | None = None
    via = ""

    # A cookie is only a *transport* for the same CLI token, resolved through the
    # same store with the same expiry — it is not a second, weaker way in. It
    # exists because a browser cannot attach an Authorization header, so without
    # it the web UI is unusable anywhere Pomerium is not the front door.
    bearer = authorization
    if not bearer and infractl_token:
        bearer = f"Bearer {infractl_token}"

    if bearer and bearer.lower().startswith("bearer "):
        raw = bearer.split(" ", 1)[1].strip()
        user_id = storage.tokens.resolve(raw)
        if user_id is None:
            raise _unauthorized("invalid or expired token")
        user = storage.users.get(user_id)
        via = "cli"
        if user is None:
            raise _unauthorized("invalid or expired token")

    if user is None:
        # Pomerium's assertion is only an identity if we can VERIFY it. Where no
        # JWKS is configured, this deployment uses Pomerium purely as a network
        # gate and the app owns identity through its own accounts — so an
        # unverifiable header is ignored rather than trusted, and rather than
        # failing the request outright.
        #
        # It previously raised "pomerium jwks not configured" the moment
        # Pomerium started forwarding traffic, which turned a working route into
        # a hard error for every visitor instead of sending them to sign in.
        #
        # Ignoring it is the safe direction: trusting an unverified header would
        # let anything that can reach this pod claim to be any user.
        if not x_pomerium_jwt_assertion:
            raise _unauthorized()
        identity = await _identity_from_pomerium(x_pomerium_jwt_assertion)
        # First login creates the account as pending; it grants nothing.
        user = storage.users.get_or_create(identity.email, identity.name)
        via = "pomerium"

    storage.users.touch(user.id)
    return Principal(
        user=user,
        surfaces=frozenset(storage.grants.surfaces_for_user(user.id)),
        via=via,
    )


async def current_user(
    principal: Annotated[Principal, Depends(current_principal)],
) -> Principal:
    """Authenticated AND activated. Use this on every non-health route."""
    if principal.user.status == "pending":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=PENDING_MESSAGE)
    if principal.user.status != "active":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=DISABLED_MESSAGE)
    return principal


def require_surface(surface: Surface):  # noqa: ANN201 - returns a FastAPI dependency
    """Dependency factory enforcing one surface grant. Deny by default."""

    async def _dep(
        principal: Annotated[Principal, Depends(current_user)],
    ) -> Principal:
        if not principal.has(surface):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing grant: {surface.value}",
            )
        return principal

    return _dep


require_admin = require_surface(Surface.ADMIN)

__all__ = [
    "DISABLED_MESSAGE",
    "PENDING_MESSAGE",
    "POMERIUM_HEADER",
    "Principal",
    "current_principal",
    "current_user",
    "require_admin",
    "require_surface",
]
