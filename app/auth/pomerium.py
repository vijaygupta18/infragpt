"""Pomerium assertion verification.

Pomerium injects ``X-Pomerium-Jwt-Assertion`` on every proxied request. The
header is only meaningful if its **signature** is verified against Pomerium's
JWKS: anything that can reach the pod directly (a port-forward, another pod in
the namespace, a misrouted ingress) can otherwise set the header itself and
become any user. There is deliberately no code path in this module that returns
an identity without a successful signature check — not behind a flag, not in
dev. If JWKS is unconfigured, authentication fails closed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx
from jose import jwt
from jose.exceptions import JOSEError

from app import config

POMERIUM_HEADER = "X-Pomerium-Jwt-Assertion"
_ALGORITHMS = ["ES256", "RS256"]


class AuthError(Exception):
    """Authentication failed. Carries no detail that helps a forger."""


@dataclass(frozen=True)
class Identity:
    email: str
    name: str = ""
    subject: str = ""


class PomeriumVerifier:
    """Verifies assertions against a TTL-cached JWKS."""

    def __init__(
        self,
        jwks_url: str | None = None,
        audience: str | None = None,
        cache_ttl_s: int = 300,
    ) -> None:
        self.jwks_url = jwks_url if jwks_url is not None else config.POMERIUM_JWKS_URL
        self.audience = audience if audience is not None else config.POMERIUM_AUDIENCE
        self.cache_ttl_s = cache_ttl_s
        self._jwks: dict[str, Any] | None = None
        self._fetched_at: float = 0.0

    # -- JWKS ---------------------------------------------------------------

    async def jwks(self, force: bool = False) -> dict[str, Any]:
        fresh = self._jwks is not None and (time.monotonic() - self._fetched_at) < self.cache_ttl_s
        if fresh and not force:
            assert self._jwks is not None
            return self._jwks
        if not self.jwks_url:
            raise AuthError("pomerium jwks not configured")
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(self.jwks_url)
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            if self._jwks is not None:
                # Serve the stale key set rather than locking everyone out during
                # a transient JWKS outage; signatures are still fully verified.
                return self._jwks
            raise AuthError("could not fetch pomerium jwks") from exc
        if not isinstance(data, dict) or not data.get("keys"):
            raise AuthError("malformed pomerium jwks")
        self._jwks = data
        self._fetched_at = time.monotonic()
        return data

    def set_jwks(self, jwks: dict[str, Any]) -> None:
        """Inject a key set directly (tests, or a sidecar-provided JWKS file)."""
        self._jwks = jwks
        self._fetched_at = time.monotonic()

    # -- verification -------------------------------------------------------

    async def verify(self, token: str) -> Identity:
        """Verify signature, audience and expiry. Raises AuthError on anything
        less than a complete pass."""
        if not token or token.count(".") != 2:
            raise AuthError("malformed assertion")

        claims = await self._decode(token, refreshed=False)

        email = str(claims.get("email") or "").strip().lower()
        if not email:
            raise AuthError("assertion carries no email")
        name = str(claims.get("name") or claims.get("given_name") or "")
        return Identity(email=email, name=name, subject=str(claims.get("sub") or ""))

    async def _decode(self, token: str, refreshed: bool) -> dict[str, Any]:
        keys = await self.jwks(force=refreshed)
        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_aud": bool(self.audience),
        }
        try:
            return jwt.decode(
                token,
                keys,
                algorithms=_ALGORITHMS,
                audience=self.audience or None,
                options=options,
            )
        except JOSEError as exc:
            # A rotated signing key looks exactly like a bad signature; retry once
            # with a forced JWKS refresh before concluding the token is forged.
            if not refreshed:
                return await self._decode(token, refreshed=True)
            raise AuthError(f"assertion rejected: {exc}") from exc


_verifier: PomeriumVerifier | None = None


def get_verifier() -> PomeriumVerifier:
    global _verifier
    if _verifier is None:
        _verifier = PomeriumVerifier()
    return _verifier


def set_verifier(verifier: PomeriumVerifier) -> None:
    """Replace the process verifier (startup wiring and tests)."""
    global _verifier
    _verifier = verifier
