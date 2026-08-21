"""Authentication: Pomerium assertions (web) and device-code CLI tokens."""

from __future__ import annotations

from app.auth.deps import (
    Principal,
    current_principal,
    current_user,
    require_admin,
    require_surface,
)
from app.auth.pomerium import (
    POMERIUM_HEADER,
    AuthError,
    Identity,
    PomeriumVerifier,
    get_verifier,
    set_verifier,
)
from app.auth.tokens import (
    new_cli_token,
    new_device_code,
    new_user_code,
    normalize_user_code,
)

__all__ = [
    "POMERIUM_HEADER",
    "AuthError",
    "Identity",
    "PomeriumVerifier",
    "Principal",
    "current_principal",
    "current_user",
    "get_verifier",
    "new_cli_token",
    "new_device_code",
    "new_user_code",
    "normalize_user_code",
    "require_admin",
    "require_surface",
    "set_verifier",
]
