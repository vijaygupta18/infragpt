"""Secret generation for CLI tokens and the device-code flow.

Everything here comes from ``secrets``. The raw values are returned to the
caller once and then only ever stored as sha256 hashes (see
``app.storage.repo.hash_token``).
"""

from __future__ import annotations

import secrets

CLI_TOKEN_PREFIX = "nyc_"  # noqa: S105 - a prefix, not a secret

# Unambiguous alphabet: no O/0, I/1, so a user reading a code off a terminal and
# typing it into a browser cannot transcribe it wrong.
_USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def new_cli_token() -> str:
    return CLI_TOKEN_PREFIX + secrets.token_urlsafe(32)


def new_device_code() -> str:
    return secrets.token_urlsafe(32)


def new_user_code() -> str:
    """A short, human-transcribable code, e.g. ``K7QM-2XPD``."""
    chars = "".join(secrets.choice(_USER_CODE_ALPHABET) for _ in range(8))
    return f"{chars[:4]}-{chars[4:]}"


def normalize_user_code(raw: str) -> str:
    """Accept ``k7qm2xpd`` / ``k7qm-2xpd`` / ``K7QM-2XPD`` as the same code."""
    cleaned = "".join(ch for ch in raw.upper() if ch in _USER_CODE_ALPHABET)
    if len(cleaned) != 8:
        return raw.strip().upper()
    return f"{cleaned[:4]}-{cleaned[4:]}"
