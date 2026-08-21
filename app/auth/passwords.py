"""Password hashing for self-registered accounts.

`hashlib.scrypt` from the standard library, not bcrypt/argon2 from PyPI. scrypt
is a memory-hard KDF designed for exactly this, it is in Python itself, and a
container that holds read-only production credentials is a bad place to add a
dependency that can be avoided.

STORED FORMAT — everything needed to verify travels with the hash, so the cost
parameters can be raised later without invalidating existing passwords:

    scrypt$<n>$<r>$<p>$<salt-b64>$<hash-b64>

WHAT THIS IS AND IS NOT. Pomerium is the perimeter: only someone who has already
passed SSO can reach the page at all. These passwords are the *second* factor of
that arrangement and the thing that ties a session to an approved account. They
are not the only thing standing between the internet and this service, and they
should not be treated as such — but they are still real passwords, so they are
hashed properly and never logged, echoed, or stored in any reversible form.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

#: Cost parameters. n=2**15 keeps a single verification near ~100ms on the nodes
#: this runs on — slow enough to make guessing expensive, fast enough that a
#: login does not feel broken. Raising n later is safe: old hashes carry their
#: own parameters and keep verifying.
_N = 2**15
_R = 8
_P = 1
_SALT_BYTES = 16
_KEY_LEN = 32

#: OpenSSL refuses scrypt above a 32MB default, and these parameters need
#: 128*n*r = 32MB exactly — which trips the limit rather than sitting under it.
#: Stated explicitly with headroom so the KDF cost is set by _N/_R/_P here and
#: not silently capped by a library default.
_MAXMEM = 128 * _N * _R * 2

#: Below this a password is not worth hashing. Deliberately a length rule and
#: nothing else: composition rules ("one symbol, one digit") push people toward
#: predictable substitutions and shorter secrets, which is the opposite of what
#: they are for.
MIN_LENGTH = 12


class PasswordError(ValueError):
    """Raised when a password is unusable. The message is shown to the user."""


def validate(password: str) -> None:
    """Reject a password before hashing it, with a reason a person can act on."""
    if len(password) < MIN_LENGTH:
        raise PasswordError(
            f"Password must be at least {MIN_LENGTH} characters. "
            "Length is what makes a password hard to guess; a long ordinary "
            "phrase beats a short complicated one."
        )
    if len(password) > 1024:
        # Not a security rule — a guard so an enormous body cannot be used to
        # make the server do expensive work.
        raise PasswordError("Password is too long.")


def hash_password(password: str) -> str:
    validate(password)
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_N,
        r=_R,
        p=_P,
        dklen=_KEY_LEN,
        maxmem=_MAXMEM,
    )
    return "$".join(
        (
            "scrypt",
            str(_N),
            str(_R),
            str(_P),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        )
    )


def verify(password: str, stored: str | None) -> bool:
    """Check a password against a stored hash.

    Returns False rather than raising on a malformed or absent hash: a user row
    with no password set must fail closed, and it must fail the same way as a
    wrong password so that neither the response nor its timing distinguishes
    "no such account" from "wrong password".
    """
    if not stored or not password:
        return False
    try:
        scheme, n_s, r_s, p_s, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        # maxmem is derived from the STORED parameters, so a hash written with
        # different costs still verifies after they are raised.
        n, r, p = int(n_s), int(r_s), int(p_s)
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=base64.b64decode(salt_b64),
            n=n,
            r=r,
            p=p,
            dklen=len(base64.b64decode(hash_b64)),
            maxmem=128 * n * r * 2,
        )
    except (ValueError, TypeError):
        return False
    # Constant-time: a short-circuiting comparison leaks how much of the hash
    # matched, which is enough to reconstruct it byte by byte.
    return hmac.compare_digest(digest, base64.b64decode(hash_b64))
