"""PII redaction — a DPDP control, applied at the executor boundary.

Runs on EVERY ExecResult before it reaches the Grid gateway or the user. There
are deliberately no per-surface exemptions: adding a business-data function
later must not be able to silently bypass redaction.

In v1 the realistic PII sources are Redis values and pod logs. The DB surface is
schema/performance metadata only and emits none — but it is redacted anyway.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# Indian mobile numbers, with or without +91 / 0 prefix.
PHONE_RE = re.compile(r"(?:(?:\+?91[\-\s]?)|0)?([6-9]\d{9})\b")
EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")
# 12-digit Aadhaar-like and PAN-like patterns are dropped entirely, never hashed.
AADHAAR_RE = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
LATLON_RE = re.compile(r"\b(-?\d{1,3})\.(\d{4,})\b")

# --- credentials ------------------------------------------------------------
#
# Added once the tool could read ConfigMaps, config files and source. Those are
# the places credentials actually live — a database URL with an inline password,
# an API key pasted into a values file, a private key committed years ago.
#
# The tool is not supposed to reach Secrets, and does not. This is for the far
# more common case: a credential sitting somewhere that is NOT a secret store,
# reaching an answer, a log and the audit trail on its way to a screen.
#
# These DROP rather than hash. A hashed password is still a fact about a
# credential, and there is no legitimate reason to correlate one across
# outputs — unlike a phone number, where the hash is what makes a driver
# traceable through a conversation.

#: key: value / key=value where the key names a credential. The value is taken
#: to the end of the token, or the quoted string, whichever ends first.
SECRET_ASSIGN_RE = re.compile(
    r"""(?ix)
    \b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key
       |private[_-]?key|client[_-]?secret|auth[_-]?token|authorization|bearer)\b
    \s*[:=]\s*
    (?:bearer\s+|basic\s+|token\s+)?
    (?P<v>"[^"]{3,}"|'[^']{3,}'|[^\s,;)'"}\]]{3,})
    """
)

#: Credentials embedded in a connection string: scheme://user:password@host
URL_CRED_RE = re.compile(r"://([^:/\s@]+):([^@/\s]{3,})@")

#: Provider-shaped keys, recognisable without a nearby label.
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
GH_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)


def redact_credentials(text: str) -> str:
    """Remove anything credential-shaped. Dropped, never hashed."""
    if not text:
        return text
    text = PRIVATE_KEY_RE.sub("[PRIVATE-KEY-REDACTED]", text)
    text = JWT_RE.sub("[JWT-REDACTED]", text)
    text = AWS_KEY_RE.sub("[AWS-KEY-REDACTED]", text)
    text = GH_TOKEN_RE.sub("[TOKEN-REDACTED]", text)
    text = SLACK_TOKEN_RE.sub("[TOKEN-REDACTED]", text)
    text = URL_CRED_RE.sub(r"://\1:[REDACTED]@", text)
    text = SECRET_ASSIGN_RE.sub(
        lambda m: f"{m.group(1)}=[REDACTED]", text
    )
    return text


def _hash8(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def redact_text(text: str) -> str:
    """Redact a blob of text. Order matters: drop-classes run before hash-classes
    so an Aadhaar number can never be partially matched as something else."""
    if not text:
        return text
    # Credentials first: a private-key block or a connection string can contain
    # digit runs that a later pattern would otherwise chew into, leaving a
    # partially-redacted secret rather than none.
    text = redact_credentials(text)
    text = AADHAAR_RE.sub("[AADHAAR-REDACTED]", text)
    text = PAN_RE.sub("[PAN-REDACTED]", text)
    text = PHONE_RE.sub(lambda m: f"phone:{_hash8(m.group(1))}", text)
    text = EMAIL_RE.sub(lambda m: f"{_hash8(m.group(1))}@{m.group(2)}", text)
    # Coarsen coordinates to ~1km: keep 2 decimal places.
    text = LATLON_RE.sub(lambda m: f"{m.group(1)}.{m.group(2)[:2]}", text)
    return text


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    return value


def redact_result(result: Any) -> Any:
    """Redact an ExecResult in place and mark it. Idempotent."""
    if getattr(result, "redacted", False):
        return result
    result.text = redact_text(result.text)
    result.rows = [redact_value(r) for r in result.rows]
    result.redacted = True
    return result
