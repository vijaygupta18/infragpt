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


def _hash8(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def redact_text(text: str) -> str:
    """Redact a blob of text. Order matters: drop-classes run before hash-classes
    so an Aadhaar number can never be partially matched as something else."""
    if not text:
        return text
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
