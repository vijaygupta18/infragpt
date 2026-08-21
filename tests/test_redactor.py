"""Redactor tests.

This is a DPDP control, so the tests are written as evidence: each one names the
class of personal data and asserts the raw value cannot survive. The critical
property is the *negative* assertion — the original string is absent — not that
the replacement looks right.
"""

from __future__ import annotations

import pytest

from app.executors.base import ExecResult
from app.redactor import redact_result, redact_text, redact_value


@pytest.mark.parametrize(
    "raw",
    [
        "9876543210",
        "+919876543210",
        "+91 9876543210",
        "+91-9876543210",
        "09876543210",
    ],
)
def test_phone_numbers_are_hashed(raw: str) -> None:
    """The property that matters is that the number cannot survive.

    Note the `+919876543210` case: the 12 consecutive digits match the
    Aadhaar pattern first and the whole run is DROPPED rather than hashed.
    That is over-redaction, not a leak, so it is accepted here — but it means a
    `+91`-prefixed number loses its hash and can no longer be correlated across
    two log lines. Worth knowing before someone debugs "why don't these hashes
    match".
    """
    out = redact_text(f"caller {raw} disconnected")
    assert "9876543210" not in out
    assert "phone:" in out or "[AADHAAR-REDACTED]" in out


def test_phone_hash_is_stable_and_short() -> None:
    a = redact_text("9876543210")
    b = redact_text("9876543210")
    assert a == b
    assert len(a.split("phone:")[1]) == 8


def test_emails_keep_domain_and_hash_local_part() -> None:
    out = redact_text("contact ravi.kumar@example.com for details")
    assert "ravi.kumar" not in out
    assert "@example.com" in out


def test_aadhaar_is_dropped_entirely_not_hashed() -> None:
    out = redact_text("aadhaar 1234 5678 9012 on file")
    assert "1234 5678 9012" not in out
    assert "123456789012" not in out
    assert "[AADHAAR-REDACTED]" in out


def test_pan_is_dropped_entirely() -> None:
    out = redact_text("pan ABCDE1234F verified")
    assert "ABCDE1234F" not in out
    assert "[PAN-REDACTED]" in out


def test_coordinates_are_coarsened_to_about_a_kilometre() -> None:
    out = redact_text("pickup at 12.971598,77.594562")
    assert "12.971598" not in out
    assert "77.594562" not in out
    assert "12.97" in out
    assert "77.59" in out


def test_non_pii_text_is_untouched() -> None:
    text = "pod driver-offer-bpp-7d9c5f8b6d-abcde is CrashLoopBackOff, 14 restarts"
    assert redact_text(text) == text


def test_driver_ids_pass_through() -> None:
    """Driver/rider IDs are deliberately NOT redacted — they are the join key
    an engineer needs, and are not personal data on their own."""
    text = "driverId=7f3c9b21-1a2b-4c3d-9e8f-0a1b2c3d4e5f"
    assert redact_text(text) == text


def test_nested_structures_are_redacted() -> None:
    value = {
        "driver": {"phone": "9876543210", "email": "a@b.com"},
        "trips": [{"pickup": "12.971598,77.594562"}, "pan ABCDE1234F"],
    }
    out = redact_value(value)
    flat = str(out)
    assert "9876543210" not in flat
    assert "ABCDE1234F" not in flat
    assert "12.971598" not in flat


def test_redact_result_marks_and_scrubs_both_channels() -> None:
    result = ExecResult(
        ok=True,
        entry_name="pod_logs",
        target="k8s_gcp",
        text="INFO driver 9876543210 assigned",
        rows=[{"query": "SELECT * WHERE mobile = '9876543210'"}],
    )
    redact_result(result)
    assert result.redacted is True
    assert "9876543210" not in result.text
    assert "9876543210" not in str(result.rows)


def test_redaction_is_idempotent() -> None:
    result = ExecResult(
        ok=True, entry_name="x", target="t", text="driver 9876543210"
    )
    once = redact_result(result).text
    twice = redact_result(result).text
    assert once == twice


def test_empty_output_is_safe() -> None:
    result = redact_result(ExecResult(ok=True, entry_name="x", target="t"))
    assert result.redacted is True
    assert result.text == ""


def test_multiple_pii_classes_in_one_line() -> None:
    line = (
        "2026-08-13 ERROR booking failed for 9876543210 (ravi@example.com) "
        "at 12.971598,77.594562 pan ABCDE1234F aadhaar 1234 5678 9012"
    )
    out = redact_text(line)
    for secret in (
        "9876543210",
        "ravi@example.com",
        "12.971598",
        "ABCDE1234F",
        "1234 5678 9012",
    ):
        assert secret not in out
    # The non-personal context survives, or the output is useless for debugging.
    assert "ERROR booking failed" in out


# --- credentials ------------------------------------------------------------
#
# Added once the tool could read ConfigMaps, config files and source — the
# places credentials actually live, as opposed to Secrets, which it cannot
# reach. Each pattern is asserted to FIRE, because the first version compiled
# \b into a literal backspace byte and every rule silently matched nothing. A
# redactor that quietly does nothing is worse than none: you trust it.


@pytest.mark.parametrize("raw,leak", [
    ("password: hunter2sekret", "hunter2sekret"),
    ("api_key = sk-live-abcdefghij", "sk-live-abcdefghij"),
    ("client_secret: 'abcd1234efgh'", "abcd1234efgh"),
    ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "eyJhbGciOiJ"),
    ("AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ("ghp_abcdefghijklmnopqrstuvwx", "ghp_abcdefghijklmnopqrstuvwx"),
    ("xoxb-1234567890-abcdefghij", "xoxb-1234567890"),
    ("postgres://app:hunter2@db:5432/x", "hunter2"),
])
def test_credentials_never_survive_redaction(raw: str, leak: str) -> None:
    from app.redactor import redact_text

    assert leak not in redact_text(raw), raw


def test_a_private_key_block_is_dropped_whole() -> None:
    from app.redactor import redact_text

    blob = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAx7Vv\nabc123\n"
        "-----END RSA PRIVATE KEY-----"
    )
    out = redact_text(blob)
    assert "MIIEowIBAAKCAQEAx7Vv" not in out
    assert "PRIVATE-KEY-REDACTED" in out


@pytest.mark.parametrize("benign", [
    "NAME  STATUS  RESTARTS\npod-1  Running  0",
    "the password_env field names the variable, not the value",
    "SELECT count(*) FROM rides WHERE city = 'x'",
    "token_bucket_size = 40",
])
def test_ordinary_output_is_left_alone(benign: str) -> None:
    """Over-redaction destroys the answers this tool exists to give."""
    from app.redactor import redact_text

    assert redact_text(benign) == benign


def test_every_credential_pattern_actually_compiles_to_something_matchable() -> None:
    """The guard against the \\b-to-backspace bug recurring: a pattern
    containing a control character can never match real text."""
    from app import redactor

    for name in dir(redactor):
        if name.endswith("_RE"):
            pattern = getattr(redactor, name).pattern
            assert "\x08" not in pattern, f"{name} contains a literal backspace"
