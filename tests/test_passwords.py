"""Password hashing and the self-registration flow.

The properties here are the ones that matter if this ever faces something other
than a friendly network: a hash that cannot be reversed, an absent password that
never verifies, and a registration that grants nothing.
"""

from __future__ import annotations

import pytest

from app.auth import passwords


def test_a_password_round_trips() -> None:
    stored = passwords.hash_password("correct horse battery staple")
    assert passwords.verify("correct horse battery staple", stored) is True


def test_a_wrong_password_is_rejected() -> None:
    stored = passwords.hash_password("correct horse battery staple")
    assert passwords.verify("correct horse battery stapl", stored) is False


def test_the_plaintext_is_not_recoverable_from_the_hash() -> None:
    secret = "correct horse battery staple"  # noqa: S105 - a test fixture, not a credential
    stored = passwords.hash_password(secret)
    assert secret not in stored
    assert stored.startswith("scrypt$")


def test_the_same_password_hashes_differently_each_time() -> None:
    """Distinct salts. Identical hashes would reveal that two accounts share a
    password, which is a real leak across an org."""
    a = passwords.hash_password("correct horse battery staple")
    b = passwords.hash_password("correct horse battery staple")
    assert a != b
    assert passwords.verify("correct horse battery staple", a)
    assert passwords.verify("correct horse battery staple", b)


@pytest.mark.parametrize("stored", [None, "", "not-a-hash", "scrypt$bad", "$$$$$"])
def test_an_absent_or_malformed_hash_never_verifies(stored: str | None) -> None:
    """An account with no password must FAIL CLOSED — never be logged into with
    an empty string, and never crash into a 500 that reveals the difference."""
    assert passwords.verify("anything", stored) is False
    assert passwords.verify("", stored) is False


def test_an_empty_password_never_verifies_against_a_real_hash() -> None:
    stored = passwords.hash_password("correct horse battery staple")
    assert passwords.verify("", stored) is False


def test_short_passwords_are_refused_with_a_reason() -> None:
    with pytest.raises(passwords.PasswordError) as excinfo:
        passwords.hash_password("short")
    assert str(passwords.MIN_LENGTH) in str(excinfo.value)


def test_cost_parameters_travel_with_the_hash() -> None:
    """So they can be raised later without invalidating existing passwords."""
    stored = passwords.hash_password("correct horse battery staple")
    scheme, n, r, p, salt, digest = stored.split("$")
    assert (scheme, int(n) > 1024, int(r), int(p)) == ("scrypt", True, 8, 1)
    assert salt and digest


# --- throttling -------------------------------------------------------------


def test_repeated_failures_are_throttled() -> None:
    from app.auth.throttle import AttemptThrottle, Throttled

    clock = [1000.0]
    t = AttemptThrottle(limit=3, window_s=60, clock=lambda: clock[0])
    for _ in range(3):
        t.check("someone@example.com")
        t.record("someone@example.com")
    with pytest.raises(Throttled) as excinfo:
        t.check("someone@example.com")
    assert 0 < excinfo.value.retry_after_s <= 60


def test_the_window_slides() -> None:
    from app.auth.throttle import AttemptThrottle, Throttled

    clock = [1000.0]
    t = AttemptThrottle(limit=2, window_s=60, clock=lambda: clock[0])
    t.record("k")
    t.record("k")
    with pytest.raises(Throttled):
        t.check("k")
    clock[0] += 61
    t.check("k")  # must not raise


def test_success_clears_the_counter() -> None:
    """One mistyped password must not accumulate toward a lockout."""
    from app.auth.throttle import AttemptThrottle

    t = AttemptThrottle(limit=2, window_s=60)
    t.record("k")
    t.reset("k")
    t.check("k")
    t.check("k")


def test_one_key_being_throttled_does_not_throttle_another() -> None:
    from app.auth.throttle import AttemptThrottle, Throttled

    t = AttemptThrottle(limit=1, window_s=60)
    t.record("victim@example.com")
    with pytest.raises(Throttled):
        t.check("victim@example.com")
    t.check("bystander@example.com")  # must not raise
