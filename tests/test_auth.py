"""Auth tests.

The load-bearing ones:

* ``test_forged_pomerium_assertion_is_rejected`` — anything that can reach the
  pod can set ``X-Pomerium-Jwt-Assertion``. If the signature is not verified,
  authentication is decorative. This test is the proof that it is verified.
* ``test_pending_user_cannot_call_granted_route`` — a grant is not access;
  admin activation is a separate, mandatory gate.
"""

from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jose import jwk, jwt

from app import config
from app.auth.pomerium import POMERIUM_HEADER, PomeriumVerifier, set_verifier
from app.main import create_app
from app.registry.schema import Surface
from app.storage import get_storage

AUDIENCE = "infragpt.example.com"


def _new_key(kid: str) -> tuple[str, dict]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public = jwk.construct(pem, algorithm="ES256").public_key().to_dict()
    public = {k: (v.decode() if isinstance(v, bytes) else v) for k, v in public.items()}
    public["kid"] = kid
    return pem, public


@pytest.fixture(scope="module")
def real_key() -> tuple[str, dict]:
    return _new_key("real")


@pytest.fixture(scope="module")
def attacker_key() -> tuple[str, dict]:
    return _new_key("attacker")


def assertion(pem: str, email: str, *, aud: str = AUDIENCE, exp_delta: int = 300) -> str:
    return jwt.encode(
        {
            "email": email,
            "name": email.split("@")[0],
            "sub": email,
            "aud": aud,
            "iss": "pomerium",
            "iat": int(time.time()),
            "exp": int(time.time()) + exp_delta,
        },
        pem,
        algorithm="ES256",
    )


@pytest.fixture()
def client(tmp_path, monkeypatch, real_key):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "auth.db")
    monkeypatch.setenv("INFRAGPT_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.delenv("INFRAGPT_BOOTSTRAP_ADMINS", raising=False)

    verifier = PomeriumVerifier(jwks_url="https://pomerium.invalid/.well-known/jwks.json",
                                audience=AUDIENCE)
    verifier.set_jwks({"keys": [real_key[1]]})
    set_verifier(verifier)

    with TestClient(create_app()) as c:
        yield c


def _pom(pem: str, email: str, **kw) -> dict[str, str]:
    return {POMERIUM_HEADER: assertion(pem, email, **kw)}


def _make_user(email: str, status: str, *surfaces: Surface) -> int:
    storage = get_storage()
    user = storage.users.get_or_create(email, email.split("@")[0])
    storage.users.set_status(user.id, status, "test")
    for s in surfaces:
        storage.grants.grant(user.id, s, "test")
    return user.id


# ---- health is the only open route ----------------------------------------


def test_health_is_unauthenticated(client) -> None:
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/health/ready").json()["schema_version"] > 0


def test_no_credentials_is_401(client) -> None:
    assert client.get("/auth/me").status_code == 401
    assert client.get("/admin/users").status_code == 401


# ---- signature verification ------------------------------------------------


def test_forged_pomerium_assertion_is_rejected(client, attacker_key, real_key) -> None:
    """A well-formed assertion signed by a key that is NOT in Pomerium's JWKS
    must be rejected, even though its claims name a real, active admin."""
    _make_user("admin@example.com", "active", Surface.ADMIN)

    forged = _pom(attacker_key[0], "admin@example.com")
    assert client.get("/auth/me", headers=forged).status_code == 401
    assert client.get("/admin/users", headers=forged).status_code == 401

    # Control: the identical request signed by the real key succeeds, so the
    # rejection above is about the signature and nothing else.
    ok = _pom(real_key[0], "admin@example.com")
    assert client.get("/auth/me", headers=ok).status_code == 200


def test_unsigned_and_malformed_assertions_are_rejected(client) -> None:
    def b64(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    alg_none = ".".join(
        [
            b64({"alg": "none", "typ": "JWT"}),
            b64({"email": "admin@example.com", "aud": AUDIENCE, "exp": int(time.time()) + 300}),
            "",
        ]
    )
    for bad in (alg_none, "not-a-jwt", "", "a.b.c", b64({"email": "x@y.z"})):
        assert client.get("/auth/me", headers={POMERIUM_HEADER: bad}).status_code == 401


def test_expired_assertion_is_rejected(client, real_key) -> None:
    headers = _pom(real_key[0], "someone@example.com", exp_delta=-60)
    assert client.get("/auth/me", headers=headers).status_code == 401


def test_wrong_audience_is_rejected(client, real_key) -> None:
    headers = _pom(real_key[0], "someone@example.com", aud="some-other-service")
    assert client.get("/auth/me", headers=headers).status_code == 401


# ---- activation gate -------------------------------------------------------


def test_first_login_creates_pending_user(client, real_key) -> None:
    resp = client.get("/auth/me", headers=_pom(real_key[0], "new.joiner@example.com"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "pending"
    assert body["grants"] == []
    assert body["via"] == "pomerium"


def test_pending_user_cannot_call_granted_route(client, real_key) -> None:
    """Holding the grant is not enough: status must be 'active' too."""
    _make_user("pending.admin@example.com", "pending", Surface.ADMIN)
    headers = _pom(real_key[0], "pending.admin@example.com")

    resp = client.get("/admin/users", headers=headers)
    assert resp.status_code == 403
    assert "awaiting admin approval" in resp.json()["detail"].lower()

    # Same user, once activated, gets through — proving the 403 was the status
    # gate and not a missing grant.
    storage = get_storage()
    user = storage.users.get_by_email("pending.admin@example.com")
    storage.users.set_status(user.id, "active", "test")
    assert client.get("/admin/users", headers=headers).status_code == 200


def test_disabled_user_is_refused(client, real_key) -> None:
    _make_user("gone@example.com", "disabled", Surface.ADMIN)
    resp = client.get("/admin/users", headers=_pom(real_key[0], "gone@example.com"))
    assert resp.status_code == 403
    assert "disabled" in resp.json()["detail"].lower()


def test_active_user_without_grant_is_refused(client, real_key) -> None:
    _make_user("plain@example.com", "active")
    resp = client.get("/admin/users", headers=_pom(real_key[0], "plain@example.com"))
    assert resp.status_code == 403
    assert "missing grant: admin" in resp.json()["detail"]


def test_admin_can_activate_and_grant(client, real_key) -> None:
    _make_user("admin@example.com", "active", Surface.ADMIN)
    target = _make_user("target@example.com", "pending")
    headers = _pom(real_key[0], "admin@example.com")

    activated = client.post(f"/admin/users/{target}/activate", headers=headers).json()
    assert activated["status"] == "active"
    assert activated["activated_by"] == "admin@example.com"

    granted = client.post(
        f"/admin/users/{target}/grants", headers=headers, json={"surface": "db:read"}
    ).json()
    assert granted["grants"] == ["db:read"]

    revoked = client.delete(f"/admin/users/{target}/grants/db:read", headers=headers).json()
    assert revoked["grants"] == []

    bad = client.post(
        f"/admin/users/{target}/grants", headers=headers, json={"surface": "k8s:azure"}
    )
    assert bad.status_code == 422


def test_disabling_a_user_revokes_their_cli_tokens(client, real_key) -> None:
    _make_user("admin@example.com", "active", Surface.ADMIN)
    victim = _make_user("victim@example.com", "active")
    storage = get_storage()
    raw = "nyc_victim_token"  # noqa: S105 - fixture
    storage.tokens.issue(victim, raw, 12)
    assert storage.tokens.resolve(raw) == victim

    client.post(
        f"/admin/users/{victim}/disable", headers=_pom(real_key[0], "admin@example.com")
    )
    assert storage.tokens.resolve(raw) is None


# ---- device-code flow ------------------------------------------------------


def test_device_flow_end_to_end(client, real_key) -> None:
    start = client.post("/auth/device/start").json()
    assert start["interval"] > 0
    assert start["user_code"] in start["verification_uri_complete"]

    # Before approval the CLI is told to keep polling, and gets no token.
    pending = client.post("/auth/device/token", json={"device_code": start["device_code"]})
    assert pending.status_code == 428
    assert pending.json()["detail"] == "authorization_pending"

    approve = client.post(
        "/auth/device/approve",
        headers=_pom(real_key[0], "cli.user@example.com"),
        json={"user_code": start["user_code"].lower()},  # normalisation
    )
    assert approve.status_code == 200

    token = client.post(
        "/auth/device/token", json={"device_code": start["device_code"]}
    ).json()["access_token"]

    me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert me["email"] == "cli.user@example.com"
    assert me["via"] == "cli"

    # Single-use: the same device_code cannot mint a second token.
    again = client.post("/auth/device/token", json={"device_code": start["device_code"]})
    assert again.status_code == 400


def test_device_approval_requires_verified_identity(client, attacker_key) -> None:
    start = client.post("/auth/device/start").json()
    resp = client.post(
        "/auth/device/approve",
        headers={POMERIUM_HEADER: assertion(attacker_key[0], "admin@example.com")},
        json={"user_code": start["user_code"]},
    )
    assert resp.status_code == 401
    assert client.post(
        "/auth/device/token", json={"device_code": start["device_code"]}
    ).status_code == 428


def test_unknown_device_code_is_rejected(client) -> None:
    resp = client.post("/auth/device/token", json={"device_code": "totally-made-up-code"})
    assert resp.status_code == 400
    assert resp.json()["detail"] == "invalid_grant"


def test_cli_token_auth_and_logout(client, real_key) -> None:
    victim = _make_user("cli2@example.com", "active")
    storage = get_storage()
    raw = "nyc_logout_me"  # noqa: S105 - fixture
    storage.tokens.issue(victim, raw, 12)
    headers = {"Authorization": f"Bearer {raw}"}

    assert client.get("/auth/me", headers=headers).status_code == 200
    assert client.post("/auth/logout", headers=headers).json()["revoked"] == "current"
    assert client.get("/auth/me", headers=headers).status_code == 401


def test_invalid_bearer_token_never_falls_back_to_header(client, real_key) -> None:
    """A bad bearer token must fail closed, not silently fall through to the
    Pomerium header path."""
    _make_user("admin@example.com", "active", Surface.ADMIN)
    headers = {
        "Authorization": "Bearer nyc_not_a_real_token",
        **_pom(real_key[0], "admin@example.com"),
    }
    assert client.get("/admin/users", headers=headers).status_code == 401


def test_ask_endpoint_passes_the_auth_gate(client, real_key) -> None:
    """An active user reaches /ask; whatever happens next is M3's business, but
    it must not be an authentication or activation refusal."""
    _make_user("plain@example.com", "active")
    resp = client.post(
        "/ask", headers=_pom(real_key[0], "plain@example.com"), json={"question": "hi"}
    )
    assert resp.status_code not in (401, 403)

    # ...whereas a pending user is stopped before any of that runs.
    _make_user("waiting@example.com", "pending")
    blocked = client.post(
        "/ask", headers=_pom(real_key[0], "waiting@example.com"), json={"question": "hi"}
    )
    assert blocked.status_code == 403


# ---- token sign-in ----------------------------------------------------------
# Replaces the earlier query-parameter dev-login. A token in a URL leaks into
# browser history, proxy logs and Referer headers; a POST body does not. That is
# what makes this safe to leave enabled in production rather than gated behind a
# dev-only flag.


def test_signin_page_renders(client) -> None:
    resp = client.get("/auth/login")
    assert resp.status_code == 200
    assert 'name="token"' in resp.text
    # A password field, so it is not shoulder-surfable or stored by the browser.
    assert 'type="password"' in resp.text


def test_valid_token_sets_an_httponly_cookie(client, real_key) -> None:
    user_id = _make_user("signin@example.com", "active", Surface.METRICS)
    raw = "nyc_signin_token"  # noqa: S105 - fixture
    get_storage().tokens.issue(user_id, raw, 12)

    resp = client.post("/auth/login", data={"token": raw}, follow_redirects=False)
    assert resp.status_code == 303
    cookie = resp.headers.get("set-cookie", "")
    assert "infractl_token=" in cookie
    assert "httponly" in cookie.lower()


def test_invalid_token_is_rejected_without_setting_a_cookie(client) -> None:
    resp = client.post("/auth/login", data={"token": "nyc_not_a_real_token"},
                       follow_redirects=False)
    assert resp.status_code == 401
    assert "set-cookie" not in {k.lower() for k in resp.headers}


def test_empty_token_is_rejected(client) -> None:
    resp = client.post("/auth/login", data={"token": "   "}, follow_redirects=False)
    assert resp.status_code == 401


def test_signin_never_mints_a_token(client) -> None:
    """It accepts an already-issued token and moves it into a cookie. It must
    not be a way to obtain access that you did not already have."""
    before = len(get_storage().db.query_all("SELECT id FROM cli_tokens", ()))
    client.post("/auth/login", data={"token": "nyc_nope"}, follow_redirects=False)
    after = len(get_storage().db.query_all("SELECT id FROM cli_tokens", ()))
    assert before == after


def test_no_token_in_url_path_exists(client) -> None:
    """The old GET /auth/dev-login took a token as a query parameter. It is gone,
    and must not come back."""
    assert client.get("/auth/dev-login?token=x").status_code == 404
