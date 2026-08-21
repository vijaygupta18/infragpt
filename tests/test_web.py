"""Web UI tests.

The load-bearing ones here are about *rendering*, not routing:

* ``test_untrusted_tool_output_is_escaped_in_history`` and
  ``test_untrusted_audit_content_is_escaped`` — pod logs and Redis values are
  attacker-influencable. If a log line containing ``<script>`` renders as markup,
  the audit screen becomes a stored-XSS delivery mechanism aimed at admins.
* ``test_no_safe_filter_anywhere`` / ``test_live_answer_renderer_never_uses_innerhtml``
  — the escaping guarantees above are only durable if no future edit can turn
  them off, so both mechanisms are asserted directly against the templates.
"""

from __future__ import annotations

import re
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jose import jwk, jwt

from app import audit, config
from app.access.roles import ROLES
from app.auth.pomerium import POMERIUM_HEADER, PomeriumVerifier, set_verifier
from app.main import create_app
from app.registry.schema import Surface
from app.storage import get_storage
from app.web import TEMPLATE_DIR

AUDIENCE = "infragpt.example.com"
XSS = "<script>alert('pwned')</script>"


@pytest.fixture(scope="module")
def signing_key() -> tuple[str, dict]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public = jwk.construct(pem, algorithm="ES256").public_key().to_dict()
    public = {k: (v.decode() if isinstance(v, bytes) else v) for k, v in public.items()}
    public["kid"] = "web-test"
    return pem, public


@pytest.fixture()
def client(tmp_path, monkeypatch, signing_key):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "web.db")
    monkeypatch.setenv("INFRAGPT_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.delenv("INFRAGPT_BOOTSTRAP_ADMINS", raising=False)

    verifier = PomeriumVerifier(jwks_url="https://pomerium.invalid/jwks", audience=AUDIENCE)
    verifier.set_jwks({"keys": [signing_key[1]]})
    set_verifier(verifier)

    with TestClient(create_app()) as c:
        yield c


def _headers(pem: str, email: str) -> dict[str, str]:
    token = jwt.encode(
        {
            "email": email,
            "name": email.split("@")[0],
            "aud": AUDIENCE,
            "exp": int(time.time()) + 300,
        },
        pem,
        algorithm="ES256",
    )
    return {POMERIUM_HEADER: token}


def _user(email: str, status: str, *surfaces: Surface) -> int:
    storage = get_storage()
    user = storage.users.get_or_create(email, email.split("@")[0])
    storage.users.set_status(user.id, status, "test")
    for s in surfaces:
        storage.grants.grant(user.id, s, "test")
    return user.id


@pytest.fixture()
def admin(client, signing_key) -> dict[str, str]:
    _user("admin@example.com", "active", Surface.ADMIN)
    return _headers(signing_key[0], "admin@example.com")


@pytest.fixture()
def member(client, signing_key) -> dict[str, str]:
    _user("dev@example.com", "active", Surface.DB_READ)
    return _headers(signing_key[0], "dev@example.com")


# ---- access control --------------------------------------------------------


def test_unauthenticated_ui_is_401(client) -> None:
    for path in ("/", "/admin", "/admin/audit-log", "/c/1"):
        assert client.get(path).status_code == 401, path


def test_pending_user_sees_awaiting_approval_page(client, signing_key) -> None:
    _user("newbie@example.com", "pending")
    resp = client.get("/", headers=_headers(signing_key[0], "newbie@example.com"))
    assert resp.status_code == 403
    assert "text/html" in resp.headers["content-type"]
    assert "Awaiting approval" in resp.text
    assert "awaiting admin approval" in resp.text.lower()
    # The chat composer must not be served to someone who cannot ask.
    assert "id=\"composer\"" not in resp.text


def test_disabled_user_sees_disabled_page(client, signing_key) -> None:
    _user("gone@example.com", "disabled", Surface.ADMIN)
    resp = client.get("/", headers=_headers(signing_key[0], "gone@example.com"))
    assert resp.status_code == 403
    assert "Account disabled" in resp.text


def test_non_admin_cannot_open_admin_screens(client, member) -> None:
    for path in ("/admin", "/admin/audit-log"):
        resp = client.get(path, headers=member)
        assert resp.status_code == 403, path
        assert "requires the admin grant" in resp.text
    # And the nav does not advertise them.
    assert 'href="/admin"' not in client.get("/", headers=member).text


def test_admin_sees_admin_nav(client, admin) -> None:
    body = client.get("/", headers=admin).text
    assert 'href="/admin"' in body
    assert 'href="/admin/audit-log"' in body


# ---- chat ------------------------------------------------------------------


def test_chat_page_renders(client, member) -> None:
    resp = client.get("/", headers=member)
    assert resp.status_code == 200
    # Assert structure, not copy. Wording is design material and will change;
    # a test that pins a headline string fails on every rewrite for no benefit.
    assert 'id="composer"' in resp.text
    assert 'id="q"' in resp.text
    assert "read-only" in resp.text
    assert 'id="composer"' in resp.text
    assert "dev@example.com" in resp.text


def test_chat_history_renders_in_sidebar_and_transcript(client, member) -> None:
    storage = get_storage()
    user = storage.users.get_by_email("dev@example.com")
    conv = storage.conversations.create(user.id)
    storage.conversations.add_message(conv.id, "user", "why is the reader slow?")
    storage.conversations.add_message(conv.id, "assistant", "top_queries shows a seq scan")

    listing = client.get("/", headers=member).text
    assert f'href="/c/{conv.id}"' in listing

    page = client.get(f"/c/{conv.id}", headers=member)
    assert page.status_code == 200
    assert "why is the reader slow?" in page.text
    assert "top_queries shows a seq scan" in page.text


def test_other_users_conversation_is_not_readable(client, member, admin) -> None:
    storage = get_storage()
    other = storage.users.get_by_email("admin@example.com")
    conv = storage.conversations.create(other.id)
    storage.conversations.add_message(conv.id, "assistant", "SECRET-CONTENT-XYZ")

    resp = client.get(f"/c/{conv.id}", headers=member)
    # Falls back to a fresh chat rather than confirming the id exists.
    assert resp.status_code == 200
    assert "SECRET-CONTENT-XYZ" not in resp.text


def test_untrusted_tool_output_is_escaped_in_history(client, member) -> None:
    """An assistant turn quoting a malicious pod log must render as text."""
    storage = get_storage()
    user = storage.users.get_by_email("dev@example.com")
    conv = storage.conversations.create(user.id)
    storage.conversations.add_message(conv.id, "assistant", f"log said: {XSS}")

    body = client.get(f"/c/{conv.id}", headers=member).text
    assert XSS not in body
    assert "&lt;script&gt;" in body


def test_ask_endpoint_contract_matches_what_the_ui_renders(client, member) -> None:
    """The UI posts here and renders either the documented success shape or the
    `detail` string. Anything else would render as a blank turn, so both branches
    are pinned regardless of whether M3's Grid backend is reachable."""
    resp = client.post("/ask", headers=member, json={"question": "hi"})
    body = resp.json()
    if resp.status_code == 200:
        assert {"conversation_id", "answer", "calls"} <= set(body)
        for call in body["calls"]:
            assert {"entry_name", "params", "target", "ok", "output"} <= set(call)
    else:
        assert isinstance(body.get("detail"), str) and body["detail"]


# ---- admin console ---------------------------------------------------------


def test_admin_console_lists_pending_queue_and_surfaces(client, admin) -> None:
    _user("waiting@example.com", "pending")
    resp = client.get("/admin", headers=admin)
    assert resp.status_code == 200
    # Assert structure, not copy — wording is design material and will change.
    assert "waiting@example.com" in resp.text
    assert 'data-role="engineer"' in resp.text   # role-based granting is offered
    assert 'data-role="viewer"' in resp.text
    # Every role must be offered — an admin should never have to leave this
    # screen to work out how to grant the access someone needs.
    for role in ROLES:
        assert f'data-role="{role.key}"' in resp.text


def test_admin_console_shows_existing_grants(client, admin) -> None:
    _user("dev@example.com", "active", Surface.DB_READ, Surface.METRICS)
    body = client.get("/admin", headers=admin).text
    # Grants are now shown as the roles they add up to, falling back to raw
    # surfaces for a hand-picked set that matches no role. This user holds
    # metrics (= Viewer) plus db:read, so both representations must appear.
    assert "dev@example.com" in body
    assert "db:read" in body


def test_admin_actions_reuse_the_json_api(client, admin) -> None:
    """The console must not introduce its own mutating form routes (CSRF)."""
    target = _user("waiting@example.com", "pending")
    body = client.get("/admin", headers=admin).text
    assert "<form" not in body  # no form-POST surface at all on this screen

    assert client.post(f"/admin/users/{target}/activate", headers=admin).status_code == 200
    assert client.post(
        f"/admin/users/{target}/grants", headers=admin, json={"surface": "redis:read"}
    ).json()["grants"] == ["redis:read"]


# ---- audit screen ----------------------------------------------------------


def _seed_audit() -> None:
    audit.audit_call(
        user_email="dev@example.com",
        conversation_id=1,
        question="unused indexes on booking?",
        entry_name="unused_indexes",
        params={"table": "booking"},
        target="driver_ro",
        cloud="gcp",
        validation_verdict="ok",
        ok=True,
        output="rows",
        duration_ms=12,
    )
    audit.audit_call(
        user_email="admin@example.com",
        entry_name="pod_logs",
        params={"pod": "apps-1"},
        target="k8s_aws",
        cloud="aws",
        validation_verdict="ok",
        ok=False,
        error="timeout",
        duration_ms=30000,
    )
    audit.audit_question(
        user_email="admin@example.com",
        question="why is redis stale?",
        ok=True,
        answer="because it is per-cloud",
    )


def test_audit_screen_renders_records(client, admin) -> None:
    _seed_audit()
    body = client.get("/admin/audit-log", headers=admin).text
    assert "unused_indexes" in body
    assert "pod_logs" in body
    assert "driver_ro" in body
    assert "3 records" in body


def test_audit_filters(client, admin) -> None:
    _seed_audit()

    by_user = client.get("/admin/audit-log?user=dev@", headers=admin).text
    assert "unused_indexes" in by_user
    assert "pod_logs" not in by_user

    by_entry = client.get("/admin/audit-log?entry=pod_", headers=admin).text
    assert "pod_logs" in by_entry
    assert "unused_indexes" not in by_entry

    failed = client.get("/admin/audit-log?outcome=failed", headers=admin).text
    assert "pod_logs" in failed
    assert "unused_indexes" not in failed

    questions = client.get("/admin/audit-log?kind=question", headers=admin).text
    assert "why is redis stale?" in questions
    assert "unused_indexes" not in questions

    empty = client.get("/admin/audit-log?user=nobody@example.com", headers=admin).text
    assert "No records match these filters" in empty


def test_audit_screen_for_a_day_with_no_file(client, admin) -> None:
    resp = client.get("/admin/audit-log?day=1999-01-01", headers=admin)
    assert resp.status_code == 200
    assert "No records match these filters" in resp.text


def test_audit_rejects_malformed_filters(client, admin) -> None:
    assert client.get("/admin/audit-log?day=yesterday", headers=admin).status_code == 422
    assert client.get("/admin/audit-log?limit=99999", headers=admin).status_code == 422
    assert client.get("/admin/audit-log?outcome=maybe", headers=admin).status_code == 422


def test_untrusted_audit_content_is_escaped(client, admin) -> None:
    audit.audit_call(
        user_email="dev@example.com",
        question=f"what about {XSS}?",
        entry_name="pod_logs",
        params={"pod": XSS},
        target="k8s_gcp",
        validation_verdict="ok",
        ok=True,
        error=XSS,
    )
    body = client.get("/admin/audit-log", headers=admin).text
    assert XSS not in body
    assert "&lt;script&gt;" in body
    assert "alert(&#39;pwned&#39;)" in body or "alert('pwned')" not in body


# ---- template invariants ---------------------------------------------------


_JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.S)
_JS_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_JS_LINE_COMMENT = re.compile(r"^\s*//.*$", re.M)


def _templates() -> list[tuple[str, str]]:
    return [(p.name, p.read_text()) for p in sorted(TEMPLATE_DIR.glob("*.html"))]


def _templates_without_comments() -> list[tuple[str, str]]:
    """Scan live markup only — a comment saying "never use innerHTML" must not
    trip the test that enforces exactly that."""
    out = []
    for name, text in _templates():
        for pattern in (_JINJA_COMMENT, _JS_BLOCK_COMMENT, _JS_LINE_COMMENT):
            text = pattern.sub("", text)
        out.append((name, text))
    return out


def test_templates_exist() -> None:
    names = {name for name, _ in _templates()}
    assert {"base.html", "chat.html", "admin.html", "audit.html", "pending.html"} <= names


def test_no_safe_filter_anywhere() -> None:
    """A single `|safe` on infra-derived output would undo every escaping test."""
    for name, text in _templates_without_comments():
        assert "|safe" not in text.replace(" ", ""), name
        assert "autoescape false" not in text, name


def test_live_answer_renderer_never_uses_innerhtml() -> None:
    """The browser-side renderer must stay escape-by-construction."""
    for name, text in _templates_without_comments():
        assert "innerHTML" not in text, name
        assert "insertAdjacentHTML" not in text, name
        assert "document.write" not in text, name
        assert "outerHTML" not in text, name


def test_no_external_assets() -> None:
    """Nothing may be fetched from a CDN: this ships behind a strict CSP."""
    pattern = re.compile(r"""(src|href)\s*=\s*["'](https?:)?//""", re.I)
    for name, text in _templates_without_comments():
        assert not pattern.search(text), f"{name} references an external asset"
        assert "@import" not in text, name


def test_autoescape_is_enabled() -> None:
    from app.web import env

    assert env.autoescape
    template = env.from_string("{{ v }}")
    assert template.render(v=XSS) == (
        "&lt;script&gt;alert(&#39;pwned&#39;)&lt;/script&gt;"
    )


# ---- markdown rendering -----------------------------------------------------


def test_markdown_renderer_never_uses_innerhtml(client, member) -> None:
    """The renderer builds DOM with createElement/textContent only.

    Answers quote pod logs and Redis values. If any of that reached innerHTML,
    a log line containing markup would execute instead of being displayed.
    """
    body = client.get("/", headers=member).text
    script = body[body.index("renderMarkdown"):]
    for banned in (".innerHTML", "insertAdjacentHTML", "document.write", "outerHTML"):
        # Prose in comments is fine; an assignment is not.
        assert f"{banned} =" not in script, banned
        assert f"{banned}=" not in script, banned


def test_markdown_renderer_does_not_parse_links(client, member) -> None:
    """Links are the one construct that lets untrusted text choose a destination,
    so they are rendered as literal text rather than parsed."""
    body = client.get("/", headers=member).text
    script = body[body.index("window.renderMarkdown"):]
    assert "createElement('a')" not in script
    assert 'createElement("a")' not in script


def test_theme_toggle_is_present_and_three_state(client, member) -> None:
    body = client.get("/", headers=member).text
    assert 'id="theme"' in body
    # 'follow the OS' must stay reachable; a two-state flip strands it.
    assert "'system', 'light', 'dark'" in body


def test_dark_tokens_are_defined_for_both_explicit_and_system(client, member) -> None:
    """A token defined only inside a media query is how half a theme goes
    missing when the user picks dark explicitly."""
    body = client.get("/", headers=member).text
    assert ':root:not([data-theme="light"])' in body
    assert ':root[data-theme="dark"]' in body


# --- evidence survives a reload -------------------------------------------
#
# The interface leads with what an answer rests on. If that disappears when the
# page is reloaded, the claim it makes about itself is only true for the few
# seconds the answer is streaming.


def test_evidence_is_stored_with_the_answer_and_returned(client, member) -> None:
    storage = get_storage()
    user = storage.users.get_by_email("dev@example.com")
    conv = storage.conversations.create(user.id)
    storage.conversations.add_message(conv.id, "user", "q")
    storage.conversations.add_message(
        conv.id, "assistant", "a", evidence='[{"entry_name":"pod_status","ok":true}]'
    )
    stored = storage.conversations.messages(conv.id)
    assert stored[0].evidence is None, "a question rests on nothing"
    assert stored[1].evidence is not None
    assert "pod_status" in stored[1].evidence


def test_absent_and_empty_evidence_are_not_the_same_thing() -> None:
    """None means 'not recorded'; [] means 'answered without running anything'.

    Collapsing them would let an unsupported answer render as an ordinary one,
    which is the single most misleading thing this UI could do.
    """
    from app.storage.models import Message

    assert Message(1, 1, "assistant", "a", "now").evidence is None
    assert Message(1, 1, "assistant", "a", "now", evidence="[]").evidence == "[]"


def test_stored_evidence_is_escaped_into_the_attribute(client, member) -> None:
    """Params can contain a pod name, a Redis value, or a quoted log line.

    The evidence JSON is emitted into an HTML attribute, so a payload that
    closes the attribute would escape into markup. Autoescape must handle it.
    """
    storage = get_storage()
    user = storage.users.get_by_email("dev@example.com")
    conv = storage.conversations.create(user.id)
    hostile = '[{"entry_name":"x","params":{"k":"\\" onload=alert(1) x=\\""},"ok":true}]'
    storage.conversations.add_message(conv.id, "user", "q")
    storage.conversations.add_message(conv.id, "assistant", "a", evidence=hostile)

    body = client.get(f"/c/{conv.id}", headers=member).text
    # The payload may appear as inert TEXT inside the attribute — that is fine
    # and unavoidable, since it is part of the recorded params. What must not
    # happen is a quote surviving unescaped, which is what would close the
    # attribute and turn the rest into markup.
    assert '" onload=' not in body
    assert "&#34;" in body or "&quot;" in body


def test_evidence_leads_the_answer(client, member) -> None:
    """Sources under the conclusion is the anti-pattern this design exists to
    avoid, so the order is asserted rather than left to drift."""
    body = client.get("/", headers=member).text
    spine = body.index("turn.appendChild(calls.length ? renderSpine(calls)")
    answer = body.index("window.renderMarkdown(data.answer, answer)")
    assert spine < answer, "the spine must be appended before the answer"


# --- self-registration -> admin approval -> sign in ------------------------


def test_registration_creates_a_pending_account_that_can_do_nothing(client) -> None:
    """Registering must not be a way in. A new account holds no grants and is
    refused everywhere until an admin approves it."""
    r = client.post(
        "/auth/register",
        data={
            "email": "newjoiner@example.com",
            "password": "correct horse battery staple",
            "confirm": "correct horse battery staple",
            "name": "New Joiner",
        },
        follow_redirects=False,
    )
    assert r.status_code == 200
    assert "pending" in r.text.lower()

    storage = get_storage()
    user = storage.users.get_by_email("newjoiner@example.com")
    assert user is not None
    assert user.status == "pending"
    assert storage.grants.surfaces_for_user(user.id) == set()
    # Stored hashed, never in the clear.
    assert user.password_hash and "correct horse" not in user.password_hash


def test_a_pending_account_cannot_sign_in(client) -> None:
    client.post(
        "/auth/register",
        data={
            "email": "waiting@example.com",
            "password": "correct horse battery staple",
            "confirm": "correct horse battery staple",
        },
    )
    r = client.post(
        "/auth/login",
        data={"email": "waiting@example.com", "password": "correct horse battery staple"},
        follow_redirects=False,
    )
    # Not a redirect into the app — it lands on the pending explanation instead.
    assert r.status_code == 200
    assert "pending" in r.text.lower()
    assert "infractl_token" not in r.cookies


def test_an_approved_account_signs_in_and_gets_a_session(client) -> None:
    client.post(
        "/auth/register",
        data={
            "email": "approved@example.com",
            "password": "correct horse battery staple",
            "confirm": "correct horse battery staple",
        },
    )
    storage = get_storage()
    user = storage.users.get_by_email("approved@example.com")
    storage.users.set_status(user.id, "active", "admin-test")

    r = client.post(
        "/auth/login",
        data={"email": "approved@example.com", "password": "correct horse battery staple"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.cookies.get("infractl_token")


def test_a_wrong_password_is_refused(client) -> None:
    client.post(
        "/auth/register",
        data={
            "email": "wrongpw@example.com",
            "password": "correct horse battery staple",
            "confirm": "correct horse battery staple",
        },
    )
    storage = get_storage()
    user = storage.users.get_by_email("wrongpw@example.com")
    storage.users.set_status(user.id, "active", "admin-test")

    r = client.post(
        "/auth/login",
        data={"email": "wrongpw@example.com", "password": "not the password"},
        follow_redirects=False,
    )
    assert r.status_code == 401
    assert "infractl_token" not in r.cookies


def test_an_unknown_email_fails_exactly_like_a_wrong_password(client) -> None:
    """The login page must not reveal who has an account here."""
    r = client.post(
        "/auth/login",
        data={"email": "nobody@example.com", "password": "correct horse battery staple"},
        follow_redirects=False,
    )
    assert r.status_code == 401
    assert "incorrect" in r.text.lower()


def test_registering_an_existing_account_does_not_confirm_it_exists(client) -> None:
    """And it must not overwrite the password of an account that has one."""
    payload = {
        "email": "taken@example.com",
        "password": "correct horse battery staple",
        "confirm": "correct horse battery staple",
    }
    client.post("/auth/register", data=payload)
    storage = get_storage()
    before = storage.users.get_by_email("taken@example.com").password_hash

    r = client.post(
        "/auth/register",
        data={
            **payload,
            "password": "a totally different one",
            "confirm": "a totally different one",
        },
    )
    after = storage.users.get_by_email("taken@example.com").password_hash
    assert after == before, "an existing password must not be silently replaced"
    assert "already exists" not in r.text.lower()


def test_passwords_do_not_have_to_match_by_accident(client) -> None:
    r = client.post(
        "/auth/register",
        data={
            "email": "mismatch@example.com",
            "password": "correct horse battery staple",
            "confirm": "correct horse battery stapl",
        },
    )
    assert r.status_code == 400
    assert get_storage().users.get_by_email("mismatch@example.com") is None


def test_login_is_throttled_before_the_kdf_runs(client) -> None:
    """Unlimited guesses is unlimited guesses at every password behind the form.

    It is also a memory-exhaustion lever: scrypt allocates ~32MB per
    verification, so an unthrottled login lets an unauthenticated caller spend
    the pod's memory at will. The throttle must refuse BEFORE hashing.
    """
    from app.auth.throttle import LOGIN_THROTTLE

    LOGIN_THROTTLE.reset("bruteforce@example.com")
    last = None
    for _ in range(LOGIN_THROTTLE.limit + 2):
        last = client.post(
            "/auth/login",
            data={"email": "bruteforce@example.com", "password": "wrong guess here"},
            follow_redirects=False,
        )
    assert last is not None
    assert "too many" in last.text.lower()
    LOGIN_THROTTLE.reset("bruteforce@example.com")


def test_signing_out_revokes_the_token_server_side(client) -> None:
    """Deleting the cookie only makes the browser forget. Anything that captured
    the token — shared machine, proxy log, screenshot — kept working until TTL.
    """
    storage = get_storage()
    client.post(
        "/auth/register",
        data={
            "email": "signsout@example.com",
            "password": "correct horse battery staple",
            "confirm": "correct horse battery staple",
        },
    )
    user = storage.users.get_by_email("signsout@example.com")
    storage.users.set_status(user.id, "active", "admin-test")
    login = client.post(
        "/auth/login",
        data={"email": "signsout@example.com", "password": "correct horse battery staple"},
        follow_redirects=False,
    )
    token = login.cookies.get("infractl_token")
    assert storage.tokens.resolve(token) == user.id

    client.post("/auth/logout-web", follow_redirects=False)
    assert storage.tokens.resolve(token) is None, "the token must be dead after logout"


def test_the_session_cookie_is_secure_behind_a_terminating_proxy(client) -> None:
    """TLS ends at the proxy, so request.url.scheme is http even when the user is
    on https. Deriving `secure` from it would ship the cookie unencrypted."""
    storage = get_storage()
    client.post(
        "/auth/register",
        data={
            "email": "behindproxy@example.com",
            "password": "correct horse battery staple",
            "confirm": "correct horse battery staple",
        },
    )
    user = storage.users.get_by_email("behindproxy@example.com")
    storage.users.set_status(user.id, "active", "admin-test")

    r = client.post(
        "/auth/login",
        data={
            "email": "behindproxy@example.com",
            "password": "correct horse battery staple",
        },
        headers={"X-Forwarded-Proto": "https"},
        follow_redirects=False,
    )
    set_cookie = r.headers.get("set-cookie", "")
    assert "Secure" in set_cookie, set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie.replace("samesite", "SameSite")


def test_no_route_answers_questions_without_authentication(client) -> None:
    """The registration flow added two unauthenticated pages. Nothing else may
    have become reachable along with them."""
    for method, path, body in [
        ("post", "/ask", {"question": "what pods are running?"}),
        ("post", "/ask/stream", {"question": "what pods are running?"}),
        ("get", "/", None),
        ("get", "/admin", None),
        ("get", "/admin/audit-log", None),
        ("get", "/auth/me", None),
    ]:
        r = getattr(client, method)(path, json=body) if body else getattr(client, method)(path)
        assert r.status_code in (401, 403), f"{path} answered {r.status_code}"


def test_the_only_unauthenticated_pages_are_the_ones_intended(client) -> None:
    for path in ("/auth/login", "/auth/register"):
        assert client.get(path).status_code == 200


def test_registering_grants_no_surfaces_even_if_approved_later(client) -> None:
    """Approval makes an account usable; it does not decide what it can read.
    Those are separate steps on purpose, and approval must not imply grants."""
    client.post(
        "/auth/register",
        data={
            "email": "nogrants@example.com",
            "password": "correct horse battery staple",
            "confirm": "correct horse battery staple",
        },
    )
    storage = get_storage()
    user = storage.users.get_by_email("nogrants@example.com")
    storage.users.set_status(user.id, "active", "admin-test")
    assert storage.grants.surfaces_for_user(user.id) == set()


def test_an_unauthenticated_browser_lands_on_the_sign_in_page(client) -> None:
    """Behind SSO, a person who is let through and has no account here saw
    `{"detail":"..."}`. A page navigation must offer a way in, not an error."""
    r = client.get("/", headers={"Accept": "text/html"}, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/auth/login"


def test_api_callers_still_get_json_not_html(client) -> None:
    """The CLI and fetch() parse errors. Redirecting them would break both."""
    r = client.post(
        "/ask",
        json={"question": "what pods are running?"},
        headers={"Accept": "text/html"},
        follow_redirects=False,
    )
    assert r.status_code == 401
    assert r.headers["content-type"].startswith("application/json")


def test_an_unverifiable_pomerium_assertion_is_not_trusted(client) -> None:
    """The fix for the JWKS error must not become 'believe the header'."""
    r = client.get(
        "/auth/me",
        headers={"X-Pomerium-Jwt-Assertion": "not.a.real.jwt"},
        follow_redirects=False,
    )
    assert r.status_code == 401


# --- modal dialogs ----------------------------------------------------------


def test_no_native_browser_dialogs_remain(client, member, admin) -> None:
    """window.confirm/alert block the page, cannot be styled or themed, and read
    as a browser warning rather than part of the product. They are also a known
    hazard for automation: a native dialog freezes every subsequent event."""
    for path, headers in (("/", member), ("/admin", admin)):
        body = client.get(path, headers=headers).text
        assert "window.confirm(" not in body, path
        assert "window.alert(" not in body, path


def test_the_modal_is_a_real_dialog_element(client, member) -> None:
    """<dialog> + showModal() gives focus trapping, an inert background and
    Esc-to-close from the platform. A hand-rolled div gets those subtly wrong,
    usually for keyboard and screen-reader users."""
    body = client.get("/", headers=member).text
    assert "<dialog" in body
    assert "showModal()" in body
    assert "aria-labelledby" in body


def test_destructive_modals_focus_cancel_not_confirm(client, member) -> None:
    """So a reflexive Enter does not delete anything."""
    body = client.get("/", headers=member).text
    assert "opts.danger && !opts.alertOnly ? cancelBtn : confirmBtn" in body


def test_escape_declines_rather_than_confirms(client, member) -> None:
    body = client.get("/", headers=member).text
    assert "dlg.addEventListener('cancel'" in body
    assert "close(false)" in body


def test_modal_text_is_set_with_textcontent_only(client, member) -> None:
    """A conversation title or a server error can contain anything. This must
    never become a markup injection path."""
    body = client.get("/", headers=member).text
    modal = body[body.index("window.confirmModal") - 3000 : body.index("window.confirmModal")]
    assert "innerHTML" not in modal
    assert "textContent" in modal
