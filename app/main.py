"""FastAPI application assembly.

Startup order matters: storage is opened and migrated before any router can
serve a request, because every auth path reads the users table.

Read-only product: no router registered here mutates infrastructure. The only
writes anywhere in this process are to infragpt's own SQLite file and its
audit log.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from app.api import admin, ask, auth, health, web
from app.registry.schema import Surface
from app.storage import init_storage

log = logging.getLogger("infragpt")


def _bootstrap_admins(storage: Any) -> None:
    """Seed the first admins from env so the system isn't unadministrable.

    Idempotent, and it only ever *adds* the admin surface — it never activates
    or elevates a user who was disabled by a human.
    """
    raw = os.getenv("INFRAGPT_BOOTSTRAP_ADMINS", "")
    for email in (e.strip().lower() for e in raw.split(",") if e.strip()):
        user = storage.users.get_or_create(email, "")
        if user.status == "pending":
            storage.users.set_status(user.id, "active", "bootstrap")
        if not storage.grants.has_surface(user.id, Surface.ADMIN):
            storage.grants.grant(user.id, Surface.ADMIN, "bootstrap")
        log.info("bootstrapped admin %s", email)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    storage = init_storage()
    _bootstrap_admins(storage)
    app.state.storage = storage
    log.info("infragpt ready (read-only)")
    yield
    storage.db.close()


def create_app() -> FastAPI:
    app = FastAPI(
        title="infragpt",
        description="Read-only AI infrastructure assistant.",
        version="0.1.0",
        lifespan=lifespan,
    )
    # Same-origin static assets (self-hosted fonts). Not a CDN: a tool used
    # during incidents should not depend on a third party being reachable.
    static_dir = Path(__file__).resolve().parent / "web" / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.exception_handler(HTTPException)
    async def _auth_redirect(request: Request, exc: HTTPException) -> Response:
        """Send unauthenticated BROWSERS to the sign-in page.

        A 401 as JSON is right for the CLI and for fetch(), and useless to a
        person who has just been let through SSO and wants to use the thing —
        they saw a raw error object instead of a way in.

        Only 401 on a page navigation is redirected. API calls, and every other
        status, keep their normal response, so nothing that parses errors starts
        receiving HTML.
        """
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            accepts_html = "text/html" in request.headers.get("accept", "")
            is_api = request.url.path.startswith(("/ask", "/auth/me", "/healthz"))
            if accepts_html and not is_api:
                return RedirectResponse(
                    url="/auth/login", status_code=status.HTTP_303_SEE_OTHER
                )
        return await http_exception_handler(request, exc)

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(admin.router)
    app.include_router(ask.router)
    # Last: the UI serves "/" and must not shadow any JSON route above it.
    app.include_router(web.router)

    return app


app = create_app()
