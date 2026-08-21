"""FastAPI routers."""

from __future__ import annotations

from app.api import admin, ask, auth, health, web

__all__ = ["admin", "ask", "auth", "health", "web"]
