"""Health endpoints — the only unauthenticated routes in the application."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from app.storage import get_storage

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "service": "infragpt", "read_only": True}


@router.get("/health/ready")
async def ready() -> dict[str, Any]:
    """Readiness: the SQLite volume must be attached and migrated."""
    storage = get_storage()
    row = storage.db.query_one("SELECT MAX(version) AS v FROM schema_version")
    return {"status": "ok", "schema_version": (row["v"] if row else 0) or 0}
