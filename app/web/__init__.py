"""Server-rendered web UI.

Two deliberate constraints, both security decisions rather than style choices:

1. **Autoescape is on and nothing derived from infra output is ever marked
   safe.** Pod logs and Redis values are attacker-influencable text — a log line
   containing ``<script>`` reaches this layer as data and must leave it as data.
   The only ``|safe`` in the whole UI would be a bug; there is none.

2. **No external assets.** CSS and JS are inlined into the page, so the app is
   servable under a strict CSP with no CDN, no remote fonts, and no network
   dependency at render time.

The live-answer path is the one place where HTML is assembled in the browser
rather than by Jinja. It builds nodes with ``createElement`` + ``textContent``
only — never ``innerHTML`` — which is escape-by-construction. ``test_web.py``
asserts that property against the shipped script so it cannot regress into a
string-concatenation renderer.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATE_DIR = Path(__file__).parent / "templates"

env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(default_for_string=True, default=True),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render(
    request: Request,
    template: str,
    context: dict[str, Any] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    """Render a template to an HTMLResponse.

    ``request`` is threaded through so templates can build self-referential URLs
    without hardcoding a host.
    """
    ctx: dict[str, Any] = {"request": request, "path": request.url.path}
    ctx.update(context or {})
    html = env.get_template(template).render(**ctx)
    return HTMLResponse(html, status_code=status_code)


__all__ = ["TEMPLATE_DIR", "env", "render"]
