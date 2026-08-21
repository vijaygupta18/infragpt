#!/usr/bin/env python3
"""Mint a local CLI token — LOCAL DEVELOPMENT AND BREAK-GLASS ONLY.

This writes directly to the SQLite database, so running it requires filesystem
access to the data directory. In production that means being inside the pod,
which is the intended bar: this is the recovery path for when SSO or the device
flow is broken, not an alternative to them.

It does NOT weaken the server's auth. The API still only accepts a verified
Pomerium assertion or a real bearer token; this just creates one of the latter.

    python scripts/dev_bootstrap.py you@example.com --all
    export INFRAGPT_URL=http://localhost:8000
    infractl ask "are rider-app pods healthy in gcp?"
"""

from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config  # noqa: E402
from app.registry.schema import Surface  # noqa: E402
from app.storage import init_storage  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("email")
    parser.add_argument("--name", default="")
    parser.add_argument(
        "--surface",
        action="append",
        default=[],
        help="Grant a surface (repeatable), e.g. --surface k8s:gcp",
    )
    parser.add_argument("--all", action="store_true", help="Grant every surface, including admin.")
    parser.add_argument("--ttl-hours", type=int, default=config.CLI_TOKEN_TTL_HOURS)
    args = parser.parse_args()

    storage = init_storage()
    user = storage.users.get_or_create(args.email, args.name or args.email.split("@")[0])
    storage.users.set_status(user.id, "active", "dev_bootstrap")

    surfaces = list(Surface) if args.all else [Surface(s) for s in args.surface]
    for surface in surfaces:
        storage.grants.grant(user.id, surface, "dev_bootstrap")

    raw = f"nyc_{secrets.token_urlsafe(32)}"
    storage.tokens.issue(user.id, raw, args.ttl_hours)

    granted = ", ".join(s.value for s in surfaces) or "(none)"
    print(f"user   : {user.email} (id={user.id}, active)", file=sys.stderr)
    print(f"grants : {granted}", file=sys.stderr)
    print(f"expires: {args.ttl_hours}h", file=sys.stderr)
    print(raw)  # stdout only, so it can be piped into the token file
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
