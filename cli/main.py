"""infractl — the infragpt command line client.

Read-only by construction: every command here is a GET, or a POST to an
infragpt endpoint that only touches infragpt's own account model. There is
no command that can change infrastructure.
"""

from __future__ import annotations

import os
import time
import webbrowser
from pathlib import Path
from typing import Any

import httpx
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="infragpt CLI — ask read-only infra questions.", no_args_is_help=True)
admin_app = typer.Typer(help="Admin commands (requires the 'admin' grant).", no_args_is_help=True)
app.add_typer(admin_app, name="admin")

console = Console()
err = Console(stderr=True)

TOKEN_DIR = Path(os.getenv("INFRACTL_HOME", str(Path.home() / ".infractl")))
TOKEN_PATH = TOKEN_DIR / "token"
DEFAULT_URL = "http://localhost:8000"


# ---- token file -----------------------------------------------------------


def server_url() -> str:
    return os.getenv("INFRAGPT_URL", DEFAULT_URL).rstrip("/")


def save_token(token: str) -> None:
    TOKEN_DIR.mkdir(parents=True, exist_ok=True)
    TOKEN_DIR.chmod(0o700)
    # Create with 0600 from the start; never widen it later.
    fd = os.open(TOKEN_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token)
    TOKEN_PATH.chmod(0o600)


def load_token() -> str | None:
    if not TOKEN_PATH.exists():
        return None
    token = TOKEN_PATH.read_text(encoding="utf-8").strip()
    return token or None


def clear_token() -> None:
    TOKEN_PATH.unlink(missing_ok=True)


def _auth_headers() -> dict[str, str]:
    token = load_token()
    if not token:
        err.print("[red]Not logged in.[/red] Run [bold]infractl login[/bold].")
        raise typer.Exit(code=1)
    return {"Authorization": f"Bearer {token}"}


def _request(method: str, path: str, **kwargs: Any) -> httpx.Response:
    url = f"{server_url()}{path}"
    try:
        with httpx.Client(timeout=60.0) as client:
            return client.request(method, url, **kwargs)
    except httpx.HTTPError as exc:
        err.print(f"[red]Cannot reach {url}:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _api(method: str, path: str, **kwargs: Any) -> Any:
    resp = _request(method, path, headers=_auth_headers(), **kwargs)
    if resp.status_code == 401:
        err.print("[red]Session expired.[/red] Run [bold]infractl login[/bold].")
        raise typer.Exit(code=1)
    if resp.status_code >= 400:
        detail = resp.json().get("detail") if resp.headers.get(
            "content-type", ""
        ).startswith("application/json") else resp.text
        err.print(f"[red]{resp.status_code}:[/red] {detail}")
        raise typer.Exit(code=1)
    return resp.json()


# ---- ask ------------------------------------------------------------------

# Module-level singletons: typer wants these as defaults, ruff's B008 forbids
# calls in defaults, and both are satisfied by binding them once here.
QUESTION_ARG = typer.Argument(..., help="Your question, in plain English.")
CONVERSATION_OPT = typer.Option(None, "--conversation", "-c", help="Continue a thread.")
QUIET_OPT = typer.Option(False, "--quiet", "-q", help="Answer only; hide the evidence.")


@app.command()
def ask(
    question: list[str] = QUESTION_ARG,
    conversation: int | None = CONVERSATION_OPT,
    quiet: bool = QUIET_OPT,
) -> None:
    """Ask a read-only infrastructure question."""
    text = " ".join(question).strip()
    payload: dict[str, Any] = {"question": text}
    if conversation is not None:
        payload["conversation_id"] = conversation

    data = _api("POST", "/ask", json=payload)

    console.print()
    console.print(data["answer"])

    calls = data.get("calls") or []
    if calls and not quiet:
        # The evidence is shown by default on purpose: an answer you cannot check
        # is worth less than one you can, especially mid-incident.
        console.print()
        console.rule("[dim]evidence[/dim]")
        for call in calls:
            status_mark = "[green]ok[/green]" if call["ok"] else "[red]FAILED[/red]"
            where = call.get("cloud") or call.get("target") or "?"
            console.print(f"\n[bold]{call['entry_name']}[/bold] ({where}) {status_mark}")
            if call.get("params"):
                console.print(f"[dim]{call['params']}[/dim]")
            body = call.get("output") or call.get("error") or "(no output)"
            console.print(body.rstrip())
    console.print()
    console.print(f"[dim]conversation {data['conversation_id']}[/dim]")


# ---- auth commands --------------------------------------------------------


@app.command()
def login(
    no_browser: bool = typer.Option(False, "--no-browser", help="Print the URL instead."),
) -> None:
    """Log in via the device-code flow (approve in a browser through SSO)."""
    resp = _request("POST", "/auth/device/start")
    if resp.status_code >= 400:
        err.print(f"[red]Could not start login ({resp.status_code}):[/red] {resp.text}")
        raise typer.Exit(code=1)
    data = resp.json()

    console.print()
    console.print(f"  Your code: [bold cyan]{data['user_code']}[/bold cyan]")
    console.print(f"  Open:      [bold]{data['verification_uri_complete']}[/bold]")
    console.print()

    if not no_browser:
        try:
            webbrowser.open(data["verification_uri_complete"])
        except Exception as exc:  # noqa: BLE001 - headless box; URL is already printed
            err.print(f"[dim]Could not open a browser ({exc}); use the URL above.[/dim]")

    interval = int(data.get("interval", 5))
    deadline = time.monotonic() + int(data.get("expires_in", 600))
    with console.status("Waiting for approval..."):
        while time.monotonic() < deadline:
            poll = _request(
                "POST", "/auth/device/token", json={"device_code": data["device_code"]}
            )
            if poll.status_code == 200:
                save_token(poll.json()["access_token"])
                console.print("[green]Logged in.[/green] Token stored at ~/.infractl/token")
                whoami()
                return
            if poll.status_code != 428:
                detail = poll.json().get("detail", poll.text)
                err.print(f"[red]Login failed:[/red] {detail}")
                raise typer.Exit(code=1)
            time.sleep(interval)

    err.print("[red]Login timed out.[/red] Run `infractl login` again.")
    raise typer.Exit(code=1)


@app.command()
def logout() -> None:
    """Revoke this machine's token and delete it locally."""
    token = load_token()
    if token:
        _request("POST", "/auth/logout", headers={"Authorization": f"Bearer {token}"})
    clear_token()
    console.print("[green]Logged out.[/green]")


@app.command()
def whoami() -> None:
    """Show your identity, account status and grants."""
    me = _api("GET", "/auth/me")
    status_colour = {"active": "green", "pending": "yellow", "disabled": "red"}.get(
        me["status"], "white"
    )
    table = Table(show_header=False, box=None)
    table.add_row("email", me["email"])
    table.add_row("name", me.get("name") or "-")
    table.add_row("status", f"[{status_colour}]{me['status']}[/{status_colour}]")
    table.add_row("grants", ", ".join(me["grants"]) or "[dim]none[/dim]")
    table.add_row("server", server_url())
    console.print(table)
    if me["status"] == "pending":
        console.print("\n[yellow]Awaiting admin approval — no surfaces are callable yet.[/yellow]")


# ---- admin commands -------------------------------------------------------


@admin_app.command("users")
def admin_users() -> None:
    """List all users with status and grants."""
    users = _api("GET", "/admin/users")
    table = Table(title="infragpt users")
    for col in ("id", "email", "status", "grants", "last seen"):
        table.add_column(col)
    for u in users:
        table.add_row(
            str(u["id"]),
            u["email"],
            u["status"],
            ", ".join(u["grants"]) or "-",
            u.get("last_seen_at") or "-",
        )
    console.print(table)


@admin_app.command("activate")
def admin_activate(user_id: int) -> None:
    """Activate a pending user."""
    u = _api("POST", f"/admin/users/{user_id}/activate")
    console.print(f"[green]{u['email']} is now {u['status']}.[/green]")


@admin_app.command("disable")
def admin_disable(user_id: int) -> None:
    """Disable a user and revoke their CLI tokens."""
    u = _api("POST", f"/admin/users/{user_id}/disable")
    console.print(f"[yellow]{u['email']} is now {u['status']}.[/yellow]")


@admin_app.command("grant")
def admin_grant(
    user_id: int,
    surface: str = typer.Argument(..., help="k8s:gcp|k8s:aws|metrics|db:read|redis:read|admin"),
    expires_at: str | None = typer.Option(None, help="ISO-8601 expiry, e.g. 2026-01-31T00:00:00Z"),
) -> None:
    """Grant a surface to a user."""
    body: dict[str, Any] = {"surface": surface}
    if expires_at:
        body["expires_at"] = expires_at
    u = _api("POST", f"/admin/users/{user_id}/grants", json=body)
    console.print(f"[green]{u['email']} grants:[/green] {', '.join(u['grants']) or 'none'}")


@admin_app.command("revoke")
def admin_revoke(user_id: int, surface: str) -> None:
    """Revoke a surface from a user."""
    u = _api("DELETE", f"/admin/users/{user_id}/grants/{surface}")
    console.print(f"[yellow]{u['email']} grants:[/yellow] {', '.join(u['grants']) or 'none'}")


@admin_app.command("audit")
def admin_audit(
    day: str | None = typer.Option(None, help="YYYY-MM-DD (default: today)"),
    limit: int = typer.Option(50, help="Most recent N records"),
) -> None:
    """Show audit records."""
    params: dict[str, Any] = {"limit": limit}
    if day:
        params["day"] = day
    records = _api("GET", "/admin/audit", params=params)
    table = Table(title=f"audit ({day or 'today'})")
    for col in ("ts", "user", "kind", "entry", "ok", "ms"):
        table.add_column(col)
    for r in records:
        table.add_row(
            r.get("ts", ""),
            r.get("user_email", ""),
            r.get("kind", ""),
            r.get("entry_name") or "-",
            "yes" if r.get("ok") else "no",
            str(r.get("duration_ms", 0)),
        )
    console.print(table)


if __name__ == "__main__":  # pragma: no cover
    app()
