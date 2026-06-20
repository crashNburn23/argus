"""argus serve — start the web UI server."""

from __future__ import annotations

import typer

app = typer.Typer(help="Start the Argus web UI server")


@app.callback(invoke_without_command=True)
def serve(
    ctx: typer.Context,
    host: str = typer.Option("127.0.0.1", "--host", "-H", help="Bind address"),
    port: int = typer.Option(8000, "--port", "-p", help="Port"),
    reload: bool = typer.Option(False, "--reload", "-r", help="Auto-reload on code changes"),
) -> None:
    """Start the Argus web UI (FastAPI + React frontend)."""
    if ctx.invoked_subcommand is not None:
        return

    try:
        import uvicorn
    except ImportError:
        typer.echo("uvicorn not installed. Run: uv add 'uvicorn[standard]'", err=True)
        raise typer.Exit(1)

    from pathlib import Path

    webui_dist = Path.cwd() / "webui" / "dist"
    if not webui_dist.exists():
        typer.echo(
            "Frontend not yet built — API will be available but the UI won't render.\n"
            "To build: cd webui && npm install && npm run build\n"
            "For development, run Vite separately: cd webui && npm run dev",
            err=True,
        )
    else:
        typer.echo(f"Serving frontend from {webui_dist}")

    typer.echo(f"Argus web server starting at http://{host}:{port}")
    typer.echo(f"API docs: http://{host}:{port}/api/docs")

    uvicorn.run(
        "argus.web.server:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )
