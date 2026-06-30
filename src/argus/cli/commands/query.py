"""argus query — natural language query via orchestrator."""

from __future__ import annotations

import asyncio
import json as json_lib
from typing import Annotated, Any

import typer

from argus.cli.output import print_agent_error, render_markdown, status, thinking

app = typer.Typer(help="Ask natural language threat intelligence questions")


@app.command("ask")
def ask(
    question: Annotated[str, typer.Argument(help="Natural language question")],
    json: Annotated[bool, typer.Option("--json", "-j", help="Output raw JSON")] = False,
) -> None:
    """Ask a threat intelligence question (routes to appropriate agents automatically)."""
    from argus.agents.orchestrator import CTIOrchestrator
    from argus.config.settings import get_settings

    settings = get_settings()
    if settings.disclosure_mode == "confirm-external" and not typer.confirm(
        f"Send query to {settings.model_provider}?",
        default=False,
    ):
        if json:
            print(json_lib.dumps({"cancelled": True}))
        else:
            typer.echo("Cancelled.")
        return

    async def _go() -> Any:
        progress = status if not json else None
        with thinking("argus is thinking", enabled=not json):
            return await CTIOrchestrator(progress=progress).run(user_query=question)

    try:
        answer = asyncio.run(_go())
        if json:
            print(json_lib.dumps({"answer": answer}))
        else:
            render_markdown(answer)
    except Exception as e:
        print_agent_error(e, as_json=json)
        raise typer.Exit(1)
