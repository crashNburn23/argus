"""argus query — natural language query via orchestrator."""
from __future__ import annotations

import asyncio
import json as json_lib
from typing import Annotated, Any

import typer

from argus.cli.output import print_agent_error, render_markdown, working

app = typer.Typer(help="Ask natural language threat intelligence questions")


@app.command("ask")
def ask(
    question: Annotated[str, typer.Argument(help="Natural language question")],
    json: Annotated[bool, typer.Option("--json", "-j", help="Output raw JSON")] = False,
) -> None:
    """Ask a threat intelligence question (routes to appropriate agents automatically)."""
    from argus.agents.orchestrator import CTIOrchestrator

    async def _go() -> Any:
        with working("Investigating query...", enabled=not json):
            return await CTIOrchestrator().run(user_query=question)

    try:
        answer = asyncio.run(_go())
        if json:
            print(json_lib.dumps({"answer": answer}))
        else:
            render_markdown(answer)
    except Exception as e:
        print_agent_error(e, as_json=json)
        raise typer.Exit(1)
