"""argus research — threat actor and campaign research commands."""
from __future__ import annotations

import asyncio
from typing import Annotated, Any

import typer

from argus.cli.output import print_agent_error, render_threat_actor_result, working

app = typer.Typer(help="Research threat actors and campaigns")


@app.command("actor")
def research_actor(
    name: Annotated[str, typer.Argument(help="Threat actor name or alias")],
    include_ttps: Annotated[bool, typer.Option("--include-ttps/--no-ttps")] = True,
    json: Annotated[bool, typer.Option("--json", "-j")] = False,
) -> None:
    """Research a threat actor or APT group."""
    from argus.agents.threat_actor_agent import ThreatActorAgent

    async def _go() -> Any:
        with working(f"Researching {name}...", enabled=not json):
            return await ThreatActorAgent().run(query=name, include_ttps=include_ttps)

    try:
        result = asyncio.run(_go())
        render_threat_actor_result(result, as_json=json)
    except Exception as e:
        print_agent_error(e, as_json=json)
        raise typer.Exit(1)


@app.command("campaign")
def research_campaign(
    name: Annotated[str, typer.Argument(help="Campaign name")],
    json: Annotated[bool, typer.Option("--json", "-j")] = False,
) -> None:
    """Research a threat campaign."""
    from argus.agents.threat_actor_agent import ThreatActorAgent

    async def _go() -> Any:
        with working(f"Researching campaign {name}...", enabled=not json):
            return await ThreatActorAgent().run(query=f"campaign: {name}")

    try:
        result = asyncio.run(_go())
        render_threat_actor_result(result, as_json=json)
    except Exception as e:
        print_agent_error(e, as_json=json)
        raise typer.Exit(1)
