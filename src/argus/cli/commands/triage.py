"""argus triage — alert triage commands."""

from __future__ import annotations

import asyncio
import json as json_lib
from pathlib import Path
from typing import Annotated, Any

import typer

from argus.cli.output import print_agent_error, print_error, render_triage_result, status, thinking

app = typer.Typer(help="Triage security alerts")


@app.command("alerts")
def triage_alerts(
    alerts_file: Annotated[Path, typer.Argument(help="JSON file containing alert objects")],
    context: Annotated[str | None, typer.Option("--context", "-c")] = None,
    json: Annotated[bool, typer.Option("--json", "-j")] = False,
) -> None:
    """Triage a batch of alerts from a JSON file."""
    from argus.agents.triage_agent import TriageAgent

    if not alerts_file.exists():
        print_error(f"File not found: {alerts_file}")
        raise typer.Exit(1)

    try:
        alerts = json_lib.loads(alerts_file.read_text())
        if not isinstance(alerts, list):
            alerts = [alerts]
    except Exception as e:
        print_error(f"Failed to parse alerts file: {e}")
        raise typer.Exit(1)

    async def _go() -> Any:
        progress = status if not json else None
        with thinking(f"triaging {len(alerts)} alert(s)", enabled=not json):
            return await TriageAgent(progress=progress).run(
                alerts=alerts,
                context=context or "",
            )

    try:
        result = asyncio.run(_go())
        render_triage_result(result, as_json=json)
    except Exception as e:
        print_agent_error(e, as_json=json)
        raise typer.Exit(1)


@app.command("alert")
def triage_single(
    raw_log: Annotated[str, typer.Option("--raw-log", "-l", help="Raw log string to triage")],
    alert_id: Annotated[str, typer.Option("--id")] = "manual-1",
    context: Annotated[str | None, typer.Option("--context", "-c")] = None,
    json: Annotated[bool, typer.Option("--json", "-j")] = False,
) -> None:
    """Triage a single alert from a raw log string."""
    from argus.agents.triage_agent import TriageAgent

    alert = {"alert_id": alert_id, "raw_log": raw_log}

    async def _go() -> Any:
        progress = status if not json else None
        with thinking("triaging alert", enabled=not json):
            return await TriageAgent(progress=progress).run(
                alerts=[alert],
                context=context or "",
            )

    try:
        result = asyncio.run(_go())
        render_triage_result(result, as_json=json)
    except Exception as e:
        print_agent_error(e, as_json=json)
        raise typer.Exit(1)
