"""argus report — report generation commands."""
from __future__ import annotations

import asyncio
import json as json_lib
from pathlib import Path
from typing import Annotated, Any

import typer

from argus.cli.output import (
    console,
    print_agent_error,
    print_error,
    print_json,
    render_markdown,
    working,
)
from argus.models.report import ReportClassification

app = typer.Typer(help="Generate CTI reports")


def _emit_report(report: Any, output: Path | None, as_json: bool) -> None:
    if as_json:
        print_json(report)
    elif output:
        output.write_text(report.content, encoding="utf-8")
        console.print(f"[green]Report saved to:[/green] {output}")
    else:
        render_markdown(report.content)


@app.command("generate")
def generate_report(
    report_type: Annotated[
        str,
        typer.Argument(help="Report type: daily | weekly | monthly | yearly | incident"),
    ],
    scope: Annotated[str | None, typer.Option("--scope", "-s", help="Scope/focus area")] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Save report to file"),
    ] = None,
    json: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output report metadata as JSON"),
    ] = False,
    no_save: Annotated[
        bool,
        typer.Option("--no-save", help="Don't auto-save to reports dir"),
    ] = False,
    classification: Annotated[
        ReportClassification,
        typer.Option("--classification", help="Traffic Light Protocol classification"),
    ] = ReportClassification.AMBER,
) -> None:
    """Generate a CTI report (daily, weekly, monthly, yearly, incident)."""
    from argus.reports.generator import ReportGenerator

    valid_types = ("daily", "weekly", "monthly", "yearly", "incident")
    if report_type.lower() not in valid_types:
        print_error(f"Invalid report type '{report_type}'. Choose from: {', '.join(valid_types)}")
        raise typer.Exit(1)

    async def _go() -> Any:
        with working(f"Generating {report_type} CTI report...", enabled=not json):
            gen = ReportGenerator()
            return await gen.generate(
                report_type=report_type.lower(),
                scope=scope or "",
                classification=classification,
                save=not no_save,
            )

    try:
        report = asyncio.run(_go())
        _emit_report(report, output, json)
    except Exception as e:
        print_agent_error(e, as_json=json)
        raise typer.Exit(1)


@app.command("incident")
def generate_incident_report(
    alerts_file: Annotated[Path, typer.Argument(help="JSON file containing incident alerts")],
    context: Annotated[str | None, typer.Option("--context", "-c")] = None,
    title: Annotated[str, typer.Option("--title")] = "Incident Response Report",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    classification: Annotated[
        ReportClassification,
        typer.Option("--classification", help="Traffic Light Protocol classification"),
    ] = ReportClassification.AMBER,
    json: Annotated[bool, typer.Option("--json", "-j")] = False,
    no_save: Annotated[bool, typer.Option("--no-save")] = False,
) -> None:
    """Triage alert tickets and generate an incident report."""
    from argus.reports.generator import ReportGenerator

    if not alerts_file.exists():
        print_error(f"File not found: {alerts_file}")
        raise typer.Exit(1)
    try:
        alerts = json_lib.loads(alerts_file.read_text(encoding="utf-8"))
        if not isinstance(alerts, list):
            alerts = [alerts]
    except Exception as exc:
        print_error(f"Failed to parse alerts file: {exc}")
        raise typer.Exit(1)

    async def _go() -> Any:
        description = f"Generating incident report from {len(alerts)} alert(s)..."
        with working(description, enabled=not json):
            return await ReportGenerator().generate_incident_from_alerts(
                alerts=alerts,
                context=context or "",
                title=title,
                classification=classification,
                save=not no_save,
            )

    try:
        report = asyncio.run(_go())
        _emit_report(report, output, json)
    except Exception as exc:
        print_agent_error(exc, as_json=json)
        raise typer.Exit(1)
