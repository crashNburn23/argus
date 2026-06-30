"""argus doctor - configuration and source readiness checks."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.table import Table

from argus.cli.output import console, print_json
from argus.diagnostics import DiagnosticResult, run_diagnostics


def render_diagnostics(result: DiagnosticResult, as_json: bool = False) -> None:
    if as_json:
        print_json(
            {
                "ready": result.ready,
                "checks": [check.model_dump() for check in result.checks],
            }
        )
        return

    table = Table(title="Argus Readiness")
    table.add_column("Category")
    table.add_column("Component")
    table.add_column("Status")
    table.add_column("Detail")
    styles = {
        "ready": "cp.green",
        "configured": "cp.cyan",
        "disabled": "cp.dim",
        "blocked": "cp.amber",
        "misconfigured": "cp.amber",
        "failed": "cp.red",
    }
    for check in result.checks:
        style = styles.get(check.status, "cp.dim")
        table.add_row(
            check.category,
            check.name,
            f"[{style}]{check.status.upper()}[/{style}]",
            check.detail,
        )
    console.print(table)
    summary_style = "cp.green" if result.ready else "cp.red"
    summary = "ready" if result.ready else "not ready"
    console.print(f"[{summary_style}]Argus is {summary}.[/{summary_style}]")


def doctor_command(
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
    no_connectivity: Annotated[
        bool,
        typer.Option("--no-connectivity", help="Skip local model connectivity checks"),
    ] = False,
) -> None:
    """Check model, storage, and threat-source readiness."""
    result = run_diagnostics(check_connectivity=not no_connectivity)
    render_diagnostics(result, as_json=json)
    if not result.ready:
        raise typer.Exit(1)
