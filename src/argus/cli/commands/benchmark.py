"""argus benchmark - built-in incident report benchmark commands."""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.table import Table

from argus.benchmarks.incidents import (
    build_expected_report,
    evaluate_report,
    get_incident_case,
    load_incident_cases,
    save_report,
)
from argus.cli.output import console, print_agent_error, print_error, print_json, working
from argus.config.settings import get_settings
from argus.reports.generator import ReportGenerator

app = typer.Typer(help="Run built-in incident response report benchmarks")


@app.command("list")
def list_cases() -> None:
    """List the built-in synthetic incident tickets."""
    table = Table(title="Incident Response Benchmark Cases")
    table.add_column("Case")
    table.add_column("Expected")
    table.add_column("Severity")
    table.add_column("Title")
    for case in load_incident_cases():
        table.add_row(case.case_id, case.expected.decision, case.expected.severity, case.title)
    console.print(table)


@app.command("render")
def render_reference_reports(
    case_id: Annotated[str | None, typer.Option("--case", "-c")] = None,
    output_dir: Annotated[Path, typer.Option("--output-dir", "-o")] = Path("benchmark-reports"),
) -> None:
    """Render deterministic ground-truth reports without model or network calls."""
    cases = [get_incident_case(case_id)] if case_id else load_incident_cases()
    generator = ReportGenerator()
    results = []
    for case in cases:
        report = build_expected_report(case)
        report.content = generator.render(report)
        path = save_report(report, output_dir, case.case_id)
        results.append(evaluate_report(case, report))
        console.print(f"[green]Rendered[/green] {case.case_id}: {path}")
    average = sum(result.score for result in results) / len(results)
    console.print(f"[bold]Reference benchmark score:[/bold] {average:.0%}")


@app.command("run")
def run_live_cases(
    case_id: Annotated[
        str | None,
        typer.Argument(help="Incident case ID, for example IR-0001"),
    ] = None,
    all_cases: Annotated[
        bool,
        typer.Option("--all", help="Run every built-in incident case"),
    ] = False,
    output_dir: Annotated[Path, typer.Option("--output-dir", "-o")] = Path("benchmark-reports"),
    json: Annotated[bool, typer.Option("--json", "-j")] = False,
    minimum_score: Annotated[
        float,
        typer.Option("--minimum-score", help="Fail when aggregate score is below this value"),
    ] = 0.0,
) -> None:
    """Generate and score incident reports using the configured model."""
    if bool(case_id) == all_cases:
        print_error("Provide one CASE_ID or use --all.")
        raise typer.Exit(2)
    if not 0.0 <= minimum_score <= 1.0:
        print_error("--minimum-score must be between 0.0 and 1.0.")
        raise typer.Exit(2)

    cases = load_incident_cases() if all_cases else [get_incident_case(case_id or "")]

    async def _go() -> Any:
        generator = ReportGenerator()
        completed = []
        with working(f"Running {len(cases)} benchmark case(s)...", enabled=not json):
            for case in cases:
                start = time.monotonic()
                report = await generator.generate_incident_from_alerts(
                    alerts=[alert.model_dump(mode="json") for alert in case.alerts],
                    context=case.context,
                    title=f"{case.case_id}: {case.title}",
                    save=False,
                )
                path = save_report(report, output_dir, case.case_id)
                completed.append({
                    "evaluation": evaluate_report(case, report),
                    "duration_seconds": time.monotonic() - start,
                    "report_path": str(path),
                })
        return completed

    try:
        start = time.monotonic()
        completed = asyncio.run(_go())
        average = sum(item["evaluation"].score for item in completed) / len(completed)
        settings = get_settings()
        passed = average >= minimum_score
        payload = {
            "model_provider": settings.model_provider,
            "model": settings.model,
            "case_count": len(completed),
            "average_score": average,
            "duration_seconds": time.monotonic() - start,
            "minimum_score": minimum_score,
            "passed": passed,
            "results": [
                {
                    **item["evaluation"].model_dump(),
                    "duration_seconds": item["duration_seconds"],
                    "report_path": item["report_path"],
                }
                for item in completed
            ],
        }
        if json:
            print_json(payload)
        else:
            table = Table(title="Benchmark Results")
            table.add_column("Case")
            table.add_column("Score", justify="right")
            table.add_column("Decision")
            table.add_column("Missing")
            table.add_column("Duration", justify="right")
            for item in completed:
                result = item["evaluation"]
                missing = (
                    len(result.techniques_missing)
                    + len(result.findings_missing)
                    + len(result.actions_missing)
                )
                table.add_row(
                    result.case_id,
                    f"{result.score:.0%}",
                    "match" if result.decision_match else "miss",
                    str(missing),
                    f"{item['duration_seconds']:.1f}s",
                )
            console.print(table)
            status = "PASS" if passed else "FAIL"
            console.print(
                f"[bold]Aggregate:[/bold] {average:.0%}  "
                f"[bold]Threshold:[/bold] {minimum_score:.0%}  "
                f"[bold]{status}[/bold]"
            )
            console.print(f"[dim]{settings.model_provider} / {settings.model}[/dim]")
        if not passed:
            raise typer.Exit(1)
    except Exception as exc:
        if isinstance(exc, typer.Exit):
            raise
        print_agent_error(exc, as_json=json)
        raise typer.Exit(1)
