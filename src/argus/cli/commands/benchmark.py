"""argus benchmark - built-in incident report benchmark commands."""
from __future__ import annotations

import asyncio
import json as json_lib
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
    jsonl: Annotated[bool, typer.Option("--jsonl")] = False,
    minimum_score: Annotated[
        float,
        typer.Option("--minimum-score", help="Fail when aggregate score is below this value"),
    ] = 0.0,
    save_baseline: Annotated[
        Path | None,
        typer.Option("--save-baseline", help="Save run results as a baseline JSON file"),
    ] = None,
    compare: Annotated[
        Path | None,
        typer.Option("--compare", help="Compare results against a saved baseline JSON file"),
    ] = None,
) -> None:
    """Generate and score incident reports using the configured model."""
    if json and jsonl:
        print_error("Use --json or --jsonl, not both.")
        raise typer.Exit(2)
    if bool(case_id) == all_cases:
        print_error("Provide one CASE_ID or use --all.")
        raise typer.Exit(2)
    if not 0.0 <= minimum_score <= 1.0:
        print_error("--minimum-score must be between 0.0 and 1.0.")
        raise typer.Exit(2)
    if compare is not None and not compare.exists():
        print_error(f"Baseline file not found: {compare}")
        raise typer.Exit(2)

    baseline: dict[str, Any] = {}
    if compare is not None:
        try:
            baseline = json_lib.loads(compare.read_text())
        except Exception as exc:
            print_error(f"Could not load baseline: {exc}")
            raise typer.Exit(2)

    baseline_by_case: dict[str, float] = {
        r["case_id"]: r["score"] for r in baseline.get("results", [])
    }

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
        baseline_average: float | None = baseline.get("average_score")

        results_payload = [
            {
                **item["evaluation"].model_dump(),
                "duration_seconds": item["duration_seconds"],
                "report_path": item["report_path"],
                **(
                    {
                        "baseline_score": baseline_by_case.get(item["evaluation"].case_id),
                        "score_delta": (
                            item["evaluation"].score
                            - baseline_by_case[item["evaluation"].case_id]
                        )
                        if item["evaluation"].case_id in baseline_by_case
                        else None,
                    }
                    if baseline_by_case
                    else {}
                ),
            }
            for item in completed
        ]
        payload: dict[str, Any] = {
            "model_provider": settings.model_provider,
            "model": settings.model,
            "case_count": len(completed),
            "average_score": average,
            "duration_seconds": time.monotonic() - start,
            "minimum_score": minimum_score,
            "passed": passed,
            "results": results_payload,
        }
        if baseline_average is not None:
            payload["baseline_score"] = baseline_average
            payload["score_delta"] = average - baseline_average
            payload["baseline_model"] = baseline.get("model", "unknown")

        if save_baseline is not None:
            try:
                save_baseline.write_text(json_lib.dumps(payload, indent=2))
                if not json:
                    console.print(f"[dim]Baseline saved → {save_baseline}[/dim]")
            except Exception as exc:
                print_error(f"Could not save baseline: {exc}")

        if jsonl:
            for entry in results_payload:
                print(json_lib.dumps(entry))
        elif json:
            print_json(payload)
        else:
            table = Table(title="Benchmark Results")
            table.add_column("Case")
            table.add_column("Score", justify="right")
            if baseline_by_case:
                table.add_column("Delta", justify="right")
            table.add_column("Decision")
            table.add_column("Tech↓", justify="right")
            table.add_column("Find↓", justify="right")
            table.add_column("Act↓", justify="right")
            table.add_column("Duration", justify="right")
            for item, result_row in zip(completed, results_payload):
                result = item["evaluation"]
                row = [
                    result.case_id,
                    f"{result.score:.0%}",
                ]
                if baseline_by_case:
                    delta = result_row.get("score_delta")
                    if delta is None:
                        row.append("n/a")
                    elif delta > 0.005:
                        row.append(f"[green]+{delta:.0%}[/green]")
                    elif delta < -0.005:
                        row.append(f"[red]{delta:.0%}[/red]")
                    else:
                        row.append("–")
                row += [
                    "match" if result.decision_match else "[red]miss[/red]",
                    str(len(result.techniques_missing)),
                    str(len(result.findings_missing)),
                    str(len(result.actions_missing)),
                    f"{item['duration_seconds']:.1f}s",
                ]
                table.add_row(*row)
            console.print(table)
            status = "PASS" if passed else "FAIL"
            aggregate_line = (
                f"[bold]Aggregate:[/bold] {average:.0%}  "
                f"[bold]Threshold:[/bold] {minimum_score:.0%}  "
                f"[bold]{status}[/bold]"
            )
            if baseline_average is not None:
                delta_sign = "+" if average >= baseline_average else ""
                aggregate_line += (
                    f"  [bold]vs baseline:[/bold] {delta_sign}"
                    f"{average - baseline_average:.0%} "
                    f"(baseline {baseline_average:.0%} on {baseline.get('model', '?')})"
                )
            console.print(aggregate_line)
            console.print(f"[dim]{settings.model_provider} / {settings.model}[/dim]")
        if not passed:
            raise typer.Exit(1)
    except Exception as exc:
        if isinstance(exc, typer.Exit):
            raise
        print_agent_error(exc, as_json=json)
        raise typer.Exit(1)
