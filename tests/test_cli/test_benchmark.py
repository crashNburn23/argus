from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from argus.benchmarks.incidents import build_expected_report, get_incident_case
from argus.benchmarks.reporting import build_reference_report, get_reporting_case
from argus.cli.app import app
from argus.reports.generator import ReportGenerator


def test_benchmark_lists_cases() -> None:
    result = CliRunner().invoke(app, ["benchmark", "list"])

    assert result.exit_code == 0
    assert "IR-0001" in result.stdout
    assert "IR-0008" in result.stdout


def test_benchmark_lists_pivot_cases() -> None:
    result = CliRunner().invoke(app, ["benchmark", "pivot", "list"])

    assert result.exit_code == 0
    assert "PIVOT-0001" in result.stdout
    assert "PIVOT-0003" in result.stdout


def test_pivot_benchmark_run_requires_case_or_all() -> None:
    result = CliRunner().invoke(app, ["benchmark", "pivot", "run"])

    assert result.exit_code == 2
    assert "Provide one CASE_ID or use --all" in result.stderr


def test_benchmark_lists_reporting_cases() -> None:
    result = CliRunner().invoke(app, ["benchmark", "report", "list"])

    assert result.exit_code == 0
    assert "REPORT-0001" in result.stdout
    assert "REPORT-0004" in result.stdout


def test_reporting_benchmark_run_requires_case_or_all() -> None:
    result = CliRunner().invoke(app, ["benchmark", "report", "run"])

    assert result.exit_code == 2
    assert "Provide one CASE_ID or use --all" in result.stderr


def test_reporting_benchmark_saves_baseline(tmp_path) -> None:
    async def generate(case):
        return build_reference_report(get_reporting_case(case.case_id))

    baseline = tmp_path / "reporting-baseline.json"
    with patch(
        "argus.agents.case_report_agent.CaseReportAgent.generate",
        new=AsyncMock(side_effect=generate),
    ):
        result = CliRunner().invoke(
            app,
            [
                "benchmark",
                "report",
                "run",
                "--all",
                "--json",
                "--output-dir",
                str(tmp_path / "reports"),
                "--save-baseline",
                str(baseline),
            ],
        )

    assert result.exit_code == 0
    assert baseline.exists()
    payload = json.loads(baseline.read_text())
    assert payload["suite"] == "cti_reporting"
    assert payload["average_score"] == 1.0


def test_benchmark_renders_reference_case(tmp_path) -> None:
    result = CliRunner().invoke(
        app,
        ["benchmark", "render", "--case", "IR-0001", "--output-dir", str(tmp_path)],
    )

    assert result.exit_code == 0
    assert "Reference benchmark score: 100%" in result.stdout
    assert (tmp_path / "IR-0001.md").exists()


def test_benchmark_run_requires_case_or_all() -> None:
    result = CliRunner().invoke(app, ["benchmark", "run"])

    assert result.exit_code == 2
    assert "Provide one CASE_ID or use --all" in result.stderr


def test_benchmark_run_all_outputs_ci_summary(tmp_path) -> None:
    generator = ReportGenerator()

    async def generate_case(*, title, **kwargs):
        case = get_incident_case(title.split(":", 1)[0])
        report = build_expected_report(case)
        report.content = generator.render(report)
        return report

    with patch(
        "argus.cli.commands.benchmark.ReportGenerator.generate_incident_from_alerts",
        new=AsyncMock(side_effect=generate_case),
    ):
        result = CliRunner().invoke(
            app,
            [
                "benchmark",
                "run",
                "--all",
                "--json",
                "--minimum-score",
                "1.0",
                "--output-dir",
                str(tmp_path),
            ],
        )

    assert result.exit_code == 0
    assert '"case_count": 8' in result.stdout
    assert '"passed": true' in result.stdout


def _make_perfect_generator() -> AsyncMock:
    generator = ReportGenerator()

    async def generate_case(*, title, **kwargs):
        case = get_incident_case(title.split(":", 1)[0])
        report = build_expected_report(case)
        report.content = generator.render(report)
        return report

    return AsyncMock(side_effect=generate_case)


def test_benchmark_save_baseline_writes_file(tmp_path) -> None:
    baseline_path = tmp_path / "baseline.json"

    with patch(
        "argus.cli.commands.benchmark.ReportGenerator.generate_incident_from_alerts",
        new=_make_perfect_generator(),
    ):
        result = CliRunner().invoke(
            app,
            [
                "benchmark",
                "run",
                "--all",
                "--output-dir",
                str(tmp_path),
                "--save-baseline",
                str(baseline_path),
            ],
        )

    assert result.exit_code == 0
    assert baseline_path.exists()
    saved = json.loads(baseline_path.read_text())
    assert saved["case_count"] == 8
    assert saved["average_score"] == 1.0
    assert len(saved["results"]) == 8


def test_benchmark_compare_baseline_shows_delta(tmp_path) -> None:
    baseline = {
        "model": "test-model",
        "average_score": 0.5,
        "results": [{"case_id": f"IR-{i:04d}", "score": 0.5} for i in range(1, 9)],
    }
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline))

    with patch(
        "argus.cli.commands.benchmark.ReportGenerator.generate_incident_from_alerts",
        new=_make_perfect_generator(),
    ):
        result = CliRunner().invoke(
            app,
            [
                "benchmark",
                "run",
                "--all",
                "--json",
                "--output-dir",
                str(tmp_path),
                "--compare",
                str(baseline_path),
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["baseline_score"] == 0.5
    assert abs(payload["score_delta"] - 0.5) < 0.01
    assert payload["results"][0]["score_delta"] is not None


def test_benchmark_compare_missing_baseline_exits(tmp_path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            "run",
            "--all",
            "--compare",
            str(tmp_path / "nonexistent.json"),
        ],
    )

    assert result.exit_code == 2


def test_benchmark_jsonl_outputs_one_line_per_case(tmp_path) -> None:
    with patch(
        "argus.cli.commands.benchmark.ReportGenerator.generate_incident_from_alerts",
        new=_make_perfect_generator(),
    ):
        result = CliRunner().invoke(
            app,
            [
                "benchmark",
                "run",
                "--all",
                "--jsonl",
                "--output-dir",
                str(tmp_path),
            ],
        )

    assert result.exit_code == 0
    lines = [line for line in result.stdout.strip().splitlines() if line]
    assert len(lines) == 8
    first = json.loads(lines[0])
    assert "case_id" in first
    assert "score" in first


def test_benchmark_json_and_jsonl_mutually_exclusive(tmp_path) -> None:
    result = CliRunner().invoke(
        app,
        ["benchmark", "run", "--all", "--json", "--jsonl", "--output-dir", str(tmp_path)],
    )

    assert result.exit_code == 2
