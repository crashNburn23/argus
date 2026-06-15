from __future__ import annotations

from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from argus.benchmarks.incidents import build_expected_report, get_incident_case
from argus.cli.app import app
from argus.reports.generator import ReportGenerator


def test_benchmark_lists_cases() -> None:
    result = CliRunner().invoke(app, ["benchmark", "list"])

    assert result.exit_code == 0
    assert "IR-0001" in result.stdout
    assert "IR-0008" in result.stdout


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
