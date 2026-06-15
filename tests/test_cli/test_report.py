from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from argus.benchmarks.incidents import build_expected_report, get_incident_case
from argus.cli.app import app


def test_incident_report_command_consumes_alert_file(tmp_path) -> None:
    case = get_incident_case("IR-0001")
    alerts_path = tmp_path / "alerts.json"
    alerts_path.write_text(json.dumps([alert.model_dump(mode="json") for alert in case.alerts]))
    report = build_expected_report(case)
    report.content = "# Incident report"

    generator = AsyncMock()
    generator.generate_incident_from_alerts.return_value = report
    with patch("argus.reports.generator.ReportGenerator", return_value=generator):
        result = CliRunner().invoke(
            app,
            [
                "report",
                "incident",
                str(alerts_path),
                "--classification",
                "TLP:RED",
                "--no-save",
            ],
        )

    assert result.exit_code == 0
    assert "Incident report" in result.stdout
    classification = generator.generate_incident_from_alerts.await_args.kwargs["classification"]
    assert classification.value == "TLP:RED"
