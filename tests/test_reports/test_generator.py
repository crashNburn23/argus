from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from argus.benchmarks.incidents import build_expected_report, get_incident_case
from argus.models.report import ReportClassification
from argus.reports.generator import ReportGenerator


@pytest.mark.asyncio
async def test_generate_incident_from_alerts_uses_triage_in_report() -> None:
    case = get_incident_case("IR-0001")
    expected_report = build_expected_report(case)
    triage_agent = AsyncMock()
    triage_agent.run.return_value = expected_report.alert_summary
    report_agent = AsyncMock()
    report_agent.run.side_effect = lambda report, scope: report.model_copy(
        update={
            "executive_summary": case.description,
            "key_findings": case.expected.required_findings,
            "recommendations": expected_report.recommendations,
        }
    )

    with (
        patch("argus.reports.generator.TriageAgent", return_value=triage_agent),
        patch("argus.reports.generator.ReportAgent", return_value=report_agent),
    ):
        report = await ReportGenerator().generate_incident_from_alerts(
            alerts=[alert.model_dump(mode="json") for alert in case.alerts],
            context=case.context,
            save=False,
        )

    assert report.alert_summary == expected_report.alert_summary
    assert "EDR-1001" in report.content
    triage_agent.run.assert_awaited_once()
    report_agent.run.assert_awaited_once()


def test_report_classification_is_rendered_from_model() -> None:
    case = get_incident_case("IR-0001")
    report = build_expected_report(case).model_copy(
        update={"classification": ReportClassification.RED}
    )

    content = ReportGenerator().render(report)

    assert "| Classification | TLP:RED |" in content
