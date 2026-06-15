"""Report Agent — second-level orchestrator that synthesizes intel into narrative reports."""
from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from argus.agents.base import BaseAgent
from argus.models.report import CTIReport, Recommendation


class _ReportNarrative(BaseModel):
    executive_summary: str = ""
    key_findings: list[str] = []
    threat_landscape: str = ""
    recommendations: list[Recommendation] = []


_SYSTEM = """\
You are a professional Cyber Threat Intelligence (CTI) report author. You write clear,
concise, and actionable threat intelligence reports for security teams and executives.

You will receive structured threat intelligence data as context. Your job is to:
1. Write an executive summary (2-3 paragraphs, suitable for non-technical leadership).
2. List key findings (bullet points, most critical first).
3. Describe the threat landscape narrative in detail.
4. Provide prioritized recommendations with rationale.

Return your analysis as a JSON object:
{
  "executive_summary": "...",
  "key_findings": ["finding 1", "finding 2"],
  "threat_landscape": "detailed narrative...",
  "recommendations": [
    {"priority": "critical|high|medium|low", "action": "...", "rationale": "..."}
  ]
}

Return ONLY valid JSON. Be specific, actionable, and accurate to the data provided."""


class ReportAgent(BaseAgent):
    name = "report"

    def get_system_prompt(self) -> str:
        return _SYSTEM

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        return []

    async def dispatch_tool(self, tool_name: str, tool_input: dict[str, Any]) -> str:
        return json.dumps({"error": f"Report agent has no tools: {tool_name}"})

    async def run(self, report: CTIReport, scope: str = "") -> CTIReport:  # type: ignore[override]
        context_parts = [f"Report Type: {report.report_type.value.upper()}"]
        if scope:
            context_parts.append(f"Scope: {scope}")
        if report.period_start and report.period_end:
            context_parts.append(
                f"Period: {report.period_start.date()} to {report.period_end.date()}"
            )

        if report.ioc_summary:
            ioc_data = report.ioc_summary.model_dump()
            ioc_data["indicators"] = ioc_data["indicators"][:10]
            ioc_json = json.dumps(ioc_data, indent=2, default=str)[:3000]
            context_parts.append(f"\n## IOC Intelligence\n{ioc_json}")

        if report.threat_actor_summary:
            ta_data = report.threat_actor_summary.model_dump()
            ta_json = json.dumps(ta_data, indent=2, default=str)[:3000]
            context_parts.append(f"\n## Threat Actor Intelligence\n{ta_json}")

        if report.vulnerability_summary:
            vuln_data = report.vulnerability_summary.model_dump()
            vuln_json = json.dumps(vuln_data, indent=2, default=str)[:3000]
            context_parts.append(f"\n## Vulnerability Intelligence\n{vuln_json}")

        if report.alert_summary:
            alert_data = report.alert_summary.model_dump()
            alert_data["triaged_alerts"] = alert_data["triaged_alerts"][:10]
            alert_json = json.dumps(alert_data, indent=2, default=str)[:2000]
            context_parts.append(f"\n## Alert Triage Summary\n{alert_json}")

        # Determine the effective time window (start_time/end_time override period_start/end)
        window_start = report.start_time or report.period_start
        window_end = report.end_time or report.period_end
        time_window_note = ""
        if window_start and window_end:
            time_window_note = (
                f"\n\nFocus on intelligence from "
                f"{window_start.strftime('%Y-%m-%d %H:%M UTC')} to "
                f"{window_end.strftime('%Y-%m-%d %H:%M UTC')}."
            )

        prompt = (
            f"Generate a {report.report_type.value} CTI report"
            " using the following intelligence data:\n\n"
            + "\n".join(context_parts)
            + time_window_note
        )

        # Raises AgentError on parse/validation failure — let caller handle.
        narrative = await self._run_structured(prompt, _ReportNarrative)
        report.executive_summary = narrative.executive_summary
        report.key_findings = narrative.key_findings
        report.threat_landscape = narrative.threat_landscape
        report.recommendations = narrative.recommendations
        return report
