"""Alert Triage Agent — enriches and triages security alerts."""
from __future__ import annotations

import json
from typing import Any

from argus.agents.base import BaseAgent
from argus.models.alert import AlertTriageResult
from argus.tools.registry import dispatch_tool, get_available_tools

_SYSTEM = """\
You are an experienced SOC analyst performing alert triage. Your job is to:
1. Extract IOCs (IPs, domains, hashes, URLs) from each raw alert log.
2. Enrich extracted IOCs using available threat intelligence tools.
3. Correlate findings with MITRE ATT&CK techniques.
4. Assign a risk score (1-10) and decide: TRUE_POSITIVE, FALSE_POSITIVE, or NEEDS_INVESTIGATION.
5. Recommend specific response actions.

For each alert, provide reasoning before concluding. Be thorough but decisive.
Return your analysis as a JSON object matching AlertTriageResult:
{
  "triaged_alerts": [
    {
      "alert": {
        "alert_id": "...",
        "raw_log": "...",
        "source_ip": null,
        "dest_ip": null,
        "rule_name": "",
        "original_severity": ""
      },
      "decision": "true_positive|false_positive|needs_investigation",
      "risk_score": 1-10,
      "confidence": 0.0-1.0,
      "enriched_iocs": [],
      "related_threat_actors": [],
      "related_techniques": ["T1566"],
      "analyst_notes": "...",
      "recommended_actions": []
    }
  ],
  "true_positive_count": 0,
  "false_positive_count": 0,
  "needs_investigation_count": 0,
  "high_priority_alerts": ["alert_ids with risk_score >= 8"],
  "summary": "..."
}

Return ONLY valid JSON."""


class TriageAgent(BaseAgent):
    name = "triage"

    def get_system_prompt(self) -> str:
        return _SYSTEM

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        return get_available_tools("triage")

    async def dispatch_tool(self, tool_name: str, tool_input: dict[str, Any]) -> str:
        return await dispatch_tool(tool_name, tool_input)

    async def run(self, alerts: list[dict[str, Any]], context: str = "") -> AlertTriageResult:  # type: ignore[override]
        alerts_json = json.dumps(alerts, indent=2)
        ctx = f"\nAdditional context: {context}" if context else ""
        prompt = f"Triage the following alerts:{ctx}\n\n{alerts_json}"
        return await self._run_structured(prompt, AlertTriageResult)
