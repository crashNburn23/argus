"""IOC Enrichment Agent — cross-references multiple threat intel sources."""
from __future__ import annotations

from typing import Any

from argus.agents.base import BaseAgent
from argus.models.ioc import IOCEnrichmentResult
from argus.tools.registry import dispatch_tool, get_available_tools

_SYSTEM = """\
You are a cyber threat intelligence IOC enrichment specialist. Your job is to:
1. Look up each provided indicator in all available threat intelligence sources.
2. Cross-reference findings across sources to assess confidence and data freshness.
3. Identify related infrastructure, malware families, and threat actors.
4. Assign an overall verdict (malicious/suspicious/benign/unknown) with confidence score (0-1).
5. Identify related kill chain phases where relevant.

Use all available tools. Gather data from multiple sources before concluding.
Return your analysis as a JSON object matching the IOCEnrichmentResult schema:
{
  "indicators": [
    {
      "indicator": "...",
      "ioc_type": "ip|domain|url|md5|sha1|sha256|email|unknown",
      "overall_verdict": "malicious|suspicious|benign|unknown",
      "confidence": 0.0-1.0,
      "source_results": [{"source": "...", "verdict": "...", "confidence": 0.0-1.0, "details": {}}],
      "malware_families": [],
      "threat_actors": [],
      "tags": [],
      "geolocation": null,
      "asn": null,
      "first_seen": null,
      "last_seen": null,
      "stix_pattern": null,
      "kill_chain_phases": []
    }
  ],
  "summary": "...",
  "high_priority_iocs": ["indicators that are clearly malicious"],
  "recommended_actions": ["block X", "hunt for Y", ...]
}

Return ONLY valid JSON. Do not include markdown fences."""


class IOCEnrichmentAgent(BaseAgent):
    name = "ioc_enrichment"

    def get_system_prompt(self) -> str:
        return _SYSTEM

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        return get_available_tools("ioc")

    async def dispatch_tool(self, tool_name: str, tool_input: dict[str, Any]) -> str:
        return await dispatch_tool(tool_name, tool_input)

    async def run(self, indicators: list[str], ioc_type: str = "auto") -> IOCEnrichmentResult:  # type: ignore[override]
        prompt = (
            f"Enrich the following indicators (type hint: {ioc_type}):\n"
            + "\n".join(f"- {ind}" for ind in indicators)
        )
        return await self._run_structured(prompt, IOCEnrichmentResult)
