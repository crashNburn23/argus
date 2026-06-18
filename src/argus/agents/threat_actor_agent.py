"""Threat Actor Research Agent — researches threat groups, campaigns, and TTPs."""
from __future__ import annotations

from typing import Any

from argus.agents.base import BaseAgent
from argus.models.threat_actor import ThreatActorResearchResult
from argus.tools.registry import dispatch_tool, get_available_tools

_SYSTEM = """\
You are a cyber threat intelligence analyst specializing in threat actor research.
Your job is to:
1. Research known threat groups/actors matching the query using MITRE ATT&CK, OTX,
   Recorded Future, and web search.
2. Map their known TTPs to MITRE ATT&CK techniques.
3. Identify campaigns, associated malware, target sectors, and countries.
4. Assess sophistication, motivation, and resource level.
5. Provide actionable detection recommendations.

CRITICAL SOURCING RULES:
- Run multiple targeted web_search queries (e.g., "Icarus ransomware 2026",
  "Icarus data extortion group", "Icarus ransomware.live").
- Every claim about victims, TTPs, or activity MUST come from a specific web search
  result. Collect the URL of each source and include it in source_urls.
- If web search returns no results or only unrelated results: set description to
  "No public intelligence found for this actor as of today's date. Intelligence is
  limited — treat any reported activity as unconfirmed." Do NOT invent victim names,
  TTPs, target countries, or campaign details. It is better to report nothing than
  to fabricate data.
- Clearly distinguish between confirmed facts (from sources) and analytical
  assessments in the summary and key_findings.

Use all available tools. Cross-reference sources for attribution confidence.
Return your analysis as a JSON object matching the ThreatActorResearchResult schema:
{
  "actors": [
    {
      "name": "...",
      "aliases": [],
      "description": "...",
      "goals": [],
      "sophistication": "none|minimal|intermediate|advanced|expert|innovator|strategic",
      "resource_level": "individual|club|contest|team|organization|government",
      "primary_motivation": "...",
      "suspected_attribution": ["..."],
      "mitre_group_id": null,
      "techniques": [
        {"technique_id": "T1566", "technique_name": "...", "tactic": "...", "description": "..."}
      ],
      "campaigns": [{"name": "...", "description": "..."}],
      "associated_malware": [],
      "target_sectors": [],
      "target_countries": [],
      "source_urls": ["https://example.com/source1", "https://example.com/source2"]
    }
  ],
  "summary": "...",
  "key_findings": ["Finding with source: <url>", "..."],
  "recommended_detections": []
}

Return ONLY valid JSON."""


class ThreatActorAgent(BaseAgent):
    name = "threat_actor"

    def get_system_prompt(self) -> str:
        return _SYSTEM

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        return get_available_tools("threat_actor")

    async def dispatch_tool(self, tool_name: str, tool_input: dict[str, Any]) -> str:
        return await dispatch_tool(tool_name, tool_input)

    async def run(  # type: ignore[override]
        self,
        query: str,
        include_ttps: bool = True,
        include_iocs: bool = True,
    ) -> ThreatActorResearchResult:
        self._progress("threat_actor: scoping actor aliases, campaigns, and TTPs")
        extras = []
        if include_ttps:
            extras.append("Include full TTP mapping to MITRE ATT&CK.")
        if include_iocs:
            extras.append("Include known associated IOCs where available.")

        prompt = (
            f"Research this threat actor/campaign: {query}\n"
            + "\n".join(extras)
        )
        return await self._run_structured(prompt, ThreatActorResearchResult)
