"""Structured IOC-pivot agent used by the deterministic benchmark."""

from __future__ import annotations

from typing import Any

from argus.agents.base import BaseAgent
from argus.benchmarks.pivoting import FixtureDispatcher, PivotAnalysisResult, PivotCase
from argus.tools import (
    abuseipdb,
    alienvault_otx,
    certs,
    mitre_attack,
    passive_dns,
    shodan,
    virustotal,
    whois,
)

_TOOL_DEFINITIONS = {
    "virustotal_lookup": virustotal.get_tool_definition,
    "passive_dns_lookup": passive_dns.get_tool_definition,
    "ssl_cert_lookup": certs.get_tool_definition,
    "whois_lookup": whois.get_tool_definition,
    "shodan_lookup": shodan.get_tool_definition,
    "abuseipdb_check": abuseipdb.get_tool_definition,
    "otx_lookup": alienvault_otx.get_tool_definition,
    "mitre_attack_lookup": mitre_attack.get_tool_definition,
}

_SYSTEM = """\
You are a CTI analyst investigating adversary infrastructure from seed IOCs.

Use the available tools to enrich each seed and pivot on useful findings. Follow domain/IP
resolutions, certificate SANs, registration details, and reputation evidence. Do not assume
that co-hosting proves common ownership. Treat CDNs, shared hosting, sinkholes, and unrelated
certificate names as possible noise. Do not invent tool results or attribution.

Every observable, relationship, or attribution must cite one or more evidence_id values
returned by tools. Record unrelated but observed infrastructure with disposition="noise".
Use these relationship types: resolves_to, resolved_to, certificate_san, registered_by,
hosted_by, communicates_with, related_to.

Return only JSON matching this shape:
{
  "observables": [
    {"value": "...", "observable_type": "domain|ip|hash|url|asn|certificate",
     "disposition": "seed|related|noise", "evidence_refs": ["tool_001"]}
  ],
  "relationships": [
    {"source": "...", "target": "...", "relationship_type": "resolves_to",
     "evidence_refs": ["tool_001"]}
  ],
  "attributions": [
    {"name": "...", "confidence": "low|moderate|high", "evidence_refs": ["tool_001"]}
  ],
  "findings": [],
  "intelligence_gaps": [],
  "recommendations": [],
  "report": "A concise evidence-grounded Markdown analyst report"
}
"""


class PivotBenchmarkAgent(BaseAgent):
    name = "pivot_benchmark"

    def __init__(self, case: PivotCase) -> None:
        super().__init__()
        self.case = case
        self.fixture_dispatcher = FixtureDispatcher(case)

    def get_system_prompt(self) -> str:
        return _SYSTEM

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        names = dict.fromkeys(fixture.tool for fixture in self.case.fixtures)
        return [_TOOL_DEFINITIONS[name]() for name in names if name in _TOOL_DEFINITIONS]

    async def dispatch_tool(self, tool_name: str, tool_input: dict[str, Any]) -> str:
        return await self.fixture_dispatcher.dispatch(tool_name, tool_input)

    async def run(self, **kwargs: Any) -> PivotAnalysisResult:
        seeds = ", ".join(
            f"{item.value} ({item.observable_type})" for item in self.case.seed_observables
        )
        prompt = f"Case: {self.case.title}\nSeeds: {seeds}\n\n{self.case.prompt}"
        return await self._run_structured(prompt, PivotAnalysisResult)
