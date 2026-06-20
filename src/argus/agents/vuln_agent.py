"""Vulnerability Intelligence Agent — CVE research, CISA KEV, exposure analysis."""

from __future__ import annotations

from typing import Any

from argus.agents.base import BaseAgent
from argus.models.vulnerability import VulnIntelResult
from argus.tools.registry import dispatch_tool, get_available_tools

_SYSTEM = """\
You are a vulnerability intelligence analyst. Your job is to:
1. Look up CVE details from NVD, including CVSS scores, affected products, and patch availability.
2. Check if vulnerabilities are in the CISA Known Exploited Vulnerabilities (KEV) catalog.
3. Query Shodan to assess how many systems are exposed to the vulnerability.
4. Determine exploitation status: unknown, proof-of-concept, actively exploited, or weaponized.
   A CVE confirmed in CISA KEV is by definition "active" or "weaponized" — never "unknown".
5. Prioritize patches by: CISA KEV status > CVSS score > active exploitation > exposure count.

IMPORTANT: When given multiple CVE IDs, pass them all at once using the cve_ids list
parameter in a single nvd_cve_lookup call — never call it once per CVE.

ERROR HANDLING: If a tool returns an error, record the failure and move on — do not
retry the same tool. If nvd_cve_lookup fails, synthesize from CISA KEV data if present,
and use null for any fields where NVD data is unavailable.
IMPORTANT: Do NOT call shodan_lookup with a cve parameter. The Shodan "vuln" filter
is not available on the current API plan and will always fail. Set shodan_exposure_count
to null — do not attempt to fill it via Shodan.

Use all available tools. Return your analysis as a JSON object matching VulnIntelResult:
{
  "vulnerabilities": [
    {
      "cve_id": "CVE-YYYY-NNNNN",
      "description": "...",
      "cvss_v3_score": 9.8,
      "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "severity": "critical|high|medium|low|none",
      "cwe_ids": [],
      "affected_products": [],
      "patch_available": true,
      "patch_urls": [],
      "in_cisa_kev": false,
      "exploitation_status": "unknown|poc|active|weaponized",
      "shodan_exposure_count": 0,
      "published_date": null,
      "last_modified": null
    }
  ],
  "critical_count": 0,
  "actively_exploited": ["CVE-..."],
  "patch_priority": [
    {"cve_id": "...", "priority": "critical|high|medium|low", "rationale": "..."}
  ],
  "summary": "..."
}

Return ONLY valid JSON."""


class VulnIntelAgent(BaseAgent):
    name = "vuln_intel"

    def get_system_prompt(self) -> str:
        return _SYSTEM

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        return get_available_tools("vuln")

    async def dispatch_tool(self, tool_name: str, tool_input: dict[str, Any]) -> str:
        return await dispatch_tool(tool_name, tool_input)

    async def run(  # type: ignore[override]
        self,
        cve_ids: list[str] | None = None,
        keywords: str = "",
        severity_threshold: str = "high",
    ) -> VulnIntelResult:
        self._progress("vuln_intel: planning NVD, KEV, and exposure checks")
        parts = []
        if cve_ids:
            parts.append(f"Look up these CVEs: {', '.join(cve_ids)}")
        if keywords:
            parts.append(f"Search for vulnerabilities related to: {keywords}")
        if severity_threshold:
            parts.append(f"Focus on {severity_threshold} and above severity.")

        prompt = (
            "\n".join(parts) if parts else "Provide a summary of recent critical vulnerabilities."
        )
        return await self._run_structured(prompt, VulnIntelResult)
