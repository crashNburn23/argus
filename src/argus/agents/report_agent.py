"""Report Agent — synthesizes multi-source intelligence into structured CTI reports."""
from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, field_validator, model_validator

from argus.agents.base import BaseAgent
from argus.models.report import CTIReport, Recommendation


class _ReportNarrative(BaseModel):
    introduction: str = ""
    executive_summary: str = ""
    key_findings: list[str] = []
    analyst_assessment: str = ""
    threat_actor_profiles: list[str] = []
    ttp_analysis: str = ""
    campaign_correlations: list[str] = []
    threat_landscape: str = ""
    confidence_assessment: str = ""
    recommendations: list[Recommendation] = []
    references: list[str] = []

    @model_validator(mode="before")
    @classmethod
    def _unwrap_recommendations(cls, data: Any) -> Any:
        """Coerce recommendations to list[Recommendation] when model returns a dict."""
        if not isinstance(data, dict):
            return data
        recs = data.get("recommendations")
        if not isinstance(recs, dict):
            return data
        # Case 1: wrapper dict with a list value — {"recommended_actions": [...]}
        for val in recs.values():
            if isinstance(val, list):
                return {**data, "recommendations": val}
        # Case 2: flat dict of priority→action strings — {"high": "Isolate...", ...}
        result = [
            {"priority": str(k), "action": str(v) if isinstance(v, str) else str(v), "rationale": ""}
            for k, v in recs.items()
        ]
        return {**data, "recommendations": result}

    @field_validator(
        "introduction", "executive_summary", "analyst_assessment",
        "ttp_analysis", "threat_landscape", "confidence_assessment",
        mode="before",
    )
    @classmethod
    def _coerce_narrative_str(cls, v: Any) -> str:
        if v is None:
            return ""
        if isinstance(v, dict):
            return " ".join(str(val) for val in v.values() if val)
        if isinstance(v, list):
            parts = []
            for item in v:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    parts.append(" ".join(str(val) for val in item.values() if val))
            return " ".join(parts)
        return str(v)

    @field_validator("key_findings", "threat_actor_profiles", "campaign_correlations", "references", mode="before")
    @classmethod
    def _coerce_str_list(cls, v: Any) -> list[str]:
        if not isinstance(v, list):
            return []
        result = []
        for item in v:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict):
                result.append(" ".join(str(val) for val in item.values() if val))
            else:
                result.append(str(item))
        return result


_SYSTEM = """\
You are a senior Cyber Threat Intelligence (CTI) analyst producing structured intelligence
reports. Your role is ANALYTICAL — you correlate evidence, identify patterns, attribute
activity, and form assessments. You are NOT a SOC triage analyst listing alert dispositions;
you are a researcher building a picture of adversary behavior.

You will receive structured intelligence from multiple sources (IOC enrichment, threat actor
research, vulnerability intelligence, and optionally alert triage). Your task:

1. CORRELATE: Find connections across sources. Which IOCs appear in known actor infrastructure?
   Which CVEs are being weaponized by observed actors? Do observed TTPs match active campaigns?
   Name specific indicators, actors, and technique IDs when making correlations.

2. ASSESS: Form a holistic intelligence assessment — what is the adversary attempting, what is
   their capability level, who is the likely target, and what is their current kill-chain stage?
   Assign confidence levels (HIGH / MODERATE / LOW) to each major conclusion.

3. PROFILE: For each relevant threat actor, analyze their *specific* activity in the provided
   context. Do not regurgitate their general description — tie their observed TTPs and known
   infrastructure to the evidence in hand.

4. MAP: Map observed behaviors to MITRE ATT&CK tactics and techniques. Explain what the TTP
   pattern reveals about actor intent, sophistication, and progress through the attack lifecycle.

5. CONTEXTUALIZE: Describe the broader threat landscape as it relates to the provided scope —
   industry sector, geopolitical context, campaign tracking — not a generic overview.

Intelligence standards to follow:
- Lead with the most important conclusion, not background.
- Every claim should be traceable to a specific piece of evidence in the provided data.
- Distinguish between confirmed intelligence and assessed (analytical) judgments.
- Acknowledge gaps — if data is insufficient to draw a conclusion, say so.
- Use precise language: "assessed with moderate confidence" not "may possibly."

Return your analysis as a JSON object:
{
  "introduction": "Purpose, scope, and intended audience. One paragraph.",
  "executive_summary": "2-3 paragraphs for non-technical leadership."
                       " Lead with the most critical conclusion. Avoid jargon.",
  "key_findings": [
    "Finding tied to specific evidence — cite IOC values, actor names, CVE IDs"
  ],
  "analyst_assessment": "Primary analytical product. Synthesize ALL intelligence into"
                        " a coherent narrative — connect IOCs to actor infrastructure,"
                        " map TTPs to kill-chain stages, assess adversary intent and"
                        " capability. Read like finished intelligence, not a fact list.",
  "threat_actor_profiles": [
    "Actor Name (MITRE ID): Specific activity in this context — which TTPs present,"
    " which IOCs tie to their infrastructure, which campaigns active, targeting intent."
  ],
  "ttp_analysis": "MITRE ATT&CK-mapped analysis grouped by tactic. Explain what the"
                  " TTP pattern reveals about sophistication and kill-chain stage.",
  "campaign_correlations": [
    "CORRELATION: Evidence A ties to Evidence B because [reason] — confidence HIGH.",
    "CORRELATION: CVE exploitation aligns with Actor Z's known targeting — MODERATE."
  ],
  "threat_landscape": "Sector/industry trends relevant to scope. Geopolitical factors,"
                      " active campaigns, year-over-year context.",
  "confidence_assessment": "Overall confidence: HIGH/MODERATE/LOW. List intelligence"
                           " gaps, collection limits, and key analytical assumptions.",
  "recommendations": [
    {
      "priority": "critical|high|medium|low",
      "action": "Specific, measurable action tied to observed intelligence",
      "rationale": "Which finding or actor behavior makes this necessary"
    }
  ],
  "references": ["Contributing source, e.g. VirusTotal, MITRE ATT&CK, NVD, OTX"]
}

Return ONLY valid JSON. Cite specific values from the data — no generalities. If a
section cannot be substantiated, state what additional collection would be needed."""


class ReportAgent(BaseAgent):
    name = "report"

    def get_system_prompt(self) -> str:
        return _SYSTEM

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        return []

    async def dispatch_tool(self, tool_name: str, tool_input: dict[str, Any]) -> str:
        return json.dumps({"error": f"Report agent has no tools: {tool_name}"})

    async def run(self, report: CTIReport, scope: str = "") -> CTIReport:  # type: ignore[override]
        self._progress("report: correlating intelligence and building analyst assessment")
        context_parts = [f"Report Type: {report.report_type.value.upper()}"]
        if scope:
            context_parts.append(f"Scope / Subject: {scope}")
        if report.period_start and report.period_end:
            context_parts.append(
                f"Intelligence Period: {report.period_start.date()} to {report.period_end.date()}"
            )

        if report.ioc_summary:
            ioc_data = report.ioc_summary.model_dump()
            ioc_data["indicators"] = ioc_data["indicators"][:15]
            context_parts.append(
                f"\n## IOC Enrichment Results\n{json.dumps(ioc_data, indent=2, default=str)[:4000]}"
            )

        if report.threat_actor_summary:
            ta_data = report.threat_actor_summary.model_dump()
            context_parts.append(
                f"\n## Threat Actor Research\n{json.dumps(ta_data, indent=2, default=str)[:4000]}"
            )

        if report.vulnerability_summary:
            vuln_data = report.vulnerability_summary.model_dump()
            vuln_json = json.dumps(vuln_data, indent=2, default=str)[:3000]
            context_parts.append(f"\n## Vulnerability Intelligence\n{vuln_json}")

        if report.alert_summary:
            alert_data = report.alert_summary.model_dump()
            alert_data["triaged_alerts"] = alert_data["triaged_alerts"][:10]
            alert_json = json.dumps(alert_data, indent=2, default=str)[:2500]
            context_parts.append(f"\n## Alert Evidence (from triage)\n{alert_json}")

        window_start = report.start_time or report.period_start
        window_end = report.end_time or report.period_end
        time_note = ""
        if window_start and window_end:
            time_note = (
                f"\n\nIntelligence window: "
                f"{window_start.strftime('%Y-%m-%d %H:%M UTC')} — "
                f"{window_end.strftime('%Y-%m-%d %H:%M UTC')}."
            )

        prompt = (
            f"Produce a {report.report_type.value} CTI intelligence report. "
            "Correlate the following multi-source intelligence into a coherent"
            " analytical product:\n\n"
            + "\n".join(context_parts)
            + time_note
        )

        narrative = await self._run_structured(prompt, _ReportNarrative)
        report.introduction = narrative.introduction
        report.executive_summary = narrative.executive_summary
        report.key_findings = narrative.key_findings
        report.analyst_assessment = narrative.analyst_assessment
        report.threat_actor_profiles = narrative.threat_actor_profiles
        report.ttp_analysis = narrative.ttp_analysis
        report.campaign_correlations = narrative.campaign_correlations
        report.threat_landscape = narrative.threat_landscape
        report.confidence_assessment = narrative.confidence_assessment
        report.recommendations = narrative.recommendations
        report.references = narrative.references
        return report
