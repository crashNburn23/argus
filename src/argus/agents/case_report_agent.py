"""CaseReportAgent — generates audience-specific intelligence products from case evidence."""
from __future__ import annotations

from typing import Any

from argus.agents.base import BaseAgent, ProgressCallback
from argus.models.case import Case
from argus.models.evidence import EvidenceStatus

_COMMON_PREAMBLE = """\
You are a senior Cyber Threat Intelligence analyst. You have been given a structured
intelligence case with confirmed evidence, extracted observables, pivot results, and
analyst notes. Your job is to synthesize this evidence into a finished intelligence
product for the specified audience.

Core rules:
- Ground every claim in the provided evidence. When citing a finding, reference the
  evidence ID (e.g., [ev_abc123]) so the reader can trace it. A downstream ReviewAgent
  will verify every citation — uncited factual claims will be flagged as UNSUPPORTED.
- Label inferred judgments explicitly: "(INFERRED — moderate confidence)" or similar.
  Clearly labeled inferences are acceptable; unlabeled assertions are not.
- Do not fabricate indicators, actors, TTPs, or statistics not in the evidence.
- Acknowledge gaps. If an observable, actor, or technique is not present in the evidence,
  say it was not observed in this case — do not assert it is globally unknown or absent.
- Distinguish confirmed intelligence from analytical assessment.
- Evidence items with status FAILED represent collection attempts that returned errors,
  not confirmed absences. Do not treat a failed enrichment as proof that no data exists.

Return your report as plain Markdown with appropriate headers.
"""

_AUDIENCE_INSTRUCTIONS: dict[str, str] = {
    "cti": """\
Audience: CTI Team
Write a finished CTI intelligence product. Include:
1. Executive Summary (2-3 sentences, key threat and confidence)
2. Key Findings (bulleted, each grounded in evidence IDs)
3. Threat Actor Assessment (if actor observables or TTPs present)
4. Technical Indicators (organized by type — IPs, domains, hashes, CVEs, TTPs)
5. Infrastructure Analysis (relationships and pivot findings)
6. Confidence Assessment and Gaps
7. Recommended Collection (what would close intelligence gaps)
""",

    "soc": """\
Audience: SOC and Detection Engineering
Write a detection-focused product. Include:
1. Threat Summary (1 paragraph — what to look for and why)
2. Indicators for Immediate Watchlisting (IPs, domains, hashes — one per line, actionable)
3. SIEM Detection Guidance (example query logic for each indicator type present)
4. MITRE ATT&CK Coverage (techniques from evidence, mapped to detectable behaviors)
5. Recommended Alert Tuning (what to enable, what noise to filter)
6. Escalation Criteria (what SOC analyst should page on)
""",

    "vm": """\
Audience: Vulnerability Management
Write a prioritized vulnerability product. Include:
1. Patch Priority Summary (critical actions first)
2. CVE Details (for each CVE in evidence: CVSS score, CISA KEV status, exploitation context)
3. Affected Asset Scope (systems/services implied by the evidence)
4. Exploit Status (in-the-wild exploitation, proof-of-concept, or theoretical)
5. Compensating Controls (if patching is not immediately possible)
6. Timeline Recommendation (patch by date or compensate by date)
""",

    "ir": """\
Audience: Incident Response Team
Write an IR-focused product. Include:
1. Threat Summary (what the actor is doing and how far they may have progressed)
2. Immediate Containment Actions (IP blocks, domain sinkholes, account actions)
3. Indicators for Threat Hunt (full list, organized by type)
4. Timeline of Observed Activity (from evidence timestamps)
5. Forensic Priorities (what to collect and preserve first, based on TTPs)
6. Recovery Guidance (what needs verification before returning to production)
""",

    "exec": """\
Audience: Executive Leadership
Write a non-technical executive briefing. Include:
1. Situation Summary (2-3 sentences: what happened, who is responsible, what is at risk)
2. Business Impact Assessment (operational, financial, reputational implications)
3. What We Know vs. What We Don't Know (honest uncertainty)
4. Actions Underway (current response activities)
5. Decision Points (what leadership needs to decide or authorize)
6. Recommended Next Steps (prioritized, owner-assignable)
Avoid technical jargon. Focus on business risk and decisions, not indicators.
""",

    "awareness": """\
Audience: Security Awareness / All Staff
Write a plain-language security awareness notice. Include:
1. What is happening (brief, no jargon)
2. Who is targeted or at risk
3. What employees should watch for (signs of suspicious activity they might notice)
4. What employees should do (specific, simple actions)
5. Who to contact if they see something (reporting guidance)
6. What NOT to do (common mistakes that make things worse)
Keep it under 400 words. Use simple language a non-technical employee can act on.
""",

    "redteam": """\
Audience: Red Team / Adversary Emulation
Write an adversary emulation brief. Include:
1. Adversary Profile Summary (TTP cluster observed, sophistication level)
2. ATT&CK Technique List (IDs and descriptions from evidence)
3. Tooling and Infrastructure Indicators (actor tools, C2 patterns observed)
4. Emulation Scenarios (1-3 specific attack chains derivable from the TTPs)
5. Detection Gaps (what in the evidence suggests defenders may not catch this)
6. Purple Team Recommendations (what to test and with what detection criteria)
""",
}


def _compile_case_prompt(case: Case) -> str:
    lines: list[str] = [
        f"# Case: {case.title}",
        f"ID: {case.case_id}",
        f"Status: {case.status.value}",
        f"Classification: {case.classification}",
    ]
    if case.scope:
        lines.append(f"Scope: {case.scope}")
    if case.description:
        lines.append(f"\nDescription: {case.description}")

    if case.pirs:
        lines.append("\n## Priority Intelligence Requirements")
        for pir in case.pirs:
            lines.append(f"- [{pir.priority.upper()}] {pir.question} [{pir.status.value}]")
            if pir.answer:
                lines.append(f"  Answer: {pir.answer}")

    if case.observables:
        lines.append("\n## Observables")
        from collections import defaultdict
        by_type: dict[str, list[str]] = defaultdict(list)
        for obs in case.observables:
            val = obs.canonical_value or obs.value
            conf = f" ({obs.confidence:.0%})" if obs.confidence else ""
            labels = f" [{', '.join(obs.labels)}]" if obs.labels else ""
            by_type[obs.observable_type.value].append(f"  - {val}{conf}{labels}")
        for obs_type, entries in sorted(by_type.items()):
            lines.append(f"\n### {obs_type.upper()}")
            lines.extend(entries)

    confirmed_all = [ev for ev in case.evidence if ev.status != EvidenceStatus.FAILED]
    failed = [ev for ev in case.evidence if ev.status == EvidenceStatus.FAILED]

    # Prioritize high-confidence confirmed evidence; cap to avoid oversized prompts.
    # Sort: CONFIRMED before INFERRED, then by confidence descending.
    _STATUS_ORDER = {EvidenceStatus.CONFIRMED: 0, EvidenceStatus.INFERRED: 1}
    confirmed_all.sort(key=lambda e: (_STATUS_ORDER.get(e.status, 2), -(e.confidence or 0.0)))
    confirmed = confirmed_all[:150]
    truncated = len(confirmed_all) - len(confirmed)

    if confirmed:
        lines.append("\n## Evidence")
        if truncated:
            lines.append(
                f"_(Showing {len(confirmed)} of {len(confirmed_all)} items, "
                f"highest confidence first. {truncated} lower-confidence items omitted.)_"
            )
        for ev in confirmed:
            src = ev.source_name or ev.source_type
            status_tag = f"[{ev.status.value}] " if ev.status != EvidenceStatus.CONFIRMED else ""
            conf_tag = f" ({ev.confidence:.0%})" if ev.confidence else ""
            lines.append(f"- [{ev.evidence_id}] {status_tag}_{src}_{conf_tag}: {ev.summary}")
            if ev.raw_excerpt and len(ev.raw_excerpt) < 300:
                lines.append(f"  Excerpt: {ev.raw_excerpt[:250]}")

    if failed:
        lines.append("\n## Collection Failures (not suitable for claims)")
        for ev in failed:
            src = ev.source_name or ev.source_type
            lines.append(f"- _{src}_: {ev.summary}")

    if case.relationships:
        lines.append("\n## Relationships")
        for rel in case.relationships:
            rationale = f" — {rel.rationale}" if rel.rationale else ""
            lines.append(
                f"- `{rel.source_ref}` —[{rel.relationship_type.value}]→ "
                f"`{rel.target_ref}`{rationale}"
            )

    if case.notes:
        lines.append("\n## Analyst Notes")
        for note in case.notes:
            lines.append(f"- {note.author}: {note.body}")

    return "\n".join(lines)


class CaseReportAgent(BaseAgent):
    """Generates an audience-specific intelligence product from a case's stored evidence."""

    AUDIENCES = list(_AUDIENCE_INSTRUCTIONS)
    name = "case_report"

    def __init__(self, audience: str = "cti", progress: ProgressCallback | None = None) -> None:
        super().__init__(progress=progress)
        if audience not in _AUDIENCE_INSTRUCTIONS:
            valid = ", ".join(_AUDIENCE_INSTRUCTIONS)
            raise ValueError(f"Unknown audience {audience!r}. Valid: {valid}")
        self.audience = audience

    def get_system_prompt(self) -> str:
        return _COMMON_PREAMBLE + "\n" + _AUDIENCE_INSTRUCTIONS[self.audience]

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        return []

    async def dispatch_tool(self, tool_name: str, tool_input: dict[str, Any]) -> str:
        return "{}"

    async def run(self, **kwargs: Any) -> Any:  # noqa: ANN401
        return await self.generate(**kwargs)

    async def generate(self, case: Case) -> str:
        """Return a Markdown intelligence product for the configured audience."""
        self._progress(f"case_report: compiling {len(case.evidence)} evidence items")
        case_prompt = _compile_case_prompt(case)
        user_prompt = (
            f"Generate a {self.audience.upper()} intelligence product from this case.\n\n"
            f"{case_prompt}"
        )
        messages: list[dict[str, Any]] = [{"role": "user", "content": user_prompt}]
        self._progress(f"case_report: synthesizing {self.audience} report")
        content = await self._run_loop(messages)
        return self._extract_text(content)
