"""CaseReportAgent — generates audience-specific intelligence products from case evidence."""

from __future__ import annotations

from typing import Any

from argus.agents.base import BaseAgent, ProgressCallback
from argus.models.case import Case
from argus.models.evidence import EvidenceStatus
from argus.models.report import ReportPlan

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
- Evidence items are authoritative. Analyst Notes are written at a point in time and
  may be outdated by subsequent collection. When a Note says "no data found" or
  "no records" for an observable but an Evidence item shows findings for that same
  observable, the Evidence item is correct — cite it and disregard the stale note text.
- Every factual claim MUST be followed by the evidence ID in brackets. Correct format:
    "IP 94.154.32.160 served approachsimply.net [ev_2b3c4d5e]."
    "The registrar was HOSTINGER, created 2025-11-05 [ev_229cf460]."
  Writing a fact with no [ev_...] citation is a critical grounding failure.
  A downstream ReviewAgent will reject any uncited claim.
- Do NOT fabricate URLs, article titles, news references, or external citations.
  Only cite evidence provided in this prompt. Do not draw on training-data knowledge
  of threat actors, CVEs, or incidents — use only what is in the Evidence section.
- The Evidence section below is the authoritative intelligence record for this case.
  Read it carefully and cite each [ev_...] ID. Do not summarize what you expect to find
  — report what the evidence actually shows.

Return your report as plain Markdown with appropriate headers.
All output must be written in English regardless of the language of any source material.
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
3. Detection Guidance (behavioral detection logic for each TTP and indicator type present)
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

    # Context sections first (short, background framing)
    if case.observables:
        lines.append("\n## Observables")
        from collections import defaultdict

        # Only include manually-added observables — pivot-discovered ones are in Evidence.
        manually_added = [o for o in case.observables if "manually_added" in o.labels]
        pivot_count = sum(1 for o in case.observables if "manually_added" not in o.labels)
        by_type: dict[str, list[str]] = defaultdict(list)
        for obs in manually_added:
            val = obs.canonical_value or obs.value
            conf = f" ({obs.confidence:.0%})" if obs.confidence else ""
            labels = f" [{', '.join(obs.labels)}]" if obs.labels else ""
            by_type[obs.observable_type.value].append(f"  - {val}{conf}{labels}")
        for obs_type, entries in sorted(by_type.items()):
            lines.append(f"\n### {obs_type.upper()}")
            lines.extend(entries)
        if pivot_count:
            lines.append(f"_(+ {pivot_count} pivot-discovered observables covered in Evidence)_")

    if case.notes:
        lines.append("\n## Analyst Notes")
        # Newest first so the most recent findings are closest to the evidence boundary.
        # Cap each note at 150 chars; show up to 4 notes total (~600 char budget).
        shown = 0
        for note in reversed(case.notes):
            if shown >= 4:
                break
            body = note.body[:150]
            if not body:
                continue
            lines.append(f"- {note.author}: {body}{'…' if len(note.body) > 150 else ''}")
            meta = note.metadata if isinstance(note.metadata, dict) else {}
            review = meta.get("analyst_review")
            if review:
                lines.append(f"  [Analyst review: {str(review)[:150]}]")
            shown += 1

    if case.relationships:
        shown_rels = case.relationships[:15]
        lines.append("\n## Relationships")
        if len(case.relationships) > 15:
            lines.append(f"_(Showing 15 of {len(case.relationships)} relationships)_")
        for rel in shown_rels:
            rationale = f" — {rel.rationale}" if rel.rationale else ""
            lines.append(
                f"- `{rel.source_ref}` —[{rel.relationship_type.value}]→ "
                f"`{rel.target_ref}`{rationale}"
            )

    confirmed_all = [ev for ev in case.evidence if ev.status != EvidenceStatus.FAILED]
    failed = [ev for ev in case.evidence if ev.status == EvidenceStatus.FAILED]

    # Sort: CONFIRMED before INFERRED, then by priority score, then by confidence descending.
    # Priority score boosts items with high-value keywords that analysts care most about.
    _STATUS_ORDER = {EvidenceStatus.CONFIRMED: 0, EvidenceStatus.INFERRED: 1}
    _HIGH_VALUE_KEYWORDS = {
        "cisa kev",
        "weaponized",
        "c2,",
        ",c2",
        "c2 ",
        " c2",
        "redline",
        "asyncrat",
        "cobalt strike",
        "mimikatz",
        "stealer",
        "infostealer",
        "ransomware",
        "unc6395",
        "malware=",
    }
    _GENERIC_KEYWORDS = {"auto-generated", "scanner", "masscan"}

    def _priority(ev: Any) -> int:
        s = (ev.summary or "").lower()
        if any(kw in s for kw in _HIGH_VALUE_KEYWORDS):
            return 2
        if any(kw in s for kw in _GENERIC_KEYWORDS):
            return 0  # de-prioritize automated/generic feed items
        return 1

    confirmed_all.sort(
        key=lambda e: (
            _STATUS_ORDER.get(e.status, 2),
            -_priority(e),
            -(e.confidence or 0.0),
        )
    )

    # Filter zero-value items (no certs found, no resolutions) — they add noise without intel.
    def _has_value(ev: Any) -> bool:
        s = ev.summary or ""
        return "0 cert(s)" not in s and "0 resolution(s)" not in s

    confirmed_valuable = [ev for ev in confirmed_all if _has_value(ev)]
    # Cap: top 20 valuable items; note how many total were omitted.
    confirmed = confirmed_valuable[:20]
    omitted_evidence = len(confirmed_all) - len(confirmed)

    # Exclude failures where the same (source, observable) pair has a confirmed record —
    # those are stale pre-fix failures superseded by a successful re-enrichment.
    confirmed_pairs = {(ev.source_name, oid) for ev in confirmed_all for oid in ev.observable_ids}
    meaningful_failed = [
        ev
        for ev in failed
        if not any((ev.source_name, oid) in confirmed_pairs for oid in ev.observable_ids)
    ]

    if meaningful_failed:
        shown_failed = meaningful_failed[:10]
        lines.append("\n## Collection Failures (not suitable for claims)")
        if len(meaningful_failed) > 10:
            lines.append(
                f"_(Showing 10 of {len(meaningful_failed)} failures — rest omitted for brevity)_"
            )
        for ev in shown_failed:
            src = ev.source_name or ev.source_type
            lines.append(f"- _{src}_: {(ev.summary or '')[:80]}")

    # Evidence LAST — closest to the generation boundary so the model attends to it fully.
    if confirmed:
        lines.append("\n## Evidence")
        if omitted_evidence:
            lines.append(
                f"_(Showing {len(confirmed)} of {len(confirmed_all)} items — "
                f"highest confidence first; {omitted_evidence} lower-value items omitted.)_"
            )
        for ev in confirmed:
            src = ev.source_name or ev.source_type
            status_tag = f"[{ev.status.value}] " if ev.status != EvidenceStatus.CONFIRMED else ""
            conf_tag = f" ({ev.confidence:.0%})" if ev.confidence else ""
            lines.append(f"- [{ev.evidence_id}] {status_tag}_{src}_{conf_tag}: {ev.summary}")
            if ev.raw_excerpt and len(ev.raw_excerpt) < 300:
                lines.append(f"  Excerpt: {ev.raw_excerpt[:250]}")

    return "\n".join(lines)


_PLAN_SYSTEM = """\
You are a senior CTI analyst performing a pre-report planning pass. Before generating a
finished intelligence product, enumerate what claims you intend to make, what evidence
supports each claim, what gaps exist, and what assertions must NOT be made.

Rules:
- Only propose claims grounded in the provided evidence. List the supporting evidence IDs.
- Mark is_inference=true for claims that extend beyond direct evidence (analytical judgments).
- Confidence is 0.0–1.0: use 0.8+ for directly evidenced claims, 0.4–0.7 for inferences.
- known_gaps: list what additional evidence would materially strengthen the report.
- forbidden_assertions: list specific claims that MUST NOT appear in the report — e.g.,
  actor attribution when no actor evidence exists, CVE severity when NVD data is absent,
  or any claim where the only source is a FAILED collection attempt.
- summary: one paragraph describing the overall evidential picture for this case.

Return ONLY a valid JSON object — no markdown fences, no prose before or after the JSON.
"""


class _ReportPlannerAgent(BaseAgent):
    """Internal planning agent — runs a pre-report structured pass, no tools."""

    name = "case_report_planner"

    def get_system_prompt(self) -> str:
        return _PLAN_SYSTEM

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        return []

    async def dispatch_tool(self, tool_name: str, tool_input: dict[str, Any]) -> str:
        return "{}"

    async def run(self, **kwargs: Any) -> Any:  # noqa: ANN401
        raise NotImplementedError


class CaseReportAgent(BaseAgent):
    """Generates an audience-specific intelligence product from a case's stored evidence."""

    AUDIENCES = list(_AUDIENCE_INSTRUCTIONS)
    name = "case_report"
    max_output_tokens = 4096  # Reports are concise; this halves output quota vs. default 8192.

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

    async def plan(self, case: Case) -> ReportPlan:
        """Return a structured pre-report plan: proposed claims, evidence IDs, gaps."""
        self._progress("case_report: generating pre-report claim plan")
        case_prompt = _compile_case_prompt(case)
        planner = _ReportPlannerAgent(progress=self.progress)
        return await planner._run_structured(
            f"Plan a {self.audience.upper()} intelligence report for this case.\n\n{case_prompt}",
            ReportPlan,
        )

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
