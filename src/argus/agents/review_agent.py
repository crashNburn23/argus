"""ReviewAgent — checks every claim in a draft report against stored case evidence."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from argus.agents.base import BaseAgent, ProgressCallback
from argus.models.case import Case
from argus.models.evidence import EvidenceStatus


class ReviewFinding(BaseModel):
    claim: str
    issue: str
    evidence_id: str = ""
    severity: str = "warning"


class ReviewResult(BaseModel):
    passed: bool
    findings: list[ReviewFinding] = []
    summary: str = ""
    grounded_claim_count: int = 0
    ungrounded_claim_count: int = 0
    inferred_claim_count: int = 0


_SYSTEM = """\
You are a Cyber Threat Intelligence quality reviewer. You will be given a draft
intelligence report and the full case evidence it should be grounded in.

Your job is to audit every substantive claim in the report and determine whether it is:

1. GROUNDED — the claim is directly supported by a cited evidence ID (e.g. [ev_abc123])
   that exists in the provided evidence list with status CONFIRMED or INFERRED.
2. INFERRED — the claim is labeled as inferred, assessed, or qualified ("assessed with
   moderate confidence", "INFERRED — low confidence") — these are acceptable.
3. UNSUPPORTED — the claim makes a factual assertion about indicators, actors, techniques,
   CVE data, or infrastructure that has no matching evidence ID and is not labeled as
   inferred. These are FAILURES.

Rules:
- Ignore formatting, structure, and style — only assess factual claims.
- A claim is grounded if it references an evidence ID that appears in the provided
  evidence list and that evidence item's summary supports the claim.
- A claim is also grounded if the exact value (IP, domain, CVE ID, hash, actor name,
  technique ID) appears in the evidence summaries, even without an explicit ID reference.
- Inferred/assessed claims marked as such are acceptable — do not flag them.
- Do not flag general context statements ("Ransomware attacks have increased...") unless
  they make specific claims about actors or indicators in this case.

Return a JSON object:
{
  "passed": true/false,
  "grounded_claim_count": <number of grounded claims>,
  "ungrounded_claim_count": <number of unsupported claims>,
  "inferred_claim_count": <number of labeled inferred claims>,
  "summary": "<One paragraph: confirm grounding if passed; explain unsupported claims if failed.>",
  "findings": [
    {
      "claim": "<exact text of the unsupported claim>",
      "issue": "<why this claim is unsupported — what evidence would be needed>",
      "evidence_id": "<closest matching evidence ID if one partially supports it, or empty>",
      "severity": "error|warning"
    }
  ]
}
passed is true only if ungrounded_claim_count is 0.
Return only findings for UNSUPPORTED claims — do not list grounded or inferred claims.
"""


def _build_review_prompt(report_content: str, case: Case) -> str:
    lines = ["## Case Evidence Available for Grounding\n"]

    confirmed = [ev for ev in case.evidence if ev.status != EvidenceStatus.FAILED]
    if confirmed:
        for ev in confirmed:
            src = ev.source_name or ev.source_type
            status_tag = f"[{ev.status.value}] " if ev.status != EvidenceStatus.CONFIRMED else ""
            lines.append(
                f"- [{ev.evidence_id}] {status_tag}_{src}_: {ev.summary}"
            )
    else:
        lines.append("(no evidence available)")

    if case.observables:
        lines.append("\n## Known Observables (available for grounding)\n")
        for obs in case.observables:
            val = obs.canonical_value or obs.value
            lines.append(f"- [{obs.observable_type.value}] {val}")

    lines.append("\n## Draft Report to Review\n")
    lines.append(report_content)

    return "\n".join(lines)


class ReviewAgent(BaseAgent):
    """Checks every claim in a draft report against case evidence."""

    name = "review"

    def __init__(self, progress: ProgressCallback | None = None) -> None:
        super().__init__(progress=progress)

    def get_system_prompt(self) -> str:
        return _SYSTEM

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        return []

    async def dispatch_tool(self, tool_name: str, tool_input: dict[str, Any]) -> str:
        return "{}"

    async def run(self, **kwargs: Any) -> Any:  # noqa: ANN401
        return await self.review(**kwargs)

    async def review(self, report_content: str, case: Case) -> ReviewResult:
        """Review a report against the case evidence. Returns ReviewResult."""
        self._progress(
            f"review: checking {len(report_content.split())} words against "
            f"{len(case.evidence)} evidence items"
        )
        prompt = _build_review_prompt(report_content, case)
        return await self._run_structured(prompt, ReviewResult)
