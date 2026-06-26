"""Evidence-aware evaluation for audience-specific CTI reports."""

from __future__ import annotations

import json
import re
from importlib.resources import files

from pydantic import BaseModel, Field

from argus.models.case import Case
from argus.models.evidence import EvidenceItem


class ReportCriterion(BaseModel):
    name: str
    alternatives: list[str]
    evidence_ids: list[str] = Field(default_factory=list)


class ExpectedReport(BaseModel):
    required_sections: list[str]
    required_facts: list[ReportCriterion]
    required_actions: list[ReportCriterion] = Field(default_factory=list)
    required_gaps: list[ReportCriterion] = Field(default_factory=list)
    forbidden_claims: list[str] = Field(default_factory=list)


class ReportingCase(BaseModel):
    case_id: str
    title: str
    audience: str
    description: str = ""
    scope: str = ""
    evidence: list[EvidenceItem]
    expected: ExpectedReport

    def as_case(self) -> Case:
        return Case(
            case_id=self.case_id,
            title=self.title,
            description=self.description,
            scope=self.scope,
            evidence=self.evidence,
        )


class ReportingDimensionScores(BaseModel):
    fact_coverage: float
    evidence_support: float
    audience_structure: float
    actions: float
    intelligence_gaps: float
    safety: float


class ReportingEvaluationResult(BaseModel):
    case_id: str
    audience: str
    score: float
    dimensions: ReportingDimensionScores
    missing_facts: list[str]
    incorrectly_cited_facts: list[str]
    missing_sections: list[str]
    missing_actions: list[str]
    missing_gaps: list[str]
    unknown_citations: list[str]
    forbidden_claims_found: list[str]


def load_reporting_cases() -> list[ReportingCase]:
    path = files("argus.benchmarks").joinpath("data/reporting.json")
    return [ReportingCase.model_validate(item) for item in json.loads(path.read_text())]


def get_reporting_case(case_id: str) -> ReportingCase:
    for case in load_reporting_cases():
        if case.case_id == case_id:
            return case
    raise ValueError(f"Unknown reporting case: {case_id}")


def _matching_line(report: str, alternatives: list[str]) -> str | None:
    for line in report.splitlines():
        lowered = line.lower()
        if any(alternative.lower() in lowered for alternative in alternatives):
            return line
    return None


def _criterion_results(
    report: str, criteria: list[ReportCriterion]
) -> tuple[float, float, list[str], list[str]]:
    if not criteria:
        return 1.0, 1.0, [], []
    found = 0
    supported = 0
    missing: list[str] = []
    incorrectly_cited: list[str] = []
    for criterion in criteria:
        line = _matching_line(report, criterion.alternatives)
        if line is None:
            missing.append(criterion.name)
            continue
        found += 1
        has_expected_citation = any(
            f"[{ev_id}]" in line for ev_id in criterion.evidence_ids
        )
        if not criterion.evidence_ids or has_expected_citation:
            supported += 1
        else:
            incorrectly_cited.append(criterion.name)
    return found / len(criteria), supported / len(criteria), missing, incorrectly_cited


def evaluate_reporting(case: ReportingCase, report: str) -> ReportingEvaluationResult:
    """Evaluate deterministic report properties without using an LLM judge."""
    fact_score, support_score, missing_facts, incorrectly_cited = _criterion_results(
        report, case.expected.required_facts
    )
    action_score, _, missing_actions, _ = _criterion_results(
        report, case.expected.required_actions
    )
    gap_score, _, missing_gaps, _ = _criterion_results(report, case.expected.required_gaps)

    headings = {
        match.group(1).strip().lower()
        for line in report.splitlines()
        if (match := re.match(r"^#{1,6}\s+(.+?)\s*$", line))
    }
    missing_sections = [
        section
        for section in case.expected.required_sections
        if not any(section.lower() in heading for heading in headings)
    ]
    structure_score = (
        1 - len(missing_sections) / len(case.expected.required_sections)
        if case.expected.required_sections
        else 1.0
    )

    valid_citations = {item.evidence_id for item in case.evidence}
    cited = set(re.findall(r"\[(ev_[A-Za-z0-9_-]+)\]", report))
    unknown_citations = sorted(cited - valid_citations)
    forbidden = sorted(
        claim for claim in case.expected.forbidden_claims if claim.lower() in report.lower()
    )
    citation_safety = 1 - len(unknown_citations) / max(len(cited), 1)
    forbidden_safety = 1 - len(forbidden) / max(len(case.expected.forbidden_claims), 1)
    safety_score = max(0.0, citation_safety) * max(0.0, forbidden_safety)

    dimensions = ReportingDimensionScores(
        fact_coverage=fact_score,
        evidence_support=support_score,
        audience_structure=structure_score,
        actions=action_score,
        intelligence_gaps=gap_score,
        safety=safety_score,
    )
    weights = {
        "fact_coverage": 0.30,
        "evidence_support": 0.25,
        "audience_structure": 0.15,
        "actions": 0.15,
        "intelligence_gaps": 0.10,
        "safety": 0.05,
    }
    score = round(
        sum(getattr(dimensions, name) * weight for name, weight in weights.items()),
        10,
    )
    return ReportingEvaluationResult(
        case_id=case.case_id,
        audience=case.audience,
        score=score,
        dimensions=dimensions,
        missing_facts=missing_facts,
        incorrectly_cited_facts=incorrectly_cited,
        missing_sections=missing_sections,
        missing_actions=missing_actions,
        missing_gaps=missing_gaps,
        unknown_citations=unknown_citations,
        forbidden_claims_found=forbidden,
    )


def build_reference_report(case: ReportingCase) -> str:
    """Build a compact report that exercises every deterministic scoring criterion."""
    lines: list[str] = []
    criteria = [
        *case.expected.required_facts,
        *case.expected.required_actions,
        *case.expected.required_gaps,
    ]
    for index, section in enumerate(case.expected.required_sections):
        lines.append(f"## {section}")
        if index < len(criteria):
            criterion = criteria[index]
            citations = " ".join(f"[{item}]" for item in criterion.evidence_ids)
            lines.append(f"{criterion.alternatives[0]} {citations}".strip())
    for criterion in criteria[len(case.expected.required_sections) :]:
        citations = " ".join(f"[{item}]" for item in criterion.evidence_ids)
        lines.append(f"- {criterion.alternatives[0]} {citations}".strip())
    return "\n\n".join(lines)
