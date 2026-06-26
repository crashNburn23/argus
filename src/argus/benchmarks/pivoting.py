"""Deterministic IOC-pivot benchmark models, fixtures, and evaluation."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any, Literal

from pydantic import BaseModel, Field


class PivotToolFixture(BaseModel):
    tool: str
    match: dict[str, Any]
    result: dict[str, Any]


class ExpectedToolCall(BaseModel):
    tool: str
    indicator: str


class PivotRelationship(BaseModel):
    source: str
    target: str
    relationship_type: str
    evidence_refs: list[str] = Field(default_factory=list)


class PivotObservable(BaseModel):
    value: str
    observable_type: str
    disposition: Literal["seed", "related", "noise"] = "related"
    evidence_refs: list[str] = Field(default_factory=list)


class PivotAttribution(BaseModel):
    name: str
    confidence: Literal["low", "moderate", "high"]
    evidence_refs: list[str] = Field(default_factory=list)


class PivotAnalysisResult(BaseModel):
    observables: list[PivotObservable] = Field(default_factory=list)
    relationships: list[PivotRelationship] = Field(default_factory=list)
    attributions: list[PivotAttribution] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    intelligence_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    report: str = ""


class ExpectedPivot(BaseModel):
    observables: list[PivotObservable]
    relationships: list[PivotRelationship]
    required_tool_calls: list[ExpectedToolCall]
    attributions: list[str] = Field(default_factory=list)
    forbidden_observables: list[str] = Field(default_factory=list)
    forbidden_attributions: list[str] = Field(default_factory=list)


class PivotCase(BaseModel):
    case_id: str
    title: str
    difficulty: Literal["direct", "multi_hop", "adversarial"]
    prompt: str
    seed_observables: list[PivotObservable]
    fixtures: list[PivotToolFixture]
    expected: ExpectedPivot


class RecordedToolCall(BaseModel):
    evidence_id: str
    tool: str
    input: dict[str, Any]
    matched_fixture: bool

    @property
    def indicator(self) -> str:
        for key in ("indicator", "domain", "ip", "ip_address", "query"):
            if value := self.input.get(key):
                return str(value)
        return ""


class PivotDimensionScores(BaseModel):
    tool_use: float
    observable_graph: float
    relationships: float
    grounding: float
    attribution: float


class PivotEvaluationResult(BaseModel):
    case_id: str
    score: float
    dimensions: PivotDimensionScores
    missing_tool_calls: list[str]
    missing_observables: list[str]
    unexpected_observables: list[str]
    missing_relationships: list[str]
    unexpected_relationships: list[str]
    unsupported_evidence_refs: list[str]
    attribution_errors: list[str]


def load_pivot_cases() -> list[PivotCase]:
    path = files("argus.benchmarks").joinpath("data/pivots.json")
    return [PivotCase.model_validate(item) for item in json.loads(path.read_text())]


def get_pivot_case(case_id: str) -> PivotCase:
    for case in load_pivot_cases():
        if case.case_id == case_id:
            return case
    raise ValueError(f"Unknown pivot case: {case_id}")


def _norm(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _f1(expected: set[Any], actual: set[Any]) -> tuple[float, set[Any], set[Any]]:
    if not expected and not actual:
        return 1.0, set(), set()
    true_positive = len(expected & actual)
    precision = true_positive / len(actual) if actual else 0.0
    recall = true_positive / len(expected) if expected else 1.0
    score = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return score, expected - actual, actual - expected


def evaluate_pivot(
    case: PivotCase,
    result: PivotAnalysisResult,
    calls: list[RecordedToolCall],
) -> PivotEvaluationResult:
    """Score investigation behavior, graph fidelity, grounding, and attribution."""
    expected_calls = {(c.tool, _norm(c.indicator)) for c in case.expected.required_tool_calls}
    actual_calls = {(c.tool, _norm(c.indicator)) for c in calls}
    tool_score, missing_calls, _ = _f1(expected_calls, actual_calls)

    expected_observables = {(_norm(o.value), o.disposition) for o in case.expected.observables}
    actual_observables = {(_norm(o.value), o.disposition) for o in result.observables}
    observable_score, missing_observables, unexpected_observables = _f1(
        expected_observables, actual_observables
    )
    forbidden_observables = {_norm(v) for v in case.expected.forbidden_observables}
    unexpected_observables |= {
        item for item in actual_observables if item[0] in forbidden_observables
    }

    def relationship_key(rel: PivotRelationship) -> tuple[str, str, str]:
        return (_norm(rel.source), _norm(rel.target), _norm(rel.relationship_type))

    expected_relationships = {relationship_key(r) for r in case.expected.relationships}
    actual_relationships = {relationship_key(r) for r in result.relationships}
    relationship_score, missing_relationships, unexpected_relationships = _f1(
        expected_relationships, actual_relationships
    )

    valid_refs = {call.evidence_id for call in calls if call.matched_fixture}
    evidence_ref_groups = (
        [item.evidence_refs for item in result.observables]
        + [item.evidence_refs for item in result.relationships]
        + [item.evidence_refs for item in result.attributions]
    )
    supplied_refs = {ref for refs in evidence_ref_groups for ref in refs}
    unsupported_refs = supplied_refs - valid_refs
    grounded_item_count = sum(
        bool(refs) and set(refs) <= valid_refs for refs in evidence_ref_groups
    )
    total_items = len(result.observables) + len(result.relationships) + len(result.attributions)
    grounding_score = grounded_item_count / total_items if total_items else 0.0

    expected_attributions = {_norm(v) for v in case.expected.attributions}
    actual_attributions = {_norm(v.name) for v in result.attributions}
    attribution_score, missing_attr, unexpected_attr = _f1(
        expected_attributions, actual_attributions
    )
    forbidden_attr = {_norm(v) for v in case.expected.forbidden_attributions}
    unexpected_attr |= actual_attributions & forbidden_attr
    attribution_errors = sorted(
        [
            *(f"missing:{v}" for v in missing_attr),
            *(f"unexpected:{v}" for v in unexpected_attr),
        ]
    )

    # Precision penalties prevent a model from maximizing recall by emitting every IOC/link.
    if unexpected_observables:
        precision_penalty = 1 - len(unexpected_observables) / max(len(actual_observables), 1)
        observable_score *= max(0.0, precision_penalty)
    weights = {
        "tool_use": 0.20,
        "observable_graph": 0.25,
        "relationships": 0.25,
        "grounding": 0.20,
        "attribution": 0.10,
    }
    dimensions = PivotDimensionScores(
        tool_use=tool_score,
        observable_graph=observable_score,
        relationships=relationship_score,
        grounding=grounding_score,
        attribution=attribution_score,
    )
    score = round(
        sum(getattr(dimensions, name) * weight for name, weight in weights.items()),
        10,
    )
    return PivotEvaluationResult(
        case_id=case.case_id,
        score=score,
        dimensions=dimensions,
        missing_tool_calls=[f"{tool}:{indicator}" for tool, indicator in sorted(missing_calls)],
        missing_observables=[
            f"{value}:{disposition}" for value, disposition in sorted(missing_observables)
        ],
        unexpected_observables=[
            f"{value}:{disposition}" for value, disposition in sorted(unexpected_observables)
        ],
        missing_relationships=["|".join(v) for v in sorted(missing_relationships)],
        unexpected_relationships=["|".join(v) for v in sorted(unexpected_relationships)],
        unsupported_evidence_refs=sorted(unsupported_refs),
        attribution_errors=attribution_errors,
    )


class FixtureDispatcher:
    """Serve deterministic tool results and retain an auditable call trace."""

    def __init__(self, case: PivotCase) -> None:
        self.case = case
        self.calls: list[RecordedToolCall] = []

    async def dispatch(self, tool: str, tool_input: dict[str, Any]) -> str:
        evidence_id = f"tool_{len(self.calls) + 1:03d}"
        fixture = next(
            (
                item
                for item in self.case.fixtures
                if item.tool == tool
                and all(
                    _norm(str(tool_input.get(k, ""))) == _norm(str(v))
                    for k, v in item.match.items()
                )
            ),
            None,
        )
        self.calls.append(
            RecordedToolCall(
                evidence_id=evidence_id,
                tool=tool,
                input=tool_input,
                matched_fixture=fixture is not None,
            )
        )
        if fixture is None:
            return json.dumps(
                {"error": "No benchmark fixture for this call", "evidence_id": evidence_id}
            )
        return json.dumps({**fixture.result, "evidence_id": evidence_id})
