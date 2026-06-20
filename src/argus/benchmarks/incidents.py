"""Synthetic incident-response ticket corpus and report evaluation helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

from pydantic import BaseModel, Field

from argus.models.alert import Alert, AlertTriageResult, TriagedAlert
from argus.models.report import CTIReport, Recommendation, ReportType


class ExpectedIncident(BaseModel):
    decision: str
    severity: str
    techniques: list[str] = Field(default_factory=list)
    required_findings: list[str] = Field(default_factory=list)
    required_actions: list[str] = Field(default_factory=list)


class IncidentCase(BaseModel):
    case_id: str
    title: str
    description: str
    context: str
    alerts: list[Alert]
    expected: ExpectedIncident


class EvaluationResult(BaseModel):
    case_id: str
    score: float
    decision_match: bool
    techniques_found: list[str]
    techniques_missing: list[str]
    findings_found: list[str]
    findings_missing: list[str]
    actions_found: list[str]
    actions_missing: list[str]


def load_incident_cases() -> list[IncidentCase]:
    data_path = files("argus.benchmarks").joinpath("data/incidents.json")
    return [IncidentCase.model_validate(item) for item in json.loads(data_path.read_text())]


def get_incident_case(case_id: str) -> IncidentCase:
    for case in load_incident_cases():
        if case.case_id == case_id:
            return case
    raise ValueError(f"Unknown incident case: {case_id}")


def build_expected_report(case: IncidentCase) -> CTIReport:
    """Build a deterministic reference report without calling an LLM."""
    expected = case.expected
    risk_score = {
        "critical": 10,
        "high": 8,
        "medium": 5,
        "low": 2,
        "info": 1,
    }[expected.severity]
    triaged = [
        TriagedAlert(
            alert=alert,
            decision=expected.decision,
            risk_score=risk_score,
            confidence=1.0,
            related_techniques=expected.techniques,
            analyst_notes=case.description,
            recommended_actions=expected.required_actions,
        )
        for alert in case.alerts
    ]
    counts = {
        "true_positive_count": len(triaged) if expected.decision == "true_positive" else 0,
        "false_positive_count": len(triaged) if expected.decision == "false_positive" else 0,
        "needs_investigation_count": (
            len(triaged) if expected.decision == "needs_investigation" else 0
        ),
    }
    now = datetime.now(UTC)
    return CTIReport(
        report_type=ReportType.INCIDENT,
        title=f"{case.case_id}: {case.title}",
        generated_at=now,
        period_start=min((a.timestamp for a in case.alerts if a.timestamp), default=now),
        period_end=max((a.timestamp for a in case.alerts if a.timestamp), default=now),
        scope=case.context,
        executive_summary=case.description,
        key_findings=expected.required_findings,
        threat_landscape=(
            f"Expected classification: {expected.decision}. "
            f"Expected severity: {expected.severity}. "
            f"Observed ATT&CK techniques: {', '.join(expected.techniques) or 'none'}."
        ),
        recommendations=[
            Recommendation(
                priority=expected.severity,
                action=action,
                rationale="Benchmark ground truth",
            )
            for action in expected.required_actions
        ],
        alert_summary=AlertTriageResult(
            triaged_alerts=triaged,
            high_priority_alerts=[a.alert.alert_id for a in triaged if a.risk_score >= 8],
            summary=case.description,
            **counts,
        ),
    )


def evaluate_report(case: IncidentCase, report: CTIReport) -> EvaluationResult:
    """Score required content and triage decisions using case-insensitive substring matching."""
    text = report.content.lower()
    decisions = {
        str(item.decision.value if hasattr(item.decision, "value") else item.decision)
        for item in (report.alert_summary.triaged_alerts if report.alert_summary else [])
    }
    expected = case.expected
    decision_match = expected.decision in decisions

    def split_matches(values: list[str]) -> tuple[list[str], list[str]]:
        found = [value for value in values if value.lower() in text]
        return found, [value for value in values if value not in found]

    techniques_found, techniques_missing = split_matches(expected.techniques)
    findings_found, findings_missing = split_matches(expected.required_findings)
    actions_found, actions_missing = split_matches(expected.required_actions)
    total = (
        1
        + len(expected.techniques)
        + len(expected.required_findings)
        + len(expected.required_actions)
    )
    matched = int(decision_match) + len(techniques_found) + len(findings_found) + len(actions_found)
    return EvaluationResult(
        case_id=case.case_id,
        score=matched / total,
        decision_match=decision_match,
        techniques_found=techniques_found,
        techniques_missing=techniques_missing,
        findings_found=findings_found,
        findings_missing=findings_missing,
        actions_found=actions_found,
        actions_missing=actions_missing,
    )


def save_report(report: CTIReport, output_dir: Path, case_id: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{case_id}.md"
    path.write_text(report.content, encoding="utf-8")
    return path
