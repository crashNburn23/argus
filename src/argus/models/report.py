from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from argus.models.alert import AlertTriageResult
from argus.models.ioc import IOCEnrichmentResult
from argus.models.threat_actor import ThreatActorResearchResult
from argus.models.vulnerability import VulnIntelResult


class ReportType(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    YEARLY = "yearly"
    INCIDENT = "incident"


class ReportClassification(StrEnum):
    CLEAR = "TLP:CLEAR"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    AMBER_STRICT = "TLP:AMBER+STRICT"
    RED = "TLP:RED"


_PRIORITY_KEYS = ("priority", "severity", "urgency", "risk_level", "risk")
_ACTION_KEYS = ("action", "recommendation", "description", "mitigation", "step", "measure")
_RATIONALE_KEYS = ("rationale", "reason", "justification", "explanation")


class Recommendation(BaseModel):
    priority: str  # critical | high | medium | low
    action: str
    rationale: str

    @model_validator(mode="before")
    @classmethod
    def _normalize_fields(cls, data: Any) -> Any:
        """Map non-standard field names to priority/action/rationale."""
        if not isinstance(data, dict):
            return data
        out: dict[str, Any] = {}
        # priority — try known keys, then any key starting with "priority"
        for k in _PRIORITY_KEYS:
            if data.get(k):
                out["priority"] = str(data[k])
                break
        if "priority" not in out:
            for k in sorted(data):
                if k.startswith("priority") and data.get(k):
                    out["priority"] = str(data[k])
                    break
        out.setdefault("priority", "medium")
        # action — try known keys, fall back to first non-empty string value not yet used
        for k in _ACTION_KEYS:
            if data.get(k):
                out["action"] = str(data[k])
                break
        if "action" not in out:
            for k in sorted(data):
                if any(k.startswith(x) for x in ("action", "recommendation", "step")):
                    if data.get(k):
                        out["action"] = str(data[k])
                        break
        if "action" not in out:
            fallback = " ".join(str(v) for v in data.values() if v and isinstance(v, str))
            out["action"] = fallback or "No action specified"
        # rationale — optional, default ""
        for k in _RATIONALE_KEYS:
            if data.get(k):
                out["rationale"] = str(data[k])
                break
        out.setdefault("rationale", "")
        return out

    @field_validator("priority", "action", "rationale", mode="before")
    @classmethod
    def _coerce_none_str(cls, v: Any) -> str:
        return "" if v is None else str(v)


class ProposedClaim(BaseModel):
    claim: str
    evidence_ids: list[str] = []
    confidence: float = 0.5
    is_inference: bool = False


class ReportPlan(BaseModel):
    proposed_claims: list[ProposedClaim] = []
    known_gaps: list[str] = []
    forbidden_assertions: list[str] = []
    summary: str = ""


class CTIReport(BaseModel):
    report_type: ReportType
    title: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    period_start: datetime | None = None
    period_end: datetime | None = None
    scope: str = ""
    classification: ReportClassification = ReportClassification.AMBER

    # Narrative sections — populated by ReportAgent
    introduction: str = ""
    executive_summary: str = ""
    key_findings: list[str] = []
    analyst_assessment: str = ""  # core analytical product: correlations, attribution, intent
    threat_actor_profiles: list[str] = []  # per-actor narrative tied to observed evidence
    ttp_analysis: str = ""  # MITRE ATT&CK-mapped TTP narrative
    campaign_correlations: list[str] = []  # specific cross-source connections
    threat_landscape: str = ""  # broader context / sector trends
    confidence_assessment: str = ""  # confidence level and intelligence gaps
    recommendations: list[Recommendation] = []
    references: list[str] = []
    technical_appendix: dict[str, Any] = {}

    # Raw intelligence — populated by specialized agents
    ioc_summary: IOCEnrichmentResult | None = None
    threat_actor_summary: ThreatActorResearchResult | None = None
    vulnerability_summary: VulnIntelResult | None = None
    alert_summary: AlertTriageResult | None = None

    format: str = "markdown"
    content: str = ""  # rendered Jinja2 output
    start_time: datetime | None = None
    end_time: datetime | None = None
