from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

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


class Recommendation(BaseModel):
    priority: str  # critical | high | medium | low
    action: str
    rationale: str


class CTIReport(BaseModel):
    report_type: ReportType
    title: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    period_start: datetime | None = None
    period_end: datetime | None = None
    scope: str = ""
    classification: ReportClassification = ReportClassification.AMBER

    executive_summary: str = ""
    key_findings: list[str] = []
    threat_landscape: str = ""
    recommendations: list[Recommendation] = []
    technical_appendix: dict[str, Any] = {}

    ioc_summary: IOCEnrichmentResult | None = None
    threat_actor_summary: ThreatActorResearchResult | None = None
    vulnerability_summary: VulnIntelResult | None = None
    alert_summary: AlertTriageResult | None = None

    format: str = "markdown"
    content: str = ""  # rendered Jinja2 output
    start_time: datetime | None = None  # explicit report time window start
    end_time: datetime | None = None    # explicit report time window end
