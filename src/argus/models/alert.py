from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class AlertSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TriageDecision(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_INVESTIGATION = "needs_investigation"


class Alert(BaseModel):
    alert_id: str
    raw_log: str = ""
    source_ip: str | None = None
    dest_ip: str | None = None
    timestamp: datetime | None = None
    rule_name: str = ""
    original_severity: str = ""
    extra: dict[str, Any] = {}

    @field_validator("alert_id", mode="before")
    @classmethod
    def _coerce_alert_id(cls, v: Any) -> str:
        return str(v)


class EnrichedIOC(BaseModel):
    ioc: str
    type: str = ""  # ip, domain, hash, url
    reputation: str = ""
    connection: str = ""
    extra: dict[str, Any] = {}


class TriagedAlert(BaseModel):
    alert: Alert
    decision: TriageDecision = TriageDecision.NEEDS_INVESTIGATION
    risk_score: int = 0  # 1–10
    confidence: float = 0.0
    enriched_iocs: list[EnrichedIOC] = []
    related_threat_actors: list[str] = []
    related_techniques: list[str] = []
    analyst_notes: str = ""
    recommended_actions: list[str] = []


class AlertTriageResult(BaseModel):
    triaged_alerts: list[TriagedAlert]
    true_positive_count: int = 0
    false_positive_count: int = 0
    needs_investigation_count: int = 0
    high_priority_alerts: list[str] = []
    summary: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
