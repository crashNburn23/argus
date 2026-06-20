from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


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
    alert_id: str = ""
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

    @field_validator("raw_log", "rule_name", "original_severity", mode="before")
    @classmethod
    def _coerce_none_str(cls, v: Any) -> str:
        return "" if v is None else str(v)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _coerce_empty_timestamp(cls, v: Any) -> Any:
        return None if v == "" else v


class EnrichedIOC(BaseModel):
    ioc: str
    type: str = ""  # ip, domain, hash, url
    reputation: str = ""
    connection: str = ""
    extra: dict[str, Any] = {}

    @field_validator("ioc", mode="before")
    @classmethod
    def _coerce_ioc(cls, v: Any) -> str:
        if isinstance(v, list):
            return ", ".join(str(x) for x in v)
        return str(v) if v is not None else ""

    @field_validator("type", "reputation", "connection", mode="before")
    @classmethod
    def _coerce_none_str(cls, v: Any) -> str:
        if v is None:
            return ""
        if isinstance(v, (dict, list)):
            return str(v)
        return str(v)

    @field_validator("extra", mode="before")
    @classmethod
    def _coerce_extra(cls, v: Any) -> dict[str, Any]:
        if isinstance(v, dict):
            return v
        return {}


_ALERT_FIELD_NAMES = {
    "alert_id",
    "raw_log",
    "source_ip",
    "dest_ip",
    "timestamp",
    "rule_name",
    "original_severity",
    "extra",
}


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

    @model_validator(mode="before")
    @classmethod
    def _promote_flat_alert(cls, data: Any) -> Any:
        """If model put alert fields at the top level, nest them under 'alert'."""
        if not isinstance(data, dict) or "alert" in data:
            return data
        alert_data = {k: data[k] for k in _ALERT_FIELD_NAMES if k in data}
        if alert_data:
            remainder = {k: v for k, v in data.items() if k not in _ALERT_FIELD_NAMES}
            remainder["alert"] = alert_data
            return remainder
        return data

    @field_validator("decision", mode="before")
    @classmethod
    def _normalize_decision(cls, v: Any) -> Any:
        return v.lower() if isinstance(v, str) else v

    @field_validator("analyst_notes", mode="before")
    @classmethod
    def _coerce_none_str(cls, v: Any) -> str:
        return "" if v is None else str(v)

    @field_validator("related_threat_actors", mode="before")
    @classmethod
    def _coerce_threat_actors(cls, v: Any) -> list[str]:
        if not isinstance(v, list):
            return []
        return [
            item if isinstance(item, str) else (item.get("name") or item.get("actor") or str(item))
            for item in v
        ]

    @field_validator("related_techniques", mode="before")
    @classmethod
    def _coerce_techniques(cls, v: Any) -> list[str]:
        if not isinstance(v, list):
            return []
        return [
            item
            if isinstance(item, str)
            else (item.get("technique_id") or item.get("name") or str(item))
            for item in v
        ]

    @field_validator("recommended_actions", mode="before")
    @classmethod
    def _coerce_actions(cls, v: Any) -> list[str]:
        if not isinstance(v, list):
            return []
        return [
            item
            if isinstance(item, str)
            else (item.get("description") or item.get("action") or str(item))
            for item in v
        ]


class AlertTriageResult(BaseModel):
    triaged_alerts: list[TriagedAlert]
    true_positive_count: int = 0
    false_positive_count: int = 0
    needs_investigation_count: int = 0
    high_priority_alerts: list[str] = []
    summary: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="before")
    @classmethod
    def _wrap_flat_result(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        if "triaged_alerts" not in data:
            # Model returned a flat single-alert dict — wrap it
            return {"triaged_alerts": [data]}
        # Filter out non-dict items and metadata dicts that leak into the array.
        # LFM-2.5 puts top-level summary fields (true_positive_count etc.) as extra
        # list items — keep only dicts that look like TriagedAlert objects.
        _TRIAGE_KEYS = {
            "alert",
            "decision",
            "risk_score",
            "confidence",
            "enriched_iocs",
            "related_threat_actors",
            "mitre_techniques",
            "recommended_actions",
            "analyst_notes",
        }
        alerts = data.get("triaged_alerts")
        if isinstance(alerts, list):
            data["triaged_alerts"] = [
                a for a in alerts if isinstance(a, dict) and bool(_TRIAGE_KEYS & a.keys())
            ]
        return data

    @field_validator("high_priority_alerts", mode="before")
    @classmethod
    def _coerce_high_priority(cls, v: Any) -> list[str]:
        if not isinstance(v, list):
            return []
        result: list[str] = []
        for item in v:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict):
                for val in item.values():
                    if isinstance(val, list):
                        result.extend(str(x) for x in val)
                    else:
                        result.append(str(val))
            else:
                result.append(str(item))
        return result

    @field_validator("summary", mode="before")
    @classmethod
    def _coerce_none_str(cls, v: Any) -> str:
        return "" if v is None else str(v)
