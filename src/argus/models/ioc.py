from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class IOCType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"


class IOCVerdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


_VERDICT_ALIASES: dict[str, str] = {
    "harmless":   "benign",
    "clean":      "benign",
    "safe":       "benign",
    "undetected": "unknown",
    "no verdict": "unknown",
    "neutral":    "unknown",
    "informational": "unknown",
    "malware":    "malicious",
    "phishing":   "malicious",
    "ransomware": "malicious",
    "spam":       "suspicious",
    "potentially unwanted": "suspicious",
}


class SourceResult(BaseModel):
    source: str
    verdict: IOCVerdict
    confidence: float  # 0.0–1.0
    details: dict[str, Any] = {}
    timestamp: datetime | None = None

    @field_validator("verdict", mode="before")
    @classmethod
    def _normalize_verdict(cls, v: Any) -> Any:
        if isinstance(v, str):
            return _VERDICT_ALIASES.get(v.lower(), v)
        return v

    @field_validator("details", mode="before")
    @classmethod
    def _coerce_details(cls, v: Any) -> dict[str, Any]:
        if isinstance(v, str):
            return {"description": v}
        if not isinstance(v, dict):
            return {}
        return v


class IOCEnrichmentRecord(BaseModel):
    indicator: str
    ioc_type: IOCType
    overall_verdict: IOCVerdict = IOCVerdict.UNKNOWN
    confidence: float = 0.0
    source_results: list[SourceResult] = []
    malware_families: list[str] = []
    threat_actors: list[str] = []
    tags: list[str] = []
    geolocation: str | None = None
    asn: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    stix_pattern: str | None = None
    kill_chain_phases: list[str] = []

    @field_validator("asn", "geolocation", "stix_pattern", mode="before")
    @classmethod
    def _coerce_optional_str(cls, v: Any) -> str | None:
        if v is None:
            return None
        return str(v)


class IOCEnrichmentResult(BaseModel):
    indicators: list[IOCEnrichmentRecord]
    summary: str = ""
    high_priority_iocs: list[str] = []
    recommended_actions: list[str] = []
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="before")
    @classmethod
    def _normalize_shape(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        if "indicators" not in data:
            # Model returned a single indicator object directly
            if "indicator" in data or "ioc_type" in data:
                return {"indicators": [data], "summary": data.get("summary", "")}
            # Model returned a list at root
            if isinstance(data.get("results"), list):
                return {"indicators": data["results"], "summary": data.get("summary", "")}
        return data
