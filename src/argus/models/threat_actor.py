from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class MITRETechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: str = ""
    detection_guidance: str = ""
    data_sources: list[str] = []

    @field_validator("description", "detection_guidance", mode="before")
    @classmethod
    def _coerce_none_str(cls, v: Any) -> str:
        return "" if v is None else str(v)


class Campaign(BaseModel):
    name: str
    description: str = ""

    @field_validator("description", mode="before")
    @classmethod
    def _coerce_none_str(cls, v: Any) -> str:
        return "" if v is None else str(v)


class DetectionRecommendation(BaseModel):
    technique_id: str = ""
    name: str = ""
    description: str = ""

    @model_validator(mode="before")
    @classmethod
    def _coerce_string(cls, v: Any) -> Any:
        if isinstance(v, str):
            return {"description": v}
        return v

    @field_validator("technique_id", "name", "description", mode="before")
    @classmethod
    def _coerce_none_str(cls, v: Any) -> str:
        return "" if v is None else str(v)


class ThreatActor(BaseModel):
    name: str
    aliases: list[str] = []
    description: str = ""
    goals: list[str] = []
    sophistication: str = ""
    resource_level: str = ""
    primary_motivation: str = ""
    suspected_attribution: list[str] = []
    mitre_group_id: str | None = None
    techniques: list[MITRETechnique] = []
    campaigns: list[Campaign] = []
    associated_malware: list[str] = []
    target_sectors: list[str] = []
    target_countries: list[str] = []
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    source_urls: list[str] = []

    @field_validator(
        "description", "sophistication", "resource_level", "primary_motivation", mode="before"
    )
    @classmethod
    def _coerce_none_str(cls, v: Any) -> str:
        return "" if v is None else str(v)


class ThreatActorResearchResult(BaseModel):
    actors: list[ThreatActor]
    summary: str = ""
    key_findings: list[str] = []
    recommended_detections: list[DetectionRecommendation] = []
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("summary", mode="before")
    @classmethod
    def _coerce_none_str(cls, v: Any) -> str:
        return "" if v is None else str(v)
