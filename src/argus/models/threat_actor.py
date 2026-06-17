from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator


class MITRETechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: str = ""
    detection_guidance: str = ""
    data_sources: list[str] = []


class Campaign(BaseModel):
    name: str
    description: str = ""


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


class ThreatActorResearchResult(BaseModel):
    actors: list[ThreatActor]
    summary: str = ""
    key_findings: list[str] = []
    recommended_detections: list[DetectionRecommendation] = []
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
