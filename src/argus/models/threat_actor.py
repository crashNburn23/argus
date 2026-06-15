from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class MITRETechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: str = ""
    detection_guidance: str = ""
    data_sources: list[str] = []


class ThreatActor(BaseModel):
    name: str
    aliases: list[str] = []
    description: str = ""
    goals: list[str] = []
    sophistication: str = ""
    resource_level: str = ""
    primary_motivation: str = ""
    suspected_attribution: str = ""
    mitre_group_id: str | None = None
    techniques: list[MITRETechnique] = []
    campaigns: list[str] = []
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
    recommended_detections: list[str] = []
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
