from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class ArtifactType(StrEnum):
    REPORT = "report"
    ALERT = "alert"
    NOTE = "note"
    STIX = "stix"
    JSON = "json"
    CSV = "csv"
    PDF = "pdf"
    UNKNOWN = "unknown"


class EvidenceStatus(StrEnum):
    CONFIRMED = "confirmed"
    INFERRED = "inferred"
    MISSING = "missing"
    FAILED = "failed"


class ObservableType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"
    ATTACK_TTP = "attack_ttp"
    ACTOR = "actor"
    MALWARE = "malware"
    UNKNOWN = "unknown"


class RelationshipType(StrEnum):
    RELATED_TO = "related_to"
    DERIVED_FROM = "derived_from"
    EVIDENCES = "evidences"
    INDICATES = "indicates"
    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    ATTRIBUTED_TO = "attributed_to"
    USES = "uses"
    EXPLOITS = "exploits"
    TARGETS = "targets"
    OBSERVED_IN = "observed_in"


class Artifact(BaseModel):
    artifact_id: str = Field(default_factory=lambda: f"art_{uuid4().hex}")
    artifact_type: ArtifactType = ArtifactType.UNKNOWN
    source_name: str = ""
    title: str = ""
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    collected_at: datetime | None = None
    content_type: str = ""
    source_uri: str = ""
    raw_text: str = ""
    content_hash: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class Observable(BaseModel):
    observable_id: str = Field(default_factory=lambda: f"obs_{uuid4().hex}")
    value: str
    observable_type: ObservableType = ObservableType.UNKNOWN
    canonical_value: str = ""
    confidence: float = 0.0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    labels: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceItem(BaseModel):
    evidence_id: str = Field(default_factory=lambda: f"ev_{uuid4().hex}")
    artifact_id: str = ""
    source_name: str = ""
    source_type: str = ""
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: EvidenceStatus = EvidenceStatus.CONFIRMED
    confidence: float = 0.0
    summary: str = ""
    raw_excerpt: str = ""
    external_reference: str = ""
    observable_ids: list[str] = Field(default_factory=list)
    relationship_ids: list[str] = Field(default_factory=list)
    inference_basis: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class Relationship(BaseModel):
    relationship_id: str = Field(default_factory=lambda: f"rel_{uuid4().hex}")
    relationship_type: RelationshipType = RelationshipType.RELATED_TO
    source_ref: str
    target_ref: str
    confidence: float = 0.0
    evidence_ids: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    rationale: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
