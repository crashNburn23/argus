from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from argus.models.evidence import Artifact, EvidenceItem, Observable, Relationship


class CaseStatus(StrEnum):
    OPEN = "open"
    ACTIVE = "active"
    MONITORING = "monitoring"
    CLOSED = "closed"


class PIRStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    ANSWERED = "answered"
    CLOSED = "closed"


class CollectionStatus(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class PIR(BaseModel):
    pir_id: str = Field(default_factory=lambda: f"pir_{uuid4().hex}")
    question: str
    owner: str = ""
    status: PIRStatus = PIRStatus.OPEN
    priority: str = "medium"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    answered_at: datetime | None = None
    answer: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CollectionTask(BaseModel):
    task_id: str = Field(default_factory=lambda: f"task_{uuid4().hex}")
    objective: str
    status: CollectionStatus = CollectionStatus.PLANNED
    requested_sources: list[str] = Field(default_factory=list)
    time_window_start: datetime | None = None
    time_window_end: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    failure_reason: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CaseNote(BaseModel):
    note_id: str = Field(default_factory=lambda: f"note_{uuid4().hex}")
    body: str
    author: str = "analyst"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    evidence_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReportArtifact(BaseModel):
    report_id: str = Field(default_factory=lambda: f"rep_{uuid4().hex}")
    report_type: str
    title: str = ""
    classification: str = "TLP:AMBER"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    evidence_ids: list[str] = Field(default_factory=list)
    content: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class Case(BaseModel):
    case_id: str = Field(default_factory=lambda: f"case_{uuid4().hex}")
    title: str
    description: str = ""
    status: CaseStatus = CaseStatus.OPEN
    classification: str = "TLP:AMBER"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    opened_by: str = "analyst"
    closed_at: datetime | None = None
    scope: str = ""
    artifacts: list[Artifact] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    observables: list[Observable] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    pirs: list[PIR] = Field(default_factory=list)
    collection_tasks: list[CollectionTask] = Field(default_factory=list)
    notes: list[CaseNote] = Field(default_factory=list)
    reports: list[ReportArtifact] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

