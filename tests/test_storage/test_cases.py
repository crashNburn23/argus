from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from argus.models.case import Case
from argus.models.evidence import (
    Artifact,
    ArtifactType,
    EvidenceItem,
    EvidenceStatus,
    Observable,
    ObservableType,
)
from argus.storage.cases import CaseNotFoundError, CaseStore, CaseStoreError


def test_case_store_round_trips_case_with_evidence(tmp_path: Path) -> None:
    store = CaseStore(tmp_path)
    artifact = Artifact(
        artifact_type=ArtifactType.REPORT,
        source_name="vendor-report",
        title="Intrusion writeup",
        raw_text="Observed 198.51.100.10 communicating with malware.example",
    )
    observable = Observable(
        value="198.51.100.10",
        observable_type=ObservableType.IP,
        canonical_value="198.51.100.10",
        confidence=0.9,
    )
    evidence = EvidenceItem(
        artifact_id=artifact.artifact_id,
        source_name="vendor-report",
        source_type="report",
        status=EvidenceStatus.CONFIRMED,
        confidence=0.85,
        summary="Vendor report observed command-and-control traffic.",
        raw_excerpt="Observed 198.51.100.10 communicating with malware.example",
        observable_ids=[observable.observable_id],
    )
    observable.evidence_ids.append(evidence.evidence_id)
    case = Case(
        title="Vendor report triage",
        artifacts=[artifact],
        observables=[observable],
        evidence=[evidence],
        tags=["triage"],
    )

    store.create(case)
    loaded = store.get(case.case_id)

    assert loaded == case
    assert loaded.artifacts[0].artifact_type is ArtifactType.REPORT
    assert loaded.evidence[0].observable_ids == [observable.observable_id]
    assert loaded.observables[0].evidence_ids == [evidence.evidence_id]


def test_case_store_lists_cases_by_updated_at(tmp_path: Path) -> None:
    store = CaseStore(tmp_path)
    older = store.create(Case(title="Older", updated_at=datetime(2026, 1, 1, tzinfo=UTC)))
    newer = store.create(Case(title="Newer", updated_at=datetime(2026, 1, 2, tzinfo=UTC)))

    cases = store.list()

    assert [case.case_id for case in cases] == [newer.case_id, older.case_id]


def test_case_store_update_and_delete(tmp_path: Path) -> None:
    store = CaseStore(tmp_path)
    case = store.create(
        Case(title="Initial", updated_at=datetime(2026, 1, 1, tzinfo=UTC))
    )

    updated = store.update(
        case.case_id,
        lambda loaded: loaded.model_copy(update={"title": "Updated"}),
    )

    assert updated.title == "Updated"
    assert updated.updated_at > case.updated_at
    assert store.get(case.case_id).title == "Updated"
    assert store.delete(case.case_id) is True
    assert store.delete(case.case_id) is False
    with pytest.raises(CaseNotFoundError):
        store.get(case.case_id)


def test_case_store_rejects_path_traversal_ids(tmp_path: Path) -> None:
    store = CaseStore(tmp_path)

    with pytest.raises(CaseStoreError):
        store.get("../outside")
