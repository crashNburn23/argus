from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from argus.config.settings import get_settings
from argus.models.case import Case


class CaseStoreError(Exception):
    """Base error for case persistence failures."""


class CaseNotFoundError(CaseStoreError):
    """Raised when a requested case does not exist."""


class CaseStore:
    """File-backed storage for CTI cases.

    Cases are persisted as one JSON document per case so the data model can evolve
    independently from the existing SQLite cache/run-record store.
    """

    def __init__(self, cases_dir: Path | None = None) -> None:
        self.cases_dir = cases_dir or get_settings().cases_dir

    def create(self, case: Case) -> Case:
        """Persist a new case and fail if the ID already exists."""
        path = self._path_for(case.case_id)
        if path.exists():
            raise CaseStoreError(f"Case already exists: {case.case_id}")
        self._write(case, touch=False)
        return case

    def save(self, case: Case) -> Case:
        """Create or replace a case document."""
        updated = self._touch(case)
        self._write(updated, touch=False)
        return updated

    def get(self, case_id: str) -> Case:
        """Load a case by ID."""
        path = self._path_for(case_id)
        if not path.exists():
            raise CaseNotFoundError(f"Case not found: {case_id}")
        return Case.model_validate_json(path.read_text(encoding="utf-8"))

    def update(self, case_id: str, mutate: Callable[[Case], Case | None]) -> Case:
        """Load a case, apply a mutation callback, and save the result."""
        case = self.get(case_id)
        updated = mutate(case) or case
        updated = self._touch(updated)
        self._write(updated, touch=False)
        return updated

    def list(self) -> list[Case]:
        """Return all cases sorted by most recent update first."""
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        cases = [
            Case.model_validate_json(path.read_text(encoding="utf-8"))
            for path in self.cases_dir.glob("*.json")
            if path.is_file()
        ]
        return sorted(cases, key=lambda case: case.updated_at, reverse=True)

    def delete(self, case_id: str) -> bool:
        """Delete a case if present."""
        path = self._path_for(case_id)
        if not path.exists():
            return False
        path.unlink()
        return True

    def _write(self, case: Case, *, touch: bool) -> None:
        if touch:
            case = self._touch(case)
        path = self._path_for(case.case_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(".json.tmp")
        tmp_path.write_text(case.model_dump_json(indent=2), encoding="utf-8")
        tmp_path.replace(path)

    def _touch(self, case: Case) -> Case:
        return case.model_copy(update={"updated_at": datetime.now(UTC)})

    def _path_for(self, case_id: str) -> Path:
        if not case_id or "/" in case_id or "\\" in case_id or case_id in {".", ".."}:
            raise CaseStoreError(f"Invalid case ID: {case_id!r}")
        return self.cases_dir / f"{case_id}.json"
