"""CSV alert/IOC list ingestor.

Parses a CSV file of alert or IOC records using field-name heuristics for
observable classification (same heuristic table as the JSON ingestor).

Used by `case extract` when an artifact's content looks like a CSV table.
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from typing import Any

from argus.ingestion.json_ingestor import _typed_observable
from argus.models.evidence import EvidenceItem, EvidenceStatus, Observable, ObservableType


@dataclass
class CsvIngestResult:
    observables: list[Observable] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    row_count: int = 0
    header: list[str] = field(default_factory=list)


def ingest_csv(text: str, *, delimiter: str | None = None) -> CsvIngestResult:
    """Parse a CSV text and return structured case data."""
    result = CsvIngestResult()

    sniff_sample = text[:2048]
    if delimiter is None:
        try:
            dialect = csv.Sniffer().sniff(sniff_sample, delimiters=",\t|;")
            delimiter = dialect.delimiter
        except csv.Error:
            delimiter = ","

    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    if reader.fieldnames:
        result.header = [str(f) for f in reader.fieldnames]

    seen: set[tuple[ObservableType, str]] = set()

    def _add(obs: Observable) -> bool:
        key = (obs.observable_type, obs.canonical_value or obs.value)
        if key in seen:
            return False
        seen.add(key)
        result.observables.append(obs)
        return True

    try:
        rows: list[dict[str, Any]] = list(reader)
    except csv.Error:
        return result

    result.row_count = len(rows)

    for row in rows:
        row_obs: list[Observable] = []
        for field_name, value in row.items():
            if not isinstance(value, str) or not value.strip():
                continue
            obs = _typed_observable(value.strip(), field_name or "")
            if obs and _add(obs):
                row_obs.append(obs)

        if row_obs:
            row_id = (
                row.get("alert_id")
                or row.get("id")
                or row.get("event_id")
                or row.get("record_id")
                or ""
            )
            ev = EvidenceItem(
                source_name="csv_import",
                source_type="csv_import",
                status=EvidenceStatus.CONFIRMED,
                confidence=0.75,
                summary=(
                    f"CSV row{f' {row_id}' if row_id else ''}: "
                    f"{len(row_obs)} observable(s) extracted"
                ),
                observable_ids=[o.observable_id for o in row_obs],
            )
            result.evidence.append(ev)

    return result


def is_csv(text: str) -> bool:
    """Quick check: does this text look like a CSV table?

    Returns True if:
    - Content is not valid JSON
    - Has at least 2 lines
    - First line looks like a header row (comma/tab-delimited text values, no quotes nesting)
    """
    stripped = text.lstrip()
    # Exclude JSON
    if stripped.startswith(("{", "[")):
        return False

    lines = text.splitlines()
    if len(lines) < 2:
        return False

    header = lines[0]
    # A header should have at least 2 delimiter-separated tokens and no control chars
    for delim in (",", "\t", "|", ";"):
        parts = header.split(delim)
        if len(parts) >= 2:
            cleaned = [p.strip().replace('"', "").replace("'", "") for p in parts]
            if all(c.isidentifier() or " " in c for c in cleaned):
                return True

    return False
