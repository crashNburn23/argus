"""Cases REST API — CRUD for CTI cases."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from argus.models.case import Case, CaseNote, CaseReference, CaseStatus, ReportArtifact
from argus.models.evidence import Observable, ObservableType, Relationship, RelationshipType
from argus.storage.cases import CaseNotFoundError, CaseStore, CaseStoreError

log = structlog.get_logger()

# ── IOC regex patterns for pivot extraction ────────────────────────────────────

_IOC_PATTERNS: list[tuple[str, ObservableType]] = [
    (r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?\b", ObservableType.IP),
    (r"\b[a-fA-F0-9]{64}\b", ObservableType.SHA256),
    (r"\b[a-fA-F0-9]{40}\b", ObservableType.SHA1),
    (r"\b[a-fA-F0-9]{32}\b", ObservableType.MD5),
    (r"\b(CVE-\d{4}-\d+)\b", ObservableType.CVE),
    (
        r"(?:^|\s)((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})(?:\s|$)",
        ObservableType.DOMAIN,
    ),
]


def _extract_discovered_iocs(text: str) -> list[tuple[str, ObservableType]]:
    """Extract IOCs from the '## Additional IOCs Discovered' section of analysis text."""
    match = re.search(
        r"##\s+Additional\s+IOCs?\s+Discovered\b(.+?)(?=^##\s|\Z)",
        text,
        re.MULTILINE | re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return []
    section = match.group(1)
    found: dict[str, ObservableType] = {}
    for pattern, obs_type in _IOC_PATTERNS:
        for m in re.finditer(pattern, section):
            value = m.group(1) if m.lastindex else m.group(0)
            value = value.strip()
            if value and value not in found:
                found[value] = obs_type
    return list(found.items())


_FEEDBACK_LOG = Path.home() / ".argus" / "feedback.jsonl"


def _load_feedback_lessons(limit: int = 10) -> list[str]:
    """Return the most recent analyst corrections for injection into prompts."""
    if not _FEEDBACK_LOG.exists():
        return []
    try:
        lines = _FEEDBACK_LOG.read_text().strip().splitlines()
        corrections: list[str] = []
        for line in reversed(lines):
            try:
                entry = json.loads(line)
                if not entry.get("correct") and entry.get("correction"):
                    corrections.append(entry["correction"])
                    if len(corrections) >= limit:
                        break
            except json.JSONDecodeError:
                pass
        return list(reversed(corrections))
    except OSError:
        return []


router = APIRouter()


class CreateCaseRequest(BaseModel):
    title: str
    description: str = ""
    classification: str = "TLP:AMBER"


class UpdateCaseRequest(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None
    classification: str | None = None
    scope: str | None = None


class AddNoteRequest(BaseModel):
    body: str
    author: str = "analyst"
    manually_added: bool = False


class ObservableInput(BaseModel):
    value: str
    observable_type: str = "unknown"


class AddObservablesRequest(BaseModel):
    observables: list[ObservableInput]


def _summary(case: Case) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "title": case.title,
        "status": case.status.value,
        "classification": case.classification,
        "description": case.description,
        "created_at": case.created_at.isoformat(),
        "updated_at": case.updated_at.isoformat(),
        "observable_count": len(case.observables),
        "evidence_count": len(case.evidence),
        "note_count": len(case.notes),
        "pir_count": len(case.pirs),
        "report_count": len(case.reports),
        "tags": case.tags,
    }


@router.get("")
async def list_cases() -> list[dict[str, Any]]:
    return [_summary(c) for c in CaseStore().list()]


@router.post("", status_code=201)
async def create_case(req: CreateCaseRequest) -> dict[str, Any]:
    case = Case(
        title=req.title,
        description=req.description,
        classification=req.classification,
    )
    try:
        created = CaseStore().create(case)
    except CaseStoreError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return created.model_dump(mode="json")


@router.get("/{case_id}")
async def get_case(case_id: str) -> dict[str, Any]:
    try:
        return CaseStore().get(case_id).model_dump(mode="json")
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")


@router.patch("/{case_id}")
async def update_case(case_id: str, req: UpdateCaseRequest) -> dict[str, Any]:
    def _mutate(case: Case) -> Case:
        updates: dict[str, Any] = {}
        if req.title is not None:
            updates["title"] = req.title
        if req.description is not None:
            updates["description"] = req.description
        if req.status is not None:
            try:
                updates["status"] = CaseStatus(req.status)
            except ValueError:
                raise HTTPException(status_code=422, detail=f"Invalid status: {req.status}")
        if req.classification is not None:
            updates["classification"] = req.classification
        if req.scope is not None:
            updates["scope"] = req.scope
        return case.model_copy(update=updates) if updates else case

    try:
        updated = CaseStore().update(case_id, _mutate)
        return updated.model_dump(mode="json")
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")


@router.delete("/{case_id}")
async def delete_case(case_id: str) -> dict[str, bool]:
    if not CaseStore().delete(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    return {"deleted": True}


@router.post("/{case_id}/notes", status_code=201)
async def add_note(case_id: str, req: AddNoteRequest) -> dict[str, Any]:
    meta: dict[str, Any] = {"source": "manual"} if req.manually_added else {}
    note = CaseNote(body=req.body, author=req.author, metadata=meta)

    def _mutate(case: Case) -> Case:
        return case.model_copy(update={"notes": [*case.notes, note]})

    try:
        updated = CaseStore().update(case_id, _mutate)
        return updated.model_dump(mode="json")
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")


@router.post("/{case_id}/observables", status_code=201)
async def add_observables(case_id: str, req: AddObservablesRequest) -> dict[str, Any]:
    if not req.observables:
        raise HTTPException(status_code=400, detail="No observables provided")

    now = datetime.now(UTC)
    new_obs = [
        Observable(
            value=item.value.strip(),
            observable_type=_coerce_obs_type(item.observable_type),
            labels=["manually_added"],
            first_seen=now,
            last_seen=now,
            metadata={"source": "manual"},
        )
        for item in req.observables
        if item.value.strip()
    ]

    def _mutate(case: Case) -> Case:
        existing_values = {o.value for o in case.observables}
        to_add = [o for o in new_obs if o.value not in existing_values]
        return case.model_copy(update={"observables": [*case.observables, *to_add]})

    try:
        updated = CaseStore().update(case_id, _mutate)
        return updated.model_dump(mode="json")
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")


class ReviewRequest(BaseModel):
    observable_ids: list[str] | None = None  # None = all manual obs
    note_ids: list[str] | None = None  # None = all manual notes
    reference_ids: list[str] | None = None  # None = no references included


def _build_review_query(
    case: Any,
    manual_obs: list[Any],
    manual_notes: list[Any],
    selected_refs: list[Any],
) -> str:
    parts: list[str] = [f"Case: {case.title}", f"Status: {case.status.value}"]
    if case.description:
        parts.append(f"Description: {case.description}")
    parts.append("")
    if manual_obs:
        parts.append(f"Observables for investigation ({len(manual_obs)}):")
        for o in manual_obs:
            parts.append(f"  [{o.observable_type.value}] {o.value}")
        parts.append("")
    if manual_notes:
        parts.append(f"Analyst notes ({len(manual_notes)}):")
        for n in manual_notes:
            parts.append(f"  --- Note by {n.author} ---")
            parts.append(f"  {n.body}")
            parts.append("")
    if selected_refs:
        parts.append(f"References for context ({len(selected_refs)}):")
        for r in selected_refs:
            parts.append(f"  {r.url}" + (f" — {r.title}" if r.title else ""))
        parts.append("")
    parts.append(
        "Investigate the above IOCs and notes. Pivot from findings to related "
        "infrastructure. Attribute to known threat actors where evidence supports it."
    )
    lessons = _load_feedback_lessons()
    if lessons:
        parts.append("")
        parts.append("Analyst corrections from previous reviews (apply these lessons):")
        for lesson in lessons:
            parts.append(f"  - {lesson}")
    return "\n".join(parts)


def _apply_review_result(
    case: Any,
    result: str,
    reviewed_note_ids: set[str],
    reviewed_ref_ids: set[str],
) -> Any:
    now = datetime.now(UTC)
    url_pattern = re.compile(r'https?://[^\s\)\]">]+')
    found_urls = list(dict.fromkeys(url_pattern.findall(result)))
    skip_domains = {"virustotal.com", "shodan.io", "abuseipdb.com", "otx.alienvault.com"}
    new_refs = [
        CaseReference(url=u, added_by="argus", needs_review=True)
        for u in found_urls
        if not any(d in u for d in skip_domains)
    ]

    new_notes = []
    for n in case.notes:
        if n.note_id in reviewed_note_ids:
            updated_meta = {**n.metadata, "reviewed": True}
            new_notes.append(n.model_copy(update={"metadata": updated_meta}))
        else:
            new_notes.append(n)
    updated_refs = [
        r.model_copy(update={"needs_review": False}) if r.ref_id in reviewed_ref_ids else r
        for r in case.references
    ]
    review_note = CaseNote(
        body=f"## Argus Review\n\n{result}",
        author="argus",
        metadata={"source": "argus_review"},
    )
    existing_urls = {r.url for r in updated_refs}
    deduped_new_refs = [r for r in new_refs if r.url not in existing_urls]

    # ── Extract discovered IOCs and create pivot relationships ─────────────────
    existing_values = {o.value for o in case.observables}
    discovered = _extract_discovered_iocs(result)
    new_obs: list[Observable] = []
    for value, obs_type in discovered:
        if value not in existing_values:
            new_obs.append(
                Observable(
                    value=value,
                    observable_type=obs_type,
                    labels=["argus_discovered"],
                    first_seen=now,
                    last_seen=now,
                    metadata={"source": "argus_review"},
                )
            )
            existing_values.add(value)

    # Create DERIVED_FROM edges: each discovered IOC → all original seed IOCs
    seed_ids = [o.observable_id for o in case.observables if "manually_added" in o.labels]
    existing_rel_pairs = {(r.source_ref, r.target_ref) for r in case.relationships}
    new_rels: list[Relationship] = []
    for obs in new_obs:
        for seed_id in seed_ids:
            pair = (obs.observable_id, seed_id)
            if pair not in existing_rel_pairs:
                new_rels.append(
                    Relationship(
                        relationship_type=RelationshipType.DERIVED_FROM,
                        source_ref=obs.observable_id,
                        target_ref=seed_id,
                        confidence=0.7,
                        rationale="Discovered during Argus pivot analysis",
                    )
                )
                existing_rel_pairs.add(pair)

    return case.model_copy(
        update={
            "notes": [*new_notes, review_note],
            "references": [*updated_refs, *deduped_new_refs],
            "observables": [*case.observables, *new_obs],
            "relationships": [*case.relationships, *new_rels],
        }
    )


def _resolve_review_selections(
    case: Any, req: ReviewRequest
) -> tuple[list[Any], list[Any], list[Any]]:
    all_manual_obs = [o for o in case.observables if "manually_added" in o.labels]
    all_manual_notes = [n for n in case.notes if n.metadata.get("source") == "manual"]
    manual_obs = (
        [o for o in all_manual_obs if o.observable_id in req.observable_ids]
        if req.observable_ids is not None
        else all_manual_obs
    )
    manual_notes = (
        [n for n in all_manual_notes if n.note_id in req.note_ids]
        if req.note_ids is not None
        else all_manual_notes
    )
    selected_refs = (
        [r for r in case.references if r.ref_id in req.reference_ids]
        if req.reference_ids is not None
        else []
    )
    return manual_obs, manual_notes, selected_refs


@router.post("/{case_id}/review")
async def review_case(case_id: str, req: ReviewRequest = ReviewRequest()) -> dict[str, Any]:
    """Run the case analysis agent against selected observables, notes, and references."""
    try:
        case = CaseStore().get(case_id)
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")

    manual_obs, manual_notes, selected_refs = _resolve_review_selections(case, req)
    if not manual_obs and not manual_notes and not selected_refs:
        raise HTTPException(
            status_code=400, detail="No observables, notes, or references selected for review"
        )

    reviewed_note_ids = {n.note_id for n in manual_notes}
    reviewed_ref_ids = {r.ref_id for r in selected_refs}
    query = _build_review_query(case, manual_obs, manual_notes, selected_refs)

    from argus.agents.case_analysis_agent import CaseAnalysisAgent

    agent = CaseAnalysisAgent()
    try:
        result = await agent.run(query=query)
    except Exception as exc:
        log.error(
            "review.agent_failed", case_id=case_id, error=str(exc), error_type=type(exc).__name__
        )
        raise HTTPException(status_code=500, detail=f"Analysis error: {exc}")

    updated = CaseStore().update(
        case_id,
        lambda c: _apply_review_result(c, result, reviewed_note_ids, reviewed_ref_ids),
    )
    review_note_out = next(
        (n for n in reversed(updated.notes) if n.metadata.get("source") == "argus_review"), None
    )
    return {
        "note": review_note_out.model_dump(mode="json") if review_note_out else {},
        "summary": _summary(updated),
    }


@router.post("/{case_id}/review/stream")
async def stream_review_case(
    case_id: str, req: ReviewRequest = ReviewRequest()
) -> StreamingResponse:
    """SSE variant of review_case — streams progress events then a final 'done' or 'error' event."""
    try:
        case = CaseStore().get(case_id)
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")

    manual_obs, manual_notes, selected_refs = _resolve_review_selections(case, req)
    if not manual_obs and not manual_notes and not selected_refs:
        raise HTTPException(
            status_code=400, detail="No observables, notes, or references selected for review"
        )

    reviewed_note_ids = {n.note_id for n in manual_notes}
    reviewed_ref_ids = {r.ref_id for r in selected_refs}
    query = _build_review_query(case, manual_obs, manual_notes, selected_refs)

    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    loop = asyncio.get_event_loop()

    def _on_progress(text: str) -> None:
        try:
            loop.call_soon_threadsafe(queue.put_nowait, {"type": "progress", "text": text})
        except Exception:
            pass

    async def _run() -> None:
        from argus.agents.case_analysis_agent import CaseAnalysisAgent

        agent = CaseAnalysisAgent(progress=_on_progress)
        try:
            result = await agent.run(query=query)
            updated = CaseStore().update(
                case_id,
                lambda c: _apply_review_result(c, result, reviewed_note_ids, reviewed_ref_ids),
            )
            review_note_out = next(
                (n for n in reversed(updated.notes) if n.metadata.get("source") == "argus_review"),
                None,
            )
            await queue.put(
                {
                    "type": "done",
                    "note": review_note_out.model_dump(mode="json") if review_note_out else {},
                    "summary": _summary(updated),
                }
            )
        except Exception as exc:
            log.error(
                "stream_review.agent_failed",
                case_id=case_id,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            await queue.put({"type": "error", "text": str(exc)})

    asyncio.create_task(_run())

    async def _event_stream() -> AsyncGenerator[str, None]:
        while True:
            event = await queue.get()
            yield f"data: {json.dumps(event)}\n\n"
            if event["type"] in ("done", "error"):
                break

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Note edit / delete / re-analyze ───────────────────────────────────────────


class UpdateNoteRequest(BaseModel):
    body: str


@router.patch("/{case_id}/notes/{note_id}")
async def update_note(case_id: str, note_id: str, req: UpdateNoteRequest) -> dict[str, Any]:
    def _mutate(case: Case) -> Case:
        new_notes = [
            n.model_copy(update={"body": req.body}) if n.note_id == note_id else n
            for n in case.notes
        ]
        if not any(n.note_id == note_id for n in case.notes):
            raise HTTPException(status_code=404, detail="Note not found")
        return case.model_copy(update={"notes": new_notes})

    try:
        updated = CaseStore().update(case_id, _mutate)
        return updated.model_dump(mode="json")
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")


@router.delete("/{case_id}/notes/{note_id}")
async def delete_note(case_id: str, note_id: str) -> dict[str, Any]:
    def _mutate(case: Case) -> Case:
        new_notes = [n for n in case.notes if n.note_id != note_id]
        if len(new_notes) == len(case.notes):
            raise HTTPException(status_code=404, detail="Note not found")
        return case.model_copy(update={"notes": new_notes})

    try:
        updated = CaseStore().update(case_id, _mutate)
        return updated.model_dump(mode="json")
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")


@router.post("/{case_id}/notes/{note_id}/reanalyze")
async def reanalyze_note(case_id: str, note_id: str) -> dict[str, Any]:
    try:
        case = CaseStore().get(case_id)
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")

    note = next((n for n in case.notes if n.note_id == note_id), None)
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")

    query = (
        f"Case: {case.title}\n\n"
        f"Re-analyze the following analyst note from an adversary infrastructure "
        f"and threat intelligence perspective. Identify IOCs, attribute to known "
        f"actors or campaigns, and provide actionable recommendations.\n\n"
        f"Note:\n{note.body}"
    )

    from argus.agents.orchestrator import CTIOrchestrator

    orchestrator = CTIOrchestrator(persistent=False)
    try:
        result = await orchestrator.run(user_query=query)
    except Exception as exc:
        log.error(
            "reanalyze.orchestrator_failed",
            case_id=case_id,
            note_id=note_id,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        raise HTTPException(status_code=500, detail=f"Orchestrator error: {exc}")

    def _add(c: Case) -> Case:
        new_note = CaseNote(
            body=f"## Re-analysis\n\n{result}",
            author="argus",
            metadata={"source": "argus_review", "reanalyzed_note_id": note_id},
        )
        return c.model_copy(update={"notes": [*c.notes, new_note]})

    updated = CaseStore().update(case_id, _add)
    return updated.model_dump(mode="json")


# ── References ─────────────────────────────────────────────────────────────────


class AddReferenceRequest(BaseModel):
    url: str
    title: str = ""
    needs_review: bool = True


class UpdateReferenceRequest(BaseModel):
    url: str | None = None
    title: str | None = None
    needs_review: bool | None = None


@router.get("/{case_id}/references")
async def list_references(case_id: str) -> list[dict[str, Any]]:
    try:
        case = CaseStore().get(case_id)
        return [r.model_dump(mode="json") for r in case.references]
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")


@router.post("/{case_id}/references", status_code=201)
async def add_reference(case_id: str, req: AddReferenceRequest) -> dict[str, Any]:
    ref = CaseReference(url=req.url.strip(), title=req.title.strip(), needs_review=req.needs_review)

    def _mutate(case: Case) -> Case:
        return case.model_copy(update={"references": [*case.references, ref]})

    try:
        updated = CaseStore().update(case_id, _mutate)
        return updated.model_dump(mode="json")
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")


@router.patch("/{case_id}/references/{ref_id}")
async def update_reference(
    case_id: str, ref_id: str, req: UpdateReferenceRequest
) -> dict[str, Any]:
    def _mutate(case: Case) -> Case:
        new_refs = []
        found = False
        for r in case.references:
            if r.ref_id == ref_id:
                found = True
                updates: dict[str, Any] = {}
                if req.url is not None:
                    updates["url"] = req.url.strip()
                if req.title is not None:
                    updates["title"] = req.title.strip()
                if req.needs_review is not None:
                    updates["needs_review"] = req.needs_review
                new_refs.append(r.model_copy(update=updates) if updates else r)
            else:
                new_refs.append(r)
        if not found:
            raise HTTPException(status_code=404, detail="Reference not found")
        return case.model_copy(update={"references": new_refs})

    try:
        updated = CaseStore().update(case_id, _mutate)
        return updated.model_dump(mode="json")
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")


@router.delete("/{case_id}/references/{ref_id}")
async def delete_reference(case_id: str, ref_id: str) -> dict[str, Any]:
    def _mutate(case: Case) -> Case:
        new_refs = [r for r in case.references if r.ref_id != ref_id]
        if len(new_refs) == len(case.references):
            raise HTTPException(status_code=404, detail="Reference not found")
        return case.model_copy(update={"references": new_refs})

    try:
        updated = CaseStore().update(case_id, _mutate)
        return updated.model_dump(mode="json")
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")


# ── Report generation ──────────────────────────────────────────────────────────

REPORT_AUDIENCES = ["cti", "soc", "vm", "ir", "exec", "awareness", "redteam"]


class GenerateReportRequest(BaseModel):
    audience: str = "cti"
    special_notes: str = ""


@router.get("/{case_id}/reports")
async def list_reports(case_id: str) -> list[dict[str, Any]]:
    try:
        case = CaseStore().get(case_id)
        return [r.model_dump(mode="json") for r in case.reports]
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")


@router.post("/{case_id}/reports", status_code=201)
async def generate_report(case_id: str, req: GenerateReportRequest) -> dict[str, Any]:
    if req.audience not in REPORT_AUDIENCES:
        raise HTTPException(
            status_code=400, detail=f"Unknown audience. Valid: {', '.join(REPORT_AUDIENCES)}"
        )
    try:
        case = CaseStore().get(case_id)
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")

    from argus.agents.case_report_agent import CaseReportAgent  # avoid circular

    agent = CaseReportAgent(audience=req.audience)
    try:
        content = await agent.generate(case)
    except Exception as exc:
        log.error(
            "report.agent_failed",
            case_id=case_id,
            audience=req.audience,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        raise HTTPException(status_code=500, detail=f"Report generation error: {exc}")

    if req.special_notes.strip():
        content = f"{content}\n\n---\n\n**Analyst Notes:**\n\n{req.special_notes.strip()}"

    artifact = ReportArtifact(
        report_type=req.audience,
        title=f"{req.audience.upper()} Report — {case.title}",
        classification=case.classification,
        content=content,
        metadata={"special_notes": req.special_notes.strip()},
    )

    def _add_report(c: Case) -> Case:
        return c.model_copy(update={"reports": [*c.reports, artifact]})

    updated = CaseStore().update(case_id, _add_report)
    latest = next((r for r in reversed(updated.reports) if r.report_id == artifact.report_id), None)
    return latest.model_dump(mode="json") if latest else artifact.model_dump(mode="json")


@router.delete("/{case_id}/reports/{report_id}")
async def delete_report(case_id: str, report_id: str) -> dict[str, bool]:
    def _mutate(case: Case) -> Case:
        new_reports = [r for r in case.reports if r.report_id != report_id]
        if len(new_reports) == len(case.reports):
            raise HTTPException(status_code=404, detail="Report not found")
        return case.model_copy(update={"reports": new_reports})

    try:
        CaseStore().update(case_id, _mutate)
        return {"deleted": True}
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")


# ── IOC relationship graph ─────────────────────────────────────────────────────


@router.get("/{case_id}/graph")
async def get_case_graph(case_id: str) -> dict[str, Any]:
    """Return graph nodes (observables) and edges (relationships) for visualisation."""
    try:
        case = CaseStore().get(case_id)
    except CaseNotFoundError:
        raise HTTPException(status_code=404, detail="Case not found")

    evidence_by_id = {ev.evidence_id: ev for ev in case.evidence}

    def _evidence_summary(evidence_ids: list[str]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for evidence_id in evidence_ids:
            ev = evidence_by_id.get(evidence_id)
            if ev is None:
                continue
            out.append(
                {
                    "id": ev.evidence_id,
                    "source": ev.source_name or ev.source_type,
                    "status": ev.status.value,
                    "confidence": ev.confidence,
                    "summary": ev.summary,
                    "excerpt": ev.raw_excerpt,
                    "reference": ev.external_reference,
                    "inference_basis": ev.inference_basis,
                }
            )
        return out

    nodes = [
        {
            "id": o.observable_id,
            "label": o.value,
            "type": o.observable_type.value,
            "manually_added": "manually_added" in o.labels,
            "argus_discovered": "argus_discovered" in o.labels,
            "confidence": o.confidence,
            "source": str(o.metadata.get("source", "")),
            "evidence": _evidence_summary(o.evidence_ids),
        }
        for o in case.observables
    ]

    # Build an index so we can label edges with node values instead of IDs
    obs_by_id = {o.observable_id: o.value for o in case.observables}

    edges = [
        {
            "id": r.relationship_id,
            "source": r.source_ref,
            "target": r.target_ref,
            "source_label": obs_by_id.get(r.source_ref, r.source_ref[:8]),
            "target_label": obs_by_id.get(r.target_ref, r.target_ref[:8]),
            "label": r.relationship_type.value.replace("_", " "),
            "confidence": r.confidence,
            "rationale": r.rationale,
            "evidence": _evidence_summary(r.evidence_ids),
        }
        for r in case.relationships
        # only include edges where both endpoints are known observables
        if r.source_ref in obs_by_id and r.target_ref in obs_by_id
    ]

    return {"nodes": nodes, "edges": edges}


# ── Feedback / learning ────────────────────────────────────────────────────────


class NoteFeedbackRequest(BaseModel):
    correct: bool
    correction: str = ""


@router.post("/{case_id}/notes/{note_id}/feedback", status_code=201)
async def submit_note_feedback(
    case_id: str, note_id: str, req: NoteFeedbackRequest
) -> dict[str, str]:
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "case_id": case_id,
        "note_id": note_id,
        "correct": req.correct,
        "correction": req.correction.strip(),
    }
    _FEEDBACK_LOG.parent.mkdir(parents=True, exist_ok=True)
    with _FEEDBACK_LOG.open("a") as f:
        f.write(json.dumps(entry) + "\n")

    # Persist the vote into note metadata so it survives page refresh
    try:

        def _record_feedback(case: Case) -> Case:
            new_notes = [
                n.model_copy(
                    update={
                        "metadata": {**n.metadata, "feedback": "up" if req.correct else "down"},
                    }
                )
                if n.note_id == note_id
                else n
                for n in case.notes
            ]
            return case.model_copy(update={"notes": new_notes})

        CaseStore().update(case_id, _record_feedback)
    except CaseNotFoundError:
        pass  # feedback log is already written; don't fail the request

    return {"status": "recorded"}


# ── Misc helpers ───────────────────────────────────────────────────────────────


def _coerce_obs_type(raw: str) -> ObservableType:
    try:
        return ObservableType(raw.lower())
    except ValueError:
        return ObservableType.UNKNOWN
