"""argus case - CTI case workspace commands."""
from __future__ import annotations

import asyncio
import hashlib
import json as json_lib
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.table import Table

from argus.cli.output import console, print_error, print_json
from argus.ingestion.extractors import extract_observables
from argus.models.case import PIR, Case, CaseNote, ReportArtifact
from argus.models.evidence import (
    Artifact,
    ArtifactType,
    EvidenceItem,
    EvidenceStatus,
    Observable,
    ObservableType,
    Relationship,
    RelationshipType,
)
from argus.storage.cases import CaseNotFoundError, CaseStore, CaseStoreError

app = typer.Typer(help="Manage CTI cases")


@app.command("create")
def create_case(
    title: Annotated[str, typer.Argument(help="Case title")],
    description: Annotated[str, typer.Option("--description", "-d")] = "",
    classification: Annotated[str, typer.Option("--classification", "-c")] = "TLP:AMBER",
    scope: Annotated[str, typer.Option("--scope", "-s")] = "",
    tag: Annotated[list[str] | None, typer.Option("--tag", help="Repeatable case tag")] = None,
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Create a new case workspace."""
    case = Case(
        title=title,
        description=description,
        classification=classification,
        scope=scope,
        tags=tag or [],
    )
    try:
        CaseStore().create(case)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    if json:
        print_json(case)
        return
    console.print(f"[cp.green]created[/cp.green] [cp.cyan]{case.case_id}[/cp.cyan] {case.title}")


@app.command("list")
def list_cases(
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """List stored cases."""
    cases = CaseStore().list()
    if json:
        print_json([case.model_dump(mode="json") for case in cases])
        return

    if not cases:
        console.print("[cp.dim]No cases found.[/cp.dim]")
        return

    table = Table(title="[cp.cyan]Cases[/cp.cyan]", header_style="cp.magenta")
    table.add_column("ID", style="cp.cyan", no_wrap=True)
    table.add_column("Status")
    table.add_column("Title")
    table.add_column("Updated", no_wrap=True)
    table.add_column("Evidence", justify="right")
    for case in cases:
        table.add_row(
            case.case_id,
            case.status.value,
            case.title,
            case.updated_at.strftime("%Y-%m-%d %H:%M"),
            str(len(case.evidence)),
        )
    console.print(table)


@app.command("show")
def show_case(
    case_id: Annotated[str, typer.Argument(help="Case ID")],
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Show a case summary."""
    try:
        case = CaseStore().get(case_id)
    except CaseNotFoundError:
        print_error(f"Case not found: {case_id}")
        raise typer.Exit(1)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    if json:
        print_json(case)
        return

    table = Table(title=f"[cp.cyan]{case.case_id}[/cp.cyan]", show_header=False)
    table.add_column("Field", style="cp.magenta")
    table.add_column("Value")
    table.add_row("Title", case.title)
    table.add_row("Status", case.status.value)
    table.add_row("Classification", case.classification)
    table.add_row("Scope", case.scope or "-")
    table.add_row("Description", case.description or "-")
    table.add_row("Artifacts", str(len(case.artifacts)))
    table.add_row("Evidence", str(len(case.evidence)))
    table.add_row("Observables", str(len(case.observables)))
    table.add_row("Relationships", str(len(case.relationships)))
    table.add_row("PIRs", str(len(case.pirs)))
    table.add_row("Notes", str(len(case.notes)))
    table.add_row("Updated", case.updated_at.isoformat())
    console.print(table)


@app.command("note")
def add_note(
    case_id: Annotated[str, typer.Argument(help="Case ID")],
    body: Annotated[str, typer.Argument(help="Analyst note text")],
    author: Annotated[str, typer.Option("--author", "-a")] = "analyst",
    evidence_id: Annotated[
        list[str] | None,
        typer.Option("--evidence-id", help="Evidence ID supporting this note"),
    ] = None,
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Append an analyst note to a case."""
    note = CaseNote(body=body, author=author, evidence_ids=evidence_id or [])

    def mutate(case: Case) -> Case:
        return case.model_copy(update={"notes": [*case.notes, note]})

    try:
        updated = CaseStore().update(case_id, mutate)
    except CaseNotFoundError:
        print_error(f"Case not found: {case_id}")
        raise typer.Exit(1)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    if json:
        print_json(updated)
        return
    console.print(
        f"[cp.green]added note[/cp.green] [cp.cyan]{note.note_id}[/cp.cyan] "
        f"to [cp.cyan]{case_id}[/cp.cyan]"
    )


@app.command("pir")
def add_pir(
    case_id: Annotated[str, typer.Argument(help="Case ID")],
    question: Annotated[str, typer.Argument(help="Priority intelligence requirement")],
    owner: Annotated[str, typer.Option("--owner", "-o")] = "",
    priority: Annotated[str, typer.Option("--priority", "-p")] = "medium",
    tag: Annotated[list[str] | None, typer.Option("--tag", help="Repeatable PIR tag")] = None,
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Add a priority intelligence requirement to a case."""
    pir = PIR(question=question, owner=owner, priority=priority, tags=tag or [])

    def mutate(case: Case) -> Case:
        return case.model_copy(update={"pirs": [*case.pirs, pir]})

    try:
        updated = CaseStore().update(case_id, mutate)
    except CaseNotFoundError:
        print_error(f"Case not found: {case_id}")
        raise typer.Exit(1)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    if json:
        print_json(updated)
        return
    console.print(
        f"[cp.green]added PIR[/cp.green] [cp.cyan]{pir.pir_id}[/cp.cyan] "
        f"to [cp.cyan]{case_id}[/cp.cyan]"
    )


@app.command("artifact")
def add_artifact(
    case_id: Annotated[str, typer.Argument(help="Case ID")],
    path: Annotated[Path | None, typer.Option("--file", "-f", help="Artifact file")] = None,
    text: Annotated[str | None, typer.Option("--text", "-t", help="Raw artifact text")] = None,
    title: Annotated[str, typer.Option("--title")] = "",
    source_name: Annotated[str, typer.Option("--source", "-s")] = "analyst",
    artifact_type: Annotated[ArtifactType, typer.Option("--type")] = ArtifactType.UNKNOWN,
    content_type: Annotated[str, typer.Option("--content-type")] = "text/plain",
    source_uri: Annotated[str, typer.Option("--source-uri")] = "",
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Attach a raw source artifact to a case."""
    if (path is None) == (text is None):
        print_error("Provide exactly one of --file or --text")
        raise typer.Exit(1)
    if path is not None:
        if not path.exists():
            print_error(f"File not found: {path}")
            raise typer.Exit(1)
        raw_text = path.read_text(encoding="utf-8")
        artifact_title = title or path.name
        artifact_source_uri = source_uri or str(path)
    else:
        raw_text = text or ""
        artifact_title = title or "Analyst supplied text"
        artifact_source_uri = source_uri

    artifact = Artifact(
        artifact_type=artifact_type,
        source_name=source_name,
        title=artifact_title,
        content_type=content_type,
        source_uri=artifact_source_uri,
        raw_text=raw_text,
        content_hash=hashlib.sha256(raw_text.encode("utf-8")).hexdigest(),
    )

    def mutate(case: Case) -> Case:
        return case.model_copy(update={"artifacts": [*case.artifacts, artifact]})

    try:
        updated = CaseStore().update(case_id, mutate)
    except CaseNotFoundError:
        print_error(f"Case not found: {case_id}")
        raise typer.Exit(1)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    if json:
        print_json(updated)
        return
    console.print(
        f"[cp.green]added artifact[/cp.green] [cp.cyan]{artifact.artifact_id}[/cp.cyan] "
        f"to [cp.cyan]{case_id}[/cp.cyan]"
    )


@app.command("extract")
def extract_case_artifacts(
    case_id: Annotated[str, typer.Argument(help="Case ID")],
    artifact_id: Annotated[
        str | None,
        typer.Option("--artifact-id", "-a", help="Extract from one artifact only"),
    ] = None,
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Extract observables from stored case artifacts."""
    extracted_count = 0
    evidence_count = 0

    def mutate(case: Case) -> Case:
        nonlocal extracted_count, evidence_count
        artifacts = [
            artifact
            for artifact in case.artifacts
            if artifact_id is None or artifact.artifact_id == artifact_id
        ]
        if artifact_id is not None and not artifacts:
            raise CaseStoreError(f"Artifact not found: {artifact_id}")

        observables = list(case.observables)
        evidence_items = list(case.evidence)
        observable_index = {
            (observable.observable_type, observable.canonical_value or observable.value): observable
            for observable in observables
        }
        evidence_index = {
            (
                evidence.artifact_id,
                evidence.metadata.get("extractor"),
                evidence.metadata.get("observable_type"),
                evidence.metadata.get("canonical_value"),
            )
            for evidence in evidence_items
        }

        relationships = list(case.relationships)

        import json as _json

        from argus.ingestion.csv_ingestor import ingest_csv, is_csv
        from argus.ingestion.json_ingestor import ingest_json_alerts, is_json_alert_array
        from argus.ingestion.stix_ingestor import ingest_stix_bundle, is_stix_bundle

        for artifact in artifacts:
            if is_stix_bundle(artifact.raw_text):
                stix_result = ingest_stix_bundle(_json.loads(artifact.raw_text))
                for obs in stix_result.observables:
                    key = (obs.observable_type, obs.canonical_value or obs.value)
                    if key not in observable_index:
                        observables.append(obs)
                        observable_index[key] = obs
                        extracted_count += 1
                for ev in stix_result.evidence:
                    ev = ev.model_copy(update={"artifact_id": artifact.artifact_id})
                    evidence_items.append(ev)
                    evidence_count += 1
                relationships.extend(stix_result.relationships)
                continue

            if is_json_alert_array(artifact.raw_text):
                json_result = ingest_json_alerts(_json.loads(artifact.raw_text))
                for obs in json_result.observables:
                    key = (obs.observable_type, obs.canonical_value or obs.value)
                    if key not in observable_index:
                        observables.append(obs)
                        observable_index[key] = obs
                        extracted_count += 1
                for ev in json_result.evidence:
                    ev = ev.model_copy(update={"artifact_id": artifact.artifact_id})
                    evidence_items.append(ev)
                    evidence_count += 1
                continue

            if is_csv(artifact.raw_text):
                csv_result = ingest_csv(artifact.raw_text)
                for obs in csv_result.observables:
                    key = (obs.observable_type, obs.canonical_value or obs.value)
                    if key not in observable_index:
                        observables.append(obs)
                        observable_index[key] = obs
                        extracted_count += 1
                for ev in csv_result.evidence:
                    ev = ev.model_copy(update={"artifact_id": artifact.artifact_id})
                    evidence_items.append(ev)
                    evidence_count += 1
                continue

            for extracted in extract_observables(artifact.raw_text):
                evidence_key = (
                    artifact.artifact_id,
                    "regex",
                    extracted.observable_type.value,
                    extracted.canonical_value,
                )
                if evidence_key in evidence_index:
                    continue
                evidence = EvidenceItem(
                    artifact_id=artifact.artifact_id,
                    source_name=artifact.source_name,
                    source_type=artifact.artifact_type.value,
                    status=EvidenceStatus.CONFIRMED,
                    confidence=0.75,
                    summary=(
                        f"Extracted {extracted.observable_type.value} "
                        f"{extracted.canonical_value} from artifact {artifact.artifact_id}."
                    ),
                    raw_excerpt=extracted.raw_excerpt,
                    metadata={
                        "extractor": "regex",
                        "observable_type": extracted.observable_type.value,
                        "canonical_value": extracted.canonical_value,
                    },
                )
                key = (extracted.observable_type, extracted.canonical_value)
                existing = observable_index.get(key)
                if existing is None:
                    observable = Observable(
                        value=extracted.value,
                        observable_type=extracted.observable_type,
                        canonical_value=extracted.canonical_value,
                        confidence=0.75,
                        evidence_ids=[evidence.evidence_id],
                    )
                    observables.append(observable)
                    observable_index[key] = observable
                    evidence.observable_ids.append(observable.observable_id)
                    extracted_count += 1
                else:
                    if evidence.evidence_id not in existing.evidence_ids:
                        existing.evidence_ids.append(evidence.evidence_id)
                    evidence.observable_ids.append(existing.observable_id)
                evidence_items.append(evidence)
                evidence_index.add(evidence_key)
                evidence_count += 1

        return case.model_copy(
            update={
                "observables": observables,
                "evidence": evidence_items,
                "relationships": relationships,
            }
        )

    try:
        updated = CaseStore().update(case_id, mutate)
    except CaseNotFoundError:
        print_error(f"Case not found: {case_id}")
        raise typer.Exit(1)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    if json:
        print_json(updated)
        return
    console.print(
        f"[cp.green]extracted[/cp.green] {extracted_count} observable(s), "
        f"{evidence_count} evidence item(s) from [cp.cyan]{case_id}[/cp.cyan]"
    )


@app.command("observables")
def list_observables(
    case_id: Annotated[str, typer.Argument(help="Case ID")],
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """List observables stored on a case."""
    try:
        case = CaseStore().get(case_id)
    except CaseNotFoundError:
        print_error(f"Case not found: {case_id}")
        raise typer.Exit(1)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    if json:
        print_json([observable.model_dump(mode="json") for observable in case.observables])
        return

    if not case.observables:
        console.print("[cp.dim]No observables found.[/cp.dim]")
        return

    table = Table(
        title=f"[cp.cyan]Observables: {case.case_id}[/cp.cyan]",
        header_style="cp.magenta",
    )
    table.add_column("ID", style="cp.cyan", no_wrap=True)
    table.add_column("Type")
    table.add_column("Value")
    table.add_column("Confidence", justify="right")
    table.add_column("Evidence", justify="right")
    for observable in case.observables:
        table.add_row(
            observable.observable_id,
            observable.observable_type.value,
            observable.canonical_value or observable.value,
            f"{observable.confidence:.2f}",
            str(len(observable.evidence_ids)),
        )
    console.print(table)


@app.command("evidence")
def list_evidence(
    case_id: Annotated[str, typer.Argument(help="Case ID")],
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """List evidence records stored on a case."""
    try:
        case = CaseStore().get(case_id)
    except CaseNotFoundError:
        print_error(f"Case not found: {case_id}")
        raise typer.Exit(1)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    if json:
        print_json([evidence.model_dump(mode="json") for evidence in case.evidence])
        return

    if not case.evidence:
        console.print("[cp.dim]No evidence found.[/cp.dim]")
        return

    table = Table(title=f"[cp.cyan]Evidence: {case.case_id}[/cp.cyan]", header_style="cp.magenta")
    table.add_column("ID", style="cp.cyan", no_wrap=True)
    table.add_column("Status")
    table.add_column("Source")
    table.add_column("Summary")
    table.add_column("Observables", justify="right")
    for evidence in case.evidence:
        table.add_row(
            evidence.evidence_id,
            evidence.status.value,
            evidence.source_name or evidence.source_type,
            evidence.summary,
            str(len(evidence.observable_ids)),
        )
    console.print(table)


@app.command("delete")
def delete_case(
    case_id: Annotated[str, typer.Argument(help="Case ID")],
    confirm: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation")] = False,
) -> None:
    """Delete a stored case."""
    if not confirm:
        typer.confirm(f"Delete case {case_id}?", abort=True)
    try:
        deleted = CaseStore().delete(case_id)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)
    if not deleted:
        print_error(f"Case not found: {case_id}")
        raise typer.Exit(1)
    console.print(f"[cp.green]deleted[/cp.green] [cp.cyan]{case_id}[/cp.cyan]")


_VALID_ENRICH_SOURCES = frozenset({"abuseipdb", "shodan", "virustotal", "nvd"})


@app.command("enrich")
def enrich_case_observables(
    case_id: Annotated[str, typer.Argument(help="Case ID")],
    type_filter: Annotated[
        str | None,
        typer.Option("--type", "-t", help="Limit to a specific observable type"),
    ] = None,
    observable_id_filter: Annotated[
        str | None,
        typer.Option("--observable-id", "-o", help="Enrich a single observable"),
    ] = None,
    sources: Annotated[
        str | None,
        typer.Option(
            "--sources",
            "-s",
            help="Comma-separated list of sources to use (abuseipdb,shodan,virustotal,nvd)",
        ),
    ] = None,
    min_confidence: Annotated[
        float,
        typer.Option(
            "--min-confidence",
            help="Minimum confidence threshold (0.0–1.0) to store an evidence item",
        ),
    ] = 0.0,
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Enrich case observables via configured intelligence sources."""
    try:
        case = CaseStore().get(case_id)
    except CaseNotFoundError:
        print_error(f"Case not found: {case_id}")
        raise typer.Exit(1)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    observables = list(case.observables)
    if observable_id_filter:
        observables = [o for o in observables if o.observable_id == observable_id_filter]
        if not observables:
            print_error(f"Observable not found: {observable_id_filter}")
            raise typer.Exit(1)
    if type_filter:
        try:
            filter_type = ObservableType(type_filter)
        except ValueError:
            print_error(f"Unknown observable type: {type_filter!r}")
            raise typer.Exit(1)
        observables = [o for o in observables if o.observable_type == filter_type]

    if not observables:
        console.print("[cp.dim]No observables to enrich.[/cp.dim]")
        return

    allowed_sources: set[str] | None = None
    if sources:
        allowed_sources = {s.strip().lower() for s in sources.split(",")}
        invalid = allowed_sources - _VALID_ENRICH_SOURCES
        if invalid:
            print_error(
                f"Unknown source(s): {', '.join(sorted(invalid))}. "
                f"Valid: {', '.join(sorted(_VALID_ENRICH_SOURCES))}"
            )
            raise typer.Exit(1)

    existing_enrichments: set[tuple[str, str]] = {
        (ev.metadata.get("enrichment_source", ""), obs_id)
        for ev in case.evidence
        for obs_id in ev.observable_ids
        if ev.metadata.get("enrichment_source")
    }

    new_evidence = asyncio.run(
        _run_enrichment(observables, existing_enrichments, allowed_sources, min_confidence)
    )
    before = len(case.evidence)

    def mutate(c: Case) -> Case:
        return c.model_copy(update={"evidence": [*c.evidence, *new_evidence]})

    try:
        updated = CaseStore().update(case_id, mutate)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    added = updated.evidence[before:]
    failed = [ev for ev in added if ev.status == EvidenceStatus.FAILED]
    succeeded = [ev for ev in added if ev.status != EvidenceStatus.FAILED]

    if json:
        envelope = {
            "status": "ok" if not failed else ("partial" if succeeded else "failed"),
            "added": len(added),
            "succeeded": len(succeeded),
            "failed": len(failed),
            "failures": [
                {
                    "observable_id": (ev.observable_ids[0] if ev.observable_ids else ""),
                    "source": ev.source_name or ev.source_type,
                    "error": ev.summary,
                }
                for ev in failed
            ],
            "case": json_lib.loads(updated.model_dump_json()),
        }
        print_json(envelope)
        return
    console.print(
        f"[cp.green]enriched[/cp.green] {len(observables)} observable(s), "
        f"added {len(succeeded)} evidence item(s) "
        f"to [cp.cyan]{case_id}[/cp.cyan]"
    )
    if failed:
        console.print(
            f"[cp.amber]⚠ {len(failed)} collection failure(s):[/cp.amber]"
        )
        for ev in failed:
            src = ev.source_name or ev.source_type
            obs_id = ev.observable_ids[0] if ev.observable_ids else "unknown"
            console.print(f"  [cp.red]✗[/cp.red] {src} / {obs_id}: {ev.summary}")


def _source_allowed(source: str, allowed: set[str] | None) -> bool:
    return allowed is None or source in allowed


async def _run_enrichment(
    observables: list[Observable],
    existing_enrichments: set[tuple[str, str]],
    allowed_sources: set[str] | None = None,
    min_confidence: float = 0.0,
) -> list[EvidenceItem]:
    from argus.config.settings import get_settings

    settings = get_settings()
    vt_key = settings.api_key("virustotal")
    shodan_key = settings.api_key("shodan")
    abuseipdb_key = settings.api_key("abuseipdb")

    all_tasks: list[tuple[Observable, str, Any]] = []
    for obs in observables:
        value = obs.canonical_value or obs.value
        obs_type = obs.observable_type
        oid = obs.observable_id

        if obs_type == ObservableType.IP:
            if (
                abuseipdb_key
                and _source_allowed("abuseipdb", allowed_sources)
                and ("abuseipdb", oid) not in existing_enrichments
            ):
                from argus.tools.abuseipdb import abuseipdb_check
                all_tasks.append((obs, "abuseipdb", abuseipdb_check(value)))
            if (
                shodan_key
                and _source_allowed("shodan", allowed_sources)
                and ("shodan", oid) not in existing_enrichments
            ):
                from argus.tools.shodan import shodan_lookup
                all_tasks.append((obs, "shodan", shodan_lookup(ip=value)))
        elif obs_type == ObservableType.DOMAIN:
            if (
                vt_key
                and _source_allowed("virustotal", allowed_sources)
                and ("virustotal", oid) not in existing_enrichments
            ):
                from argus.tools.virustotal import virustotal_lookup
                all_tasks.append((obs, "virustotal", virustotal_lookup(value, "domain")))
        elif obs_type == ObservableType.URL:
            if (
                vt_key
                and _source_allowed("virustotal", allowed_sources)
                and ("virustotal", oid) not in existing_enrichments
            ):
                from argus.tools.virustotal import virustotal_lookup
                all_tasks.append((obs, "virustotal", virustotal_lookup(value, "url")))
        elif obs_type in {ObservableType.MD5, ObservableType.SHA1, ObservableType.SHA256}:
            if (
                vt_key
                and _source_allowed("virustotal", allowed_sources)
                and ("virustotal", oid) not in existing_enrichments
            ):
                from argus.tools.virustotal import virustotal_lookup
                all_tasks.append((obs, "virustotal", virustotal_lookup(value, obs_type.value)))
        elif obs_type == ObservableType.CVE:
            if (
                _source_allowed("nvd", allowed_sources)
                and ("nvd", oid) not in existing_enrichments
            ):
                from argus.tools.nvd import nvd_cve_lookup
                all_tasks.append((obs, "nvd", nvd_cve_lookup(cve_id=value.upper())))

    if not all_tasks:
        return []

    obs_list, sources, coros = zip(*all_tasks)
    results = await asyncio.gather(*coros, return_exceptions=True)

    evidence_items = []
    for obs, source, result in zip(obs_list, sources, results):
        if isinstance(result, Exception):
            evidence_items.append(_error_evidence(obs, source, str(result)))
        else:
            ev = _parse_enrichment_evidence(obs, source, str(result))
            if ev.confidence >= min_confidence:
                evidence_items.append(ev)
    return evidence_items


def _error_evidence(obs: Observable, source: str, error: str) -> EvidenceItem:
    value = obs.canonical_value or obs.value
    return EvidenceItem(
        source_name=source,
        source_type="enrichment",
        status=EvidenceStatus.FAILED,
        confidence=0.0,
        summary=f"{source}: error enriching {obs.observable_type.value} {value}: {error}",
        raw_excerpt=error[:2000],
        observable_ids=[obs.observable_id],
        metadata={
            "enrichment_source": source,
            "observable_type": obs.observable_type.value,
            "canonical_value": obs.canonical_value or obs.value,
        },
    )


def _parse_enrichment_evidence(obs: Observable, source: str, raw_json: str) -> EvidenceItem:
    try:
        data: dict[str, Any] = json_lib.loads(raw_json)
    except Exception:
        data = {}

    has_error = "error" in data
    summary, confidence = _summarize_enrichment(source, data, obs)
    status = EvidenceStatus.FAILED if has_error else EvidenceStatus.CONFIRMED

    return EvidenceItem(
        source_name=source,
        source_type="enrichment",
        status=status,
        confidence=confidence,
        summary=summary,
        raw_excerpt=raw_json[:2000],
        observable_ids=[obs.observable_id],
        metadata={
            "enrichment_source": source,
            "observable_type": obs.observable_type.value,
            "canonical_value": obs.canonical_value or obs.value,
        },
    )


def _summarize_enrichment(
    source: str, data: dict[str, Any], obs: Observable
) -> tuple[str, float]:
    value = obs.canonical_value or obs.value

    if "error" in data:
        return f"{source}: error for {value}: {data['error']}", 0.0

    if source == "abuseipdb":
        score = data.get("abuse_confidence_score", 0)
        reports = data.get("total_reports", 0)
        country = data.get("country_code", "")
        summary = f"AbuseIPDB: score={score}/100, {reports} report(s)"
        if country:
            summary += f", country={country}"
        return summary, score / 100.0

    if source == "virustotal":
        malicious = data.get("malicious", 0)
        total = data.get("total_engines", 1) or 1
        ratio = data.get("detection_ratio", f"{malicious}/{total}")
        label = data.get("popular_threat_label", "")
        summary = f"VirusTotal: {ratio} detections"
        if label:
            summary += f", label={label}"
        return summary, min(malicious / total, 1.0)

    if source == "shodan":
        ports = data.get("ports", [])
        org = data.get("org", "")
        vulns = data.get("vulns", [])
        summary = f"Shodan: {len(ports)} open port(s)"
        if org:
            summary += f", org={org}"
        if vulns:
            summary += f", {len(vulns)} vuln(s)"
        return summary, 0.9

    if source == "nvd":
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return f"NVD: no record for {value}", 0.3
        vuln = vulns[0]
        score = vuln.get("cvss_v3_score", "N/A")
        severity = vuln.get("severity", "unknown")
        in_kev = vuln.get("in_cisa_kev", False)
        summary = f"NVD: CVSS {score} ({severity})"
        if in_kev:
            summary += ", IN CISA KEV"
        return summary, 0.95 if score != "N/A" else 0.7

    return f"{source}: enrichment retrieved for {value}", 0.5


_VALID_PIVOT_SOURCES = frozenset({"passive_dns", "ssl_cert", "whois"})


@app.command("pivot")
def pivot_case_observables(
    case_id: Annotated[str, typer.Argument(help="Case ID")],
    type_filter: Annotated[
        str | None,
        typer.Option("--type", "-t", help="Limit to ip or domain observables"),
    ] = None,
    observable_id_filter: Annotated[
        str | None,
        typer.Option("--observable-id", "-o", help="Pivot a single observable"),
    ] = None,
    no_certs: Annotated[bool, typer.Option("--no-certs", help="Skip cert lookups")] = False,
    no_whois: Annotated[bool, typer.Option("--no-whois", help="Skip WHOIS lookups")] = False,
    sources: Annotated[
        str | None,
        typer.Option(
            "--sources",
            help="Comma-separated pivot sources to run: passive_dns,ssl_cert,whois",
        ),
    ] = None,
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Pivot case observables via passive DNS, certificates, and WHOIS."""
    allowed_pivot_sources: set[str] | None = None
    if sources is not None:
        allowed_pivot_sources = {s.strip().lower() for s in sources.split(",") if s.strip()}
        invalid = allowed_pivot_sources - _VALID_PIVOT_SOURCES
        if invalid:
            print_error(
                f"Unknown pivot source(s): {', '.join(sorted(invalid))}. "
                f"Valid: {', '.join(sorted(_VALID_PIVOT_SOURCES))}"
            )
            raise typer.Exit(1)
    if no_certs:
        allowed_pivot_sources = set(allowed_pivot_sources or _VALID_PIVOT_SOURCES) - {"ssl_cert"}
    if no_whois:
        allowed_pivot_sources = set(allowed_pivot_sources or _VALID_PIVOT_SOURCES) - {"whois"}

    try:
        case = CaseStore().get(case_id)
    except CaseNotFoundError:
        print_error(f"Case not found: {case_id}")
        raise typer.Exit(1)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    pivot_types = {ObservableType.IP, ObservableType.DOMAIN}
    observables = [o for o in case.observables if o.observable_type in pivot_types]
    if observable_id_filter:
        observables = [o for o in observables if o.observable_id == observable_id_filter]
        if not observables:
            print_error(f"Observable not found: {observable_id_filter}")
            raise typer.Exit(1)
    if type_filter:
        try:
            filter_type = ObservableType(type_filter)
        except ValueError:
            print_error(f"Unknown observable type: {type_filter!r}")
            raise typer.Exit(1)
        observables = [o for o in observables if o.observable_type == filter_type]

    if not observables:
        console.print("[cp.dim]No pivotable observables (IP or domain) found.[/cp.dim]")
        return

    existing_pivots: set[tuple[str, str]] = {
        (ev.metadata.get("pivot_source", ""), ev.metadata.get("source_observable_id", ""))
        for ev in case.evidence
        if ev.metadata.get("pivot_source")
    }
    existing_index: dict[tuple[ObservableType, str], Observable] = {
        (o.observable_type, o.canonical_value or o.value): o
        for o in case.observables
    }

    new_obs, new_evidence, new_rels = asyncio.run(
        _run_pivots(
            observables,
            existing_pivots,
            existing_index,
            allowed_sources=allowed_pivot_sources,
        )
    )

    before_obs = len(case.observables)
    before_ev = len(case.evidence)
    before_rel = len(case.relationships)

    def mutate(c: Case) -> Case:
        return c.model_copy(
            update={
                "observables": [*c.observables, *new_obs],
                "evidence": [*c.evidence, *new_evidence],
                "relationships": [*c.relationships, *new_rels],
            }
        )

    try:
        updated = CaseStore().update(case_id, mutate)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    added_ev = updated.evidence[before_ev:]
    failed_ev = [ev for ev in added_ev if ev.status == EvidenceStatus.FAILED]
    succeeded_ev = [ev for ev in added_ev if ev.status != EvidenceStatus.FAILED]

    if json:
        envelope = {
            "status": "ok" if not failed_ev else ("partial" if succeeded_ev else "failed"),
            "new_observables": len(updated.observables) - before_obs,
            "new_evidence": len(succeeded_ev),
            "new_relationships": len(updated.relationships) - before_rel,
            "failed": len(failed_ev),
            "failures": [
                {
                    "observable_id": (ev.observable_ids[0] if ev.observable_ids else ""),
                    "source": ev.source_name or ev.source_type,
                    "error": ev.summary,
                }
                for ev in failed_ev
            ],
            "case": json_lib.loads(updated.model_dump_json()),
        }
        print_json(envelope)
        return
    console.print(
        f"[cp.green]pivoted[/cp.green] {len(observables)} observable(s): "
        f"+{len(updated.observables) - before_obs} observable(s), "
        f"+{len(succeeded_ev)} evidence item(s), "
        f"+{len(updated.relationships) - before_rel} relationship(s) "
        f"added to [cp.cyan]{case_id}[/cp.cyan]"
    )
    if failed_ev:
        console.print(
            f"[cp.amber]⚠ {len(failed_ev)} collection failure(s):[/cp.amber]"
        )
        for ev in failed_ev:
            src = ev.source_name or ev.source_type
            obs_id = ev.observable_ids[0] if ev.observable_ids else "unknown"
            console.print(f"  [cp.red]✗[/cp.red] {src} / {obs_id}: {ev.summary}")


def _pivot_source_allowed(source: str, allowed: set[str] | None) -> bool:
    return allowed is None or source in allowed


async def _run_pivots(
    observables: list[Observable],
    existing_pivots: set[tuple[str, str]],
    existing_index: dict[tuple[ObservableType, str], Observable],
    allowed_sources: set[str] | None = None,
) -> tuple[list[Observable], list[EvidenceItem], list[Relationship]]:
    from argus.config.settings import get_settings

    vt_key = get_settings().api_key("virustotal")

    all_tasks: list[tuple[Observable, str, Any]] = []

    for obs in observables:
        value = obs.canonical_value or obs.value
        oid = obs.observable_id
        obs_type = obs.observable_type
        itype = "ip" if obs_type == ObservableType.IP else "domain"

        if (
            vt_key
            and _pivot_source_allowed("passive_dns", allowed_sources)
            and ("passive_dns", oid) not in existing_pivots
        ):
            from argus.tools.passive_dns import passive_dns_lookup
            all_tasks.append((obs, "passive_dns", passive_dns_lookup(value, itype)))

        if obs_type == ObservableType.DOMAIN:
            if (
                _pivot_source_allowed("ssl_cert", allowed_sources)
                and ("ssl_cert", oid) not in existing_pivots
            ):
                from argus.tools.certs import ssl_cert_lookup
                all_tasks.append((obs, "ssl_cert", ssl_cert_lookup(value, "domain")))
            if (
                _pivot_source_allowed("whois", allowed_sources)
                and ("whois", oid) not in existing_pivots
            ):
                from argus.tools.whois import whois_lookup
                all_tasks.append((obs, "whois", whois_lookup(value)))

    if not all_tasks:
        return [], [], []

    obs_list, sources, coros = zip(*all_tasks)
    results = await asyncio.gather(*coros, return_exceptions=True)

    new_observables: list[Observable] = []
    new_evidence: list[EvidenceItem] = []
    new_relationships: list[Relationship] = []

    for obs, source, result in zip(obs_list, sources, results):
        if isinstance(result, Exception):
            new_evidence.append(_pivot_error_evidence(obs, source, str(result)))
        else:
            disc_obs, ev_items, rels = _parse_pivot_result(
                obs, source, str(result), existing_index
            )
            new_observables.extend(disc_obs)
            new_evidence.extend(ev_items)
            new_relationships.extend(rels)

    return new_observables, new_evidence, new_relationships


def _pivot_error_evidence(obs: Observable, source: str, error: str) -> EvidenceItem:
    value = obs.canonical_value or obs.value
    return EvidenceItem(
        source_name=source,
        source_type="pivot",
        status=EvidenceStatus.FAILED,
        confidence=0.0,
        summary=f"{source}: pivot error for {obs.observable_type.value} {value}: {error}",
        raw_excerpt=error[:2000],
        observable_ids=[obs.observable_id],
        metadata={
            "pivot_source": source,
            "source_observable_id": obs.observable_id,
            "source_observable_type": obs.observable_type.value,
        },
    )


def _parse_pivot_result(
    source_obs: Observable,
    source: str,
    raw_json: str,
    existing_index: dict[tuple[ObservableType, str], Observable],
) -> tuple[list[Observable], list[EvidenceItem], list[Relationship]]:
    try:
        data: dict[str, Any] = json_lib.loads(raw_json)
    except Exception:
        data = {}

    source_value = source_obs.canonical_value or source_obs.value
    source_obs_type = source_obs.observable_type
    new_obs: list[Observable] = []
    evidence_items: list[EvidenceItem] = []
    rels: list[Relationship] = []

    if source == "passive_dns":
        resolutions = data.get("resolutions", [])
        resolution_count = data.get("resolution_count", len(resolutions))
        all_obs_ids = [source_obs.observable_id]

        for res in resolutions[:20]:
            if source_obs_type == ObservableType.IP:
                discovered_value = res.get("hostname", "").lower()
                disc_type = ObservableType.DOMAIN
                rel_type = RelationshipType.RESOLVES_TO
                rel_source = discovered_value
                rel_target = source_value
            else:
                discovered_value = res.get("ip_address", "")
                disc_type = ObservableType.IP
                rel_type = RelationshipType.RESOLVES_TO
                rel_source = source_value
                rel_target = discovered_value

            if not discovered_value:
                continue

            key = (disc_type, discovered_value)
            if key not in existing_index:
                disc_obs = Observable(
                    value=discovered_value,
                    observable_type=disc_type,
                    canonical_value=discovered_value,
                    confidence=0.8,
                    evidence_ids=[],
                    labels=["pivot-discovered"],
                )
                existing_index[key] = disc_obs
                new_obs.append(disc_obs)
            else:
                disc_obs = existing_index[key]

            all_obs_ids.append(disc_obs.observable_id)
            rels.append(
                Relationship(
                    relationship_type=rel_type,
                    source_ref=rel_source,
                    target_ref=rel_target,
                    confidence=0.8,
                    evidence_ids=[],
                    rationale=f"Passive DNS resolution from {source}",
                )
            )

        obs_label = f"{source_obs_type.value} {source_value}"
        summary = f"Passive DNS: {resolution_count} resolution(s) for {obs_label}"
        if "error" in data:
            summary = f"Passive DNS error for {source_value}: {data['error']}"
        evidence_items.append(
            EvidenceItem(
                source_name=source,
                source_type="pivot",
                status=EvidenceStatus.FAILED if "error" in data else EvidenceStatus.CONFIRMED,
                confidence=0.8 if "error" not in data else 0.0,
                summary=summary,
                raw_excerpt=raw_json[:2000],
                observable_ids=all_obs_ids,
                metadata={
                    "pivot_source": source,
                    "source_observable_id": source_obs.observable_id,
                    "source_observable_type": source_obs_type.value,
                    "discovered_count": len(new_obs),
                },
            )
        )

        ev_id = evidence_items[-1].evidence_id
        for rel in rels:
            rel.evidence_ids.append(ev_id)

    elif source == "ssl_cert":
        all_sans: list[str] = data.get("all_sans", [])
        cert_count = data.get("cert_count", 0)
        all_obs_ids = [source_obs.observable_id]

        for san in all_sans[:20]:
            san = san.lower().lstrip("*.")
            if not san or san == source_value:
                continue
            key = (ObservableType.DOMAIN, san)
            if key not in existing_index:
                disc_obs = Observable(
                    value=san,
                    observable_type=ObservableType.DOMAIN,
                    canonical_value=san,
                    confidence=0.7,
                    labels=["cert-san"],
                )
                existing_index[key] = disc_obs
                new_obs.append(disc_obs)
            else:
                disc_obs = existing_index[key]
            all_obs_ids.append(disc_obs.observable_id)
            rels.append(
                Relationship(
                    relationship_type=RelationshipType.RELATED_TO,
                    source_ref=source_value,
                    target_ref=san,
                    confidence=0.7,
                    evidence_ids=[],
                    rationale="Shared TLS certificate SAN from crt.sh",
                )
            )

        evidence_items.append(
            EvidenceItem(
                source_name=source,
                source_type="pivot",
                status=EvidenceStatus.CONFIRMED,
                confidence=0.7,
                summary=f"SSL/TLS: {cert_count} cert(s) for {source_value}, {len(all_sans)} SAN(s)",
                raw_excerpt=raw_json[:2000],
                observable_ids=all_obs_ids,
                metadata={
                    "pivot_source": source,
                    "source_observable_id": source_obs.observable_id,
                    "source_observable_type": source_obs_type.value,
                },
            )
        )
        ev_id = evidence_items[-1].evidence_id
        for rel in rels:
            rel.evidence_ids.append(ev_id)

    elif source == "whois":
        registrar = data.get("registrar", "")
        creation = data.get("creation_date", "")
        nameservers = data.get("nameservers", [])
        registrant_org = data.get("registrant_org", "")
        parts = []
        if registrar:
            parts.append(f"registrar={registrar}")
        if creation:
            parts.append(f"created={creation[:10]}")
        if registrant_org:
            parts.append(f"org={registrant_org}")
        if nameservers:
            parts.append(f"ns={','.join(nameservers[:2])}")
        summary = f"WHOIS: {source_value}" + (f" — {', '.join(parts)}" if parts else "")
        if "rdap_error" in data and not parts:
            summary = f"WHOIS: lookup failed for {source_value}: {data['rdap_error']}"
        evidence_items.append(
            EvidenceItem(
                source_name=source,
                source_type="pivot",
                status=(
                    EvidenceStatus.FAILED
                    if ("rdap_error" in data and not parts)
                    else EvidenceStatus.CONFIRMED
                ),
                confidence=0.9 if parts else 0.0,
                summary=summary,
                raw_excerpt=raw_json[:2000],
                observable_ids=[source_obs.observable_id],
                metadata={
                    "pivot_source": source,
                    "source_observable_id": source_obs.observable_id,
                    "source_observable_type": source_obs_type.value,
                },
            )
        )

    return new_obs, evidence_items, rels


@app.command("report")
def generate_case_report(
    case_id: Annotated[str, typer.Argument(help="Case ID")],
    report_type: Annotated[str, typer.Option("--type", "-t")] = "cti",
    title: Annotated[str, typer.Option("--title")] = "",
    classification: Annotated[str, typer.Option("--classification", "-c")] = "TLP:AMBER",
    save: Annotated[bool, typer.Option("--save/--no-save", help="Attach report to case")] = True,
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Generate an evidence-backed CTI report from a case."""
    try:
        case = CaseStore().get(case_id)
    except CaseNotFoundError:
        print_error(f"Case not found: {case_id}")
        raise typer.Exit(1)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    report_title = title or f"{case.title} — {report_type.upper()} Report"
    content = _render_case_report(case, report_type, report_title, classification)
    evidence_ids = [ev.evidence_id for ev in case.evidence]

    report_artifact = ReportArtifact(
        report_type=report_type,
        title=report_title,
        classification=classification,
        evidence_ids=evidence_ids,
        content=content,
    )

    if save:
        def mutate(c: Case) -> Case:
            return c.model_copy(update={"reports": [*c.reports, report_artifact]})

        try:
            CaseStore().update(case_id, mutate)
        except CaseStoreError as exc:
            print_error(str(exc))
            raise typer.Exit(1)

    if json:
        print_json(report_artifact)
        return

    from argus.cli.output import render_markdown
    render_markdown(content)


def _render_case_report(
    case: Case, report_type: str, title: str, classification: str
) -> str:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []

    lines.append(f"# {title}")
    lines.append(f"\n**Classification:** {classification}  ")
    lines.append(f"**Generated:** {now}  ")
    lines.append(f"**Case:** {case.case_id}  ")
    lines.append(f"**Status:** {case.status.value}\n")

    if case.description:
        lines.append(f"## Summary\n\n{case.description}\n")

    if case.pirs:
        lines.append("## Priority Intelligence Requirements\n")
        for pir in case.pirs:
            status_tag = f"[{pir.status.value}]"
            lines.append(f"- **{status_tag}** {pir.question}")
            if pir.answer:
                lines.append(f"  - *Answer:* {pir.answer}")
        lines.append("")

    if case.observables:
        lines.append("## Observables\n")
        by_type: dict[str, list[Observable]] = {}
        for obs in case.observables:
            by_type.setdefault(obs.observable_type.value, []).append(obs)
        for obs_type, obs_list in sorted(by_type.items()):
            lines.append(f"### {obs_type.upper()}\n")
            for obs in obs_list:
                value = obs.canonical_value or obs.value
                conf = f" (confidence: {obs.confidence:.0%})" if obs.confidence else ""
                lines.append(f"- `{value}`{conf}")
            lines.append("")

    confirmed = [ev for ev in case.evidence if ev.status == EvidenceStatus.CONFIRMED]
    failed = [ev for ev in case.evidence if ev.status == EvidenceStatus.FAILED]
    inferred = [ev for ev in case.evidence if ev.status == EvidenceStatus.INFERRED]

    if case.evidence:
        lines.append(f"## Evidence ({len(case.evidence)} items)\n")
        lines.append(
            f"- Confirmed: {len(confirmed)}  "
            f"Inferred: {len(inferred)}  "
            f"Failed: {len(failed)}\n"
        )
        for ev in case.evidence:
            if ev.status == EvidenceStatus.FAILED:
                continue
            source = ev.source_name or ev.source_type
            status_label = f"[{ev.status.value}]" if ev.status != EvidenceStatus.CONFIRMED else ""
            conf_label = f" ({ev.confidence:.0%})" if ev.confidence else ""
            lines.append(
                f"- **[{ev.evidence_id}]** {status_label} "
                f"_{source}_{conf_label}: {ev.summary}"
            )
        if failed:
            lines.append(f"\n### Collection Failures ({len(failed)})\n")
            for ev in failed:
                source = ev.source_name or ev.source_type
                lines.append(f"- _{source}_: {ev.summary}")
        lines.append("")

    if case.relationships:
        lines.append(f"## Relationships ({len(case.relationships)})\n")
        for rel in case.relationships:
            lines.append(
                f"- `{rel.source_ref}` —[{rel.relationship_type.value}]→ `{rel.target_ref}`"
            )
            if rel.rationale:
                lines.append(f"  - {rel.rationale}")
        lines.append("")

    if case.notes:
        lines.append("## Analyst Notes\n")
        for note in case.notes:
            ts = note.created_at.strftime("%Y-%m-%d")
            lines.append(f"- **{note.author}** ({ts}): {note.body}")
        lines.append("")

    source_coverage = {ev.source_name for ev in case.evidence if ev.source_name}
    if source_coverage:
        lines.append("## Source Coverage\n")
        for src in sorted(source_coverage):
            src_evidence = [ev for ev in case.evidence if ev.source_name == src]
            success = sum(1 for ev in src_evidence if ev.status != EvidenceStatus.FAILED)
            lines.append(f"- **{src}**: {success}/{len(src_evidence)} items confirmed")
        lines.append("")

    return "\n".join(lines)


@app.command("status")
def update_case_status(
    case_id: Annotated[str, typer.Argument(help="Case ID")],
    new_status: Annotated[str, typer.Argument(help="New status: open, active, monitoring, closed")],
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Transition a case to a new status."""
    from argus.models.case import CaseStatus

    try:
        status_val = CaseStatus(new_status)
    except ValueError:
        valid = ", ".join(s.value for s in CaseStatus)
        print_error(f"Invalid status {new_status!r}. Valid: {valid}")
        raise typer.Exit(1)

    def mutate(c: Case) -> Case:
        updates: dict[str, Any] = {"status": status_val}
        if status_val == CaseStatus.CLOSED:
            updates["closed_at"] = datetime.now(UTC)
        return c.model_copy(update=updates)

    try:
        updated = CaseStore().update(case_id, mutate)
    except CaseNotFoundError:
        print_error(f"Case not found: {case_id}")
        raise typer.Exit(1)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    if json:
        print_json(updated)
        return
    console.print(
        f"[cp.green]status[/cp.green] [cp.cyan]{case_id}[/cp.cyan]"
        f" → [cp.cyan]{new_status}[/cp.cyan]"
    )


@app.command("timeline")
def show_case_timeline(
    case_id: Annotated[str, typer.Argument(help="Case ID")],
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Show a chronological timeline of case evidence and activity."""
    try:
        case = CaseStore().get(case_id)
    except CaseNotFoundError:
        print_error(f"Case not found: {case_id}")
        raise typer.Exit(1)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    events: list[dict[str, Any]] = []

    events.append({
        "ts": case.created_at.isoformat(),
        "type": "case_opened",
        "summary": f"Case opened: {case.title}",
    })
    for artifact in case.artifacts:
        art_label = artifact.title or artifact.artifact_id
        events.append({
            "ts": artifact.received_at.isoformat(),
            "type": "artifact",
            "summary": f"Artifact added: {art_label} ({artifact.artifact_type.value})",
        })
    for evidence in case.evidence:
        ev_src = evidence.source_name or evidence.source_type
        events.append({
            "ts": evidence.collected_at.isoformat(),
            "type": f"evidence_{evidence.status.value}",
            "summary": f"[{evidence.status.value}] {ev_src}: {evidence.summary}",
            "evidence_id": evidence.evidence_id,
        })
    for note in case.notes:
        events.append({
            "ts": note.created_at.isoformat(),
            "type": "note",
            "summary": f"Note ({note.author}): {note.body[:80]}",
        })
    for pir in case.pirs:
        events.append({
            "ts": pir.created_at.isoformat(),
            "type": "pir_added",
            "summary": f"PIR added: {pir.question[:80]}",
        })
        if pir.answered_at:
            events.append({
                "ts": pir.answered_at.isoformat(),
                "type": "pir_answered",
                "summary": f"PIR answered: {pir.question[:60]}",
            })
    for report in case.reports:
        events.append({
            "ts": report.generated_at.isoformat(),
            "type": "report",
            "summary": f"Report generated: {report.title} ({report.report_type})",
        })

    events.sort(key=lambda e: e["ts"])

    if json:
        print_json(events)
        return

    if not events:
        console.print("[cp.dim]No timeline events.[/cp.dim]")
        return

    table = Table(
        title=f"[cp.cyan]Timeline: {case.case_id}[/cp.cyan]",
        header_style="cp.magenta",
    )
    table.add_column("Time", no_wrap=True, style="cp.dim")
    table.add_column("Type")
    table.add_column("Summary")
    for event in events:
        ts = event["ts"][:16].replace("T", " ")
        event_type = event["type"]
        color = {
            "case_opened": "cp.green",
            "artifact": "cp.cyan",
            "note": "cp.amber",
            "pir_added": "cp.magenta",
            "pir_answered": "cp.green",
            "report": "cp.cyan",
        }.get(event_type, "")
        styled_type = f"[{color}]{event_type}[/{color}]" if color else event_type
        table.add_row(ts, styled_type, event["summary"])
    console.print(table)


@app.command("analyze")
def analyze_case(
    case_id: Annotated[str, typer.Argument(help="Case ID")],
    audience: Annotated[
        str,
        typer.Option(
            "--audience",
            "-a",
            help="Target audience: cti, soc, vm, ir, exec, awareness, redteam",
        ),
    ] = "cti",
    save: Annotated[bool, typer.Option("--save/--no-save", help="Attach report to case")] = True,
    review: Annotated[
        bool,
        typer.Option("--review/--no-review", help="Run ReviewAgent to check grounding"),
    ] = False,
    json: Annotated[
        bool, typer.Option("--json", "-j", help="Output report artifact as JSON")
    ] = False,
) -> None:
    """Generate an LLM-synthesized audience-specific intelligence product from a case."""
    from argus.agents.case_report_agent import CaseReportAgent
    from argus.cli.output import render_markdown, status, thinking

    valid_audiences = CaseReportAgent.AUDIENCES
    if audience not in valid_audiences:
        print_error(f"Unknown audience {audience!r}. Valid: {', '.join(valid_audiences)}")
        raise typer.Exit(1)

    try:
        case = CaseStore().get(case_id)
    except CaseNotFoundError:
        print_error(f"Case not found: {case_id}")
        raise typer.Exit(1)
    except CaseStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    if not case.evidence:
        print_error("No evidence in case — run 'case extract' and 'case enrich' first")
        raise typer.Exit(1)

    try:
        with thinking(f"synthesizing {audience} report for {case.title}"):
            agent = CaseReportAgent(audience=audience, progress=status)
            content = asyncio.run(agent.generate(case))
    except Exception as exc:
        from argus.cli.output import print_agent_error
        print_agent_error(exc)
        raise typer.Exit(1)

    review_metadata: dict[str, Any] = {}
    if review:
        from argus.agents.review_agent import ReviewAgent
        try:
            with thinking("reviewing report grounding"):
                review_result = asyncio.run(
                    ReviewAgent(progress=status).review(content, case)
                )
            review_metadata = {
                "review_passed": review_result.passed,
                "grounded_claim_count": review_result.grounded_claim_count,
                "inferred_claim_count": review_result.inferred_claim_count,
                "ungrounded_claim_count": review_result.ungrounded_claim_count,
                "review_summary": review_result.summary,
                "findings": [
                    {
                        "claim": f.claim,
                        "issue": f.issue,
                        "severity": f.severity,
                        "evidence_id": f.evidence_id,
                    }
                    for f in review_result.findings
                ],
            }
            if review_result.passed:
                console.print(
                    f"[cp.green]✓ review passed[/cp.green] — "
                    f"{review_result.grounded_claim_count} grounded, "
                    f"{review_result.inferred_claim_count} inferred"
                )
            else:
                console.print(
                    f"[cp.amber]⚠ review flagged {review_result.ungrounded_claim_count} "
                    f"unsupported claim(s)[/cp.amber]"
                )
                for finding in review_result.findings:
                    sev_color = "cp.red" if finding.severity == "error" else "cp.amber"
                    console.print(
                        f"  [{sev_color}]{finding.severity}[/{sev_color}]"
                        f" {finding.claim[:80]}"
                    )
                    console.print(f"    {finding.issue}")
        except Exception as exc:
            from argus.cli.output import print_agent_error
            print_agent_error(exc)

    report_artifact = ReportArtifact(
        report_type=audience,
        title=f"{case.title} — {audience.upper()} Report",
        classification=case.classification,
        evidence_ids=[ev.evidence_id for ev in case.evidence],
        content=content,
        metadata=review_metadata,
    )

    if save:
        def mutate(c: Case) -> Case:
            return c.model_copy(update={"reports": [*c.reports, report_artifact]})

        try:
            CaseStore().update(case_id, mutate)
        except CaseStoreError as exc:
            print_error(str(exc))
            raise typer.Exit(1)

    if json:
        print_json(report_artifact)
        return

    render_markdown(content)


@app.command("path")
def case_path() -> None:
    """Print the active case storage directory."""
    console.print(str(Path(CaseStore().cases_dir)))
