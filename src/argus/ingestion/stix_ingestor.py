"""STIX 2.x bundle ingestor — extracts observables, evidence, and relationships.

Accepts a parsed STIX bundle dict and returns structured case data without
making any external API calls.  Intended to run inside `case extract` when
the artifact content is detected as a STIX bundle.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from argus.models.evidence import (
    EvidenceItem,
    EvidenceStatus,
    Observable,
    ObservableType,
    Relationship,
    RelationshipType,
)

# ---------------------------------------------------------------------------
# STIX indicator pattern → observable extraction
# ---------------------------------------------------------------------------

_PATTERN_RULES: list[tuple[re.Pattern[str], ObservableType]] = [
    (re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'"), ObservableType.IP),
    (re.compile(r"ipv6-addr:value\s*=\s*'([^']+)'"), ObservableType.IP),
    (re.compile(r"domain-name:value\s*=\s*'([^']+)'"), ObservableType.DOMAIN),
    (re.compile(r"url:value\s*=\s*'([^']+)'"), ObservableType.URL),
    (re.compile(r"file:hashes\.MD5\s*=\s*'([^']+)'"), ObservableType.MD5),
    (re.compile(r"file:hashes\.'SHA-1'\s*=\s*'([^']+)'"), ObservableType.SHA1),
    (re.compile(r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'"), ObservableType.SHA256),
    (re.compile(r"email-addr:value\s*=\s*'([^']+)'"), ObservableType.EMAIL),
]

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

_STIX_TO_REL: dict[str, RelationshipType] = {
    "resolves-to": RelationshipType.RESOLVES_TO,
    "indicates": RelationshipType.INDICATES,
    "attributed-to": RelationshipType.ATTRIBUTED_TO,
    "uses": RelationshipType.USES,
    "exploits": RelationshipType.EXPLOITS,
    "targets": RelationshipType.TARGETS,
    "observed-in": RelationshipType.OBSERVED_IN,
    "hosts": RelationshipType.HOSTS,
}


def _parse_indicator_pattern(pattern: str) -> list[Observable]:
    """Extract observables from a STIX indicator pattern string."""
    results = []
    for rx, obs_type in _PATTERN_RULES:
        for match in rx.finditer(pattern):
            value = match.group(1).strip()
            if value:
                results.append(Observable(value=value, observable_type=obs_type))
    return results


def _mitre_ttps_from_refs(refs: list[dict[str, Any]]) -> list[Observable]:
    """Extract ATT&CK technique IDs from external_references."""
    out = []
    for ref in refs:
        if ref.get("source_name") == "mitre-attack":
            eid = ref.get("external_id", "")
            if re.match(r"T\d{4}(\.\d{3})?", eid, re.IGNORECASE):
                out.append(Observable(
                    value=eid.upper(),
                    observable_type=ObservableType.ATTACK_TTP,
                ))
    return out


@dataclass
class StixIngestResult:
    observables: list[Observable] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    skipped: int = 0


def ingest_stix_bundle(bundle: dict[str, Any]) -> StixIngestResult:
    """Parse a STIX 2.x bundle dict and return structured case data."""
    result = StixIngestResult()

    if bundle.get("type") != "bundle":
        return result

    objects = bundle.get("objects", [])
    if not isinstance(objects, list):
        return result

    # Build an ID→Observable index so relationship objects can link by STIX ID
    stix_id_to_observable: dict[str, Observable] = {}
    stix_id_to_evidence: dict[str, EvidenceItem] = {}

    seen_obs: set[tuple[ObservableType, str]] = set()

    def _add_obs(obs: Observable) -> Observable | None:
        key = (obs.observable_type, obs.canonical_value or obs.value)
        if key in seen_obs:
            return None
        seen_obs.add(key)
        result.observables.append(obs)
        return obs

    def _add_ev(ev: EvidenceItem) -> None:
        result.evidence.append(ev)

    for obj in objects:
        obj_type = obj.get("type", "")
        stix_id = obj.get("id", "")
        name = obj.get("name", "")
        desc = obj.get("description", "")
        refs = obj.get("external_references", [])
        labels = obj.get("labels", [])
        confidence = obj.get("confidence", 50)
        confidence_f = min(1.0, max(0.0, confidence / 100)) if isinstance(confidence, int) else 0.5

        if obj_type == "indicator":
            pattern = obj.get("pattern", "")
            obs_list = _parse_indicator_pattern(pattern)
            for obs in obs_list:
                added = _add_obs(obs)
                if added and stix_id:
                    stix_id_to_observable[stix_id] = added
            if obs_list:
                summary_parts = [f"STIX indicator: {name or pattern[:60]}"]
                if labels:
                    summary_parts.append(f"labels={','.join(labels)}")
                if desc:
                    summary_parts.append(desc[:120])
                ev = EvidenceItem(
                    source_name="stix_import",
                    source_type="stix_import",
                    status=EvidenceStatus.CONFIRMED,
                    confidence=confidence_f,
                    summary="; ".join(summary_parts),
                    observable_ids=[o.observable_id for o in obs_list],
                )
                _add_ev(ev)
                if stix_id:
                    stix_id_to_evidence[stix_id] = ev

        elif obj_type == "threat-actor":
            aliases = obj.get("aliases", [])
            sophistication = obj.get("sophistication", "")
            goals = obj.get("goals", [])
            parts = [f"Threat actor: {name}"]
            if aliases:
                parts.append(f"aliases: {', '.join(aliases[:5])}")
            if sophistication:
                parts.append(f"sophistication: {sophistication}")
            if goals:
                parts.append(f"goals: {', '.join(goals[:3])}")
            if desc:
                parts.append(desc[:200])
            ev = EvidenceItem(
                source_name="stix_import",
                source_type="stix_import",
                status=EvidenceStatus.CONFIRMED,
                confidence=confidence_f,
                summary="; ".join(parts),
                metadata={"stix_type": "threat-actor", "stix_id": stix_id, "name": name},
            )
            _add_ev(ev)
            if stix_id:
                stix_id_to_evidence[stix_id] = ev

        elif obj_type == "malware":
            families = obj.get("malware_types", obj.get("labels", []))
            parts = [f"Malware: {name}"]
            if families:
                parts.append(f"types: {', '.join(families[:3])}")
            if desc:
                parts.append(desc[:200])
            ev = EvidenceItem(
                source_name="stix_import",
                source_type="stix_import",
                status=EvidenceStatus.CONFIRMED,
                confidence=confidence_f,
                summary="; ".join(parts),
                metadata={"stix_type": "malware", "stix_id": stix_id, "name": name},
            )
            _add_ev(ev)
            if stix_id:
                stix_id_to_evidence[stix_id] = ev

        elif obj_type == "campaign":
            parts = [f"Campaign: {name}"]
            if desc:
                parts.append(desc[:200])
            ev = EvidenceItem(
                source_name="stix_import",
                source_type="stix_import",
                status=EvidenceStatus.INFERRED,
                confidence=confidence_f,
                summary="; ".join(parts),
                metadata={"stix_type": "campaign", "stix_id": stix_id, "name": name},
            )
            _add_ev(ev)
            if stix_id:
                stix_id_to_evidence[stix_id] = ev

        elif obj_type == "attack-pattern":
            ttp_obs = _mitre_ttps_from_refs(refs)
            for obs in ttp_obs:
                added = _add_obs(obs)
                if added and stix_id:
                    stix_id_to_observable[stix_id] = added
            parts = [f"ATT&CK technique: {name}"]
            if refs:
                eids = [
                    r.get("external_id", "")
                    for r in refs
                    if r.get("source_name") == "mitre-attack"
                ]
                if eids:
                    parts.append(f"technique ID(s): {', '.join(eids)}")
            if desc:
                parts.append(desc[:120])
            ev = EvidenceItem(
                source_name="stix_import",
                source_type="stix_import",
                status=EvidenceStatus.CONFIRMED,
                confidence=confidence_f,
                summary="; ".join(parts),
                observable_ids=[o.observable_id for o in ttp_obs],
                metadata={"stix_type": "attack-pattern", "stix_id": stix_id},
            )
            _add_ev(ev)
            if stix_id:
                stix_id_to_evidence[stix_id] = ev

        elif obj_type == "vulnerability":
            cve_matches = _CVE_RE.findall(name + " " + desc)
            for cve in cve_matches:
                obs = Observable(value=cve.upper(), observable_type=ObservableType.CVE)
                added = _add_obs(obs)
                if added and stix_id:
                    stix_id_to_observable[stix_id] = added
            parts = [f"Vulnerability: {name}"]
            if desc:
                parts.append(desc[:200])
            ev = EvidenceItem(
                source_name="stix_import",
                source_type="stix_import",
                status=EvidenceStatus.CONFIRMED,
                confidence=confidence_f,
                summary="; ".join(parts),
                metadata={"stix_type": "vulnerability", "stix_id": stix_id},
            )
            _add_ev(ev)
            if stix_id:
                stix_id_to_evidence[stix_id] = ev

        elif obj_type == "infrastructure":
            infra_types = obj.get("infrastructure_types", obj.get("labels", []))
            parts = [f"Infrastructure: {name}"]
            if infra_types:
                parts.append(f"types: {', '.join(infra_types[:3])}")
            if desc:
                parts.append(desc[:120])
            ev = EvidenceItem(
                source_name="stix_import",
                source_type="stix_import",
                status=EvidenceStatus.CONFIRMED,
                confidence=confidence_f,
                summary="; ".join(parts),
                metadata={"stix_type": "infrastructure", "stix_id": stix_id},
            )
            _add_ev(ev)
            if stix_id:
                stix_id_to_evidence[stix_id] = ev

        elif obj_type == "relationship":
            src_ref = obj.get("source_ref", "")
            tgt_ref = obj.get("target_ref", "")
            rel_type_str = obj.get("relationship_type", "related-to")
            rel_type = _STIX_TO_REL.get(rel_type_str, RelationshipType.RELATED_TO)

            src_obs = stix_id_to_observable.get(src_ref)
            tgt_obs = stix_id_to_observable.get(tgt_ref)

            if src_obs and tgt_obs:
                rel = Relationship(
                    source_ref=src_obs.observable_id,
                    target_ref=tgt_obs.observable_id,
                    relationship_type=rel_type,
                    rationale=f"STIX: {rel_type_str}",
                    confidence=confidence_f,
                )
                result.relationships.append(rel)
            else:
                result.skipped += 1

        else:
            result.skipped += 1

    return result


def is_stix_bundle(text: str) -> bool:
    """Quick check: does this text look like a STIX bundle?"""
    stripped = text.lstrip()
    if not stripped.startswith("{"):
        return False
    try:
        import json
        data = json.loads(text)
        return isinstance(data, dict) and data.get("type") == "bundle"
    except (ValueError, TypeError):
        return False
