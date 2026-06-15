from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from argus.models.ioc import IOCEnrichmentRecord, IOCType, IOCVerdict
from argus.models.threat_actor import ThreatActor
from argus.models.vulnerability import Vulnerability


def _stix_id(object_type: str) -> str:
    return f"{object_type}--{uuid.uuid4()}"


def _build_stix_pattern(ioc: IOCEnrichmentRecord) -> str:
    v = ioc.indicator
    match ioc.ioc_type:
        case IOCType.IP:
            return f"[ipv4-addr:value = '{v}']"
        case IOCType.DOMAIN:
            return f"[domain-name:value = '{v}']"
        case IOCType.URL:
            return f"[url:value = '{v}']"
        case IOCType.MD5:
            return f"[file:hashes.MD5 = '{v}']"
        case IOCType.SHA1:
            return f"[file:hashes.'SHA-1' = '{v}']"
        case IOCType.SHA256:
            return f"[file:hashes.'SHA-256' = '{v}']"
        case IOCType.EMAIL:
            return f"[email-addr:value = '{v}']"
        case _:
            return "[artifact:mime_type = 'text/plain']"


def _verdict_to_indicator_type(verdict: IOCVerdict) -> list[str]:
    return {
        IOCVerdict.MALICIOUS: ["malicious-activity"],
        IOCVerdict.SUSPICIOUS: ["anomalous-activity"],
        IOCVerdict.BENIGN: ["benign"],
        IOCVerdict.UNKNOWN: ["unknown"],
    }.get(verdict, ["unknown"])


def ioc_to_stix_indicator(ioc: IOCEnrichmentRecord) -> dict[str, Any]:
    now = datetime.now(tz=UTC).isoformat()
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _stix_id("indicator"),
        "created": now,
        "modified": now,
        "name": ioc.indicator,
        "indicator_types": _verdict_to_indicator_type(ioc.overall_verdict),
        "pattern": _build_stix_pattern(ioc),
        "pattern_type": "stix",
        "valid_from": now,
        "labels": ioc.tags,
        "confidence": int(ioc.confidence * 100),
    }


def actor_to_stix_threat_actor(actor: ThreatActor) -> dict[str, Any]:
    now = datetime.now(tz=UTC).isoformat()
    return {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": _stix_id("threat-actor"),
        "created": now,
        "modified": now,
        "name": actor.name,
        "aliases": actor.aliases,
        "description": actor.description,
        "goals": actor.goals,
        "sophistication": actor.sophistication or "unknown",
        "resource_level": actor.resource_level or "unknown",
        "primary_motivation": actor.primary_motivation or "unknown",
        "labels": ["threat-actor"],
    }


def vuln_to_stix_vulnerability(vuln: Vulnerability) -> dict[str, Any]:
    now = datetime.now(tz=UTC).isoformat()
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": _stix_id("vulnerability"),
        "created": now,
        "modified": now,
        "name": vuln.cve_id,
        "description": vuln.description,
        "external_references": [
            {
                "source_name": "cve",
                "external_id": vuln.cve_id,
                "url": f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id}",
            }
        ],
        "labels": ["vulnerability"],
    }
