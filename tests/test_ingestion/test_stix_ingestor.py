from __future__ import annotations

import json

from argus.ingestion.stix_ingestor import ingest_stix_bundle, is_stix_bundle
from argus.models.evidence import ObservableType, RelationshipType

_MINIMAL_BUNDLE: dict = {
    "type": "bundle",
    "id": "bundle--00000000-0000-0000-0000-000000000001",
    "objects": [],
}


def test_is_stix_bundle_detects_valid_bundle() -> None:
    assert is_stix_bundle(json.dumps(_MINIMAL_BUNDLE))


def test_is_stix_bundle_rejects_plain_json() -> None:
    assert not is_stix_bundle(json.dumps({"foo": "bar"}))


def test_is_stix_bundle_rejects_plain_text() -> None:
    assert not is_stix_bundle("192.168.1.1 malware.example.com")


def test_ingest_empty_bundle_returns_empty() -> None:
    result = ingest_stix_bundle(_MINIMAL_BUNDLE)
    assert result.observables == []
    assert result.evidence == []
    assert result.relationships == []


def test_ingest_indicator_ip() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000002",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--aaa",
                "name": "Malicious IP",
                "pattern": "[ipv4-addr:value = '198.51.100.10']",
                "labels": ["malicious-activity"],
                "confidence": 90,
            }
        ],
    }
    result = ingest_stix_bundle(bundle)
    assert len(result.observables) == 1
    obs = result.observables[0]
    assert obs.observable_type == ObservableType.IP
    assert obs.value == "198.51.100.10"
    assert len(result.evidence) == 1
    ev = result.evidence[0]
    assert "malicious-activity" in ev.summary
    assert ev.confidence == 0.9


def test_ingest_indicator_domain_and_hash() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000003",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--bbb",
                "name": "Dropper",
                "pattern": (
                    "[domain-name:value = 'evil.example.com'] OR "
                    "[file:hashes.'SHA-256' = 'aabbccdd' * 8]"
                ),
                "labels": [],
                "confidence": 70,
            }
        ],
    }
    result = ingest_stix_bundle(bundle)
    types = {o.observable_type for o in result.observables}
    assert ObservableType.DOMAIN in types


def test_ingest_threat_actor() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000004",
        "objects": [
            {
                "type": "threat-actor",
                "id": "threat-actor--ccc",
                "name": "Lazarus Group",
                "aliases": ["Hidden Cobra", "ZINC"],
                "sophistication": "advanced",
                "goals": ["financial", "espionage"],
                "description": "North Korea-linked APT.",
                "confidence": 80,
            }
        ],
    }
    result = ingest_stix_bundle(bundle)
    assert len(result.evidence) == 1
    ev = result.evidence[0]
    assert "Lazarus Group" in ev.summary
    assert "Hidden Cobra" in ev.summary
    assert ev.metadata["stix_type"] == "threat-actor"


def test_ingest_attack_pattern_extracts_ttp() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000005",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--ddd",
                "name": "Spearphishing Link",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1566.002",
                        "url": "https://attack.mitre.org/techniques/T1566/002",
                    }
                ],
                "confidence": 100,
            }
        ],
    }
    result = ingest_stix_bundle(bundle)
    assert len(result.observables) == 1
    assert result.observables[0].observable_type == ObservableType.ATTACK_TTP
    assert result.observables[0].value == "T1566.002"


def test_ingest_vulnerability_extracts_cve() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000006",
        "objects": [
            {
                "type": "vulnerability",
                "id": "vulnerability--eee",
                "name": "CVE-2021-44228",
                "description": "Log4Shell remote code execution vulnerability.",
                "confidence": 100,
            }
        ],
    }
    result = ingest_stix_bundle(bundle)
    assert len(result.observables) == 1
    assert result.observables[0].observable_type == ObservableType.CVE
    assert result.observables[0].value == "CVE-2021-44228"


def test_ingest_relationship_links_observables() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000007",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--src",
                "name": "C2 IP",
                "pattern": "[ipv4-addr:value = '203.0.113.5']",
                "confidence": 80,
            },
            {
                "type": "indicator",
                "id": "indicator--tgt",
                "name": "C2 domain",
                "pattern": "[domain-name:value = 'c2.example.com']",
                "confidence": 80,
            },
            {
                "type": "relationship",
                "id": "relationship--rel",
                "relationship_type": "resolves-to",
                "source_ref": "indicator--src",
                "target_ref": "indicator--tgt",
                "confidence": 90,
            },
        ],
    }
    result = ingest_stix_bundle(bundle)
    assert len(result.observables) == 2
    assert len(result.relationships) == 1
    rel = result.relationships[0]
    assert rel.relationship_type == RelationshipType.RESOLVES_TO


def test_ingest_deduplicates_observables() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000008",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--dup1",
                "name": "IP A",
                "pattern": "[ipv4-addr:value = '198.51.100.99']",
                "confidence": 80,
            },
            {
                "type": "indicator",
                "id": "indicator--dup2",
                "name": "IP A again",
                "pattern": "[ipv4-addr:value = '198.51.100.99']",
                "confidence": 60,
            },
        ],
    }
    result = ingest_stix_bundle(bundle)
    assert len(result.observables) == 1


def test_ingest_malware_creates_evidence() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000009",
        "objects": [
            {
                "type": "malware",
                "id": "malware--fff",
                "name": "WannaCry",
                "malware_types": ["ransomware"],
                "description": "Ransomware that exploits EternalBlue.",
                "confidence": 100,
            }
        ],
    }
    result = ingest_stix_bundle(bundle)
    assert len(result.evidence) == 1
    ev = result.evidence[0]
    assert "WannaCry" in ev.summary
    assert "ransomware" in ev.summary


def test_ingest_non_bundle_returns_empty() -> None:
    result = ingest_stix_bundle({"type": "indicator", "id": "indicator--xxx"})
    assert result.observables == []


def test_ingest_skips_unresolvable_relationship() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000010",
        "objects": [
            {
                "type": "relationship",
                "id": "relationship--orphan",
                "relationship_type": "uses",
                "source_ref": "threat-actor--missing",
                "target_ref": "malware--also-missing",
            }
        ],
    }
    result = ingest_stix_bundle(bundle)
    assert result.relationships == []
    assert result.skipped >= 1
