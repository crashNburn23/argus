"""Structured JSON alert/event ingestor.

Parses a JSON array (or single object) of alert/event records and extracts
observables with higher fidelity than regex alone by using field name heuristics.

Used by `case extract` when an artifact's content is a JSON array but not a
STIX bundle.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from argus.ingestion.extractors import extract_observables
from argus.models.evidence import EvidenceItem, EvidenceStatus, Observable, ObservableType

# ---------------------------------------------------------------------------
# Field-name heuristics: map well-known field names to observable types
# ---------------------------------------------------------------------------

_IP_FIELDS = frozenset({
    "src_ip", "dst_ip", "source_ip", "dest_ip", "destination_ip",
    "client_ip", "server_ip", "remote_ip", "local_ip", "ip", "ip_address",
    "src", "dst", "source", "destination",
    "srcip", "dstip", "sourceip", "destip",
    "src_addr", "dst_addr", "source_addr", "dest_addr",
    "attacker_ip", "victim_ip", "c2_ip", "beacon_ip",
})

_DOMAIN_FIELDS = frozenset({
    "domain", "hostname", "fqdn", "host", "dest_host", "src_host",
    "dns_query", "queried_domain", "resolved_domain", "target_domain",
    "c2_domain", "beacon_domain", "referrer_host",
})

_URL_FIELDS = frozenset({
    "url", "uri", "request_url", "http_url", "full_url",
    "c2_url", "download_url", "referrer", "redirect_url",
})

_HASH_FIELDS = frozenset({
    "md5", "sha1", "sha256", "sha512", "file_hash", "hash", "filehash",
    "process_md5", "process_sha256", "parent_md5", "parent_sha256",
    "dropped_hash", "artifact_hash",
})

_CVE_FIELDS = frozenset({
    "cve", "cve_id", "vulnerability", "vuln_id",
})

_EMAIL_FIELDS = frozenset({
    "email", "sender", "recipient", "from", "to", "reply_to",
    "sender_email", "recipient_email",
})

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_PRIVATE_IP_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|169\.254\.)"
)


@dataclass
class JsonIngestResult:
    observables: list[Observable] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    record_count: int = 0


def _typed_observable(value: str, field_name: str) -> Observable | None:
    """Try to create a typed observable from a known field name + value pair."""
    key = field_name.lower().strip()
    v = value.strip()
    if not v:
        return None

    if key in _IP_FIELDS:
        if _IP_RE.match(v) and not _PRIVATE_IP_RE.match(v):
            return Observable(value=v, observable_type=ObservableType.IP, confidence=0.85)
    elif key in _DOMAIN_FIELDS:
        # Basic sanity: must have a dot and no spaces
        if "." in v and " " not in v and len(v) < 255:
            return Observable(value=v, observable_type=ObservableType.DOMAIN, confidence=0.8)
    elif key in _URL_FIELDS:
        if v.startswith(("http://", "https://", "ftp://")):
            return Observable(value=v, observable_type=ObservableType.URL, confidence=0.85)
    elif key in _HASH_FIELDS:
        if _SHA256_RE.match(v):
            return Observable(value=v, observable_type=ObservableType.SHA256, confidence=0.9)
        if _SHA1_RE.match(v):
            return Observable(value=v, observable_type=ObservableType.SHA1, confidence=0.9)
        if _MD5_RE.match(v):
            return Observable(value=v, observable_type=ObservableType.MD5, confidence=0.9)
    elif key in _CVE_FIELDS:
        if _CVE_RE.match(v):
            return Observable(value=v.upper(), observable_type=ObservableType.CVE, confidence=0.9)
    elif key in _EMAIL_FIELDS:
        if _EMAIL_RE.match(v):
            return Observable(
                value=v.lower(), observable_type=ObservableType.EMAIL, confidence=0.85
            )

    return None


def _flatten_record(
    record: dict[str, Any],
    prefix: str = "",
) -> list[tuple[str, str]]:
    """Flatten a nested dict to (field_name, value) pairs of string values."""
    out = []
    for k, v in record.items():
        key = f"{prefix}{k}" if prefix else k
        if isinstance(v, str):
            out.append((key, v))
        elif isinstance(v, (int, float)):
            out.append((key, str(v)))
        elif isinstance(v, dict):
            out.extend(_flatten_record(v, prefix=f"{key}."))
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    out.append((key, item))
                elif isinstance(item, dict):
                    out.extend(_flatten_record(item, prefix=f"{key}."))
    return out


def ingest_json_alerts(data: list[Any] | dict[str, Any]) -> JsonIngestResult:
    """Parse a JSON alert array (or single object) and return structured case data."""
    result = JsonIngestResult()

    records: list[Any] = data if isinstance(data, list) else [data]
    result.record_count = len(records)

    seen: set[tuple[ObservableType, str]] = set()

    def _add(obs: Observable) -> bool:
        key = (obs.observable_type, obs.canonical_value or obs.value)
        if key in seen:
            return False
        seen.add(key)
        result.observables.append(obs)
        return True

    # Per-record extraction
    for record in records:
        if not isinstance(record, dict):
            continue

        pairs = _flatten_record(record)
        record_obs: list[Observable] = []

        # 1. Field-name heuristic extraction (high confidence)
        for field_name, value in pairs:
            bare_key = field_name.split(".")[-1]
            obs = _typed_observable(value, bare_key)
            if obs and _add(obs):
                record_obs.append(obs)

        # 2. Regex fallback on remaining string values (lower confidence)
        all_text = " ".join(v for _, v in pairs)
        for extracted in extract_observables(all_text):
            key = (extracted.observable_type, extracted.canonical_value)
            if key not in seen:
                obs = Observable(
                    value=extracted.value,
                    observable_type=extracted.observable_type,
                    canonical_value=extracted.canonical_value,
                    confidence=0.65,
                )
                seen.add(key)
                result.observables.append(obs)
                record_obs.append(obs)

        if record_obs:
            alert_id = (
                record.get("alert_id")
                or record.get("id")
                or record.get("event_id")
                or ""
            )
            ev = EvidenceItem(
                source_name="json_import",
                source_type="json_import",
                status=EvidenceStatus.CONFIRMED,
                confidence=0.75,
                summary=(
                    f"JSON alert{f' {alert_id}' if alert_id else ''}: "
                    f"{len(record_obs)} observable(s) extracted"
                ),
                observable_ids=[o.observable_id for o in record_obs],
            )
            result.evidence.append(ev)

    return result


def is_json_alert_array(text: str) -> bool:
    """Quick check: does this text look like a JSON array of objects (not STIX)?"""
    stripped = text.lstrip()
    if not stripped.startswith("["):
        return False
    try:
        import json
        data = json.loads(text)
        return isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict)
    except (ValueError, TypeError):
        return False
