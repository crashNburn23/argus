from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel

from argus.models.evidence import ObservableType


class ExtractedObservable(BaseModel):
    value: str
    observable_type: ObservableType
    canonical_value: str
    raw_excerpt: str


_URL_RE = re.compile(r"https?://[^\s<>'\")]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
_SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
_MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
_IP_CANDIDATE_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?!(?:CVE|TLP)\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63})\b",
    re.IGNORECASE,
)


def extract_observables(text: str, *, context_chars: int = 80) -> list[ExtractedObservable]:
    """Extract common CTI observables from raw text.

    This intentionally covers high-signal deterministic patterns first. Model-assisted
    extraction can layer on later, but it should write the same observable/evidence shape.
    """
    extracted: list[ExtractedObservable] = []

    def add(
        match: re.Match[str],
        observable_type: ObservableType,
        canonical_value: str | None = None,
    ) -> None:
        value = match.group(0).rstrip(".,;:")
        canonical = canonical_value or _canonicalize(value, observable_type)
        excerpt = _excerpt(text, match.start(), match.end(), context_chars)
        extracted.append(
            ExtractedObservable(
                value=value,
                observable_type=observable_type,
                canonical_value=canonical,
                raw_excerpt=excerpt,
            )
        )

    for regex, observable_type in (
        (_URL_RE, ObservableType.URL),
        (_EMAIL_RE, ObservableType.EMAIL),
        (_CVE_RE, ObservableType.CVE),
        (_ATTACK_RE, ObservableType.ATTACK_TTP),
        (_SHA256_RE, ObservableType.SHA256),
        (_SHA1_RE, ObservableType.SHA1),
        (_MD5_RE, ObservableType.MD5),
    ):
        for match in regex.finditer(text):
            add(match, observable_type)

    for match in _IP_CANDIDATE_RE.finditer(text):
        value = match.group(0)
        try:
            canonical = str(ipaddress.ip_address(value))
        except ValueError:
            continue
        add(match, ObservableType.IP, canonical)

    for match in _DOMAIN_RE.finditer(text):
        value = match.group(0).rstrip(".,;:").lower()
        if _is_probably_url_host_duplicate(value, extracted):
            continue
        add(match, ObservableType.DOMAIN, value)

    return _dedupe(extracted)


def _canonicalize(value: str, observable_type: ObservableType) -> str:
    if observable_type in {
        ObservableType.DOMAIN,
        ObservableType.EMAIL,
        ObservableType.CVE,
        ObservableType.ATTACK_TTP,
        ObservableType.MD5,
        ObservableType.SHA1,
        ObservableType.SHA256,
    }:
        return value.lower()
    return value


def _excerpt(text: str, start: int, end: int, context_chars: int) -> str:
    excerpt_start = max(0, start - context_chars)
    excerpt_end = min(len(text), end + context_chars)
    return " ".join(text[excerpt_start:excerpt_end].split())


def _dedupe(extracted: list[ExtractedObservable]) -> list[ExtractedObservable]:
    seen: set[tuple[ObservableType, str]] = set()
    deduped: list[ExtractedObservable] = []
    for item in extracted:
        key = (item.observable_type, item.canonical_value)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _is_probably_url_host_duplicate(
    domain: str,
    extracted: list[ExtractedObservable],
) -> bool:
    return any(
        item.observable_type is ObservableType.URL and f"://{domain}" in item.canonical_value
        for item in extracted
    )
