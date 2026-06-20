from __future__ import annotations

from argus.ingestion.extractors import extract_observables
from argus.models.evidence import ObservableType


def test_extract_observables_finds_common_cti_patterns() -> None:
    text = (
        "CVE-2021-44228 exploitation from 198.51.100.10 used https://evil.example/a "
        "with contact threat@example.com and technique T1059.001. "
        "Hash d41d8cd98f00b204e9800998ecf8427e was observed."
    )

    extracted = extract_observables(text)
    values = {(item.observable_type, item.canonical_value) for item in extracted}

    assert (ObservableType.CVE, "cve-2021-44228") in values
    assert (ObservableType.IP, "198.51.100.10") in values
    assert (ObservableType.URL, "https://evil.example/a") in values
    assert (ObservableType.EMAIL, "threat@example.com") in values
    assert (ObservableType.ATTACK_TTP, "t1059.001") in values
    assert (ObservableType.MD5, "d41d8cd98f00b204e9800998ecf8427e") in values


def test_extract_observables_deduplicates_matches() -> None:
    extracted = extract_observables("198.51.100.10 198.51.100.10 CVE-2021-44228 cve-2021-44228")

    values = [(item.observable_type, item.canonical_value) for item in extracted]

    assert values.count((ObservableType.IP, "198.51.100.10")) == 1
    assert values.count((ObservableType.CVE, "cve-2021-44228")) == 1


def test_extract_observables_empty_text() -> None:
    assert extract_observables("") == []
    assert extract_observables("   \n\t  ") == []


def test_extract_observables_no_matches() -> None:
    extracted = extract_observables("The quick brown fox jumps over the lazy dog.")
    assert extracted == []


def test_extract_observables_strips_trailing_punctuation() -> None:
    extracted = extract_observables("Contacted 198.51.100.10, and malware.example.")
    values = {item.canonical_value for item in extracted}
    assert "198.51.100.10" in values
    assert "malware.example" in values


def test_extract_observables_domain_not_duplicated_from_url() -> None:
    text = "Downloaded from https://evil.example/payload.exe"
    extracted = extract_observables(text)
    types = {item.observable_type for item in extracted}
    values_by_type = {item.observable_type: item.canonical_value for item in extracted}
    assert ObservableType.URL in types
    assert values_by_type.get(ObservableType.DOMAIN, "") != "evil.example"


def test_extract_observables_raw_excerpt_captures_context() -> None:
    text = "The malicious IP 198.51.100.10 was seen in access logs."
    extracted = extract_observables(text, context_chars=20)
    ip_item = next(item for item in extracted if item.observable_type == ObservableType.IP)
    assert "198.51.100.10" in ip_item.raw_excerpt
    assert len(ip_item.raw_excerpt) < len(text) + 5


def test_extract_observables_invalid_ip_not_extracted() -> None:
    text = "Version 10.999.0.1 is not a valid IP address."
    extracted = extract_observables(text)
    ip_values = [item.value for item in extracted if item.observable_type == ObservableType.IP]
    assert "10.999.0.1" not in ip_values


def test_extract_observables_sha256_and_md5_together() -> None:
    sha256 = "a" * 64
    md5 = "b" * 32
    text = f"Hash1: {sha256} and hash2: {md5}"
    extracted = extract_observables(text)
    types = {item.observable_type for item in extracted}
    assert ObservableType.SHA256 in types
    assert ObservableType.MD5 in types
