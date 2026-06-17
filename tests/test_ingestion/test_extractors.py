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
