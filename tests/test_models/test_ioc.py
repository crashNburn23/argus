"""Unit tests for IOC models."""
from __future__ import annotations

from argus.models.ioc import (
    IOCEnrichmentRecord,
    IOCEnrichmentResult,
    IOCType,
    IOCVerdict,
)
from argus.models.stix_helpers import ioc_to_stix_indicator


def test_ioc_enrichment_record_defaults():
    record = IOCEnrichmentRecord(indicator="1.2.3.4", ioc_type=IOCType.IP)
    assert record.overall_verdict == IOCVerdict.UNKNOWN
    assert record.confidence == 0.0
    assert record.source_results == []


def test_ioc_enrichment_result():
    record = IOCEnrichmentRecord(
        indicator="evil.com",
        ioc_type=IOCType.DOMAIN,
        overall_verdict=IOCVerdict.MALICIOUS,
        confidence=0.95,
        malware_families=["Emotet"],
    )
    result = IOCEnrichmentResult(
        indicators=[record],
        summary="One malicious domain found",
        high_priority_iocs=["evil.com"],
    )
    assert len(result.indicators) == 1
    assert result.high_priority_iocs == ["evil.com"]


def test_stix_ip_pattern():
    record = IOCEnrichmentRecord(indicator="1.2.3.4", ioc_type=IOCType.IP,
                                  overall_verdict=IOCVerdict.MALICIOUS)
    stix = ioc_to_stix_indicator(record)
    assert stix["type"] == "indicator"
    assert "[ipv4-addr:value = '1.2.3.4']" in stix["pattern"]
    assert "malicious-activity" in stix["indicator_types"]


def test_stix_domain_pattern():
    record = IOCEnrichmentRecord(indicator="evil.com", ioc_type=IOCType.DOMAIN,
                                  overall_verdict=IOCVerdict.SUSPICIOUS)
    stix = ioc_to_stix_indicator(record)
    assert "[domain-name:value = 'evil.com']" in stix["pattern"]
    assert "anomalous-activity" in stix["indicator_types"]


def test_stix_sha256_pattern():
    record = IOCEnrichmentRecord(
        indicator="abc123" * 10 + "abcd",
        ioc_type=IOCType.SHA256,
        overall_verdict=IOCVerdict.MALICIOUS,
    )
    stix = ioc_to_stix_indicator(record)
    assert "SHA-256" in stix["pattern"]
