from __future__ import annotations

import json

from argus.ingestion.json_ingestor import ingest_json_alerts, is_json_alert_array
from argus.models.evidence import ObservableType


def test_is_json_alert_array_detects_array_of_objects() -> None:
    data = json.dumps([{"alert_id": "A1", "src_ip": "198.51.100.1"}])
    assert is_json_alert_array(data)


def test_is_json_alert_array_rejects_plain_array() -> None:
    assert not is_json_alert_array(json.dumps(["string1", "string2"]))


def test_is_json_alert_array_rejects_object() -> None:
    assert not is_json_alert_array(json.dumps({"src_ip": "1.2.3.4"}))


def test_is_json_alert_array_rejects_plain_text() -> None:
    assert not is_json_alert_array("192.168.1.1 malware.example.com")


def test_ingest_empty_array_returns_empty() -> None:
    result = ingest_json_alerts([])
    assert result.observables == []
    assert result.evidence == []
    assert result.record_count == 0


def test_ingest_ip_from_src_ip_field() -> None:
    alerts = [{"alert_id": "A1", "src_ip": "203.0.113.10"}]
    result = ingest_json_alerts(alerts)
    values = [o.value for o in result.observables]
    assert "203.0.113.10" in values


def test_ingest_private_ip_not_added_by_field_heuristic() -> None:
    # The field-name heuristic skips private IPs, but the regex fallback may catch them.
    # A private IP in a dedicated src_ip field should not be added by heuristic alone.
    alerts = [{"src_ip": "10.0.0.1"}]
    result = ingest_json_alerts(alerts)
    # The heuristic won't add it (private range filtered), but regex fallback might.
    # We just verify that confidence for any found ip is not the heuristic confidence (0.85).
    ip_obs = [o for o in result.observables if o.value == "10.0.0.1"]
    for obs in ip_obs:
        assert obs.confidence != 0.85, "heuristic should not add private IPs at 0.85 confidence"


def test_ingest_domain_from_dns_query_field() -> None:
    alerts = [{"dns_query": "evil.example.com"}]
    result = ingest_json_alerts(alerts)
    types = {o.observable_type for o in result.observables}
    assert ObservableType.DOMAIN in types
    assert any(o.value == "evil.example.com" for o in result.observables)


def test_ingest_sha256_from_hash_field() -> None:
    sha256 = "a" * 64
    alerts = [{"file_hash": sha256}]
    result = ingest_json_alerts(alerts)
    assert any(o.observable_type == ObservableType.SHA256 and o.value == sha256 for o in result.observables)


def test_ingest_url_from_url_field() -> None:
    alerts = [{"url": "https://malware.example.com/payload.exe"}]
    result = ingest_json_alerts(alerts)
    assert any(o.observable_type == ObservableType.URL for o in result.observables)


def test_ingest_cve_from_cve_field() -> None:
    alerts = [{"cve_id": "CVE-2021-44228"}]
    result = ingest_json_alerts(alerts)
    assert any(o.observable_type == ObservableType.CVE and "CVE-2021-44228" in o.value for o in result.observables)


def test_ingest_email_from_sender_field() -> None:
    alerts = [{"sender": "attacker@evil.example.com"}]
    result = ingest_json_alerts(alerts)
    assert any(o.observable_type == ObservableType.EMAIL for o in result.observables)


def test_ingest_deduplicates_across_records() -> None:
    alerts = [
        {"src_ip": "203.0.113.5"},
        {"src_ip": "203.0.113.5"},
        {"src_ip": "203.0.113.5"},
    ]
    result = ingest_json_alerts(alerts)
    ip_obs = [o for o in result.observables if o.observable_type == ObservableType.IP]
    assert len(ip_obs) == 1


def test_ingest_nested_fields_flattened() -> None:
    alerts = [{"network": {"src_ip": "198.51.100.20", "dst_ip": "8.8.8.8"}}]
    result = ingest_json_alerts(alerts)
    values = [o.value for o in result.observables]
    assert "198.51.100.20" in values


def test_ingest_creates_evidence_with_alert_id() -> None:
    alerts = [{"alert_id": "SEC-123", "src_ip": "203.0.113.99"}]
    result = ingest_json_alerts(alerts)
    assert len(result.evidence) == 1
    assert "SEC-123" in result.evidence[0].summary


def test_ingest_record_count_set() -> None:
    alerts = [{"src_ip": "1.2.3.4"}, {"src_ip": "5.6.7.8"}, {"src_ip": "9.10.11.12"}]
    result = ingest_json_alerts(alerts)
    assert result.record_count == 3


def test_ingest_single_object() -> None:
    alert = {"src_ip": "203.0.113.7", "dst_ip": "192.168.0.1"}
    result = ingest_json_alerts(alert)
    assert any(o.value == "203.0.113.7" for o in result.observables)


def test_ingest_regex_fallback_picks_up_free_text_fields() -> None:
    alerts = [{"description": "Detected callback to 198.51.100.44 CVE-2023-1234"}]
    result = ingest_json_alerts(alerts)
    values = [o.value for o in result.observables]
    assert "198.51.100.44" in values
