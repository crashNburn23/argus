from __future__ import annotations

from argus.ingestion.csv_ingestor import CsvIngestResult, ingest_csv, is_csv
from argus.models.evidence import ObservableType

_BASIC_CSV = """\
alert_id,src_ip,dst_ip,domain,severity
A1,203.0.113.10,192.168.0.1,evil.example.com,high
A2,203.0.113.11,10.0.0.2,bad.example.org,medium
"""

_HASH_CSV = """\
file_hash,alert_id
{sha256},SEC-001
""".format(sha256="b" * 64)

_TAB_CSV = "alert_id\tsrc_ip\tdomain\nA1\t198.51.100.5\tevil.test.com\n"


def test_is_csv_detects_basic_csv() -> None:
    assert is_csv(_BASIC_CSV)


def test_is_csv_rejects_json() -> None:
    assert not is_csv('[{"src_ip": "1.2.3.4"}]')


def test_is_csv_rejects_stix_bundle() -> None:
    assert not is_csv('{"type": "bundle", "objects": []}')


def test_is_csv_rejects_single_line() -> None:
    assert not is_csv("just one line with no delimiter")


def test_ingest_csv_extracts_ip_from_src_ip_column() -> None:
    result = ingest_csv(_BASIC_CSV)
    values = [o.value for o in result.observables]
    assert "203.0.113.10" in values
    assert "203.0.113.11" in values


def test_ingest_csv_extracts_domain() -> None:
    result = ingest_csv(_BASIC_CSV)
    types = {o.observable_type for o in result.observables}
    assert ObservableType.DOMAIN in types
    values = [o.value for o in result.observables]
    assert "evil.example.com" in values


def test_ingest_csv_deduplicates_across_rows() -> None:
    csv_text = "alert_id,src_ip\nA1,203.0.113.5\nA2,203.0.113.5\nA3,203.0.113.5\n"
    result = ingest_csv(csv_text)
    ip_obs = [o for o in result.observables if o.observable_type == ObservableType.IP]
    assert len(ip_obs) == 1


def test_ingest_csv_extracts_sha256_from_hash_column() -> None:
    result = ingest_csv(_HASH_CSV)
    assert any(o.observable_type == ObservableType.SHA256 for o in result.observables)


def test_ingest_csv_tab_delimiter() -> None:
    result = ingest_csv(_TAB_CSV)
    values = [o.value for o in result.observables]
    assert "198.51.100.5" in values
    assert "evil.test.com" in values


def test_ingest_csv_row_count() -> None:
    result = ingest_csv(_BASIC_CSV)
    assert result.row_count == 2


def test_ingest_csv_evidence_has_alert_id() -> None:
    result = ingest_csv(_BASIC_CSV)
    summaries = " ".join(ev.summary for ev in result.evidence)
    assert "A1" in summaries or "A2" in summaries


def test_ingest_csv_header_captured() -> None:
    result = ingest_csv(_BASIC_CSV)
    assert "src_ip" in result.header
    assert "domain" in result.header


def test_ingest_csv_empty_returns_empty() -> None:
    result = ingest_csv("alert_id,src_ip\n")
    assert result.observables == []
    assert result.row_count == 0


def test_ingest_csv_handles_missing_values() -> None:
    csv_text = "alert_id,src_ip,domain\nA1,,evil.example.com\n"
    result = ingest_csv(csv_text)
    assert any(o.value == "evil.example.com" for o in result.observables)
