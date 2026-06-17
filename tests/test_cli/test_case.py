from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from argus.cli.app import app


def test_case_create_show_and_list_json() -> None:
    runner = CliRunner()

    created = runner.invoke(
        app,
        [
            "case",
            "create",
            "Suspicious infrastructure",
            "--description",
            "Initial triage",
            "--scope",
            "198.51.100.0/24",
            "--tag",
            "triage",
            "--json",
        ],
    )

    assert created.exit_code == 0
    created_payload = json.loads(created.stdout)
    case_id = created_payload["case_id"]
    assert created_payload["title"] == "Suspicious infrastructure"
    assert created_payload["tags"] == ["triage"]

    shown = runner.invoke(app, ["case", "show", case_id, "--json"])
    assert shown.exit_code == 0
    assert json.loads(shown.stdout)["case_id"] == case_id

    listed = runner.invoke(app, ["case", "list", "--json"])
    assert listed.exit_code == 0
    listed_payload = json.loads(listed.stdout)
    assert [case["case_id"] for case in listed_payload] == [case_id]


def test_case_delete_removes_case() -> None:
    runner = CliRunner()

    created = runner.invoke(app, ["case", "create", "Delete me", "--json"])
    case_id = json.loads(created.stdout)["case_id"]

    deleted = runner.invoke(app, ["case", "delete", case_id, "--yes"])
    assert deleted.exit_code == 0
    assert case_id in deleted.stdout

    shown = runner.invoke(app, ["case", "show", case_id])
    assert shown.exit_code == 1
    assert "Case not found" in shown.stderr


def test_case_workspace_commands_add_note_pir_and_artifact(tmp_path: Path) -> None:
    runner = CliRunner()

    created = runner.invoke(app, ["case", "create", "Workspace", "--json"])
    case_id = json.loads(created.stdout)["case_id"]

    note = runner.invoke(
        app,
        ["case", "note", case_id, "Initial analyst observation", "--author", "alice", "--json"],
    )
    assert note.exit_code == 0
    note_payload = json.loads(note.stdout)
    assert note_payload["notes"][0]["body"] == "Initial analyst observation"
    assert note_payload["notes"][0]["author"] == "alice"

    pir = runner.invoke(
        app,
        [
            "case",
            "pir",
            case_id,
            "Which actor uses this infrastructure?",
            "--owner",
            "cti",
            "--priority",
            "high",
            "--tag",
            "attribution",
            "--json",
        ],
    )
    assert pir.exit_code == 0
    pir_payload = json.loads(pir.stdout)
    assert pir_payload["pirs"][0]["question"] == "Which actor uses this infrastructure?"
    assert pir_payload["pirs"][0]["owner"] == "cti"
    assert pir_payload["pirs"][0]["priority"] == "high"
    assert pir_payload["pirs"][0]["tags"] == ["attribution"]

    artifact_path = tmp_path / "report.txt"
    artifact_path.write_text("Observed malware.example resolving to 198.51.100.10")
    artifact = runner.invoke(
        app,
        [
            "case",
            "artifact",
            case_id,
            "--file",
            str(artifact_path),
            "--type",
            "report",
            "--source",
            "vendor",
            "--json",
        ],
    )
    assert artifact.exit_code == 0
    artifact_payload = json.loads(artifact.stdout)
    assert artifact_payload["artifacts"][0]["artifact_type"] == "report"
    assert artifact_payload["artifacts"][0]["source_name"] == "vendor"
    assert artifact_payload["artifacts"][0]["title"] == "report.txt"
    assert artifact_payload["artifacts"][0]["content_hash"]

    shown = runner.invoke(app, ["case", "show", case_id, "--json"])
    shown_payload = json.loads(shown.stdout)
    assert len(shown_payload["notes"]) == 1
    assert len(shown_payload["pirs"]) == 1
    assert len(shown_payload["artifacts"]) == 1


def test_case_artifact_requires_one_source() -> None:
    runner = CliRunner()

    created = runner.invoke(app, ["case", "create", "Workspace", "--json"])
    case_id = json.loads(created.stdout)["case_id"]

    missing = runner.invoke(app, ["case", "artifact", case_id])
    assert missing.exit_code == 1
    assert "Provide exactly one of --file or --text" in missing.stderr


def test_case_extract_creates_evidence_linked_observables() -> None:
    runner = CliRunner()

    created = runner.invoke(app, ["case", "create", "Extraction", "--json"])
    case_id = json.loads(created.stdout)["case_id"]
    artifact = runner.invoke(
        app,
        [
            "case",
            "artifact",
            case_id,
            "--text",
            "CVE-2021-44228 callback to 198.51.100.10 from malware.example via T1059.",
            "--type",
            "report",
            "--json",
        ],
    )
    artifact_payload = json.loads(artifact.stdout)
    artifact_id = artifact_payload["artifacts"][0]["artifact_id"]

    extracted = runner.invoke(
        app,
        ["case", "extract", case_id, "--artifact-id", artifact_id, "--json"],
    )

    assert extracted.exit_code == 0
    extracted_payload = json.loads(extracted.stdout)
    observables = {
        (observable["observable_type"], observable["canonical_value"]): observable
        for observable in extracted_payload["observables"]
    }
    assert ("cve", "cve-2021-44228") in observables
    assert ("ip", "198.51.100.10") in observables
    assert ("domain", "malware.example") in observables
    assert ("attack_ttp", "t1059") in observables
    assert extracted_payload["evidence"]
    for evidence in extracted_payload["evidence"]:
        assert evidence["artifact_id"] == artifact_id
        assert evidence["observable_ids"]
        assert evidence["metadata"]["extractor"] == "regex"

    observables_result = runner.invoke(app, ["case", "observables", case_id, "--json"])
    assert observables_result.exit_code == 0
    assert len(json.loads(observables_result.stdout)) == len(extracted_payload["observables"])

    evidence_result = runner.invoke(app, ["case", "evidence", case_id, "--json"])
    assert evidence_result.exit_code == 0
    assert len(json.loads(evidence_result.stdout)) == len(extracted_payload["evidence"])

    second = runner.invoke(
        app,
        ["case", "extract", case_id, "--artifact-id", artifact_id, "--json"],
    )
    second_payload = json.loads(second.stdout)
    assert len(second_payload["observables"]) == len(extracted_payload["observables"])
    assert len(second_payload["evidence"]) == len(extracted_payload["evidence"])


def test_case_enrich_creates_evidence_from_mock_tools(monkeypatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-abuseipdb-key")
    from argus.config.settings import get_settings
    get_settings.cache_clear()

    runner = CliRunner()

    created = runner.invoke(app, ["case", "create", "Enrich test", "--json"])
    case_id = json.loads(created.stdout)["case_id"]
    runner.invoke(
        app,
        [
            "case",
            "artifact",
            case_id,
            "--text",
            "CVE-2021-44228 exploitation from 198.51.100.10 via malware.example",
            "--type",
            "report",
        ],
    )
    runner.invoke(app, ["case", "extract", case_id])

    abuseipdb_result = json.dumps({
        "ip_address": "198.51.100.10",
        "abuse_confidence_score": 87,
        "total_reports": 42,
        "country_code": "DE",
    })
    nvd_result = json.dumps({
        "total_results": 1,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2021-44228",
                "cvss_v3_score": 10.0,
                "severity": "critical",
                "in_cisa_kev": True,
                "description": "Log4Shell",
            }
        ],
        "cisa_kev_matches": ["CVE-2021-44228"],
    })

    with (
        patch(
            "argus.tools.abuseipdb.abuseipdb_check",
            new_callable=AsyncMock,
            return_value=abuseipdb_result,
        ),
        patch(
            "argus.tools.nvd.nvd_cve_lookup",
            new_callable=AsyncMock,
            return_value=nvd_result,
        ),
    ):
        result = runner.invoke(app, ["case", "enrich", case_id, "--json"])

    assert result.exit_code == 0, result.output or result.stderr
    payload = json.loads(result.stdout)
    evidence = payload["evidence"]
    sources = {ev["source_name"] for ev in evidence if ev["source_type"] == "enrichment"}
    assert "abuseipdb" in sources
    assert "nvd" in sources

    abuseipdb_ev = next(ev for ev in evidence if ev["source_name"] == "abuseipdb")
    assert "87" in abuseipdb_ev["summary"]
    assert abuseipdb_ev["status"] == "confirmed"

    nvd_ev = next(ev for ev in evidence if ev["source_name"] == "nvd")
    assert "CISA KEV" in nvd_ev["summary"]
    assert nvd_ev["status"] == "confirmed"


def test_case_enrich_skips_already_enriched_observables() -> None:
    runner = CliRunner()

    created = runner.invoke(app, ["case", "create", "Dedupe enrich", "--json"])
    case_id = json.loads(created.stdout)["case_id"]
    runner.invoke(
        app,
        ["case", "artifact", case_id, "--text", "CVE-2021-44228", "--type", "report"],
    )
    runner.invoke(app, ["case", "extract", case_id])

    nvd_result = json.dumps({
        "total_results": 1,
        "vulnerabilities": [{"cve_id": "CVE-2021-44228", "cvss_v3_score": 10.0,
                              "severity": "critical", "in_cisa_kev": True,
                              "description": "Log4Shell"}],
        "cisa_kev_matches": ["CVE-2021-44228"],
    })

    with patch(
        "argus.tools.nvd.nvd_cve_lookup", new_callable=AsyncMock, return_value=nvd_result
    ) as mock_nvd:
        runner.invoke(app, ["case", "enrich", case_id])
        first_call_count = mock_nvd.call_count
        runner.invoke(app, ["case", "enrich", case_id])
        second_call_count = mock_nvd.call_count

    assert first_call_count == 1
    assert second_call_count == first_call_count


def test_case_report_generates_markdown_from_evidence() -> None:
    runner = CliRunner()

    created = runner.invoke(
        app,
        [
            "case",
            "create",
            "Log4Shell campaign",
            "--description",
            "Active exploitation of CVE-2021-44228 targeting financial sector.",
            "--json",
        ],
    )
    case_id = json.loads(created.stdout)["case_id"]

    runner.invoke(
        app,
        [
            "case",
            "artifact",
            case_id,
            "--text",
            "CVE-2021-44228 exploitation from 198.51.100.10",
            "--type",
            "report",
        ],
    )
    runner.invoke(app, ["case", "extract", case_id])
    runner.invoke(
        app,
        ["case", "pir", case_id, "What actor is exploiting Log4Shell?", "--priority", "high"],
    )
    runner.invoke(
        app, ["case", "note", case_id, "Indicator confirmed via threat intel feed."]
    )

    result = runner.invoke(app, ["case", "report", case_id, "--no-save"])
    assert result.exit_code == 0
    assert "Log4Shell campaign" in result.output
    assert "CVE" in result.output or "cve" in result.output
    assert "Evidence" in result.output


def test_case_pivot_creates_relationships_and_discovers_observables(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-vt-key")
    from argus.config.settings import get_settings
    get_settings.cache_clear()

    runner = CliRunner()

    created = runner.invoke(app, ["case", "create", "Pivot test", "--json"])
    case_id = json.loads(created.stdout)["case_id"]
    runner.invoke(
        app,
        [
            "case",
            "artifact",
            case_id,
            "--text",
            "Observed 198.51.100.10 and malware.example in use by threat actor.",
            "--type",
            "report",
        ],
    )
    runner.invoke(app, ["case", "extract", case_id])

    pdns_ip_result = json.dumps({
        "indicator": "198.51.100.10",
        "indicator_type": "ip",
        "resolution_count": 2,
        "resolutions": [
            {"date": "2026-01-01", "resolver": "pdns", "hostname": "pivot-host1.example"},
            {"date": "2026-01-02", "resolver": "pdns", "hostname": "malware.example"},
        ],
    })
    pdns_domain_result = json.dumps({
        "indicator": "malware.example",
        "indicator_type": "domain",
        "resolution_count": 1,
        "resolutions": [
            {"date": "2026-01-01", "resolver": "pdns", "ip_address": "198.51.100.10"},
        ],
    })
    whois_result = json.dumps({
        "domain": "malware.example",
        "source": "rdap",
        "registrar": "BadRegistrar Inc",
        "creation_date": "2025-12-01T00:00:00Z",
        "nameservers": ["ns1.bad-dns.com"],
    })
    cert_result = json.dumps({
        "indicator": "malware.example",
        "indicator_type": "domain",
        "cert_count": 1,
        "certs": [],
        "all_sans": ["malware.example", "malware2.example"],
    })

    with (
        patch(
            "argus.tools.passive_dns.passive_dns_lookup",
            new_callable=AsyncMock,
            side_effect=lambda indicator, indicator_type, **kw: (
                pdns_ip_result if indicator_type == "ip" else pdns_domain_result
            ),
        ),
        patch(
            "argus.tools.certs.ssl_cert_lookup",
            new_callable=AsyncMock,
            return_value=cert_result,
        ),
        patch(
            "argus.tools.whois.whois_lookup",
            new_callable=AsyncMock,
            return_value=whois_result,
        ),
    ):
        result = runner.invoke(app, ["case", "pivot", case_id, "--json"])

    assert result.exit_code == 0, result.output or result.stderr
    payload = json.loads(result.stdout)

    obs_values = {o["canonical_value"] for o in payload["observables"]}
    assert "pivot-host1.example" in obs_values

    rel_types = {r["relationship_type"] for r in payload["relationships"]}
    assert "resolves_to" in rel_types

    ev_sources = {
        ev["metadata"].get("pivot_source")
        for ev in payload["evidence"]
        if ev.get("metadata")
    }
    assert "passive_dns" in ev_sources
    assert "whois" in ev_sources

    whois_ev = next(
        ev for ev in payload["evidence"] if ev.get("metadata", {}).get("pivot_source") == "whois"
    )
    assert "BadRegistrar" in whois_ev["summary"]


def test_case_pivot_skips_already_pivoted_observables(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-vt-key")
    from argus.config.settings import get_settings
    get_settings.cache_clear()

    runner = CliRunner()

    created = runner.invoke(app, ["case", "create", "Pivot dedupe", "--json"])
    case_id = json.loads(created.stdout)["case_id"]
    runner.invoke(
        app,
        ["case", "artifact", case_id, "--text", "malware.example", "--type", "report"],
    )
    runner.invoke(app, ["case", "extract", case_id])

    pdns_result = json.dumps({"indicator": "malware.example", "indicator_type": "domain",
                               "resolution_count": 0, "resolutions": []})
    whois_result = json.dumps({"domain": "malware.example", "registrar": "Reg Inc"})
    cert_result = json.dumps({"indicator": "malware.example", "cert_count": 0, "certs": [],
                               "all_sans": []})

    with (
        patch("argus.tools.passive_dns.passive_dns_lookup", new_callable=AsyncMock,
              return_value=pdns_result) as mock_pdns,
        patch("argus.tools.certs.ssl_cert_lookup", new_callable=AsyncMock,
              return_value=cert_result),
        patch("argus.tools.whois.whois_lookup", new_callable=AsyncMock,
              return_value=whois_result) as mock_whois,
    ):
        runner.invoke(app, ["case", "pivot", case_id])
        first_pdns = mock_pdns.call_count
        first_whois = mock_whois.call_count
        runner.invoke(app, ["case", "pivot", case_id])
        second_pdns = mock_pdns.call_count
        second_whois = mock_whois.call_count

    assert first_pdns == 1
    assert second_pdns == first_pdns
    assert first_whois == 1
    assert second_whois == first_whois


def test_case_analyze_generates_llm_report_and_stores_artifact() -> None:
    runner = CliRunner()

    created = runner.invoke(
        app, ["case", "create", "LLM report test", "--description", "Test case", "--json"]
    )
    case_id = json.loads(created.stdout)["case_id"]
    runner.invoke(
        app,
        ["case", "artifact", case_id, "--text", "CVE-2021-44228 198.51.100.10", "--type", "report"],
    )
    runner.invoke(app, ["case", "extract", case_id])

    fake_report = "# CTI Report\n\nFindings grounded in evidence [ev_xxx]."

    with patch(
        "argus.agents.case_report_agent.CaseReportAgent.generate",
        new_callable=AsyncMock,
        return_value=fake_report,
    ):
        result = runner.invoke(
            app, ["case", "analyze", case_id, "--audience", "cti", "--no-save"]
        )

    assert result.exit_code == 0, result.output or result.stderr
    assert "CTI Report" in result.output or "Findings" in result.output


def test_case_analyze_stores_report_artifact_on_case() -> None:
    runner = CliRunner()

    created = runner.invoke(app, ["case", "create", "Store report", "--json"])
    case_id = json.loads(created.stdout)["case_id"]
    runner.invoke(
        app, ["case", "artifact", case_id, "--text", "198.51.100.10", "--type", "report"]
    )
    runner.invoke(app, ["case", "extract", case_id])

    with patch(
        "argus.agents.case_report_agent.CaseReportAgent.generate",
        new_callable=AsyncMock,
        return_value="# SOC Report\n\nDetection guidance.",
    ):
        result = runner.invoke(
            app, ["case", "analyze", case_id, "--audience", "soc", "--save", "--json"]
        )

    assert result.exit_code == 0, result.output or result.stderr
    payload = json.loads(result.stdout)
    assert payload["report_type"] == "soc"
    assert "SOC Report" in payload["content"]

    shown = runner.invoke(app, ["case", "show", case_id, "--json"])
    shown_payload = json.loads(shown.stdout)
    assert len(shown_payload["reports"]) == 1
    assert shown_payload["reports"][0]["report_type"] == "soc"


def test_case_report_json_output_stores_report_artifact() -> None:
    runner = CliRunner()

    created = runner.invoke(app, ["case", "create", "JSON report test", "--json"])
    case_id = json.loads(created.stdout)["case_id"]

    result = runner.invoke(
        app, ["case", "report", case_id, "--save", "--json"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["report_type"] == "cti"
    assert payload["classification"] == "TLP:AMBER"
    assert "content" in payload

    shown = runner.invoke(app, ["case", "show", case_id, "--json"])
    shown_payload = json.loads(shown.stdout)
    assert len(shown_payload["reports"]) == 1


def test_case_status_transitions() -> None:
    runner = CliRunner()

    created = runner.invoke(app, ["case", "create", "Lifecycle test", "--json"])
    case_id = json.loads(created.stdout)["case_id"]
    assert json.loads(created.stdout)["status"] == "open"

    active = runner.invoke(app, ["case", "status", case_id, "active", "--json"])
    assert active.exit_code == 0
    assert json.loads(active.stdout)["status"] == "active"

    closed = runner.invoke(app, ["case", "status", case_id, "closed", "--json"])
    assert closed.exit_code == 0
    closed_payload = json.loads(closed.stdout)
    assert closed_payload["status"] == "closed"
    assert closed_payload["closed_at"] is not None

    bad_status = runner.invoke(app, ["case", "status", case_id, "nonexistent"])
    assert bad_status.exit_code == 1
    assert "Invalid status" in bad_status.stderr


def test_case_timeline_shows_events_in_order() -> None:
    runner = CliRunner()

    created = runner.invoke(app, ["case", "create", "Timeline test", "--json"])
    case_id = json.loads(created.stdout)["case_id"]
    runner.invoke(
        app, ["case", "artifact", case_id, "--text", "198.51.100.10", "--type", "alert"]
    )
    runner.invoke(app, ["case", "extract", case_id])
    runner.invoke(app, ["case", "note", case_id, "Analyst observation"])
    runner.invoke(
        app, ["case", "pir", case_id, "Who is responsible?", "--priority", "high"]
    )

    result = runner.invoke(app, ["case", "timeline", case_id, "--json"])
    assert result.exit_code == 0
    events = json.loads(result.stdout)
    assert len(events) > 0
    event_types = [e["type"] for e in events]
    assert "case_opened" in event_types
    assert "artifact" in event_types
    assert "note" in event_types
    assert "pir_added" in event_types
    timestamps = [e["ts"] for e in events]
    assert timestamps == sorted(timestamps)


def test_case_analyze_with_review_flag_shows_grounding_result() -> None:
    runner = CliRunner()

    created = runner.invoke(app, ["case", "create", "Review test", "--json"])
    case_id = json.loads(created.stdout)["case_id"]
    runner.invoke(
        app, ["case", "artifact", case_id, "--text", "198.51.100.10 CVE-2021-44228",
               "--type", "report"]
    )
    runner.invoke(app, ["case", "extract", case_id])

    from argus.agents.review_agent import ReviewResult

    with (
        patch(
            "argus.agents.case_report_agent.CaseReportAgent.generate",
            new_callable=AsyncMock,
            return_value="# CTI\n\n198.51.100.10 is malicious [ev_xxx].",
        ),
        patch(
            "argus.agents.review_agent.ReviewAgent._run_structured",
            new_callable=AsyncMock,
            return_value=ReviewResult(
                passed=True,
                grounded_claim_count=1,
                summary="All claims grounded.",
            ),
        ),
    ):
        result = runner.invoke(
            app, ["case", "analyze", case_id, "--audience", "cti", "--review", "--no-save"]
        )

    assert result.exit_code == 0, result.output or result.stderr
    assert "review passed" in result.output or "grounded" in result.output
