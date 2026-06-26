from __future__ import annotations

from argus.benchmarks.reporting import (
    build_reference_report,
    evaluate_reporting,
    load_reporting_cases,
)


def test_reporting_corpus_covers_core_audiences() -> None:
    cases = load_reporting_cases()

    assert len(cases) == 4
    assert {case.audience for case in cases} == {"cti", "soc", "exec", "ir"}
    assert all(case.evidence for case in cases)
    assert all(case.expected.required_facts for case in cases)


def test_reference_reports_receive_full_score() -> None:
    for case in load_reporting_cases():
        result = evaluate_reporting(case, build_reference_report(case))

        assert result.score == 1.0, case.case_id


def test_unknown_citation_and_forbidden_claim_are_penalized() -> None:
    case = load_reporting_cases()[0]
    report = build_reference_report(case) + "\n\nAPT29 owns this cluster [ev_invented]."

    result = evaluate_reporting(case, report)

    assert result.score < 1.0
    assert result.unknown_citations == ["ev_invented"]
    assert result.forbidden_claims_found == ["APT29"]


def test_fact_requires_expected_evidence_on_same_line() -> None:
    case = load_reporting_cases()[0]
    report = build_reference_report(case).replace("[ev_dns_001]", "[ev_cert_001]", 1)

    result = evaluate_reporting(case, report)

    assert "shared host" in result.incorrectly_cited_facts
    assert result.dimensions.fact_coverage == 1.0
    assert result.dimensions.evidence_support < 1.0
