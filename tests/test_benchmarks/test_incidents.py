from __future__ import annotations

from argus.benchmarks.incidents import build_expected_report, evaluate_report, load_incident_cases
from argus.reports.generator import ReportGenerator


def test_incident_corpus_loads_with_expected_coverage() -> None:
    cases = load_incident_cases()

    assert len(cases) == 8
    assert {case.expected.decision for case in cases} == {
        "true_positive",
        "false_positive",
        "needs_investigation",
    }
    assert all(case.alerts for case in cases)
    assert all(case.expected.required_actions for case in cases)


def test_reference_reports_receive_full_score() -> None:
    generator = ReportGenerator()

    for case in load_incident_cases():
        report = build_expected_report(case)
        report.content = generator.render(report)
        result = evaluate_report(case, report)

        assert result.score == 1.0, case.case_id
