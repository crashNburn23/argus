from __future__ import annotations

import pytest

from argus.benchmarks.pivoting import (
    FixtureDispatcher,
    PivotAnalysisResult,
    PivotObservable,
    evaluate_pivot,
    load_pivot_cases,
)


def test_pivot_corpus_covers_progressive_difficulty() -> None:
    cases = load_pivot_cases()

    assert len(cases) == 3
    assert {case.difficulty for case in cases} == {"direct", "multi_hop", "adversarial"}
    assert all(case.fixtures for case in cases)
    assert all(case.expected.required_tool_calls for case in cases)


@pytest.mark.asyncio
async def test_expected_pivot_graphs_receive_full_score() -> None:
    for case in load_pivot_cases():
        dispatcher = FixtureDispatcher(case)
        for required in case.expected.required_tool_calls:
            fixture = next(
                item
                for item in case.fixtures
                if item.tool == required.tool and required.indicator in item.match.values()
            )
            await dispatcher.dispatch(fixture.tool, fixture.match)

        valid_ref = dispatcher.calls[0].evidence_id
        result = PivotAnalysisResult(
            observables=[
                item.model_copy(update={"evidence_refs": [valid_ref]})
                for item in case.expected.observables
            ],
            relationships=[
                item.model_copy(update={"evidence_refs": [valid_ref]})
                for item in case.expected.relationships
            ],
            attributions=[],
            findings=["Ground-truth benchmark result"],
            report="Ground-truth benchmark report",
        )
        evaluation = evaluate_pivot(case, result, dispatcher.calls)

        assert evaluation.score == 1.0, case.case_id


@pytest.mark.asyncio
async def test_hallucinated_ioc_and_evidence_reduce_score() -> None:
    case = load_pivot_cases()[0]
    dispatcher = FixtureDispatcher(case)
    fixture = case.fixtures[0]
    await dispatcher.dispatch(fixture.tool, fixture.match)
    result = PivotAnalysisResult(
        observables=[
            PivotObservable(
                value="unseen-attacker.test",
                observable_type="domain",
                evidence_refs=["tool_999"],
            )
        ]
    )

    evaluation = evaluate_pivot(case, result, dispatcher.calls)

    assert evaluation.score < 0.5
    assert "unseen-attacker.test:related" in evaluation.unexpected_observables
    assert evaluation.unsupported_evidence_refs == ["tool_999"]


@pytest.mark.asyncio
async def test_fixture_dispatcher_rejects_unavailable_results() -> None:
    case = load_pivot_cases()[0]
    dispatcher = FixtureDispatcher(case)

    result = await dispatcher.dispatch(
        "passive_dns_lookup",
        {"indicator": "invented.test", "indicator_type": "domain"},
    )

    assert "No benchmark fixture" in result
    assert dispatcher.calls[0].matched_fixture is False
