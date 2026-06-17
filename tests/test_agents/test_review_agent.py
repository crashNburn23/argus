"""Tests for ReviewAgent claim-grounding checks."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from argus.agents.review_agent import ReviewAgent, ReviewFinding, ReviewResult
from argus.models.case import Case
from argus.models.evidence import EvidenceItem, EvidenceStatus


def _make_case(evidence_summaries: list[str]) -> Case:
    evidence = [
        EvidenceItem(
            source_name="test",
            source_type="enrichment",
            status=EvidenceStatus.CONFIRMED,
            confidence=0.9,
            summary=summary,
        )
        for summary in evidence_summaries
    ]
    return Case(title="Test Case", evidence=evidence)


def _mock_result(**kwargs) -> ReviewResult:
    defaults = {
        "passed": True,
        "grounded_claim_count": 2,
        "ungrounded_claim_count": 0,
        "inferred_claim_count": 0,
        "summary": "All claims grounded.",
        "findings": [],
    }
    defaults.update(kwargs)
    return ReviewResult(**defaults)


@pytest.mark.asyncio
async def test_review_agent_passes_grounded_report() -> None:
    case = _make_case(["AbuseIPDB: 198.51.100.10 abuse score 87/100"])

    passed_result = _mock_result(passed=True, grounded_claim_count=1)

    with patch.object(ReviewAgent, "_run_structured", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = passed_result
        agent = ReviewAgent()
        result = await agent.review(
            report_content="198.51.100.10 was flagged [ev_abc] with abuse score 87.",
            case=case,
        )

    assert result.passed is True
    assert result.ungrounded_claim_count == 0
    mock_run.assert_called_once()


@pytest.mark.asyncio
async def test_review_agent_flags_unsupported_claims() -> None:
    case = _make_case(["AbuseIPDB: 198.51.100.10 abuse score 10/100"])

    failed_result = _mock_result(
        passed=False,
        ungrounded_claim_count=1,
        findings=[
            ReviewFinding(
                claim="APT29 is behind this attack.",
                issue="No actor attribution evidence found in the case.",
                severity="error",
            )
        ],
    )

    with patch.object(ReviewAgent, "_run_structured", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = failed_result
        agent = ReviewAgent()
        result = await agent.review(
            report_content="APT29 is behind this attack. 198.51.100.10 shows low abuse score.",
            case=case,
        )

    assert result.passed is False
    assert len(result.findings) == 1
    assert result.findings[0].severity == "error"
    assert "APT29" in result.findings[0].claim


@pytest.mark.asyncio
async def test_review_agent_accepts_inferred_claims() -> None:
    case = _make_case(["VirusTotal: 0/90 detections for malware.example"])

    with patch.object(ReviewAgent, "_run_structured", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = _mock_result(inferred_claim_count=1, passed=True)
        agent = ReviewAgent()
        result = await agent.review(
            report_content=(
                "malware.example shows no detections [ev_abc]. "
                "The domain may be freshly registered (INFERRED — low confidence)."
            ),
            case=case,
        )

    assert result.passed is True
    assert result.inferred_claim_count == 1
