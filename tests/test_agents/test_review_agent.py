"""Tests for ReviewAgent claim-grounding checks."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from argus.agents.review_agent import ReviewAgent, ReviewFinding, ReviewResult
from argus.llm.client import LLMResponse, TextBlock, Usage
from argus.models.case import Case
from argus.models.evidence import EvidenceItem, EvidenceStatus

# ---------------------------------------------------------------------------
# Fake LLM for calibration tests
# ---------------------------------------------------------------------------


@dataclass
class _FakeResp:
    text: str
    stop_reason: str = "end_turn"

    def to_llm_response(self) -> LLMResponse:
        return LLMResponse(
            content=[TextBlock(text=self.text)],
            stop_reason=self.stop_reason,
            usage=Usage(input_tokens=10, output_tokens=20),
        )


class _FakeLLM:
    def __init__(self, responses: list[_FakeResp]) -> None:
        self._responses = responses
        self._index = 0
        self.calls: list[dict[str, Any]] = field(default_factory=list)  # type: ignore[assignment]
        self.calls = []

    def create_message(self, **kwargs: Any) -> LLMResponse:
        self.calls.append(kwargs)
        resp = self._responses[min(self._index, len(self._responses) - 1)]
        self._index += 1
        return resp.to_llm_response()


def _agent_with_fake(responses: list[_FakeResp]) -> ReviewAgent:
    agent = ReviewAgent.__new__(ReviewAgent)
    agent.client = _FakeLLM(responses)
    agent.model = "fake"
    agent.progress = None
    return agent


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


# ---------------------------------------------------------------------------
# Calibration test: ReviewAgent parses structured output correctly when the
# fake LLM returns a known-bad result (report with unsupported claims).
# Verifies the agent's output parsing pipeline, not live LLM judgment.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_review_agent_calibration_unsupported_claim_parsed_correctly() -> None:
    """ReviewAgent must parse a reviewer response that flags an unsupported claim."""
    fake_review_json = json.dumps(
        {
            "passed": False,
            "grounded_claim_count": 1,
            "ungrounded_claim_count": 1,
            "inferred_claim_count": 0,
            "summary": "One claim is unsupported: actor attribution has no evidence basis.",
            "findings": [
                {
                    "claim": "APT41 is responsible for this intrusion.",
                    "issue": "No actor attribution evidence in the case. No evidence ID cites APT41.",  # noqa: E501
                    "evidence_id": "",
                    "severity": "error",
                }
            ],
        }
    )

    case = _make_case(["AbuseIPDB: 203.0.113.5 abuse score 92/100"])
    agent = _agent_with_fake([_FakeResp(text=fake_review_json)])

    result = await agent.review(
        report_content=(
            "203.0.113.5 showed high abuse score [ev_abc]. "
            "APT41 is responsible for this intrusion."
        ),
        case=case,
    )

    assert result.passed is False
    assert result.ungrounded_claim_count == 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == "error"
    assert "APT41" in finding.claim
    assert finding.evidence_id == ""


@pytest.mark.asyncio
async def test_review_agent_calibration_grounded_report_passes() -> None:
    """ReviewAgent parses a passing review response correctly."""
    fake_review_json = json.dumps(
        {
            "passed": True,
            "grounded_claim_count": 2,
            "ungrounded_claim_count": 0,
            "inferred_claim_count": 0,
            "summary": "All claims are grounded in provided evidence.",
            "findings": [],
        }
    )

    case = _make_case(
        [
            "AbuseIPDB: 203.0.113.5 abuse score 92/100",
            "VirusTotal: hash abc123 detected by 45/90 engines",
        ]
    )
    agent = _agent_with_fake([_FakeResp(text=fake_review_json)])

    result = await agent.review(
        report_content=(
            "203.0.113.5 showed high abuse score [ev_abc]. "
            "Hash abc123 was confirmed malicious by 45/90 engines [ev_def]."
        ),
        case=case,
    )

    assert result.passed is True
    assert result.grounded_claim_count == 2
    assert result.findings == []
