"""Integration tests for ThreatActorAgent, VulnIntelAgent, and TriageAgent.

Uses FakeLLMClient from test_base_agent.py pattern — no live LLM calls.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from argus.agents.threat_actor_agent import ThreatActorAgent
from argus.agents.triage_agent import TriageAgent
from argus.agents.vuln_agent import VulnIntelAgent
from argus.llm.client import LLMResponse, TextBlock, ToolUseBlock, Usage

# ---------------------------------------------------------------------------
# Minimal fake LLM (duplicated from test_base_agent pattern for isolation)
# ---------------------------------------------------------------------------


@dataclass
class FakeResponse:
    text: str | None = None
    tool_name: str | None = None
    tool_input: dict[str, Any] = field(default_factory=dict)
    stop_reason: str = "end_turn"

    def to_llm_response(self) -> LLMResponse:
        content: list[Any] = []
        if self.tool_name:
            content.append(ToolUseBlock(name=self.tool_name, input=self.tool_input, id="t1"))
        if self.text is not None:
            content.append(TextBlock(text=self.text))
        return LLMResponse(
            content=content,
            stop_reason=self.stop_reason,
            usage=Usage(input_tokens=10, output_tokens=20),
        )


class FakeLLMClient:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self._responses = responses
        self._index = 0
        self.calls: list[dict[str, Any]] = []

    def create_message(self, **kwargs: Any) -> LLMResponse:
        self.calls.append(kwargs)
        resp = self._responses[min(self._index, len(self._responses) - 1)]
        self._index += 1
        return resp.to_llm_response()


def _patch_agent(agent_cls: type, responses: list[FakeResponse]) -> Any:
    agent = agent_cls.__new__(agent_cls)
    agent.client = FakeLLMClient(responses)
    agent.model = "fake-model"
    agent.progress = None
    return agent


# ---------------------------------------------------------------------------
# ThreatActorAgent
# ---------------------------------------------------------------------------

_THREAT_ACTOR_RESULT = {
    "actors": [
        {
            "name": "Lazarus Group",
            "aliases": ["Hidden Cobra"],
            "nation_state": "DPRK",
            "motivation": "Financial",
            "description": "North Korea-linked APT.",
            "capabilities": [],
            "known_ttps": [],
            "targeted_sectors": [],
            "active_campaigns": [],
            "suspected_attribution": ["North Korea"],
            "iocs": [],
        }
    ],
    "summary": "Lazarus Group is a DPRK-linked APT.",
    "key_findings": ["Financially motivated"],
    "recommended_detections": [],
}


@pytest.mark.asyncio
async def test_threat_actor_agent_returns_typed_result() -> None:
    agent = _patch_agent(ThreatActorAgent, [FakeResponse(text=json.dumps(_THREAT_ACTOR_RESULT))])
    result = await agent.run(query="Lazarus Group")
    assert result.actors[0].name == "Lazarus Group"
    assert result.summary == "Lazarus Group is a DPRK-linked APT."


@pytest.mark.asyncio
async def test_threat_actor_agent_include_ttps_flag_appends_to_prompt() -> None:
    agent = _patch_agent(ThreatActorAgent, [FakeResponse(text=json.dumps(_THREAT_ACTOR_RESULT))])
    await agent.run(query="APT29", include_ttps=True)
    prompt_content = agent.client.calls[0]["messages"][0]["content"]
    assert "MITRE ATT&CK" in prompt_content


@pytest.mark.asyncio
async def test_threat_actor_agent_excludes_ttp_instruction_when_false() -> None:
    agent = _patch_agent(ThreatActorAgent, [FakeResponse(text=json.dumps(_THREAT_ACTOR_RESULT))])
    await agent.run(query="APT29", include_ttps=False)
    prompt_content = agent.client.calls[0]["messages"][0]["content"]
    assert "MITRE ATT&CK" not in prompt_content


@pytest.mark.asyncio
async def test_threat_actor_agent_raises_on_invalid_json() -> None:
    from argus.agents.errors import AgentError

    agent = _patch_agent(ThreatActorAgent, [FakeResponse(text="NOT JSON")])
    with pytest.raises(AgentError):
        await agent.run(query="BadActor")


# ---------------------------------------------------------------------------
# VulnIntelAgent
# ---------------------------------------------------------------------------

_VULN_RESULT = {
    "vulnerabilities": [
        {
            "cve_id": "CVE-2021-44228",
            "description": "Log4Shell RCE.",
            "cvss_score": 10.0,
            "severity": "critical",
            "affected_products": ["Apache Log4j 2.x"],
            "patch_available": True,
            "in_cisa_kev": True,
            "exploit_public": True,
            "patch_notes": "",
            "references": [],
        }
    ],
    "critical_count": 1,
    "actively_exploited": ["CVE-2021-44228"],
    "patch_priority": [],
    "summary": "Log4Shell is critical and actively exploited.",
}


@pytest.mark.asyncio
async def test_vuln_intel_agent_returns_typed_result() -> None:
    agent = _patch_agent(VulnIntelAgent, [FakeResponse(text=json.dumps(_VULN_RESULT))])
    result = await agent.run(cve_ids=["CVE-2021-44228"])
    assert result.vulnerabilities[0].cve_id == "CVE-2021-44228"
    assert result.critical_count == 1
    assert "CVE-2021-44228" in result.actively_exploited


@pytest.mark.asyncio
async def test_vuln_intel_agent_keyword_search_included_in_prompt() -> None:
    agent = _patch_agent(VulnIntelAgent, [FakeResponse(text=json.dumps(_VULN_RESULT))])
    await agent.run(keywords="log4j")
    prompt_content = agent.client.calls[0]["messages"][0]["content"]
    assert "log4j" in prompt_content


@pytest.mark.asyncio
async def test_vuln_intel_agent_raises_on_bad_json() -> None:
    from argus.agents.errors import AgentError

    agent = _patch_agent(VulnIntelAgent, [FakeResponse(text="{bad json")])
    with pytest.raises(AgentError):
        await agent.run(cve_ids=["CVE-2021-99999"])


# ---------------------------------------------------------------------------
# TriageAgent
# ---------------------------------------------------------------------------

_TRIAGE_ALERT = {
    "alert_id": "EDR-001",
    "raw_log": "process_name=powershell.exe command_line=-enc abc",
    "source": "edr",
}

_TRIAGE_RESULT = {
    "triaged_alerts": [
        {
            "alert": _TRIAGE_ALERT,
            "decision": "true_positive",
            "confidence": 0.9,
            "related_techniques": ["T1059.001"],
            "risk_score": 8,
            "analyst_notes": "PowerShell encoded command — likely malicious.",
            "enriched_iocs": [],
            "recommended_actions": ["Isolate host"],
        }
    ],
    "true_positive_count": 1,
    "false_positive_count": 0,
    "needs_investigation_count": 0,
    "high_priority_alerts": ["EDR-001"],
    "summary": "One true positive detected.",
}


@pytest.mark.asyncio
async def test_triage_agent_returns_typed_result() -> None:
    agent = _patch_agent(TriageAgent, [FakeResponse(text=json.dumps(_TRIAGE_RESULT))])
    result = await agent.run(alerts=[_TRIAGE_ALERT])
    assert result.triaged_alerts[0].decision.value == "true_positive"
    assert result.true_positive_count == 1
    assert "EDR-001" in result.high_priority_alerts


@pytest.mark.asyncio
async def test_triage_agent_alert_id_in_prompt() -> None:
    agent = _patch_agent(TriageAgent, [FakeResponse(text=json.dumps(_TRIAGE_RESULT))])
    await agent.run(alerts=[_TRIAGE_ALERT])
    prompt_content = agent.client.calls[0]["messages"][0]["content"]
    assert "EDR-001" in prompt_content


@pytest.mark.asyncio
async def test_triage_agent_context_included_when_provided() -> None:
    agent = _patch_agent(TriageAgent, [FakeResponse(text=json.dumps(_TRIAGE_RESULT))])
    await agent.run(alerts=[_TRIAGE_ALERT], context="IR-2026 ransomware response")
    prompt_content = agent.client.calls[0]["messages"][0]["content"]
    assert "IR-2026" in prompt_content


@pytest.mark.asyncio
async def test_triage_agent_raises_on_invalid_json() -> None:
    from argus.agents.errors import AgentError

    agent = _patch_agent(TriageAgent, [FakeResponse(text="null")])
    with pytest.raises(AgentError):
        await agent.run(alerts=[_TRIAGE_ALERT])
