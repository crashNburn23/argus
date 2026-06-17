"""Orchestrator integration tests — no live LLM or feed access."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from argus.agents.errors import AgentError, AgentFailureCategory
from argus.llm.client import LLMResponse, TextBlock, ToolUseBlock, Usage


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
            usage=Usage(input_tokens=5, output_tokens=10),
        )


class FakeLLMClient:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self._responses = responses
        self._index = 0

    def create_message(self, **kwargs: Any) -> LLMResponse:
        resp = self._responses[min(self._index, len(self._responses) - 1)]
        self._index += 1
        return resp.to_llm_response()


def _make_orchestrator(responses: list[FakeResponse]) -> Any:
    """Build a CTIOrchestrator with a fake LLM client, no DB/settings needed."""
    from argus.agents.orchestrator import CTIOrchestrator
    from argus.agents.orchestrator import _AGENT_TOOL_DEFINITIONS
    orch = CTIOrchestrator.__new__(CTIOrchestrator)
    orch.client = FakeLLMClient(responses)
    orch.model = "fake"
    orch._persistent = False
    orch._conversation = []
    orch._agents = {}
    orch._tool_definitions = list(_AGENT_TOOL_DEFINITIONS)
    return orch


@pytest.mark.asyncio
async def test_orchestrator_end_turn_returns_text():
    """Orchestrator returns the text directly when model stops at end_turn."""
    orch = _make_orchestrator([FakeResponse(text="Here is your intel.")])
    result = await orch.run(user_query="What are the latest threats?")
    assert "intel" in result


@pytest.mark.asyncio
async def test_orchestrator_agent_error_returned_as_json_to_model():
    """When a sub-agent raises AgentError, orchestrator sends error JSON back to model."""
    failing_agent = MagicMock()
    failing_agent.run = AsyncMock(
        side_effect=AgentError(AgentFailureCategory.PARSE_ERROR, "ioc_enrichment", "bad JSON")
    )

    orch = _make_orchestrator([
        FakeResponse(
            tool_name="ioc_enrichment_agent",
            tool_input={"indicators": ["1.2.3.4"]},
            stop_reason="tool_use",
        ),
        FakeResponse(text="Agent failed but I can still answer."),
    ])
    orch._agents = {"ioc_enrichment_agent": failing_agent}

    result = await orch.run(user_query="Enrich 1.2.3.4")
    assert "still answer" in result


@pytest.mark.asyncio
async def test_orchestrator_unknown_agent_returns_error():
    orch = _make_orchestrator([
        FakeResponse(tool_name="nonexistent_agent", tool_input={}, stop_reason="tool_use"),
        FakeResponse(text="Unknown agent handled."),
    ])
    result = await orch.run(user_query="call the ghost")
    assert "handled" in result


@pytest.mark.asyncio
async def test_orchestrator_loop_exhaustion_returns_fallback():
    """If model keeps calling tools without end_turn, we get the fallback string."""
    orch = _make_orchestrator(
        [FakeResponse(tool_name="ioc_enrichment_agent", tool_input={}, stop_reason="tool_use")] * 20
    )
    orch._agents = {
        "ioc_enrichment_agent": MagicMock(
            run=AsyncMock(return_value=MagicMock(model_dump_json=lambda: "{}"))
        )
    }
    result = await orch.run(user_query="never ending")
    assert "could not produce" in result.lower()


@pytest.mark.asyncio
async def test_persistent_orchestrator_keeps_and_clears_conversation():
    orch = _make_orchestrator([
        FakeResponse(text="First answer."),
        FakeResponse(text="Second answer."),
    ])
    orch._persistent = True

    await orch.run(user_query="First question")
    await orch.run(user_query="Follow-up question")

    assert orch.conversation_turns == 2
    assert len(orch._conversation) == 4
    orch.clear_conversation()
    assert orch.conversation_turns == 0
