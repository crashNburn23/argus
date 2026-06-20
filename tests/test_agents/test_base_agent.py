"""Integration tests for BaseAgent — uses a fake LLM client, no live calls."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest
from pydantic import BaseModel

from argus.agents.base import BaseAgent
from argus.agents.errors import AgentError, AgentFailureCategory
from argus.llm.client import LLMResponse, TextBlock, ToolUseBlock, Usage

# ---------------------------------------------------------------------------
# Fake LLM infrastructure
# ---------------------------------------------------------------------------


@dataclass
class FakeResponse:
    """One canned response to serve from FakeLLMClient."""

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
    """Returns pre-configured responses in sequence; repeats last if exhausted."""

    def __init__(self, responses: list[FakeResponse]) -> None:
        self._responses = responses
        self._index = 0
        self.calls: list[dict[str, Any]] = []

    def create_message(self, **kwargs: Any) -> LLMResponse:
        self.calls.append(kwargs)
        resp = self._responses[min(self._index, len(self._responses) - 1)]
        self._index += 1
        return resp.to_llm_response()


# ---------------------------------------------------------------------------
# Concrete agent for testing (no tools, just returns text)
# ---------------------------------------------------------------------------


class _SimpleResult(BaseModel):
    value: str
    score: int = 0


class _SimpleAgent(BaseAgent):
    name = "test_agent"

    def get_system_prompt(self) -> str:
        return "Return JSON."

    def get_tool_definitions(self) -> list[dict]:  # type: ignore[override]
        return []

    async def dispatch_tool(self, tool_name: str, tool_input: dict) -> str:  # type: ignore[override]
        return json.dumps({"result": f"tool:{tool_name}"})

    async def run(self, **kwargs: Any) -> Any:  # type: ignore[override]
        raise NotImplementedError


def _make_agent(responses: list[FakeResponse]) -> _SimpleAgent:
    agent = _SimpleAgent.__new__(_SimpleAgent)
    agent.client = FakeLLMClient(responses)
    agent.model = "fake-model"
    return agent


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_structured_success():
    payload = json.dumps({"value": "hello", "score": 42})
    agent = _make_agent([FakeResponse(text=payload)])
    result = await agent._run_structured("do something", _SimpleResult)
    assert result.value == "hello"
    assert result.score == 42


@pytest.mark.asyncio
async def test_run_structured_strips_markdown_fences():
    payload = '```json\n{"value": "fenced", "score": 1}\n```'
    agent = _make_agent([FakeResponse(text=payload)])
    result = await agent._run_structured("do something", _SimpleResult)
    assert result.value == "fenced"


@pytest.mark.asyncio
async def test_run_structured_invalid_json_raises_agent_error():
    agent = _make_agent([FakeResponse(text="not json at all")] * 4)
    with pytest.raises(AgentError) as exc_info:
        await agent._run_structured("do something", _SimpleResult, max_parse_retries=0)
    assert exc_info.value.category == AgentFailureCategory.PARSE_ERROR
    assert exc_info.value.agent == "test_agent"


@pytest.mark.asyncio
async def test_run_structured_schema_validation_failure():
    # JSON parses but missing required field 'value'
    agent = _make_agent([FakeResponse(text='{"score": 5}')] * 4)
    with pytest.raises(AgentError) as exc_info:
        await agent._run_structured("do something", _SimpleResult, max_parse_retries=0)
    assert exc_info.value.category == AgentFailureCategory.VALIDATION_ERROR


@pytest.mark.asyncio
async def test_run_structured_retries_on_bad_json_then_succeeds():
    """First response is garbage; second attempt returns valid JSON after correction."""
    good_payload = json.dumps({"value": "fixed", "score": 7})
    agent = _make_agent(
        [
            FakeResponse(text="oops not json"),
            FakeResponse(text=good_payload),
        ]
    )
    result = await agent._run_structured("do something", _SimpleResult, max_parse_retries=1)
    assert result.value == "fixed"
    # Two calls: one failed parse, one successful
    assert len(agent.client.calls) == 2  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_loop_exhaustion_raises_agent_error():
    """If the model keeps requesting tool_use forever, we raise LOOP_EXHAUSTED."""

    class _ToolAgent(_SimpleAgent):
        def get_tool_definitions(self):
            return [
                {
                    "name": "noop",
                    "description": "x",
                    "input_schema": {"type": "object", "properties": {}},
                }
            ]

        async def dispatch_tool(self, tool_name, tool_input):
            return json.dumps({"ok": True})

    agent = _ToolAgent.__new__(_ToolAgent)
    agent.client = FakeLLMClient([FakeResponse(tool_name="noop", stop_reason="tool_use")] * 20)
    agent.model = "fake"

    with pytest.raises(AgentError) as exc_info:
        await agent._run_loop([{"role": "user", "content": "loop forever"}])
    assert exc_info.value.category == AgentFailureCategory.LOOP_EXHAUSTED


@pytest.mark.asyncio
async def test_unexpected_stop_reason_raises_agent_error():
    agent = _make_agent([FakeResponse(text="hi", stop_reason="max_tokens")])
    with pytest.raises(AgentError) as exc_info:
        await agent._run_loop([{"role": "user", "content": "go"}])
    assert exc_info.value.category == AgentFailureCategory.LLM_ERROR


@pytest.mark.asyncio
async def test_tool_use_then_end_turn():
    """One tool call followed by a text response succeeds."""

    class _ToolAgent(_SimpleAgent):
        def get_tool_definitions(self):
            return [
                {
                    "name": "lookup",
                    "description": "x",
                    "input_schema": {"type": "object", "properties": {}},
                }
            ]

        async def dispatch_tool(self, tool_name, tool_input):
            return json.dumps({"data": "found"})

    good = json.dumps({"value": "enriched", "score": 9})
    agent = _ToolAgent.__new__(_ToolAgent)
    agent.client = FakeLLMClient(
        [
            FakeResponse(tool_name="lookup", stop_reason="tool_use"),
            FakeResponse(text=good),
        ]
    )
    agent.model = "fake"

    result = await agent._run_structured("enrich", _SimpleResult)
    assert result.value == "enriched"
    assert len(agent.client.calls) == 2  # type: ignore[union-attr]


def test_parse_result_empty_text():
    agent = _make_agent([])
    with pytest.raises(AgentError) as exc_info:
        agent._parse_result("", _SimpleResult)
    assert exc_info.value.category == AgentFailureCategory.PARSE_ERROR


def test_agent_error_to_dict():
    err = AgentError(AgentFailureCategory.PARSE_ERROR, "myagent", "bad JSON", raw_output="x")
    d = err.to_dict()
    assert d["error"] is True
    assert d["category"] == "parse_error"
    assert d["agent"] == "myagent"
    assert "bad JSON" in d["message"]  # type: ignore[operator]
