from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from pytest_httpx import HTTPXMock

from argus.llm.client import AnthropicClient, OllamaClient, TextBlock, ToolUseBlock


def test_ollama_converts_tools_and_tool_results() -> None:
    tool = {
        "name": "lookup",
        "description": "Look up an IOC",
        "input_schema": {
            "type": "object",
            "properties": {"indicator": {"type": "string"}},
            "required": ["indicator"],
        },
    }
    assert OllamaClient._convert_tool(tool)["function"]["parameters"] == tool["input_schema"]

    converted = OllamaClient._convert_messages(
        [
            {"role": "user", "content": "Check 1.2.3.4"},
            {
                "role": "assistant",
                "content": [
                    TextBlock("Checking."),
                    ToolUseBlock(id="call-1", name="lookup", input={"indicator": "1.2.3.4"}),
                ],
            },
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "call-1", "content": "{}"}],
            },
        ]
    )

    assert converted[1]["tool_calls"][0]["function"]["name"] == "lookup"
    assert converted[2] == {"role": "tool", "content": "{}", "tool_name": "lookup"}


def test_ollama_chat_response_with_tool_call(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        method="POST",
        url="http://localhost:11434/api/chat",
        json={
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "function": {"name": "lookup", "arguments": {"indicator": "1.2.3.4"}},
                    }
                ],
            },
            "prompt_eval_count": 12,
            "eval_count": 5,
        },
    )

    response = OllamaClient("http://localhost:11434", 5).create_message(
        model="qwen3:8b",
        max_tokens=100,
        system="Use tools.",
        messages=[{"role": "user", "content": "Check 1.2.3.4"}],
        tools=[
            {
                "name": "lookup",
                "description": "Look up an IOC",
                "input_schema": {"type": "object", "properties": {}},
            }
        ],
    )

    assert response.stop_reason == "tool_use"
    assert response.content[0].name == "lookup"
    assert response.usage.input_tokens == 12


# ---------------------------------------------------------------------------
# AnthropicClient
# ---------------------------------------------------------------------------


def _mock_anthropic(
    text: str | None = None,
    tool_calls: list | None = None,
    stop_reason: str = "end_turn",
    input_tokens: int = 10,
    output_tokens: int = 20,
) -> AnthropicClient:
    """Build an AnthropicClient whose SDK client is fully mocked."""
    blocks: list[SimpleNamespace] = []
    if text is not None:
        blocks.append(SimpleNamespace(type="text", text=text))
    for call in tool_calls or []:
        blocks.append(
            SimpleNamespace(type="tool_use", id=call["id"], name=call["name"], input=call["input"])
        )

    fake_response = SimpleNamespace(
        content=blocks,
        stop_reason=stop_reason,
        usage=SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens),
    )
    client = AnthropicClient.__new__(AnthropicClient)
    client._client = MagicMock()
    stream_ctx = MagicMock()
    stream_ctx.__enter__ = MagicMock(return_value=stream_ctx)
    stream_ctx.__exit__ = MagicMock(return_value=False)
    stream_ctx.get_final_message = MagicMock(return_value=fake_response)
    client._client.messages.stream = MagicMock(return_value=stream_ctx)
    return client


def test_anthropic_text_response() -> None:
    client = _mock_anthropic(text='{"value": "ok"}')
    response = client.create_message(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system="You are helpful.",
        messages=[{"role": "user", "content": "Answer."}],
    )
    assert response.stop_reason == "end_turn"
    assert response.content[0].text == '{"value": "ok"}'
    assert response.usage.input_tokens == 10
    assert response.usage.output_tokens == 20


def test_anthropic_tool_use_response() -> None:
    client = _mock_anthropic(
        tool_calls=[{"id": "t1", "name": "nvd_cve_lookup", "input": {"cve_id": "CVE-2021-44228"}}],
        stop_reason="tool_use",
    )
    response = client.create_message(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system="Use tools.",
        messages=[{"role": "user", "content": "Look up Log4Shell."}],
        tools=[
            {
                "name": "nvd_cve_lookup",
                "description": "NVD lookup",
                "input_schema": {"type": "object", "properties": {}},
            }
        ],
    )
    assert response.stop_reason == "tool_use"
    assert response.content[0].name == "nvd_cve_lookup"
    assert response.content[0].input == {"cve_id": "CVE-2021-44228"}


def test_anthropic_forwards_kwargs_to_sdk() -> None:
    client = _mock_anthropic(text="done")
    client.create_message(
        model="claude-opus-4-8",
        max_tokens=2048,
        system="sys",
        messages=[{"role": "user", "content": "go"}],
    )
    call_kwargs = client._client.messages.stream.call_args.kwargs
    assert call_kwargs["model"] == "claude-opus-4-8"
    assert call_kwargs["max_tokens"] == 2048
