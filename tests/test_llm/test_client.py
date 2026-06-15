from __future__ import annotations

from pytest_httpx import HTTPXMock

from argus.llm.client import OllamaClient, TextBlock, ToolUseBlock


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

    converted = OllamaClient._convert_messages([
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
    ])

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
                "tool_calls": [{
                    "function": {"name": "lookup", "arguments": {"indicator": "1.2.3.4"}},
                }],
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
        tools=[{
            "name": "lookup",
            "description": "Look up an IOC",
            "input_schema": {"type": "object", "properties": {}},
        }],
    )

    assert response.stop_reason == "tool_use"
    assert response.content[0].name == "lookup"
    assert response.usage.input_tokens == 12
