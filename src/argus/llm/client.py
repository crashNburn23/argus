"""Small provider boundary for Anthropic and local Ollama models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol
from uuid import uuid4

import anthropic
import httpx

from argus.config.settings import Settings


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class TextBlock:
    text: str
    type: str = "text"


@dataclass
class ToolUseBlock:
    name: str
    input: dict[str, Any]
    id: str = field(default_factory=lambda: f"tool_{uuid4().hex}")
    type: str = "tool_use"


@dataclass
class LLMResponse:
    content: list[Any]
    stop_reason: str
    usage: Usage


class LLMClient(Protocol):
    def create_message(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, Any] | None = None,
        temperature: float | None = None,
    ) -> LLMResponse: ...


class AnthropicClient:
    def __init__(self, api_key: str) -> None:
        # 30-minute total timeout. Streaming prevents idle LB drops; this caps total inference
        # time for large report prompts (~6KB expected, 8KB worst-case with full evidence load).
        self._client = anthropic.Anthropic(
            api_key=api_key,
            timeout=httpx.Timeout(timeout=1800.0, connect=10.0, read=1800.0),
        )

    def create_message(self, **kwargs: Any) -> LLMResponse:
        # Anthropic's Messages API does not accept Ollama-style structured-output
        # format hints. BaseAgent still validates the returned text against Pydantic.
        kwargs.pop("response_format", None)
        # Anthropic uses float temperature directly; None means use API default (1.0).
        temperature = kwargs.pop("temperature", None)
        if temperature is not None:
            kwargs["temperature"] = temperature
        # Use streaming to prevent load-balancer 300s idle TCP drops.
        # Tokens flow immediately — no silent idle period for the LB to kill.
        with self._client.messages.stream(**kwargs) as stream:
            response = stream.get_final_message()
        return LLMResponse(
            content=response.content,
            stop_reason=response.stop_reason or "",
            usage=Usage(
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
            ),
        )


class OllamaClient:
    def __init__(self, base_url: str, timeout: float) -> None:
        # Ollama is normally local. Ignore ambient proxy variables so a workstation
        # proxy cannot break localhost model calls with unsupported schemes.
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            trust_env=False,
        )

    def create_message(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, Any] | None = None,
        temperature: float | None = None,
    ) -> LLMResponse:
        options: dict[str, Any] = {"num_predict": max_tokens}
        if temperature is not None:
            options["temperature"] = temperature
        payload: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "system", "content": system}, *self._convert_messages(messages)],
            "stream": False,
            "options": options,
        }
        if tools:
            payload["tools"] = [self._convert_tool(tool) for tool in tools]
        if response_format:
            payload["format"] = response_format

        response = self._client.post("/api/chat", json=payload)
        response.raise_for_status()
        data = response.json()
        message = data.get("message", {})

        content: list[Any] = []
        if message.get("content"):
            content.append(TextBlock(text=message["content"]))
        for call in message.get("tool_calls", []):
            function = call.get("function", {})
            content.append(
                ToolUseBlock(
                    id=call.get("id") or f"tool_{uuid4().hex}",
                    name=function.get("name", ""),
                    input=function.get("arguments") or {},
                )
            )

        return LLMResponse(
            content=content,
            stop_reason=(
                "tool_use" if any(block.type == "tool_use" for block in content) else "end_turn"
            ),
            usage=Usage(
                input_tokens=data.get("prompt_eval_count", 0),
                output_tokens=data.get("eval_count", 0),
            ),
        )

    @staticmethod
    def _convert_tool(tool: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "parameters": tool["input_schema"],
            },
        }

    @staticmethod
    def _convert_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        converted: list[dict[str, Any]] = []
        tool_names: dict[str, str] = {}
        for message in messages:
            content = message["content"]
            if isinstance(content, str):
                converted.append({"role": message["role"], "content": content})
                continue

            if message["role"] == "assistant":
                assistant: dict[str, Any] = {"role": "assistant", "content": ""}
                text = [block.text for block in content if getattr(block, "type", "") == "text"]
                assistant["content"] = "\n".join(text)
                calls = []
                for block in content:
                    if getattr(block, "type", "") == "tool_use":
                        tool_names[block.id] = block.name
                        calls.append(
                            {
                                "id": block.id,
                                "type": "function",
                                "function": {"name": block.name, "arguments": block.input},
                            }
                        )
                if calls:
                    assistant["tool_calls"] = calls
                converted.append(assistant)
                continue

            for result in content:
                converted.append(
                    {
                        "role": "tool",
                        "content": result["content"],
                        "tool_name": tool_names.get(result["tool_use_id"], ""),
                    }
                )
        return converted


def create_llm_client(settings: Settings) -> LLMClient:
    if settings.model_provider == "ollama":
        return OllamaClient(settings.ollama_base_url, settings.ollama_timeout_seconds)
    return AnthropicClient(settings.api_key("anthropic"))
