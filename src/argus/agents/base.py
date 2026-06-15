"""BaseAgent - generic model agentic loop with tool use and run logging."""
from __future__ import annotations

import asyncio
import json
import re
import time
from abc import ABC, abstractmethod
from typing import Any, TypeVar

import structlog
from pydantic import BaseModel

from argus.agents.errors import AgentError, AgentFailureCategory
from argus.config.settings import get_settings
from argus.llm import create_llm_client
from argus.storage.database import get_session
from argus.storage.models_db import AgentRunRecord

log = structlog.get_logger()

MAX_LOOP_ITERATIONS = 10
MAX_PARSE_RETRIES = 2

T = TypeVar("T", bound=BaseModel)


class BaseAgent(ABC):
    name: str = "base"

    def __init__(self) -> None:
        settings = get_settings()
        self.client = create_llm_client(settings)
        self.model = settings.model

    @abstractmethod
    def get_system_prompt(self) -> str: ...

    @abstractmethod
    def get_tool_definitions(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    async def dispatch_tool(self, tool_name: str, tool_input: dict[str, Any]) -> str: ...

    @abstractmethod
    async def run(self, **kwargs: Any) -> Any: ...

    async def _run_loop(self, messages: list[dict[str, Any]]) -> list[Any]:
        """Run the model tool-use loop. Returns final content blocks or raises AgentError."""
        start = time.monotonic()
        tools = self.get_tool_definitions()
        total_input_tokens = 0
        total_output_tokens = 0
        input_data = str(messages[0]["content"])[:4096] if messages else ""

        log.info("agent.start", agent=self.name, prompt_len=len(input_data))

        for iteration in range(MAX_LOOP_ITERATIONS):
            kwargs: dict[str, Any] = {
                "model": self.model,
                "max_tokens": 8192,
                "system": self.get_system_prompt(),
                "messages": messages,
            }
            if tools:
                kwargs["tools"] = tools

            response = await asyncio.to_thread(self.client.create_message, **kwargs)
            total_input_tokens += response.usage.input_tokens
            total_output_tokens += response.usage.output_tokens

            log.debug(
                "agent.iteration",
                agent=self.name,
                iteration=iteration,
                stop_reason=response.stop_reason,
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
            )

            if response.stop_reason == "end_turn":
                self._log_run(
                    input_data, response.content,
                    total_input_tokens, total_output_tokens,
                    time.monotonic() - start,
                    status="success",
                )
                return response.content

            if response.stop_reason != "tool_use":
                self._log_run(
                    input_data, [],
                    total_input_tokens, total_output_tokens,
                    time.monotonic() - start,
                    status="failed",
                    error_category=AgentFailureCategory.LLM_ERROR.value,
                )
                raise AgentError(
                    AgentFailureCategory.LLM_ERROR,
                    self.name,
                    f"Unexpected stop reason: {response.stop_reason!r}",
                )

            messages.append({"role": "assistant", "content": response.content})
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    log.info("agent.tool_call", agent=self.name, tool=block.name)
                    try:
                        result_str = await self.dispatch_tool(block.name, dict(block.input))
                    except Exception as e:
                        result_str = json.dumps({"error": str(e)})
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_str,
                    })
            messages.append({"role": "user", "content": tool_results})

        self._log_run(
            input_data, [],
            total_input_tokens, total_output_tokens,
            time.monotonic() - start,
            status="failed",
            error_category=AgentFailureCategory.LOOP_EXHAUSTED.value,
        )
        raise AgentError(
            AgentFailureCategory.LOOP_EXHAUSTED,
            self.name,
            f"Agent loop exhausted after {MAX_LOOP_ITERATIONS} iterations without end_turn",
        )

    async def _run_structured(
        self,
        user_prompt: str,
        result_cls: type[T],
        max_parse_retries: int = MAX_PARSE_RETRIES,
    ) -> T:
        """Run the agent loop and parse structured output, retrying on invalid JSON."""
        messages: list[dict[str, Any]] = [{"role": "user", "content": user_prompt}]
        last_error: AgentError | None = None

        for attempt in range(max_parse_retries + 1):
            # Pass a copy so each retry starts from the accumulated messages, not a
            # polluted mid-loop state left by the previous attempt's tool calls.
            content = await self._run_loop(list(messages))
            text = self._extract_text(content)
            try:
                return self._parse_result(text, result_cls)
            except AgentError as exc:
                last_error = exc
                if attempt < max_parse_retries:
                    log.warning(
                        "agent.parse_retry",
                        agent=self.name,
                        attempt=attempt + 1,
                        error=str(exc),
                    )
                    messages.append({"role": "assistant", "content": content})
                    if exc.category == AgentFailureCategory.VALIDATION_ERROR:
                        schema = result_cls.model_json_schema()
                        required = schema.get("required", list(schema.get("properties", {}).keys()))
                        correction = (
                            f"Your JSON did not match the required schema: {exc}\n"
                            f"The top-level object MUST contain these fields: {required}\n"
                            "Do not return raw tool results. Synthesize all findings into"
                            " the required schema and return that JSON object only."
                        )
                    else:
                        correction = (
                            f"Your response could not be parsed as JSON: {exc}\n"
                            "Return ONLY a valid JSON object — no markdown fences, no prose."
                        )
                    messages.append({"role": "user", "content": correction})

        raise last_error  # type: ignore[misc]

    def _parse_result(self, text: str, result_cls: type[T]) -> T:
        """Parse and validate text as result_cls, raising AgentError on failure."""
        cleaned = self._strip_fences(text)
        if not cleaned:
            raise AgentError(
                AgentFailureCategory.PARSE_ERROR,
                self.name,
                "Empty response from model",
                raw_output=text[:500],
            )
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise AgentError(
                AgentFailureCategory.PARSE_ERROR,
                self.name,
                f"JSON parse error: {exc}",
                raw_output=text[:500],
            ) from exc
        try:
            return result_cls(**data)
        except Exception as exc:
            raise AgentError(
                AgentFailureCategory.VALIDATION_ERROR,
                self.name,
                f"Schema validation error: {exc}",
                raw_output=text[:500],
            ) from exc

    @staticmethod
    def _strip_fences(text: str) -> str:
        """Remove markdown code fences if present."""
        text = text.strip()
        match = re.search(r"```(?:json)?\s*\n([\s\S]*?)```", text)
        if match:
            return match.group(1).strip()
        return text

    def _extract_text(self, content: list[Any]) -> str:
        return "\n".join(
            block.text for block in content if hasattr(block, "text")
        )

    def _log_run(
        self,
        input_data: str,
        output_content: list[Any],
        input_tokens: int,
        output_tokens: int,
        duration: float,
        status: str = "success",
        error_category: str | None = None,
    ) -> None:
        try:
            output_text = self._extract_text(output_content)
            with get_session() as session:
                session.add(AgentRunRecord(
                    agent_name=self.name,
                    input_data=input_data[:4096],
                    output_data=output_text[:4096],
                    model_used=self.model,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    duration_seconds=duration,
                    status=status,
                    error_category=error_category,
                ))
        except Exception as e:
            log.warning("agent.log_run_failed", error=str(e))
