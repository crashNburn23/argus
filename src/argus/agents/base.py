"""BaseAgent - generic model agentic loop with tool use and run logging."""

from __future__ import annotations

import asyncio
import json
import re
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import date
from typing import Any, TypeVar

import httpx
import json_repair
import structlog
from pydantic import BaseModel
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from argus.agents.errors import AgentError, AgentFailureCategory
from argus.config.settings import get_settings
from argus.llm import create_llm_client
from argus.storage.database import get_session
from argus.storage.models_db import AgentRunRecord

log = structlog.get_logger()

MAX_LOOP_ITERATIONS = 10
MAX_PARSE_RETRIES = 2

T = TypeVar("T", bound=BaseModel)
ProgressCallback = Callable[[str], None]


@retry(
    retry=retry_if_exception_type(
        (
            httpx.ReadTimeout,
            httpx.RemoteProtocolError,
            httpx.ConnectError,
            httpx.ConnectTimeout,
        )
    ),
    wait=wait_exponential(multiplier=2, min=10, max=90),
    stop=stop_after_attempt(
        2
    ),  # 2 attempts max: 1 try + 1 retry. Fail fast; don't queue for hours.
    reraise=True,
)
def _llm_call_sync(fn: Any, **kwargs: Any) -> Any:
    return fn(**kwargs)


async def _llm_call_with_retry(fn: Any, **kwargs: Any) -> Any:
    """Wrap a sync LLM client call with retry on ReadTimeout (load-balancer idle drops)."""
    return await asyncio.to_thread(_llm_call_sync, fn, **kwargs)


class BaseAgent(ABC):
    name: str = "base"

    def __init__(self, progress: ProgressCallback | None = None) -> None:
        settings = get_settings()
        self.client = create_llm_client(settings)
        self.model = settings.model
        self.progress = progress

    def _progress(self, message: str) -> None:
        callback = getattr(self, "progress", None)
        if callback is not None:
            callback(message)

    @staticmethod
    def _summarize_tool_input(tool_input: dict[str, Any]) -> str:
        if indicators := tool_input.get("indicators"):
            return f"{len(indicators)} indicator(s)"
        if cve_ids := tool_input.get("cve_ids"):
            return ", ".join(str(cve) for cve in cve_ids[:3])
        if query := tool_input.get("query"):
            return str(query)[:80]
        if alerts := tool_input.get("alerts"):
            return f"{len(alerts)} alert(s)"
        if keywords := tool_input.get("keywords"):
            return str(keywords)[:80]
        return "request parameters"

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
        log.info("agent.input", agent=self.name, text=input_data[:500])
        excerpt = input_data[:120].replace("\n", " ")
        self._progress(
            f"[{self.name}] asked ({len(input_data)} chars): "
            f"{excerpt}{'…' if len(input_data) > 120 else ''}"
        )

        try:
            for iteration in range(MAX_LOOP_ITERATIONS):
                if iteration > 0:
                    self._progress(f"[{self.name}] thinking (iteration {iteration + 1})")
                system = (
                    f"Today's date is {date.today().isoformat()}.\n\n{self.get_system_prompt()}"
                )
                kwargs: dict[str, Any] = {
                    "model": self.model,
                    "max_tokens": getattr(self, "max_output_tokens", 8192),
                    "system": system,
                    "messages": messages,
                }
                if tools:
                    kwargs["tools"] = tools

                response = await _llm_call_with_retry(self.client.create_message, **kwargs)
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
                    output_text = self._extract_text(response.content)
                    log.info(
                        "agent.output",
                        agent=self.name,
                        tokens=total_output_tokens,
                        text=output_text[:500],
                    )
                    out_excerpt = (output_text[:120] or "(structured output)").replace("\n", " ")
                    self._progress(
                        f"[{self.name}] done ({total_output_tokens} tokens): "
                        f"{out_excerpt}{'…' if len(output_text) > 120 else ''}"
                    )
                    self._log_run(
                        input_data,
                        response.content,
                        total_input_tokens,
                        total_output_tokens,
                        time.monotonic() - start,
                        status="success",
                    )
                    return response.content  # type: ignore[no-any-return]

                if response.stop_reason != "tool_use":
                    self._log_run(
                        input_data,
                        [],
                        total_input_tokens,
                        total_output_tokens,
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
                tool_use_blocks = [b for b in response.content if b.type == "tool_use"]

                async def _call_tool(block: Any) -> dict[str, Any]:
                    detail = self._summarize_tool_input(dict(block.input))
                    log.info("agent.tool_call", agent=self.name, tool=block.name, detail=detail)
                    self._progress(f"[{self.name}] → {block.name}: {detail}")
                    t0 = time.monotonic()
                    try:
                        result_str = await self.dispatch_tool(block.name, dict(block.input))
                        elapsed_ms = int((time.monotonic() - t0) * 1000)
                        try:
                            parsed = json.loads(result_str)
                            if "error" in parsed:
                                tool_status = "error"
                            elif parsed.get("status") in ("no_data", "not_found", "error"):
                                tool_status = parsed["status"]
                            else:
                                tool_status = "ok"
                        except Exception:
                            tool_status = "ok"
                        log.info(
                            "agent.tool_result",
                            agent=self.name,
                            tool=block.name,
                            status=tool_status,
                            duration_ms=elapsed_ms,
                            result_bytes=len(result_str),
                        )
                        self._progress(
                            f"[{self.name}] ← {block.name}: {tool_status} "
                            f"({elapsed_ms}ms, {len(result_str)}B)"
                        )
                    except Exception as e:
                        elapsed_ms = int((time.monotonic() - t0) * 1000)
                        log.warning(
                            "agent.tool_result",
                            agent=self.name,
                            tool=block.name,
                            status="dispatch_error",
                            duration_ms=elapsed_ms,
                            error=str(e),
                        )
                        self._progress(
                            f"[{self.name}] ← {block.name}: dispatch_error ({elapsed_ms}ms) — {e}"
                        )
                        result_str = json.dumps({"error": str(e)})
                    return {"type": "tool_result", "tool_use_id": block.id, "content": result_str}

                tool_results = list(await asyncio.gather(*(_call_tool(b) for b in tool_use_blocks)))
                messages.append({"role": "user", "content": tool_results})

            self._log_run(
                input_data,
                [],
                total_input_tokens,
                total_output_tokens,
                time.monotonic() - start,
                status="failed",
                error_category=AgentFailureCategory.LOOP_EXHAUSTED.value,
            )
            raise AgentError(
                AgentFailureCategory.LOOP_EXHAUSTED,
                self.name,
                f"Agent loop exhausted after {MAX_LOOP_ITERATIONS} iterations without end_turn",
            )

        except AgentError:
            raise
        except Exception as exc:
            log.error(
                "agent.unexpected_error",
                agent=self.name,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            self._log_run(
                input_data,
                [],
                total_input_tokens,
                total_output_tokens,
                time.monotonic() - start,
                status="failed",
                error_category=AgentFailureCategory.LLM_ERROR.value,
            )
            raise AgentError(
                AgentFailureCategory.LLM_ERROR,
                self.name,
                f"{type(exc).__name__}: {exc}",
            ) from exc

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
            self._progress(f"{self.name}: validating response schema")
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
                    self._progress(
                        f"{self.name}: response needs cleanup; retrying parse "
                        f"({attempt + 1}/{max_parse_retries})"
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
                            "Return ONLY a valid JSON object — no markdown fences, no prose. "
                            "Start with `{` and end with `}`. "
                            "You already have all the research from your prior tool calls; "
                            "synthesize it into the required JSON format."
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
            # Pre-quote unquoted snake_case tokens before json_repair sees them —
            # json_repair parses true_positive as bool True, false_positive as False, etc.
            # Cover both value position (after :) and bare array element position (after [ or ,).
            cleaned = re.sub(
                r":\s*([a-z][a-z0-9]*(?:_[a-z0-9]+)+)(\s*[,}\]])",
                r': "\1"\2',
                cleaned,
            )
            cleaned = re.sub(
                r"(?<=[\[,])\s*([a-z][a-z0-9]*(?:_[a-z0-9]+)+)(\s*[,\]])",
                r'"\1"\2',
                cleaned,
            )
            data = json_repair.loads(cleaned)
            if not isinstance(data, dict):
                raise ValueError(f"Expected JSON object, got {type(data).__name__}")
        except Exception as exc:
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
        return "\n".join(block.text for block in content if hasattr(block, "text"))

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
                session.add(
                    AgentRunRecord(
                        agent_name=self.name,
                        input_data=input_data[:4096],
                        output_data=output_text[:4096],
                        model_used=self.model,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        duration_seconds=duration,
                        status=status,
                        error_category=error_category,
                    )
                )
        except Exception as e:
            log.warning("agent.log_run_failed", error=str(e))
