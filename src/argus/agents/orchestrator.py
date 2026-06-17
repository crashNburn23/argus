"""CTI Orchestrator - routes tasks to specialized agents registered as model tools."""
from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Callable
from typing import Any

import structlog

from argus.agents.errors import AgentError
from argus.agents.ioc_agent import IOCEnrichmentAgent
from argus.agents.threat_actor_agent import ThreatActorAgent
from argus.agents.triage_agent import TriageAgent
from argus.agents.vuln_agent import VulnIntelAgent
from argus.config.settings import get_settings
from argus.llm import create_llm_client
from argus.storage.database import get_session
from argus.storage.models_db import AgentRunRecord
from argus.tools import siem as siem_tool
from argus.tools.registry import _AVAILABILITY

log = structlog.get_logger()

MAX_ITERATIONS = 8
MAX_COMPLETION_RETRIES = 2   # verification cycles after the main loop
MAX_GAP_FILL_ITERATIONS = 4  # agent calls allowed per gap-fill cycle
ProgressCallback = Callable[[str], None]

_SYSTEM = """\
You are the CTI Orchestrator — a senior threat intelligence analyst who coordinates
specialized AI agents to answer complex cybersecurity questions.

You have access to the following tools:
- siem_query: Fetch raw alert and log events from the SIEM (Splunk or configured backend)
- ioc_enrichment_agent: Enrich IPs, domains, URLs, and file hashes against threat feeds
- threat_actor_agent: Research threat actors, campaigns, and MITRE ATT&CK TTPs
- vuln_intel_agent: Look up CVE details, exploitation status, CISA KEV, and exposed systems
- triage_agent: Triage security alerts — requires real alert objects with actual log data

IMPORTANT — fetching SIEM data before triage:
When asked to triage, analyze, or report on SIEM alerts or log events, you MUST call
siem_query first to fetch the actual events. Pass the returned events as the `alerts`
list to triage_agent. Never fabricate alert content — only triage data that siem_query
returned. If siem_query returns an error or no results, report that to the user instead
of inventing alerts.

Decide which tools to invoke based on the user's request. Synthesize results into a
clear, actionable response. Be specific and reference evidence from findings."""

_COMPLETION_CHECK_SYSTEM = """\
You are a senior CTI analyst verifying that an analysis fully answers the original question.

Respond with a JSON object only — no prose, no markdown fences:
{
  "complete": true | false,
  "retriable_gaps": ["description"],
  "permanent_gaps": ["description"]
}

Definitions:
- complete: true only if every distinct part of the original question is addressed.
- retriable_gaps: gaps where invoking an agent with a better or different query is likely
  to yield useful data (the agent was never called, or a different angle may help).
- permanent_gaps: gaps caused by tool errors, API failures, rate limits, or data that
  simply does not exist. Retrying would not help — document them honestly.

Rules:
- "No data found" is a valid answer, not a gap.
- Do NOT mark a gap as retriable if a tool already attempted it and returned an error.
- Prefer marking ambiguous gaps as permanent over triggering endless retries."""

# Sub-agent tool definitions (always present)
_AGENT_TOOL_DEFINITIONS = [
    {
        "name": "ioc_enrichment_agent",
        "description": (
            "Enrich indicators of compromise (IPs, domains, URLs, file hashes) against "
            "VirusTotal, Shodan, AbuseIPDB, AlienVault OTX, and URLhaus."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "indicators": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of IOC values to enrich",
                },
                "ioc_type": {
                    "type": "string",
                    "description": "IOC type hint: auto, ip, domain, url, md5, sha256",
                    "default": "auto",
                },
            },
            "required": ["indicators"],
        },
    },
    {
        "name": "threat_actor_agent",
        "description": (
            "Research threat actors, APT groups, campaigns. Returns TTPs mapped to "
            "MITRE ATT&CK, associated malware, targets, and detection recommendations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Threat actor name, alias, or campaign name to research",
                },
                "include_ttps": {
                    "type": "boolean",
                    "description": "Include MITRE ATT&CK TTP mapping",
                    "default": True,
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "vuln_intel_agent",
        "description": (
            "Look up CVE vulnerability intelligence from NVD and CISA KEV. "
            "Includes CVSS scores, exploitation status, and Shodan exposure counts."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "CVE IDs to look up",
                },
                "keywords": {
                    "type": "string",
                    "description": "Keyword to search vulnerabilities",
                },
                "severity_threshold": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                    "default": "high",
                },
            },
        },
    },
    {
        "name": "triage_agent",
        "description": (
            "Triage raw security alerts. Extracts IOCs, enriches them, correlates with "
            "MITRE ATT&CK, assigns risk scores, and decides TP/FP/NI."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "alerts": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": (
                        "List of alert objects (each needs at minimum alert_id and raw_log)"
                    ),
                },
                "context": {
                    "type": "string",
                    "description": "Additional context about the environment or incident",
                },
            },
            "required": ["alerts"],
        },
    },
]


class CTIOrchestrator:
    def __init__(
        self,
        persistent: bool = False,
        progress: ProgressCallback | None = None,
    ) -> None:
        settings = get_settings()
        self.client = create_llm_client(settings)
        self.model = settings.model
        self._persistent = persistent
        self.progress = progress
        self._conversation: list[dict[str, Any]] = []
        self._agents = {
            "ioc_enrichment_agent": IOCEnrichmentAgent(progress=progress),
            "threat_actor_agent": ThreatActorAgent(progress=progress),
            "vuln_intel_agent": VulnIntelAgent(progress=progress),
            "triage_agent": TriageAgent(progress=progress),
        }
        # Include siem_query as a direct tool when SIEM is configured
        self._tool_definitions = list(_AGENT_TOOL_DEFINITIONS)
        siem_check = _AVAILABILITY.get("siem_query")
        if siem_check and siem_check(settings):
            self._tool_definitions.insert(0, siem_tool.get_tool_definition())

    def _progress(self, message: str) -> None:
        callback = getattr(self, "progress", None)
        if callback is not None:
            callback(message)

    @staticmethod
    def _summarize_agent_input(tool_input: dict[str, Any]) -> str:
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
        return "the current request"

    @property
    def conversation_turns(self) -> int:
        return sum(
            1
            for message in self._conversation
            if message["role"] == "user" and isinstance(message["content"], str)
        )

    def clear_conversation(self) -> None:
        self._conversation.clear()

    async def _invoke_agent(self, tool_name: str, tool_input: dict[str, Any]) -> str:
        detail = self._summarize_agent_input(tool_input)
        self._progress(f"orchestrator: routing {detail} to {tool_name}")
        try:
            if tool_name == "siem_query":
                return await siem_tool.siem_query(**tool_input)
            elif tool_name == "ioc_enrichment_agent":
                result = await self._agents["ioc_enrichment_agent"].run(**tool_input)
            elif tool_name == "threat_actor_agent":
                result = await self._agents["threat_actor_agent"].run(**tool_input)
            elif tool_name == "vuln_intel_agent":
                result = await self._agents["vuln_intel_agent"].run(**tool_input)
            elif tool_name == "triage_agent":
                result = await self._agents["triage_agent"].run(**tool_input)
            else:
                return json.dumps({"error": f"Unknown agent: {tool_name}"})
            self._progress(f"orchestrator: {tool_name} returned findings")
            return str(result.model_dump_json())
        except AgentError as e:
            log.error(
                "orchestrator.agent_error",
                agent=tool_name,
                category=e.category,
                error=str(e),
            )
            return json.dumps(e.to_dict())
        except Exception as e:
            log.error("orchestrator.agent_error", agent=tool_name, error=str(e))
            return json.dumps({"error": True, "agent": tool_name, "message": str(e)})

    async def run(self, user_query: str) -> str:
        start = time.monotonic()
        messages: list[dict[str, Any]] = [
            *getattr(self, "_conversation", []),
            {"role": "user", "content": user_query},
        ]
        total_input = 0
        total_output = 0
        final_text: str | None = None

        log.info("orchestrator.start", query_len=len(user_query))
        self._progress("orchestrator: reading request and selecting analysis path")

        for iteration in range(MAX_ITERATIONS):
            if iteration > 0:
                self._progress("orchestrator: reviewing agent findings")
            response = await asyncio.to_thread(
                self.client.create_message,
                model=self.model,
                max_tokens=8192,
                system=_SYSTEM,
                tools=self._tool_definitions,
                messages=messages,
            )
            total_input += response.usage.input_tokens
            total_output += response.usage.output_tokens

            log.debug(
                "orchestrator.iteration",
                iteration=iteration,
                stop_reason=response.stop_reason,
            )

            if response.stop_reason == "end_turn":
                final_text = "\n".join(
                    b.text for b in response.content if hasattr(b, "text")
                )
                self._progress("orchestrator: composing initial answer")
                if getattr(self, "_persistent", False):
                    self._conversation = [
                        *messages,
                        {"role": "assistant", "content": response.content},
                    ]
                messages.append({"role": "assistant", "content": response.content})
                break

            if response.stop_reason != "tool_use":
                break

            messages.append({"role": "assistant", "content": response.content})
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    log.info("orchestrator.agent_call", agent=block.name)
                    self._progress(f"orchestrator: decided {block.name} is needed")
                    agent_result = await self._invoke_agent(block.name, dict(block.input))
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": agent_result,
                    })
            messages.append({"role": "user", "content": tool_results})

        if final_text is None:
            self._log_run(user_query, "", total_input, total_output, time.monotonic() - start)
            if getattr(self, "_persistent", False):
                self._conversation = messages
            return "Orchestrator could not produce a response."

        # --- Completion verification loop ---
        permanent_gaps: list[str] = []
        for check_attempt in range(MAX_COMPLETION_RETRIES):
            check = await self._check_completion(user_query, final_text, check_attempt)
            log.info(
                "orchestrator.completion_check",
                attempt=check_attempt,
                complete=check["complete"],
                retriable=len(check["retriable_gaps"]),
                permanent=len(check["permanent_gaps"]),
            )

            if check["complete"]:
                self._progress("orchestrator: analysis verified complete")
                permanent_gaps = []
                break

            permanent_gaps = check["permanent_gaps"]

            if not check["retriable_gaps"]:
                self._progress("orchestrator: remaining gaps are not retriable")
                break

            self._progress(
                f"orchestrator: filling {len(check['retriable_gaps'])} gap(s) "
                f"(pass {check_attempt + 1}/{MAX_COMPLETION_RETRIES})"
            )
            updated = await self._fill_gaps(
                user_query, final_text, check["retriable_gaps"]
            )
            if updated is not None:
                final_text = updated
            else:
                self._progress("orchestrator: gap-fill produced no new results")
                break

        if permanent_gaps:
            lines = "\n".join(f"- {g}" for g in permanent_gaps)
            final_text += f"\n\n---\n**Note — could not complete the following:**\n{lines}"

        self._log_run(user_query, final_text, total_input, total_output, time.monotonic() - start)
        return final_text

    async def _check_completion(
        self,
        original_query: str,
        current_answer: str,
        attempt: int,
    ) -> dict[str, Any]:
        """Ask the model to verify the answer covers the original query.

        Returns a dict with keys: complete, retriable_gaps, permanent_gaps.
        Failures default to complete=True so a broken check never loops forever.
        """
        self._progress(
            f"orchestrator: verifying completeness "
            f"(check {attempt + 1}/{MAX_COMPLETION_RETRIES})"
        )
        prompt = (
            f"ORIGINAL QUESTION:\n{original_query}\n\n"
            f"CURRENT ANALYSIS:\n{current_answer}"
        )
        try:
            response = await asyncio.to_thread(
                self.client.create_message,
                model=self.model,
                max_tokens=1024,
                system=_COMPLETION_CHECK_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "\n".join(b.text for b in response.content if hasattr(b, "text")).strip()
            fence = re.search(r"```(?:json)?\s*\n([\s\S]*?)```", text)
            if fence:
                text = fence.group(1).strip()
            data = json.loads(text)
            return {
                "complete": bool(data.get("complete", False)),
                "retriable_gaps": [str(g) for g in data.get("retriable_gaps", [])],
                "permanent_gaps": [str(g) for g in data.get("permanent_gaps", [])],
            }
        except Exception as exc:
            log.warning("orchestrator.completion_check_failed", error=str(exc))
            # Fail safe: treat as complete so we never loop on a broken check
            return {"complete": True, "retriable_gaps": [], "permanent_gaps": []}

    async def _fill_gaps(
        self,
        original_query: str,
        current_answer: str,
        gaps: list[str],
    ) -> str | None:
        """Run a tight agent loop to address specific gaps. Returns updated answer or None."""
        gap_lines = "\n".join(f"- {g}" for g in gaps)
        fill_messages: list[dict[str, Any]] = [
            {
                "role": "user",
                "content": (
                    f"Original question: {original_query}\n\n"
                    f"Current analysis:\n{current_answer}\n\n"
                    f"The following gaps remain unanswered:\n{gap_lines}\n\n"
                    "Use the available agents to address these gaps. "
                    "If a tool returns an error or no data, acknowledge it and move on — "
                    "do not retry a tool that already failed. "
                    "Return a complete, updated analysis that incorporates any new findings."
                ),
            }
        ]
        try:
            for iteration in range(MAX_GAP_FILL_ITERATIONS):
                response = await asyncio.to_thread(
                    self.client.create_message,
                    model=self.model,
                    max_tokens=8192,
                    system=_SYSTEM,
                    tools=self._tool_definitions,
                    messages=fill_messages,
                )
                if response.stop_reason == "end_turn":
                    return "\n".join(
                        b.text for b in response.content if hasattr(b, "text")
                    )
                if response.stop_reason != "tool_use":
                    break
                fill_messages.append({"role": "assistant", "content": response.content})
                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        self._progress(f"orchestrator: gap-fill calling {block.name}")
                        agent_result = await self._invoke_agent(block.name, dict(block.input))
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": agent_result,
                        })
                fill_messages.append({"role": "user", "content": tool_results})
        except Exception as exc:
            log.warning("orchestrator.gap_fill_failed", error=str(exc))
        return None

    def _log_run(
        self, input_data: str, output: str, input_tok: int, output_tok: int, duration: float
    ) -> None:
        try:
            with get_session() as session:
                session.add(AgentRunRecord(
                    agent_name="orchestrator",
                    input_data=input_data[:4096],
                    output_data=output[:4096],
                    model_used=self.model,
                    input_tokens=input_tok,
                    output_tokens=output_tok,
                    duration_seconds=duration,
                ))
        except Exception as e:
            log.warning("orchestrator.log_failed", error=str(e))
