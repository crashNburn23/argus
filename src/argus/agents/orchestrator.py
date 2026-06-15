"""CTI Orchestrator - routes tasks to specialized agents registered as model tools."""
from __future__ import annotations

import asyncio
import json
import time
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

log = structlog.get_logger()

MAX_ITERATIONS = 8

_SYSTEM = """\
You are the CTI Orchestrator — a senior threat intelligence analyst who coordinates
specialized AI agents to answer complex cybersecurity questions.

You have access to the following specialized agents as tools:
- ioc_enrichment_agent: Enrich IPs, domains, URLs, and file hashes against multiple threat feeds
- threat_actor_agent: Research threat actors, campaigns, and MITRE ATT&CK TTPs
- vuln_intel_agent: Look up CVE details, exploitation status, CISA KEV, and exposed systems
- triage_agent: Triage security alerts, extract and enrich IOCs, assign risk scores

Decide which agents to invoke based on the user's request. You can invoke multiple agents.
Synthesize their results into a clear, actionable response.
Be specific and reference evidence from the agents' findings."""

# Tool definitions for each sub-agent (registered as Claude tools)
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
    def __init__(self, persistent: bool = False) -> None:
        settings = get_settings()
        self.client = create_llm_client(settings)
        self.model = settings.model
        self._persistent = persistent
        self._conversation: list[dict[str, Any]] = []
        self._agents = {
            "ioc_enrichment_agent": IOCEnrichmentAgent(),
            "threat_actor_agent": ThreatActorAgent(),
            "vuln_intel_agent": VulnIntelAgent(),
            "triage_agent": TriageAgent(),
        }

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
        try:
            if tool_name == "ioc_enrichment_agent":
                result = await self._agents["ioc_enrichment_agent"].run(**tool_input)
            elif tool_name == "threat_actor_agent":
                result = await self._agents["threat_actor_agent"].run(**tool_input)
            elif tool_name == "vuln_intel_agent":
                result = await self._agents["vuln_intel_agent"].run(**tool_input)
            elif tool_name == "triage_agent":
                result = await self._agents["triage_agent"].run(**tool_input)
            else:
                return json.dumps({"error": f"Unknown agent: {tool_name}"})
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

        log.info("orchestrator.start", query_len=len(user_query))

        for iteration in range(MAX_ITERATIONS):
            response = await asyncio.to_thread(
                self.client.create_message,
                model=self.model,
                max_tokens=8192,
                system=_SYSTEM,
                tools=_AGENT_TOOL_DEFINITIONS,
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
                if getattr(self, "_persistent", False):
                    self._conversation = [
                        *messages,
                        {"role": "assistant", "content": response.content},
                    ]
                self._log_run(user_query, final_text, total_input, total_output,
                              time.monotonic() - start)
                return final_text

            if response.stop_reason != "tool_use":
                break

            messages.append({"role": "assistant", "content": response.content})
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    log.info("orchestrator.agent_call", agent=block.name)
                    agent_result = await self._invoke_agent(block.name, dict(block.input))
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": agent_result,
                    })
            messages.append({"role": "user", "content": tool_results})

        self._log_run(user_query, "", total_input, total_output, time.monotonic() - start)
        if getattr(self, "_persistent", False):
            self._conversation = messages
        return "Orchestrator could not produce a response."

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
