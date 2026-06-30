"""CTI Orchestrator - routes tasks to specialized agents registered as model tools."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

import structlog

from argus.agents.base import _llm_call_with_retry
from argus.agents.case_analysis_agent import CaseAnalysisAgent
from argus.agents.errors import AgentError
from argus.agents.threat_actor_agent import ThreatActorAgent
from argus.agents.triage_agent import TriageAgent
from argus.agents.vuln_agent import VulnIntelAgent
from argus.async_utils import run_sync
from argus.config.settings import get_settings
from argus.llm import create_llm_client
from argus.storage.database import get_session
from argus.storage.models_db import AgentRunRecord

log = structlog.get_logger()

MAX_ITERATIONS = 8
MAX_COMPLETION_RETRIES = 1  # one verification cycle is usually sufficient
MAX_GAP_FILL_ITERATIONS = 2  # limit gap-fill depth to avoid runaway loops
AGENT_TIMEOUT_SECONDS = (
    3600  # hard cutoff per sub-agent call (60 min); streaming prevents idle drops
)
ProgressCallback = Callable[[str], None]

_SYSTEM = """\
You are the CTI Orchestrator — a senior threat intelligence analyst who coordinates
specialized AI agents to answer complex cybersecurity questions.

You have access to the following tools:
- url_fetch: Fetch and return the cleaned text of a specific URL. Use this FIRST when
  the user provides a URL to synthesize or analyze — do not skip or defer this step.
- threat_actor_agent: Research threat actors, campaigns, and MITRE ATT&CK TTPs
- vuln_intel_agent: Look up CVE details, exploitation status, CISA KEV, and exposed systems
- triage_agent: Triage security alerts — requires real alert objects with actual log data
- case_analysis_agent: Enrich and pivot on IOCs (IPs, domains, hashes, URLs) found in
  reports or articles. Performs mandatory infrastructure pivoting. Use when a page or
  report contains indicators that need enrichment.

WORKFLOW — URL QUERIES (highest priority):
1. Call url_fetch on every URL in the user's query before doing anything else.
2. Read the url_fetch result. The result includes:
   - "content": first 3000 chars of the article (truncated for routing)
   - "extracted_iocs": structured IOCs pre-extracted by Python regex — use these as-is.
   From the content, identify:
     - Threat actor name + incident context (e.g. "Icarus extortion group Klue OAuth
       breach June 2026", NOT just "Icarus" which may match unrelated groups)
     - Whether named organizations are report authors/research teams versus adversaries.
       Do not treat phrases like "Adversary Pursuit Group identified..." as actor attribution.
3. In your NEXT response after url_fetch, issue BOTH tool calls in the SAME response:
   - threat_actor_agent: only when a real adversary/threat actor/campaign name is present;
     pass the actor name WITH incident context to disambiguate. If only the reporting team
     is named, do not call threat_actor_agent for that team.
   - case_analysis_agent: pass extracted_iocs.ips, domains, hashes, urls, and ip_ports
     directly from the url_fetch result. Do NOT copy IOC values from the article text
     yourself — use the pre-extracted list. If extracted_iocs is absent, do NOT guess IOCs.
   Issuing both in the same response runs them in parallel — do NOT call one and wait.
4. Synthesize all results. Reference source URLs from agent outputs in your final answer.

ANTI-HALLUCINATION — MANDATORY:
- Report ONLY data returned by tools. Never invent IOC values, actor names, victim names,
  TTPs, or attribution that tools did not return.
- If a tool returns no data or an error, say so explicitly — omitting failures misleads.
- Every attribution claim (actor, campaign, malware family) MUST cite a source URL.
- "No data found" from a tool is a valid and credible answer; do not paper over it.

Synthesize results into a clear, actionable CTI response. Be specific and reference
evidence from tool findings."""

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
- Agent timeouts ("timed out") are ALWAYS permanent — the service is slow or unavailable;
  retrying will time out again. Mark them permanent without exception.
- Prefer marking ambiguous gaps as permanent over triggering endless retries."""

# Sub-agent tool definitions (always present)
_AGENT_TOOL_DEFINITIONS = [
    {
        "name": "url_fetch",
        "description": (
            "Fetch and return the cleaned text content of a specific URL (article, report, "
            "advisory, blog post). Use this FIRST when the user provides a URL to synthesize "
            "or analyze. Do not skip this step. Returns plain text with HTML stripped."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The URL to fetch"},
            },
            "required": ["url"],
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
    {
        "name": "case_analysis_agent",
        "description": (
            "Enrich and pivot on IOCs (IPs, domains, file hashes) extracted from "
            "articles, reports, or advisories. Performs mandatory infrastructure pivoting: "
            "passive DNS, WHOIS, certificate SANs, VirusTotal, Shodan. Use when a URL or "
            "report contains indicators that need enrichment. Call simultaneously with "
            "threat_actor_agent when both actor info and IOCs are present. "
            "IMPORTANT: Only list IOCs that appear verbatim in the fetched article. "
            "Never infer, estimate, or placeholder IOC values."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ips": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "IP addresses found verbatim in the article text. "
                        "Omit if none are present — do NOT invent or estimate IPs."
                    ),
                },
                "domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Domain names found verbatim in the article text. Omit if none are present."
                    ),
                },
                "hashes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "File hashes (MD5/SHA256) found verbatim in the article.",
                },
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "URLs found verbatim or de-fanged in the article.",
                },
                "ip_ports": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "IP:port endpoints found verbatim in the article.",
                },
                "context": {
                    "type": "string",
                    "description": (
                        "Brief description of the incident and source URL, "
                        "e.g. 'Klue OAuth breach by Icarus, source: https://...'"
                    ),
                },
            },
            "required": ["context"],
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
            "threat_actor_agent": ThreatActorAgent(progress=progress),
            "vuln_intel_agent": VulnIntelAgent(progress=progress),
            "triage_agent": TriageAgent(progress=progress),
            "case_analysis_agent": CaseAnalysisAgent(progress=progress),
        }
        self._tool_definitions = list(_AGENT_TOOL_DEFINITIONS)

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

    # Public IPs only (RFC1918/loopback excluded).
    _IP_PATTERN = (
        r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    )
    _IP_RE = re.compile(rf"\b{_IP_PATTERN}\b")
    _IP_PORT_RE = re.compile(rf"\b({_IP_PATTERN}):([1-9]\d{{0,4}})\b")
    _HASH_RE = re.compile(
        r"\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b"
    )
    _URL_RE = re.compile(r"\b(?:hxxps?|https?)://[^\s<>()\"']+", re.IGNORECASE)
    _DOMAIN_RE = re.compile(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,63}\b"
    )
    _DOMAIN_NOISE_TLDS = {
        "bmp",
        "css",
        "dll",
        "exe",
        "gif",
        "html",
        "ico",
        "jpg",
        "jpeg",
        "js",
        "json",
        "log",
        "png",
        "ps1",
        "py",
        "svg",
        "txt",
        "xml",
        "zip",
    }

    @staticmethod
    def _dedupe_limit(values: list[str], limit: int) -> list[str]:
        cleaned = [v.strip().strip(".,;:)]}>\"'") for v in values if v.strip()]
        return list(dict.fromkeys(v for v in cleaned if v))[:limit]

    @staticmethod
    def _refang(text: str) -> str:
        text = re.sub(r"hxxps?://", lambda m: m.group(0).replace("hxxp", "http"), text, flags=re.I)
        text = re.sub(r"\[\.\]|\(\.\)|\{\.}|\\\.", ".", text)
        return text

    @classmethod
    def _is_public_ip(cls, value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )

    @classmethod
    def _is_material_domain(cls, domain: str, source_host: str | None) -> bool:
        lowered = domain.lower().strip(".")
        if source_host and (lowered == source_host or lowered.endswith(f".{source_host}")):
            return False
        if lowered.split(".")[-1] in cls._DOMAIN_NOISE_TLDS:
            return False
        if lowered.startswith(("www.", "cdn.", "api.")) and source_host:
            host_base = source_host.removeprefix("www.")
            if lowered.endswith(host_base):
                return False
        return True

    @staticmethod
    def _is_material_url(url: str, source_host: str | None) -> bool:
        if not source_host:
            return True
        host = urlparse(url).netloc.lower().removeprefix("www.")
        return not (host == source_host or host.endswith(f".{source_host}"))

    @classmethod
    def _extract_iocs_from_text(
        cls, text: str, source_url: str | None = None
    ) -> dict[str, list[str]]:
        refanged = cls._refang(text)
        source_host = None
        if source_url:
            source_host = urlparse(source_url).netloc.lower().removeprefix("www.") or None

        ips = [ip for ip in cls._IP_RE.findall(refanged) if cls._is_public_ip(ip)]
        ip_ports = [
            f"{ip}:{port}"
            for ip, port in cls._IP_PORT_RE.findall(refanged)
            if int(port) <= 65535 and cls._is_public_ip(ip)
        ]
        hashes = cls._HASH_RE.findall(refanged)
        urls = [
            url
            for url in cls._URL_RE.findall(refanged)
            if cls._is_material_url(url, source_host)
        ]
        domains = [
            domain.lower()
            for domain in cls._DOMAIN_RE.findall(refanged)
            if cls._is_material_domain(domain, source_host)
        ]

        return {
            "ips": cls._dedupe_limit(ips, 50),
            "ip_ports": cls._dedupe_limit(ip_ports, 50),
            "domains": cls._dedupe_limit(domains, 100),
            "hashes": cls._dedupe_limit(hashes, 100),
            "urls": cls._dedupe_limit(urls, 50),
        }

    async def _invoke_agent(self, tool_name: str, tool_input: dict[str, Any]) -> str:
        from argus.tools.web_search import url_fetch as _url_fetch

        detail = self._summarize_agent_input(tool_input)
        _ips = tool_input.get("ips") or []
        query_str = (
            tool_input.get("url")
            or tool_input.get("query")
            or (", ".join(str(ip) for ip in _ips[:4]) if _ips else None)
            or ", ".join(str(c) for c in (tool_input.get("cve_ids") or [])[:5])
            or detail
        )
        log.info("orchestrator.routing", agent=tool_name, query=str(query_str)[:200])
        self._progress(f"[orchestrator] → {tool_name}: {str(query_str)[:120]}")
        # Tools that return plain strings (not Pydantic models)
        _STRING_TOOLS = {"url_fetch", "case_analysis_agent"}
        try:
            if tool_name == "url_fetch":
                raw_result = await _url_fetch(**tool_input)
                try:
                    parsed = json.loads(raw_result)
                    if parsed.get("status") == "ok" and parsed.get("content"):
                        content = parsed["content"]
                        extracted = self._extract_iocs_from_text(content, parsed.get("url"))
                        if any(extracted.values()):
                            parsed["extracted_iocs"] = extracted
                            log.info(
                                "orchestrator.ioc_extract",
                                ips=extracted["ips"],
                                domains=extracted["domains"],
                                hashes=len(extracted["hashes"]),
                                count=sum(len(v) for v in extracted.values()),
                            )
                        # Truncate article for orchestrator routing context —
                        # extracted_iocs carries the structured data; agents can
                        # url_fetch the full article themselves if they need it.
                        if len(content) > 3000:
                            parsed["content"] = content[:3000] + "\n[truncated for routing]"
                        raw_result = json.dumps(parsed)
                except Exception:
                    pass
                coro_result = raw_result
                result_str = coro_result
                log.info("orchestrator.agent_result", agent=tool_name, result_bytes=len(result_str))
                self._progress(f"[orchestrator] ← {tool_name}: complete ({len(result_str)}B)")
                return result_str
            elif tool_name == "threat_actor_agent":
                coro = self._agents["threat_actor_agent"].run(**tool_input)
            elif tool_name == "vuln_intel_agent":
                coro = self._agents["vuln_intel_agent"].run(**tool_input)
            elif tool_name == "triage_agent":
                coro = self._agents["triage_agent"].run(**tool_input)
            elif tool_name == "case_analysis_agent":
                # Build structured query from typed IOC fields (new schema)
                ips = tool_input.get("ips") or []
                domains = tool_input.get("domains") or []
                hashes = tool_input.get("hashes") or []
                urls = tool_input.get("urls") or []
                ip_ports = tool_input.get("ip_ports") or []
                context = tool_input.get("context") or tool_input.get("query") or ""
                parts = [context]
                if ips:
                    parts.append(f"IPs: {', '.join(str(ip) for ip in ips)}")
                if ip_ports:
                    parts.append(f"IP:port endpoints: {', '.join(str(ep) for ep in ip_ports)}")
                if domains:
                    parts.append(f"Domains: {', '.join(str(d) for d in domains)}")
                if hashes:
                    parts.append(f"Hashes: {', '.join(str(h) for h in hashes)}")
                if urls:
                    parts.append(f"URLs: {', '.join(str(u) for u in urls)}")
                coro = self._agents["case_analysis_agent"].run(query=". ".join(parts))
            else:
                return json.dumps({"error": f"Unknown agent: {tool_name}"})
            result = await asyncio.wait_for(coro, timeout=AGENT_TIMEOUT_SECONDS)
            from pydantic import BaseModel as _BM

            result_str = str(result.model_dump_json()) if isinstance(result, _BM) else str(result)
            log.info("orchestrator.agent_result", agent=tool_name, result_bytes=len(result_str))
            self._progress(f"[orchestrator] ← {tool_name}: complete ({len(result_str)}B)")
            return result_str
        except TimeoutError:
            log.error("orchestrator.agent_error", agent=tool_name, error="timed out")
            return json.dumps({"error": True, "agent": tool_name, "message": "timed out"})
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
        log.info("orchestrator.input", text=user_query[:500])
        q_excerpt = user_query[:120].replace("\n", " ")
        self._progress(
            f"[orchestrator] question ({len(user_query)} chars): "
            f"{q_excerpt}{'…' if len(user_query) > 120 else ''}"
        )

        for iteration in range(MAX_ITERATIONS):
            if iteration > 0:
                self._progress("orchestrator: reviewing agent findings")
            response = await _llm_call_with_retry(
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
                ).strip()
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
            tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
            for block in tool_use_blocks:
                log.info("orchestrator.agent_call", agent=block.name)
                self._progress(f"orchestrator: decided {block.name} is needed")

            async def _call_agent(block: Any) -> dict[str, Any]:
                result = await self._invoke_agent(block.name, dict(block.input))
                return {"type": "tool_result", "tool_use_id": block.id, "content": result}

            tool_results = list(await asyncio.gather(*(_call_agent(b) for b in tool_use_blocks)))
            messages.append({"role": "user", "content": tool_results})

        if final_text is None:
            self._log_run(user_query, "", total_input, total_output, time.monotonic() - start)
            if getattr(self, "_persistent", False):
                self._conversation = messages
            return "Orchestrator could not produce a response."

        if not final_text:
            fallback = self._fallback_from_tool_results(messages)
            final_text = (
                fallback
                or "Orchestrator completed, but the model returned an empty response."
            )
            log.warning("orchestrator.empty_final_response")

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
            updated = await self._fill_gaps(user_query, final_text, check["retriable_gaps"])
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

    @staticmethod
    def _fallback_from_tool_results(messages: list[dict[str, Any]]) -> str:
        tool_outputs: list[str] = []
        for message in reversed(messages):
            content = message.get("content")
            if not isinstance(content, list):
                continue
            for item in content:
                if isinstance(item, dict) and item.get("type") == "tool_result":
                    text = str(item.get("content", "")).strip()
                    if text:
                        tool_outputs.append(text[:1200])
            if tool_outputs:
                break
        if not tool_outputs:
            return ""
        joined = "\n\n".join(tool_outputs[:3])
        return (
            "The model completed without a narrative response. "
            "Latest tool output is below for analyst review:\n\n"
            f"```json\n{joined}\n```"
        )

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
            f"orchestrator: verifying completeness (check {attempt + 1}/{MAX_COMPLETION_RETRIES})"
        )
        prompt = f"ORIGINAL QUESTION:\n{original_query}\n\nCURRENT ANALYSIS:\n{current_answer}"
        try:
            response = await _llm_call_with_retry(
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
                response = await run_sync(
                    self.client.create_message,
                    model=self.model,
                    max_tokens=8192,
                    system=_SYSTEM,
                    tools=self._tool_definitions,
                    messages=fill_messages,
                )
                if response.stop_reason == "end_turn":
                    return "\n".join(b.text for b in response.content if hasattr(b, "text"))
                if response.stop_reason != "tool_use":
                    break
                fill_messages.append({"role": "assistant", "content": response.content})
                fill_blocks = [b for b in response.content if b.type == "tool_use"]
                for block in fill_blocks:
                    self._progress(f"orchestrator: gap-fill calling {block.name}")

                async def _call_fill(block: Any) -> dict[str, Any]:
                    result = await self._invoke_agent(block.name, dict(block.input))
                    return {"type": "tool_result", "tool_use_id": block.id, "content": result}

                tool_results = list(await asyncio.gather(*(_call_fill(b) for b in fill_blocks)))
                fill_messages.append({"role": "user", "content": tool_results})
        except Exception as exc:
            log.warning("orchestrator.gap_fill_failed", error=str(exc))
        return None

    def _log_run(
        self, input_data: str, output: str, input_tok: int, output_tok: int, duration: float
    ) -> None:
        try:
            with get_session() as session:
                session.add(
                    AgentRunRecord(
                        agent_name="orchestrator",
                        input_data=input_data[:4096],
                        output_data=output[:4096],
                        model_used=self.model,
                        input_tokens=input_tok,
                        output_tokens=output_tok,
                        duration_seconds=duration,
                    )
                )
        except Exception as e:
            log.warning("orchestrator.log_failed", error=str(e))
