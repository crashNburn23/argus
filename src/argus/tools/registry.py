"""Tool registry — returns available tool definitions based on configured API keys."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from argus.config.settings import get_settings
from argus.tools import (
    abuseipdb,
    alienvault_otx,
    certs,
    misp,
    mitre_attack,
    nvd,
    passive_dns,
    recorded_future,
    shodan,
    siem,
    urlhaus,
    virustotal,
    web_search,
    whois,
)


# Maps tool name → availability check lambda
_AVAILABILITY: dict[str, Callable[..., bool]] = {
    "virustotal_lookup": lambda s: bool(s.api_key("virustotal")),
    "shodan_lookup": lambda s: bool(s.api_key("shodan")),
    "recorded_future_search": lambda s: bool(s.api_key("recorded_future")),
    "abuseipdb_check": lambda s: bool(s.api_key("abuseipdb")),
    "otx_lookup": lambda s: bool(s.api_key("otx")),
    "misp_search": lambda s: bool(s.misp_url),
    # Pivot tools
    "passive_dns_lookup": lambda s: bool(s.api_key("virustotal")),
    "ssl_cert_lookup": lambda s: True,   # crt.sh is always free
    "whois_lookup": lambda s: True,      # RDAP is always free
    "siem_query": lambda s: (
        bool(
            s.siem_url
            and (
                (s.siem_api_key and s.siem_api_key.get_secret_value())
                or (s.splunk_username and s.splunk_password.get_secret_value())
            )
        )
        if s.siem_type.lower() == "splunk"
        else bool(s.siem_log_path)
        if s.siem_type.lower() == "file"
        else bool(s.siem_url)
    ),
    # Always available — no key required
    "mitre_attack_lookup": lambda s: True,
    "nvd_cve_lookup": lambda s: True,
    "urlhaus_lookup": lambda s: True,
    "web_search": lambda s: True,
    "url_fetch": lambda s: True,
}

# Maps tool name → definition getter
_DEFINITIONS: dict[str, Callable[[], dict[str, Any]]] = {
    "virustotal_lookup": virustotal.get_tool_definition,
    "shodan_lookup": shodan.get_tool_definition,
    "recorded_future_search": recorded_future.get_tool_definition,
    "abuseipdb_check": abuseipdb.get_tool_definition,
    "otx_lookup": alienvault_otx.get_tool_definition,
    "misp_search": misp.get_tool_definition,
    "siem_query": siem.get_tool_definition,
    "mitre_attack_lookup": mitre_attack.get_tool_definition,
    "nvd_cve_lookup": nvd.get_tool_definition,
    "urlhaus_lookup": urlhaus.get_tool_definition,
    "web_search": web_search.get_tool_definition,
    "passive_dns_lookup": passive_dns.get_tool_definition,
    "ssl_cert_lookup": certs.get_tool_definition,
    "whois_lookup": whois.get_tool_definition,
    "url_fetch": web_search.get_url_fetch_tool_definition,
}

# Which tools each agent type uses
_AGENT_TOOLS: dict[str, list[str]] = {
    "ioc": [
        "virustotal_lookup", "shodan_lookup", "abuseipdb_check", "otx_lookup", "urlhaus_lookup",
        "passive_dns_lookup", "ssl_cert_lookup", "whois_lookup",
    ],
    "threat_actor": ["mitre_attack_lookup", "otx_lookup", "recorded_future_search", "web_search"],
    "vuln": ["nvd_cve_lookup", "shodan_lookup"],
    "triage": ["virustotal_lookup", "abuseipdb_check", "otx_lookup", "mitre_attack_lookup"],
    "report": ["siem_query"],
    "orchestrator": [],  # orchestrator uses agents as tools
    "case_analysis": [
        "virustotal_lookup", "shodan_lookup", "abuseipdb_check", "otx_lookup", "urlhaus_lookup",
        "passive_dns_lookup", "ssl_cert_lookup", "whois_lookup", "mitre_attack_lookup",
        "recorded_future_search", "web_search", "url_fetch",
    ],
}


def get_available_tools(agent_type: str) -> list[dict[str, Any]]:
    """Return Claude tool definitions for tools that are available for the given agent type."""
    settings = get_settings()
    tool_names = _AGENT_TOOLS.get(agent_type, [])
    result = []
    for name in tool_names:
        check = _AVAILABILITY.get(name)
        defn_fn = _DEFINITIONS.get(name)
        if check and defn_fn and check(settings):
            result.append(defn_fn())
    return result


def get_tool_definitions(agent_type: str) -> list[dict[str, Any]]:
    """Alias for get_available_tools — returns only configured tool definitions."""
    return get_available_tools(agent_type)


def tool_status() -> list[dict[str, Any]]:
    """Return availability info for all registered tools.

    Returns a list of dicts with keys: name, available, reason.
    Used by the /sources command.
    """
    settings = get_settings()
    result = []
    for name, check in _AVAILABILITY.items():
        try:
            available = check(settings)
        except Exception as exc:
            available = False
            result.append({"name": name, "available": False, "reason": str(exc)})
            continue

        if available:
            reason = "ready (no key required)" if check(settings) and name in (
                "mitre_attack_lookup", "nvd_cve_lookup", "urlhaus_lookup",
                "web_search", "url_fetch",
            ) else "API key configured"
        else:
            # Derive a human-readable reason
            if name == "misp_search":
                reason = "MISP_URL not configured"
            elif name == "siem_query":
                siem_type = settings.siem_type.lower()
                if siem_type == "splunk":
                    reason = "SIEM_URL or Splunk credentials not configured"
                elif siem_type == "file":
                    reason = "SIEM_LOG_PATH not configured"
                else:
                    reason = "SIEM_URL not configured"
            else:
                reason = "API key not configured"
        result.append({"name": name, "available": available, "reason": reason})
    return result


async def dispatch_tool(tool_name: str, tool_input: dict[str, Any]) -> str:
    """Route a Claude tool_use block to the appropriate async function."""
    from argus.tools import (
        abuseipdb,
        alienvault_otx,
        certs,
        misp,
        mitre_attack,
        nvd,
        passive_dns,
        recorded_future,
        shodan,
        siem,
        urlhaus,
        virustotal,
        web_search,
        whois,
    )

    _HANDLERS: dict[str, Callable[..., Any]] = {
        "virustotal_lookup": virustotal.virustotal_lookup,
        "shodan_lookup": shodan.shodan_lookup,
        "recorded_future_search": recorded_future.recorded_future_search,
        "abuseipdb_check": abuseipdb.abuseipdb_check,
        "otx_lookup": alienvault_otx.otx_lookup,
        "misp_search": misp.misp_search,
        "siem_query": siem.siem_query,
        "mitre_attack_lookup": mitre_attack.mitre_attack_lookup,
        "nvd_cve_lookup": nvd.nvd_cve_lookup,
        "urlhaus_lookup": urlhaus.urlhaus_lookup,
        "web_search": web_search.web_search,
        "url_fetch": web_search.url_fetch,
        "passive_dns_lookup": passive_dns.passive_dns_lookup,
        "ssl_cert_lookup": certs.ssl_cert_lookup,
        "whois_lookup": whois.whois_lookup,
    }

    handler = _HANDLERS.get(tool_name)
    if handler is None:
        import json
        return json.dumps({"error": f"Unknown tool: {tool_name}"})

    # Normalize mismatched argument names the LLM sometimes produces.
    if tool_name == "recorded_future_search" and "query" in tool_input and "entity" not in tool_input:
        tool_input = {**tool_input, "entity": tool_input.pop("query"), "entity_type": tool_input.get("entity_type", "actor")}
    if tool_name == "ssl_cert_lookup" and "query" in tool_input and "indicator" not in tool_input:
        import json
        return json.dumps({"error": "ssl_cert_lookup requires indicator + indicator_type, not a search query"})
    if tool_name == "passive_dns_lookup" and "ioc_type" in tool_input and "indicator_type" not in tool_input:
        tool_input = {**tool_input, "indicator_type": tool_input.pop("ioc_type")}
    if tool_name == "passive_dns_lookup" and "ip" in tool_input and "indicator" not in tool_input:
        tool_input = {**tool_input, "indicator": tool_input.pop("ip")}

    result = str(await handler(**tool_input))

    # Truncate url_fetch content so sub-agents don't accumulate huge context.
    # Large context (7 articles × 10KB) causes very slow LLM calls.
    if tool_name == "url_fetch":
        import json as _json
        try:
            parsed = _json.loads(result)
            if parsed.get("status") == "ok" and parsed.get("content"):
                content = parsed["content"]
                if len(content) > 4000:
                    parsed["content"] = content[:4000] + "\n[truncated]"
                    result = _json.dumps(parsed)
        except Exception:
            pass

    return result
