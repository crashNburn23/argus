"""Tool registry — returns available tool definitions based on configured API keys."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from argus.config.settings import get_settings
from argus.tools import (
    abuseipdb,
    alienvault_otx,
    misp,
    mitre_attack,
    nvd,
    recorded_future,
    shodan,
    siem,
    urlhaus,
    virustotal,
    web_search,
)

# Maps tool name → availability check lambda
_AVAILABILITY: dict[str, Callable[..., bool]] = {
    "virustotal_lookup": lambda s: bool(s.api_key("virustotal")),
    "shodan_lookup": lambda s: bool(s.api_key("shodan")),
    "recorded_future_search": lambda s: bool(s.api_key("recorded_future")),
    "abuseipdb_check": lambda s: bool(s.api_key("abuseipdb")),
    "otx_lookup": lambda s: bool(s.api_key("otx")),
    "misp_search": lambda s: bool(s.misp_url),
    "siem_query": lambda s: bool(s.siem_type),
    # Always available — no key required
    "mitre_attack_lookup": lambda s: True,
    "nvd_cve_lookup": lambda s: True,
    "urlhaus_lookup": lambda s: True,
    "web_search": lambda s: True,
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
}

# Which tools each agent type uses
_AGENT_TOOLS: dict[str, list[str]] = {
    "ioc": [
        "virustotal_lookup", "shodan_lookup", "abuseipdb_check", "otx_lookup", "urlhaus_lookup",
    ],
    "threat_actor": ["mitre_attack_lookup", "otx_lookup", "recorded_future_search", "web_search"],
    "vuln": ["nvd_cve_lookup", "shodan_lookup"],
    "triage": ["virustotal_lookup", "abuseipdb_check", "otx_lookup", "mitre_attack_lookup"],
    "report": [],  # report agent delegates to other agents, no direct API tools
    "orchestrator": [],  # orchestrator uses agents as tools
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
                "mitre_attack_lookup", "nvd_cve_lookup", "urlhaus_lookup", "web_search"
            ) else "API key configured"
        else:
            # Derive a human-readable reason
            if name == "misp_search":
                reason = "MISP_URL not configured"
            elif name == "siem_query":
                reason = "SIEM_TYPE not configured"
            else:
                reason = "API key not configured"
        result.append({"name": name, "available": available, "reason": reason})
    return result


async def dispatch_tool(tool_name: str, tool_input: dict[str, Any]) -> str:
    """Route a Claude tool_use block to the appropriate async function."""
    from argus.tools import (
        abuseipdb,
        alienvault_otx,
        misp,
        mitre_attack,
        nvd,
        recorded_future,
        shodan,
        siem,
        urlhaus,
        virustotal,
        web_search,
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
    }

    handler = _HANDLERS.get(tool_name)
    if handler is None:
        import json
        return json.dumps({"error": f"Unknown tool: {tool_name}"})
    return str(await handler(**tool_input))
