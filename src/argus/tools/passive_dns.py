"""Passive DNS tool — historical DNS resolutions via VirusTotal."""
from __future__ import annotations

import json
from typing import Any

import httpx

from argus.config.settings import get_settings
from argus.storage.cache import cache_get, cache_set, get_rate_limiter

_BASE = "https://www.virustotal.com/api/v3"


def get_tool_definition() -> dict[str, Any]:
    return {
        "name": "passive_dns_lookup",
        "description": (
            "Query passive DNS history for an IP or domain. "
            "IP → returns all hostnames that have resolved to it (infrastructure reuse pivoting). "
            "Domain → returns all IPs it has historically resolved to. "
            "Use to detect shared hosting, fast-flux patterns, and actor infrastructure overlap."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator": {
                    "type": "string",
                    "description": "IP address or domain name",
                },
                "indicator_type": {
                    "type": "string",
                    "enum": ["ip", "domain"],
                    "description": "Type of indicator",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results to return (max 40)",
                    "default": 20,
                },
            },
            "required": ["indicator", "indicator_type"],
        },
    }


async def passive_dns_lookup(
    indicator: str,
    indicator_type: str,
    limit: int = 20,
) -> str:
    cache_key = f"pdns:{indicator_type}:{indicator}"
    cached = cache_get(cache_key)
    if cached:
        return json.dumps(cached)

    rl = get_rate_limiter("virustotal")
    await rl.wait_and_acquire()

    settings = get_settings()
    headers = {"x-apikey": settings.api_key("virustotal")}

    endpoint = (
        f"{_BASE}/ip_addresses/{indicator}/resolutions"
        if indicator_type == "ip"
        else f"{_BASE}/domains/{indicator}/resolutions"
    )

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                endpoint,
                params={"limit": min(limit, 40)},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

        resolutions = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            entry: dict[str, Any] = {
                "date": attrs.get("date"),
                "resolver": attrs.get("resolver", ""),
            }
            if indicator_type == "ip":
                entry["hostname"] = attrs.get("host_name", "")
            else:
                entry["ip_address"] = attrs.get("ip_address", "")
            resolutions.append(entry)

        result: dict[str, Any] = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "resolution_count": len(resolutions),
            "resolutions": resolutions,
        }
    except Exception as e:
        result = {"error": str(e), "indicator": indicator}

    cache_set(cache_key, result, ttl=3600)
    return json.dumps(result)
