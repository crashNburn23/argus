"""Shodan tool — requires SHODAN_API_KEY."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from argus.config.settings import get_settings
from argus.storage.cache import cache_get, cache_set, get_rate_limiter


def get_tool_definition() -> dict[str, Any]:
    return {
        "name": "shodan_lookup",
        "description": (
            "Query Shodan for host information (open ports, services, vulnerabilities) "
            "or search for hosts exposing a specific CVE."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to look up"},
                "cve": {"type": "string", "description": "CVE ID to search exposed hosts"},
                "query": {"type": "string", "description": "Arbitrary Shodan search query"},
            },
        },
    }


async def shodan_lookup(
    ip: str = "",
    cve: str = "",
    query: str = "",
) -> str:
    indicator = ip or cve or query
    cache_key = f"shodan:{indicator}"
    cached = cache_get(cache_key)
    if cached:
        return json.dumps(cached)

    rl = get_rate_limiter("shodan")
    await rl.wait_and_acquire()
    settings = get_settings()

    try:
        import shodan as shodan_lib

        api = shodan_lib.Shodan(settings.api_key("shodan"))

        if ip:
            host = await asyncio.to_thread(api.host, ip)
            _vulns = host.get("vulns") or {}
            result = {
                "ip": ip,
                "ports": host.get("ports", []),
                "hostnames": host.get("hostnames", []),
                "country": host.get("country_name", ""),
                "org": host.get("org", ""),
                "isp": host.get("isp", ""),
                "os": host.get("os", ""),
                "vulns": list(_vulns.keys() if isinstance(_vulns, dict) else _vulns)[:20],
                "tags": host.get("tags", []),
                "services": [
                    {
                        "port": s.get("port"),
                        "transport": s.get("transport", ""),
                        "product": s.get("product", ""),
                        "version": s.get("version", ""),
                    }
                    for s in host.get("data", [])[:10]
                ],
            }
        elif cve:
            search_result = await asyncio.to_thread(api.search, f"vuln:{cve}", limit=10)
            result = {
                "cve": cve,
                "total_exposed": search_result.get("total", 0),
                "sample_hosts": [
                    {
                        "ip": m.get("ip_str", ""),
                        "country": m.get("location", {}).get("country_name", ""),
                        "org": m.get("org", ""),
                        "ports": [m.get("port")],
                    }
                    for m in search_result.get("matches", [])[:10]
                ],
            }
        elif query:
            search_result = await asyncio.to_thread(api.search, query, limit=10)
            result = {
                "query": query,
                "total": search_result.get("total", 0),
                "sample_hosts": [
                    {
                        "ip": m.get("ip_str", ""),
                        "country": m.get("location", {}).get("country_name", ""),
                        "org": m.get("org", ""),
                        "port": m.get("port"),
                    }
                    for m in search_result.get("matches", [])[:10]
                ],
            }
        else:
            return json.dumps({"error": "Provide ip, cve, or query"})

    except Exception as e:
        msg = str(e)
        if "No information available" in msg or "404" in msg:
            result = {"indicator": indicator, "status": "not_found"}
        else:
            result = {"error": msg, "indicator": indicator, "status": "error"}

    cache_set(cache_key, result, ttl=86400)
    return json.dumps(result)
