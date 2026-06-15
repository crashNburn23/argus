"""SIEM connector — supports file, webhook, and api modes via SIEM_TYPE setting."""
from __future__ import annotations

import json
from typing import Any

import httpx

from argus.config.settings import get_settings
from argus.storage.cache import cache_get, cache_set


def get_tool_definition() -> dict[str, Any]:
    return {
        "name": "siem_query",
        "description": (
            "Query the configured SIEM for alerts and log events. "
            "Supports file, webhook, and API SIEM types."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query or filter string"},
                "time_range": {
                    "type": "string",
                    "description": "Time range, e.g. '24h', '7d', '2024-01-01/2024-01-07'",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results",
                    "default": 50,
                },
            },
            "required": ["query"],
        },
    }


async def _query_file(query: str, limit: int) -> list[dict[str, Any]]:
    settings = get_settings()
    log_path = settings.siem_log_path
    if not log_path:
        return [{"error": "SIEM_LOG_PATH not configured"}]

    import os
    if not os.path.exists(log_path):
        return [{"error": f"Log file not found: {log_path}"}]

    results = []
    query_lower = query.lower()
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if query_lower in line.lower():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    results.append({"raw": line})
            if len(results) >= limit:
                break
    return results


async def _query_webhook(query: str, time_range: str, limit: int) -> list[dict[str, Any]]:
    settings = get_settings()
    if not settings.siem_url:
        return [{"error": "SIEM_URL not configured"}]

    headers = {"Content-Type": "application/json"}
    if settings.siem_api_key:
        headers["Authorization"] = f"Bearer {settings.siem_api_key.get_secret_value()}"

    payload = {"query": query, "time_range": time_range, "limit": limit}
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(settings.siem_url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else data.get("results", [data])


async def siem_query(
    query: str,
    time_range: str = "24h",
    limit: int = 50,
) -> str:
    cache_key = f"siem:{query}:{time_range}:{limit}"
    cached = cache_get(cache_key)
    if cached:
        return json.dumps(cached)

    settings = get_settings()
    siem_type = settings.siem_type.lower()

    try:
        if siem_type == "file":
            events = await _query_file(query, limit)
        elif siem_type in ("webhook", "api"):
            events = await _query_webhook(query, time_range, limit)
        else:
            events = [{"error": f"Unsupported SIEM_TYPE: {siem_type}"}]

        result = {
            "query": query,
            "time_range": time_range,
            "total_returned": len(events),
            "events": events[:limit],
        }
    except Exception as e:
        result = {"error": str(e), "query": query}

    cache_set(cache_key, result, ttl=300)
    return json.dumps(result)
