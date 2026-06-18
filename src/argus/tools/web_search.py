"""Web/OSINT search tool — real DuckDuckGo results via duckduckgo-search."""
from __future__ import annotations

import asyncio
import json
from typing import Any

from ddgs import DDGS

from argus.storage.cache import cache_get, cache_set


def get_tool_definition() -> dict[str, Any]:
    return {
        "name": "web_search",
        "description": (
            "Search the web for OSINT information about threat actors, campaigns, "
            "malware families, ransomware groups, or recent cybersecurity news. "
            "Returns real search results with URLs and snippets from current web pages."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query, e.g. 'Icarus ransomware group 2026'",
                },
                "num_results": {
                    "type": "integer",
                    "description": "Number of results to return (default 8, max 15)",
                    "default": 8,
                },
            },
            "required": ["query"],
        },
    }


def _ddg_search(query: str, max_results: int) -> list[dict[str, str]]:
    with DDGS() as ddgs:
        return list(ddgs.text(query, max_results=max_results))


async def web_search(query: str, num_results: int = 8) -> str:
    num_results = min(num_results, 15)
    cache_key = f"websearch:{query}:{num_results}"
    cached = cache_get(cache_key)
    if cached:
        return json.dumps(cached)

    try:
        raw = await asyncio.to_thread(_ddg_search, query, num_results)
        results = [
            {
                "title": r.get("title", ""),
                "snippet": r.get("body", ""),
                "url": r.get("href", ""),
                "source": _domain(r.get("href", "")),
            }
            for r in raw
        ]
        result: dict[str, Any] = {
            "query": query,
            "results": results,
            "total_returned": len(results),
        }
    except Exception as e:
        result = {"error": str(e), "query": query, "results": []}

    cache_set(cache_key, result, ttl=1800)
    return json.dumps(result)


def _domain(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc or "unknown"
    except Exception:
        return "unknown"
