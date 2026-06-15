"""Web/OSINT search tool — uses DuckDuckGo instant answers API (no key required)."""
from __future__ import annotations

import json
from typing import Any

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from argus.storage.cache import cache_get, cache_set

_DDG_URL = "https://api.duckduckgo.com/"


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in (429, 500, 502, 503, 504)
    return isinstance(exc, httpx.TransportError)


def get_tool_definition() -> dict[str, Any]:
    return {
        "name": "web_search",
        "description": (
            "Search the web for OSINT information about threat actors, campaigns, "
            "malware families, or recent cybersecurity news."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query, e.g. 'APT29 recent campaigns 2024'",
                },
                "num_results": {
                    "type": "integer",
                    "description": "Number of results to return (default 5)",
                    "default": 5,
                },
            },
            "required": ["query"],
        },
    }


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    retry=retry_if_exception(_is_retryable),
    reraise=True,
)
async def _fetch_ddg(query: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            _DDG_URL,
            params={"q": query, "format": "json", "no_html": "1", "skip_disambig": "1"},
        )
        resp.raise_for_status()
        return dict(resp.json())


async def web_search(query: str, num_results: int = 5) -> str:
    cache_key = f"websearch:{query}:{num_results}"
    cached = cache_get(cache_key)
    if cached:
        return json.dumps(cached)

    try:
        data = await _fetch_ddg(query)
        results = []

        if data.get("AbstractText"):
            results.append({
                "title": data.get("Heading", ""),
                "snippet": data.get("AbstractText", ""),
                "url": data.get("AbstractURL", ""),
                "source": data.get("AbstractSource", ""),
            })

        for topic in data.get("RelatedTopics", [])[:num_results - len(results)]:
            if isinstance(topic, dict) and "Text" in topic:
                results.append({
                    "title": topic.get("Text", "")[:100],
                    "snippet": topic.get("Text", ""),
                    "url": topic.get("FirstURL", ""),
                    "source": "DuckDuckGo",
                })

        result = {
            "query": query,
            "results": results[:num_results],
            "total_returned": len(results),
        }
    except Exception as e:
        result = {"error": str(e), "query": query, "results": []}

    cache_set(cache_key, result, ttl=1800)
    return json.dumps(result)
