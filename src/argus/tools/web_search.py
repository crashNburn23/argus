"""Web/OSINT search tool — real DuckDuckGo results via duckduckgo-search.

Also provides url_fetch for reading a specific page URL and returning clean text.
"""

from __future__ import annotations

import html as _html
import json
import re
from html.parser import HTMLParser
from typing import Any

from ddgs import DDGS

from argus.async_utils import run_sync
from argus.storage.cache import cache_get, cache_set

# ---------------------------------------------------------------------------
# HTML → text stripper
# ---------------------------------------------------------------------------


class _TagStripper(HTMLParser):
    _SKIP_TAGS = {"script", "style", "head", "nav", "noscript", "iframe", "svg", "footer"}
    _BLOCK_TAGS = {"p", "div", "br", "h1", "h2", "h3", "h4", "h5", "li", "tr", "article"}

    def __init__(self) -> None:
        super().__init__()
        self._parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in self._SKIP_TAGS:
            self._skip += 1
        elif not self._skip and tag in self._BLOCK_TAGS:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP_TAGS:
            self._skip = max(0, self._skip - 1)

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self._parts.append(data)

    def get_text(self) -> str:
        text = "".join(self._parts)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()


def _strip_html(raw: str) -> str:
    stripper = _TagStripper()
    try:
        stripper.feed(raw)
    except Exception:
        pass
    return stripper.get_text()


# ---------------------------------------------------------------------------
# url_fetch tool
# ---------------------------------------------------------------------------


def get_url_fetch_tool_definition() -> dict[str, Any]:
    return {
        "name": "url_fetch",
        "description": (
            "Fetch and return the text content of a specific URL (article, report, advisory). "
            "Use this FIRST when the user provides a URL to synthesize or analyze — do not "
            "skip this step. Returns cleaned article text with HTML stripped."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to fetch",
                },
            },
            "required": ["url"],
        },
    }


async def url_fetch(url: str) -> str:
    cache_key = f"urlfetch:{url}"
    cached = cache_get(cache_key)
    if cached:
        return json.dumps(cached)

    result: dict[str, Any]
    try:
        import httpx

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; argus-cti/1.0; research)"},
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            raw = resp.text

        text = _html.unescape(_strip_html(raw))
        MAX_CHARS = 20000
        if len(text) > MAX_CHARS:
            text = text[:MAX_CHARS] + "\n\n[content truncated at 20 000 chars]"

        result = {"url": url, "content": text, "status": "ok"}
    except Exception as e:
        result = {"url": url, "error": str(e), "status": "error"}

    cache_set(cache_key, result, ttl=3600)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# web_search tool
# ---------------------------------------------------------------------------


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
        raw = await run_sync(_ddg_search, query, num_results)
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
