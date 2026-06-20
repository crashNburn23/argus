"""URLhaus lookup tool — no API key required."""
from __future__ import annotations

import json
from typing import Any

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from argus.storage.cache import cache_get, cache_set, get_rate_limiter
from argus.tools.http import get_client

_URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/"


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in (429, 500, 502, 503, 504)
    return isinstance(exc, httpx.TransportError)


def get_tool_definition() -> dict[str, Any]:
    return {
        "name": "urlhaus_lookup",
        "description": (
            "Look up malicious URLs, hosts, or file hashes in URLhaus (abuse.ch). "
            "Free, no API key required."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to look up"},
                "host": {"type": "string", "description": "Hostname or IP to look up"},
                "payload_md5": {"type": "string", "description": "MD5 hash of a payload"},
                "payload_sha256": {"type": "string", "description": "SHA256 hash of a payload"},
            },
        },
    }


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    retry=retry_if_exception(_is_retryable),
    reraise=True,
)
async def _post(endpoint: str, data: dict[str, Any]) -> dict[str, Any]:
    rl = get_rate_limiter("urlhaus")
    await rl.wait_and_acquire()
    resp = await get_client().post(_URLHAUS_API + endpoint, data=data)
    resp.raise_for_status()
    return dict(resp.json())


async def urlhaus_lookup(
    url: str = "",
    host: str = "",
    payload_md5: str = "",
    payload_sha256: str = "",
) -> str:
    indicator = url or host or payload_md5 or payload_sha256
    cache_key = f"urlhaus:{indicator}"
    cached = cache_get(cache_key)
    if cached:
        return json.dumps(cached)

    try:
        if url:
            data = await _post("url/", {"url": url})
        elif host:
            data = await _post("host/", {"host": host})
        elif payload_md5:
            data = await _post("payload/", {"md5_hash": payload_md5})
        elif payload_sha256:
            data = await _post("payload/", {"sha256_hash": payload_sha256})
        else:
            return json.dumps({"error": "Provide url, host, payload_md5, or payload_sha256"})

        result = {
            "query_status": data.get("query_status", ""),
            "indicator": indicator,
            "threat": data.get("threat", ""),
            "tags": data.get("tags", []),
            "urls_count": len(data.get("urls", [])),
            "payloads_count": len(data.get("payloads", [])),
            "urls": [
                {"url": u.get("url", ""), "url_status": u.get("url_status", ""),
                 "threat": u.get("threat", "")}
                for u in data.get("urls", [])[:10]
            ],
        }
    except Exception as e:
        result = {"error": str(e), "indicator": indicator}

    cache_set(cache_key, result, ttl=1800)
    return json.dumps(result)
