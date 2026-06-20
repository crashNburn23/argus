"""MISP tool — optional, skipped if MISP_URL is unset."""

from __future__ import annotations

import json
from typing import Any

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from argus.config.settings import get_settings
from argus.storage.cache import cache_get, cache_set, get_rate_limiter
from argus.tools.http import get_misp_client


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in (429, 500, 502, 503, 504)
    return isinstance(exc, httpx.TransportError)


def get_tool_definition() -> dict[str, Any]:
    return {
        "name": "misp_search",
        "description": (
            "Search a MISP instance for threat intelligence events and attributes. "
            "Only available when MISP_URL is configured."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "value": {"type": "string", "description": "Attribute value to search for"},
                "type": {
                    "type": "string",
                    "description": "MISP attribute type, e.g. ip-dst, domain, md5",
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Tags to filter events",
                },
                "event_id": {
                    "type": "string",
                    "description": "Specific MISP event ID",
                },
            },
        },
    }


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception(_is_retryable),
    reraise=True,
)
async def _search(payload: dict[str, Any]) -> dict[str, Any]:
    rl = get_rate_limiter("misp")
    await rl.wait_and_acquire()
    settings = get_settings()
    headers = {
        "Authorization": settings.api_key("misp"),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    resp = await get_misp_client(settings.misp_verify_ssl).post(
        f"{settings.misp_url}/attributes/restSearch",
        json=payload,
        headers=headers,
    )
    resp.raise_for_status()
    return dict(resp.json())


async def misp_search(
    value: str = "",
    type: str = "",  # noqa: A002
    tags: list[str] | None = None,
    event_id: str = "",
) -> str:
    settings = get_settings()
    if not settings.misp_url:
        return json.dumps({"error": "MISP_URL not configured"})

    cache_key = f"misp:{value}:{type}:{event_id}:{tags}"
    cached = cache_get(cache_key)
    if cached:
        return json.dumps(cached)

    payload: dict[str, Any] = {"returnFormat": "json", "limit": 50}
    if value:
        payload["value"] = value
    if type:
        payload["type"] = type
    if tags:
        payload["tags"] = tags
    if event_id:
        payload["eventid"] = event_id

    try:
        raw = await _search(payload)
        attrs = raw.get("response", {}).get("Attribute", [])
        result = {
            "total": len(attrs),
            "attributes": [
                {
                    "event_id": a.get("event_id", ""),
                    "type": a.get("type", ""),
                    "value": a.get("value", ""),
                    "category": a.get("category", ""),
                    "comment": a.get("comment", ""),
                    "timestamp": a.get("timestamp", ""),
                    "tags": [t.get("name", "") for t in a.get("Tag", [])],
                }
                for a in attrs[:20]
            ],
        }
    except Exception as e:
        result = {"error": str(e), "value": value}

    cache_set(cache_key, result, ttl=3600)
    return json.dumps(result)
