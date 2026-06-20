"""Recorded Future tool — requires RECORDED_FUTURE_API_KEY."""

from __future__ import annotations

import json
from typing import Any

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from argus.config.settings import get_settings
from argus.storage.cache import cache_get, cache_set, get_rate_limiter
from argus.tools.http import get_client

_BASE = "https://api.recordedfuture.com/v2"

_RF_TYPE_MAP = {
    "ip": "ip",
    "domain": "domain",
    "url": "url",
    "md5": "hash",
    "sha256": "hash",
    "actor": "entity",
    "malware": "malware",
    "vulnerability": "vulnerability",
}


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in (429, 500, 502, 503, 504)
    return isinstance(exc, httpx.TransportError)


def get_tool_definition() -> dict[str, Any]:
    return {
        "name": "recorded_future_search",
        "description": (
            "Search Recorded Future for finished threat intelligence on an entity. "
            "Returns risk score, risk rules, related entities, and evidence."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "entity": {"type": "string", "description": "The entity value to look up"},
                "entity_type": {
                    "type": "string",
                    "enum": [
                        "ip",
                        "domain",
                        "url",
                        "md5",
                        "sha256",
                        "actor",
                        "malware",
                        "vulnerability",
                    ],
                    "description": "Type of entity",
                },
            },
            "required": ["entity", "entity_type"],
        },
    }


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception(_is_retryable),
    reraise=True,
)
async def _fetch(entity: str, rf_type: str) -> dict[str, Any]:
    rl = get_rate_limiter("recorded_future")
    await rl.wait_and_acquire()
    settings = get_settings()
    headers = {
        "X-RFToken": settings.api_key("recorded_future"),
        "Content-Type": "application/json",
    }
    params = {"fields": "risk,intelCard,relatedEntities,threatLists,metrics"}
    resp = await get_client().get(f"{_BASE}/{rf_type}/{entity}", headers=headers, params=params)
    resp.raise_for_status()
    return dict(resp.json())


async def recorded_future_search(entity: str, entity_type: str) -> str:
    cache_key = f"rf:{entity_type}:{entity}"
    cached = cache_get(cache_key)
    if cached:
        return json.dumps(cached)

    rf_type = _RF_TYPE_MAP.get(entity_type, "ip")

    try:
        raw = await _fetch(entity, rf_type)
        data = raw.get("data", {})
        risk = data.get("risk", {})
        result = {
            "entity": entity,
            "entity_type": entity_type,
            "risk_score": risk.get("score", 0),
            "risk_level": risk.get("criticalityLabel", ""),
            "risk_rules": [
                {"rule": r.get("rule", ""), "evidence_string": r.get("evidenceString", "")}
                for r in risk.get("evidenceDetails", [])[:10]
            ],
            "related_entities": [
                {"name": e.get("entity", {}).get("name", ""), "type": e.get("type", "")}
                for e in data.get("relatedEntities", [])[:10]
            ],
            "intel_card_url": data.get("intelCard", ""),
        }
    except Exception as e:
        result = {"error": str(e), "entity": entity}

    cache_set(cache_key, result, ttl=1800)
    return json.dumps(result)
