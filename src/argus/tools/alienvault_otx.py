"""AlienVault OTX tool — requires OTX_API_KEY."""
from __future__ import annotations

import json
from typing import Any

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from argus.config.settings import get_settings
from argus.storage.cache import cache_get, cache_set, get_rate_limiter

_BASE = "https://otx.alienvault.com/api/v1/indicators"

_OTX_TYPE_MAP = {
    "ip": "IPv4",
    "domain": "domain",
    "url": "url",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
    "hostname": "hostname",
}


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in (429, 500, 502, 503, 504)
    return isinstance(exc, httpx.TransportError)


def get_tool_definition() -> dict[str, Any]:
    return {
        "name": "otx_lookup",
        "description": (
            "Look up threat intelligence for an indicator in AlienVault OTX. "
            "Supports IPs, domains, URLs, and file hashes."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "The IOC value to look up"},
                "indicator_type": {
                    "type": "string",
                    "enum": ["ip", "domain", "url", "md5", "sha1", "sha256", "hostname"],
                    "description": "Type of indicator",
                },
            },
            "required": ["indicator", "indicator_type"],
        },
    }


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    retry=retry_if_exception(_is_retryable),
    reraise=True,
)
async def _fetch(indicator: str, otx_type: str, section: str) -> dict[str, Any]:
    rl = get_rate_limiter("otx")
    await rl.wait_and_acquire()
    settings = get_settings()
    headers = {"X-OTX-API-KEY": settings.api_key("otx")}
    url = f"{_BASE}/{otx_type}/{indicator}/{section}"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        return dict(resp.json())


async def otx_lookup(indicator: str, indicator_type: str) -> str:
    cache_key = f"otx:{indicator_type}:{indicator}"
    cached = cache_get(cache_key)
    if cached:
        return json.dumps(cached)

    otx_type = _OTX_TYPE_MAP.get(indicator_type, "IPv4")

    try:
        general = await _fetch(indicator, otx_type, "general")
        pulses = general.get("pulse_info", {})
        result = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "pulse_count": pulses.get("count", 0),
            "malware_families": list({
                tag
                for p in pulses.get("pulses", [])
                for tag in p.get("malware_families", [])
            })[:20],
            "tags": list({
                tag
                for p in pulses.get("pulses", [])
                for tag in p.get("tags", [])
            })[:20],
            "adversaries": list({
                adv
                for p in pulses.get("pulses", [])
                for adv in p.get("adversary", []) if adv
            })[:10],
            "recent_pulses": [
                {
                    "name": p.get("name", ""),
                    "created": p.get("created", ""),
                    "tlp": p.get("tlp", ""),
                }
                for p in pulses.get("pulses", [])[:5]
            ],
            "reputation": general.get("reputation", 0),
            "country_code": general.get("country_code", ""),
            "asn": general.get("asn", ""),
        }
    except Exception as e:
        result = {"error": str(e), "indicator": indicator}

    cache_set(cache_key, result, ttl=3600)
    return json.dumps(result)
