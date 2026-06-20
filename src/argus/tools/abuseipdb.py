"""AbuseIPDB tool — requires ABUSEIPDB_API_KEY."""
from __future__ import annotations

import json
from typing import Any

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from argus.config.settings import get_settings
from argus.storage.cache import cache_get, cache_set, get_rate_limiter
from argus.tools.http import get_client

_BASE = "https://api.abuseipdb.com/api/v2"


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in (429, 500, 502, 503, 504)
    return isinstance(exc, httpx.TransportError)


def get_tool_definition() -> dict[str, Any]:
    return {
        "name": "abuseipdb_check",
        "description": "Check an IP address against AbuseIPDB for abuse reports.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "IP address to check",
                },
                "max_age_in_days": {
                    "type": "integer",
                    "description": "Only return reports within this many days (default 90)",
                    "default": 90,
                },
            },
            "required": ["ip_address"],
        },
    }


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    retry=retry_if_exception(_is_retryable),
    reraise=True,
)
async def _fetch(ip_address: str, max_age_in_days: int) -> dict[str, Any]:
    rl = get_rate_limiter("abuseipdb")
    await rl.wait_and_acquire()
    settings = get_settings()
    headers = {"Key": settings.api_key("abuseipdb"), "Accept": "application/json"}
    resp = await get_client().get(
        f"{_BASE}/check",
        headers=headers,
        params={"ipAddress": ip_address, "maxAgeInDays": max_age_in_days, "verbose": True},
    )
    resp.raise_for_status()
    return dict(resp.json())


async def abuseipdb_check(ip_address: str, max_age_in_days: int = 90) -> str:
    cache_key = f"abuseipdb:ip:{ip_address}:{max_age_in_days}"
    cached = cache_get(cache_key)
    if cached:
        return json.dumps(cached)

    try:
        raw = await _fetch(ip_address, max_age_in_days)
        d = raw.get("data", {})
        result = {
            "ip_address": d.get("ipAddress", ip_address),
            "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "num_distinct_users": d.get("numDistinctUsers", 0),
            "country_code": d.get("countryCode", ""),
            "isp": d.get("isp", ""),
            "domain": d.get("domain", ""),
            "usage_type": d.get("usageType", ""),
            "is_tor": d.get("isTor", False),
            "is_public": d.get("isPublic", True),
            "last_reported_at": d.get("lastReportedAt", ""),
        }
        cache_set(cache_key, result, ttl=3600)
        return json.dumps(result)
    except Exception as e:
        # Do not cache errors — let the caller retry on next request.
        return json.dumps({"error": str(e), "ip_address": ip_address})
