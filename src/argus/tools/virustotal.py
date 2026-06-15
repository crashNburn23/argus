"""VirusTotal tool — reference implementation of the tool pattern. Requires VIRUSTOTAL_API_KEY."""
from __future__ import annotations

import json
from typing import Any

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from argus.config.settings import get_settings
from argus.storage.cache import cache_get, cache_set, get_rate_limiter

_BASE = "https://www.virustotal.com/api/v3"

_VT_TYPE_MAP = {
    "ip": "ip_addresses",
    "domain": "domains",
    "url": "urls",
    "md5": "files",
    "sha1": "files",
    "sha256": "files",
}


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in (429, 500, 502, 503, 504)
    return isinstance(exc, httpx.TransportError)


def get_tool_definition() -> dict[str, Any]:
    return {
        "name": "virustotal_lookup",
        "description": (
            "Look up threat reputation for an IP, domain, URL, or file hash in VirusTotal. "
            "Returns detection counts, malware labels, and last analysis date."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "The IOC value to look up"},
                "ioc_type": {
                    "type": "string",
                    "enum": ["ip", "domain", "url", "md5", "sha1", "sha256"],
                    "description": "Type of indicator",
                },
            },
            "required": ["indicator", "ioc_type"],
        },
    }


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=15),
    retry=retry_if_exception(_is_retryable),
    reraise=True,
)
async def _fetch(endpoint: str) -> dict[str, Any]:
    rl = get_rate_limiter("virustotal")
    await rl.wait_and_acquire()
    settings = get_settings()
    headers = {"x-apikey": settings.api_key("virustotal")}
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{_BASE}/{endpoint}", headers=headers)
        resp.raise_for_status()
        return dict(resp.json())


def _normalize(raw: dict[str, Any], indicator: str, ioc_type: str) -> dict[str, Any]:
    attrs = raw.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values()) or 1
    return {
        "indicator": indicator,
        "ioc_type": ioc_type,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total_engines": total,
        "detection_ratio": f"{stats.get('malicious', 0)}/{total}",
        "reputation": attrs.get("reputation", 0),
        "tags": attrs.get("tags", []),
        "popular_threat_label": attrs.get("popular_threat_classification", {}).get(
            "suggested_threat_label", ""
        ),
        "last_analysis_date": attrs.get("last_analysis_date", ""),
        "creation_date": attrs.get("creation_date", ""),
        "country": attrs.get("country", ""),
        "asn": attrs.get("asn", ""),
    }


async def virustotal_lookup(indicator: str, ioc_type: str) -> str:
    cache_key = f"vt:{ioc_type}:{indicator}"
    cached = cache_get(cache_key)
    if cached:
        return json.dumps(cached)

    vt_type = _VT_TYPE_MAP.get(ioc_type)
    if not vt_type:
        return json.dumps({"error": f"Unsupported ioc_type: {ioc_type}"})

    try:
        if ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
            raw = await _fetch(f"urls/{url_id}")
        else:
            raw = await _fetch(f"{vt_type}/{indicator}")
        result = _normalize(raw, indicator, ioc_type)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            result = {"indicator": indicator, "ioc_type": ioc_type, "status": "not_found",
                      "malicious": 0, "total_engines": 0}
        else:
            result = {"error": str(e), "indicator": indicator}
    except Exception as e:
        result = {"error": str(e), "indicator": indicator}

    cache_set(cache_key, result, ttl=3600)
    return json.dumps(result)
