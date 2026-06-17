"""SIEM connector — splunk, webhook, and file backends via SIEM_TYPE setting."""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx

from argus.config.settings import get_settings
from argus.storage.cache import cache_get, cache_set


def get_tool_definition() -> dict[str, Any]:
    siem_type = get_settings().siem_type.lower()

    if siem_type == "splunk":
        query_desc = (
            "Splunk SPL query. Omit the leading 'search' keyword for transforming commands "
            "(e.g. '| tstats ...'). Examples: "
            "'index=botsv3 src_ip=* | stats count by src_ip | sort -count | head 20', "
            "'index=* sourcetype=syslog (error OR critical) | timechart span=1h count'"
        )
        tool_desc = (
            "Query Splunk SIEM for security events and alerts using SPL. "
            "Use for alert volume trends, top IOCs, source/dest analysis, "
            "malware detections, and incident timeline data."
        )
    else:
        query_desc = "Search query or filter string"
        tool_desc = "Query the configured SIEM for alerts and log events."

    return {
        "name": "siem_query",
        "description": tool_desc,
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": query_desc},
                "time_range": {
                    "type": "string",
                    "description": (
                        "Time window: '1h', '24h', '7d', '30d'. "
                        "Splunk also accepts modifier syntax like '-1d@d/now'."
                    ),
                    "default": "24h",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results to return",
                    "default": 50,
                },
            },
            "required": ["query"],
        },
    }


# ---------------------------------------------------------------------------
# Time range helpers
# ---------------------------------------------------------------------------

_UNIT_MAP = {"h": "h", "d": "d", "w": "w", "m": "mon"}


def _splunk_time_range(time_range: str) -> tuple[str, str]:
    """Convert '24h', '7d', '30m' etc. to (earliest, latest) Splunk modifiers."""
    tr = time_range.strip()
    # Already a Splunk modifier pair like "-1d@d/now"
    if "/" in tr:
        parts = tr.split("/", 1)
        return parts[0], parts[1]
    # Pattern: <n><unit>
    m = re.match(r"^(\d+)([hdwm])$", tr.lower())
    if m:
        n, unit = m.groups()
        splunk_unit = _UNIT_MAP[unit]
        return f"-{n}{splunk_unit}", "now"
    # Fall through — let Splunk interpret it
    return f"-{tr}", "now"


# ---------------------------------------------------------------------------
# Splunk REST API backend
# ---------------------------------------------------------------------------

async def _query_splunk(query: str, time_range: str, limit: int) -> list[dict[str, Any]]:
    settings = get_settings()
    base_url = settings.siem_url
    if not base_url:
        return [{"error": "SIEM_URL not configured (e.g. https://localhost:8089)"}]

    token = settings.siem_api_key.get_secret_value() if settings.siem_api_key else ""
    client_kwargs: dict[str, Any] = {"verify": settings.splunk_verify_ssl, "timeout": 60}
    headers: dict[str, str] = {}

    if token:
        headers["Authorization"] = f"Splunk {token}"
    elif settings.splunk_username and settings.splunk_password.get_secret_value():
        client_kwargs["auth"] = httpx.BasicAuth(
            settings.splunk_username,
            settings.splunk_password.get_secret_value(),
        )
    else:
        return [{
            "error": (
                "Splunk auth not configured — set SIEM_API_KEY (token) "
                "or SPLUNK_USERNAME + SPLUNK_PASSWORD"
            )
        }]

    spl = query.strip()
    if not spl.lower().startswith("search ") and not spl.startswith("|"):
        spl = f"search {spl}"

    earliest, latest = _splunk_time_range(time_range)

    async with httpx.AsyncClient(**client_kwargs) as client:
        # 1. Create search job
        create_resp = await client.post(
            f"{base_url}/services/search/jobs",
            data={
                "search": spl,
                "earliest_time": earliest,
                "latest_time": latest,
                "output_mode": "json",
                "exec_mode": "normal",
            },
            headers=headers,
        )
        create_resp.raise_for_status()
        sid = create_resp.json()["sid"]

        # 2. Poll until done (max 120s)
        for _ in range(120):
            await asyncio.sleep(1)
            poll_resp = await client.get(
                f"{base_url}/services/search/jobs/{sid}",
                params={"output_mode": "json"},
                headers=headers,
            )
            poll_resp.raise_for_status()
            content = poll_resp.json()["entry"][0]["content"]
            if content.get("isDone"):
                if content.get("isFailed"):
                    return [{"error": f"Splunk search failed: {content.get('messages', '')}"}]
                break
        else:
            return [{"error": "Splunk search timed out after 120 seconds"}]

        # 3. Fetch results
        results_resp = await client.get(
            f"{base_url}/services/search/jobs/{sid}/results",
            params={"output_mode": "json", "count": str(limit)},
            headers=headers,
        )
        results_resp.raise_for_status()
        data: list[dict[str, Any]] = results_resp.json().get("results", [])
        return data


# ---------------------------------------------------------------------------
# Webhook / generic API backend
# ---------------------------------------------------------------------------

async def _query_webhook(query: str, time_range: str, limit: int) -> list[dict[str, Any]]:
    settings = get_settings()
    if not settings.siem_url:
        return [{"error": "SIEM_URL not configured"}]

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if settings.siem_api_key:
        headers["Authorization"] = f"Bearer {settings.siem_api_key.get_secret_value()}"

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            settings.siem_url,
            json={"query": query, "time_range": time_range, "limit": limit},
            headers=headers,
        )
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else data.get("results", [data])


# ---------------------------------------------------------------------------
# File backend
# ---------------------------------------------------------------------------

async def _query_file(query: str, limit: int) -> list[dict[str, Any]]:
    settings = get_settings()
    if not settings.siem_log_path:
        return [{"error": "SIEM_LOG_PATH not configured"}]

    import os
    if not os.path.exists(settings.siem_log_path):
        return [{"error": f"Log file not found: {settings.siem_log_path}"}]

    results: list[dict[str, Any]] = []
    query_lower = query.lower()
    with open(settings.siem_log_path) as f:
        for line in f:
            line = line.strip()
            if not line or query_lower not in line.lower():
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                results.append({"raw": line})
            if len(results) >= limit:
                break
    return results


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

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
        if siem_type == "splunk":
            events = await _query_splunk(query, time_range, limit)
        elif siem_type in ("webhook", "api"):
            events = await _query_webhook(query, time_range, limit)
        elif siem_type == "file":
            events = await _query_file(query, limit)
        else:
            events = [{"error": f"Unsupported SIEM_TYPE: {siem_type!r}"}]

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
