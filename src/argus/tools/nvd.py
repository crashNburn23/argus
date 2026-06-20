"""NVD CVE lookup tool — no API key required."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from argus.storage.cache import cache_get, cache_set, get_rate_limiter
from argus.tools.http import get_client

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
_CISA_KEV_CACHE_KEY = "cisa:kev:full"
_CISA_KEV_TTL = 86400


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in (429, 500, 502, 503, 504)
    return isinstance(exc, httpx.TransportError)


def get_tool_definition() -> dict[str, Any]:
    return {
        "name": "nvd_cve_lookup",
        "description": (
            "Look up CVE vulnerability information from NVD. Also checks CISA KEV list. "
            "Pass cve_ids (list) to look up multiple CVEs in parallel in a single call — "
            "always prefer this over multiple single-CVE calls. "
            "Use keyword/severity/days_back for search queries."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "List of CVE IDs to look up in parallel,"
                        " e.g. ['CVE-2021-44228', 'CVE-2023-23397']"
                    ),
                },
                "cve_id": {
                    "type": "string",
                    "description": "Single CVE ID (use cve_ids list instead for multiple)",
                },
                "keyword": {
                    "type": "string",
                    "description": "Keyword to search vulnerabilities",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                    "description": "Minimum CVSS severity filter",
                },
                "days_back": {
                    "type": "integer",
                    "description": "Only return CVEs published in the last N days",
                },
            },
        },
    }


async def _get_cisa_kev_ids() -> set[str]:
    cached = cache_get(_CISA_KEV_CACHE_KEY)
    if cached:
        return set(cached)
    try:
        resp = await get_client().get(_CISA_KEV_URL)
        resp.raise_for_status()
        data = resp.json()
        ids = [v["cveID"] for v in data.get("vulnerabilities", [])]
        cache_set(_CISA_KEV_CACHE_KEY, ids, ttl=_CISA_KEV_TTL)
        return set(ids)
    except Exception:
        return set()


def _normalize_cve(item: dict[str, Any], kev_ids: set[str]) -> dict[str, Any]:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    metrics = cve.get("metrics", {})

    cvss_v3 = None
    score_v3 = None
    vector_v3 = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            m = metrics[key][0].get("cvssData", {})
            score_v3 = m.get("baseScore")
            vector_v3 = m.get("vectorString")
            cvss_v3 = m.get("baseSeverity", "").lower()
            break

    descriptions = cve.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    return {
        "cve_id": cve_id,
        "description": desc_en[:1000],
        "cvss_v3_score": score_v3,
        "cvss_v3_vector": vector_v3,
        "severity": cvss_v3 or "unknown",
        "cwe_ids": cwes,
        "in_cisa_kev": cve_id in kev_ids,
        "published_date": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "references": [r["url"] for r in cve.get("references", [])[:5]],
    }


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception(_is_retryable),
    reraise=True,
)
async def _fetch_nvd(params: dict[str, Any]) -> dict[str, Any]:
    rl = get_rate_limiter("nvd")
    await rl.wait_and_acquire()
    resp = await get_client().get(_NVD_BASE, params=params)
    resp.raise_for_status()
    return dict(resp.json())


async def _lookup_one(cve_id: str, kev_ids: set[str]) -> dict[str, Any]:
    """Fetch and cache a single CVE by ID. Used by the batch path."""
    cache_key = f"nvd:{cve_id}:::"
    cached = cache_get(cache_key)
    # Only return cache if it's a success (has vulnerabilities key, no error key).
    if cached and "error" not in cached:
        return cached  # type: ignore[no-any-return]
    try:
        data = await _fetch_nvd({"cveId": cve_id})
        vulns = [_normalize_cve(item, kev_ids) for item in data.get("vulnerabilities", [])]
        result: dict[str, Any] = {
            "total_results": data.get("totalResults", 0),
            "vulnerabilities": vulns[:20],
            "cisa_kev_matches": [v["cve_id"] for v in vulns if v["in_cisa_kev"]],
        }
        cache_set(cache_key, result, ttl=86400)
        return result
    except Exception as e:
        # Do not cache errors — let the caller retry on next request.
        return {"error": str(e), "cve_id": cve_id, "vulnerabilities": []}


async def nvd_cve_lookup(
    cve_id: str = "",
    cve_ids: list[str] | None = None,
    keyword: str = "",
    severity: str = "",
    days_back: int | None = None,
) -> str:
    ids = [c.strip().upper() for c in (cve_ids or []) if c.strip()]
    if not ids and cve_id:
        ids = [cve_id.strip().upper()]

    # Batch path: multiple CVEs fetched in parallel, one CISA KEV request shared
    if ids and not keyword and not severity and not days_back:
        kev_ids = await _get_cisa_kev_ids()
        per_cve = await asyncio.gather(*(_lookup_one(i, kev_ids) for i in ids))
        all_vulns: list[dict[str, Any]] = []
        all_kev: list[str] = []
        errors: list[str] = []
        for r in per_cve:
            if "error" in r:
                errors.append(f"{r.get('cve_id', '?')}: {r['error']}")
            else:
                all_vulns.extend(r.get("vulnerabilities", []))
                all_kev.extend(r.get("cisa_kev_matches", []))
        combined: dict[str, Any] = {
            "total_results": len(all_vulns),
            "vulnerabilities": all_vulns[:20],
            "cisa_kev_matches": list(dict.fromkeys(all_kev)),
        }
        if errors:
            combined["errors"] = errors
        return json.dumps(combined)

    # Search/filter path (keyword / severity / days_back)
    cache_key = f"nvd:{cve_id}:{keyword}:{severity}:{days_back}"
    cached = cache_get(cache_key)
    # Only use cache if it's a successful result (no error key).
    if cached and "error" not in cached:
        return json.dumps(cached)

    kev_ids = await _get_cisa_kev_ids()
    params: dict[str, Any] = {}

    if cve_id:
        params["cveId"] = cve_id.upper()
    if keyword:
        params["keywordSearch"] = keyword
    if severity:
        params["cvssV3Severity"] = severity.upper()
    if days_back:
        end = datetime.now(tz=UTC)
        start = end - timedelta(days=days_back)
        params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["pubEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000")

    try:
        data = await _fetch_nvd(params)
        vulns = [_normalize_cve(item, kev_ids) for item in data.get("vulnerabilities", [])]
        result = {
            "total_results": data.get("totalResults", 0),
            "vulnerabilities": vulns[:20],
            "cisa_kev_matches": [v["cve_id"] for v in vulns if v["in_cisa_kev"]],
        }
        cache_set(cache_key, result, ttl=86400)
        return json.dumps(result)
    except Exception as e:
        # Do not cache errors — let the caller retry on next request.
        return json.dumps({"error": str(e), "vulnerabilities": []})
