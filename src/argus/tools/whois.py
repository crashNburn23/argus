"""WHOIS tool — registration data via RDAP (free, no key) + VirusTotal historical WHOIS."""
from __future__ import annotations

import json
from typing import Any

import httpx
import tldextract

from argus.config.settings import get_settings
from argus.storage.cache import cache_get, cache_set, get_rate_limiter
from argus.tools.http import get_client, get_redirect_client

_RDAP_BASE = "https://rdap.org"
_VT_BASE = "https://www.virustotal.com/api/v3"


def _registered_domain(domain: str) -> str:
    """Return the registered (apex) domain for any subdomain input.

    RDAP only serves data at the eTLD+1 level — querying a subdomain always 404s.
    """
    ext = tldextract.extract(domain)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return domain


def get_tool_definition() -> dict[str, Any]:
    return {
        "name": "whois_lookup",
        "description": (
            "Look up WHOIS/RDAP registration data for a domain. "
            "Returns registrar, creation/expiry dates, nameservers, and registrant info. "
            "Use to pivot: registrant email or org reuse across domains, recently-registered "
            "domain detection, fast-flux or bulletproof nameserver patterns."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain name to look up (e.g. example.com)",
                },
            },
            "required": ["domain"],
        },
    }


async def _rdap(domain: str) -> dict[str, Any]:
    resp = await get_redirect_client().get(f"{_RDAP_BASE}/domain/{domain}")
    resp.raise_for_status()
    data = resp.json()

    registrar = ""
    registrant_org = ""
    registrant_email = ""
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [None, []])[1]
        fn = next((f[3] for f in vcard if f[0] == "fn"), "")
        email = next((f[3] for f in vcard if f[0] == "email"), "")
        org = next((f[3] for f in vcard if f[0] == "org"), "")
        if "registrar" in roles:
            registrar = fn
        if "registrant" in roles:
            registrant_org = org
            registrant_email = email

    events: dict[str, str] = {
        e.get("eventAction", ""): e.get("eventDate", "")
        for e in data.get("events", [])
    }
    nameservers = [ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])]

    return {
        "source": "rdap",
        "registrar": registrar,
        "registrant_org": registrant_org,
        "registrant_email": registrant_email,
        "creation_date": events.get("registration", ""),
        "expiry_date": events.get("expiration", ""),
        "last_changed": events.get("last changed", ""),
        "nameservers": nameservers,
        "status": data.get("status", []),
    }


async def _vt_historical_whois(domain: str, api_key: str) -> list[dict[str, Any]]:
    rl = get_rate_limiter("virustotal")
    await rl.wait_and_acquire()

    headers = {"x-apikey": api_key}
    resp = await get_client().get(
        f"{_VT_BASE}/domains/{domain}/historical_whois",
        params={"limit": 5},
        headers=headers,
    )
    resp.raise_for_status()
    data = resp.json()

    records = []
    for item in data.get("data", [])[:5]:
        attrs = item.get("attributes", {})
        records.append({
            "date": attrs.get("date", ""),
            "registrar": attrs.get("registrar", ""),
            "registrant_email": attrs.get("registrant_email", ""),
            "registrant_org": attrs.get("registrant_organization", ""),
            "creation_date": attrs.get("creation_date", ""),
            "expiry_date": attrs.get("expiry_date", ""),
            "nameservers": attrs.get("name_servers", []),
        })
    return records


async def whois_lookup(domain: str) -> str:
    apex = _registered_domain(domain)
    cache_key = f"whois:{apex}"
    cached = cache_get(cache_key)
    if cached:
        return json.dumps(cached)

    result: dict[str, Any] = {"domain": apex}
    if apex != domain:
        result["queried_as"] = apex

    try:
        result.update(await _rdap(apex))
    except Exception as e:
        result["rdap_error"] = str(e)

    vt_key = get_settings().api_key("virustotal")
    if vt_key:
        try:
            historical = await _vt_historical_whois(apex, vt_key)
            if historical:
                result["historical_records"] = historical
        except Exception as e:
            result["vt_whois_error"] = str(e)

    cache_set(cache_key, result, ttl=86400)
    return json.dumps(result)
