"""SSL/TLS certificate tool — Certificate Transparency (crt.sh) + VirusTotal."""

from __future__ import annotations

import json
from typing import Any

from argus.config.settings import get_settings
from argus.storage.cache import cache_get, cache_set, get_rate_limiter
from argus.tools.http import get_client

_CRTSH = "https://crt.sh"
_VT_BASE = "https://www.virustotal.com/api/v3"


def get_tool_definition() -> dict[str, Any]:
    return {
        "name": "ssl_cert_lookup",
        "description": (
            "Look up SSL/TLS certificates for a domain or IP address. "
            "Returns cert metadata from Certificate Transparency logs (crt.sh) and VirusTotal: "
            "SANs, issuer, fingerprint, validity dates. "
            "Use to pivot: find other domains sharing the same cert (cert reuse), discover "
            "subdomains via Subject Alternative Names, detect self-signed actor infrastructure."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator": {
                    "type": "string",
                    "description": "Domain name or IP address",
                },
                "indicator_type": {
                    "type": "string",
                    "enum": ["ip", "domain"],
                    "description": "Type of indicator",
                },
                "include_subdomains": {
                    "type": "boolean",
                    "description": "Include wildcard/subdomain certs from CT logs (domain only)",
                    "default": True,
                },
            },
            "required": ["indicator", "indicator_type"],
        },
    }


async def _query_crtsh(domain: str, include_subdomains: bool) -> list[dict[str, Any]]:
    query = f"%.{domain}" if include_subdomains else domain
    resp = await get_client().get(_CRTSH, params={"q": query, "output": "json"})
    resp.raise_for_status()
    raw: list[dict[str, Any]] = resp.json()

    seen: set[str] = set()
    certs = []
    for entry in raw[:100]:
        serial = entry.get("serial_number", "")
        if serial in seen:
            continue
        seen.add(serial)
        sans = [s.strip() for s in entry.get("name_value", "").split("\n") if s.strip()]
        certs.append(
            {
                "serial_number": serial,
                "common_name": entry.get("common_name", ""),
                "sans": sans,
                "issuer": entry.get("issuer_name", ""),
                "not_before": entry.get("not_before", ""),
                "not_after": entry.get("not_after", ""),
                "logged_at": entry.get("logged_at", ""),
                "source": "crt.sh",
            }
        )
    return certs


async def _query_vt_certs(
    indicator: str,
    indicator_type: str,
    headers: dict[str, str],
) -> list[dict[str, Any]]:
    rl = get_rate_limiter("virustotal")
    await rl.wait_and_acquire()

    endpoint = (
        f"{_VT_BASE}/ip_addresses/{indicator}/historical_ssl_certificates"
        if indicator_type == "ip"
        else f"{_VT_BASE}/domains/{indicator}/historical_ssl_certificates"
    )
    resp = await get_client().get(endpoint, params={"limit": 10}, headers=headers)
    resp.raise_for_status()
    data = resp.json()

    certs = []
    for item in data.get("data", [])[:10]:
        attrs = item.get("attributes", {})
        raw_sans: list[str] = attrs.get("extensions", {}).get("subject_alternative_name", [])
        sans = [s.replace("DNS:", "").replace("IP:", "").strip() for s in raw_sans]
        certs.append(
            {
                "serial_number": attrs.get("serial_number", ""),
                "thumbprint": attrs.get("thumbprint", ""),
                "thumbprint_sha256": attrs.get("thumbprint_sha256", ""),
                "common_name": attrs.get("subject", {}).get("CN", ""),
                "subject": attrs.get("subject", {}),
                "issuer": attrs.get("issuer", {}),
                "not_before": attrs.get("validity", {}).get("not_before", ""),
                "not_after": attrs.get("validity", {}).get("not_after", ""),
                "sans": sans,
                "source": "virustotal",
            }
        )
    return certs


async def ssl_cert_lookup(
    indicator: str,
    indicator_type: str,
    include_subdomains: bool = True,
) -> str:
    cache_key = f"sslcert:{indicator_type}:{indicator}"
    cached = cache_get(cache_key)
    if cached:
        return json.dumps(cached)

    certs: list[dict[str, Any]] = []
    errors: list[str] = []

    # crt.sh — only meaningful for domain names (CT logs index by domain, not IP)
    if indicator_type == "domain":
        try:
            certs.extend(await _query_crtsh(indicator, include_subdomains))
        except Exception as e:
            errors.append(f"crt.sh: {e}")

    # VirusTotal — works for both IPs and domains if key is present
    vt_key = get_settings().api_key("virustotal")
    if vt_key:
        try:
            existing_serials = {c["serial_number"] for c in certs}
            vt_certs = await _query_vt_certs(indicator, indicator_type, {"x-apikey": vt_key})
            certs.extend(c for c in vt_certs if c["serial_number"] not in existing_serials)
        except Exception as e:
            errors.append(f"VirusTotal: {e}")

    # Collect all SANs across certs for pivot surface
    all_sans: set[str] = set()
    for cert in certs:
        all_sans.update(cert.get("sans", []))

    result: dict[str, Any] = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "cert_count": len(certs),
        "certs": certs[:25],
        "all_sans": sorted(all_sans)[:60],
        "status": "ok" if certs else ("error" if errors else "no_data"),
    }
    if errors:
        result["errors"] = errors

    cache_set(cache_key, result, ttl=3600)
    return json.dumps(result)
