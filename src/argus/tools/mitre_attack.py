"""MITRE ATT&CK tool — uses local mitreattack-python data, no API key required."""

from __future__ import annotations

import json
from typing import Any

from argus.storage.cache import cache_get, cache_set

_MITRE_DATA = None


def _get_data() -> tuple[Any, str | None]:
    global _MITRE_DATA
    if _MITRE_DATA is None:
        try:
            import os

            from mitreattack.stix20 import MitreAttackData

            # Try to use a local enterprise-attack.json if available, else download
            local_path = os.environ.get("MITRE_ATTACK_JSON", "")
            if local_path and os.path.exists(local_path):
                _MITRE_DATA = MitreAttackData(local_path)
            else:
                # Fetch from MITRE CDN
                import urllib.request

                url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
                cache_path = "/tmp/enterprise-attack.json"
                if not os.path.exists(cache_path):
                    urllib.request.urlretrieve(url, cache_path)
                _MITRE_DATA = MitreAttackData(cache_path)
        except Exception as e:
            return None, str(e)
    return _MITRE_DATA, None


def get_tool_definition() -> dict[str, Any]:
    return {
        "name": "mitre_attack_lookup",
        "description": (
            "Look up MITRE ATT&CK techniques, groups (threat actors), and software. "
            "Use technique_id (e.g. T1566), group_name (e.g. APT29), or a keyword to search."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "technique_id": {
                    "type": "string",
                    "description": "ATT&CK technique ID, e.g. T1566 or T1566.001",
                },
                "group_name": {
                    "type": "string",
                    "description": "Threat actor / group name or alias, e.g. APT29",
                },
                "keyword": {
                    "type": "string",
                    "description": "Free-text keyword to search techniques and groups",
                },
            },
        },
    }


async def mitre_attack_lookup(
    technique_id: str = "",
    group_name: str = "",
    keyword: str = "",
) -> str:
    cache_key = f"mitre:{technique_id}:{group_name}:{keyword}"
    cached = cache_get(cache_key)
    if cached:
        return json.dumps(cached)

    data, err = _get_data()
    if err or data is None:
        return json.dumps({"error": f"MITRE ATT&CK data unavailable: {err}"})

    results: dict[str, Any] = {}

    if technique_id:
        try:
            techniques = data.get_techniques(remove_revoked_deprecated=True)
            matched = [
                t
                for t in techniques
                if t.get("external_references")
                and any(
                    ref.get("external_id", "").upper() == technique_id.upper()
                    for ref in t["external_references"]
                )
            ]
            if matched:
                t = matched[0]
                results["technique"] = {
                    "id": technique_id,
                    "name": t.get("name", ""),
                    "description": t.get("description", "")[:1000],
                    "kill_chain_phases": [p["phase_name"] for p in t.get("kill_chain_phases", [])],
                    "detection": t.get("x_mitre_detection", "")[:500],
                    "data_sources": t.get("x_mitre_data_sources", []),
                }
        except Exception as e:
            results["technique_error"] = str(e)

    if group_name:
        try:
            groups = data.get_groups(remove_revoked_deprecated=True)
            matched = [
                g
                for g in groups
                if group_name.lower() in g.get("name", "").lower()
                or any(group_name.lower() in a.lower() for a in g.get("aliases", []))
            ]
            results["groups"] = [
                {
                    "name": g.get("name", ""),
                    "aliases": g.get("aliases", []),
                    "description": g.get("description", "")[:800],
                    "mitre_id": next(
                        (
                            ref["external_id"]
                            for ref in g.get("external_references", [])
                            if ref.get("source_name") == "mitre-attack"
                        ),
                        "",
                    ),
                }
                for g in matched[:5]
            ]
        except Exception as e:
            results["group_error"] = str(e)

    if keyword and not technique_id and not group_name:
        try:
            techniques = data.get_techniques(remove_revoked_deprecated=True)
            kw = keyword.lower()
            matched = [
                t
                for t in techniques
                if kw in t.get("name", "").lower() or kw in t.get("description", "").lower()
            ][:10]
            results["keyword_techniques"] = [
                {
                    "id": next(
                        (
                            ref["external_id"]
                            for ref in t.get("external_references", [])
                            if ref.get("source_name") == "mitre-attack"
                        ),
                        "",
                    ),
                    "name": t.get("name", ""),
                    "tactics": [p["phase_name"] for p in t.get("kill_chain_phases", [])],
                }
                for t in matched
            ]
        except Exception as e:
            results["keyword_error"] = str(e)

    cache_set(cache_key, results, ttl=604800)
    return json.dumps(results)
