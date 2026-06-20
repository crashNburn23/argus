"""Settings, tools, and agents REST API."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from argus.config.settings import get_settings
from argus.tools.registry import _AGENT_TOOLS, tool_status

router = APIRouter()

_TOOLS_DIR = Path(__file__).parents[2] / "tools"

_MODULE_TO_TOOLS: dict[str, list[str]] = {
    "virustotal": ["virustotal_lookup"],
    "shodan": ["shodan_lookup"],
    "recorded_future": ["recorded_future_search"],
    "abuseipdb": ["abuseipdb_check"],
    "alienvault_otx": ["otx_lookup"],
    "misp": ["misp_search"],
    "siem": ["siem_query"],
    "mitre_attack": ["mitre_attack_lookup"],
    "nvd": ["nvd_cve_lookup"],
    "urlhaus": ["urlhaus_lookup"],
    "web_search": ["web_search"],
    "passive_dns": ["passive_dns_lookup"],
    "certs": ["ssl_cert_lookup"],
    "whois": ["whois_lookup"],
}

_ENV_PATH = Path(".env")

_FIELD_TO_ENV: dict[str, str] = {
    "model_provider": "MODEL_PROVIDER",
    "model": "MODEL",
    "disclosure_mode": "DISCLOSURE_MODE",
    "ollama_base_url": "OLLAMA_BASE_URL",
    "log_level": "LOG_LEVEL",
}

_KEY_TO_ENV: dict[str, str] = {
    "anthropic_api_key": "ANTHROPIC_API_KEY",
    "virustotal_api_key": "VIRUSTOTAL_API_KEY",
    "shodan_api_key": "SHODAN_API_KEY",
    "recorded_future_api_key": "RECORDED_FUTURE_API_KEY",
    "otx_api_key": "OTX_API_KEY",
    "abuseipdb_api_key": "ABUSEIPDB_API_KEY",
    "misp_api_key": "MISP_API_KEY",
}

_AGENT_DESCRIPTIONS: dict[str, str] = {
    "orchestrator": "Routes requests to specialized sub-agents and synthesizes results",
    "ioc": "Enriches IOCs (IPs, domains, hashes) across configured threat intel feeds",
    "threat_actor": "Researches APT groups, campaigns, and MITRE ATT&CK TTPs",
    "vuln": "Looks up CVE details, CVSS scores, and exploitation status from NVD / CISA KEV",
    "triage": "Triages raw security alerts — extracts IOCs and assigns TP/FP/NI verdicts",
    "report": "Generates SIEM-based incident summary reports",
}

_ANTHROPIC_MODELS = [
    "claude-sonnet-4-6",
    "claude-opus-4-8",
    "claude-haiku-4-5-20251001",
]


def _ollama_models(base_url: str) -> list[str]:
    try:
        response = httpx.get(f"{base_url.rstrip('/')}/api/tags", timeout=2.0)
        response.raise_for_status()
        return sorted(
            item["name"] for item in response.json().get("models", []) if item.get("name")
        )
    except Exception:
        return []


class UpdateSettingsRequest(BaseModel):
    model_provider: str | None = None
    model: str | None = None
    disclosure_mode: str | None = None
    ollama_base_url: str | None = None
    log_level: str | None = None
    anthropic_api_key: str | None = None
    virustotal_api_key: str | None = None
    shodan_api_key: str | None = None
    recorded_future_api_key: str | None = None
    otx_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    misp_api_key: str | None = None


def _write_env(updates: dict[str, str]) -> None:
    existing: list[str] = []
    if _ENV_PATH.exists():
        existing = _ENV_PATH.read_text(encoding="utf-8").splitlines()

    done: set[str] = set()
    out: list[str] = []
    for line in existing:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.split("=", 1)[0].strip().upper()
            if k in updates:
                out.append(f"{k}={updates[k]}")
                done.add(k)
                continue
        out.append(line)

    for k, v in updates.items():
        if k not in done:
            out.append(f"{k}={v}")

    _ENV_PATH.write_text("\n".join(out) + "\n", encoding="utf-8")


def _key_configured(s: Any, attr: str) -> bool:
    try:
        val = getattr(s, attr, None)
        if val is None:
            return False
        return bool(val.get_secret_value()) if hasattr(val, "get_secret_value") else bool(val)
    except Exception:
        return False


@router.get("/settings")
async def get_settings_api() -> dict[str, Any]:
    s = get_settings()
    ollama_models = _ollama_models(s.ollama_base_url)
    return {
        "model_provider": s.model_provider,
        "model": s.model,
        "model_options": {
            "anthropic": _ANTHROPIC_MODELS,
            "ollama": ollama_models,
        },
        "disclosure_mode": s.disclosure_mode,
        "ollama_base_url": s.ollama_base_url,
        "ollama_timeout_seconds": s.ollama_timeout_seconds,
        "misp_url": s.misp_url,
        "siem_type": s.siem_type,
        "siem_url": s.siem_url,
        "db_path": str(s.db_path),
        "cases_dir": str(s.cases_dir),
        "reports_dir": str(s.reports_dir),
        "log_level": s.log_level,
        "api_keys_configured": {
            "anthropic": _key_configured(s, "anthropic_api_key"),
            "virustotal": _key_configured(s, "virustotal_api_key"),
            "shodan": _key_configured(s, "shodan_api_key"),
            "recorded_future": _key_configured(s, "recorded_future_api_key"),
            "otx": _key_configured(s, "otx_api_key"),
            "abuseipdb": _key_configured(s, "abuseipdb_api_key"),
            "misp": _key_configured(s, "misp_api_key"),
        },
    }


@router.patch("/settings")
async def update_settings(req: UpdateSettingsRequest) -> dict[str, Any]:
    updates: dict[str, str] = {}

    for field, env_key in _FIELD_TO_ENV.items():
        val = getattr(req, field, None)
        if val is not None:
            updates[env_key] = val

    for field, env_key in _KEY_TO_ENV.items():
        val = getattr(req, field, None)
        if val is not None and val.strip():
            updates[env_key] = val.strip()

    if updates:
        _write_env(updates)
        get_settings.cache_clear()

    return await get_settings_api()


@router.get("/tools")
async def get_tools() -> list[dict[str, Any]]:
    return tool_status()


@router.get("/agents")
async def get_agents() -> list[dict[str, Any]]:
    result = []
    for name, tools in _AGENT_TOOLS.items():
        result.append(
            {
                "name": name,
                "description": _AGENT_DESCRIPTIONS.get(name, ""),
                "tools": tools,
            }
        )
    return result


@router.get("/tools/files")
async def list_tool_files() -> list[dict[str, Any]]:
    skip = {"__init__.py", "registry.py"}
    status_map = {t["name"]: t for t in tool_status()}
    result = []
    for f in sorted(_TOOLS_DIR.glob("*.py")):
        if f.name in skip:
            continue
        tool_names = _MODULE_TO_TOOLS.get(f.stem, [])
        statuses = [status_map[n] for n in tool_names if n in status_map]
        available: bool | None = any(s["available"] for s in statuses) if statuses else None
        result.append(
            {
                "filename": f.name,
                "stem": f.stem,
                "tool_names": tool_names,
                "available": available,
                "size": f.stat().st_size,
            }
        )
    return result


@router.get("/tools/files/{filename}")
async def get_tool_file(filename: str) -> dict[str, Any]:
    if "/" in filename or "\\" in filename or not filename.endswith(".py"):
        raise HTTPException(status_code=400, detail="Invalid filename")
    path = _TOOLS_DIR / filename
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return {"filename": filename, "content": path.read_text(encoding="utf-8")}
