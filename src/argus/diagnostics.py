"""Configuration and readiness diagnostics for Argus."""
from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel

from argus.config.settings import Settings, get_settings


class DiagnosticCheck(BaseModel):
    category: str
    name: str
    status: str
    detail: str
    required: bool = False


class DiagnosticResult(BaseModel):
    checks: list[DiagnosticCheck]

    @property
    def ready(self) -> bool:
        return not any(check.required and check.status == "failed" for check in self.checks)


def _writable_check(name: str, path: Path) -> DiagnosticCheck:
    target = path if path.exists() and path.is_dir() else path.parent
    while not target.exists() and target != target.parent:
        target = target.parent
    writable = target.exists() and os.access(target, os.W_OK)
    return DiagnosticCheck(
        category="storage",
        name=name,
        status="ready" if writable else "failed",
        detail=f"{path} (writable parent: {target})",
        required=True,
    )


def _model_checks(settings: Settings, check_connectivity: bool) -> list[DiagnosticCheck]:
    if settings.model_provider == "anthropic":
        configured = bool(settings.api_key("anthropic"))
        return [
            DiagnosticCheck(
                category="model",
                name=f"anthropic / {settings.model}",
                status="ready" if configured else "failed",
                detail=(
                    "API key configured; connectivity not tested"
                    if configured
                    else "ANTHROPIC_API_KEY is missing"
                ),
                required=True,
            )
        ]

    if not check_connectivity:
        return [
            DiagnosticCheck(
                category="model",
                name=f"ollama / {settings.model}",
                status="configured",
                detail=f"Connectivity check skipped; endpoint {settings.ollama_base_url}",
                required=True,
            )
        ]

    try:
        from argus.cli.commands.model import list_ollama_models

        models = list_ollama_models(settings.ollama_base_url, timeout=2.0)
        installed = settings.model in models
        return [
            DiagnosticCheck(
                category="model",
                name=f"ollama / {settings.model}",
                status="ready" if installed else "failed",
                detail=(
                    f"Connected to {settings.ollama_base_url}"
                    if installed
                    else f"Model is not installed; available: {', '.join(models) or 'none'}"
                ),
                required=True,
            )
        ]
    except Exception as exc:
        return [
            DiagnosticCheck(
                category="model",
                name=f"ollama / {settings.model}",
                status="failed",
                detail=f"Could not reach {settings.ollama_base_url}: {exc}",
                required=True,
            )
        ]


def _source_checks(settings: Settings) -> list[DiagnosticCheck]:
    keyed_sources = {
        "VirusTotal": "virustotal",
        "Shodan": "shodan",
        "Recorded Future": "recorded_future",
        "AlienVault OTX": "otx",
        "AbuseIPDB": "abuseipdb",
    }
    checks = [
        DiagnosticCheck(
            category="source",
            name=name,
            status="configured" if settings.api_key(key) else "disabled",
            detail=(
                "API key configured; connectivity tested during use"
                if settings.api_key(key)
                else "Optional API key not configured"
            ),
        )
        for name, key in keyed_sources.items()
    ]
    checks.extend(
        DiagnosticCheck(
            category="source",
            name=name,
            status="ready",
            detail="No API key required; connectivity tested during use",
        )
        for name in ("MITRE ATT&CK", "NVD / CISA KEV", "URLhaus", "Web search")
    )

    if not settings.misp_url:
        misp_status, misp_detail = "disabled", "MISP_URL is not configured"
    elif not settings.api_key("misp"):
        misp_status, misp_detail = "misconfigured", "MISP_API_KEY is missing"
    else:
        misp_status, misp_detail = "configured", "URL and API key configured"
    checks.append(
        DiagnosticCheck(category="source", name="MISP", status=misp_status, detail=misp_detail)
    )

    if settings.siem_type == "file":
        if settings.siem_log_path:
            path = Path(settings.siem_log_path)
            status = "configured" if path.exists() else "misconfigured"
            detail = f"Log path: {path}" if path.exists() else f"Log path does not exist: {path}"
        else:
            status, detail = "misconfigured", "SIEM_LOG_PATH is required for file mode"
    elif settings.siem_type in {"api", "webhook"}:
        status = "configured" if settings.siem_url else "misconfigured"
        detail = f"Endpoint: {settings.siem_url}" if settings.siem_url else "SIEM_URL is required"
    elif settings.siem_type == "splunk":
        has_url = bool(settings.siem_url)
        has_token = bool(settings.siem_api_key and settings.siem_api_key.get_secret_value())
        has_basic = bool(
            settings.splunk_username
            and settings.splunk_password.get_secret_value()
        )
        if not has_url:
            status, detail = "misconfigured", "SIEM_URL is required for Splunk mode"
        elif not (has_token or has_basic):
            status, detail = (
                "misconfigured",
                "Splunk auth not configured — set SIEM_API_KEY or "
                "SPLUNK_USERNAME + SPLUNK_PASSWORD",
            )
        else:
            auth_method = "token" if has_token else "basic auth"
            status, detail = "configured", f"Splunk at {settings.siem_url} ({auth_method})"
    else:
        status, detail = "misconfigured", f"Unsupported SIEM_TYPE: {settings.siem_type!r}"
    checks.append(DiagnosticCheck(category="source", name="SIEM", status=status, detail=detail))
    return checks


def _disclosure_check(settings: Settings) -> DiagnosticCheck:
    mode = settings.disclosure_mode
    if mode == "local-only" and settings.model_provider != "ollama":
        status, detail = (
            "warning",
            f"local-only mode set but model provider is '{settings.model_provider}' "
            "(data will leave the machine). Switch to Ollama or change mode.",
        )
    elif mode == "confirm-external":
        status, detail = "configured", "confirm-external: user prompted before each agent run"
    elif mode == "local-only":
        status, detail = "configured", "local-only: Ollama confirmed, no external model calls"
    else:
        status, detail = "ready", "unrestricted: data sent to configured model and sources"
    return DiagnosticCheck(
        category="disclosure",
        name="data-disclosure",
        status=status,
        detail=detail,
    )


def run_diagnostics(check_connectivity: bool = True) -> DiagnosticResult:
    settings = get_settings()
    checks = [
        _disclosure_check(settings),
        *_model_checks(settings, check_connectivity),
        _writable_check("Cache directory", settings.cache_dir),
        _writable_check("Database", settings.db_path),
        _writable_check("Reports directory", settings.reports_dir),
        *_source_checks(settings),
    ]
    return DiagnosticResult(checks=checks)

