from __future__ import annotations

import json

from typer.testing import CliRunner

from argus.cli.app import app
from argus.config.settings import get_settings


def test_doctor_reports_ready_configuration_as_json() -> None:
    result = CliRunner().invoke(app, ["doctor", "--json", "--no-connectivity"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ready"] is True
    assert any(check["name"] == "MITRE ATT&CK" for check in payload["checks"])


def test_doctor_fails_when_required_model_key_is_missing(monkeypatch) -> None:
    monkeypatch.setenv("MODEL_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    get_settings.cache_clear()
    result = CliRunner().invoke(app, ["doctor", "--json"])

    assert result.exit_code == 1
    assert json.loads(result.stdout)["ready"] is False


# ---------------------------------------------------------------------------
# Disclosure mode diagnostics
# ---------------------------------------------------------------------------


def _disclosure_check(monkeypatch, **env_vars) -> dict:
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    settings = get_settings()
    from argus.diagnostics import _disclosure_check as _dc

    return _dc(settings)


def test_disclosure_unrestricted_is_ready(monkeypatch) -> None:
    check = _disclosure_check(monkeypatch, DISCLOSURE_MODE="unrestricted")
    assert check.status == "ready"


def test_disclosure_confirm_external_is_configured(monkeypatch) -> None:
    check = _disclosure_check(monkeypatch, DISCLOSURE_MODE="confirm-external")
    assert check.status == "configured"
    assert "prompt" in check.detail.lower()


def test_disclosure_local_only_with_ollama_is_configured(monkeypatch) -> None:
    check = _disclosure_check(
        monkeypatch,
        DISCLOSURE_MODE="local-only",
        MODEL_PROVIDER="ollama",
    )
    assert check.status == "configured"


def test_disclosure_local_only_with_anthropic_warns(monkeypatch) -> None:
    check = _disclosure_check(
        monkeypatch,
        DISCLOSURE_MODE="local-only",
        MODEL_PROVIDER="anthropic",
    )
    assert check.status == "warning"
    assert "anthropic" in check.detail


def test_doctor_includes_disclosure_check(monkeypatch) -> None:
    result = CliRunner().invoke(app, ["doctor", "--json", "--no-connectivity"])
    payload = json.loads(result.stdout)
    assert any(c["name"] == "data-disclosure" for c in payload["checks"])


def test_doctor_marks_sources_blocked_in_local_only(monkeypatch) -> None:
    monkeypatch.setenv("DISCLOSURE_MODE", "local-only")
    monkeypatch.setenv("MODEL_PROVIDER", "ollama")
    get_settings.cache_clear()

    result = CliRunner().invoke(app, ["doctor", "--json", "--no-connectivity"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    source_checks = [c for c in payload["checks"] if c["category"] == "source"]
    assert source_checks
    assert {c["status"] for c in source_checks} == {"blocked"}
