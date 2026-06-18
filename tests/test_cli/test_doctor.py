from __future__ import annotations

import json

from typer.testing import CliRunner

from argus.cli.app import app
from argus.config.settings import get_settings
from argus.diagnostics import _source_checks


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
# SIEM diagnostics
# ---------------------------------------------------------------------------

def _siem_check(monkeypatch, **env_vars) -> dict:
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    settings = get_settings()
    checks = _source_checks(settings)
    return next(c for c in checks if c.name == "SIEM")


def test_siem_file_mode_misconfigured_without_path(monkeypatch) -> None:
    check = _siem_check(monkeypatch, SIEM_TYPE="file", SIEM_LOG_PATH="")
    assert check.status == "misconfigured"
    assert "SIEM_LOG_PATH" in check.detail


def test_siem_file_mode_configured_with_path(monkeypatch, tmp_path) -> None:
    log_file = tmp_path / "siem.json"
    log_file.touch()
    check = _siem_check(monkeypatch, SIEM_TYPE="file", SIEM_LOG_PATH=str(log_file))
    assert check.status == "configured"


def test_siem_webhook_mode_misconfigured_without_url(monkeypatch) -> None:
    check = _siem_check(monkeypatch, SIEM_TYPE="webhook", SIEM_URL="")
    assert check.status == "misconfigured"


def test_siem_webhook_mode_configured_with_url(monkeypatch) -> None:
    check = _siem_check(monkeypatch, SIEM_TYPE="webhook", SIEM_URL="https://siem.example.com")
    assert check.status == "configured"


def test_siem_splunk_misconfigured_without_url(monkeypatch) -> None:
    check = _siem_check(monkeypatch, SIEM_TYPE="splunk", SIEM_URL="", SIEM_API_KEY="")
    assert check.status == "misconfigured"
    assert "SIEM_URL" in check.detail


def test_siem_splunk_misconfigured_without_auth(monkeypatch) -> None:
    check = _siem_check(
        monkeypatch,
        SIEM_TYPE="splunk",
        SIEM_URL="https://splunk:8089",
        SIEM_API_KEY="",
        SPLUNK_USERNAME="",
        SPLUNK_PASSWORD="",
    )
    assert check.status == "misconfigured"
    assert "auth" in check.detail.lower()


def test_siem_splunk_configured_with_token(monkeypatch) -> None:
    check = _siem_check(
        monkeypatch,
        SIEM_TYPE="splunk",
        SIEM_URL="https://splunk:8089",
        SIEM_API_KEY="mytoken",
    )
    assert check.status == "configured"
    assert "token" in check.detail


def test_siem_splunk_configured_with_basic_auth(monkeypatch) -> None:
    check = _siem_check(
        monkeypatch,
        SIEM_TYPE="splunk",
        SIEM_URL="https://splunk:8089",
        SIEM_API_KEY="",
        SPLUNK_USERNAME="admin",
        SPLUNK_PASSWORD="argus_splunk_1",
    )
    assert check.status == "configured"
    assert "basic auth" in check.detail


def test_siem_unsupported_type(monkeypatch) -> None:
    check = _siem_check(monkeypatch, SIEM_TYPE="elastic")
    assert check.status == "misconfigured"
    assert "elastic" in check.detail
