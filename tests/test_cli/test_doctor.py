from __future__ import annotations

import json

from typer.testing import CliRunner

from argus.cli.app import app


def test_doctor_reports_ready_configuration_as_json() -> None:
    result = CliRunner().invoke(app, ["doctor", "--json", "--no-connectivity"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ready"] is True
    assert any(check["name"] == "MITRE ATT&CK" for check in payload["checks"])


def test_doctor_fails_when_required_model_key_is_missing(monkeypatch) -> None:
    monkeypatch.setenv("MODEL_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    from argus.config.settings import get_settings

    get_settings.cache_clear()
    result = CliRunner().invoke(app, ["doctor", "--json"])

    assert result.exit_code == 1
    assert json.loads(result.stdout)["ready"] is False
