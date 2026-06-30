from __future__ import annotations

from unittest.mock import ANY, AsyncMock, patch

from pytest_httpx import HTTPXMock
from typer.testing import CliRunner

from argus.cli.app import app


def test_no_args_starts_persistent_session_until_exit() -> None:
    orchestrator = AsyncMock()
    orchestrator.run.return_value = "Analysis complete."

    with patch(
        "argus.agents.orchestrator.CTIOrchestrator",
        return_value=orchestrator,
    ):
        result = CliRunner().invoke(app, input="Investigate 1.2.3.4\n/exit\n")

    assert result.exit_code == 0
    assert "ARGUS" in result.stdout
    assert "Analysis complete." in result.stdout
    orchestrator.run.assert_awaited_once_with(user_query="Investigate 1.2.3.4")


def test_interactive_session_ignores_empty_input() -> None:
    orchestrator = AsyncMock()

    with patch(
        "argus.agents.orchestrator.CTIOrchestrator",
        return_value=orchestrator,
    ) as constructor:
        result = CliRunner().invoke(app, input="\n/exit\n")

    assert result.exit_code == 0
    orchestrator.run.assert_not_awaited()
    constructor.assert_called_once_with(persistent=True, progress=ANY)


def test_non_tty_interactive_confirm_external_can_cancel(monkeypatch) -> None:
    monkeypatch.setenv("DISCLOSURE_MODE", "confirm-external")
    from argus.config.settings import get_settings

    get_settings.cache_clear()
    orchestrator = AsyncMock()

    with patch(
        "argus.agents.orchestrator.CTIOrchestrator",
        return_value=orchestrator,
    ):
        result = CliRunner().invoke(app, input="Investigate 1.2.3.4\nn\n/exit\n")

    assert result.exit_code == 0
    assert "Cancelled." in result.stdout
    orchestrator.run.assert_not_awaited()


def test_interactive_doctor_command(monkeypatch) -> None:
    orchestrator = AsyncMock()

    with patch(
        "argus.agents.orchestrator.CTIOrchestrator",
        return_value=orchestrator,
    ):
        result = CliRunner().invoke(app, input="/doctor\n/exit\n")

    assert result.exit_code == 0
    assert "Argus Readiness" in result.stdout
    orchestrator.run.assert_not_awaited()


def test_interactive_model_command_lists_capabilities(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        method="GET",
        url="http://localhost:11434/api/tags",
        json={"models": [{"name": "qwen2.5:7b"}]},
    )
    orchestrator = AsyncMock()

    with patch(
        "argus.agents.orchestrator.CTIOrchestrator",
        return_value=orchestrator,
    ):
        result = CliRunner().invoke(app, input="/model\n/exit\n")

    assert result.exit_code == 0
    assert "Capabilities:" in result.stdout
    assert "qwen2.5:7b" in result.stdout
    assert "tool loops" in result.stdout
    orchestrator.run.assert_not_awaited()


def test_direct_ask_alias() -> None:
    orchestrator = AsyncMock()
    orchestrator.run.return_value = "Direct answer."

    with patch(
        "argus.agents.orchestrator.CTIOrchestrator",
        return_value=orchestrator,
    ):
        result = CliRunner().invoke(app, ["ask", "Investigate this"])

    assert result.exit_code == 0
    assert "Direct answer." in result.stdout


def test_direct_ask_confirm_external_can_cancel(monkeypatch) -> None:
    monkeypatch.setenv("DISCLOSURE_MODE", "confirm-external")
    from argus.config.settings import get_settings

    get_settings.cache_clear()
    orchestrator = AsyncMock()

    with patch(
        "argus.agents.orchestrator.CTIOrchestrator",
        return_value=orchestrator,
    ):
        result = CliRunner().invoke(app, ["ask", "Investigate this"], input="n\n")

    assert result.exit_code == 0
    assert "Cancelled." in result.stdout
    orchestrator.run.assert_not_awaited()
