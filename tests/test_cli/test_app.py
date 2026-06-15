from __future__ import annotations

from unittest.mock import AsyncMock, patch

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
    constructor.assert_called_once_with(persistent=True)


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
