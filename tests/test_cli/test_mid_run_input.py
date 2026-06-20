"""Tests for mid-run input classification and background task helpers."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from argus.cli.app import _classify_mid_run_input, _drain_completed


def _done_task(result: str) -> MagicMock:
    t = MagicMock()
    t.done.return_value = True
    t.result.return_value = result
    return t


def _cancelled_task() -> MagicMock:
    import asyncio

    t = MagicMock()
    t.done.return_value = True
    t.result.side_effect = asyncio.CancelledError()
    return t


def _failed_task(exc: Exception) -> MagicMock:
    t = MagicMock()
    t.done.return_value = True
    t.result.side_effect = exc
    return t


def _running_task() -> MagicMock:
    t = MagicMock()
    t.done.return_value = False
    return t


# ---------------------------------------------------------------------------
# _classify_mid_run_input — heuristic path (no LLM call needed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_classify_extend_starters() -> None:
    for prefix in ("also check", "and look at", "what about the subnet", "additionally pivot"):
        result = await _classify_mid_run_input(prefix, "active query")
        assert result == "extend", f"Expected 'extend' for: {prefix!r}"


@pytest.mark.asyncio
async def test_classify_short_message_is_extend() -> None:
    result = await _classify_mid_run_input("its ASN too", "Investigate 1.2.3.4")
    assert result == "extend"


@pytest.mark.asyncio
async def test_classify_long_unrelated_falls_back_without_credentials(monkeypatch) -> None:
    # LLM call will fail (no API key in test env) → should default to "background".
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    from argus.config.settings import get_settings

    get_settings.cache_clear()
    result = await _classify_mid_run_input(
        "Research the Lazarus Group campaign in Southeast Asia",
        "Investigate 1.2.3.4",
    )
    # No credentials → exception → safe default.
    assert result == "background"


# ---------------------------------------------------------------------------
# _drain_completed — result display and session state update
# ---------------------------------------------------------------------------


def test_drain_completed_removes_finished_task(monkeypatch) -> None:
    printed: list[str] = []
    monkeypatch.setattr("argus.cli.app.render_markdown", lambda s: printed.append(s))
    monkeypatch.setattr("argus.cli.app.console", MagicMock())

    active: list[tuple[str, Any]] = [("test query", _done_task("The analysis result."))]
    session: dict[str, Any] = {"exchanges": []}

    _drain_completed(active, session)

    assert active == []
    assert printed == ["The analysis result."]
    assert session["exchanges"] == [
        {"role": "user", "text": "test query"},
        {"role": "assistant", "text": "The analysis result."},
    ]


def test_drain_completed_leaves_running_task(monkeypatch) -> None:
    monkeypatch.setattr("argus.cli.app.render_markdown", lambda s: None)
    monkeypatch.setattr("argus.cli.app.console", MagicMock())

    active: list[tuple[str, Any]] = [("running query", _running_task())]
    session: dict[str, Any] = {"exchanges": []}

    _drain_completed(active, session)

    assert len(active) == 1
    assert session["exchanges"] == []


def test_drain_completed_handles_cancelled_task(monkeypatch) -> None:
    monkeypatch.setattr("argus.cli.app.render_markdown", lambda s: None)
    mock_console = MagicMock()
    monkeypatch.setattr("argus.cli.app.console", mock_console)

    active: list[tuple[str, Any]] = [("cancelled query", _cancelled_task())]
    session: dict[str, Any] = {"exchanges": []}

    _drain_completed(active, session)

    assert active == []
    assert session["exchanges"] == []
    mock_console.print.assert_called_once()
    assert "cancel" in mock_console.print.call_args[0][0].lower()


def test_drain_completed_handles_failed_task(monkeypatch) -> None:
    errors: list[Exception] = []
    monkeypatch.setattr("argus.cli.app.render_markdown", lambda s: None)
    monkeypatch.setattr("argus.cli.app.console", MagicMock())
    monkeypatch.setattr("argus.cli.app.print_agent_error", lambda e: errors.append(e))

    active: list[tuple[str, Any]] = [("failing query", _failed_task(RuntimeError("boom")))]
    session: dict[str, Any] = {"exchanges": []}

    _drain_completed(active, session)

    assert active == []
    assert len(errors) == 1
    assert "boom" in str(errors[0])
    assert session["exchanges"] == []


def test_drain_completed_drains_multiple_tasks(monkeypatch) -> None:
    rendered: list[str] = []
    monkeypatch.setattr("argus.cli.app.render_markdown", rendered.append)
    monkeypatch.setattr("argus.cli.app.console", MagicMock())

    active: list[tuple[str, Any]] = [
        ("q1", _done_task("result 1")),
        ("q2", _running_task()),
        ("q3", _done_task("result 3")),
    ]
    session: dict[str, Any] = {"exchanges": []}

    _drain_completed(active, session)

    assert len(active) == 1  # only the running one remains
    assert active[0][0] == "q2"
    assert "result 1" in rendered
    assert "result 3" in rendered
    assert len(session["exchanges"]) == 4  # q1 + q3 each add 2
