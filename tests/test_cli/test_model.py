from __future__ import annotations

from pathlib import Path

from pytest_httpx import HTTPXMock
from typer.testing import CliRunner

from argus.cli.app import app
from argus.cli.commands.model import list_ollama_models, persist_model


def test_persist_model_updates_env(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    persist_model("ollama", "qwen3:8b", env_path)

    content = env_path.read_text()
    assert "MODEL_PROVIDER='ollama'" in content
    assert "MODEL='qwen3:8b'" in content


def test_model_command_selects_without_validation(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["model", "qwen3:8b", "--no-validate"])

    assert result.exit_code == 0
    assert "ollama / qwen3:8b" in result.stdout
    assert "MODEL_PROVIDER='ollama'" in (tmp_path / ".env").read_text()


def test_list_ollama_models_ignores_ambient_proxy(
    monkeypatch,
    httpx_mock: HTTPXMock,
) -> None:
    monkeypatch.setenv("ALL_PROXY", "socks://127.0.0.1:1080")
    httpx_mock.add_response(
        method="GET",
        url="http://localhost:11434/api/tags",
        json={"models": [{"name": "qwen3:8b"}]},
    )

    assert list_ollama_models("http://localhost:11434") == ["qwen3:8b"]
