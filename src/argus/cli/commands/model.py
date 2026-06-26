"""Select the LLM provider and model used by Argus."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

import httpx
import typer
from dotenv import set_key
from rich.table import Table

from argus.cli.output import console, print_error
from argus.config.settings import get_settings


def list_ollama_models(base_url: str, timeout: float = 5.0) -> list[str]:
    response = httpx.get(
        f"{base_url.rstrip('/')}/api/tags",
        timeout=timeout,
        trust_env=False,
    )
    response.raise_for_status()
    return [item["name"] for item in response.json().get("models", [])]


def persist_model(provider: str, model_name: str, env_path: Path = Path(".env")) -> None:
    env_path.touch(exist_ok=True)
    set_key(str(env_path), "MODEL_PROVIDER", provider)
    set_key(str(env_path), "MODEL", model_name)
    get_settings.cache_clear()


def model_command(
    model_name: Annotated[
        str | None,
        typer.Argument(help="Model to select; omit to show the current and local models"),
    ] = None,
    provider: Annotated[
        Literal["anthropic", "ollama"],
        typer.Option("--provider", "-p", help="Provider for the selected model"),
    ] = "ollama",
    no_validate: Annotated[
        bool,
        typer.Option(
            "--no-validate",
            help="Select an Ollama model without checking the local server",
        ),
    ] = False,
) -> None:
    """Show or select the model used by all agents."""
    settings = get_settings()
    if model_name is None:
        console.print(
            f"Current: [bold]{settings.model_provider}[/bold] / [bold]{settings.model}[/bold]"
        )
        try:
            models = list_ollama_models(settings.ollama_base_url)
        except Exception as exc:
            console.print(f"[dim]Ollama unavailable at {settings.ollama_base_url}: {exc}[/dim]")
            return

        table = Table(title="Local Ollama Models")
        table.add_column("Model")
        for local_model in models:
            table.add_row(local_model)
        console.print(table)
        return

    if provider == "ollama" and not no_validate:
        try:
            models = list_ollama_models(settings.ollama_base_url)
        except Exception as exc:
            print_error(f"Could not reach Ollama at {settings.ollama_base_url}: {exc}")
            raise typer.Exit(1)
        if model_name not in models:
            available = ", ".join(models) or "none"
            print_error(f"Local model '{model_name}' is not installed. Available: {available}")
            raise typer.Exit(1)

    persist_model(provider, model_name)
    console.print(f"Selected [bold]{provider}[/bold] / [bold]{model_name}[/bold] in .env")
