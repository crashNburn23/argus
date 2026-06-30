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
from argus.llm.capabilities import model_capabilities


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


def yes_no(value: bool) -> str:
    return "yes" if value else "no"


def capability_summary(provider: str, model_name: str) -> str:
    caps = model_capabilities(provider, model_name)
    return (
        f"tools={yes_no(caps.tool_calling)}, "
        f"structured={yes_no(caps.structured_output)}, "
        f"recommended={caps.recommendation}"
    )


def add_capability_row(table: Table, provider: str, model_name: str) -> None:
    caps = model_capabilities(provider, model_name)
    context = str(caps.context_window) if caps.context_window is not None else "unknown"
    notes = caps.caution_summary or caps.recommendation
    table.add_row(
        model_name,
        yes_no(caps.tool_calling),
        yes_no(caps.structured_output),
        context,
        caps.recommendation,
        notes,
    )


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
        current = model_capabilities(settings.model_provider, settings.model)
        console.print(
            f"Current: [bold]{settings.model_provider}[/bold] / [bold]{settings.model}[/bold]"
        )
        console.print(
            f"Capabilities: {capability_summary(settings.model_provider, settings.model)}"
        )
        if current.cautions:
            console.print(f"[yellow]Caution:[/yellow] {current.caution_summary}")
        try:
            models = list_ollama_models(settings.ollama_base_url)
        except Exception as exc:
            console.print(f"[dim]Ollama unavailable at {settings.ollama_base_url}: {exc}[/dim]")
            return

        table = Table(title="Local Ollama Models")
        table.add_column("Model")
        table.add_column("Tools")
        table.add_column("Structured")
        table.add_column("Context")
        table.add_column("Recommended")
        table.add_column("Notes")
        for local_model in models:
            add_capability_row(table, "ollama", local_model)
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
    caps = model_capabilities(provider, model_name)
    console.print(f"Capabilities: {capability_summary(provider, model_name)}")
    if caps.cautions:
        console.print(f"[yellow]Caution:[/yellow] {caps.caution_summary}")
    if not caps.tool_calling:
        console.print(
            "[yellow]Warning:[/yellow] This model does not support tool calling. "
            "Agents that use enrichment tools (triage, case analysis, threat actor) "
            "will not function correctly. Use a tool-capable model for agent workflows."
        )
    if not caps.structured_output:
        console.print(
            "[yellow]Warning:[/yellow] This model does not support native structured output. "
            "Argus will fall back to json_repair parsing — validate results carefully."
        )
