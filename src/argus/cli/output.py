"""CLI output helpers — Rich terminal rendering, themed console."""
from __future__ import annotations

import json
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# ---------------------------------------------------------------------------
# Theme registry
# ---------------------------------------------------------------------------

THEMES: dict[str, dict[str, str]] = {
    "analyst": {
        "cp.cyan":    "#4499cc bold",
        "cp.magenta": "#6677aa bold",
        "cp.green":   "#338855 bold",
        "cp.amber":   "#997733",
        "cp.red":     "#bb3333 bold",
        "cp.purple":  "#445588",
        "cp.dim":     "dim #556677",
        "cp.border":  "#334466",
        "verdict.malicious":  "#bb3333 bold",
        "verdict.suspicious": "#997733",
        "verdict.benign":     "#338855",
        "verdict.unknown":    "dim #445588",
        "sev.critical": "#bb3333 bold",
        "sev.high":     "#bb3333",
        "sev.medium":   "#997733",
        "sev.low":      "#4499cc",
        "sev.none":     "dim",
        "triage.tp": "#bb3333 bold",
        "triage.fp": "#338855",
        "triage.ni": "#997733",
    },
    "contrast": {
        "cp.cyan":    "bright_cyan bold",
        "cp.magenta": "bright_magenta bold",
        "cp.green":   "bright_green bold",
        "cp.amber":   "bright_yellow",
        "cp.red":     "bright_red bold",
        "cp.purple":  "bright_blue bold",
        "cp.dim":     "dim white",
        "cp.border":  "bright_white",
        "verdict.malicious":  "bright_red bold",
        "verdict.suspicious": "bright_yellow bold",
        "verdict.benign":     "bright_green bold",
        "verdict.unknown":    "dim white",
        "sev.critical": "bright_red bold underline",
        "sev.high":     "bright_red bold",
        "sev.medium":   "bright_yellow bold",
        "sev.low":      "bright_cyan bold",
        "sev.none":     "dim",
        "triage.tp": "bright_red bold",
        "triage.fp": "bright_green bold",
        "triage.ni": "bright_yellow bold",
    },
    "mono": {
        "cp.cyan":    "bold",
        "cp.magenta": "bold underline",
        "cp.green":   "bold",
        "cp.amber":   "italic",
        "cp.red":     "bold reverse",
        "cp.purple":  "dim bold",
        "cp.dim":     "dim",
        "cp.border":  "dim",
        "verdict.malicious":  "bold reverse",
        "verdict.suspicious": "bold italic",
        "verdict.benign":     "bold",
        "verdict.unknown":    "dim",
        "sev.critical": "bold reverse",
        "sev.high":     "bold underline",
        "sev.medium":   "bold italic",
        "sev.low":      "bold",
        "sev.none":     "dim",
        "triage.tp": "bold reverse",
        "triage.fp": "bold",
        "triage.ni": "bold italic",
    },
    "midnight": {
        "cp.cyan":    "#7ca2d6 bold",
        "cp.magenta": "#a070a0 bold",
        "cp.green":   "#5aad7e bold",
        "cp.amber":   "#c49a3c",
        "cp.red":     "#c26a6a bold",
        "cp.purple":  "#6b6aad",
        "cp.dim":     "dim #3a4a5e",
        "cp.border":  "#2a3a5a",
        "verdict.malicious":  "#c26a6a bold",
        "verdict.suspicious": "#c49a3c",
        "verdict.benign":     "#5aad7e",
        "verdict.unknown":    "dim #6b6aad",
        "sev.critical": "#c26a6a bold",
        "sev.high":     "#c26a6a",
        "sev.medium":   "#c49a3c",
        "sev.low":      "#7ca2d6",
        "sev.none":     "dim",
        "triage.tp": "#c26a6a bold",
        "triage.fp": "#5aad7e",
        "triage.ni": "#c49a3c",
    },
    "nord": {
        "cp.cyan":    "#88c0d0 bold",
        "cp.magenta": "#b48ead bold",
        "cp.green":   "#a3be8c bold",
        "cp.amber":   "#ebcb8b",
        "cp.red":     "#bf616a bold",
        "cp.purple":  "#81a1c1",
        "cp.dim":     "dim #4c566a",
        "cp.border":  "#3b4252",
        "verdict.malicious":  "#bf616a bold",
        "verdict.suspicious": "#ebcb8b",
        "verdict.benign":     "#a3be8c",
        "verdict.unknown":    "dim #81a1c1",
        "sev.critical": "#bf616a bold",
        "sev.high":     "#bf616a",
        "sev.medium":   "#ebcb8b",
        "sev.low":      "#88c0d0",
        "sev.none":     "dim",
        "triage.tp": "#bf616a bold",
        "triage.fp": "#a3be8c",
        "triage.ni": "#ebcb8b",
    },
    "ember": {
        "cp.cyan":    "#e8a26b bold",
        "cp.magenta": "#d4714f bold",
        "cp.green":   "#7daa6b bold",
        "cp.amber":   "#cc8833",
        "cp.red":     "#cc4433 bold",
        "cp.purple":  "#996644",
        "cp.dim":     "dim #5a3a22",
        "cp.border":  "#6b4422",
        "verdict.malicious":  "#cc4433 bold",
        "verdict.suspicious": "#cc8833",
        "verdict.benign":     "#7daa6b",
        "verdict.unknown":    "dim #996644",
        "sev.critical": "#cc4433 bold",
        "sev.high":     "#cc4433",
        "sev.medium":   "#cc8833",
        "sev.low":      "#e8a26b",
        "sev.none":     "dim",
        "triage.tp": "#cc4433 bold",
        "triage.fp": "#7daa6b",
        "triage.ni": "#cc8833",
    },
}

THEME_DESCRIPTIONS: dict[str, str] = {
    "analyst":  "Muted steel blues — professional (default)",
    "contrast": "Full ANSI saturation — high visibility",
    "mono":     "Bold and dim only — no color",
    "midnight": "Deep navy and periwinkle — dark IDE feel",
    "nord":     "Arctic blues and aurora — Nord palette",
    "ember":    "Warm amber and flame — firelight on dark",
}

_CONFIG_FILE = Path.home() / ".argus_config.json"


def _load_saved_theme() -> str:
    try:
        data = json.loads(_CONFIG_FILE.read_text())
        name = data.get("theme", "analyst")
        return name if name in THEMES else "analyst"
    except Exception:
        return "analyst"


def _save_theme(name: str) -> None:
    try:
        data: dict[str, Any] = {}
        if _CONFIG_FILE.exists():
            data = json.loads(_CONFIG_FILE.read_text())
        data["theme"] = name
        _CONFIG_FILE.write_text(json.dumps(data, indent=2))
    except Exception:
        pass


_current_theme: str = _load_saved_theme()
_output_history: list[tuple[tuple[Any, ...], dict[str, Any]]] = []


class _ConsoleProxy:
    """Proxy around Rich Console that intercepts print() for theme replay."""

    def __init__(self, *, stderr: bool = False) -> None:
        self._stderr = stderr
        self._console: Console = self._build()

    def _build(self) -> Console:
        return Console(theme=Theme(THEMES[_current_theme]), stderr=self._stderr)

    def update_theme(self) -> None:
        self._console = self._build()

    @property
    def raw(self) -> Console:
        return self._console

    def print(self, *args: Any, **kwargs: Any) -> None:
        if not self._stderr:
            _output_history.append((args, kwargs))
        self._console.print(*args, **kwargs)

    def clear(self) -> None:
        self._console.clear()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._console, name)


console = _ConsoleProxy()
err_console = _ConsoleProxy(stderr=True)

# ---------------------------------------------------------------------------
# Theme management
# ---------------------------------------------------------------------------

def set_theme(name: str) -> None:
    """Switch to a named theme and replay the full output history."""
    global _current_theme
    if name not in THEMES:
        raise ValueError(f"Unknown theme: {name!r}. Available: {list(THEMES)}")
    _current_theme = name
    snapshot = list(_output_history)
    _output_history.clear()
    console.update_theme()
    err_console.update_theme()
    console.clear()
    for args, kwargs in snapshot:
        console._console.print(*args, **kwargs)
    _output_history.extend(snapshot)
    _save_theme(name)


def get_theme() -> str:
    return _current_theme


def get_theme_names() -> list[str]:
    return list(THEMES)


def clear_output_history() -> None:
    _output_history.clear()


# ---------------------------------------------------------------------------
# Style lookup helpers
# ---------------------------------------------------------------------------

_VERDICT_STYLES: dict[str, str] = {
    "malicious": "verdict.malicious",
    "suspicious": "verdict.suspicious",
    "benign":     "verdict.benign",
    "unknown":    "verdict.unknown",
}

_SEV_STYLES: dict[str, str] = {
    "critical": "sev.critical",
    "high":     "sev.high",
    "medium":   "sev.medium",
    "low":      "sev.low",
    "none":     "sev.none",
}

_TRIAGE_STYLES: dict[str, str] = {
    "true_positive":       "triage.tp",
    "false_positive":      "triage.fp",
    "needs_investigation": "triage.ni",
}


def _vs(verdict: str) -> str:
    return _VERDICT_STYLES.get(str(verdict), "cp.dim")

def _ss(severity: str) -> str:
    return _SEV_STYLES.get(str(severity).lower(), "sev.none")

def _ts(decision: str) -> str:
    return _TRIAGE_STYLES.get(str(decision), "cp.dim")


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def print_json(data: Any) -> None:
    if isinstance(data, BaseModel):
        text = data.model_dump_json(indent=2)
    elif isinstance(data, dict | list):
        text = json.dumps(data, indent=2, default=str)
    else:
        text = str(data)
    print(text)


def print_error(msg: str) -> None:
    err_console.print(f"[cp.red]ERR ▸[/cp.red] {msg}")


def print_agent_error(exc: Exception, as_json: bool = False) -> None:
    from argus.agents.errors import AgentError
    if as_json and isinstance(exc, AgentError):
        print(json.dumps(exc.to_dict(), indent=2))
    elif isinstance(exc, AgentError):
        err_console.print(f"[cp.red]AGENT ERR ▸[/cp.red] [{exc.category.value}] {exc}")
    else:
        err_console.print(f"[cp.red]ERR ▸[/cp.red] {exc}")


def render_markdown(text: str) -> None:
    console.print(Markdown(text))


class _ThinkingIndicator:
    _frames = ("◐", "◓", "◑", "◒")

    def __init__(self, message: str) -> None:
        self._message = message
        self._frame = 0
        self._start = time.monotonic()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._live: Live | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> _ThinkingIndicator:
        global _active_thinking_indicator
        self._previous = _active_thinking_indicator
        _active_thinking_indicator = self
        self._live = Live(
            self._render(),
            console=console.raw,
            refresh_per_second=12,
            transient=True,
        )
        self._live.start()
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        global _active_thinking_indicator
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=0.5)
        if self._live is not None:
            self._live.stop()
        _active_thinking_indicator = self._previous

    def update(self, message: str) -> None:
        with self._lock:
            self._message = message
        self._refresh()

    def _animate(self) -> None:
        while not self._stop.wait(0.12):
            with self._lock:
                self._frame = (self._frame + 1) % len(self._frames)
            self._refresh()

    def _refresh(self) -> None:
        if self._live is not None:
            self._live.update(self._render())

    def _render(self) -> Text:
        with self._lock:
            frame = self._frames[self._frame]
            message = self._message
        elapsed = time.monotonic() - self._start
        elapsed_str = f"{elapsed:.0f}s" if elapsed >= 1 else ""
        text = Text()
        text.append("⟐ ", style="cp.magenta")
        text.append(frame, style="cp.cyan")
        text.append(" ⟐", style="cp.magenta")
        text.append(f"  {message}")
        if elapsed_str:
            text.append(f"  {elapsed_str}", style="cp.dim")
        return text


_active_thinking_indicator: _ThinkingIndicator | None = None


@contextmanager
def thinking(
    message: str = "argus is thinking",
    enabled: bool = True,
) -> Generator[None, None, None]:
    """Show the animated evil-eye thinking indicator for human-readable output."""
    if not enabled:
        yield
        return
    with _ThinkingIndicator(message):
        yield


def status(msg: str) -> None:
    """Update active thinking state, or print a status line when no indicator is active."""
    if _active_thinking_indicator is not None:
        _active_thinking_indicator.update(msg)
    else:
        console.print(f"[cp.cyan]⟳[/cp.cyan]  {msg}")



# ---------------------------------------------------------------------------
# IOC enrichment
# ---------------------------------------------------------------------------

def render_ioc_result(result: Any, as_json: bool = False) -> None:
    if as_json:
        print_json(result)
        return

    for ioc in result.indicators:
        s = _vs(ioc.overall_verdict)
        title = (
            f"[cp.cyan]{ioc.indicator}[/cp.cyan]"
            f"  [{s}]{str(ioc.overall_verdict).upper()}[/{s}]"
            f"  [cp.dim]confidence {ioc.confidence:.0%}[/cp.dim]"
        )
        rows = []
        for sr in ioc.source_results:
            ss = _vs(sr.verdict)
            rows.append(f"  [{ss}]{sr.source:<18}[/{ss}] [cp.dim]{sr.verdict}[/cp.dim]")
        if ioc.malware_families:
            rows.append(f"  [cp.amber]Malware  [/cp.amber] {', '.join(ioc.malware_families[:5])}")
        if ioc.threat_actors:
            rows.append(f"  [cp.magenta]Actors   [/cp.magenta] {', '.join(ioc.threat_actors[:5])}")
        if ioc.asn:
            rows.append(f"  [cp.dim]ASN      [/cp.dim] {ioc.asn}")
        if ioc.geolocation:
            rows.append(f"  [cp.dim]Geo      [/cp.dim] {ioc.geolocation}")
        console.print(Panel(
            "\n".join(rows) if rows else "[cp.dim]No source details.[/cp.dim]",
            title=title,
            border_style="cp.border",
        ))

    if result.high_priority_iocs:
        console.print(
            f"\n[cp.red]HIGH PRIORITY ▸[/cp.red] {', '.join(result.high_priority_iocs)}"
        )
    if result.recommended_actions:
        console.print("\n[cp.cyan]Recommended Actions[/cp.cyan]")
        for action in result.recommended_actions:
            console.print(f"  [cp.magenta]▸[/cp.magenta] {action}")


# ---------------------------------------------------------------------------
# Threat actor
# ---------------------------------------------------------------------------

def render_threat_actor_result(result: Any, as_json: bool = False) -> None:
    if as_json:
        print_json(result)
        return

    if result.summary:
        console.print(
            Panel(
                result.summary,
                title="[cp.cyan]Summary[/cp.cyan]",
                border_style="cp.border",
            )
        )

    for actor in result.actors:
        table = Table(
            title=f"[cp.magenta]{actor.name}[/cp.magenta]",
            show_header=True,
            header_style="cp.cyan",
            border_style="cp.purple",
        )
        table.add_column("Attribute", style="cp.dim", width=18)
        table.add_column("Value")
        if actor.aliases:
            table.add_row("Aliases", ", ".join(actor.aliases))
        if actor.mitre_group_id:
            table.add_row("MITRE ID", f"[cp.cyan]{actor.mitre_group_id}[/cp.cyan]")
        if actor.primary_motivation:
            table.add_row("Motivation", actor.primary_motivation)
        if actor.sophistication:
            table.add_row("Sophistication", f"[cp.amber]{actor.sophistication}[/cp.amber]")
        if actor.target_sectors:
            table.add_row("Targets", ", ".join(actor.target_sectors[:5]))
        console.print(table)

        if actor.techniques:
            tech_table = Table(
                title="[cp.cyan]ATT&CK Techniques[/cp.cyan]",
                show_header=True,
                header_style="cp.magenta",
                border_style="cp.purple",
            )
            tech_table.add_column("ID", style="cp.cyan", width=10)
            tech_table.add_column("Technique")
            tech_table.add_column("Tactic", style="cp.amber")
            for tech in actor.techniques[:15]:
                tech_table.add_row(tech.technique_id, tech.technique_name, tech.tactic)
            console.print(tech_table)

    if result.recommended_detections:
        console.print("\n[cp.cyan]Detection Recommendations[/cp.cyan]")
        for det in result.recommended_detections:
            console.print(f"  [cp.magenta]▸[/cp.magenta] {det}")


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------

def render_vuln_result(result: Any, as_json: bool = False) -> None:
    if as_json:
        print_json(result)
        return

    table = Table(
        title="[cp.cyan]Vulnerability Intelligence[/cp.cyan]",
        show_header=True,
        header_style="cp.magenta",
        border_style="cp.purple",
    )
    table.add_column("CVE ID", style="cp.cyan")
    table.add_column("Severity")
    table.add_column("CVSS", justify="right")
    table.add_column("KEV")
    table.add_column("Status")

    for vuln in result.vulnerabilities:
        ss = _ss(vuln.severity)
        table.add_row(
            vuln.cve_id,
            f"[{ss}]{vuln.severity.upper()}[/{ss}]",
            str(vuln.cvss_v3_score or "—"),
            "[cp.red]YES[/cp.red]" if vuln.in_cisa_kev else "[cp.dim]no[/cp.dim]",
            f"[cp.amber]{vuln.exploitation_status}[/cp.amber]",
        )
    console.print(table)

    if result.patch_priority:
        console.print("\n[cp.cyan]Patch Priority[/cp.cyan]")
        for p in result.patch_priority:
            ss = _ss(p.priority)
            console.print(
                f"  [{ss}]{p.priority.upper()}[/{ss}]  "
                f"[cp.cyan]{p.cve_id}[/cp.cyan]  [cp.dim]{p.rationale}[/cp.dim]"
            )


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------

def render_triage_result(result: Any, as_json: bool = False) -> None:
    if as_json:
        print_json(result)
        return

    stats = Table(
        title="[cp.cyan]Triage Summary[/cp.cyan]",
        show_header=True,
        header_style="cp.magenta",
        border_style="cp.purple",
    )
    stats.add_column("Decision")
    stats.add_column("Count", justify="right", style="cp.cyan")
    stats.add_row("[triage.tp]True Positive[/triage.tp]",   str(result.true_positive_count))
    stats.add_row("[triage.fp]False Positive[/triage.fp]",  str(result.false_positive_count))
    stats.add_row(
        "[triage.ni]Needs Investigation[/triage.ni]",
        str(result.needs_investigation_count),
    )
    console.print(stats)

    for ta in sorted(result.triaged_alerts, key=lambda x: x.risk_score, reverse=True)[:10]:
        ts = _ts(str(ta.decision))
        title = (
            f"[{ts}]{str(ta.decision).upper()}[/{ts}]"
            f"  [cp.dim]alert {ta.alert.alert_id}[/cp.dim]"
            f"  [cp.cyan]risk {ta.risk_score}/10[/cp.cyan]"
        )
        body = ta.analyst_notes or "[cp.dim]No notes.[/cp.dim]"
        if ta.recommended_actions:
            body += "\n" + "\n".join(
                f"[cp.magenta]▸[/cp.magenta] {a}" for a in ta.recommended_actions
            )
        console.print(Panel(body, title=title, border_style=ts))


# ---------------------------------------------------------------------------
# Cache / misc
# ---------------------------------------------------------------------------

def spinner(description: str) -> Progress:
    return Progress(
        SpinnerColumn(style="cp.magenta"),
        TextColumn(f"[cp.cyan]{description}[/cp.cyan]"),
        transient=True,
        console=console.raw,
    )


@contextmanager
def working(description: str, enabled: bool = True) -> Generator[None, None, None]:
    """Show a transient working indicator without contaminating machine output."""
    if not enabled:
        yield
        return
    with spinner(description) as progress:
        progress.add_task(description)
        yield


def cache_stats_display() -> None:
    from argus.storage.cache import cache_stats
    stats = cache_stats()
    table = Table(
        title="[cp.cyan]Cache[/cp.cyan]",
        show_header=True,
        header_style="cp.magenta",
        border_style="cp.purple",
    )
    table.add_column("Metric", style="cp.dim")
    table.add_column("Value", style="cp.cyan", justify="right")
    table.add_row("Items", str(stats["item_count"]))
    table.add_row("Size", f"{stats['size_bytes'] / 1024 / 1024:.1f} MB")
    table.add_row("Directory", stats["directory"])
    console.print(table)


def cache_clear_display() -> None:
    from argus.storage.cache import cache_clear
    count = cache_clear()
    console.print(f"[cp.green]✓ Cleared {count} cached items.[/cp.green]")
