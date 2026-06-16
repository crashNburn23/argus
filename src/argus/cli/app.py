"""Argus CLI — root Typer application."""
from __future__ import annotations

import asyncio
import shlex
from collections.abc import Generator
from pathlib import Path
from typing import Any

import typer
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style

from argus.cli.commands import (
    benchmark,
    doctor,
    enrich,
    model,
    query,
    report,
    research,
    triage,
    vuln,
)
from argus.cli.output import (
    cache_clear_display,
    cache_stats_display,
    console,
    print_agent_error,
    render_markdown,
    status,
)
from argus.storage.sessions import (
    delete_session,
    generate_session_id,
    list_sessions,
    load_session,
    save_session,
)

# ---------------------------------------------------------------------------
# prompt_toolkit per-theme styles
# ---------------------------------------------------------------------------

_PT_STYLES: dict[str, dict[str, str]] = {
    "analyst": {
        "argus-name":  "#6677aa bold",
        "argus-arrow": "#4499cc bold",
        "completion-menu":                    "bg:#000d1a #4499cc",
        "completion-menu.completion":         "bg:#000d1a #4499cc",
        "completion-menu.completion.current": "bg:#334466 #ffffff bold",
        "completion-menu.meta":               "bg:#000d1a #445588",
        "completion-menu.meta.current":       "bg:#334466 #aaaacc",
        "completion-menu.multi-column-meta":  "bg:#000d1a #4499cc",
        "scrollbar.background": "bg:#000d1a",
        "scrollbar.button":     "bg:#334466",
        "auto-suggest":         "#334455",
        "bottom-toolbar":       "bg:#000d1a #334466",
    },
    "contrast": {
        "argus-name":  "bold ansimagenta",
        "argus-arrow": "bold ansicyan",
        "completion-menu":                    "bg:ansiblack ansicyan",
        "completion-menu.completion":         "bg:ansiblack ansicyan",
        "completion-menu.completion.current": "bg:ansiblue bold ansiwhite",
        "completion-menu.meta":               "bg:ansiblack ansiblue",
        "completion-menu.meta.current":       "bg:ansiblue ansiwhite",
        "completion-menu.multi-column-meta":  "bg:ansiblack ansicyan",
        "scrollbar.background": "bg:ansiblack",
        "scrollbar.button":     "bg:ansiblue",
        "auto-suggest":         "ansiblue",
        "bottom-toolbar":       "bg:ansiblack bold ansicyan",
    },
    "mono": {
        "argus-name":  "bold underline",
        "argus-arrow": "bold",
        "completion-menu":                    "reverse",
        "completion-menu.completion":         "reverse",
        "completion-menu.completion.current": "bold",
        "completion-menu.meta":               "dim reverse",
        "completion-menu.meta.current":       "bold",
        "completion-menu.multi-column-meta":  "reverse",
        "scrollbar.background": "",
        "scrollbar.button":     "reverse",
        "auto-suggest":         "italic",
        "bottom-toolbar":       "reverse",
    },
    "midnight": {
        "argus-name":  "#a070a0 bold",
        "argus-arrow": "#7ca2d6 bold",
        "completion-menu":                    "bg:#0d1a2e #7ca2d6",
        "completion-menu.completion":         "bg:#0d1a2e #7ca2d6",
        "completion-menu.completion.current": "bg:#2a3a5a #ffffff bold",
        "completion-menu.meta":               "bg:#0d1a2e #6b6aad",
        "completion-menu.meta.current":       "bg:#2a3a5a #c0c0e0",
        "completion-menu.multi-column-meta":  "bg:#0d1a2e #7ca2d6",
        "scrollbar.background": "bg:#0d1a2e",
        "scrollbar.button":     "bg:#2a3a5a",
        "auto-suggest":         "#3a4a5e",
        "bottom-toolbar":       "bg:#0d1a2e #2a3a5a",
    },
    "nord": {
        "argus-name":  "#b48ead bold",
        "argus-arrow": "#88c0d0 bold",
        "completion-menu":                    "bg:#2e3440 #88c0d0",
        "completion-menu.completion":         "bg:#2e3440 #88c0d0",
        "completion-menu.completion.current": "bg:#4c566a #eceff4 bold",
        "completion-menu.meta":               "bg:#2e3440 #81a1c1",
        "completion-menu.meta.current":       "bg:#4c566a #d8dee9",
        "completion-menu.multi-column-meta":  "bg:#2e3440 #88c0d0",
        "scrollbar.background": "bg:#2e3440",
        "scrollbar.button":     "bg:#4c566a",
        "auto-suggest":         "#4c566a",
        "bottom-toolbar":       "bg:#2e3440 #3b4252",
    },
    "ember": {
        "argus-name":  "#d4714f bold",
        "argus-arrow": "#e8a26b bold",
        "completion-menu":                    "bg:#1a0d05 #e8a26b",
        "completion-menu.completion":         "bg:#1a0d05 #e8a26b",
        "completion-menu.completion.current": "bg:#6b4422 #ffffff bold",
        "completion-menu.meta":               "bg:#1a0d05 #996644",
        "completion-menu.meta.current":       "bg:#6b4422 #e0c8a0",
        "completion-menu.multi-column-meta":  "bg:#1a0d05 #e8a26b",
        "scrollbar.background": "bg:#1a0d05",
        "scrollbar.button":     "bg:#6b4422",
        "auto-suggest":         "#5a3a22",
        "bottom-toolbar":       "bg:#1a0d05 #6b4422",
    },
}


def _pt_style() -> Style:
    from argus.cli.output import get_theme
    return Style.from_dict(_PT_STYLES.get(get_theme(), _PT_STYLES["analyst"]))

_PROMPT_TOKENS = FormattedText([
    ("class:argus-name",  "argus"),
    ("class:argus-arrow", "> "),
])


def _make_toolbar(session_id: str = "") -> str:
    try:
        from argus.cli.output import get_theme
        from argus.config.settings import get_settings
        s = get_settings()
        sid_part = f"  ·  session:{session_id[:8]}" if session_id else ""
        return f"  {s.model_provider}/{s.model}  ·  theme:{get_theme()}{sid_part} "
    except Exception:
        return "  argus "

app = typer.Typer(
    name="argus",
    help="Argus — Cyber Threat Intelligence AI harness powered by Claude",
    no_args_is_help=False,
    rich_markup_mode="rich",
)

# Register sub-apps
app.add_typer(enrich.app, name="enrich", help="Enrich IOCs (ip, domain, hash, url)")
app.add_typer(research.app, name="research", help="Research threat actors and campaigns")
app.add_typer(vuln.app, name="vuln", help="Vulnerability intelligence")
app.add_typer(triage.app, name="triage", help="Triage security alerts")
app.add_typer(report.app, name="report", help="Generate CTI reports")
app.add_typer(query.app, name="query", help="Natural language queries via orchestrator")
app.add_typer(benchmark.app, name="benchmark", help="Incident response report benchmarks")
app.command("model")(model.model_command)
app.command("doctor")(doctor.doctor_command)
app.command("ask")(query.ask)

_SLASH_COMMANDS = [
    ("/enrich",   "<indicator...>"),
    ("/research", "<actor or campaign>"),
    ("/vuln",     "<CVE-ID...>"),
    ("/report",   "daily|weekly|monthly|yearly|incident"),
    ("/triage",   "<raw log>"),
    ("/model",    "[name|list]"),
    ("/theme",    "[name|list]"),
    ("/doctor",   ""),
    ("/status",   ""),
    ("/clear",    ""),
    ("/new",      ""),
    ("/cache",    ""),
    ("/sessions", "[delete <id>]"),
    ("/save",     "[title]"),
    ("/resume",   "<session-id>"),
    ("/runs",     "[N]"),
    ("/sources",  ""),
    ("/help",     ""),
    ("/exit",     ""),
    ("/quit",     ""),
]

_REPORT_TYPES = ["daily", "weekly", "monthly", "yearly", "incident"]


def _ollama_models() -> list[str]:
    try:
        from argus.cli.commands.model import list_ollama_models
        from argus.config.settings import get_settings
        return list_ollama_models(get_settings().ollama_base_url, timeout=1.0)
    except Exception:
        return []


class _ArgusCompleter(Completer):
    def get_completions(
        self, document: Any, complete_event: Any
    ) -> Generator[Completion, None, None]:
        text = document.text_before_cursor
        if not text.startswith("/"):
            return

        parts = text.split(None, 1)
        verb = parts[0]

        # Still typing the command name — complete it
        if len(parts) == 1:
            for cmd, hint in _SLASH_COMMANDS:
                if cmd.startswith(verb):
                    yield Completion(
                        cmd[len(verb):],
                        display=cmd,
                        display_meta=hint,
                    )
            return

        partial = parts[1].lstrip()

        # /report → complete report type
        if verb == "/report":
            for rt in _REPORT_TYPES:
                if rt.startswith(partial):
                    yield Completion(rt[len(partial):], display=rt)

        # /model → complete "list" or local Ollama model names
        elif verb == "/model":
            candidates = ["list"] + _ollama_models()
            for c in candidates:
                if c.startswith(partial):
                    yield Completion(c[len(partial):], display=c)

        # /theme → complete theme names
        elif verb == "/theme":
            from argus.cli.output import get_theme_names
            for nm in ["list"] + get_theme_names():
                if nm.startswith(partial):
                    yield Completion(nm[len(partial):], display=nm)

        # /sessions → complete "delete" subcommand
        elif verb == "/sessions":
            for sub in ["delete"]:
                if sub.startswith(partial):
                    yield Completion(sub[len(partial):], display=sub)

        # /resume → complete session IDs
        elif verb == "/resume":
            try:
                for s in list_sessions():
                    sid = s["id"]
                    if sid.startswith(partial):
                        yield Completion(
                            sid[len(partial):],
                            display=sid,
                            display_meta=s.get("title", "")[:40],
                        )
            except Exception:
                pass


_SLASH_HELP = """
[cp.magenta]// ARGUS COMMANDS //[/cp.magenta]

  [cp.cyan]/enrich[/cp.cyan]  [cp.dim]<indicator...>[/cp.dim]   Enrich IPs, domains, URLs, hashes
  [cp.cyan]/research[/cp.cyan] [cp.dim]<actor>[/cp.dim]        Research a threat actor or campaign
  [cp.cyan]/vuln[/cp.cyan]    [cp.dim]<CVE-ID...>[/cp.dim]       Look up CVE intelligence
  [cp.cyan]/report[/cp.cyan]  [cp.dim]daily|weekly|...[/cp.dim]  Generate a CTI report
  [cp.cyan]/triage[/cp.cyan]  [cp.dim]<raw log>[/cp.dim]         Triage a raw alert
  [cp.cyan]/model[/cp.cyan]                       Show or switch model
  [cp.cyan]/model[/cp.cyan]   [cp.dim]<name>[/cp.dim]            Switch to a local Ollama model
  [cp.cyan]/theme[/cp.cyan]                       List available themes
  [cp.cyan]/theme[/cp.cyan]   [cp.dim]<name>[/cp.dim]            Switch theme and re-render history
  [cp.cyan]/doctor[/cp.cyan]                      Check model, storage, and source readiness
  [cp.cyan]/status[/cp.cyan]                      Show active model and conversation state
  [cp.cyan]/clear[/cp.cyan] [cp.dim]or[/cp.dim] [cp.cyan]/new[/cp.cyan]   Start a fresh conversation
  [cp.cyan]/cache[/cp.cyan]                       Cache statistics
  [cp.cyan]/sessions[/cp.cyan]                    List saved sessions
  [cp.cyan]/sessions[/cp.cyan] [cp.dim]delete <id>[/cp.dim]     Delete a saved session
  [cp.cyan]/save[/cp.cyan]    [cp.dim][title][/cp.dim]           Save current session
  [cp.cyan]/resume[/cp.cyan]  [cp.dim]<session-id>[/cp.dim]     Resume a saved session
  [cp.cyan]/runs[/cp.cyan]    [cp.dim][N][/cp.dim]               Show last N agent runs (default 10)
  [cp.cyan]/sources[/cp.cyan]                     Show tool/source availability
  [cp.cyan]/help[/cp.cyan]                        This message
  [cp.cyan]/exit[/cp.cyan]   [cp.dim]or[/cp.dim]  [cp.cyan]/quit[/cp.cyan]      Close session

[cp.dim]Anything else is routed to the orchestrator as a natural language query.[/cp.dim]
"""


async def _handle_slash(
    cmd: str,
    orchestrator: object,
    pt_session: PromptSession[str] | None = None,
    session_state: dict[str, Any] | None = None,
) -> bool:
    """Dispatch a slash command. Returns False if the session should end.

    session_state is a mutable dict with keys:
        id: str — current session ID
        exchanges: list[dict] — accumulated user/assistant exchanges
    """
    parts = shlex.split(cmd) if cmd.strip() else []
    if not parts:
        return True
    verb = parts[0].lower()
    args = parts[1:]

    if verb in ("/exit", "/quit"):
        return False

    if verb == "/help":
        console.print(_SLASH_HELP)

    elif verb == "/enrich":
        if not args:
            console.print("[cp.amber]usage:[/cp.amber] /enrich <indicator> [indicator...]")
        else:
            from argus.agents.ioc_agent import IOCEnrichmentAgent
            from argus.cli.output import render_ioc_result
            status(f"enriching {', '.join(args)}")
            try:
                result: Any = await IOCEnrichmentAgent().run(indicators=args)
                render_ioc_result(result)
            except Exception as exc:
                print_agent_error(exc)

    elif verb == "/research":
        if not args:
            console.print("[cp.amber]usage:[/cp.amber] /research <threat actor or campaign>")
        else:
            from argus.agents.threat_actor_agent import ThreatActorAgent
            from argus.cli.output import render_threat_actor_result
            query_str = " ".join(args)
            status(f"researching {query_str}")
            try:
                result2: Any = await ThreatActorAgent().run(query=query_str)
                render_threat_actor_result(result2)
            except Exception as exc:
                print_agent_error(exc)

    elif verb == "/vuln":
        if not args:
            console.print("[cp.amber]usage:[/cp.amber] /vuln <CVE-ID> [CVE-ID...]")
        else:
            from argus.agents.vuln_agent import VulnIntelAgent
            from argus.cli.output import render_vuln_result
            status(f"looking up {', '.join(args)}")
            try:
                result3: Any = await VulnIntelAgent().run(cve_ids=args)
                render_vuln_result(result3)
            except Exception as exc:
                print_agent_error(exc)

    elif verb == "/report":
        report_type = args[0] if args else "daily"
        valid = ("daily", "weekly", "monthly", "yearly", "incident")
        if report_type not in valid:
            console.print(f"[cp.amber]usage:[/cp.amber] /report <{'|'.join(valid)}>")
        else:
            from argus.reports.generator import ReportGenerator
            status(f"generating {report_type} report")
            try:
                rpt = await ReportGenerator().generate(report_type=report_type, save=False)
                render_markdown(rpt.content)
            except Exception as exc:
                print_agent_error(exc)

    elif verb == "/triage":
        if not args:
            console.print("[cp.amber]usage:[/cp.amber] /triage <raw log text>")
        else:
            from argus.agents.triage_agent import TriageAgent
            from argus.cli.output import render_triage_result
            raw_log = " ".join(args)
            status("triaging alert")
            alert = {"alert_id": "interactive-1", "raw_log": raw_log}
            try:
                result4: Any = await TriageAgent().run(alerts=[alert])
                render_triage_result(result4)
            except Exception as exc:
                print_agent_error(exc)

    elif verb == "/model":
        from argus.cli.commands.model import list_ollama_models, persist_model
        from argus.config.settings import get_settings
        s = get_settings()
        if not args or args[0] == "list":
            console.print(f"Current: [bold]{s.model_provider}[/bold] / [bold]{s.model}[/bold]")
            try:
                models = list_ollama_models(s.ollama_base_url)
                from rich.table import Table
                t = Table(title="Local Ollama Models")
                t.add_column("Model")
                for m in models:
                    t.add_row(f"[bold cyan]{m}[/bold cyan]" if m == s.model else m)
                console.print(t)
            except Exception as exc:
                console.print(f"[dim]Ollama unavailable: {exc}[/dim]")
        else:
            name = args[0]
            try:
                available = list_ollama_models(s.ollama_base_url)
            except Exception as exc:
                console.print(f"[red]Could not reach Ollama:[/red] {exc}")
                return True
            if name not in available:
                console.print(
                    f"[red]Model '{name}' not found.[/red]"
                    f" Available: {', '.join(available)}"
                )
                return True
            persist_model("ollama", name)
            console.print(f"Switched to [bold cyan]{name}[/bold cyan]")

    elif verb == "/theme":
        from rich.table import Table as _Table

        from argus.cli.output import (
            THEME_DESCRIPTIONS,
            get_theme,
            get_theme_names,
            set_theme,
        )

        if not args or args[0] == "list":
            current = get_theme()
            t = _Table(
                title="[cp.cyan]Themes[/cp.cyan]",
                show_header=True,
                header_style="cp.magenta",
                border_style="cp.border",
            )
            t.add_column("Name", style="cp.cyan", width=12)
            t.add_column("Description")
            for nm in get_theme_names():
                marker = "  [cp.magenta]◀ active[/cp.magenta]" if nm == current else ""
                t.add_row(nm, THEME_DESCRIPTIONS.get(nm, "") + marker)
            console.print(t)
        else:
            name = args[0].lower()
            if name not in get_theme_names():
                console.print(
                    f"[cp.amber]unknown theme:[/cp.amber] {name}  "
                    f"available: {', '.join(get_theme_names())}"
                )
            else:
                set_theme(name)
                if pt_session is not None:
                    pt_session.style = Style.from_dict(
                        _PT_STYLES.get(name, _PT_STYLES["analyst"])
                    )
                console.print(f"[cp.green]✓[/cp.green] theme: [cp.cyan]{name}[/cp.cyan]")

    elif verb == "/cache":
        cache_stats_display()

    elif verb == "/doctor":
        from argus.cli.commands.doctor import render_diagnostics
        from argus.diagnostics import run_diagnostics

        render_diagnostics(run_diagnostics())

    elif verb == "/status":
        from argus.config.settings import get_settings

        settings = get_settings()
        turns = getattr(orchestrator, "conversation_turns", 0)
        console.print(
            f"Model: [cp.cyan]{settings.model_provider} / {settings.model}[/cp.cyan]\n"
            f"Conversation turns: [cp.cyan]{turns}[/cp.cyan]"
        )

    elif verb in ("/clear", "/new"):
        clear = getattr(orchestrator, "clear_conversation", None)
        if clear:
            clear()
        from argus.cli.output import clear_output_history
        clear_output_history()
        console.clear()
        console.print("[cp.green]▸[/cp.green] [cp.cyan]Fresh conversation started.[/cp.cyan]")

    elif verb == "/sessions":
        if args and args[0] == "delete":
            if len(args) < 2:
                console.print("[cp.amber]usage:[/cp.amber] /sessions delete <id>")
            else:
                sid = args[1]
                if delete_session(sid):
                    console.print(
                        f"[cp.green]✓[/cp.green] session [cp.cyan]{sid}[/cp.cyan] deleted"
                    )
                else:
                    console.print(f"[cp.amber]session not found:[/cp.amber] {sid}")
        else:
            from rich.table import Table as _Table
            sessions = list_sessions()
            if not sessions:
                console.print("[cp.dim]No saved sessions.[/cp.dim]")
            else:
                t = _Table(
                    title="[cp.cyan]Saved Sessions[/cp.cyan]",
                    show_header=True,
                    header_style="cp.magenta",
                    border_style="cp.border",
                )
                t.add_column("ID", style="cp.cyan", no_wrap=True)
                t.add_column("Title")
                t.add_column("Turns", justify="right")
                t.add_column("Updated", no_wrap=True)
                for sess in sessions:
                    updated = sess.get("updated_at", "")[:16].replace("T", " ")
                    t.add_row(
                        sess["id"],
                        sess.get("title", "")[:50],
                        str(sess.get("turns", 0)),
                        updated,
                    )
                console.print(t)

    elif verb == "/save":
        if session_state is None:
            console.print("[cp.dim]No active session to save.[/cp.dim]")
        else:
            exchanges = session_state.get("exchanges", [])
            sid = session_state.get("id", generate_session_id())
            # Default title: first 60 chars of first user message
            default_title = ""
            for ex in exchanges:
                if ex.get("role") == "user":
                    default_title = ex.get("text", "")[:60]
                    break
            title = " ".join(args) if args else (default_title or sid)
            from argus.config.settings import get_settings
            cfg = get_settings()
            model_info = f"{cfg.model_provider}/{cfg.model}"
            save_session(sid, title, model_info, exchanges)
            console.print(
                f"[cp.green]✓[/cp.green] session saved: "
                f"[cp.cyan]{sid}[/cp.cyan]  [cp.dim]{title[:50]}[/cp.dim]"
            )

    elif verb == "/resume":
        if not args:
            console.print("[cp.amber]usage:[/cp.amber] /resume <session-id>")
        else:
            sid = args[0]
            data = load_session(sid)
            if data is None:
                console.print(f"[cp.amber]session not found:[/cp.amber] {sid}")
            else:
                exchanges = data.get("exchanges", [])
                # Rebuild orchestrator conversation
                conversation: list[dict[str, Any]] = []
                for ex in exchanges:
                    conversation.append({"role": ex["role"], "content": ex["text"]})
                setattr(orchestrator, "_conversation", conversation)
                # Update session state
                if session_state is not None:
                    session_state["id"] = sid
                    session_state["exchanges"] = list(exchanges)
                turns = data.get("turns", len([e for e in exchanges if e.get("role") == "user"]))
                title = data.get("title", sid)
                console.print(
                    f"[cp.green]▸[/cp.green] resumed session [cp.cyan]{sid}[/cp.cyan]  "
                    f"[cp.dim]{title[:50]}[/cp.dim]  ({turns} turns)"
                )

    elif verb == "/runs":
        n = 10
        if args:
            try:
                n = int(args[0])
            except ValueError:
                console.print("[cp.amber]usage:[/cp.amber] /runs [N]")
                return True
        try:
            from rich.table import Table as _Table
            from sqlalchemy import desc, select

            from argus.storage.database import get_session as get_db_session
            from argus.storage.models_db import AgentRunRecord

            with get_db_session() as db:
                rows = db.execute(
                    select(AgentRunRecord).order_by(desc(AgentRunRecord.created_at)).limit(n)
                ).scalars().all()

            if not rows:
                console.print("[cp.dim]No agent runs recorded yet.[/cp.dim]")
            else:
                t = _Table(
                    title=f"[cp.cyan]Last {n} Agent Runs[/cp.cyan]",
                    show_header=True,
                    header_style="cp.magenta",
                    border_style="cp.border",
                )
                t.add_column("Time", no_wrap=True)
                t.add_column("Agent")
                t.add_column("Status")
                t.add_column("Tokens", justify="right")
                t.add_column("Duration", justify="right")
                for row in rows:
                    time_str = row.created_at.strftime("%Y-%m-%d %H:%M") if row.created_at else ""
                    tokens = str(row.input_tokens + row.output_tokens)
                    duration = f"{row.duration_seconds:.1f}s"
                    status_style = "cp.green" if row.status == "success" else "cp.amber"
                    t.add_row(
                        time_str,
                        row.agent_name,
                        f"[{status_style}]{row.status}[/{status_style}]",
                        tokens,
                        duration,
                    )
                console.print(t)
        except Exception as exc:
            console.print(f"[red]Error querying runs:[/red] {exc}")

    elif verb == "/sources":
        try:
            from rich.table import Table as _Table

            from argus.tools.registry import tool_status

            statuses = tool_status()
            t = _Table(
                title="[cp.cyan]Tool / Source Availability[/cp.cyan]",
                show_header=True,
                header_style="cp.magenta",
                border_style="cp.border",
            )
            t.add_column("Tool", style="cp.cyan")
            t.add_column("Status")
            t.add_column("Detail")
            for entry in statuses:
                avail = entry["available"]
                status_str = (
                    "[cp.green]enabled[/cp.green]" if avail else "[cp.dim]disabled[/cp.dim]"
                )
                t.add_row(entry["name"], status_str, entry.get("reason", ""))
            console.print(t)
        except Exception as exc:
            console.print(f"[red]Error querying sources:[/red] {exc}")

    else:
        console.print(f"[cp.amber]unknown command:[/cp.amber] {verb}  [cp.dim](try /help)[/cp.dim]")

    return True


async def _interactive_loop() -> None:
    import sys

    from argus.agents.orchestrator import CTIOrchestrator

    orchestrator = CTIOrchestrator(persistent=True)

    # Session state tracking
    session_id = generate_session_id()
    session_exchanges: list[dict[str, Any]] = []
    session_state: dict[str, Any] = {"id": session_id, "exchanges": session_exchanges}

    # Use prompt_toolkit only in a real terminal; fall back to plain input() in pipes/tests.
    pt_session: PromptSession[str] | None = None
    if sys.stdin.isatty():
        console.clear()
        history_path = Path.home() / ".argus_history"

        def _toolbar() -> str:
            return _make_toolbar(session_state.get("id", ""))

        pt_session = PromptSession(
            history=FileHistory(str(history_path)),
            auto_suggest=AutoSuggestFromHistory(),
            completer=_ArgusCompleter(),
            complete_while_typing=True,
            style=_pt_style(),
            bottom_toolbar=_toolbar,
        )

    console.print(
        "[cp.magenta]▸ ARGUS[/cp.magenta] [cp.dim]//[/cp.dim]"
        " type a question or [cp.cyan]/help[/cp.cyan] for commands"
    )

    while True:
        try:
            if pt_session is not None:
                line = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: pt_session.prompt(_PROMPT_TOKENS)
                )
            else:
                line = input("argus> ")
            line = line.strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            break

        if not line:
            continue

        if line.startswith("/"):
            if not await _handle_slash(line, orchestrator, pt_session, session_state):
                break
            continue

        try:
            answer = await orchestrator.run(user_query=line)
            render_markdown(answer)
            # Track exchanges for session persistence
            session_state["exchanges"].append({"role": "user", "text": line})
            session_state["exchanges"].append({"role": "assistant", "text": answer})
        except Exception as exc:
            print_agent_error(exc)


def run_interactive() -> None:
    asyncio.run(_interactive_loop())


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """Start an interactive session when no subcommand is provided."""
    if ctx.invoked_subcommand is None:
        run_interactive()


# Cache management commands
cache_app = typer.Typer(help="Cache management")
app.add_typer(cache_app, name="cache")


@cache_app.command("stats")
def cache_stats() -> None:
    """Show cache statistics."""
    cache_stats_display()


@cache_app.command("clear")
def cache_clear(
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
) -> None:
    """Clear the response cache."""
    if not confirm:
        typer.confirm("Clear the entire response cache?", abort=True)
    cache_clear_display()


if __name__ == "__main__":
    app()
