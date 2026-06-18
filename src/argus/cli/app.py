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
from prompt_toolkit.styles import DynamicStyle, Style

from argus.cli.commands import (
    benchmark,
    case,
    doctor,
    model,
    query,
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
    thinking,
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
        "completion-menu":                    "bg:#07111f #c8d3df",
        "completion-menu.completion":         "bg:#07111f #c8d3df",
        "completion-menu.completion.current": "bg:#1f3148 #ffffff bold",
        "completion-menu.meta":               "bg:#07111f #6f8398",
        "completion-menu.meta.current":       "bg:#1f3148 #b7c4d6",
        "completion-menu.multi-column-meta":  "bg:#07111f #6f8398",
        "scrollbar.background": "bg:#07111f",
        "scrollbar.button":     "bg:#1f3148",
        "auto-suggest":         "#334455",
        "bottom-toolbar":       "bg:#000d1a #334466",
    },
    "contrast": {
        "argus-name":  "bold ansimagenta",
        "argus-arrow": "bold ansicyan",
        "completion-menu":                    "bg:ansiblack ansiwhite",
        "completion-menu.completion":         "bg:ansiblack ansiwhite",
        "completion-menu.completion.current": "bg:ansiwhite ansiblack bold",
        "completion-menu.meta":               "bg:ansiblack ansicyan",
        "completion-menu.meta.current":       "bg:ansiwhite ansiblack",
        "completion-menu.multi-column-meta":  "bg:ansiblack ansicyan",
        "scrollbar.background": "bg:ansiblack",
        "scrollbar.button":     "bg:ansiwhite",
        "auto-suggest":         "ansiblue",
        "bottom-toolbar":       "bg:ansiblack bold ansicyan",
    },
    "mono": {
        "argus-name":  "bold underline",
        "argus-arrow": "bold",
        "completion-menu":                    "",
        "completion-menu.completion":         "",
        "completion-menu.completion.current": "reverse bold",
        "completion-menu.meta":               "dim",
        "completion-menu.meta.current":       "reverse",
        "completion-menu.multi-column-meta":  "dim",
        "scrollbar.background": "",
        "scrollbar.button":     "reverse",
        "auto-suggest":         "italic",
        "bottom-toolbar":       "reverse",
    },
    "midnight": {
        "argus-name":  "#a070a0 bold",
        "argus-arrow": "#7ca2d6 bold",
        "completion-menu":                    "bg:#101827 #cad5e2",
        "completion-menu.completion":         "bg:#101827 #cad5e2",
        "completion-menu.completion.current": "bg:#273653 #ffffff bold",
        "completion-menu.meta":               "bg:#101827 #788ca8",
        "completion-menu.meta.current":       "bg:#273653 #c2cce0",
        "completion-menu.multi-column-meta":  "bg:#101827 #788ca8",
        "scrollbar.background": "bg:#101827",
        "scrollbar.button":     "bg:#273653",
        "auto-suggest":         "#3a4a5e",
        "bottom-toolbar":       "bg:#0d1a2e #2a3a5a",
    },
    "nord": {
        "argus-name":  "#b48ead bold",
        "argus-arrow": "#88c0d0 bold",
        "completion-menu":                    "bg:#252b35 #d8dee9",
        "completion-menu.completion":         "bg:#252b35 #d8dee9",
        "completion-menu.completion.current": "bg:#3b4252 #eceff4 bold",
        "completion-menu.meta":               "bg:#252b35 #8f9eb5",
        "completion-menu.meta.current":       "bg:#3b4252 #c8d1df",
        "completion-menu.multi-column-meta":  "bg:#252b35 #8f9eb5",
        "scrollbar.background": "bg:#252b35",
        "scrollbar.button":     "bg:#3b4252",
        "auto-suggest":         "#4c566a",
        "bottom-toolbar":       "bg:#2e3440 #3b4252",
    },
    "ember": {
        "argus-name":  "#d4714f bold",
        "argus-arrow": "#e8a26b bold",
        "completion-menu":                    "bg:#1b130d #e0d3c1",
        "completion-menu.completion":         "bg:#1b130d #e0d3c1",
        "completion-menu.completion.current": "bg:#54331f #ffffff bold",
        "completion-menu.meta":               "bg:#1b130d #9b846e",
        "completion-menu.meta.current":       "bg:#54331f #ddc3a8",
        "completion-menu.multi-column-meta":  "bg:#1b130d #9b846e",
        "scrollbar.background": "bg:#1b130d",
        "scrollbar.button":     "bg:#54331f",
        "auto-suggest":         "#5a3a22",
        "bottom-toolbar":       "bg:#1a0d05 #6b4422",
    },
}


def _pt_style() -> Style:
    from argus.cli.output import get_theme
    return Style.from_dict(_PT_STYLES.get(get_theme(), _PT_STYLES["analyst"]))


app = typer.Typer(
    name="argus",
    help="Argus — Cyber Threat Intelligence AI harness powered by Claude",
    no_args_is_help=False,
    rich_markup_mode="rich",
)

# Register sub-apps
app.add_typer(research.app, name="research", help="Research threat actors and campaigns")
app.add_typer(vuln.app, name="vuln", help="Vulnerability intelligence")
app.add_typer(triage.app, name="triage", help="Triage security alerts")
app.add_typer(case.app, name="case", help="Manage CTI cases (create, enrich, pivot, analyze)")
app.add_typer(query.app, name="query", help="Natural language queries via orchestrator")
app.add_typer(benchmark.app, name="benchmark", help="Incident response report benchmarks")
app.command("model")(model.model_command)
app.command("doctor")(doctor.doctor_command)
app.command("ask")(query.ask)

_SLASH_COMMANDS = [
    ("/case",     "new|list|use|show|enrich|pivot|analyze|report"),
    ("/research", "<actor or campaign>"),
    ("/vuln",     "<CVE-ID...>"),
    ("/triage",   "<raw log>"),
    ("/model",    "[name|list]"),
    ("/theme",    "[name|list]"),
    ("/doctor",   ""),
    ("/status",   ""),
    ("/verbose",  "[on|off]"),
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

_CASE_SUBCOMMANDS = ["new", "list", "use", "show", "enrich", "pivot", "analyze", "report"]

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

        # /case → complete subcommands
        if verb == "/case":
            for sub in _CASE_SUBCOMMANDS:
                if sub.startswith(partial):
                    yield Completion(sub[len(partial):], display=sub)

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

        # /verbose → complete toggle values
        elif verb == "/verbose":
            for value in ["on", "off"]:
                if value.startswith(partial):
                    yield Completion(value[len(partial):], display=value)

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

[cp.magenta]Case workflow:[/cp.magenta]
  [cp.cyan]/case new[/cp.cyan]  [cp.dim]<title>[/cp.dim]     Create a case and set it active
  [cp.cyan]/case list[/cp.cyan]              List recent cases
  [cp.cyan]/case use[/cp.cyan]  [cp.dim]<id>[/cp.dim]        Set the active case
  [cp.cyan]/case show[/cp.cyan]              Show active case summary
  [cp.cyan]/case enrich[/cp.cyan]            Enrich observables in the active case
  [cp.cyan]/case pivot[/cp.cyan]             Pivot active case observables
  [cp.cyan]/case analyze[/cp.cyan] [cp.dim][audience][/cp.dim] LLM report (default: cti)
  [cp.cyan]/case report[/cp.cyan]            Deterministic report (no LLM)

[cp.magenta]Research:[/cp.magenta]
  [cp.cyan]/research[/cp.cyan] [cp.dim]<actor>[/cp.dim]      Research a threat actor or campaign
  [cp.cyan]/vuln[/cp.cyan]     [cp.dim]<CVE-ID...>[/cp.dim]  Look up CVE intelligence
  [cp.cyan]/triage[/cp.cyan]   [cp.dim]<raw log>[/cp.dim]    Triage a raw alert

[cp.magenta]Session:[/cp.magenta]
  [cp.cyan]/model[/cp.cyan]                  Show or switch model
  [cp.cyan]/theme[/cp.cyan]   [cp.dim][name][/cp.dim]        Switch theme (or list)
  [cp.cyan]/doctor[/cp.cyan]                 Check readiness
  [cp.cyan]/status[/cp.cyan]                 Model, active case, conversation state
  [cp.cyan]/verbose[/cp.cyan] [cp.dim][on|off][/cp.dim]      Toggle runtime log messages
  [cp.cyan]/clear[/cp.cyan] [cp.dim]or[/cp.dim] [cp.cyan]/new[/cp.cyan]   Fresh conversation
  [cp.cyan]/cache[/cp.cyan]                  Cache statistics
  [cp.cyan]/sessions[/cp.cyan]               List saved sessions
  [cp.cyan]/save[/cp.cyan]    [cp.dim][title][/cp.dim]       Save current session
  [cp.cyan]/resume[/cp.cyan]  [cp.dim]<id>[/cp.dim]         Resume a saved session
  [cp.cyan]/runs[/cp.cyan]    [cp.dim][N][/cp.dim]           Last N agent runs (default 10)
  [cp.cyan]/sources[/cp.cyan]                Source availability
  [cp.cyan]/help[/cp.cyan]                   This message
  [cp.cyan]/exit[/cp.cyan] [cp.dim]or[/cp.dim] [cp.cyan]/quit[/cp.cyan]   Close session

[cp.dim]Anything else → CTI orchestrator (actor research, CVE queries, SIEM triage).[/cp.dim]
"""


async def _handle_case(args: list[str], session_state: dict[str, Any] | None) -> None:
    """Dispatch /case <subcommand> [args] from the interactive shell."""
    from argus.storage.cases import CaseNotFoundError, CaseStore, CaseStoreError

    sub = args[0].lower() if args else ""
    rest = args[1:]

    if sub == "new":
        from argus.models.case import Case as _Case
        title = " ".join(rest) if rest else "Untitled case"
        try:
            new_case = CaseStore().create(_Case(title=title))
        except CaseStoreError as exc:
            console.print(f"[cp.red]ERR ▸[/cp.red] {exc}")
            return
        if session_state is not None:
            session_state["active_case_id"] = new_case.case_id
        console.print(
            f"[cp.green]✓[/cp.green] case created: [cp.cyan]{new_case.case_id}[/cp.cyan]"
            f"  [cp.dim]{title}[/cp.dim]  (set as active)"
        )

    elif sub == "list":
        try:
            cases = CaseStore().list()[:15]
        except CaseStoreError as exc:
            console.print(f"[cp.red]ERR ▸[/cp.red] {exc}")
            return
        if not cases:
            console.print("[cp.dim]No cases found. Use /case new <title> to create one.[/cp.dim]")
            return
        from rich.table import Table as _Table
        active_id = (session_state or {}).get("active_case_id", "")
        t = _Table(
            title="[cp.cyan]Recent Cases[/cp.cyan]",
            show_header=True,
            header_style="cp.magenta",
            border_style="cp.border",
        )
        t.add_column("", width=2)
        t.add_column("ID", style="cp.cyan", no_wrap=True)
        t.add_column("Title")
        t.add_column("Status")
        t.add_column("Updated", no_wrap=True)
        for c in cases:
            marker = "▶" if c.case_id == active_id else ""
            updated = c.updated_at.strftime("%Y-%m-%d %H:%M") if c.updated_at else ""
            t.add_row(marker, c.case_id[:12], c.title[:50], c.status.value, updated)
        console.print(t)

    elif sub == "use":
        if not rest:
            console.print("[cp.amber]usage:[/cp.amber] /case use <case-id>")
            return
        case_id = rest[0]
        try:
            c = CaseStore().get(case_id)
        except CaseNotFoundError:
            console.print(f"[cp.amber]case not found:[/cp.amber] {case_id}")
            return
        if session_state is not None:
            session_state["active_case_id"] = c.case_id
        console.print(
            f"[cp.green]✓[/cp.green] active case: [cp.cyan]{c.case_id}[/cp.cyan]"
            f"  [cp.dim]{c.title}[/cp.dim]"
        )

    elif sub == "show":
        case_id = str((session_state or {}).get("active_case_id") or "")
        if not case_id:
            console.print("[cp.amber]No active case.[/cp.amber] Use /case use <id> or /case new.")
            return
        try:
            c = CaseStore().get(case_id)
        except CaseNotFoundError:
            console.print(f"[cp.amber]case not found:[/cp.amber] {case_id}")
            return
        console.print(
            f"[cp.cyan]{c.case_id}[/cp.cyan]  [bold]{c.title}[/bold]  [{c.status.value}]\n"
            f"  Observables: [cp.green]{len(c.observables)}[/cp.green]  "
            f"Evidence: [cp.green]{len(c.evidence)}[/cp.green]  "
            f"Relationships: [cp.green]{len(c.relationships)}[/cp.green]  "
            f"Notes: [cp.green]{len(c.notes)}[/cp.green]"
        )
        if c.pirs:
            console.print(f"  PIRs: {', '.join(p.question[:40] for p in c.pirs[:3])}")

    elif sub in ("enrich", "pivot", "analyze", "report"):
        case_id = (session_state or {}).get("active_case_id") or ""
        if not case_id:
            console.print("[cp.amber]No active case.[/cp.amber] Use /case use <id> or /case new.")
            return
        from typer.testing import CliRunner

        from argus.cli.commands.case import app as case_app
        runner = CliRunner()
        extra = list(rest)
        if sub == "analyze" and not any(a.startswith("--audience") for a in extra):
            audience = extra.pop(0) if extra else "cti"
            extra = ["--audience", audience]
        result = runner.invoke(case_app, [sub, case_id, *extra])
        if result.output:
            console.print(result.output.rstrip())
        if result.exit_code != 0 and result.exception:
            console.print(f"[cp.red]ERR ▸[/cp.red] {result.exception}")

    else:
        console.print(
            "[cp.amber]usage:[/cp.amber] /case <new|list|use|show|enrich|pivot|analyze|report>"
        )


async def _handle_slash(
    cmd: str,
    orchestrator: object,
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

    elif verb == "/case":
        await _handle_case(args, session_state)

    elif verb == "/research":
        if not args:
            console.print("[cp.amber]usage:[/cp.amber] /research <threat actor or campaign>")
        else:
            from argus.agents.threat_actor_agent import ThreatActorAgent
            from argus.cli.output import render_threat_actor_result
            query_str = " ".join(args)
            try:
                with thinking(f"researching {query_str}"):
                    result2: Any = await ThreatActorAgent(progress=status).run(query=query_str)
                render_threat_actor_result(result2)
            except Exception as exc:
                print_agent_error(exc)

    elif verb == "/vuln":
        if not args:
            console.print("[cp.amber]usage:[/cp.amber] /vuln <CVE-ID> [CVE-ID...]")
        else:
            from argus.agents.vuln_agent import VulnIntelAgent
            from argus.cli.output import render_vuln_result
            try:
                with thinking(f"looking up {', '.join(args)}"):
                    result3: Any = await VulnIntelAgent(progress=status).run(cve_ids=args)
                render_vuln_result(result3)
            except Exception as exc:
                print_agent_error(exc)

    elif verb == "/triage":
        if not args:
            console.print("[cp.amber]usage:[/cp.amber] /triage <raw log text>")
        else:
            from argus.agents.triage_agent import TriageAgent
            from argus.cli.output import render_triage_result
            raw_log = " ".join(args)
            alert = {"alert_id": "interactive-1", "raw_log": raw_log}
            try:
                with thinking("triaging alert"):
                    result4: Any = await TriageAgent(progress=status).run(alerts=[alert])
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
                console.print(f"[cp.green]✓[/cp.green] theme: [cp.cyan]{name}[/cp.cyan]")

    elif verb == "/cache":
        cache_stats_display()

    elif verb == "/doctor":
        from argus.cli.commands.doctor import render_diagnostics
        from argus.diagnostics import run_diagnostics

        render_diagnostics(run_diagnostics())

    elif verb == "/status":
        from argus.config.settings import get_settings
        from argus.log_config import get_verbose

        settings = get_settings()
        turns = getattr(orchestrator, "conversation_turns", 0)
        verbose = "on" if get_verbose() else "off"
        active_case = (session_state or {}).get("active_case_id", "")
        case_line = (
            f"Active case:  [cp.cyan]{active_case}[/cp.cyan]"
            if active_case
            else "Active case:  [cp.dim]none  (use /case new or /case use <id>)[/cp.dim]"
        )
        console.print(
            f"Model: [cp.cyan]{settings.model_provider} / {settings.model}[/cp.cyan]\n"
            f"{case_line}\n"
            f"Conversation turns: [cp.cyan]{turns}[/cp.cyan]\n"
            f"Verbose logs: [cp.cyan]{verbose}[/cp.cyan]"
        )

    elif verb == "/verbose":
        from argus.log_config import get_verbose, set_verbose

        if args:
            value = args[0].lower()
            if value not in ("on", "off"):
                console.print("[cp.amber]usage:[/cp.amber] /verbose [on|off]")
                return True
            enabled = value == "on"
        else:
            enabled = not get_verbose()
        set_verbose(enabled)
        state = "on" if enabled else "off"
        detail = (
            "runtime log messages enabled"
            if enabled
            else "runtime log messages hidden; agent status updates remain visible"
        )
        console.print(
            f"[cp.green]✓[/cp.green] verbose: [cp.cyan]{state}[/cp.cyan]  "
            f"[cp.dim]{detail}[/cp.dim]"
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


def _pt_make_style() -> Style:
    from argus.cli.output import get_theme
    pt = _PT_STYLES.get(get_theme(), _PT_STYLES["analyst"])
    return Style.from_dict({
        **pt,
        "completion.cmd":  pt.get("completion-menu.completion", ""),
        "completion.meta": pt.get("completion-menu.meta", "dim"),
        "bottom-toolbar":  pt.get("bottom-toolbar", "reverse"),
    })


def _show_first_run_guidance() -> None:
    """Detect missing model configuration and show setup guidance."""
    from argus.diagnostics import run_diagnostics
    try:
        result = run_diagnostics(check_connectivity=False)
    except Exception:
        return
    model_check = next((c for c in result.checks if c.category == "model"), None)
    if model_check and model_check.status != "failed":
        return
    console.print(
        "\n[cp.magenta]▸ First-run setup[/cp.magenta]\n"
        "\nNo model is configured. Choose a path:\n\n"
        "  [cp.cyan]Offline / benchmark only[/cp.cyan]\n"
        "    No keys needed — inspect built-in incident cases:\n"
        "    [cp.dim]argus benchmark list[/cp.dim]\n"
        "    [cp.dim]argus benchmark render --case IR-0001[/cp.dim]\n\n"
        "  [cp.cyan]Local model (Ollama)[/cp.cyan]\n"
        "    1. Install Ollama: https://ollama.com\n"
        "    2. Pull a model:  [cp.dim]ollama pull qwen3:8b[/cp.dim]\n"
        "    3. Select it:     [cp.dim]argus model qwen3:8b --provider ollama[/cp.dim]\n\n"
        "  [cp.cyan]Hosted model (Anthropic)[/cp.cyan]\n"
        "    1. Add key to .env:  [cp.dim]ANTHROPIC_API_KEY=sk-ant-...[/cp.dim]\n"
        "    2. Select model:     "
        "[cp.dim]argus model claude-sonnet-4-6 --provider anthropic[/cp.dim]\n\n"
        "  Run [cp.cyan]argus doctor[/cp.cyan] at any time to check configuration.\n"
    )


async def _interactive_loop() -> None:
    import sys

    from argus.agents.orchestrator import CTIOrchestrator

    _show_first_run_guidance()
    orchestrator = CTIOrchestrator(persistent=True, progress=status)
    session_id = generate_session_id()
    session_state: dict[str, Any] = {"id": session_id, "exchanges": []}

    console.print(
        "[cp.magenta]▸ ARGUS[/cp.magenta] [cp.dim]//[/cp.dim]"
        " type a question or [cp.cyan]/help[/cp.cyan] for commands"
    )

    if not sys.stdin.isatty():
        while True:
            try:
                line = input("argus> ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                break
            if not line:
                continue
            if line.startswith("/"):
                if not await _handle_slash(line, orchestrator, session_state):
                    break
                continue
            try:
                with thinking("argus is thinking"):
                    answer = await orchestrator.run(user_query=line)
                render_markdown(answer)
                session_state["exchanges"].append({"role": "user", "text": line})
                session_state["exchanges"].append({"role": "assistant", "text": answer})
            except Exception as exc:
                print_agent_error(exc)
        return

    def _toolbar() -> str:
        try:
            from argus.cli.output import get_theme
            from argus.config.settings import get_settings
            s = get_settings()
            sid = session_state.get("id", "")
            sid_part = f"  ·  session:{sid[:8]}" if sid else ""
            active_case = session_state.get("active_case_id", "")
            case_part = f"  ·  case:{active_case[:12]}" if active_case else ""
            return f"  {s.model_provider}/{s.model}  ·  theme:{get_theme()}{sid_part}{case_part} "
        except Exception:
            return "  argus "

    pt_session: PromptSession[str] = PromptSession(
        completer=_ArgusCompleter(),
        history=FileHistory(str(Path.home() / ".argus_history")),
        style=DynamicStyle(_pt_make_style),
        bottom_toolbar=_toolbar,
        complete_while_typing=True,
        auto_suggest=AutoSuggestFromHistory(),
    )

    _prompt = FormattedText([
        ("class:argus-name", "  argus"),
        ("class:argus-arrow", " › "),
    ])

    while True:
        try:
            line = await pt_session.prompt_async(_prompt)
        except (EOFError, KeyboardInterrupt):
            console.print()
            break
        line = line.strip()
        if not line:
            continue
        if line.startswith("/"):
            if not await _handle_slash(line, orchestrator, session_state):
                break
            continue
        console.print(f"[cp.dim]you: {line}[/cp.dim]")
        try:
            with thinking("argus is thinking"):
                answer = await orchestrator.run(user_query=line)
            render_markdown(answer)
            session_state["exchanges"].append({"role": "user", "text": line})
            session_state["exchanges"].append({"role": "assistant", "text": answer})
        except Exception as exc:
            print_agent_error(exc)


def run_interactive() -> None:
    asyncio.run(_interactive_loop())


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """Start an interactive session when no subcommand is provided."""
    from argus.log_config import configure_logging
    configure_logging()
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
