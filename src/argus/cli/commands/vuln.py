"""argus vuln — vulnerability intelligence commands."""
from __future__ import annotations

import asyncio
from typing import Annotated, Any

import typer

from argus.cli.output import print_agent_error, render_vuln_result, working

app = typer.Typer(help="Vulnerability intelligence")


@app.command("cve")
def lookup_cve(
    cve_ids: Annotated[list[str], typer.Argument(help="CVE IDs to look up")],
    json: Annotated[bool, typer.Option("--json", "-j")] = False,
) -> None:
    """Look up specific CVE(s)."""
    from argus.agents.vuln_agent import VulnIntelAgent

    async def _go() -> Any:
        with working(f"Looking up {len(cve_ids)} CVE(s)...", enabled=not json):
            return await VulnIntelAgent().run(cve_ids=cve_ids)

    try:
        result = asyncio.run(_go())
        render_vuln_result(result, as_json=json)
    except Exception as e:
        print_agent_error(e, as_json=json)
        raise typer.Exit(1)


@app.command("search")
def search_vulns(
    keyword: Annotated[str | None, typer.Option("--keyword", "-k", help="Search keyword")] = None,
    severity: Annotated[
        str, typer.Option("--severity", "-s", help="Minimum severity: critical|high|medium|low")
    ] = "high",
    json: Annotated[bool, typer.Option("--json", "-j")] = False,
) -> None:
    """Search for vulnerabilities by keyword and/or severity."""
    from argus.agents.vuln_agent import VulnIntelAgent

    async def _go() -> Any:
        with working("Searching vulnerability intelligence...", enabled=not json):
            return await VulnIntelAgent().run(keywords=keyword or "", severity_threshold=severity)

    try:
        result = asyncio.run(_go())
        render_vuln_result(result, as_json=json)
    except Exception as e:
        print_agent_error(e, as_json=json)
        raise typer.Exit(1)
