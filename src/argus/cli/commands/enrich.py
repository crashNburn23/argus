"""argus enrich — IOC enrichment commands."""
from __future__ import annotations

import asyncio
from typing import Annotated, Any

import typer

from argus.cli.output import print_agent_error, print_error, render_ioc_result, working

app = typer.Typer(help="Enrich indicators of compromise")


def _run(indicators: list[str], ioc_type: str, as_json: bool) -> None:
    from argus.agents.errors import AgentError
    from argus.agents.ioc_agent import IOCEnrichmentAgent

    async def _go() -> Any:
        with working(f"Enriching {len(indicators)} indicator(s)...", enabled=not as_json):
            return await IOCEnrichmentAgent().run(indicators=indicators, ioc_type=ioc_type)

    try:
        result = asyncio.run(_go())
        render_ioc_result(result, as_json=as_json)
    except AgentError as e:
        print_agent_error(e, as_json=as_json)
        raise typer.Exit(1)
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)


@app.command("ip")
def enrich_ip(
    addresses: Annotated[list[str], typer.Argument(help="IP addresses to enrich")],
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Enrich one or more IP addresses."""
    _run(addresses, "ip", json)


@app.command("domain")
def enrich_domain(
    domains: Annotated[list[str], typer.Argument(help="Domains to enrich")],
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Enrich one or more domain names."""
    _run(domains, "domain", json)


@app.command("hash")
def enrich_hash(
    hashes: Annotated[list[str], typer.Argument(help="File hashes to enrich (MD5/SHA1/SHA256)")],
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Enrich one or more file hashes."""
    _run(hashes, "auto", json)


@app.command("url")
def enrich_url(
    urls: Annotated[list[str], typer.Argument(help="URLs to enrich")],
    json: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Enrich one or more URLs."""
    _run(urls, "url", json)
