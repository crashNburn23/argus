# Argus

> **Personal project — under active development.** This is a side project I'm building to
> explore multi-agent AI for threat intelligence workflows. It works, but expect rough
> edges. Feel free to use it as inspiration for your own tooling rather than dropping it
> straight into production.

Terminal-based cyber threat intelligence harness built around **case workspaces**. Load
artifacts, extract indicators, enrich them against your feeds, pivot across infrastructure,
and generate audience-specific reports — all from a single case that keeps every piece of
evidence and its provenance in one place.

```
argus> /case new "Log4Shell campaign"
argus> /case use case_abc123
argus> What threat actors are known to exploit Log4Shell?
```

Runs on Claude or a local Ollama model. All threat-feed integrations are optional and
activate automatically when you add an API key.

## Setup

```bash
git clone https://github.com/crashNburn23/argus
cd argus
./setup.sh
```

Requires [uv](https://docs.astral.sh/uv/). Edit `.env` after setup with your keys.

```bash
# Minimum to get started
ANTHROPIC_API_KEY=sk-ant-...
MODEL_PROVIDER=anthropic
MODEL=claude-sonnet-4-6

# Or use a local model
MODEL_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434

# Optional — tools activate when keys are present
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
OTX_API_KEY=
RECORDED_FUTURE_API_KEY=

# Optional data-disclosure controls
# unrestricted | confirm-external | local-only
DISCLOSURE_MODE=unrestricted
```

Free sources (no key needed): MITRE ATT&CK, NVD, CISA KEV, URLhaus, passive DNS,
SSL certs, WHOIS, web search.

Use `DISCLOSURE_MODE=confirm-external` to prompt before interactive or `argus ask`
queries are sent to the configured model. Use `DISCLOSURE_MODE=local-only` with
`MODEL_PROVIDER=ollama` to keep model traffic local and block all external enrichment,
pivot, and tool calls.

Run `argus doctor` to check what's configured before you start.

## Case workflow

Cases are the primary unit of work. Each case stores artifacts, extracted observables,
enrichment evidence, pivot results, analyst notes, and generated reports.

```bash
# Create and populate a case
argus case create "Log4Shell exploitation campaign"
argus case artifact <id> --file siem_export.csv --type alert_export
argus case artifact <id> --file intel.stix.json --type report
argus case artifact <id> --text "Callback to 198.51.100.10 CVE-2021-44228" --type note

# Extract observables — auto-detects STIX bundles, JSON alert arrays, CSV, and free text
argus case extract <id>

# Enrich without an LLM — routes by observable type
# IP → AbuseIPDB + Shodan  |  Domain/URL/Hash → VirusTotal  |  CVE → NVD
argus case enrich <id>
argus case enrich <id> --sources abuseipdb,nvd     # limit sources
argus case enrich <id> --min-confidence 0.7

# Pivot across infrastructure (passive DNS, SSL certs, WHOIS)
argus case pivot <id>
argus case pivot <id> --sources passive_dns,whois

# Generate a deterministic evidence report (no LLM)
argus case report <id>

# Generate an LLM-synthesised intelligence product
# Audiences: cti  soc  vm  ir  exec  awareness  redteam
argus case analyze <id> --audience soc
argus case analyze <id> --audience exec --review   # grounding check after generation

# Case lifecycle
argus case list
argus case show <id>
argus case status <id> active    # open → active → closed
argus case timeline <id>
argus case note <id> "Confirmed C2 via passive DNS"
argus case pir <id> "Which actor is behind this campaign?" --priority high
```

All commands accept `--json` for machine-readable output.

## Interactive session

```bash
argus
```

Keeps conversation context across turns. Active case is shown in the bottom toolbar and
follows you into every `/case` subcommand.

**Slash commands**

```
Case
  /case new <title>          Create a case and set it active
  /case list                 List recent cases
  /case use <id>             Switch active case
  /case show                 Summary of active case
  /case enrich [args]        Enrich active case observables
  /case pivot [args]         Pivot active case observables
  /case analyze [args]       LLM analysis of active case
  /case report [args]        Deterministic report from active case

Research
  /research <actor>          Threat actor and campaign research
  /vuln <CVE>                CVE intelligence

Session
  /model   [name]            Show or switch model
  /theme   [name]            Colour theme: analyst / midnight / nord / ember
  /status                    Session info and active case
  /clear                     Fresh conversation
  /help                      This list

Other
  /serve                     Open the web UI in a browser
```

## Web UI

Build the frontend once before first run:

```bash
cd webui && npm install && npm run build
```

Then start the server:

```bash
argus serve              # http://127.0.0.1:8000
argus serve --port 9000
argus serve --reload     # auto-reload on code changes (dev)
```

Or from inside the interactive session: `/serve`

React + Tailwind frontend backed by FastAPI. Five pages:

| Page | What it does |
|------|-------------|
| **Chat** | Full conversation interface — same as the terminal session, works with active cases |
| **Cases** | Browse, create, and inspect cases; view artifacts, observables, evidence, and reports |
| **IOC Graph** | Force-directed network diagram of enrichment and pivot results for the active case |
| **Tools** | See which integrations are configured and their live availability status |
| **Settings** | Edit model, provider, API keys, and data-disclosure mode without touching `.env` directly |

The IOC Graph is the most useful view after running `case enrich` + `case pivot` — it shows how IPs, domains, and certificates cluster across infrastructure.

## One-shot commands

```bash
# Research
argus research actor "Lazarus Group"
argus research campaign "Operation SolarWinds"

# Vulnerability intelligence
argus vuln cve CVE-2021-44228
argus vuln search --severity critical --json

# Alert triage
argus triage alerts alerts.json
argus triage alert --raw-log "src=1.2.3.4 action=blocked"

# Natural language (orchestrator)
argus ask "What TTPs does APT29 use against financial institutions?"

# Diagnostics
argus doctor
argus cache stats
```

## Benchmarks

Eight synthetic IR tickets with known-correct triage decisions, ATT&CK techniques, and
response actions. Useful for comparing models or validating changes.

```bash
argus benchmark run --all
argus benchmark run --all --minimum-score 0.8   # non-zero exit if score drops
argus benchmark run --all --json
```

Deterministic IOC-pivot and evidence-grounded reporting suites are also included:

```bash
argus benchmark pivot list
argus benchmark pivot run --all --minimum-score 0.8

argus benchmark report list
argus benchmark report run --all --minimum-score 0.8
argus benchmark report run --all --save-baseline baselines/reporting.json
```

The reporting suite covers CTI, SOC, executive, and IR audiences. It scores factual
coverage, evidence attachment, required structure, actions, intelligence gaps, unknown
citations, and prohibited unsupported claims.

### Model baselines

Save a run as a named baseline, then compare future runs against it:

```bash
# Capture current model's performance
argus benchmark run --all --save-baseline baselines/sonnet-4-6.json

# Later — switch model in .env, then compare
argus benchmark run --all --compare baselines/sonnet-4-6.json
```

The comparison output shows per-case score deltas and the overall average delta so you
can see exactly where a model gained or lost ground. The `--json` flag includes
`baseline_score` and `score_delta` fields for scripting.

## Architecture

```
Ingestion layer (no LLM)
  case extract
    ├── STIX 2.x bundle     → indicators, threat actors, malware, relationships
    ├── JSON alert array    → field-name heuristics + regex fallback
    ├── CSV alert/IOC list  → field-name heuristics, auto-detect delimiter
    └── Free text           → regex: IP, domain, URL, hash, CVE, ATT&CK TTP

Enrichment layer (no LLM)
  case enrich              → AbuseIPDB, Shodan, VirusTotal, NVD
  case pivot               → passive DNS, SSL certs, WHOIS

Analysis layer (LLM)
  case analyze             → CaseReportAgent (audience-specific narrative)
                             └── ReviewAgent (grounding check, --review flag)
  case report              → deterministic Markdown from stored evidence

Orchestrator (interactive / one-shot queries)
  CTIOrchestrator
    ├── url_fetch           → fetch + clean text of a URL (HTML stripper, IOC pre-extract)
    ├── ThreatActorAgent    → MITRE ATT&CK, OTX, Recorded Future, web
    ├── VulnIntelAgent      → NVD, CISA KEV, Shodan
    ├── TriageAgent         → VT, AbuseIPDB, OTX, MITRE ATT&CK
    └── CaseAnalysisAgent   → IOC enrichment + mandatory infrastructure pivoting
```

Each agent runs its own model tool-use loop, returns a typed Pydantic result, and stores
a run record. The orchestrator fetches URLs before dispatching sub-agents, then uses
CaseAnalysisAgent to enrich any IOCs found. A verification pass identifies retriable vs
permanent gaps before returning.

## Development

```bash
uv run pytest
uv run ruff check src tests
uv run mypy src/argus --ignore-missing-imports
```

CI (pre-commit hooks) runs all three on every push. Currently 210 tests.

## TODO

- [x] Architecture review against harness design best practices
      — 7/14 practices fully satisfied, 5 partial, 1 gap (sprint contracts / planning step).
        Top fixes applied: evidence cap + priority sort in `_compile_case_prompt`, grounding
        prompt improvements in `CaseReportAgent`, `ReviewResult` logged to `ReportArtifact`.

## License

MIT © 2026 crashNburn23
