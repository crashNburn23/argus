# Argus

> **Personal project — under active development.** This is a side project I'm building to
> explore multi-agent AI for threat intelligence workflows. It works, but expect rough
> edges. Feel free to use it as inspiration for your own tooling rather than dropping it
> straight into production.

Terminal-based cyber threat intelligence harness. Ask questions in plain English or run
commands — Argus routes to the right agents, hits your threat feeds, and comes back with
answers.

```
argus> Is 1.2.3.4 malicious?
argus> What's APT29 been up to lately?
argus> /vuln CVE-2021-44228
```

Runs on Claude or a local Ollama model. All threat-feed integrations are optional and
activate automatically when you add an API key.

---

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
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
OTX_API_KEY=
ABUSEIPDB_API_KEY=
RECORDED_FUTURE_API_KEY=
```

Free sources (no key needed): MITRE ATT&CK, NVD, CISA KEV, URLhaus, web search.

Run `argus doctor` to check what's configured and ready before you start.

---

## Interactive session

```bash
argus
```

Keeps conversation context across turns so follow-up questions work. Tab-completes
slash commands. Arrow keys scroll history. Bottom bar shows active model and theme.

**Slash commands**

```
/enrich  <indicator...>          Enrich IPs, domains, hashes, URLs
/research <actor or campaign>    Threat actor and campaign research
/vuln    <CVE-ID...>             CVE intelligence
/report  daily|weekly|incident   Generate a report
/triage  <raw log>               Triage a raw alert

/model   [name]                  Show or switch model
/theme   [name]                  Switch colour theme (cyberpunk/analyst/contrast/mono)
/save    [title]                 Save this conversation
/resume  <session-id>            Resume a saved conversation
/sessions                        List saved conversations
/sources                         Show which feeds are configured
/runs    [N]                     Recent agent run history
/doctor                          Config and connectivity check
/clear                           Fresh conversation
/help                            This list
```

Themes recolour the entire session history immediately so you can see the difference.

---

## One-shot commands

```bash
# Enrich
argus enrich ip 1.2.3.4
argus enrich domain evil.com --json

# Threat actors
argus research actor "Lazarus Group"
argus research campaign "Operation SolarWinds"

# CVEs
argus vuln cve CVE-2021-44228
argus vuln search --severity critical --json

# Alerts
argus triage alerts alerts.json
argus triage alert --raw-log "src=1.2.3.4 action=blocked"

# Reports
argus report generate daily
argus report incident alerts.json --classification TLP:RED

# Natural language
argus ask "Summarise the ransomware landscape this week"
```

All commands accept `--json` for machine-readable output.

---

## Benchmarks

Eight synthetic IR tickets with known-correct decisions, ATT&CK techniques, and response
actions. Useful for comparing models or validating changes.

```bash
argus benchmark run --all
argus benchmark run --all --minimum-score 0.8   # non-zero exit if score drops
argus benchmark run --all --json
```

---

## How it works

```
User query
    │
CTIOrchestrator  (model decides which agents to call)
    ├── IOCEnrichmentAgent   → VT, Shodan, AbuseIPDB, OTX, URLhaus
    ├── ThreatActorAgent     → MITRE ATT&CK, OTX, Recorded Future, web
    ├── VulnIntelAgent       → NVD, CISA KEV, Shodan
    └── TriageAgent          → VT, AbuseIPDB, OTX, MITRE ATT&CK

ReportAgent collects from all four in parallel and writes the narrative.
```

Each agent runs its own model tool-use loop against real APIs, then synthesises the
results into a structured response. The orchestrator combines everything into a final
answer.

---

## Development

```bash
uv run pytest
uv run ruff check src tests
uv run mypy src/argus --ignore-missing-imports
```

CI runs all three on every push.
