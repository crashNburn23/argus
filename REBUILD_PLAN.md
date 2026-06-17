# Argus Rebuild Plan

This plan assumes we are restarting the product around a CTI-first data model rather than
continuing to extend the current LLM-first CLI. The goal is not to add more prompts. The
goal is to build a system that can ingest intelligence, normalize it, preserve evidence,
pivot across relationships, and generate audience-specific products from the same case.

## Product Goal

Argus should be able to:

- ingest threat reports, alerts, and structured intelligence
- extract observables, indicators, actors, campaigns, malware, vulnerabilities, and TTPs
- enrich and pivot from those entities across external sources
- preserve evidence provenance and source coverage
- generate useful outputs for CTI, SOC, VM, IR, Red Team, Awareness, and leadership

If a result cannot be traced back to evidence or a clearly labeled inference, it does not
belong in the platform.

## Core Principles

1. Evidence first, narrative second.
2. Every claim must carry provenance.
3. Normalize before you synthesize.
4. Reports are views over cases, not isolated LLM outputs.
5. Tool failures must be typed and visible.
6. Time windows and source coverage are mandatory.
7. The model assists extraction and synthesis; it is not the source of truth.

## What To Keep

- Existing threat-intel integrations that are genuinely useful:
  - MITRE ATT&CK
  - NVD
  - CISA KEV
  - URLhaus
  - VirusTotal
  - Shodan
  - AbuseIPDB
  - AlienVault OTX
  - Recorded Future
  - MISP
  - WHOIS, passive DNS, cert pivots, and SIEM integrations
- The synthetic benchmark incident corpus and reference reports
- The CLI shell and diagnostics entry points
- The current report templates as a temporary rendering layer

## What To Replace

- Prompt-only workflows that return a final report directly
- Silent failure handling that turns parse errors into empty findings
- Scope-string-based collection with no case model
- Report synthesis that is not backed by stored evidence
- Any flow that cannot explain why a conclusion was made

## Resolved Decisions

### Persistence: JSON files per case

Cases are stored as individual JSON files (`~/.argus/cases/{case_id}.json`) via `model_dump_json()` / `model_validate_json()`. A `CaseStore` class in `storage/` owns all read/write operations.

The existing SQLAlchemy/SQLite layer stays for IOC cache and run records — it is not used for case storage.

Cross-case pivot queries load cases into memory at query time. This is acceptable for single-analyst scale (hundreds of cases). If scale requirements change, the `CaseStore` interface can be backed by a DB without touching case models or callers.

### Failure Handling: Epic 6 as planned

Typed failure primitives (`EvidenceStatus.FAILED`, `CollectionTask.failure_reason`) are already present in the Phase 1 models. Full typed error payloads, partial-success handling, and CLI exposure of failures are scoped to Epic 6.

---

## Target Architecture

### 1. Ingestion Layer

Accept raw content from:

- text and markdown
- JSON and CSV
- alert exports
- PDFs and documents
- STIX bundles
- analyst notes
- threat reports and vendor writeups

The ingestion layer should:

- store the original artifact
- extract entities and observables
- normalize identifiers
- retain exact source text for provenance
- mark uncertain extractions as such

### 2. Evidence Model

Add a common evidence layer with fields such as:

- source name
- source type
- collection time
- raw excerpt
- normalized entity reference
- confidence basis
- external reference or URL
- status: confirmed, inferred, missing, failed

This is the backbone of the rebuild. Without it, report generation is just a better
prompt.

### 3. Entity and Relationship Graph

Represent and connect:

- documents
- evidence items
- observables
- indicators
- actors
- campaigns
- malware
- vulnerabilities
- techniques
- infrastructure
- sightings
- relationships

Support pivots such as:

- indicator to infrastructure
- infrastructure to actor
- actor to campaign
- campaign to technique
- technique to detection guidance
- vulnerability to exploitation status

### 4. Case Workspace

Treat a case as the central workflow object.

A case should hold:

- source artifacts
- analyst notes
- PIRs
- evidence
- extraction results
- pivot jobs
- runs
- reports
- timelines

This is where CTI work should live. Reports should be generated from a case, not from a
blank query.

### 5. Audience-Specific Output

Generate separate products from the same case for:

- Threat Overview
- CTI Team
- SOC and Detection Engineering
- Vulnerability Management
- Red Team and Adversary Emulation
- Incident Response
- Security Awareness
- Executive Briefing

Each audience needs different emphasis, not just a different title.

### 6. Agent Communication Layer

Three resolved decisions that cut across all agents:

**Streaming progress.** Every agent emits short status lines to the CLI as it runs — tool
calls made, findings, gaps, and failures. `BaseAgent` exposes a `status_callback` that the
CLI wires to its renderer. Agents call it at key moments: query sent, results received,
enrichment outcome, failure encountered. This is not optional output — it is the primary
way operators understand what the system is doing.

**Clarification protocol.** The orchestrator asks clarifying questions in two places:
- Pre-run: before any collection starts, ambiguities about scope, audience, or depth are
  raised and resolved
- Mid-run: when an agent hits a meaningful decision point (no data found, weak attribution,
  optional expansion), it surfaces a yes/no or choice prompt rather than making a silent
  assumption

The orchestrator owns the question queue. Agents signal that a pause is needed; they do
not directly prompt the user.

**Review agent.** After the main agents complete and before a report is finalized, a
`ReviewAgent` reads the draft output and checks every claim against stored evidence
records. Claims without an `evidence_id` or an explicit `INFERRED` label are flagged. The
report is not generated until grounding passes or flagged items are resolved. This is the
primary mechanism for keeping the system honest.

## Rebuild Phases

### Phase 0: Reset The Shape Of The Product

Define the new product boundaries before adding features.

Deliverables:

- canonical data model for cases, evidence, and entities
- architecture notes for ingestion, pivoting, and reporting
- clear separation between raw artifacts, evidence, and conclusions

Exit criteria:

- the repo has a written model for what the system stores and why
- the current codebase can be mapped onto the new structure without ambiguity

### Phase 1: Data Model And Persistence

Build the core entities and storage layer first.

Deliverables:

- normalized database models
- provenance fields on evidence and findings
- case storage
- relationship storage
- run records for ingestion, extraction, enrichment, and reporting

Exit criteria:

- a case can store raw input, evidence, and derived entities
- a report can be regenerated from stored data

### Phase 2: Ingestion And Extraction

Add parsers and extractors that turn raw material into structured intelligence.

Deliverables:

- document ingestion
- IOC extraction
- CVE extraction
- ATT&CK technique extraction
- actor and campaign extraction
- deduplication and canonicalization

Exit criteria:

- a report or alert file can be ingested into a case
- extracted entities are visible and queryable

### Phase 3: Enrichment And Pivoting

Make the platform useful for investigation, not just storage.

Deliverables:

- IOC enrichment
- passive DNS pivots
- certificate pivots
- WHOIS pivots
- infrastructure clustering
- source coverage reporting

Exit criteria:

- one indicator produces related infrastructure with provenance
- pivot depth and source coverage are visible

### Phase 4: Case Workflow

Turn the system into an investigation workspace.

Deliverables:

- case creation and lifecycle
- analyst notes
- PIR tracking
- timelines
- run history
- evidence review

Exit criteria:

- an analyst can open a case, add evidence, pivot, and review a timeline

### Phase 5: Report Products

Generate audience-specific outputs from the same evidence base.

Deliverables:

- CTI overview report
- SOC detection report
- vulnerability report
- incident response report
- executive briefing
- awareness summary

Exit criteria:

- the same case can produce different products without redoing collection
- each product cites evidence and notes gaps

### Phase 6: Honest Failure Handling

Make failure explicit everywhere.

Deliverables:

- typed tool and agent errors
- partial success handling
- parse and validation failure reporting
- JSON output that distinguishes no data from broken collection

Exit criteria:

- no failed tool call is rendered as a clean empty result
- CLI and JSON outputs expose failures consistently

### Phase 7: Analyst Controls

Give the operator control over collection and synthesis.

Deliverables:

- source selection
- confidence thresholds
- time windows
- collection profiles
- export options

Exit criteria:

- analysts can tune the system instead of only prompting it

### Phase 8: Test And Harden

Stabilize the rebuild with strong regression coverage.

Deliverables:

- ingestion tests
- pivot tests
- case workflow tests
- report rendering tests
- failure-path tests
- mocked source integrations

Exit criteria:

- the core workflows run without live model or live feed access
- failures are covered, not hand-waved

## First Milestone

The first milestone should be this single flow:

1. ingest a threat report or alert file
2. extract entities and evidence
3. enrich and pivot the indicators
4. attach everything to a case
5. generate a CTI report with provenance

If that does not work cleanly, nothing else matters yet.

## Suggested Build Order

1. Data model and case storage
2. Ingestion and extraction
3. Provenance and evidence display
4. Pivot graph and enrichment
5. Case workflow
6. Report products
7. Failure handling
8. Analyst controls
9. Tests and hardening

## Non-Goals For The First Rebuild Pass

- full GUI
- multi-tenant RBAC
- heavy workflow automation
- elaborate dashboarding
- generic chat-first product expansion
- adding more report templates before the evidence layer exists

## Success Definition

The rebuild is successful when a user can:

- load a report, alert bundle, or case artifact
- see the extracted entities and evidence
- pivot across related infrastructure and activity
- review why conclusions were made
- generate CTI, SOC, VM, IR, awareness, and executive outputs from the same case

At that point the platform is CTI-first rather than model-first.
