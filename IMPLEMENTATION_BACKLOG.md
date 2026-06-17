# Argus Implementation Backlog

This backlog is derived from `REBUILD_PLAN.md`. It is the working queue for the restart.
The order matters: each phase should produce a usable artifact before the next one begins.

## Priority Definitions

- **P0:** Required for a CTI-first platform.
- **P1:** Required for trustworthy daily use.
- **P2:** Needed for scale, polish, or operational efficiency after the core model exists.

## Epic 1: Data Model And Persistence

**Goal**

Create the evidence and case backbone that everything else will depend on.

**Storage approach:** JSON files per case (`~/.argus/cases/{case_id}.json`). A `CaseStore`
class in `storage/` owns all reads and writes. The existing SQLAlchemy/SQLite layer stays
for IOC cache and run records only.

**Scope**

- define canonical models for artifacts, evidence, observables, relationships, cases, PIRs,
  and collection tasks
- store provenance, timestamps, source names, and confidence basis
- separate raw artifacts from extracted evidence and analyst conclusions
- preserve links between cases, runs, reports, and source material
- implement `CaseStore` with create, read, update, list, and delete operations

**Exit Criteria**

- a case can store raw input and derived intelligence
- a report can be regenerated from stored evidence
- provenance is present on every stored finding
- cases round-trip cleanly through JSON serialization

## Epic 1b: Agent Communication Infrastructure

**Goal**

Give every agent a consistent way to stream progress and ask clarifying questions.

**Scope**

- add `status_callback` to `BaseAgent` — called at key moments (query sent, results
  received, finding noted, failure hit)
- wire the callback to the CLI renderer so status lines appear in real time
- implement the orchestrator clarification protocol: pre-run question queue, mid-run pause
  signaling from agents, yes/no and choice prompts at the CLI
- define the contract for when agents are allowed to raise a clarification vs. proceed with
  an assumption

**Exit Criteria**

- running any agent prints live status lines to the terminal
- the orchestrator asks scope/audience questions before starting work
- an agent can signal a mid-run pause and the CLI handles it cleanly

## Epic 2: Ingestion And Extraction

**Goal**

Turn raw material into structured intelligence.

**Scope**

- ingest text, markdown, JSON, CSV, STIX, alert exports, and document-like inputs
- extract IOCs, CVEs, actors, campaigns, malware, and ATT&CK techniques
- canonicalize observables and deduplicate repeated entities
- track extraction confidence and source quality

**Exit Criteria**

- a report or alert file can be ingested into a case
- extracted entities are queryable without rerunning the model

## Epic 3: Enrichment And Pivoting

**Goal**

Make the platform useful for investigation, not just storage.

**Scope**

- enrich indicators across configured sources
- pivot through passive DNS, certificates, WHOIS, and infrastructure clustering
- store pivot rationale and pivot depth
- report source coverage and missing sources

**Exit Criteria**

- one indicator yields related infrastructure with provenance
- pivot results are visible as structured evidence

## Epic 4: Case Workflow

**Goal**

Make the case the center of analyst work.

**Scope**

- create, update, and close cases
- attach evidence, notes, timelines, and PIRs
- record collection tasks and run history
- expose a concise case status view

**Exit Criteria**

- an analyst can work an investigation end to end inside one case

## Epic 5: Audience-Specific Reports

**Goal**

Generate different intelligence products from the same evidence base, with a grounding
check before every report is finalized.

**Scope**

- CTI overview
- CTI team product
- SOC and detection engineering product
- vulnerability management product
- red team / emulation product
- incident response product
- awareness product
- executive briefing
- `ReviewAgent` that runs after draft generation and before output: checks every claim
  against stored evidence records, flags claims without an `evidence_id` or explicit
  `INFERRED` label, blocks finalization until grounding passes or items are resolved

**Exit Criteria**

- the same case can produce distinct products without duplicating collection
- each product cites evidence and states gaps
- no report is finalized with an unsupported claim that was not explicitly labeled as
  inferred or flagged by the review agent

## Epic 6: Honest Failure Handling

**Goal**

Stop hiding collection failures behind empty outputs.

**Scope**

- typed agent and tool failure states
- partial success reporting
- parse and validation failure reporting
- JSON output that distinguishes no data from broken collection

**Exit Criteria**

- failed tools and failed parsing are visible to the operator
- no failure path is rendered as a clean success

## Epic 7: Analyst Controls

**Goal**

Let the operator steer collection and synthesis.

**Scope**

- source selection
- confidence thresholds
- report windows
- collection profiles
- export formats

**Exit Criteria**

- the user can choose what to collect, how hard to push, and how to present it

## Epic 8: Testing And Hardening

**Goal**

Prove the rebuilt core works without live model or live feed access.

**Scope**

- ingestion tests
- extraction tests
- pivot tests
- case workflow tests
- report tests
- failure-path tests
- mocked integrations for external sources

**Exit Criteria**

- core flows are covered by repeatable tests
- regression fixtures exist for malformed input and source failure

## Suggested Build Order

1. Data model and persistence
2. Agent communication infrastructure (streaming + clarification)
3. Ingestion and extraction
4. Enrichment and pivoting
5. Case workflow
6. Audience-specific reports (includes ReviewAgent)
7. Honest failure handling
8. Analyst controls
9. Testing and hardening

