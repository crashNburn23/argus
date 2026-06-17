# Argus Deprecation List

This list identifies the current architecture elements that should be retired during the
rebuild. These are not the end state. They are the parts that should stop being extended
once the new CTI-first model exists.

## Retire First

### 1. Prompt-First Reporting

**Current Shape**

Agents return a narrative report directly from prompts and tool results.

**Why It Goes Away**

- it hides provenance
- it encourages model-led synthesis before evidence is normalized
- it makes reports hard to audit or regenerate

**Replacement**

- evidence-backed case reports with audience-specific renderers

### 2. Silent Failure Handling

**Current Shape**

Parsing and validation failures are sometimes collapsed into empty or partial success
results.

**Why It Goes Away**

- empty output is not the same as no findings
- operators need to see parse, validation, and tool errors explicitly

**Replacement**

- typed failure states with machine-readable error payloads

### 3. Scope-String Collection

**Current Shape**

Report generation frequently begins from a free-form scope string.

**Why It Goes Away**

- it does not define a case
- it does not preserve source artifacts
- it cannot reliably support pivots or timeline work

**Replacement**

- case-based collection with explicit artifacts and evidence items

### 4. Report-As-System-Of-Record

**Current Shape**

The report model carries both the narrative and the underlying intelligence payload.

**Why It Goes Away**

- report output should be a view over the investigation, not the storage model itself

**Replacement**

- case, evidence, and relationship models with report views layered on top

### 5. Agent Run Logs As The Main Audit Trail

**Current Shape**

Run records capture model usage and output snippets, but not a full evidence chain.

**Why It Goes Away**

- run logs are useful, but they are not intelligence provenance

**Replacement**

- persistent evidence records, pivot jobs, and source coverage tracking

### 6. Generic Chat-First CLI Behavior

**Current Shape**

Natural language questions drive the system directly, and the CLI wraps that path.

**Why It Goes Away**

- chat is an interface, not the architecture
- CTI work needs cases, evidence, timelines, and product-specific outputs

**Replacement**

- workflow commands centered on cases and analysis products

### 7. Hard-Coded Report Templates As The Main Deliverable

**Current Shape**

Markdown templates format report output but do not define the information model.

**Why It Goes Away**

- templates are fine as a rendering layer
- they are not enough to define CTI operations

**Replacement**

- schema-driven report products generated from cases

## Keep Temporarily

These pieces can stay during the rebuild, but they should be treated as transitional:

- current CLI shell
- current diagnostics command
- current threat-feed integrations
- benchmark corpus and scoring harness
- markdown report templates

## Retire After Replacement Is Available

- `CTIOrchestrator` as the main product entry point
- `ReportAgent` as the primary intelligence synthesizer
- direct report generation from `scope` strings
- any code path that treats a failed parse as a valid empty result
- any storage model that cannot represent provenance or relationships

## Rebuild Rule

Do not add new features to a deprecated path if the replacement path exists or is already
in scope. Once the case/evidence model is available, new CTI work should land there.

