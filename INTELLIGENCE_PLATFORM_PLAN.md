# Intelligence Platform Plan

This plan assumes we evolve this repository into a general, authorized evidence-intelligence platform while keeping the current Wi-Fi workflow as the first concrete plugin.

## Scope

What this system is:

- A pipeline that ingests approved data sources.
- A platform that extracts, normalizes, enriches, correlates, and presents intelligence.
- A system that preserves provenance, confidence, and auditability across every step.

What this system is not:

- Not a pentesting toolkit.
- Not a vulnerability scanner.
- Not an exploitation or offensive automation framework.
- Not a system for indiscriminate credential abuse or unapproved data collection.

## Working Assumption

Keep this repository and refactor it into:

- a generic core engine,
- a plugin registry,
- a Wi-Fi plugin built from the existing `wifi_pipeline` package,
- optional adapters for other approved evidence sources and enrichers.

## Phase 0 - Architecture Decision

1. Add an architecture decision record that freezes the product boundary and naming.
2. Declare the primary data path as `collect -> extract -> normalize -> recover -> correlate -> present`.
3. Define the allowed source classes: pcap/logs, local files, system artifacts, and approved public-source connectors.
4. Define the prohibited capability classes: scanning, exploitation, active attack automation, and non-approved credential abuse.
5. Decide whether the current package name stays `wifi_pipeline` or becomes one plugin under a new root package such as `intel_core`.
6. Freeze the first milestone: file + pcap intake, passive extraction, normalization, and correlation graph.

Exit criteria:

- One written ADR exists.
- The repo has a single agreed package layout.
- The README and plan use the same vocabulary.

## Phase 1 - Repository Restructure

1. Create a new core package, for example `intel_core`.
2. Create sibling packages:
   `intel_collectors`
   `intel_extractors`
   `intel_normalizers`
   `intel_recovery`
   `intel_correlators`
   `intel_storage`
   `intel_api`
   `intel_plugins`
3. Move the current Wi-Fi functionality into `intel_plugins/wifi` or adapt `wifi_pipeline` as a compatibility layer.
4. Keep the current CLI working while introducing a new top-level CLI entry point.
5. Update `pyproject.toml` to expose both the legacy Wi-Fi commands and the new platform CLI.
6. Add a plugin registry module that can discover built-in and optional plugins.

Exit criteria:

- Existing Wi-Fi tests still pass.
- The repo can import the new core without breaking the current workflow.
- A new empty platform CLI starts successfully.

## Phase 2 - Canonical Data Model

1. Define schema versions for every top-level record.
2. Create canonical record types:
   `SourceRecord`
   `ArtifactRecord`
   `IndicatorRecord`
   `IdentityRecord`
   `CredentialRecord`
   `RelationshipRecord`
   `EventRecord`
   `TimelineRecord`
   `JobRecord`
3. Add required shared fields to every record:
   `id`
   `source_id`
   `case_id`
   `created_at`
   `observed_at`
   `provenance`
   `confidence`
   `tags`
   `schema_version`
4. Define stable fingerprint rules for dedupe.
5. Define provenance rules so every derived record points back to its parent artifact or source.
6. Define confidence scoring fields and allowed confidence bands.
7. Define JSON serialization and validation rules.

Exit criteria:

- A schema module exists.
- Round-trip tests pass for all record types.
- Every plugin contract targets the canonical models.

## Phase 3 - Storage and Job Model

1. Create an object store layout under a workspace directory for raw inputs and derived artifacts.
2. Create a normalized record store, starting with SQLite.
3. Create tables for each canonical record type.
4. Create a job table for pipeline runs, stage status, timing, and failures.
5. Create a content-addressed artifact index using hashes.
6. Create a simple queue/runner for stage execution.
7. Define idempotency rules so reruns do not duplicate records.
8. Add audit logging for every plugin execution.

Exit criteria:

- The platform can ingest a sample file into raw storage and create job records.
- Canonical records can be written, read, and deduplicated.
- Re-running the same source does not create duplicate artifacts.

## Phase 4 - Ingestion Layer

1. Build a file collector for individual files and directories.
2. Build a pcap collector for `pcap` and `pcapng`.
3. Build a log collector for text, JSON, and line-oriented logs.
4. Build a system-artifact collector for approved local evidence directories.
5. Build a connector interface for approved public-source providers.
6. Require every collector to emit:
   a source manifest,
   a list of raw artifacts,
   initial source metadata,
   a queued extraction job.
7. Add MIME/type sniffing and size limits at intake time.
8. Add allowlists and deny rules for collectors.

Exit criteria:

- The CLI can ingest a file, a directory, and a pcap.
- The system writes source manifests consistently.
- Large or unsupported inputs fail cleanly with audit logs.

## Phase 5 - Extraction Layer

1. Build a base extractor interface with capability flags and timeouts.
2. Build first-party extractors for:
   file metadata,
   hashes,
   entropy,
   strings,
   URLs,
   domains,
   IPs,
   emails,
   usernames,
   endpoint patterns,
   embedded file signatures.
3. Adapt the existing Wi-Fi extractor logic into a network/session extractor plugin.
4. Build document extractors for PDFs, Office docs, and generic archives.
5. Build binary extractors for file signatures, sections, imports, and printable strings.
6. Build a system-artifact extractor for common local evidence structures.
7. Store all raw extractor findings before normalization.
8. Add extractor-level provenance for every finding.

Exit criteria:

- A file and a pcap both produce raw extractor findings.
- Findings are attributable to specific source artifacts.
- Extractors can be enabled or disabled independently.

## Phase 6 - Normalization Layer

1. Map raw extractor findings into canonical records.
2. Normalize timestamps into UTC plus original timezone metadata.
3. Normalize identity strings such as emails, usernames, and account handles.
4. Normalize domains, URLs, IPs, and hostnames.
5. Normalize hashes, credential material labels, and encoding labels.
6. Deduplicate records using canonical fingerprints.
7. Create relationship edges during normalization when the linkage is deterministic.
8. Mark uncertain mappings as provisional with lower confidence.

Exit criteria:

- The same URL, domain, or identity from multiple sources collapses into one canonical record.
- Derived relationships carry provenance and confidence.
- Normalization reruns are deterministic.

## Phase 7 - Recovery and Decoding Layer

1. Create a policy gate that must approve recovery actions before they run.
2. Build passive decoders first:
   base64,
   hex,
   URL encoding,
   gzip,
   zip,
   common archive/container unpacking,
   simple text transformations.
3. Add file-unpacking and embedded-object extraction for supported containers.
4. Add hash identification for recovered credential material.
5. Add a recovery adapter interface for approved offline workflows.
6. Require explicit operator opt-in for any sensitive recovery module.
7. Log every recovery attempt and output artifact.
8. Feed recovered artifacts back into extraction and normalization automatically.

Exit criteria:

- Decoded or unpacked artifacts re-enter the pipeline as first-class inputs.
- Recovery actions are auditable and gated.
- Disabled recovery modules never run accidentally.

## Phase 8 - Correlation Layer

1. Build an entity-resolution module for domains, identities, hosts, artifacts, and accounts.
2. Build relationship builders for:
   identity-to-identity,
   identity-to-domain,
   identity-to-account,
   host-to-IP,
   artifact-to-indicator,
   source-to-artifact.
3. Add clustering rules for shared attributes and shared provenance.
4. Add temporal correlation rules to build event chains.
5. Build a timeline materializer from normalized events.
6. Build confidence propagation rules across relationship edges.
7. Expose graph traversal helpers for the CLI and UI.

Exit criteria:

- The platform can turn mixed inputs into a graph and a timeline.
- Correlated relationships have explanations.
- Analysts can trace every edge back to source evidence.

## Phase 9 - Outputs and Interfaces

1. Build a top-level CLI with commands like:
   `ingest`
   `extract`
   `normalize`
   `recover`
   `correlate`
   `report`
   `graph`
   `timeline`
2. Build JSON export for every canonical record set.
3. Add SQLite export and a Datasette-friendly layout.
4. Extend the dashboard so analysts can browse:
   jobs,
   artifacts,
   findings,
   identities,
   domains,
   relationships,
   timelines.
5. Add search and filtering across normalized records.
6. Add a report builder for case summaries and correlation summaries.

Exit criteria:

- A user can ingest data and inspect the resulting graph/timeline from the UI or CLI.
- Reports can be exported as JSON and queried through SQLite.
- The Wi-Fi plugin surfaces into the same interface as other data sources.

## Phase 10 - Plugin System

1. Define plugin manifests with:
   name,
   version,
   capabilities,
   required tools,
   policy requirements,
   input types,
   output record types.
2. Build built-in plugins for:
   Wi-Fi / pcap analysis,
   generic file intake,
   document metadata,
   binary metadata.
3. Build optional enricher adapters for approved external tools.
4. Build connector adapters for approved public-source providers.
5. Add per-plugin enable/disable controls.
6. Add plugin health checks and version reporting.

Exit criteria:

- The core engine can run with only built-in plugins.
- Optional plugins register cleanly or fail gracefully.
- Plugin output is indistinguishable from built-in output after normalization.

## Phase 11 - Testing and Validation

1. Add fixtures for:
   pcap,
   logs,
   text files,
   PDFs,
   Office documents,
   archives,
   binaries,
   extracted system artifacts.
2. Add unit tests for schema, normalization, dedupe, and correlation.
3. Add integration tests for end-to-end ingestion and reporting.
4. Add regression tests for the existing Wi-Fi flow.
5. Add fixture provenance tests to ensure every record has lineage.
6. Add performance tests for large artifact sets.
7. Add compatibility tests for disabled or missing optional tools.

Exit criteria:

- The pipeline passes unit and integration tests across mixed-source datasets.
- The Wi-Fi flow still works.
- Missing optional tools do not break the platform.

## Phase 12 - Security, Policy, and Operations

1. Add source-authorization checks at ingestion time.
2. Add operator acknowledgement for sensitive recovery modules.
3. Add secret scrubbing in logs and UI where needed.
4. Add per-run audit trails.
5. Add workspace isolation for artifacts and reports.
6. Add retention and cleanup controls.
7. Add configuration profiles for local lab use and evidence-processing mode.
8. Document the prohibited behaviors clearly in the CLI and README.

Exit criteria:

- Sensitive steps are gated and audited.
- The platform can run in a restricted, passive mode by default.
- The operator can explain what the system did and why.

## First Three Milestones To Build

Milestone 1:

- Create the new package layout.
- Define canonical schemas.
- Keep the current Wi-Fi CLI functional.

Milestone 2:

- Implement file and pcap ingestion.
- Implement basic extractors and normalization.
- Write normalized records to SQLite.

Milestone 3:

- Implement graph and timeline correlation.
- Add a unified dashboard for artifacts, entities, and relationships.
- Expose the Wi-Fi plugin through the shared platform workflow.

## Recommended Immediate Next Tasks

1. Create the ADR and freeze the package layout.
2. Create the canonical schema module and tests.
3. Create the raw/object store and SQLite storage layer.
4. Wrap the existing Wi-Fi pipeline as the first plugin.
5. Implement the new platform CLI with `ingest` and `extract`.
