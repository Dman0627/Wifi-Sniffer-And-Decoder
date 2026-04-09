# ADR 0001: Intelligence Platform Boundary And Package Layout

- Status: Accepted
- Date: 2026-04-08

## Context

This repository started as a Wi-Fi capture and analysis pipeline centered on `wifi_pipeline`.

The current roadmap expands that direction into a broader, authorized evidence-intelligence platform that can:

- ingest approved data sources,
- extract metadata and indicators,
- normalize and correlate findings,
- run policy-gated recovery and decoding steps,
- present graph, timeline, and report outputs.

That pivot introduces two risks:

1. the repository can lose its current shape and break the working Wi-Fi workflow,
2. the project can drift into offensive or out-of-scope behavior if the boundary is not written down early.

We need one durable decision document that freezes:

- what product we are building,
- what product we are not building,
- how the repository will be structured,
- what the first shared milestone is.

## Decision

### Product Boundary

This project is an authorized evidence-intelligence platform.

Its primary pipeline is:

`collect -> extract -> normalize -> recover -> correlate -> present`

Allowed source classes:

- packet captures and logs,
- local files and directories,
- approved system artifacts,
- approved public-source connectors.

Explicitly out of scope:

- vulnerability scanning,
- exploitation,
- active attack automation,
- red-team framework behavior,
- indiscriminate credential abuse,
- plugin behavior that bypasses authorization or provenance tracking.

### Repository Direction

This repository will evolve into a generic platform with a plugin model.

The current Wi-Fi functionality remains important and will become the first concrete plugin or compatibility module during the transition.

### Frozen Package Direction

The target package layout is:

- `intel_core`
  Orchestration, schemas, policy gates, job model, provenance, and shared utilities.
- `intel_collectors`
  Source intake for pcap, files, logs, system artifacts, and approved connectors.
- `intel_extractors`
  Passive extraction of metadata, indicators, strings, embedded objects, and protocol/session details.
- `intel_normalizers`
  Canonical record mapping, cleanup, standardization, and deduplication.
- `intel_recovery`
  Policy-gated offline decoding, unpacking, and approved recovery workflows.
- `intel_correlators`
  Relationship builders, entity resolution, graph edges, and timeline materialization.
- `intel_storage`
  Object storage, record persistence, indexes, and exports.
- `intel_api`
  CLI-facing and UI-facing service layer.
- `intel_plugins`
  Built-in and optional plugins.

The existing `wifi_pipeline` package will remain functional during the migration.

Transition rule:

- do not break the current `videopipeline` entry point while the new platform packages are being introduced.

### Naming Direction

The generic platform uses the `intel_*` package family.

The current `wifi_pipeline` package remains a supported compatibility surface until the Wi-Fi functionality is fully exposed through the new plugin system.

### First Shared Milestone

The first cross-platform milestone is frozen as:

1. ingest files and pcap inputs,
2. run passive extraction,
3. normalize findings into canonical records,
4. persist them in the first shared storage layer,
5. produce initial relationship graph and timeline outputs,
6. keep the current Wi-Fi workflow working.

## Consequences

### Positive

- The product boundary is explicit before deeper implementation starts.
- The repository gets a clear migration target instead of ad hoc expansion.
- The working Wi-Fi pipeline remains valuable and protected during the pivot.
- Future plugins have a single agreed destination.

### Tradeoffs

- The repository will temporarily contain both legacy and new structures.
- Some duplicated plumbing may exist while compatibility is maintained.
- Naming and package migration will take multiple phases.

### Follow-On Work

The next implementation step after this ADR is:

- define the canonical schema and plugin contracts in `intel_core`.

After that:

- introduce the initial package skeleton,
- wrap or adapt `wifi_pipeline` as the first plugin-facing module,
- build file and pcap ingestion against the new shared model.
