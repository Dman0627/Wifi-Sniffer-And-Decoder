# Changelog

## Unreleased

This branch adds a second product layer on top of the original Wi-Fi workflow: a plugin-driven passive intelligence platform.

Highlights:

- added `intel_core`, canonical records, plugin contracts, and registry support
- added `intelpipeline` with `ingest -> extract -> recover -> normalize -> correlate -> store -> present`
- added SQLite-backed storage, local API routes, HTML dashboard views, and dataset export/report surfaces
- added a passive monitor runtime with watched-source registration, adaptive scheduling, queue orchestration, cleanup, forecasting, tuning, and operator controls
- added passive remote connector intake for approved HTTP feeds and RDAP domain lookups
- added plugin profiles and enable/disable controls for builtin platform plugins
- added passive enrichment and compatibility wiring so the legacy Wi-Fi workflow still works alongside the new platform
- added broad unit and integration coverage for the platform, monitor runtime, connector collectors, dashboard, CLI, storage, and packaging

## 3.0.0

This release reshapes the project around a narrow, explicit support matrix:

- `Ubuntu standalone`
- `Raspberry Pi OS standalone`
- `Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture`

Highlights:

- added product-profile awareness and command support gating
- made Windows a remote-first controller workflow instead of pretending full local Wi-Fi parity
- made Ubuntu and Raspberry Pi OS first-class standalone targets
- added Windows helper scripts for setup, validation, and daily remote capture
- added Linux helper scripts for setup, standalone validation, and daily local runs
- added remote bootstrap, doctor, service, integrity verification, and validation flows
- added packaging, release automation, and broader automated test coverage
- added a simulated validation matrix test pass for Ubuntu standalone, Raspberry Pi OS standalone, and Windows remote workflows

Still intentionally limited:

- native Windows monitor-mode capture remains experimental
- Linux distributions outside Ubuntu and Raspberry Pi OS remain best effort
- replay, payload decoding, and reconstruction remain heuristic

Release gate:

- the final supported-path release should only be treated as fully validated after real hardware smoke tests pass on:
  - Ubuntu standalone
  - Raspberry Pi OS standalone
  - Windows 10/11 + Ubuntu or Raspberry Pi OS remote capture
- `RELEASE_CHECKLIST.md` documents the exact release gate and what the simulated matrix does and does not prove
