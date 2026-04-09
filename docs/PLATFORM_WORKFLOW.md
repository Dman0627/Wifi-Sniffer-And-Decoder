# Platform Workflow

This document covers the operator path for the evidence-intelligence platform layers in this repository.

The platform is intentionally passive by default. It is designed to ingest approved evidence, extract and normalize findings, correlate them into intelligence, store them, and present them through exported views or a local API.

## Stage Order

The shared platform flow is:

`ingest -> extract -> recover -> normalize -> correlate -> store -> present`

The legacy Wi-Fi workflow still exists under `videopipeline`, but the generic platform path is exposed through `intelpipeline`.

## Quick Start

Use a local file:

```powershell
python -m intel_api.cli run .\sample.txt --case-id demo --json
```

Or run stage-by-stage:

```powershell
python -m intel_api.cli ingest .\sample.txt --case-id demo --json
python -m intel_api.cli extract .\pipeline_output\platform\intake\<source-id>\<job-id>\source_manifest.json --json
python -m intel_api.cli recover .\pipeline_output\platform\extract\<source-id>\<job-id>\extract_report.json --json
python -m intel_api.cli normalize .\pipeline_output\platform\recover\<source-id>\<job-id>\recover_report.json --json
python -m intel_api.cli correlate .\pipeline_output\platform\normalize\<source-id>\<job-id>\normalize_report.json --json
python -m intel_api.cli store .\pipeline_output\platform\correlate\<source-id>\<job-id>\correlation_report.json --json
python -m intel_api.cli present .\pipeline_output\platform\store\<source-id>\<job-id>\store_report.json --json
```

Or let the queue runner consume staged jobs automatically:

```powershell
python -m intel_api.cli ingest .\sample.txt --case-id demo --json
python -m intel_api.cli run-queued --output-root .\pipeline_output\platform --workspace-root . --json
```

Approved passive public-source locators now work through the same `ingest` path:

```powershell
python -m intel_api.cli ingest https://example.test/feed.json --case-id feed-demo --json
python -m intel_api.cli ingest example.com --source-type domain --case-id domain-demo --json
```

Or keep a passive monitor loop running over queued work:

```powershell
python -m intel_api.cli monitor --output-root .\pipeline_output\platform --workspace-root .
```

To delta-check a source and only ingest it when the content changed:

```powershell
python -m intel_api.cli watch .\sample.txt --case-id demo --output-root .\pipeline_output\platform --workspace-root . --json
python -m intel_api.cli watch https://example.test/feed.json --case-id demo --output-root .\pipeline_output\platform --workspace-root . --json
```

To register a source for automatic monitor checks:

```powershell
python -m intel_api.cli watch-add .\sample.txt --case-id demo --output-root .\pipeline_output\platform --workspace-root . --poll-interval 30 --json
python -m intel_api.cli watch-list --output-root .\pipeline_output\platform --json
```

For a bounded smoke test or one-shot cycle:

```powershell
python -m intel_api.cli monitor --output-root .\pipeline_output\platform --workspace-root . --iterations 2 --poll-interval 0 --json
python -m intel_api.cli monitor-once --output-root .\pipeline_output\platform --workspace-root . --json
python -m intel_api.cli monitor-status --output-root .\pipeline_output\platform --workspace-root . --json
```

To prune old queue archives and stale watch-delta artifacts without touching active queues or raw evidence:

```powershell
python -m intel_api.cli cleanup --output-root .\pipeline_output\platform --completed-days 7 --failed-days 30 --watch-delta-days 3 --json
```

Use a pcap:

```powershell
python -m intel_api.cli ingest .\capture.pcapng --source-type pcapng --case-id wifi-demo --json
```

The later stages follow the same pattern with the generated report paths.

## What Each Stage Produces

`ingest`

- `source_manifest.json`
- raw artifact copies under `objects/raw`
- audit entries in `audit/audit_log.jsonl`
- queued extract job
- raw source and artifact records

`watch`

- compares the current source hash against persisted watcher state
- skips unchanged inputs without creating a new intake manifest
- ingests changed inputs and queues `extract`
- updates `source_monitor` watcher rows in SQLite
- reuses stored per-file hashes when size and mtime are unchanged
- marks append-only log growth separately from general file rewrites
- materializes append-only watched log growth as delta artifacts under `objects/derived/watch_delta` so later stages only process the appended bytes
- assigns a lightweight triage score so monitor mode can spend limited processing budget on the hottest queued work first

`watch-add`

- registers a local source in the watched-source registry
- registers a source in the watched-source registry
- also supports passive remote locators like approved HTTP feeds and RDAP domain lookups
- stores poll interval, recursive mode, and enabled status in SQLite
- makes the source eligible for automatic checks during `monitor`

`extract`

- `extract_report.json`
- queued recover job
- metadata, indicators, document/archive/binary/system-artifact structure, relationships, and carved artifacts
- optional external enrichers can also emit passive metadata or rule-hit summaries when configured tools are available

`recover`

- `recover_report.json`
- queued normalize job
- passive decoded or unpacked artifacts
- automatic extractor findings from recovered artifacts

`normalize`

- `normalize_report.json`
- queued correlate job
- canonicalized values, derived identities, deduplicated records

`correlate`

- `correlation_report.json`
- queued store job
- graph edges and timeline records

`store`

- `store_report.json`
- `storage/intelligence.sqlite3`
- persisted job, audit, and watcher-state tables
- queued present job

`present`

- `presentation_report.json`
- `case_summary.json`
- `graph_view.json`
- `timeline_view.json`
- `dataset_export.json`
- `dashboard_view.json`

## Local API

After `store`, you can serve the SQLite dataset locally:

```powershell
python -m intel_api.cli serve .\pipeline_output\platform\storage\intelligence.sqlite3 --host 127.0.0.1 --port 8080
```

Useful endpoints:

- `/`
- `/dashboard`
- `/health`
- `/plugins`
- `/cases`
- `/cases/<case-id>/dashboard`
- `/cases/<case-id>/summary`
- `/cases/<case-id>/records`
- `/cases/<case-id>/search?q=<term>`
- `/cases/<case-id>/relationships`
- `/cases/<case-id>/jobs`
- `/cases/<case-id>/audit`
- `/cases/<case-id>/timeline`
- `/cases/<case-id>/timeline?timeline_id=<timeline-id>`
- `/cases/<case-id>/timeline-view?timeline_id=<timeline-id>`
- `/cases/<case-id>/graph`
- `/cases/<case-id>/graph?node_id=<record-id>&depth=1`
- `/cases/<case-id>/graph-view?node_id=<record-id>&depth=1`
- `/cases/<case-id>/export`

The browser routes give you a local analyst UI on top of the same stored data:

- `/` or `/dashboard` shows stored cases and links into each case dashboard
- `/plugins` shows plugin health and availability as JSON
- `/cases/<case-id>/dashboard` shows summary, search, jobs, audit, graph, and timeline sections
- `/cases/<case-id>/timeline-view` focuses on one timeline
- `/cases/<case-id>/graph-view` focuses on the graph or a single node neighborhood

## Output Layout

By default, platform output is written under:

`pipeline_output/platform`

Key subdirectories:

- `objects/raw`
- `objects/derived`
- `audit`
- `intake`
- `extract`
- `recover`
- `normalize`
- `correlate`
- `store`
- `present`
- `queues`
- `storage`
- `monitor`

The monitor runtime persists its last heartbeat and queue summary at:

`pipeline_output/platform/monitor/monitor_status.json`

It also persists restart-safe watcher rows in:

`pipeline_output/platform/storage/intelligence.sqlite3`

Registered watched sources are stored in the same SQLite database and are checked automatically during monitor cycles before queue draining begins.

## Operator Notes

- Use explicit `case_id` values whenever possible so datasets group cleanly.
- The platform preserves provenance on every stage output; if a record cannot be traced back, treat that as a bug.
- The Wi-Fi plugin remains a compatibility bridge. It can feed the same shared store and presentation layers as file and log inputs.
- `present` materializes analyst-friendly JSON views; `serve` exposes the same stored data through a local read-only API.
- `python -m intel_api.cli plugins --json` shows the same plugin readiness snapshot used by `/plugins`, `/health`, and the dashboard.
- `python -m intel_api.cli run-queued --json` processes active queue files in stage order and archives them under `queues/completed` or `queues/failed`.
- Queue execution is now triage-aware within each stage, so higher-signal sources like network captures, system artifacts, logs, and append-only deltas are processed before lower-priority backlog when `--max-jobs` limits the cycle budget.
- Monitor mode now also adapts stage budgets per cycle: when fresh source activity is hot it biases budget toward `extract` and `recover`, and when intake is quiet it drains `normalize`, `correlate`, `store`, and `present` more aggressively.
- Aged queue backlog now gets a fairness override: if late-stage work has been waiting across repeated hot cycles, monitor mode will temporarily hand one budget slot to that aged stage instead of starving it indefinitely.
- Watched sources now use adaptive polling on top of their configured base interval: recently active sources get shorter effective intervals, while long-quiet sources back off automatically instead of being checked as often as hot ones.
- Very active watched sources can now enter a short-lived `burst` polling lane, while repeated low-priority churn can set a `suppression_until` window so noisy sources cool off briefly instead of being reevaluated every cycle.
- `python -m intel_api.cli monitor` is the first monitor-mode runtime step: it is passive, queue-driven, and designed to keep watching and draining queued work without adding active probing.
- `python -m intel_api.cli monitor-once` is useful for schedulers, services, and tests that want a single heartbeat cycle.
- `python -m intel_api.cli monitor-status` reads the persisted monitor snapshot so you can inspect queue health without opening the filesystem directly.
- `python -m intel_api.cli cleanup` gives you an explicit retention control for long-running workspaces: it prunes old `queues/completed`, `queues/failed`, and `objects/derived/watch_delta` content while leaving active queues and raw evidence alone.
- The read-only API now exposes monitor state at `/monitor` and `/cases/<case-id>/monitor`, and the browser UI exposes the same scheduler view at `/monitor-view` and `/cases/<case-id>/monitor-view`.
- Monitor cycle history is now exposed at `/monitor-history` and `/cases/<case-id>/monitor-history`, which gives you compact per-cycle queue and throughput snapshots instead of only the latest status file.
- Forecast and anomaly summaries are now exposed at `/monitor-forecast` and `/cases/<case-id>/monitor-forecast`, including predicted next-cycle queue pressure, estimated drain cycles, and alert rows when queue pressure, source churn, throughput, or failures deviate from the recent baseline.
- `python -m intel_api.cli monitor-tuning` lets you view or update those forecast thresholds and alert suppressions from the terminal, and the same settings are exposed at `/monitor-tuning` and `/cases/<case-id>/monitor-tuning`.
- Monitor tuning now supports named presets like `balanced`, `collection_first`, and `quiet`, so a new global default or a new case can start from a sane threshold profile before you layer on case-specific overrides.
- Monitor tuning now also has an `automation_mode` of `off`, `recommend`, or `apply`. In `recommend`, the passive monitor suggests case or watch preset changes when a scope stays noisy; in `apply`, it can auto-apply those preset swaps when the current tuning still matches clean preset defaults.
- That preset automation now supports rollback too: after several calm cycles, a case that was pushed to `collection_first` can be recommended back to `balanced`, and a watch that was pushed into a source-specific preset like `source:log` can be recommended back to `source:default`.
- Recommendation rows now preserve preset-change provenance. The monitor can distinguish an active recommendation from `already_applied`, `already_rolled_back`, and `manual_override`, so operators can tell whether a preset came from the runtime or from a later manual change.
- Monitor tuning now also supports per-alert severity overrides and per-stage threshold overrides, so a noisy `extract` queue can use different queue/throughput sensitivity than `store` or `present` without changing the whole case profile.
- Those monitor payloads and pages now also surface the active cleanup policy and the latest workspace-cleanup result, including removed counts and the last cleanup report path.
- The monitor dashboard now renders queue-pressure and throughput trend views from that history log, plus a recent-cycle table so backlog movement is visible over time.
- The monitor dashboard now also renders a backlog-outlook panel that summarizes forecast alerts and projected queue drain pressure without requiring you to inspect the raw history JSON.
- The monitor page now includes a local tuning form, so you can adjust thresholds or clear suppressions without editing JSON files directly.
- Recent queue archives are now browseable at `/archives` and `/cases/<case-id>/archives`, so you can inspect recently processed or failed queued work without opening the archived JSON files directly.
- Cleanup-report history is now browseable at `/cleanup-reports` and `/cases/<case-id>/cleanup-reports`, and the monitor UI surfaces the same recent report list beside the latest cleanup summary.
- Monitor control surfaces now live beside those views: `/cases/<case-id>/watch-sources` and `/cases/<case-id>/watchers` expose watched-source and watcher-state detail, and the monitor UI can enable/disable sources or clear/shorten suppression windows through local POST actions.
- Those same watch-source controls can now also snooze or resume a source and update its poll interval, analyst notes, and tags without touching SQLite directly.
- Watched sources can now also carry a small source-level tuning profile with their own churn sensitivity and suppressed alert ids, so especially noisy sources can cool off without changing the whole case-wide monitor tuning block.
- New watched sources now inherit a source-class tuning preset automatically, and `watch-add --tuning-preset ...` or the monitor UI can swap them between presets like `source:file`, `source:log`, `source:pcap`, and `source:system`.
- The monitor JSON and monitor pages now surface preset recommendations and any auto-applied preset actions, so you can see when the runtime wants to shift a case to `collection_first` or move an active watch into a source-specific preset.
- The monitor dashboard tuning form now includes clear actions for suppressions, alert severities, and stage thresholds, so you can reset one tuning layer without wiping the others.
- `python -m intel_api.cli watch <locator>` now supports both local evidence and passive remote feeds: unchanged sources are recorded and skipped, while changed sources are reingested and queued.
- `python -m intel_api.cli watch-add <locator>` registers a source for automatic monitor checks, and `watch-list` shows the current registry. `watch-add` now also accepts optional per-source churn tuning and suppressed alerts.
- Monitor mode now records watcher state in SQLite, including last checked time, queue backlog pointer, consecutive idle cycles, and cumulative check/change counts.
- Registered watched sources can each carry their own poll interval, so monitor mode only rechecks them when they are due.
- For local files and bundles, watched-source checks now reuse unchanged file hashes, surface append-only log growth in the monitor summary, and queue append-only log deltas without full-source reingest.
- Monitor snapshots now include per-priority backlog counts so you can see whether urgent work is building up before lower-priority backlog drains.
- Monitor snapshots now also include `stage_budget_mode`, `stage_budget_plan`, `fairness_stage`, `hot_cycle_streak`, and `queue_stage_age_stats_before`, which show how the current cycle split its limited processing budget and whether aged backlog fairness kicked in.
- Source-check results now include `base_poll_interval_seconds`, `effective_poll_interval_seconds`, `poll_adaptation`, `cooldown_remaining_seconds`, `suppressed_until`, and `suppression_remaining_seconds`, which makes adaptive polling decisions visible in the monitor JSON.
- Optional extractor adapters currently support `exiftool` and `yara`. They are safe to leave uninstalled; the pipeline will skip them cleanly.
- Use `exiftool_command` or `exiftool_path` in stage config to override the `exiftool` executable when needed.
- Use `yara_command` or `yara_path` plus `yara_rules_path` to enable YARA rule matching for artifacts.
- Monitor mode can now also run the same retention logic automatically when `--cleanup-completed-days`, `--cleanup-failed-days`, or `--cleanup-watch-delta-days` are set. That cleanup is workspace-scoped and is skipped for case-filtered monitor runs.
