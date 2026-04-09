from __future__ import annotations

import argparse
import json
from pathlib import Path

from intel_core import IngestRequest, record_to_dict
from intel_runtime import MonitorRuntime

from .app import PlatformApp
from .server import run_api_server


def _detect_source_type(locator: str) -> str:
    text = str(locator or "").strip()
    if text.startswith(("http://", "https://")):
        return "http-feed"
    path = Path(text).expanduser()
    if path.is_dir():
        return "directory"
    suffix = path.suffix.lower()
    if suffix in {".log", ".jsonl", ".ndjson", ".csv"}:
        return "log"
    if suffix in {".evtx", ".sqlite", ".db", ".dat", ".reg", ".hve", ".plist"}:
        return "system-artifact"
    if suffix == ".pcap":
        return "pcap"
    if suffix == ".pcapng":
        return "pcapng"
    return "file"


def _parse_csv_list(value: str) -> list[str]:
    rows: list[str] = []
    for piece in str(value or "").replace(";", ",").split(","):
        normalized = piece.strip()
        if not normalized or normalized in rows:
            continue
        rows.append(normalized)
    return rows


def _parse_alert_mapping(value: str) -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for piece in _parse_csv_list(value):
        key, separator, alert_id = piece.partition(":")
        normalized_key = key.strip()
        normalized_alert = alert_id.strip() if separator else ""
        if not normalized_key or not normalized_alert:
            continue
        rows.setdefault(normalized_key, [])
        if normalized_alert not in rows[normalized_key]:
            rows[normalized_key].append(normalized_alert)
    return rows


def _parse_severity_mapping(value: str) -> dict[str, str]:
    rows: dict[str, str] = {}
    for piece in _parse_csv_list(value):
        key, separator, severity = piece.partition(":")
        normalized_key = key.strip()
        normalized_severity = severity.strip().lower() if separator else ""
        if not normalized_key or normalized_severity not in {"info", "warning", "critical"}:
            continue
        rows[normalized_key] = normalized_severity
    return rows


def _parse_stage_threshold_mapping(value: str) -> dict[str, dict[str, float]]:
    rows: dict[str, dict[str, float]] = {}
    for piece in _parse_csv_list(value):
        stage, separator, remainder = piece.partition(":")
        threshold_key, equals, threshold_value = remainder.partition("=")
        normalized_stage = stage.strip()
        normalized_threshold_key = threshold_key.strip()
        if (
            not separator
            or not equals
            or not normalized_stage
            or normalized_threshold_key not in {"queue_spike_factor", "throughput_drop_factor"}
        ):
            continue
        try:
            numeric_value = float(threshold_value.strip())
        except ValueError:
            continue
        rows.setdefault(normalized_stage, {})
        rows[normalized_stage][normalized_threshold_key] = numeric_value
    return rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Platform CLI for the evidence-intelligence pipeline.")
    subparsers = parser.add_subparsers(dest="command")

    plugins_p = subparsers.add_parser("plugins", help="List registered builtin plugins with health and availability status")
    plugins_p.add_argument("--output-root", default="./pipeline_output/platform", help="Platform output root")
    plugins_p.add_argument("--enable", default="", help="Enable a plugin in the active or selected profile")
    plugins_p.add_argument("--disable", default="", help="Disable a plugin in the active or selected profile")
    plugins_p.add_argument("--profile", default="", help="Target profile for plugin changes or activation")
    plugins_p.add_argument("--save-profile", default="", help="Save the current or selected profile under a new name")
    plugins_p.add_argument("--source-profile", default="", help="Source profile to copy when saving a new profile")
    plugins_p.add_argument("--delete-profile", default="", help="Delete a saved plugin profile")
    plugins_p.add_argument("--json", action="store_true", help="Print plugin status as JSON")

    queued_p = subparsers.add_parser("run-queued", help="Execute queued platform stage jobs from the workspace output directory")
    queued_p.add_argument("--case-id", default="", help="Optional case identifier filter")
    queued_p.add_argument("--output-root", default="./pipeline_output/platform", help="Platform output root")
    queued_p.add_argument("--workspace-root", default=".", help="Workspace root for plugin execution")
    queued_p.add_argument("--database-path", default="", help="Optional SQLite database path override")
    queued_p.add_argument(
        "--stage",
        action="append",
        choices=["extract", "recover", "normalize", "correlate", "store", "present"],
        help="Optionally limit execution to one or more queue stages",
    )
    queued_p.add_argument("--max-jobs", type=int, default=0, help="Maximum number of queued jobs to process (0 = no limit)")
    queued_p.add_argument("--json", action="store_true", help="Print full JSON output")

    monitor_p = subparsers.add_parser("monitor", help="Run the passive monitor loop over queued platform jobs")
    monitor_p.add_argument("--case-id", default="", help="Optional case identifier filter")
    monitor_p.add_argument("--output-root", default="./pipeline_output/platform", help="Platform output root")
    monitor_p.add_argument("--workspace-root", default=".", help="Workspace root for plugin execution")
    monitor_p.add_argument("--database-path", default="", help="Optional SQLite database path override")
    monitor_p.add_argument(
        "--stage",
        action="append",
        choices=["extract", "recover", "normalize", "correlate", "store", "present"],
        help="Optionally limit the monitor to one or more queue stages",
    )
    monitor_p.add_argument("--max-jobs", type=int, default=0, help="Maximum number of queued jobs to process per cycle (0 = no limit)")
    monitor_p.add_argument("--poll-interval", type=float, default=5.0, help="Seconds to wait between monitor cycles")
    monitor_p.add_argument("--iterations", type=int, default=0, help="Run a fixed number of monitor cycles (0 = run until interrupted)")
    monitor_p.add_argument("--json", action="store_true", help="Print final monitor status as JSON")

    once_p = subparsers.add_parser("monitor-once", help="Run one passive monitor cycle and persist monitor status")
    once_p.add_argument("--case-id", default="", help="Optional case identifier filter")
    once_p.add_argument("--output-root", default="./pipeline_output/platform", help="Platform output root")
    once_p.add_argument("--workspace-root", default=".", help="Workspace root for plugin execution")
    once_p.add_argument("--database-path", default="", help="Optional SQLite database path override")
    once_p.add_argument(
        "--stage",
        action="append",
        choices=["extract", "recover", "normalize", "correlate", "store", "present"],
        help="Optionally limit the cycle to one or more queue stages",
    )
    once_p.add_argument("--max-jobs", type=int, default=0, help="Maximum number of queued jobs to process during the cycle (0 = no limit)")
    once_p.add_argument("--poll-interval", type=float, default=5.0, help="Stored poll interval for later monitor runs")
    once_p.add_argument("--json", action="store_true", help="Print final monitor status as JSON")

    status_p = subparsers.add_parser("monitor-status", help="Read the persisted passive monitor status snapshot")
    status_p.add_argument("--case-id", default="", help="Optional case identifier filter")
    status_p.add_argument("--output-root", default="./pipeline_output/platform", help="Platform output root")
    status_p.add_argument("--workspace-root", default=".", help="Workspace root for plugin execution")
    status_p.add_argument("--database-path", default="", help="Optional SQLite database path override")
    status_p.add_argument(
        "--stage",
        action="append",
        choices=["extract", "recover", "normalize", "correlate", "store", "present"],
        help="Optionally scope status to the same stage filter used by the monitor",
    )
    status_p.add_argument("--max-jobs", type=int, default=0, help="Stored per-cycle maximum used when constructing a default status")
    status_p.add_argument("--poll-interval", type=float, default=5.0, help="Stored poll interval used when constructing a default status")
    for monitor_like in (monitor_p, once_p, status_p):
        monitor_like.add_argument("--cleanup-completed-days", type=float, default=0.0, help="Workspace cleanup threshold for completed queue archives")
        monitor_like.add_argument("--cleanup-failed-days", type=float, default=0.0, help="Workspace cleanup threshold for failed queue archives")
        monitor_like.add_argument("--cleanup-watch-delta-days", type=float, default=0.0, help="Workspace cleanup threshold for watch-delta derived artifacts")
    status_p.add_argument("--json", action="store_true", help="Print full monitor status as JSON")

    tuning_p = subparsers.add_parser("monitor-tuning", help="View or update forecast thresholds and alert suppressions")
    tuning_p.add_argument("--case-id", default="", help="Optional case identifier filter")
    tuning_p.add_argument("--output-root", default="./pipeline_output/platform", help="Platform output root")
    tuning_p.add_argument("--preset", default=None, help="Named monitor tuning preset (balanced, collection_first, quiet)")
    tuning_p.add_argument("--automation-mode", default=None, help="Monitor automation mode (off, recommend, apply)")
    tuning_p.add_argument("--forecast-min-history", type=int, default=None, help="Minimum history cycles before alerts can fire")
    tuning_p.add_argument("--queue-spike-factor", type=float, default=None, help="Multiplier that defines a queue pressure spike")
    tuning_p.add_argument("--source-churn-spike-factor", type=float, default=None, help="Multiplier that defines a source churn spike")
    tuning_p.add_argument("--throughput-drop-factor", type=float, default=None, help="Throughput ratio that defines a drop alert")
    tuning_p.add_argument("--suppressed-alerts", default=None, help="Comma-separated alert ids to suppress globally in this scope")
    tuning_p.add_argument("--stage-suppressions", default=None, help="Comma-separated stage:alert_id suppressions")
    tuning_p.add_argument("--watch-suppressions", default=None, help="Comma-separated watch_id:alert_id suppressions")
    tuning_p.add_argument("--alert-severity-overrides", default=None, help="Comma-separated alert_id:severity overrides")
    tuning_p.add_argument("--stage-thresholds", default=None, help="Comma-separated stage:key=value overrides for queue_spike_factor or throughput_drop_factor")
    tuning_p.add_argument("--clear-suppressions", action="store_true", help="Clear all alert suppressions in this scope")
    tuning_p.add_argument("--clear-alert-severities", action="store_true", help="Clear alert severity overrides in this scope")
    tuning_p.add_argument("--clear-stage-thresholds", action="store_true", help="Clear per-stage threshold overrides in this scope")
    tuning_p.add_argument("--json", action="store_true", help="Print full JSON output")

    cleanup_p = subparsers.add_parser("cleanup", help="Prune old queue archives and watch-delta artifacts from the workspace")
    cleanup_p.add_argument("--output-root", default="./pipeline_output/platform", help="Platform output root")
    cleanup_p.add_argument("--completed-days", type=float, default=0.0, help="Delete completed queue archives older than this many days")
    cleanup_p.add_argument("--failed-days", type=float, default=0.0, help="Delete failed queue archives older than this many days")
    cleanup_p.add_argument("--watch-delta-days", type=float, default=0.0, help="Delete watch-delta artifacts older than this many days")
    cleanup_p.add_argument("--dry-run", action="store_true", help="Preview cleanup without deleting files")
    cleanup_p.add_argument("--json", action="store_true", help="Print full JSON output")

    watch_add_p = subparsers.add_parser("watch-add", help="Register a source locator for automatic passive monitor checks")
    watch_add_p.add_argument("locator", help="Path, URL, or approved source locator to register")
    watch_add_p.add_argument(
        "--source-type",
        default="auto",
        choices=[
            "auto",
            "file",
            "directory",
            "log",
            "log-bundle",
            "pcap",
            "pcapng",
            "wifi-capture",
            "system-artifact",
            "system-artifact-bundle",
            "http-feed",
            "domain",
            "rdap-domain",
            "public-source",
        ],
        help="Source type for the locator (default: auto-detect)",
    )
    watch_add_p.add_argument("--case-id", default="", help="Optional case identifier")
    watch_add_p.add_argument("--output-root", default="./pipeline_output/platform", help="Platform output root")
    watch_add_p.add_argument("--workspace-root", default=".", help="Workspace root for plugin execution")
    watch_add_p.add_argument("--database-path", default="", help="Optional SQLite database path override")
    watch_add_p.add_argument("--recursive", action="store_true", help="Recurse when registering a directory or bundle")
    watch_add_p.add_argument("--poll-interval", type=float, default=0.0, help="Seconds between automatic monitor checks for this source")
    watch_add_p.add_argument("--start-disabled", action="store_true", help="Register the source but leave it disabled")
    watch_add_p.add_argument("--tuning-preset", default="", help="Optional watch tuning preset name")
    watch_add_p.add_argument("--forecast-min-history", type=int, default=None, help="Optional per-source minimum history before churn alerts fire")
    watch_add_p.add_argument("--source-churn-factor", type=float, default=None, help="Optional per-source churn spike factor override")
    watch_add_p.add_argument("--suppressed-alerts", default=None, help="Optional per-source suppressed alert ids")
    watch_add_p.add_argument("--json", action="store_true", help="Print full JSON output")

    watch_list_p = subparsers.add_parser("watch-list", help="List registered watched sources")
    watch_list_p.add_argument("--case-id", default="", help="Optional case identifier filter")
    watch_list_p.add_argument("--output-root", default="./pipeline_output/platform", help="Platform output root")
    watch_list_p.add_argument("--database-path", default="", help="Optional SQLite database path override")
    watch_list_p.add_argument("--enabled-only", action="store_true", help="Only show enabled watched sources")
    watch_list_p.add_argument("--json", action="store_true", help="Print full JSON output")

    watch_p = subparsers.add_parser("watch", help="Delta-check a source locator and ingest it only when content changed")
    watch_p.add_argument("locator", help="Path, URL, or approved source locator to watch")
    watch_p.add_argument(
        "--source-type",
        default="auto",
        choices=[
            "auto",
            "file",
            "directory",
            "log",
            "log-bundle",
            "pcap",
            "pcapng",
            "wifi-capture",
            "system-artifact",
            "system-artifact-bundle",
            "http-feed",
            "domain",
            "rdap-domain",
            "public-source",
        ],
        help="Source type for the locator (default: auto-detect)",
    )
    watch_p.add_argument("--case-id", default="", help="Optional case identifier")
    watch_p.add_argument("--output-root", default="./pipeline_output/platform", help="Platform output root")
    watch_p.add_argument("--workspace-root", default=".", help="Workspace root for plugin execution")
    watch_p.add_argument("--database-path", default="", help="Optional SQLite database path override")
    watch_p.add_argument("--recursive", action="store_true", help="Recurse when watching a directory or bundle")
    watch_p.add_argument("--force", action="store_true", help="Force ingest even when the content hash is unchanged")
    watch_p.add_argument("--json", action="store_true", help="Print full JSON output")

    ingest_p = subparsers.add_parser("ingest", help="Ingest a source locator into platform source records")
    ingest_p.add_argument("locator", help="Path, URL, domain, or approved source locator to ingest")
    ingest_p.add_argument(
        "--source-type",
        default="auto",
        choices=[
            "auto",
            "file",
            "directory",
            "log",
            "log-bundle",
            "pcap",
            "pcapng",
            "wifi-capture",
            "system-artifact",
            "system-artifact-bundle",
            "http-feed",
            "domain",
            "rdap-domain",
            "public-source",
        ],
        help="Source type for the locator (default: auto-detect)",
    )
    ingest_p.add_argument("--case-id", default="", help="Optional case identifier")
    ingest_p.add_argument("--output-root", default="./pipeline_output/platform", help="Platform output root")
    ingest_p.add_argument("--workspace-root", default=".", help="Workspace root for plugin execution")
    ingest_p.add_argument("--recursive", action="store_true", help="Recurse when ingesting a directory")
    ingest_p.add_argument("--json", action="store_true", help="Print full JSON output")

    run_p = subparsers.add_parser("run", help="Run the full platform pipeline from ingest through presentation")
    run_p.add_argument("locator", help="Path, URL, domain, or approved source locator to ingest")
    run_p.add_argument(
        "--source-type",
        default="auto",
        choices=[
            "auto",
            "file",
            "directory",
            "log",
            "log-bundle",
            "pcap",
            "pcapng",
            "wifi-capture",
            "system-artifact",
            "system-artifact-bundle",
            "http-feed",
            "domain",
            "rdap-domain",
            "public-source",
        ],
        help="Source type for the locator (default: auto-detect)",
    )
    run_p.add_argument("--case-id", default="", help="Optional case identifier")
    run_p.add_argument("--output-root", default="./pipeline_output/platform", help="Platform output root")
    run_p.add_argument("--workspace-root", default=".", help="Workspace root for plugin execution")
    run_p.add_argument("--database-path", default="", help="Optional SQLite database path override")
    run_p.add_argument("--recursive", action="store_true", help="Recurse when ingesting a directory")
    run_p.add_argument("--json", action="store_true", help="Print full JSON output")

    extract_p = subparsers.add_parser("extract", help="Run builtin extractor plugins against an intake source manifest")
    extract_p.add_argument("manifest", help="Path to the source_manifest.json written during intake")
    extract_p.add_argument("--case-id", default="", help="Optional case identifier override")
    extract_p.add_argument("--output-root", default="", help="Optional platform output root override")
    extract_p.add_argument("--workspace-root", default=".", help="Workspace root for plugin execution")
    extract_p.add_argument("--json", action="store_true", help="Print full JSON output")

    recover_p = subparsers.add_parser("recover", help="Run builtin passive recovery plugins against an extract report")
    recover_p.add_argument("report", help="Path to the extract_report.json written during extraction")
    recover_p.add_argument("--case-id", default="", help="Optional case identifier override")
    recover_p.add_argument("--output-root", default="", help="Optional platform output root override")
    recover_p.add_argument("--workspace-root", default=".", help="Workspace root for plugin execution")
    recover_p.add_argument("--json", action="store_true", help="Print full JSON output")

    normalize_p = subparsers.add_parser("normalize", help="Run builtin normalizer plugins against an extract report")
    normalize_p.add_argument("report", help="Path to the recover_report.json or extract_report.json written upstream")
    normalize_p.add_argument("--case-id", default="", help="Optional case identifier override")
    normalize_p.add_argument("--output-root", default="", help="Optional platform output root override")
    normalize_p.add_argument("--workspace-root", default=".", help="Workspace root for plugin execution")
    normalize_p.add_argument("--json", action="store_true", help="Print full JSON output")

    correlate_p = subparsers.add_parser("correlate", help="Run builtin correlator plugins against a normalize report")
    correlate_p.add_argument("report", help="Path to the normalize_report.json written during normalization")
    correlate_p.add_argument("--case-id", default="", help="Optional case identifier override")
    correlate_p.add_argument("--output-root", default="", help="Optional platform output root override")
    correlate_p.add_argument("--workspace-root", default=".", help="Workspace root for plugin execution")
    correlate_p.add_argument("--json", action="store_true", help="Print full JSON output")

    store_p = subparsers.add_parser("store", help="Persist a correlation report into the platform SQLite store")
    store_p.add_argument("report", help="Path to the correlation_report.json written during correlation")
    store_p.add_argument("--case-id", default="", help="Optional case identifier override")
    store_p.add_argument("--output-root", default="", help="Optional platform output root override")
    store_p.add_argument("--workspace-root", default=".", help="Workspace root for plugin execution")
    store_p.add_argument("--database-path", default="", help="Optional SQLite database path override")
    store_p.add_argument("--json", action="store_true", help="Print full JSON output")

    present_p = subparsers.add_parser("present", help="Materialize summary, graph, timeline, and export views from a store report")
    present_p.add_argument("report", help="Path to the store_report.json written during storage")
    present_p.add_argument("--case-id", default="", help="Optional case identifier override")
    present_p.add_argument("--output-root", default="", help="Optional platform output root override")
    present_p.add_argument("--workspace-root", default=".", help="Workspace root for plugin execution")
    present_p.add_argument("--database-path", default="", help="Optional SQLite database path override")
    present_p.add_argument("--json", action="store_true", help="Print full JSON output")

    serve_p = subparsers.add_parser("serve", help="Run a read-only local API over the stored SQLite intelligence dataset")
    serve_p.add_argument("database_path", help="Path to the SQLite database created by the store stage")
    serve_p.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    serve_p.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    app = PlatformApp()

    if args.command == "plugins":
        payload = None
        if args.enable:
            payload = app.update_plugin_settings(
                output_root=str(args.output_root),
                plugin_name=str(args.enable),
                enabled=True,
                profile_name=str(args.profile or ""),
            )
        elif args.disable:
            payload = app.update_plugin_settings(
                output_root=str(args.output_root),
                plugin_name=str(args.disable),
                enabled=False,
                profile_name=str(args.profile or ""),
            )
        elif args.save_profile:
            payload = app.update_plugin_settings(
                output_root=str(args.output_root),
                save_profile_as=str(args.save_profile),
                source_profile_name=str(args.source_profile or args.profile or ""),
            )
        elif args.delete_profile:
            payload = app.update_plugin_settings(
                output_root=str(args.output_root),
                delete_profile_name=str(args.delete_profile),
            )
        elif args.profile:
            payload = app.update_plugin_settings(
                output_root=str(args.output_root),
                set_active_profile=str(args.profile),
            )

        settings = app.plugin_settings(output_root=str(args.output_root))
        statuses = app.plugin_statuses(output_root=str(args.output_root))
        summary = app.plugin_status_summary(output_root=str(args.output_root))
        if args.json:
            print(
                json.dumps(
                    {
                        "summary": summary,
                        "plugins": list(statuses),
                        "settings": settings["settings"],
                        "active_profile": settings["active_profile"],
                        "profiles": settings["profiles"],
                        "result": payload,
                    },
                    indent=2,
                )
            )
        else:
            print(
                f"profile={settings['active_profile']} plugins={summary['plugin_count']} ready={summary['ready_count']} "
                f"missing_tools={summary['optional_tool_missing_count']} attention={summary['attention_count']}"
            )
            for profile in settings["profiles"]:
                marker = "*" if profile["active"] else "-"
                print(
                    f"{marker} profile {profile['name']}\tenabled={profile['enabled_count']}\tdisabled={profile['disabled_count']}"
                )
            for item in statuses:
                required_tools = ",".join(item["required_tools"]) or "-"
                print(
                    f"{item['name']}\t{item['plugin_type']}\t{item['status']}\t"
                    f"{required_tools}\t{item['summary']}"
                )
            if payload and not payload.get("ok", False):
                for error in list(payload.get("errors") or []):
                    print(f"error: {error}")
        return 0 if not payload or bool(payload.get("ok", True)) else 1

    if args.command == "run-queued":
        result = app.run_queued(
            case_id=str(args.case_id or ""),
            output_root=str(args.output_root),
            workspace_root=str(args.workspace_root),
            database_path=str(args.database_path or "") or None,
            stages=tuple(args.stage or ()),
            max_jobs=int(args.max_jobs or 0),
        )
        if args.json:
            payload = {
                "ok": result.ok,
                "records": [record_to_dict(record) for record in result.records],
                "artifact_paths": list(result.artifact_paths),
                "warnings": list(result.warnings),
                "errors": list(result.errors),
                "metrics": dict(result.metrics),
            }
            print(json.dumps(payload, indent=2))
        else:
            print(f"ok={result.ok}")
            for key, value in result.metrics.items():
                print(f"{key}: {value}")
            for path in result.artifact_paths:
                print(path)
            for warning in result.warnings:
                print(f"warning: {warning}")
            for error in result.errors:
                print(f"error: {error}")
        return 0 if result.ok else 1

    if args.command in {"monitor", "monitor-once", "monitor-status"}:
        monitor = MonitorRuntime(
            app=app,
            output_root=Path(str(args.output_root)),
            workspace_root=Path(str(args.workspace_root)),
            database_path=str(args.database_path or "") or None,
            case_id=str(args.case_id or ""),
            stages=tuple(args.stage or ()),
            max_jobs=int(args.max_jobs or 0),
            poll_interval=float(args.poll_interval or 0.0),
            cleanup_completed_days=float(args.cleanup_completed_days or 0.0),
            cleanup_failed_days=float(args.cleanup_failed_days or 0.0),
            cleanup_watch_delta_days=float(args.cleanup_watch_delta_days or 0.0),
        )
        if args.command == "monitor":
            payload = monitor.run_forever(iterations=int(args.iterations or 0))
        elif args.command == "monitor-once":
            payload = monitor.run_once()
        else:
            payload = monitor.read_status()
        last_result = payload.get("last_result", {})

        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(
                f"cycles={payload.get('cycle_count', 0)} idle={payload.get('idle_cycle_count', 0)} "
                f"queued={payload.get('queue_total_after', 0)} processed={payload.get('total_processed_job_count', 0)}"
            )
            print(f"state: {last_result.get('reason', 'unknown')}")
            print(f"status: {payload.get('status_path', '')}")
        return 0 if bool(last_result.get("ok", True)) else 1

    if args.command == "monitor-tuning":
        has_updates = any(
            value is not None
            for value in (
                args.forecast_min_history,
                args.preset,
                args.automation_mode,
                args.queue_spike_factor,
                args.source_churn_spike_factor,
                args.throughput_drop_factor,
                args.suppressed_alerts,
                args.stage_suppressions,
                args.watch_suppressions,
                args.alert_severity_overrides,
                args.stage_thresholds,
            )
        ) or bool(args.clear_suppressions) or bool(args.clear_alert_severities) or bool(args.clear_stage_thresholds)
        if has_updates:
            payload = app.update_monitor_tuning(
                case_id=str(args.case_id or ""),
                output_root=str(args.output_root),
                preset_name=args.preset,
                automation_mode=args.automation_mode,
                forecast_min_history=args.forecast_min_history,
                queue_spike_factor=args.queue_spike_factor,
                source_churn_spike_factor=args.source_churn_spike_factor,
                throughput_drop_factor=args.throughput_drop_factor,
                suppressed_alert_ids=[] if args.clear_suppressions else (_parse_csv_list(args.suppressed_alerts) if args.suppressed_alerts is not None else None),
                suppressed_stage_alerts={} if args.clear_suppressions else (_parse_alert_mapping(args.stage_suppressions) if args.stage_suppressions is not None else None),
                suppressed_watch_alerts={} if args.clear_suppressions else (_parse_alert_mapping(args.watch_suppressions) if args.watch_suppressions is not None else None),
                alert_severity_overrides={} if args.clear_alert_severities else (_parse_severity_mapping(args.alert_severity_overrides) if args.alert_severity_overrides is not None else None),
                stage_threshold_overrides={} if args.clear_stage_thresholds else (_parse_stage_threshold_mapping(args.stage_thresholds) if args.stage_thresholds is not None else None),
            )
        else:
            payload = app.get_monitor_tuning(
                case_id=str(args.case_id or ""),
                output_root=str(args.output_root),
            )

        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            tuning = dict(payload.get("tuning") or {})
            print(
                f"preset_name={tuning.get('preset_name', '')} "
                f"automation_mode={tuning.get('automation_mode', '')} "
                f"min_history={tuning.get('forecast_min_history', 0)} "
                f"queue_spike_factor={tuning.get('queue_spike_factor', 0.0)} "
                f"source_churn_spike_factor={tuning.get('source_churn_spike_factor', 0.0)} "
                f"throughput_drop_factor={tuning.get('throughput_drop_factor', 0.0)}"
            )
            print(f"suppressed_alerts: {','.join(list(tuning.get('suppressed_alert_ids') or [])) or '-'}")
            print(f"suppressed_stage_alerts: {json.dumps(dict(tuning.get('suppressed_stage_alerts') or {}), sort_keys=True)}")
            print(f"suppressed_watch_alerts: {json.dumps(dict(tuning.get('suppressed_watch_alerts') or {}), sort_keys=True)}")
            print(f"alert_severity_overrides: {json.dumps(dict(tuning.get('alert_severity_overrides') or {}), sort_keys=True)}")
            print(f"stage_threshold_overrides: {json.dumps(dict(tuning.get('stage_threshold_overrides') or {}), sort_keys=True)}")
        return 0 if bool(payload.get("ok", False)) else 1

    if args.command == "cleanup":
        payload = app.cleanup_workspace(
            output_root=str(args.output_root),
            queue_completed_max_age_seconds=float(args.completed_days or 0.0) * 86400.0,
            queue_failed_max_age_seconds=float(args.failed_days or 0.0) * 86400.0,
            watch_delta_max_age_seconds=float(args.watch_delta_days or 0.0) * 86400.0,
            dry_run=bool(args.dry_run),
        )
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(
                f"ok={payload.get('ok', False)} removed={payload.get('metrics', {}).get('removed_count', 0)} "
                f"candidates={payload.get('metrics', {}).get('candidate_count', 0)}"
            )
            for path in list(payload.get("artifact_paths") or []):
                print(path)
            for warning in list(payload.get("warnings") or []):
                print(f"warning: {warning}")
            for error in list(payload.get("errors") or []):
                print(f"error: {error}")
        return 0 if bool(payload.get("ok", False)) else 1

    if args.command == "watch-add":
        source_type = str(args.source_type)
        if source_type == "auto":
            source_type = _detect_source_type(args.locator)
        payload = app.register_watch_source(
            IngestRequest(
                source_type=source_type,
                locator=args.locator,
                options={"recursive": bool(args.recursive)},
            ),
            case_id=str(args.case_id or ""),
            output_root=str(args.output_root),
            workspace_root=str(args.workspace_root),
            database_path=str(args.database_path or "") or None,
            enabled=not bool(args.start_disabled),
            poll_interval_seconds=float(args.poll_interval or 0.0),
            tuning_preset_name=str(args.tuning_preset or ""),
            forecast_min_history=args.forecast_min_history,
            source_churn_spike_factor=args.source_churn_factor,
            suppressed_alert_ids=_parse_csv_list(args.suppressed_alerts) if args.suppressed_alerts is not None else None,
        )
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"ok={payload.get('ok', False)}")
            for key, value in dict(payload.get("metrics") or {}).items():
                print(f"{key}: {value}")
            watched_source = dict(payload.get("watched_source") or {})
            if watched_source:
                print(f"watch_id: {watched_source.get('watch_id', '')}")
                print(f"status: {watched_source.get('status', '')}")
            for path in list(payload.get("artifact_paths") or []):
                print(path)
            for error in list(payload.get("errors") or []):
                print(f"error: {error}")
        return 0 if bool(payload.get("ok", False)) else 1

    if args.command == "watch-list":
        payload = app.list_watch_sources(
            case_id=str(args.case_id or ""),
            output_root=str(args.output_root),
            database_path=str(args.database_path or "") or None,
            enabled_only=bool(args.enabled_only),
        )
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"ok={payload.get('ok', False)}")
            for item in list(payload.get("watched_sources") or []):
                print(
                    f"{item.get('watch_id', '')}\t{item.get('status', '')}\t"
                    f"{item.get('source_type', '')}\t{item.get('locator', '')}"
                )
        return 0 if bool(payload.get("ok", False)) else 1

    if args.command == "watch":
        source_type = str(args.source_type)
        if source_type == "auto":
            source_type = _detect_source_type(args.locator)
        request = IngestRequest(
            source_type=source_type,
            locator=args.locator,
            options={"recursive": bool(args.recursive)},
        )
        payload = app.watch_source(
            request,
            case_id=str(args.case_id or ""),
            output_root=str(args.output_root),
            workspace_root=str(args.workspace_root),
            database_path=str(args.database_path or "") or None,
            force=bool(args.force),
        )
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(
                f"ok={payload.get('ok', False)} changed={payload.get('changed', False)} "
                f"ingested={payload.get('ingested', False)} skipped={payload.get('skipped', False)}"
            )
            for key, value in dict(payload.get("metrics") or {}).items():
                print(f"{key}: {value}")
            for path in list(payload.get("artifact_paths") or []):
                print(path)
            for warning in list(payload.get("warnings") or []):
                print(f"warning: {warning}")
            for error in list(payload.get("errors") or []):
                print(f"error: {error}")
        return 0 if bool(payload.get("ok", False)) else 1

    if args.command == "ingest":
        source_type = str(args.source_type)
        if source_type == "auto":
            source_type = _detect_source_type(args.locator)
        request = IngestRequest(
            source_type=source_type,
            locator=args.locator,
            options={"recursive": bool(args.recursive)},
        )
        result = app.ingest(
            request,
            case_id=str(args.case_id or ""),
            output_root=str(args.output_root),
            workspace_root=str(args.workspace_root),
        )
        if args.json:
            payload = {
                "ok": result.ok,
                "records": [record_to_dict(record) for record in result.records],
                "artifact_paths": list(result.artifact_paths),
                "warnings": list(result.warnings),
                "errors": list(result.errors),
                "metrics": dict(result.metrics),
            }
            print(json.dumps(payload, indent=2))
        else:
            print(f"ok={result.ok}")
            for key, value in result.metrics.items():
                print(f"{key}: {value}")
            for path in result.artifact_paths:
                print(path)
            for warning in result.warnings:
                print(f"warning: {warning}")
            for error in result.errors:
                print(f"error: {error}")
        return 0 if result.ok else 1

    if args.command == "run":
        source_type = str(args.source_type)
        if source_type == "auto":
            source_type = _detect_source_type(args.locator)
        request = IngestRequest(
            source_type=source_type,
            locator=args.locator,
            options={"recursive": bool(args.recursive)},
        )
        result = app.run_pipeline(
            request,
            case_id=str(args.case_id or ""),
            output_root=str(args.output_root),
            workspace_root=str(args.workspace_root),
            database_path=str(args.database_path or "") or None,
        )
        if args.json:
            payload = {
                "ok": result.ok,
                "records": [record_to_dict(record) for record in result.records],
                "artifact_paths": list(result.artifact_paths),
                "warnings": list(result.warnings),
                "errors": list(result.errors),
                "metrics": dict(result.metrics),
            }
            print(json.dumps(payload, indent=2))
        else:
            print(f"ok={result.ok}")
            for key, value in result.metrics.items():
                print(f"{key}: {value}")
            for path in result.artifact_paths:
                print(path)
            for warning in result.warnings:
                print(f"warning: {warning}")
            for error in result.errors:
                print(f"error: {error}")
        return 0 if result.ok else 1

    if args.command == "extract":
        result = app.extract(
            args.manifest,
            case_id=str(args.case_id or ""),
            output_root=str(args.output_root or "") or None,
            workspace_root=str(args.workspace_root),
        )
        if args.json:
            payload = {
                "ok": result.ok,
                "records": [record_to_dict(record) for record in result.records],
                "artifact_paths": list(result.artifact_paths),
                "warnings": list(result.warnings),
                "errors": list(result.errors),
                "metrics": dict(result.metrics),
            }
            print(json.dumps(payload, indent=2))
        else:
            print(f"ok={result.ok}")
            for key, value in result.metrics.items():
                print(f"{key}: {value}")
            for path in result.artifact_paths:
                print(path)
            for warning in result.warnings:
                print(f"warning: {warning}")
            for error in result.errors:
                print(f"error: {error}")
        return 0 if result.ok else 1

    if args.command == "recover":
        result = app.recover(
            args.report,
            case_id=str(args.case_id or ""),
            output_root=str(args.output_root or "") or None,
            workspace_root=str(args.workspace_root),
        )
        if args.json:
            payload = {
                "ok": result.ok,
                "records": [record_to_dict(record) for record in result.records],
                "artifact_paths": list(result.artifact_paths),
                "warnings": list(result.warnings),
                "errors": list(result.errors),
                "metrics": dict(result.metrics),
            }
            print(json.dumps(payload, indent=2))
        else:
            print(f"ok={result.ok}")
            for key, value in result.metrics.items():
                print(f"{key}: {value}")
            for path in result.artifact_paths:
                print(path)
            for warning in result.warnings:
                print(f"warning: {warning}")
            for error in result.errors:
                print(f"error: {error}")
        return 0 if result.ok else 1

    if args.command == "normalize":
        result = app.normalize(
            args.report,
            case_id=str(args.case_id or ""),
            output_root=str(args.output_root or "") or None,
            workspace_root=str(args.workspace_root),
        )
        if args.json:
            payload = {
                "ok": result.ok,
                "records": [record_to_dict(record) for record in result.records],
                "artifact_paths": list(result.artifact_paths),
                "warnings": list(result.warnings),
                "errors": list(result.errors),
                "metrics": dict(result.metrics),
            }
            print(json.dumps(payload, indent=2))
        else:
            print(f"ok={result.ok}")
            for key, value in result.metrics.items():
                print(f"{key}: {value}")
            for path in result.artifact_paths:
                print(path)
            for warning in result.warnings:
                print(f"warning: {warning}")
            for error in result.errors:
                print(f"error: {error}")
        return 0 if result.ok else 1

    if args.command == "correlate":
        result = app.correlate(
            args.report,
            case_id=str(args.case_id or ""),
            output_root=str(args.output_root or "") or None,
            workspace_root=str(args.workspace_root),
        )
        if args.json:
            payload = {
                "ok": result.ok,
                "records": [record_to_dict(record) for record in result.records],
                "artifact_paths": list(result.artifact_paths),
                "warnings": list(result.warnings),
                "errors": list(result.errors),
                "metrics": dict(result.metrics),
            }
            print(json.dumps(payload, indent=2))
        else:
            print(f"ok={result.ok}")
            for key, value in result.metrics.items():
                print(f"{key}: {value}")
            for path in result.artifact_paths:
                print(path)
            for warning in result.warnings:
                print(f"warning: {warning}")
            for error in result.errors:
                print(f"error: {error}")
        return 0 if result.ok else 1

    if args.command == "store":
        result = app.store(
            args.report,
            case_id=str(args.case_id or ""),
            output_root=str(args.output_root or "") or None,
            workspace_root=str(args.workspace_root),
            database_path=str(args.database_path or "") or None,
        )
        if args.json:
            payload = {
                "ok": result.ok,
                "records": [record_to_dict(record) for record in result.records],
                "artifact_paths": list(result.artifact_paths),
                "warnings": list(result.warnings),
                "errors": list(result.errors),
                "metrics": dict(result.metrics),
            }
            print(json.dumps(payload, indent=2))
        else:
            print(f"ok={result.ok}")
            for key, value in result.metrics.items():
                print(f"{key}: {value}")
            for path in result.artifact_paths:
                print(path)
            for warning in result.warnings:
                print(f"warning: {warning}")
            for error in result.errors:
                print(f"error: {error}")
        return 0 if result.ok else 1

    if args.command == "present":
        result = app.present(
            args.report,
            case_id=str(args.case_id or ""),
            output_root=str(args.output_root or "") or None,
            workspace_root=str(args.workspace_root),
            database_path=str(args.database_path or "") or None,
        )
        if args.json:
            payload = {
                "ok": result.ok,
                "records": [record_to_dict(record) for record in result.records],
                "artifact_paths": list(result.artifact_paths),
                "warnings": list(result.warnings),
                "errors": list(result.errors),
                "metrics": dict(result.metrics),
            }
            print(json.dumps(payload, indent=2))
        else:
            print(f"ok={result.ok}")
            for key, value in result.metrics.items():
                print(f"{key}: {value}")
            for path in result.artifact_paths:
                print(path)
            for warning in result.warnings:
                print(f"warning: {warning}")
            for error in result.errors:
                print(f"error: {error}")
        return 0 if result.ok else 1

    if args.command == "serve":
        run_api_server(args.database_path, host=str(args.host), port=int(args.port))
        return 0

    parser.print_help()
    return 0
