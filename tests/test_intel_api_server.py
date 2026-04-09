from __future__ import annotations

import json
import threading
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request
from urllib.request import urlopen

from intel_api import create_api_server
from intel_core import EventRecord, IndicatorRecord, JobRecord, RelationshipRecord, SourceRecord, TimelineRecord
from intel_storage import SQLiteIntelligenceStore


def _read_json(url: str) -> dict[str, object]:
    with urlopen(url) as response:  # noqa: S310 - local test server only
        return json.loads(response.read().decode("utf-8"))


def _read_text(url: str) -> tuple[str, str]:
    with urlopen(url) as response:  # noqa: S310 - local test server only
        content_type = response.headers.get_content_type()
        body = response.read().decode("utf-8")
    return content_type, body


def _post_form(url: str, payload: dict[str, object]) -> dict[str, object]:
    body = urlencode({key: str(value) for key, value in payload.items()}).encode("utf-8")
    request = Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urlopen(request) as response:  # noqa: S310 - local test server only
        return json.loads(response.read().decode("utf-8"))


def _seed_monitor_snapshot(database_path: Path, store: SQLiteIntelligenceStore, *, case_id: str) -> None:
    store.persist_watched_sources(
        (
            {
                "watch_id": "watch-hot",
                "case_id": case_id,
                "source_type": "log",
                "locator": "C:/evidence/hot.log",
                "display_name": "hot.log",
                "recursive": False,
                "enabled": True,
                "poll_interval_seconds": 60.0,
                "status": "active",
                "created_at": "2026-04-08T12:00:00Z",
                "updated_at": "2026-04-08T12:10:00Z",
                "snooze_until": "",
                "notes": "hot-path source",
                "tags": ["priority", "log"],
            },
            {
                "watch_id": "watch-cool",
                "case_id": case_id,
                "source_type": "file",
                "locator": "C:/evidence/cool.txt",
                "display_name": "cool.txt",
                "recursive": False,
                "enabled": True,
                "poll_interval_seconds": 20.0,
                "status": "active",
                "created_at": "2026-04-08T12:00:00Z",
                "updated_at": "2026-04-08T12:10:00Z",
                "snooze_until": "",
                "notes": "",
                "tags": [],
            },
        )
    )
    store.persist_watcher_states(
        (
            {
                "watcher_id": "watcher-hot",
                "source_id": "source-1",
                "case_id": case_id,
                "watcher_type": "source_monitor",
                "source_type": "log",
                "locator": "C:/evidence/hot.log",
                "status": "changed",
                "last_checked_at": "2026-04-08T12:10:00Z",
                "last_seen_at": "2026-04-08T12:10:00Z",
                "last_changed_at": "2026-04-08T12:09:45Z",
                "cursor": "cursor:2",
                "content_hash": "hash-hot",
                "suppression_until": "",
                "backlog_pointer": "extract",
                "consecutive_no_change_count": 0,
                "total_check_count": 4,
                "total_change_count": 3,
                "last_error": "",
                "triage_priority": "high",
                "triage_score": 82,
                "burst_change_streak": 2,
                "change_kind": "append_only",
                "registered_poll_interval_seconds": 60.0,
            },
            {
                "watcher_id": "watcher-cool",
                "source_id": "source-1",
                "case_id": case_id,
                "watcher_type": "source_monitor",
                "source_type": "file",
                "locator": "C:/evidence/cool.txt",
                "status": "changed",
                "last_checked_at": "2026-04-08T12:10:00Z",
                "last_seen_at": "2026-04-08T12:10:00Z",
                "last_changed_at": "2026-04-08T12:09:50Z",
                "cursor": "cursor:5",
                "content_hash": "hash-cool",
                "suppression_until": "2026-04-08T12:15:00Z",
                "backlog_pointer": "",
                "consecutive_no_change_count": 0,
                "total_check_count": 5,
                "total_change_count": 4,
                "last_error": "",
                "triage_priority": "low",
                "triage_score": 32,
                "burst_change_streak": 0,
                "change_kind": "modified",
                "registered_poll_interval_seconds": 20.0,
            },
        )
    )

    output_root = database_path.parent
    monitor_dir = output_root / "monitor"
    monitor_dir.mkdir(parents=True, exist_ok=True)
    queues_root = output_root / "queues"
    completed_root = queues_root / "completed" / "extract"
    failed_root = queues_root / "failed" / "recover"
    other_root = queues_root / "completed" / "store"
    completed_root.mkdir(parents=True, exist_ok=True)
    failed_root.mkdir(parents=True, exist_ok=True)
    other_root.mkdir(parents=True, exist_ok=True)

    completed_archive = {
        "schema_version": 1,
        "archived_at": "2026-04-08T12:11:00Z",
        "archive_state": "completed",
        "stage": "extract",
        "queue_path": str((queues_root / "extract" / "job-archive-completed.json").resolve()),
        "queue": {
            "source_manifest_path": str((output_root / "manifests" / "source_manifest.json").resolve()),
            "triage": {"priority_label": "high", "priority_score": 82},
            "job": {"id": "job-archive-completed", "case_id": case_id, "source_id": "source-1", "stage": "extract"},
            "source": {
                "id": "source-1",
                "source_id": "source-1",
                "case_id": case_id,
                "source_type": "log",
                "locator": "C:/evidence/hot.log",
                "display_name": "hot.log",
            },
        },
        "result": {
            "ok": True,
            "warnings": [],
            "errors": [],
            "artifact_paths": [str((output_root / "reports" / "extract_report.json").resolve())],
        },
    }
    failed_archive = {
        "schema_version": 1,
        "archived_at": "2026-04-08T12:12:00Z",
        "archive_state": "failed",
        "stage": "recover",
        "queue_path": str((queues_root / "recover" / "job-archive-failed.json").resolve()),
        "queue": {
            "extract_report_path": str((output_root / "reports" / "extract_report.json").resolve()),
            "triage": {"priority_label": "low", "priority_score": 18},
            "job": {"id": "job-archive-failed", "case_id": case_id, "source_id": "source-1", "stage": "recover"},
            "source": {
                "id": "source-1",
                "source_id": "source-1",
                "case_id": case_id,
                "source_type": "file",
                "locator": "C:/evidence/cool.txt",
                "display_name": "cool.txt",
            },
        },
        "result": {
            "ok": False,
            "warnings": ["recover warning"],
            "errors": ["recover failed"],
            "artifact_paths": [str((output_root / "reports" / "recover_report.json").resolve())],
        },
    }
    other_archive = {
        "schema_version": 1,
        "archived_at": "2026-04-08T12:10:30Z",
        "archive_state": "completed",
        "stage": "store",
        "queue_path": str((queues_root / "store" / "job-archive-other.json").resolve()),
        "queue": {
            "correlation_report_path": str((output_root / "reports" / "other_correlation_report.json").resolve()),
            "job": {"id": "job-archive-other", "case_id": "case-other", "source_id": "source-other", "stage": "store"},
            "source": {
                "id": "source-other",
                "source_id": "source-other",
                "case_id": "case-other",
                "source_type": "file",
                "locator": "C:/evidence/other.bin",
                "display_name": "other.bin",
            },
        },
        "result": {
            "ok": True,
            "warnings": [],
            "errors": [],
            "artifact_paths": [str((output_root / "storage" / "other.sqlite3").resolve())],
        },
    }
    (completed_root / "job-archive-completed__20260408121100.json").write_text(
        json.dumps(completed_archive, indent=2),
        encoding="utf-8",
    )
    (failed_root / "job-archive-failed__20260408121200.json").write_text(
        json.dumps(failed_archive, indent=2),
        encoding="utf-8",
    )
    (other_root / "job-archive-other__20260408121030.json").write_text(
        json.dumps(other_archive, indent=2),
        encoding="utf-8",
    )

    retention_root = output_root / "retention"
    retention_history = retention_root / "history"
    retention_history.mkdir(parents=True, exist_ok=True)
    cleanup_report_path = retention_root / "cleanup_report.json"
    cleanup_report = {
        "schema_version": 1,
        "started_at": "2026-04-08T12:09:55Z",
        "completed_at": "2026-04-08T12:10:05Z",
        "ok": True,
        "dry_run": False,
        "output_root": str(output_root.resolve()),
        "targets": {
            "queue_completed_max_age_seconds": 604800.0,
            "queue_failed_max_age_seconds": 2592000.0,
            "watch_delta_max_age_seconds": 259200.0,
        },
        "metrics": {
            "candidate_count": 2,
            "candidate_bytes": 128,
            "removed_count": 2,
            "removed_bytes": 128,
            "warning_count": 0,
            "error_count": 0,
        },
        "categories": {
            "queue_completed": {"candidate_count": 1, "candidate_bytes": 64, "removed_count": 1, "removed_bytes": 64},
            "watch_delta": {"candidate_count": 1, "candidate_bytes": 64, "removed_count": 1, "removed_bytes": 64},
        },
        "warnings": [],
        "errors": [],
    }
    cleanup_report["report_path"] = str(cleanup_report_path.resolve())
    cleanup_report["history_path"] = str((retention_history / "cleanup_report__20260408121005.json").resolve())
    cleanup_report["artifact_paths"] = [cleanup_report["report_path"], cleanup_report["history_path"]]
    cleanup_report_text = json.dumps(cleanup_report, indent=2)
    cleanup_report_path.write_text(cleanup_report_text, encoding="utf-8")
    (retention_history / "cleanup_report__20260408121005.json").write_text(cleanup_report_text, encoding="utf-8")
    older_cleanup_report = {
        **cleanup_report,
        "started_at": "2026-04-08T10:00:00Z",
        "completed_at": "2026-04-08T10:00:10Z",
        "report_path": str(cleanup_report_path.resolve()),
        "history_path": str((retention_history / "cleanup_report__20260408100010.json").resolve()),
        "artifact_paths": [
            str(cleanup_report_path.resolve()),
            str((retention_history / "cleanup_report__20260408100010.json").resolve()),
        ],
    }
    (retention_history / "cleanup_report__20260408100010.json").write_text(
        json.dumps(older_cleanup_report, indent=2),
        encoding="utf-8",
    )
    history_rows = [
        {
            "schema_version": 1,
            "recorded_at": "2026-04-08T12:08:05Z",
            "case_id": case_id,
            "cycle_count": 1,
            "last_heartbeat_at": "2026-04-08T12:08:05Z",
            "stage_budget_mode": "idle",
            "queue_total_before": 0,
            "queue_total_after": 0,
            "queue_counts_before": {},
            "queue_counts_after": {},
            "executed_check_count": 1,
            "changed_count": 0,
            "failed_check_count": 0,
            "processed_job_count": 0,
            "completed_job_count": 0,
            "failed_job_count": 0,
            "hot_source_count": 0,
            "artifact_path_count": 0,
            "cleanup_removed_count": 0,
            "cleanup_removed_bytes": 0,
            "fairness_stage": "",
            "ok": True,
        },
        {
            "schema_version": 1,
            "recorded_at": "2026-04-08T12:09:05Z",
            "case_id": case_id,
            "cycle_count": 2,
            "last_heartbeat_at": "2026-04-08T12:09:05Z",
            "stage_budget_mode": "collection_hot",
            "queue_total_before": 4,
            "queue_total_after": 2,
            "queue_counts_before": {"extract": 3, "recover": 1},
            "queue_counts_after": {"extract": 1, "recover": 1},
            "executed_check_count": 2,
            "changed_count": 1,
            "failed_check_count": 0,
            "processed_job_count": 2,
            "completed_job_count": 2,
            "failed_job_count": 0,
            "hot_source_count": 1,
            "artifact_path_count": 2,
            "cleanup_removed_count": 0,
            "cleanup_removed_bytes": 0,
            "fairness_stage": "",
            "ok": True,
        },
        {
            "schema_version": 1,
            "recorded_at": "2026-04-08T12:10:05Z",
            "case_id": case_id,
            "cycle_count": 3,
            "last_heartbeat_at": "2026-04-08T12:10:05Z",
            "stage_budget_mode": "collection_hot",
            "queue_total_before": 3,
            "queue_total_after": 1,
            "queue_counts_before": {"extract": 2, "recover": 1},
            "queue_counts_after": {"extract": 1},
            "executed_check_count": 2,
            "changed_count": 2,
            "failed_check_count": 0,
            "processed_job_count": 2,
            "completed_job_count": 1,
            "failed_job_count": 1,
            "hot_source_count": 1,
            "artifact_path_count": 3,
            "cleanup_removed_count": 2,
            "cleanup_removed_bytes": 128,
            "fairness_stage": "",
            "ok": False,
        },
    ]
    (monitor_dir / "monitor_history.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in history_rows),
        encoding="utf-8",
    )

    monitor_payload = {
        "schema_version": 1,
        "runtime": "passive_monitor",
        "cycle_count": 3,
        "last_heartbeat_at": "2026-04-08T12:10:05Z",
        "stage_budget_mode": "collection_hot",
        "hot_cycle_streak": 2,
        "drain_cycle_streak": 0,
        "queue_total_before": 3,
        "queue_total_after": 1,
        "queue_counts_before": {"extract": 2, "recover": 1, "normalize": 0, "correlate": 0, "store": 0, "present": 0},
        "queue_counts_after": {"extract": 1, "recover": 0, "normalize": 0, "correlate": 0, "store": 0, "present": 0},
        "queue_stage_priority_counts_before": {
            "extract": {"urgent": 1, "high": 1, "normal": 0, "low": 0},
            "recover": {"urgent": 0, "high": 1, "normal": 0, "low": 0},
        },
        "queue_stage_age_stats_before": {
            "extract": {"oldest_age_seconds": 240, "aged_job_count_soft": 2, "aged_job_count_hard": 0},
            "recover": {"oldest_age_seconds": 120, "aged_job_count_soft": 1, "aged_job_count_hard": 0},
        },
        "cleanup_policy": {
            "enabled": True,
            "cleanup_completed_days": 7.0,
            "cleanup_failed_days": 30.0,
            "cleanup_watch_delta_days": 3.0,
            "workspace_scoped_only": True,
        },
        "cleanup": {
            "configured": True,
            "executed": True,
            "skipped": False,
            "reason": "completed",
            "removed_count": 2,
            "removed_bytes": 128,
            "report_path": str(cleanup_report_path.resolve()),
            "artifact_paths": [str(cleanup_report_path.resolve()), str((retention_history / "cleanup_report__20260408121005.json").resolve())],
            "categories": {
                "queue_completed": {"removed_count": 1},
                "watch_delta": {"removed_count": 1},
            },
            "warnings": [],
            "errors": [],
            "metrics": {
                "candidate_count": 2,
                "candidate_bytes": 128,
                "removed_count": 2,
                "removed_bytes": 128,
                "warning_count": 0,
                "error_count": 0,
            },
        },
        "source_checks": {
            "registered_count": 2,
            "eligible_count": 2,
            "executed_check_count": 2,
            "changed_count": 2,
            "ingested_count": 1,
            "skipped_count": 0,
            "cooldown_skip_count": 1,
            "suppressed_count": 1,
            "failed_count": 0,
            "reused_hash_count": 1,
            "full_hash_count": 1,
            "append_only_count": 1,
            "priority_counts": {"urgent": 0, "high": 1, "normal": 0, "low": 1},
            "poll_adaptation_counts": {"always_on": 0, "base": 0, "burst": 1, "hot": 0, "idle_backoff": 0, "snoozed": 0, "suppressed": 1},
            "artifact_path_count": 1,
            "results": [
                {
                    "watch_id": "watch-hot",
                    "locator": "C:/evidence/hot.log",
                    "source_type": "log",
                    "ok": True,
                    "executed": True,
                    "reason": "changed",
                    "changed": True,
                    "ingested": True,
                    "skipped": False,
                    "change_kind": "append_only",
                    "priority_label": "high",
                    "priority_score": 82,
                    "delta_ingest": True,
                    "poll_adaptation": "burst",
                    "next_poll_adaptation": "burst",
                    "burst_mode": True,
                    "burst_change_streak": 2,
                    "cooldown_remaining_seconds": 0.0,
                    "effective_poll_interval_seconds": 15.0,
                },
                {
                    "watch_id": "watch-cool",
                    "locator": "C:/evidence/cool.txt",
                    "source_type": "file",
                    "ok": True,
                    "executed": False,
                    "reason": "suppressed",
                    "changed": False,
                    "ingested": False,
                    "skipped": True,
                    "priority_label": "low",
                    "priority_score": 32,
                    "poll_adaptation": "suppressed",
                    "suppressed": True,
                    "suppressed_until": "2026-04-08T12:15:00Z",
                    "suppression_remaining_seconds": 300.0,
                    "cooldown_remaining_seconds": 300.0,
                    "effective_poll_interval_seconds": 300.0,
                    "burst_mode": False,
                    "burst_change_streak": 0,
                },
            ],
        },
        "automation": {
            "enabled": True,
            "mode": "recommend",
            "evaluated_at": "2026-04-08T12:10:05Z",
            "recommendations": [
                {
                    "scope": "case",
                    "case_id": case_id,
                    "target_id": case_id,
                    "target_label": case_id,
                    "current_preset_name": "balanced",
                    "recommended_preset_name": "collection_first",
                    "reason": "Sustained queue pressure is keeping this case in collection_hot mode.",
                    "safe_to_apply": True,
                    "action": "recommend",
                },
                {
                    "scope": "watch",
                    "case_id": case_id,
                    "watch_id": "watch-hot",
                    "target_id": "watch-hot",
                    "target_label": "hot.log",
                    "current_preset_name": "source:default",
                    "recommended_preset_name": "source:log",
                    "reason": "This log source is staying active enough to benefit from the append-heavy source:log preset.",
                    "safe_to_apply": True,
                    "action": "recommend",
                },
            ],
            "applied_actions": [],
            "summary": {
                "recommendation_count": 2,
                "case_recommendation_count": 1,
                "watch_recommendation_count": 1,
                "safe_to_apply_count": 2,
                "applied_count": 0,
                "case_applied_count": 0,
                "watch_applied_count": 0,
            },
        },
    }
    (monitor_dir / "monitor_status.json").write_text(json.dumps(monitor_payload, indent=2), encoding="utf-8")


def test_api_server_exposes_case_summary_and_relationship_endpoints(tmp_path) -> None:
    database_path = tmp_path / "intel.sqlite3"
    store = SQLiteIntelligenceStore(database_path)
    source = SourceRecord(
        id="source-1",
        source_id="source-1",
        case_id="case-api",
        source_type="file",
        locator="C:/evidence/sample.txt",
    )
    store.persist(
        source=source,
        records=(
            IndicatorRecord(
                id="indicator-1",
                source_id="source-1",
                case_id="case-api",
                indicator_type="domain",
                value="example.com",
                normalized_value="example.com",
            ),
            RelationshipRecord(
                id="rel-1",
                source_id="source-1",
                case_id="case-api",
                relationship_type="url_references_domain",
                source_ref="indicator-url",
                target_ref="indicator-1",
            ),
            EventRecord(
                id="event-1",
                source_id="source-1",
                case_id="case-api",
                event_type="artifact_metadata",
                title="Metadata event",
                timestamp="2026-04-08T12:00:00Z",
            ),
            TimelineRecord(
                id="timeline-1",
                source_id="source-1",
                case_id="case-api",
                title="Case timeline",
                start_time="2026-04-08T12:00:00Z",
                end_time="2026-04-08T12:00:00Z",
                event_refs=("event-1",),
            ),
            JobRecord(
                id="job-1",
                source_id="source-1",
                case_id="case-api",
                job_type="pipeline-stage",
                stage="extract",
                status="completed",
                worker="platform_extract",
                finished_at="2026-04-08T12:05:00Z",
            ),
        ),
    )
    store.persist_audit_events(
        (
            {
                "audit_id": "audit-1",
                "created_at": "2026-04-08T12:06:00Z",
                "source_id": "source-1",
                "case_id": "case-api",
                "stage": "extract",
                "plugin": "platform_extract",
                "job_id": "job-1",
                "ok": True,
                "status": "completed",
                "metrics": {"record_count": 4},
                "warnings": [],
                "errors": [],
                "artifact_paths": ["D:/tmp/extract_report.json"],
            },
        )
    )
    _seed_monitor_snapshot(database_path, store, case_id="case-api")

    server = create_api_server(database_path, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        base_url = f"http://{host}:{port}"
        health = _read_json(f"{base_url}/health")
        monitor = _read_json(f"{base_url}/monitor")
        monitor_forecast = _read_json(f"{base_url}/monitor-forecast")
        monitor_history = _read_json(f"{base_url}/monitor-history")
        archives = _read_json(f"{base_url}/archives")
        cleanup_reports = _read_json(f"{base_url}/cleanup-reports")
        plugins = _read_json(f"{base_url}/plugins")
        cases = _read_json(f"{base_url}/cases")
        summary = _read_json(f"{base_url}/cases/case-api/summary")
        case_monitor = _read_json(f"{base_url}/cases/case-api/monitor")
        case_tuning = _read_json(f"{base_url}/cases/case-api/monitor-tuning")
        case_monitor_forecast = _read_json(f"{base_url}/cases/case-api/monitor-forecast")
        case_monitor_history = _read_json(f"{base_url}/cases/case-api/monitor-history")
        case_archives = _read_json(f"{base_url}/cases/case-api/archives")
        case_cleanup_reports = _read_json(f"{base_url}/cases/case-api/cleanup-reports")
        watch_sources = _read_json(f"{base_url}/cases/case-api/watch-sources")
        watch_detail = _read_json(f"{base_url}/cases/case-api/watch-sources?watch_id=watch-hot")
        watcher_detail = _read_json(f"{base_url}/cases/case-api/watchers?watch_id=watch-cool")
        disable_result = _post_form(
            f"{base_url}/cases/case-api/watch-sources",
            {"watch_id": "watch-hot", "action": "disable"},
        )
        update_result = _post_form(
            f"{base_url}/cases/case-api/watch-sources",
            {
                "watch_id": "watch-hot",
                "action": "update",
                "poll_interval_seconds": 45,
                "notes": "primary hot lane",
                "tags": "priority, triage, priority",
            },
        )
        source_tuning_update = _post_form(
            f"{base_url}/cases/case-api/watch-sources",
            {
                "watch_id": "watch-hot",
                "action": "update",
                "tuning_preset_name": "source:log",
                "forecast_min_history": 5,
                "source_churn_spike_factor": 4.0,
                "suppressed_alert_ids": "source_churn_spike, failure_burst",
            },
        )
        snooze_result = _post_form(
            f"{base_url}/cases/case-api/watch-sources",
            {"watch_id": "watch-hot", "action": "snooze", "seconds": 600},
        )
        monitor_after_snooze = _read_json(f"{base_url}/cases/case-api/monitor")
        resumed_result = _post_form(
            f"{base_url}/cases/case-api/watch-sources",
            {"watch_id": "watch-hot", "action": "resume"},
        )
        tuning_update = _post_form(
            f"{base_url}/cases/case-api/monitor-tuning",
            {
                "preset_name": "quiet",
                "queue_spike_factor": 2.5,
                "suppressed_alert_ids": "failure_burst",
                "alert_severity_overrides": "failure_burst:critical, throughput_drop:info",
                "stage_threshold_overrides": "extract:queue_spike_factor=2.5, store:throughput_drop_factor=0.4",
            },
        )
        updated_case_tuning = _read_json(f"{base_url}/cases/case-api/monitor-tuning")
        case_monitor_after_tuning = _read_json(f"{base_url}/cases/case-api/monitor")
        case_monitor_forecast_after_tuning = _read_json(f"{base_url}/cases/case-api/monitor-forecast")
        tuning_clear = _post_form(
            f"{base_url}/cases/case-api/monitor-tuning",
            {
                "clear_suppressions": "true",
                "clear_alert_severities": "true",
                "clear_stage_thresholds": "true",
            },
        )
        source_tuning_clear = _post_form(
            f"{base_url}/cases/case-api/watch-sources",
            {"watch_id": "watch-hot", "action": "update", "clear_tuning_profile": "true"},
        )
        clear_result = _post_form(
            f"{base_url}/cases/case-api/watchers",
            {"watch_id": "watch-cool", "action": "clear_suppression"},
        )
        updated_watch_detail = _read_json(f"{base_url}/cases/case-api/watch-sources?watch_id=watch-hot")
        relationships = _read_json(f"{base_url}/cases/case-api/relationships")
        graph = _read_json(f"{base_url}/cases/case-api/graph")
        search = _read_json(f"{base_url}/cases/case-api/search?q=example.com")
        jobs = _read_json(f"{base_url}/cases/case-api/jobs?stage=extract")
        audit = _read_json(f"{base_url}/cases/case-api/audit?stage=extract")
        timeline = _read_json(f"{base_url}/cases/case-api/timeline?timeline_id=timeline-1")
        neighbors = _read_json(f"{base_url}/cases/case-api/graph?node_id=indicator-1&depth=1")

        assert health["ok"] is True
        assert health["plugin_summary"]["plugin_count"] >= 1
        assert health["monitor"]["overview"]["cycle_count"] == 3
        assert health["monitor"]["overview"]["cleanup_removed_count"] == 2
        assert health["monitor"]["overview"]["recent_archive_count"] == 3
        assert health["monitor"]["overview"]["history_cycle_count"] == 3
        assert health["monitor"]["overview"]["forecast_alert_count"] == 1
        assert health["monitor"]["overview"]["automation_recommendation_count"] == 2
        assert monitor["monitor"]["overview"]["burst_source_count"] == 1
        assert monitor["monitor"]["overview"]["automation_mode"] == "recommend"
        assert monitor["monitor"]["cleanup"]["policy"]["cleanup_completed_days"] == 7.0
        assert monitor["monitor"]["cleanup"]["summary"]["report_path"].endswith("cleanup_report.json")
        assert monitor["monitor"]["trends"]["summary"]["history_count"] == 3
        assert monitor["monitor"]["trends"]["queue_pressure"][-1]["queue_total_before"] == 3
        assert monitor["monitor"]["trends"]["throughput"][-1]["processed_job_count"] == 2
        assert monitor["monitor"]["forecast"]["summary"]["predicted_next_queue_total_before"] == 4
        assert monitor["monitor"]["forecast"]["alerts"][0]["id"] == "failure_burst"
        assert monitor["monitor"]["automation"]["recommendations"][0]["recommended_preset_name"] == "collection_first"
        assert monitor_forecast["forecast"]["summary"]["highest_alert_severity"] == "warning"
        assert monitor_history["history"][-1]["cycle_count"] == 3
        assert monitor["monitor"]["recent_archives"][0]["archive_name"].startswith("job-archive-failed")
        assert monitor["monitor"]["cleanup_reports"][0]["report_name"].startswith("cleanup_report__")
        assert monitor["monitor"]["hot_sources"][0]["display_name"] == "hot.log"
        assert len(archives["archives"]) == 3
        assert archives["archives"][0]["archive_state"] == "failed"
        assert case_monitor_forecast["forecast"]["summary"]["predicted_next_queue_total_before"] == 4
        assert len(case_monitor_history["history"]) == 3
        assert len(case_archives["archives"]) == 2
        assert all(item["case_id"] == "case-api" for item in case_archives["archives"])
        assert len(cleanup_reports["cleanup_reports"]) == 2
        assert cleanup_reports["cleanup_reports"][0]["report_name"].startswith("cleanup_report__")
        assert len(case_cleanup_reports["cleanup_reports"]) == 2
        assert plugins["summary"]["plugin_count"] >= 1
        assert any(item["name"] == "metadata_extractor" for item in plugins["plugins"])
        assert plugins["active_profile"] == "default"
        assert str(plugins["settings_path"]).endswith("plugin_settings.json")
        assert any(item["name"] == "default" and item["active"] for item in plugins["profiles"])
        assert any(item["case_id"] == "case-api" for item in cases["cases"])
        assert summary["summary"]["record_count"] >= 5
        assert any(item["name"] == "quiet" for item in case_tuning["available_presets"])
        assert case_tuning["tuning"]["queue_spike_factor"] == 1.75
        assert any(item["name"] == "source:log" for item in watch_sources["available_watch_presets"])
        assert watch_sources["metrics"]["watched_source_count"] == 2
        assert watch_detail["watched_source"]["watch_id"] == "watch-hot"
        assert watch_detail["watcher_state"]["watcher_id"] == "watcher-hot"
        assert watcher_detail["watcher_state"]["watcher_id"] == "watcher-cool"
        assert disable_result["watched_source"]["enabled"] is False
        assert update_result["watched_source"]["poll_interval_seconds"] == 45.0
        assert update_result["watched_source"]["notes"] == "primary hot lane"
        assert update_result["watched_source"]["tags"] == ["priority", "triage"]
        assert source_tuning_update["watched_source"]["tuning_profile"]["preset_name"] == "source:log"
        assert source_tuning_update["watched_source"]["tuning_profile"]["forecast_min_history"] == 5
        assert source_tuning_update["watched_source"]["tuning_profile"]["source_churn_spike_factor"] == 4.0
        assert source_tuning_update["watched_source"]["tuning_profile"]["suppressed_alert_ids"] == [
            "source_churn_spike",
            "failure_burst",
        ]
        assert snooze_result["watched_source"]["status"] == "snoozed"
        assert snooze_result["watched_source"]["snooze_until"]
        assert any(item["watch_id"] == "watch-hot" for item in monitor_after_snooze["monitor"]["snoozed_sources"])
        assert resumed_result["watched_source"]["snooze_until"] == ""
        assert tuning_update["tuning"]["preset_name"] == "quiet"
        assert tuning_update["tuning"]["forecast_min_history"] == 5
        assert tuning_update["tuning"]["queue_spike_factor"] == 2.5
        assert tuning_update["tuning"]["suppressed_alert_ids"] == ["failure_burst"]
        assert tuning_update["tuning"]["alert_severity_overrides"] == {
            "failure_burst": "critical",
            "throughput_drop": "info",
        }
        assert tuning_update["tuning"]["stage_threshold_overrides"] == {
            "extract": {"queue_spike_factor": 2.5},
            "store": {"throughput_drop_factor": 0.4},
        }
        assert updated_case_tuning["tuning"]["queue_spike_factor"] == 2.5
        assert case_monitor_after_tuning["monitor"]["overview"]["forecast_alert_count"] == 0
        assert case_monitor_after_tuning["monitor"]["overview"]["tuning_suppressed_alert_count"] == 1
        assert case_monitor_after_tuning["monitor"]["overview"]["tuning_alert_severity_override_count"] == 2
        assert case_monitor_after_tuning["monitor"]["overview"]["tuning_stage_threshold_override_count"] == 2
        assert case_monitor_forecast_after_tuning["forecast"]["alerts"] == []
        assert case_monitor_forecast_after_tuning["forecast"]["suppressed_alerts"][0]["id"] == "failure_burst"
        assert tuning_clear["tuning"]["preset_name"] == "quiet"
        assert tuning_clear["tuning"]["suppressed_alert_ids"] == []
        assert tuning_clear["tuning"]["alert_severity_overrides"] == {}
        assert tuning_clear["tuning"]["stage_threshold_overrides"] == {}
        assert source_tuning_clear["watched_source"]["tuning_profile"]["preset_name"] == ""
        assert source_tuning_clear["watched_source"]["tuning_profile"]["forecast_min_history"] == 0
        assert source_tuning_clear["watched_source"]["tuning_profile"]["source_churn_spike_factor"] == 0.0
        assert source_tuning_clear["watched_source"]["tuning_profile"]["suppressed_alert_ids"] == []
        assert updated_watch_detail["watched_source"]["poll_interval_seconds"] == 45.0
        assert updated_watch_detail["watched_source"]["notes"] == "primary hot lane"
        assert updated_watch_detail["watched_source"]["tags"] == ["priority", "triage"]
        assert clear_result["watcher_state"]["suppression_until"] == ""
        assert case_monitor["monitor"]["suppressed_sources"][0]["display_name"] == "cool.txt"
        assert case_monitor["monitor"]["backlogged_sources"][0]["backlog_pointer"] == "extract"
        assert summary["summary"]["job_stage_counts"]["extract"] == 1
        assert relationships["relationships"][0]["relationship_type"] == "url_references_domain"
        assert graph["graph"]["edges"][0]["type"] == "url_references_domain"
        assert search["records"][0]["id"] == "indicator-1"
        assert jobs["jobs"][0]["id"] == "job-1"
        assert audit["audit_events"][0]["audit_id"] == "audit-1"
        assert timeline["timeline"]["id"] == "timeline-1"
        assert neighbors["graph"]["root_id"] == "indicator-1"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_api_server_plugin_controls_persist_profiles(tmp_path) -> None:
    database_path = tmp_path / "intel.sqlite3"
    store = SQLiteIntelligenceStore(database_path)
    source = SourceRecord(
        id="source-1",
        source_id="source-1",
        case_id="case-plugin-api",
        source_type="file",
        locator="C:/evidence/sample.txt",
        display_name="sample.txt",
    )
    store.persist(source=source, records=())

    server = create_api_server(database_path, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        base_url = f"http://{host}:{port}"

        initial_plugins = _read_json(f"{base_url}/plugins")
        disable_result = _post_form(
            f"{base_url}/plugins",
            {"action": "disable", "plugin_name": "string_indicator_extractor", "profile_name": "default"},
        )
        save_profile_result = _post_form(
            f"{base_url}/plugins",
            {"action": "save-profile", "profile_name": "no-strings", "source_profile_name": "default"},
        )
        activate_profile_result = _post_form(
            f"{base_url}/plugins",
            {"action": "set-active-profile", "profile_name": "no-strings"},
        )
        updated_plugins = _read_json(f"{base_url}/plugins")
        delete_profile_result = _post_form(
            f"{base_url}/plugins",
            {"action": "delete-profile", "profile_name": "no-strings"},
        )
        final_plugins = _read_json(f"{base_url}/plugins")

        assert initial_plugins["active_profile"] == "default"
        assert any(item["name"] == "default" for item in initial_plugins["profiles"])
        assert disable_result["ok"] is True
        assert disable_result["active_profile"] == "default"
        assert any(
            item["name"] == "string_indicator_extractor" and item["enabled"] is False
            for item in disable_result["plugin_statuses"]
        )
        assert save_profile_result["ok"] is True
        assert any(item["name"] == "no-strings" for item in save_profile_result["profiles"])
        assert activate_profile_result["ok"] is True
        assert activate_profile_result["active_profile"] == "no-strings"
        assert updated_plugins["active_profile"] == "no-strings"
        assert any(item["name"] == "no-strings" and item["active"] for item in updated_plugins["profiles"])
        assert any(
            item["name"] == "string_indicator_extractor" and item["configured_enabled"] is False
            for item in updated_plugins["plugins"]
        )
        assert delete_profile_result["ok"] is True
        assert delete_profile_result["active_profile"] == "default"
        assert final_plugins["active_profile"] == "default"
        assert not any(item["name"] == "no-strings" for item in final_plugins["profiles"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_api_server_exposes_html_dashboard_views(tmp_path) -> None:
    database_path = tmp_path / "intel.sqlite3"
    store = SQLiteIntelligenceStore(database_path)
    source = SourceRecord(
        id="source-1",
        source_id="source-1",
        case_id="case-ui",
        source_type="file",
        locator="C:/evidence/sample.txt",
        display_name="sample.txt",
    )
    store.persist(
        source=source,
        records=(
            IndicatorRecord(
                id="indicator-1",
                source_id="source-1",
                case_id="case-ui",
                indicator_type="domain",
                value="example.com",
                normalized_value="example.com",
            ),
            EventRecord(
                id="event-1",
                source_id="source-1",
                case_id="case-ui",
                event_type="artifact_metadata",
                title="Metadata event",
                timestamp="2026-04-08T12:00:00Z",
            ),
            TimelineRecord(
                id="timeline-1",
                source_id="source-1",
                case_id="case-ui",
                title="Case timeline",
                start_time="2026-04-08T12:00:00Z",
                end_time="2026-04-08T12:00:00Z",
                event_refs=("event-1",),
            ),
            RelationshipRecord(
                id="rel-1",
                source_id="source-1",
                case_id="case-ui",
                relationship_type="contains",
                source_ref="source-1",
                target_ref="indicator-1",
                reason="extractor output",
            ),
            JobRecord(
                id="job-1",
                source_id="source-1",
                case_id="case-ui",
                job_type="pipeline-stage",
                stage="extract",
                status="completed",
                worker="platform_extract",
                finished_at="2026-04-08T12:05:00Z",
            ),
        ),
    )
    store.persist_audit_events(
        (
            {
                "audit_id": "audit-1",
                "created_at": "2026-04-08T12:06:00Z",
                "source_id": "source-1",
                "case_id": "case-ui",
                "stage": "extract",
                "plugin": "platform_extract",
                "job_id": "job-1",
                "ok": True,
                "status": "completed",
                "metrics": {"record_count": 4},
                "warnings": [],
                "errors": [],
                "artifact_paths": ["D:/tmp/extract_report.json"],
            },
        )
    )
    _seed_monitor_snapshot(database_path, store, case_id="case-ui")

    server = create_api_server(database_path, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        base_url = f"http://{host}:{port}"

        content_type, home = _read_text(f"{base_url}/")
        monitor_type, monitor = _read_text(f"{base_url}/monitor-view")
        dash_type, dashboard = _read_text(
            f"{base_url}/cases/case-ui/dashboard?q=example.com&timeline_id=timeline-1&node_id=indicator-1&depth=1"
        )
        monitor_case_type, monitor_case = _read_text(f"{base_url}/cases/case-ui/monitor-view")
        timeline_type, timeline = _read_text(f"{base_url}/cases/case-ui/timeline-view?timeline_id=timeline-1")
        graph_type, graph = _read_text(f"{base_url}/cases/case-ui/graph-view?node_id=indicator-1&depth=1")

        assert content_type == "text/html"
        assert monitor_type == "text/html"
        assert dash_type == "text/html"
        assert monitor_case_type == "text/html"
        assert timeline_type == "text/html"
        assert graph_type == "text/html"
        assert "Case Browser" in home
        assert "Passive Runtime Overview" in home
        assert "Workspace Cleanup" in home
        assert "Backlog Outlook" in home
        assert "Forecast Tuning" in home
        assert "Queue Pressure Trend" in home
        assert "Throughput Trend" in home
        assert "Recent Queue Archives" in home
        assert "Cleanup Reports" in home
        assert "Plugin Health" in home
        assert "metadata_extractor" in home
        assert "Activate Profile" in home
        assert "Save Profile" in home
        assert "Delete Profile" in home
        assert "Disable" in home
        assert "/cases/case-ui/dashboard" in home
        assert "Monitor" in monitor
        assert "hot.log" in monitor
        assert "Cleanup Removed" in monitor
        assert "Backlog Outlook" in monitor
        assert "Forecast Tuning" in monitor
        assert "Preset Recommendations" in monitor
        assert "Policy: completed 7.0d" in monitor
        assert "Recent Monitor Cycles" in monitor
        assert "History JSON" in monitor
        assert "Forecast JSON" in monitor
        assert "Tuning JSON" in monitor
        assert "Save Tuning" in monitor
        assert "Clear Suppressions" in monitor
        assert "Clear Alert Severities" in monitor
        assert "Clear Stage Thresholds" in monitor
        assert "balanced, collection_first, quiet" in monitor
        assert "off, recommend, apply" in monitor
        assert "Alert Severities" in monitor
        assert "Stage Thresholds" in monitor
        assert "collection_first" in monitor
        assert "source:log" in monitor
        assert "Failures detected in the latest cycle" in monitor
        assert "job-archive-failed__20260408121200.json" in monitor
        assert "cleanup_report__20260408121005.json" in monitor
        assert "cool.txt" in monitor_case
        assert "/cases/case-ui/watch-sources?watch_id=watch-hot" in monitor_case
        assert "Snooze 10m" in monitor_case
        assert "Save Poll" in monitor_case
        assert "Save Meta" in monitor_case
        assert "source:file, source:log, source:pcap, source:system" in monitor_case
        assert "Save Source Tuning" in monitor_case
        assert "Clear Source Tuning" in monitor_case
        assert "Clear Suppression" in monitor_case
        assert "Disable" in monitor_case
        assert "case-ui" in dashboard
        assert "Plugin Health" in dashboard
        assert "Activate Profile" in dashboard
        assert "Save Profile" in dashboard
        assert "Delete Profile" in dashboard
        assert "Disable" in dashboard
        assert "Runtime Snapshot" in dashboard
        assert "Workspace Cleanup" in dashboard
        assert "Backlog Outlook" in dashboard
        assert "Forecast Tuning" in dashboard
        assert "Preset Recommendations" in dashboard
        assert "Queue Pressure Trend" in dashboard
        assert "Recent Queue Archives" in dashboard
        assert "example.com" in dashboard
        assert "Case timeline" in dashboard
        assert "indicator-1" in dashboard
        assert "Timeline Drilldown" in timeline
        assert "Metadata event" in timeline
        assert "Graph Drilldown" in graph
        assert "contains" in graph
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
