from __future__ import annotations

import json
import os
import time
from pathlib import Path

from intel_api import PlatformApp
from intel_core import IngestRequest
from intel_runtime import MonitorRuntime
from intel_runtime.monitor import HOT_FAIRNESS_TRIGGER_STREAK, QUEUE_AGE_SOFT_THRESHOLD_SECONDS, build_monitor_forecast
from intel_storage import SQLiteIntelligenceStore
from intel_core import utc_now


def _age_queue_payload(queue_path: str | Path, *, seconds_old: int) -> None:
    path = Path(queue_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    age_anchor = json.loads(json.dumps({"generated_at": utc_now()}))["generated_at"]
    # Convert the current UTC timestamp into an older one without pulling in extra date helpers here.
    from datetime import datetime, timedelta, timezone

    current = datetime.fromisoformat(str(age_anchor).replace("Z", "+00:00")).astimezone(timezone.utc)
    payload["generated_at"] = (current - timedelta(seconds=seconds_old)).isoformat().replace("+00:00", "Z")
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _shift_utc_timestamp(*, seconds_ago: int) -> str:
    from datetime import datetime, timedelta, timezone

    current = datetime.fromisoformat(str(utc_now()).replace("Z", "+00:00")).astimezone(timezone.utc)
    return (current - timedelta(seconds=seconds_ago)).isoformat().replace("+00:00", "Z")


def _set_age_days(path: Path, *, days: float) -> None:
    timestamp = time.time() - (float(days) * 86400.0)
    os.utime(path, (timestamp, timestamp))


def _seed_collection_hot_history(runtime: MonitorRuntime, *, case_id: str) -> None:
    seeded_status = runtime._default_status()
    seeded_status["started_at"] = "2026-04-08T11:59:00Z"
    seeded_status["cycle_count"] = 1
    seeded_status["hot_cycle_streak"] = 1
    runtime.status_path.parent.mkdir(parents=True, exist_ok=True)
    runtime.status_path.write_text(json.dumps(seeded_status, indent=2), encoding="utf-8")
    runtime.history_path.write_text(
        "".join(
            json.dumps(row, sort_keys=True) + "\n"
            for row in (
                {
                    "schema_version": 1,
                    "recorded_at": "2026-04-08T12:00:00Z",
                    "case_id": case_id,
                    "cycle_count": 1,
                    "last_heartbeat_at": "2026-04-08T12:00:00Z",
                    "stage_budget_mode": "collection_hot",
                    "queue_total_before": 1,
                    "queue_total_after": 0,
                    "executed_check_count": 1,
                    "changed_count": 1,
                    "failed_check_count": 0,
                    "processed_job_count": 1,
                    "completed_job_count": 1,
                    "failed_job_count": 0,
                    "hot_source_count": 1,
                    "artifact_path_count": 1,
                    "cleanup_removed_count": 0,
                    "cleanup_removed_bytes": 0,
                    "fairness_stage": "",
                    "ok": True,
                },
                {
                    "schema_version": 1,
                    "recorded_at": "2026-04-08T12:01:00Z",
                    "case_id": case_id,
                    "cycle_count": 2,
                    "last_heartbeat_at": "2026-04-08T12:01:00Z",
                    "stage_budget_mode": "collection_hot",
                    "queue_total_before": 1,
                    "queue_total_after": 0,
                    "executed_check_count": 1,
                    "changed_count": 1,
                    "failed_check_count": 0,
                    "processed_job_count": 1,
                    "completed_job_count": 1,
                    "failed_job_count": 0,
                    "hot_source_count": 1,
                    "artifact_path_count": 1,
                    "cleanup_removed_count": 0,
                    "cleanup_removed_bytes": 0,
                    "fairness_stage": "",
                    "ok": True,
                },
                {
                    "schema_version": 1,
                    "recorded_at": "2026-04-08T12:02:00Z",
                    "case_id": case_id,
                    "cycle_count": 3,
                    "last_heartbeat_at": "2026-04-08T12:02:00Z",
                    "stage_budget_mode": "collection_hot",
                    "queue_total_before": 2,
                    "queue_total_after": 1,
                    "executed_check_count": 1,
                    "changed_count": 1,
                    "failed_check_count": 0,
                    "processed_job_count": 1,
                    "completed_job_count": 1,
                    "failed_job_count": 0,
                    "hot_source_count": 1,
                    "artifact_path_count": 1,
                    "cleanup_removed_count": 0,
                    "cleanup_removed_bytes": 0,
                    "fairness_stage": "",
                    "ok": True,
                },
            )
        ),
        encoding="utf-8",
    )


def _seed_calm_history(runtime: MonitorRuntime, *, case_id: str, current_preset_name: str = "balanced") -> None:
    seeded_status = runtime._default_status()
    seeded_status["started_at"] = "2026-04-08T12:00:00Z"
    seeded_status["cycle_count"] = 3
    seeded_status["hot_cycle_streak"] = 0
    seeded_status["drain_cycle_streak"] = 1
    seeded_status["tuning"]["preset_name"] = current_preset_name
    runtime.status_path.parent.mkdir(parents=True, exist_ok=True)
    runtime.status_path.write_text(json.dumps(seeded_status, indent=2), encoding="utf-8")
    runtime.history_path.write_text(
        "".join(
            json.dumps(row, sort_keys=True) + "\n"
            for row in (
                {
                    "schema_version": 1,
                    "recorded_at": "2026-04-08T12:00:00Z",
                    "case_id": case_id,
                    "cycle_count": 1,
                    "last_heartbeat_at": "2026-04-08T12:00:00Z",
                    "stage_budget_mode": "processing_drain",
                    "queue_total_before": 1,
                    "queue_total_after": 0,
                    "executed_check_count": 1,
                    "changed_count": 0,
                    "failed_check_count": 0,
                    "processed_job_count": 1,
                    "completed_job_count": 1,
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
                    "recorded_at": "2026-04-08T12:01:00Z",
                    "case_id": case_id,
                    "cycle_count": 2,
                    "last_heartbeat_at": "2026-04-08T12:01:00Z",
                    "stage_budget_mode": "processing_drain",
                    "queue_total_before": 0,
                    "queue_total_after": 0,
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
                    "recorded_at": "2026-04-08T12:02:00Z",
                    "case_id": case_id,
                    "cycle_count": 3,
                    "last_heartbeat_at": "2026-04-08T12:02:00Z",
                    "stage_budget_mode": "processing_drain",
                    "queue_total_before": 1,
                    "queue_total_after": 0,
                    "executed_check_count": 1,
                    "changed_count": 0,
                    "failed_check_count": 0,
                    "processed_job_count": 1,
                    "completed_job_count": 1,
                    "failed_job_count": 0,
                    "hot_source_count": 0,
                    "artifact_path_count": 0,
                    "cleanup_removed_count": 0,
                    "cleanup_removed_bytes": 0,
                    "fairness_stage": "",
                    "ok": True,
                },
            )
        ),
        encoding="utf-8",
    )


def test_monitor_runtime_run_once_processes_queue_and_writes_status(tmp_path) -> None:
    sample = tmp_path / "monitor_sample.txt"
    sample.write_text("email=test@example.com https://example.com/path domain=example.org", encoding="utf-8")

    app = PlatformApp()
    app.ingest(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="monitor-case",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
    )
    payload = runtime.run_once()

    status_path = Path(payload["status_path"])
    persisted = json.loads(status_path.read_text(encoding="utf-8"))

    assert payload["cycle_count"] == 1
    assert payload["last_result"]["executed"] is True
    assert payload["total_processed_job_count"] >= 6
    assert payload["queue_total_after"] == 0
    assert status_path.exists()
    assert persisted["cycle_count"] == 1
    assert persisted["last_result"]["reason"] == "processed"
    assert payload["watcher_summary"]["watcher_count"] == 1
    assert payload["watchers"][0]["watcher_type"] == "queue_monitor"

    store = SQLiteIntelligenceStore(payload["database_path"])
    watcher_rows = store.fetch_watcher_states(watcher_type="queue_monitor")

    assert watcher_rows
    assert watcher_rows[0]["watcher_id"] == payload["watcher_id"]
    assert watcher_rows[0]["total_check_count"] == 1


def test_monitor_runtime_appends_cycle_history(tmp_path) -> None:
    sample = tmp_path / "monitor_history_sample.txt"
    sample.write_text("email=test@example.com https://example.com/path", encoding="utf-8")

    app = PlatformApp()
    app.ingest(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="monitor-history-case",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id="monitor-history-case",
    )
    first = runtime.run_once()
    second = runtime.run_once()

    history_path = Path(second["history_path"])
    history_rows = runtime.read_history(limit=10)

    assert history_path.exists()
    assert first["history_path"] == second["history_path"]
    assert len(history_rows) == 2
    assert history_rows[0]["cycle_count"] == 1
    assert history_rows[1]["cycle_count"] == 2
    assert history_rows[0]["case_id"] == "monitor-history-case"
    assert history_rows[1]["queue_total_after"] == 0


def test_monitor_runtime_forecast_flags_queue_pressure_spike(tmp_path) -> None:
    app = PlatformApp()
    output_root = tmp_path / "out"
    case_id = "monitor-forecast-case"
    for index in range(6):
        sample = tmp_path / f"forecast_spike_{index}.txt"
        sample.write_text(f"email=user{index}@example.com https://example.com/{index}", encoding="utf-8")
        app.ingest(
            IngestRequest(source_type="file", locator=str(sample)),
            case_id=case_id,
            output_root=str(output_root),
            workspace_root=str(tmp_path),
        )

    runtime = MonitorRuntime(
        app=app,
        output_root=output_root,
        workspace_root=tmp_path,
        case_id=case_id,
        max_jobs=1,
    )
    runtime.history_path.parent.mkdir(parents=True, exist_ok=True)
    seeded_history = [
        {
            "schema_version": 1,
            "recorded_at": "2026-04-08T12:00:00Z",
            "case_id": case_id,
            "cycle_count": 1,
            "last_heartbeat_at": "2026-04-08T12:00:00Z",
            "stage_budget_mode": "idle",
            "queue_total_before": 1,
            "queue_total_after": 0,
            "executed_check_count": 1,
            "changed_count": 0,
            "failed_check_count": 0,
            "processed_job_count": 1,
            "completed_job_count": 1,
            "failed_job_count": 0,
            "hot_source_count": 0,
            "artifact_path_count": 1,
            "cleanup_removed_count": 0,
            "cleanup_removed_bytes": 0,
            "fairness_stage": "",
            "ok": True,
        },
        {
            "schema_version": 1,
            "recorded_at": "2026-04-08T12:01:00Z",
            "case_id": case_id,
            "cycle_count": 2,
            "last_heartbeat_at": "2026-04-08T12:01:00Z",
            "stage_budget_mode": "processing_drain",
            "queue_total_before": 1,
            "queue_total_after": 0,
            "executed_check_count": 1,
            "changed_count": 0,
            "failed_check_count": 0,
            "processed_job_count": 1,
            "completed_job_count": 1,
            "failed_job_count": 0,
            "hot_source_count": 0,
            "artifact_path_count": 1,
            "cleanup_removed_count": 0,
            "cleanup_removed_bytes": 0,
            "fairness_stage": "",
            "ok": True,
        },
        {
            "schema_version": 1,
            "recorded_at": "2026-04-08T12:02:00Z",
            "case_id": case_id,
            "cycle_count": 3,
            "last_heartbeat_at": "2026-04-08T12:02:00Z",
            "stage_budget_mode": "processing_drain",
            "queue_total_before": 2,
            "queue_total_after": 1,
            "executed_check_count": 1,
            "changed_count": 0,
            "failed_check_count": 0,
            "processed_job_count": 1,
            "completed_job_count": 1,
            "failed_job_count": 0,
            "hot_source_count": 0,
            "artifact_path_count": 1,
            "cleanup_removed_count": 0,
            "cleanup_removed_bytes": 0,
            "fairness_stage": "",
            "ok": True,
        },
    ]
    runtime.history_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in seeded_history),
        encoding="utf-8",
    )

    payload = runtime.run_once()

    assert payload["forecast"]["summary"]["alert_count"] >= 1
    assert payload["forecast"]["summary"]["predicted_next_queue_total_before"] >= 4
    assert any(item["id"] == "queue_pressure_spike" for item in payload["forecast"]["alerts"])


def test_build_monitor_forecast_honors_watch_profile_thresholds_and_suppressions() -> None:
    history = [
        {
            "cycle_count": 1,
            "last_heartbeat_at": "2026-04-08T12:00:00Z",
            "queue_total_before": 1,
            "queue_total_after": 0,
            "processed_job_count": 1,
            "completed_job_count": 1,
            "changed_count": 1,
            "failed_job_count": 0,
            "failed_check_count": 0,
            "executed_check_count": 1,
        },
        {
            "cycle_count": 2,
            "last_heartbeat_at": "2026-04-08T12:01:00Z",
            "queue_total_before": 1,
            "queue_total_after": 0,
            "processed_job_count": 1,
            "completed_job_count": 1,
            "changed_count": 1,
            "failed_job_count": 0,
            "failed_check_count": 0,
            "executed_check_count": 1,
        },
        {
            "cycle_count": 3,
            "last_heartbeat_at": "2026-04-08T12:02:00Z",
            "queue_total_before": 1,
            "queue_total_after": 0,
            "processed_job_count": 1,
            "completed_job_count": 1,
            "changed_count": 4,
            "failed_job_count": 0,
            "failed_check_count": 0,
            "executed_check_count": 4,
        },
    ]
    changed_results = [
        {
            "watch_id": f"watch-{index}",
            "changed": True,
            "priority_label": "high",
            "tuning_profile": {
                "forecast_min_history": 4,
                "source_churn_spike_factor": 4.0,
                "suppressed_alert_ids": ["source_churn_spike"],
            },
        }
        for index in range(4)
    ]

    threshold_suppressed = build_monitor_forecast(
        history,
        status={
            "source_checks": {"results": changed_results},
            "watch_tuning_profiles": {
                row["watch_id"]: row["tuning_profile"]
                for row in changed_results
            },
        },
    )

    assert threshold_suppressed["alerts"] == []
    assert threshold_suppressed["summary"]["effective_source_churn_forecast_min_history"] == 4
    assert threshold_suppressed["summary"]["effective_source_churn_spike_factor"] == 4.0

    suppression_history = [
        {
            "cycle_count": 1,
            "last_heartbeat_at": "2026-04-08T12:00:00Z",
            "queue_total_before": 1,
            "queue_total_after": 0,
            "processed_job_count": 1,
            "completed_job_count": 1,
            "changed_count": 1,
            "failed_job_count": 0,
            "failed_check_count": 0,
            "executed_check_count": 1,
        },
        {
            "cycle_count": 2,
            "last_heartbeat_at": "2026-04-08T12:01:00Z",
            "queue_total_before": 1,
            "queue_total_after": 0,
            "processed_job_count": 1,
            "completed_job_count": 1,
            "changed_count": 1,
            "failed_job_count": 0,
            "failed_check_count": 0,
            "executed_check_count": 1,
        },
        {
            "cycle_count": 3,
            "last_heartbeat_at": "2026-04-08T12:02:00Z",
            "queue_total_before": 1,
            "queue_total_after": 0,
            "processed_job_count": 1,
            "completed_job_count": 1,
            "changed_count": 1,
            "failed_job_count": 0,
            "failed_check_count": 0,
            "executed_check_count": 1,
        },
        {
            "cycle_count": 4,
            "last_heartbeat_at": "2026-04-08T12:03:00Z",
            "queue_total_before": 1,
            "queue_total_after": 0,
            "processed_job_count": 1,
            "completed_job_count": 1,
            "changed_count": 4,
            "failed_job_count": 0,
            "failed_check_count": 0,
            "executed_check_count": 4,
        }
    ]
    suppression_only_results = [
        {
            **row,
            "tuning_profile": {
                "suppressed_alert_ids": ["source_churn_spike"],
            },
        }
        for row in changed_results
    ]

    suppression_only = build_monitor_forecast(
        suppression_history,
        status={
            "source_checks": {"results": suppression_only_results},
            "watch_tuning_profiles": {
                row["watch_id"]: row["tuning_profile"]
                for row in suppression_only_results
            },
        },
    )

    assert suppression_only["alerts"] == []
    assert suppression_only["suppressed_alerts"][0]["id"] == "source_churn_spike"


def test_build_monitor_forecast_honors_stage_thresholds_and_alert_severities() -> None:
    history = [
        {
            "cycle_count": 1,
            "last_heartbeat_at": "2026-04-08T12:00:00Z",
            "queue_total_before": 2,
            "queue_total_after": 1,
            "processed_job_count": 4,
            "completed_job_count": 4,
            "changed_count": 0,
            "failed_job_count": 0,
            "failed_check_count": 0,
            "executed_check_count": 1,
        },
        {
            "cycle_count": 2,
            "last_heartbeat_at": "2026-04-08T12:01:00Z",
            "queue_total_before": 2,
            "queue_total_after": 1,
            "processed_job_count": 4,
            "completed_job_count": 4,
            "changed_count": 0,
            "failed_job_count": 0,
            "failed_check_count": 0,
            "executed_check_count": 1,
        },
        {
            "cycle_count": 3,
            "last_heartbeat_at": "2026-04-08T12:02:00Z",
            "queue_total_before": 6,
            "queue_total_after": 5,
            "processed_job_count": 1,
            "completed_job_count": 1,
            "changed_count": 0,
            "failed_job_count": 0,
            "failed_check_count": 0,
            "executed_check_count": 1,
        },
    ]

    without_stage_override = build_monitor_forecast(
        history,
        status={"queue_counts_before": {"extract": 6, "normalize": 1}},
    )
    with_stage_override = build_monitor_forecast(
        history,
        tuning={
            "stage_threshold_overrides": {
                "extract": {
                    "queue_spike_factor": 2.5,
                    "throughput_drop_factor": 0.2,
                }
            },
            "alert_severity_overrides": {
                "queue_pressure_spike": "critical",
                "throughput_drop": "info",
            },
        },
        status={"queue_counts_before": {"extract": 6, "normalize": 1}},
    )

    assert any(item["id"] == "queue_pressure_spike" for item in without_stage_override["alerts"])
    assert any(item["id"] == "throughput_drop" for item in without_stage_override["alerts"])
    assert [item["id"] for item in with_stage_override["alerts"]] == ["throughput_drop"]
    assert with_stage_override["alerts"][0]["severity"] == "info"
    suppressed_like = build_monitor_forecast(
        history,
        tuning={
            "stage_threshold_overrides": {"extract": {"queue_spike_factor": 1.5}},
            "alert_severity_overrides": {
                "queue_pressure_spike": "critical",
                "throughput_drop": "info",
            },
        },
        status={"queue_counts_before": {"extract": 6}},
    )
    assert any(item["id"] == "queue_pressure_spike" and item["severity"] == "critical" for item in suppressed_like["alerts"])
    assert any(item["id"] == "throughput_drop" and item["severity"] == "info" for item in suppressed_like["alerts"])
    assert suppressed_like["summary"]["dominant_stage"] == "extract"
    assert suppressed_like["summary"]["effective_queue_spike_factor"] == 1.5
    assert suppressed_like["summary"]["effective_throughput_drop_factor"] == 0.5


def test_monitor_runtime_runs_registered_source_checks_before_queue_drain(tmp_path) -> None:
    sample = tmp_path / "registered_monitor.txt"
    sample.write_text("email=registered@example.com https://example.com/registered", encoding="utf-8")

    app = PlatformApp()
    register_payload = app.register_watch_source(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="monitor-registry-case",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id="monitor-registry-case",
    )
    payload = runtime.run_once()

    assert register_payload["ok"] is True
    assert payload["source_checks"]["registered_count"] == 1
    assert payload["source_checks"]["executed_check_count"] == 1
    assert payload["source_checks"]["changed_count"] == 1
    assert payload["source_checks"]["ingested_count"] == 1
    assert sum(payload["source_checks"]["priority_counts"].values()) >= 1
    assert payload["total_processed_job_count"] >= 6
    assert payload["watched_source_summary"]["watched_source_count"] == 1
    assert any(item["watch_id"] == register_payload["watch_id"] for item in payload["watched_sources"])


def test_monitor_runtime_reports_append_only_log_growth(tmp_path) -> None:
    sample = tmp_path / "monitor_append.log"
    sample.write_text("line1\n", encoding="utf-8")

    app = PlatformApp()
    app.register_watch_source(
        IngestRequest(source_type="log", locator=str(sample)),
        case_id="monitor-append-case",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id="monitor-append-case",
    )
    runtime.run_once()
    sample.write_text("line1\nline2\n", encoding="utf-8")
    payload = runtime.run_once()

    assert payload["source_checks"]["changed_count"] >= 1
    assert payload["source_checks"]["append_only_count"] >= 1
    assert any(item["change_kind"] == "append_only" for item in payload["source_checks"]["results"] if item["executed"])
    assert any(item["delta_ingest"] is True for item in payload["source_checks"]["results"] if item["executed"])
    assert any(item["priority_label"] in {"high", "urgent"} for item in payload["source_checks"]["results"] if item["executed"])


def test_monitor_runtime_applies_idle_backoff_to_quiet_watched_source(tmp_path) -> None:
    sample = tmp_path / "idle_backoff.log"
    sample.write_text("line1\n", encoding="utf-8")

    app = PlatformApp()
    register_payload = app.register_watch_source(
        IngestRequest(source_type="log", locator=str(sample)),
        case_id="monitor-poll-backoff",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
        poll_interval_seconds=10.0,
    )
    watch_payload = app.watch_source(
        IngestRequest(source_type="log", locator=str(sample)),
        case_id="monitor-poll-backoff",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    store = SQLiteIntelligenceStore(watch_payload["metrics"]["database_path"])
    watcher = store.fetch_watcher_states(case_id="monitor-poll-backoff", watcher_type="source_monitor", limit=1)[0]
    watcher["status"] = "unchanged"
    watcher["consecutive_no_change_count"] = 6
    watcher["last_checked_at"] = _shift_utc_timestamp(seconds_ago=15)
    watcher["last_seen_at"] = watcher["last_checked_at"]
    watcher["last_changed_at"] = _shift_utc_timestamp(seconds_ago=900)
    store.persist_watcher_states((watcher,))

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id="monitor-poll-backoff",
    )
    payload = runtime.run_once()
    result = next(item for item in payload["source_checks"]["results"] if item["watch_id"] == register_payload["watch_id"])

    assert payload["source_checks"]["executed_check_count"] == 0
    assert payload["source_checks"]["cooldown_skip_count"] == 1
    assert payload["source_checks"]["poll_adaptation_counts"]["idle_backoff"] >= 1
    assert result["reason"] == "cooldown"
    assert result["poll_adaptation"] == "idle_backoff"
    assert result["base_poll_interval_seconds"] == 10.0
    assert result["effective_poll_interval_seconds"] >= 20.0
    assert result["cooldown_remaining_seconds"] > 0.0


def test_monitor_runtime_shortens_poll_interval_for_recently_active_source(tmp_path) -> None:
    sample = tmp_path / "hot_poll.log"
    sample.write_text("line1\n", encoding="utf-8")

    app = PlatformApp()
    register_payload = app.register_watch_source(
        IngestRequest(source_type="log", locator=str(sample)),
        case_id="monitor-poll-hot",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
        poll_interval_seconds=60.0,
    )
    watch_payload = app.watch_source(
        IngestRequest(source_type="log", locator=str(sample)),
        case_id="monitor-poll-hot",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    store = SQLiteIntelligenceStore(watch_payload["metrics"]["database_path"])
    watcher = store.fetch_watcher_states(case_id="monitor-poll-hot", watcher_type="source_monitor", limit=1)[0]
    watcher["status"] = "changed"
    watcher["consecutive_no_change_count"] = 0
    watcher["last_checked_at"] = _shift_utc_timestamp(seconds_ago=35)
    watcher["last_seen_at"] = watcher["last_checked_at"]
    watcher["last_changed_at"] = _shift_utc_timestamp(seconds_ago=20)
    store.persist_watcher_states((watcher,))

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id="monitor-poll-hot",
    )
    payload = runtime.run_once()
    result = next(item for item in payload["source_checks"]["results"] if item["watch_id"] == register_payload["watch_id"])

    assert payload["source_checks"]["executed_check_count"] == 1
    assert payload["source_checks"]["poll_adaptation_counts"]["hot"] >= 1
    assert result["executed"] is True
    assert result["poll_adaptation"] == "hot"
    assert result["base_poll_interval_seconds"] == 60.0
    assert result["effective_poll_interval_seconds"] == 30.0


def test_monitor_runtime_enters_burst_mode_for_rapid_source_changes(tmp_path) -> None:
    sample = tmp_path / "burst_poll.log"
    sample.write_text("line1\n", encoding="utf-8")

    app = PlatformApp()
    register_payload = app.register_watch_source(
        IngestRequest(source_type="log", locator=str(sample)),
        case_id="monitor-poll-burst",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
        poll_interval_seconds=60.0,
    )
    watch_payload = app.watch_source(
        IngestRequest(source_type="log", locator=str(sample)),
        case_id="monitor-poll-burst",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    store = SQLiteIntelligenceStore(watch_payload["metrics"]["database_path"])
    watcher = store.fetch_watcher_states(case_id="monitor-poll-burst", watcher_type="source_monitor", limit=1)[0]
    watcher["status"] = "changed"
    watcher["triage_priority"] = "high"
    watcher["burst_change_streak"] = 2
    watcher["consecutive_no_change_count"] = 0
    watcher["last_checked_at"] = _shift_utc_timestamp(seconds_ago=20)
    watcher["last_seen_at"] = watcher["last_checked_at"]
    watcher["last_changed_at"] = _shift_utc_timestamp(seconds_ago=10)
    watcher["suppression_until"] = ""
    store.persist_watcher_states((watcher,))
    sample.write_text("line1\nline2\n", encoding="utf-8")

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id="monitor-poll-burst",
    )
    payload = runtime.run_once()
    result = next(item for item in payload["source_checks"]["results"] if item["watch_id"] == register_payload["watch_id"])

    assert payload["source_checks"]["executed_check_count"] == 1
    assert payload["source_checks"]["poll_adaptation_counts"]["burst"] >= 1
    assert result["executed"] is True
    assert result["poll_adaptation"] == "burst"
    assert result["base_poll_interval_seconds"] == 60.0
    assert result["effective_poll_interval_seconds"] == 15.0
    assert result["burst_mode"] is True
    assert result["burst_change_streak"] >= 2


def test_monitor_runtime_honors_suppression_windows_for_low_signal_sources(tmp_path) -> None:
    sample = tmp_path / "suppressed_watch.txt"
    sample.write_text("first version", encoding="utf-8")

    app = PlatformApp()
    register_payload = app.register_watch_source(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="monitor-poll-suppressed",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
        poll_interval_seconds=20.0,
    )
    app.watch_source(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="monitor-poll-suppressed",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    sample.write_text("second version", encoding="utf-8")
    second_watch = app.watch_source(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="monitor-poll-suppressed",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id="monitor-poll-suppressed",
    )
    payload = runtime.run_once()
    result = next(item for item in payload["source_checks"]["results"] if item["watch_id"] == register_payload["watch_id"])

    assert second_watch["watcher_state"]["suppression_until"]
    assert payload["source_checks"]["executed_check_count"] == 0
    assert payload["source_checks"]["cooldown_skip_count"] == 1
    assert payload["source_checks"]["suppressed_count"] == 1
    assert payload["source_checks"]["poll_adaptation_counts"]["suppressed"] >= 1
    assert result["reason"] == "suppressed"
    assert result["poll_adaptation"] == "suppressed"
    assert result["suppressed"] is True
    assert result["suppressed_until"] == second_watch["watcher_state"]["suppression_until"]
    assert result["suppression_remaining_seconds"] > 0.0


def test_monitor_runtime_honors_snooze_windows_for_watched_sources(tmp_path) -> None:
    sample = tmp_path / "snoozed_watch.txt"
    sample.write_text("line1\n", encoding="utf-8")

    app = PlatformApp()
    register_payload = app.register_watch_source(
        IngestRequest(source_type="log", locator=str(sample)),
        case_id="monitor-poll-snoozed",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
        poll_interval_seconds=20.0,
    )
    app.watch_source(
        IngestRequest(source_type="log", locator=str(sample)),
        case_id="monitor-poll-snoozed",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    snooze_payload = app.set_watch_source_snooze(
        case_id="monitor-poll-snoozed",
        watch_id=register_payload["watch_id"],
        seconds=600.0,
        output_root=str(tmp_path / "out"),
    )

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id="monitor-poll-snoozed",
    )
    payload = runtime.run_once()
    result = next(item for item in payload["source_checks"]["results"] if item["watch_id"] == register_payload["watch_id"])

    assert snooze_payload["watched_source"]["snooze_until"]
    assert payload["source_checks"]["executed_check_count"] == 0
    assert payload["source_checks"]["cooldown_skip_count"] == 0
    assert payload["source_checks"]["snoozed_count"] == 1
    assert payload["source_checks"]["poll_adaptation_counts"]["snoozed"] >= 1
    assert result["reason"] == "snoozed"
    assert result["poll_adaptation"] == "snoozed"
    assert result["snoozed"] is True
    assert result["snooze_until"] == snooze_payload["watched_source"]["snooze_until"]
    assert result["snooze_remaining_seconds"] > 0.0


def test_monitor_runtime_runs_workspace_cleanup_when_configured(tmp_path) -> None:
    output_root = tmp_path / "out"
    completed = output_root / "queues" / "completed" / "extract"
    delta = output_root / "objects" / "derived" / "watch_delta" / "source-1"
    completed.mkdir(parents=True, exist_ok=True)
    delta.mkdir(parents=True, exist_ok=True)

    old_completed = completed / "old.json"
    old_completed.write_text("{}", encoding="utf-8")
    old_delta = delta / "old.bin"
    old_delta.write_bytes(b"delta")
    _set_age_days(old_completed, days=2.0)
    _set_age_days(old_delta, days=2.0)

    runtime = MonitorRuntime(
        app=PlatformApp(),
        output_root=output_root,
        workspace_root=tmp_path,
        cleanup_completed_days=1.0,
        cleanup_watch_delta_days=1.0,
    )
    payload = runtime.run_once()

    assert payload["cleanup"]["executed"] is True
    assert payload["cleanup"]["reason"] == "completed"
    assert payload["cleanup"]["removed_count"] == 2
    assert not old_completed.exists()
    assert not old_delta.exists()
    assert payload["last_result"]["cleanup_removed_count"] == 2


def test_monitor_runtime_biases_budget_toward_late_stages_when_intake_is_quiet(tmp_path) -> None:
    early_sample = tmp_path / "early_backlog.txt"
    early_sample.write_text("plain file backlog", encoding="utf-8")
    late_sample = tmp_path / "late_backlog.txt"
    late_sample.write_text("email=late@example.com https://example.com/late", encoding="utf-8")

    app = PlatformApp()
    app.ingest(
        IngestRequest(source_type="file", locator=str(early_sample)),
        case_id="monitor-budget-quiet",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    ingest_result = app.ingest(
        IngestRequest(source_type="file", locator=str(late_sample)),
        case_id="monitor-budget-quiet",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    late_extract_queue = next(path for path in ingest_result.artifact_paths if "\\queues\\extract\\" in path or "/queues/extract/" in path)
    extract_result = app.extract(
        next(path for path in ingest_result.artifact_paths if path.endswith("source_manifest.json")),
        workspace_root=str(tmp_path),
    )
    app.recover(
        next(path for path in extract_result.artifact_paths if path.endswith("extract_report.json")),
        workspace_root=str(tmp_path),
    )
    Path(late_extract_queue).unlink()

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id="monitor-budget-quiet",
        max_jobs=1,
    )
    payload = runtime.run_once()

    assert payload["stage_budget_mode"] == "processing_drain"
    assert payload["queue_counts_before"]["extract"] == 1
    assert payload["queue_counts_before"]["normalize"] == 1
    assert payload["stage_budget_plan"]["normalize"] >= payload["stage_budget_plan"]["extract"]
    assert payload["queue_counts_after"]["extract"] == 1
    assert payload["queue_counts_after"]["normalize"] == 0
    assert payload["queue_counts_after"]["correlate"] == 1


def test_monitor_runtime_biases_budget_toward_early_stages_when_collection_is_hot(tmp_path) -> None:
    watched_log = tmp_path / "hot_watch.log"
    watched_log.write_text("line1\n", encoding="utf-8")
    late_sample = tmp_path / "late_backlog_hot.txt"
    late_sample.write_text("email=late@example.com https://example.com/hot", encoding="utf-8")

    app = PlatformApp()
    app.register_watch_source(
        IngestRequest(source_type="log", locator=str(watched_log)),
        case_id="monitor-budget-hot",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    ingest_result = app.ingest(
        IngestRequest(source_type="file", locator=str(late_sample)),
        case_id="monitor-budget-hot",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    late_extract_queue = next(path for path in ingest_result.artifact_paths if "\\queues\\extract\\" in path or "/queues/extract/" in path)
    extract_result = app.extract(
        next(path for path in ingest_result.artifact_paths if path.endswith("source_manifest.json")),
        workspace_root=str(tmp_path),
    )
    app.recover(
        next(path for path in extract_result.artifact_paths if path.endswith("extract_report.json")),
        workspace_root=str(tmp_path),
    )
    Path(late_extract_queue).unlink()

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id="monitor-budget-hot",
        max_jobs=1,
    )
    payload = runtime.run_once()

    assert payload["stage_budget_mode"] == "collection_hot"
    assert payload["source_checks"]["changed_count"] == 1
    assert payload["queue_counts_before"]["extract"] == 1
    assert payload["queue_counts_before"]["normalize"] == 1
    assert payload["stage_budget_plan"]["extract"] >= payload["stage_budget_plan"]["normalize"]
    assert payload["queue_counts_after"]["extract"] == 0
    assert payload["last_result"]["stage_results"][0]["stage"] == "extract"
    assert payload["last_result"]["stage_results"][0]["processed_job_count"] == 1
    assert payload["queue_counts_after"]["recover"] >= 1
    assert payload["queue_counts_after"]["normalize"] == 1


def test_monitor_runtime_uses_fairness_cycle_for_aged_late_stage_backlog(tmp_path) -> None:
    watched_log = tmp_path / "fairness_watch.log"
    watched_log.write_text("line1\n", encoding="utf-8")
    late_sample = tmp_path / "fairness_backlog.txt"
    late_sample.write_text("email=late@example.com https://example.com/fairness", encoding="utf-8")

    app = PlatformApp()
    app.register_watch_source(
        IngestRequest(source_type="log", locator=str(watched_log)),
        case_id="monitor-budget-fairness",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    ingest_result = app.ingest(
        IngestRequest(source_type="file", locator=str(late_sample)),
        case_id="monitor-budget-fairness",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    late_extract_queue = next(path for path in ingest_result.artifact_paths if "\\queues\\extract\\" in path or "/queues/extract/" in path)
    extract_result = app.extract(
        next(path for path in ingest_result.artifact_paths if path.endswith("source_manifest.json")),
        workspace_root=str(tmp_path),
    )
    recover_result = app.recover(
        next(path for path in extract_result.artifact_paths if path.endswith("extract_report.json")),
        workspace_root=str(tmp_path),
    )
    Path(late_extract_queue).unlink()
    normalize_queue = next(path for path in recover_result.artifact_paths if "\\queues\\normalize\\" in path or "/queues/normalize/" in path)
    _age_queue_payload(normalize_queue, seconds_old=QUEUE_AGE_SOFT_THRESHOLD_SECONDS * 2)

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id="monitor-budget-fairness",
        max_jobs=1,
    )
    seeded_status = runtime._default_status()
    seeded_status["hot_cycle_streak"] = HOT_FAIRNESS_TRIGGER_STREAK
    runtime.status_path.write_text(json.dumps(seeded_status, indent=2), encoding="utf-8")
    watched_log.write_text("line1\nline2\n", encoding="utf-8")

    payload = runtime.run_once()

    assert payload["stage_budget_mode"] == "collection_hot_fairness"
    assert payload["fairness_stage"] == "normalize"
    assert payload["queue_counts_before"]["extract"] == 1
    assert payload["queue_counts_before"]["normalize"] == 1
    assert payload["queue_stage_age_stats_before"]["normalize"]["aged_job_count_soft"] >= 1
    assert payload["queue_stage_age_stats_before"]["normalize"]["oldest_age_seconds"] >= QUEUE_AGE_SOFT_THRESHOLD_SECONDS
    assert payload["queue_counts_after"]["extract"] == 1
    assert payload["queue_counts_after"]["normalize"] == 0
    assert any(
        item["stage"] == "normalize" and item["processed_job_count"] == 1
        for item in payload["last_result"]["stage_results"]
    )


def test_monitor_runtime_recommends_case_and_watch_presets_for_noisy_scope(tmp_path) -> None:
    case_id = "monitor-automation-recommend"
    watched_log = tmp_path / "automation_watch.log"
    watched_log.write_text("line1\n", encoding="utf-8")

    app = PlatformApp()
    register_payload = app.register_watch_source(
        IngestRequest(source_type="log", locator=str(watched_log)),
        case_id=case_id,
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    watch_id = str(register_payload["watched_source"]["watch_id"])
    app.update_watch_source_settings(
        case_id=case_id,
        watch_id=watch_id,
        clear_tuning_profile=True,
        output_root=str(tmp_path / "out"),
    )
    for index in range(4):
        sample = tmp_path / f"automation_recommend_{index}.txt"
        sample.write_text(f"email=user{index}@example.com https://example.com/{index}", encoding="utf-8")
        app.ingest(
            IngestRequest(source_type="file", locator=str(sample)),
            case_id=case_id,
            output_root=str(tmp_path / "out"),
            workspace_root=str(tmp_path),
        )

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id=case_id,
        max_jobs=1,
    )
    _seed_collection_hot_history(runtime, case_id=case_id)

    payload = runtime.run_once()
    recommendations = list(payload["automation"]["recommendations"])

    assert payload["automation"]["mode"] == "recommend"
    assert payload["automation"]["summary"]["recommendation_count"] >= 2
    assert payload["automation"]["summary"]["applied_count"] == 0
    assert any(
        item["scope"] == "case"
        and item["recommended_preset_name"] == "collection_first"
        and item["safe_to_apply"] is True
        for item in recommendations
    )
    assert any(
        item["scope"] == "watch"
        and item["watch_id"] == watch_id
        and item["recommended_preset_name"] == "source:log"
        and item["action"] == "recommend"
        for item in recommendations
    )


def test_monitor_runtime_auto_applies_case_and_watch_presets_when_enabled(tmp_path) -> None:
    case_id = "monitor-automation-apply"
    watched_log = tmp_path / "automation_apply.log"
    watched_log.write_text("line1\n", encoding="utf-8")

    app = PlatformApp()
    register_payload = app.register_watch_source(
        IngestRequest(source_type="log", locator=str(watched_log)),
        case_id=case_id,
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    watch_id = str(register_payload["watched_source"]["watch_id"])
    app.update_watch_source_settings(
        case_id=case_id,
        watch_id=watch_id,
        clear_tuning_profile=True,
        output_root=str(tmp_path / "out"),
    )
    app.update_monitor_tuning(
        case_id=case_id,
        output_root=str(tmp_path / "out"),
        automation_mode="apply",
    )
    for index in range(4):
        sample = tmp_path / f"automation_apply_{index}.txt"
        sample.write_text(f"email=user{index}@example.com https://example.com/{index}", encoding="utf-8")
        app.ingest(
            IngestRequest(source_type="file", locator=str(sample)),
            case_id=case_id,
            output_root=str(tmp_path / "out"),
            workspace_root=str(tmp_path),
        )

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id=case_id,
        max_jobs=1,
    )
    _seed_collection_hot_history(runtime, case_id=case_id)

    payload = runtime.run_once()
    applied_actions = list(payload["automation"]["applied_actions"])
    tuning_payload = app.get_monitor_tuning(case_id=case_id, output_root=str(tmp_path / "out"))
    watch_payload = app.get_watch_source_detail(case_id=case_id, watch_id=watch_id, output_root=str(tmp_path / "out"))

    assert payload["automation"]["mode"] == "apply"
    assert payload["automation"]["summary"]["applied_count"] >= 2
    assert any(
        item["scope"] == "case"
        and item["recommended_preset_name"] == "collection_first"
        and item["action"] == "applied"
        for item in applied_actions
    )
    assert any(
        item["scope"] == "watch"
        and item["watch_id"] == watch_id
        and item["recommended_preset_name"] == "source:log"
        and item["action"] == "applied"
        for item in applied_actions
    )
    assert tuning_payload["tuning"]["preset_name"] == "collection_first"
    assert tuning_payload["tuning"]["automation_mode"] == "apply"
    assert watch_payload["watched_source"]["tuning_profile"]["preset_name"] == "source:log"


def test_monitor_runtime_recommends_case_rollback_after_sustained_calm(tmp_path) -> None:
    case_id = "monitor-automation-case-rollback"
    app = PlatformApp()
    app.update_monitor_tuning(
        case_id=case_id,
        output_root=str(tmp_path / "out"),
        preset_name="collection_first",
    )

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id=case_id,
        max_jobs=1,
    )
    _seed_calm_history(runtime, case_id=case_id, current_preset_name="collection_first")

    payload = runtime.run_once()
    recommendations = list(payload["automation"]["recommendations"])

    assert any(
        item["scope"] == "case"
        and item["recommended_preset_name"] == "balanced"
        and item["current_preset_name"] == "collection_first"
        and item["action"] == "recommend"
        for item in recommendations
    )


def test_monitor_runtime_auto_applies_case_and_watch_rollbacks_after_calm(tmp_path) -> None:
    case_id = "monitor-automation-rollback-apply"
    watched_log = tmp_path / "automation_rollback.log"
    watched_log.write_text("line1\n", encoding="utf-8")

    app = PlatformApp()
    register_payload = app.register_watch_source(
        IngestRequest(source_type="log", locator=str(watched_log)),
        case_id=case_id,
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
        poll_interval_seconds=0.0,
    )
    watch_id = str(register_payload["watched_source"]["watch_id"])
    app.update_watch_source_settings(
        case_id=case_id,
        watch_id=watch_id,
        tuning_preset_name="source:log",
        output_root=str(tmp_path / "out"),
    )
    app.update_monitor_tuning(
        case_id=case_id,
        output_root=str(tmp_path / "out"),
        preset_name="collection_first",
        automation_mode="apply",
    )

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id=case_id,
        max_jobs=1,
    )
    _seed_calm_history(runtime, case_id=case_id, current_preset_name="collection_first")

    payload = {}
    all_applied_actions: list[dict[str, object]] = []
    for _ in range(4):
        payload = runtime.run_once()
        all_applied_actions.extend(list(payload["automation"]["applied_actions"]))
    tuning_payload = app.get_monitor_tuning(case_id=case_id, output_root=str(tmp_path / "out"))
    watch_payload = app.get_watch_source_detail(case_id=case_id, watch_id=watch_id, output_root=str(tmp_path / "out"))

    assert any(
        item["scope"] == "case"
        and item["recommended_preset_name"] == "balanced"
        and item["action"] == "applied"
        for item in all_applied_actions
    )
    assert any(
        item["scope"] == "watch"
        and item["watch_id"] == watch_id
        and item["recommended_preset_name"] == "source:default"
        and item["action"] == "applied"
        for item in all_applied_actions
    )
    assert tuning_payload["tuning"]["preset_name"] == "balanced"
    assert tuning_payload["tuning"]["automation_mode"] == "apply"
    assert watch_payload["watched_source"]["tuning_profile"]["preset_name"] == "source:default"


def test_monitor_runtime_marks_already_applied_for_automation_presets(tmp_path) -> None:
    case_id = "monitor-automation-already-applied"
    watched_log = tmp_path / "automation_already_applied.log"
    watched_log.write_text("line1\n", encoding="utf-8")

    app = PlatformApp()
    register_payload = app.register_watch_source(
        IngestRequest(source_type="log", locator=str(watched_log)),
        case_id=case_id,
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
        poll_interval_seconds=0.0,
    )
    watch_id = str(register_payload["watched_source"]["watch_id"])
    app.update_watch_source_settings(
        case_id=case_id,
        watch_id=watch_id,
        clear_tuning_profile=True,
        output_root=str(tmp_path / "out"),
    )
    app.update_watch_source_settings(
        case_id=case_id,
        watch_id=watch_id,
        tuning_preset_name="source:log",
        change_origin="automation",
        automation_direction="escalate",
        automation_reason="test setup",
        output_root=str(tmp_path / "out"),
    )
    app.update_monitor_tuning(
        case_id=case_id,
        output_root=str(tmp_path / "out"),
        preset_name="collection_first",
        change_origin="automation",
        automation_direction="escalate",
        automation_reason="test setup",
    )
    for index in range(4):
        sample = tmp_path / f"automation_already_applied_{index}.txt"
        sample.write_text(f"email=user{index}@example.com https://example.com/{index}", encoding="utf-8")
        app.ingest(
            IngestRequest(source_type="file", locator=str(sample)),
            case_id=case_id,
            output_root=str(tmp_path / "out"),
            workspace_root=str(tmp_path),
        )
    watched_log.write_text("line1\nline2\n", encoding="utf-8")

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id=case_id,
        max_jobs=1,
    )
    _seed_collection_hot_history(runtime, case_id=case_id)

    payload = runtime.run_once()
    recommendations = list(payload["automation"]["recommendations"])

    assert payload["automation"]["summary"]["already_count"] >= 2
    assert any(
        item["scope"] == "case"
        and item["recommended_preset_name"] == "collection_first"
        and item["action"] == "already_applied"
        for item in recommendations
    )
    assert any(
        item["scope"] == "watch"
        and item["watch_id"] == watch_id
        and item["recommended_preset_name"] == "source:log"
        and item["action"] == "already_applied"
        for item in recommendations
    )


def test_monitor_runtime_marks_already_rolled_back_for_automation_rollbacks(tmp_path) -> None:
    case_id = "monitor-automation-already-rolled-back"
    watched_log = tmp_path / "automation_already_rolled_back.log"
    watched_log.write_text("line1\n", encoding="utf-8")

    app = PlatformApp()
    register_payload = app.register_watch_source(
        IngestRequest(source_type="log", locator=str(watched_log)),
        case_id=case_id,
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
        poll_interval_seconds=0.0,
    )
    watch_id = str(register_payload["watched_source"]["watch_id"])
    app.update_watch_source_settings(
        case_id=case_id,
        watch_id=watch_id,
        tuning_preset_name="source:log",
        output_root=str(tmp_path / "out"),
    )
    app.update_watch_source_settings(
        case_id=case_id,
        watch_id=watch_id,
        tuning_preset_name="source:default",
        change_origin="automation",
        automation_direction="rollback",
        automation_reason="test setup",
        output_root=str(tmp_path / "out"),
    )
    app.update_monitor_tuning(
        case_id=case_id,
        output_root=str(tmp_path / "out"),
        preset_name="collection_first",
    )
    app.update_monitor_tuning(
        case_id=case_id,
        output_root=str(tmp_path / "out"),
        preset_name="balanced",
        change_origin="automation",
        automation_direction="rollback",
        automation_reason="test setup",
    )

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id=case_id,
        max_jobs=1,
    )
    _seed_calm_history(runtime, case_id=case_id, current_preset_name="balanced")

    all_recommendations: list[dict[str, object]] = []
    for _ in range(4):
        payload = runtime.run_once()
        all_recommendations.extend(list(payload["automation"]["recommendations"]))

    assert any(
        item["scope"] == "case"
        and item["recommended_preset_name"] == "balanced"
        and item["action"] == "already_rolled_back"
        for item in all_recommendations
    )
    assert any(
        item["scope"] == "watch"
        and item["watch_id"] == watch_id
        and item["recommended_preset_name"] == "source:default"
        and item["action"] == "already_rolled_back"
        for item in all_recommendations
    )


def test_monitor_runtime_respects_manual_case_and_watch_preset_overrides(tmp_path) -> None:
    case_id = "monitor-automation-manual-override"
    watched_log = tmp_path / "automation_manual_override.log"
    watched_log.write_text("line1\n", encoding="utf-8")

    app = PlatformApp()
    register_payload = app.register_watch_source(
        IngestRequest(source_type="log", locator=str(watched_log)),
        case_id=case_id,
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
        poll_interval_seconds=0.0,
    )
    watch_id = str(register_payload["watched_source"]["watch_id"])
    app.update_watch_source_settings(
        case_id=case_id,
        watch_id=watch_id,
        clear_tuning_profile=True,
        output_root=str(tmp_path / "out"),
    )
    app.update_watch_source_settings(
        case_id=case_id,
        watch_id=watch_id,
        tuning_preset_name="source:log",
        change_origin="automation",
        automation_direction="escalate",
        automation_reason="test setup",
        output_root=str(tmp_path / "out"),
    )
    app.update_watch_source_settings(
        case_id=case_id,
        watch_id=watch_id,
        tuning_preset_name="source:pcap",
        output_root=str(tmp_path / "out"),
    )
    app.update_monitor_tuning(
        case_id=case_id,
        output_root=str(tmp_path / "out"),
        preset_name="collection_first",
        change_origin="automation",
        automation_direction="escalate",
        automation_reason="test setup",
    )
    app.update_monitor_tuning(
        case_id=case_id,
        output_root=str(tmp_path / "out"),
        preset_name="balanced",
    )
    for index in range(4):
        sample = tmp_path / f"automation_manual_override_{index}.txt"
        sample.write_text(f"email=user{index}@example.com https://example.com/{index}", encoding="utf-8")
        app.ingest(
            IngestRequest(source_type="file", locator=str(sample)),
            case_id=case_id,
            output_root=str(tmp_path / "out"),
            workspace_root=str(tmp_path),
        )
    watched_log.write_text("line1\nline2\n", encoding="utf-8")

    runtime = MonitorRuntime(
        app=app,
        output_root=tmp_path / "out",
        workspace_root=tmp_path,
        case_id=case_id,
        max_jobs=1,
    )
    _seed_collection_hot_history(runtime, case_id=case_id)

    payload = runtime.run_once()
    recommendations = list(payload["automation"]["recommendations"])

    assert payload["automation"]["summary"]["manual_override_count"] >= 2
    assert any(
        item["scope"] == "case"
        and item["current_preset_name"] == "balanced"
        and item["recommended_preset_name"] == "collection_first"
        and item["action"] == "manual_override"
        for item in recommendations
    )
    assert any(
        item["scope"] == "watch"
        and item["watch_id"] == watch_id
        and item["current_preset_name"] == "source:pcap"
        and item["recommended_preset_name"] == "source:log"
        and item["action"] == "manual_override"
        for item in recommendations
    )
