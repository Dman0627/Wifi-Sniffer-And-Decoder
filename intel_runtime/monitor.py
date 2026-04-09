from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from intel_api.app import QUEUE_STAGE_ORDER, PlatformApp
from intel_core import IngestRequest, PluginResult, stable_record_id, utc_now
from intel_storage import DEFAULT_DATABASE_NAME, SQLiteIntelligenceStore, ensure_workspace_layout
from .tuning import (
    DEFAULT_ALERT_SEVERITY,
    DEFAULT_AUTOMATION_MODE,
    DEFAULT_FORECAST_MIN_HISTORY,
    DEFAULT_MONITOR_TUNING_PRESET,
    DEFAULT_QUEUE_SPIKE_FACTOR,
    DEFAULT_SOURCE_CHURN_SPIKE_FACTOR,
    DEFAULT_THROUGHPUT_DROP_FACTOR,
    DEFAULT_WATCH_TUNING_PRESET,
    VALID_AUTOMATION_MODES,
    apply_monitor_tuning_preset,
    apply_watch_tuning_preset,
    normalize_preset_automation_state,
    load_monitor_tuning,
    normalize_monitor_tuning,
    normalize_watch_tuning_profile,
    watch_tuning_preset_name_for_source_type,
)

DEFAULT_MONITOR_STATUS_NAME = "monitor_status.json"
DEFAULT_MONITOR_HISTORY_NAME = "monitor_history.jsonl"
FORECAST_LOOKBACK_CYCLES = 8
QUEUE_AGE_SOFT_THRESHOLD_SECONDS = 120
QUEUE_AGE_HARD_THRESHOLD_SECONDS = 600
HOT_FAIRNESS_TRIGGER_STREAK = 2
BURST_POLL_INTERVAL_FACTOR = 0.25
BURST_CHANGE_STREAK_THRESHOLD = 2
HOT_POLL_INTERVAL_FACTOR = 0.5
IDLE_POLL_BACKOFF_FACTORS = (
    (6, 4.0),
    (3, 2.0),
)
BURST_POLL_LOOKBACK_MIN_SECONDS = 120
HOT_POLL_LOOKBACK_MIN_SECONDS = 60
AUTOMATION_MIN_HOT_STREAK = 2
AUTOMATION_MIN_CALM_CYCLES = 3
AUTOMATION_CALM_QUEUE_THRESHOLD = 1
AUTOMATION_CALM_CHANGED_THRESHOLD = 1
AUTOMATION_ACTIVE_PRIORITY_LABELS = {"urgent", "high"}
AUTOMATION_ACTIVE_POLL_MODES = {"burst", "hot"}


def _normalize_automation_mode(value: object) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in VALID_AUTOMATION_MODES:
        return normalized
    return DEFAULT_AUTOMATION_MODE


def _default_monitor_automation(*, mode: str = DEFAULT_AUTOMATION_MODE) -> dict[str, object]:
    normalized_mode = _normalize_automation_mode(mode)
    return {
        "enabled": normalized_mode != "off",
        "mode": normalized_mode,
        "evaluated_at": "",
        "recommendations": [],
        "applied_actions": [],
        "summary": {
            "recommendation_count": 0,
            "active_recommendation_count": 0,
            "case_recommendation_count": 0,
            "watch_recommendation_count": 0,
            "safe_to_apply_count": 0,
            "applied_count": 0,
            "case_applied_count": 0,
            "watch_applied_count": 0,
            "already_count": 0,
            "manual_override_count": 0,
        },
    }


def _normalize_monitor_automation_snapshot(payload: dict[str, object] | None, *, mode: str) -> dict[str, object]:
    source = dict(payload or {})
    normalized = _default_monitor_automation(mode=mode)
    recommendations = [dict(item) for item in list(source.get("recommendations") or []) if isinstance(item, dict)]
    applied_actions = [dict(item) for item in list(source.get("applied_actions") or []) if isinstance(item, dict)]
    case_recommendation_count = sum(1 for item in recommendations if str(item.get("scope") or "") == "case")
    watch_recommendation_count = sum(1 for item in recommendations if str(item.get("scope") or "") == "watch")
    case_applied_count = sum(1 for item in applied_actions if str(item.get("scope") or "") == "case")
    watch_applied_count = sum(1 for item in applied_actions if str(item.get("scope") or "") == "watch")
    safe_to_apply_count = sum(1 for item in recommendations if bool(item.get("safe_to_apply")))
    active_recommendation_count = sum(1 for item in recommendations if str(item.get("action") or "recommend") == "recommend")
    already_count = sum(
        1
        for item in recommendations
        if str(item.get("action") or "") in {"already_applied", "already_rolled_back"}
    )
    manual_override_count = sum(1 for item in recommendations if str(item.get("action") or "") == "manual_override")
    return {
        **normalized,
        "evaluated_at": str(source.get("evaluated_at") or ""),
        "recommendations": recommendations,
        "applied_actions": applied_actions,
        "summary": {
            "recommendation_count": len(recommendations),
            "active_recommendation_count": active_recommendation_count,
            "case_recommendation_count": case_recommendation_count,
            "watch_recommendation_count": watch_recommendation_count,
            "safe_to_apply_count": safe_to_apply_count,
            "applied_count": len(applied_actions),
            "case_applied_count": case_applied_count,
            "watch_applied_count": watch_applied_count,
            "already_count": already_count,
            "manual_override_count": manual_override_count,
        },
    }


def _monitor_tuning_matches_preset_defaults(tuning: dict[str, object]) -> bool:
    payload = normalize_monitor_tuning(dict(tuning or {}), case_id=str(tuning.get("case_id") or ""))
    preset_name = str(payload.get("preset_name") or DEFAULT_MONITOR_TUNING_PRESET)
    preset_defaults = apply_monitor_tuning_preset(preset_name, case_id=str(payload.get("case_id") or ""))
    return (
        int(payload.get("forecast_min_history") or 0) == int(preset_defaults.get("forecast_min_history") or 0)
        and float(payload.get("queue_spike_factor") or 0.0) == float(preset_defaults.get("queue_spike_factor") or 0.0)
        and float(payload.get("source_churn_spike_factor") or 0.0)
        == float(preset_defaults.get("source_churn_spike_factor") or 0.0)
        and float(payload.get("throughput_drop_factor") or 0.0)
        == float(preset_defaults.get("throughput_drop_factor") or 0.0)
    )


def _monitor_tuning_is_auto_apply_safe(tuning: dict[str, object]) -> bool:
    payload = normalize_monitor_tuning(dict(tuning or {}), case_id=str(tuning.get("case_id") or ""))
    return bool(
        not list(payload.get("suppressed_alert_ids") or [])
        and not dict(payload.get("suppressed_stage_alerts") or {})
        and not dict(payload.get("suppressed_watch_alerts") or {})
        and not dict(payload.get("alert_severity_overrides") or {})
        and not dict(payload.get("stage_threshold_overrides") or {})
        and _monitor_tuning_matches_preset_defaults(payload)
    )


def _watch_profile_is_auto_apply_safe(profile: dict[str, object]) -> bool:
    payload = normalize_watch_tuning_profile(dict(profile or {}))
    preset_name = str(payload.get("preset_name") or "")
    effective_preset_name = preset_name or DEFAULT_WATCH_TUNING_PRESET
    preset_defaults = apply_watch_tuning_preset(effective_preset_name)
    return bool(
        int(payload.get("forecast_min_history") or 0) == int(preset_defaults.get("forecast_min_history") or 0)
        and float(payload.get("source_churn_spike_factor") or 0.0)
        == float(preset_defaults.get("source_churn_spike_factor") or 0.0)
        and list(payload.get("suppressed_alert_ids") or []) == list(preset_defaults.get("suppressed_alert_ids") or [])
    )


def _is_calm_history_row(row: dict[str, object]) -> bool:
    payload = dict(row or {})
    return bool(
        int(payload.get("queue_total_before") or 0) <= AUTOMATION_CALM_QUEUE_THRESHOLD
        and int(payload.get("queue_total_after") or 0) <= AUTOMATION_CALM_QUEUE_THRESHOLD
        and int(payload.get("changed_count") or 0) <= AUTOMATION_CALM_CHANGED_THRESHOLD
        and int(payload.get("failed_job_count") or 0) == 0
        and int(payload.get("failed_check_count") or 0) == 0
        and int(payload.get("hot_source_count") or 0) <= AUTOMATION_CALM_CHANGED_THRESHOLD
    )


def _trailing_calm_cycle_count(rows: list[dict[str, object]] | tuple[dict[str, object], ...]) -> int:
    count = 0
    for row in reversed([dict(item) for item in rows if isinstance(item, dict)]):
        if not _is_calm_history_row(row):
            break
        count += 1
    return count


def build_monitor_forecast(
    history: list[dict[str, object]] | tuple[dict[str, object], ...],
    *,
    tuning: dict[str, object] | None = None,
    status: dict[str, object] | None = None,
) -> dict[str, object]:
    rows = [dict(item) for item in history if isinstance(item, dict)]
    rows.sort(
        key=lambda item: (
            str(item.get("last_heartbeat_at") or item.get("recorded_at") or ""),
            int(item.get("cycle_count") or 0),
        )
    )
    recent = rows[-FORECAST_LOOKBACK_CYCLES:]
    if not recent:
        return _default_monitor_forecast()

    tuning_map = _normalized_forecast_tuning(tuning)
    status_map = dict(status or {})
    latest = recent[-1]
    history_count = len(recent)
    avg_queue_total_before = _average_metric(recent, "queue_total_before")
    avg_queue_total_after = _average_metric(recent, "queue_total_after")
    avg_processed_job_count = _average_metric(recent, "processed_job_count")
    avg_completed_job_count = _average_metric(recent, "completed_job_count")
    avg_changed_count = _average_metric(recent, "changed_count")
    avg_failed_job_count = _average_metric(recent, "failed_job_count")
    avg_executed_check_count = _average_metric(recent, "executed_check_count")

    intake_deltas: list[float] = []
    for previous, current in zip(recent, recent[1:]):
        intake_deltas.append(float(int(current.get("queue_total_before") or 0) - int(previous.get("queue_total_after") or 0)))
    avg_intake_delta = (sum(intake_deltas) / len(intake_deltas)) if intake_deltas else 0.0

    latest_queue_total_before = int(latest.get("queue_total_before") or 0)
    latest_queue_total_after = int(latest.get("queue_total_after") or 0)
    latest_processed_job_count = int(latest.get("processed_job_count") or 0)
    latest_completed_job_count = int(latest.get("completed_job_count") or 0)
    latest_changed_count = int(latest.get("changed_count") or 0)
    latest_failed_job_count = int(latest.get("failed_job_count") or 0)
    latest_failed_check_count = int(latest.get("failed_check_count") or 0)

    predicted_next_queue_total_before = max(0, int(round(latest_queue_total_after + avg_intake_delta)))
    drain_capacity = max(0.0, avg_completed_job_count or avg_processed_job_count)
    predicted_backlog_drain_cycles = 0
    if latest_queue_total_after > 0 and drain_capacity > 0.0:
        drain_units = max(1, int(round(drain_capacity)))
        predicted_backlog_drain_cycles = max(1, (latest_queue_total_after + drain_units - 1) // drain_units)

    alerts: list[dict[str, object]] = []
    suppressed_alerts: list[dict[str, object]] = []
    dominant_stage = _dominant_stage(dict(status_map.get("queue_counts_before") or {}))
    changed_watch_ids = _active_watch_ids(status_map, only_failures=False)
    failed_watch_ids = _active_watch_ids(status_map, only_failures=True)
    watch_profiles = _watch_profile_map(status_map)
    min_history = int(tuning_map.get("forecast_min_history") or DEFAULT_FORECAST_MIN_HISTORY)
    stage_threshold_tuning = _effective_stage_threshold_tuning(
        tuning_map=tuning_map,
        stage=dominant_stage,
    )
    if history_count >= min_history and latest_queue_total_before >= max(
        5.0,
        avg_queue_total_before
        * float(stage_threshold_tuning.get("queue_spike_factor") or DEFAULT_QUEUE_SPIKE_FACTOR),
    ):
        _append_forecast_alert(
            alerts,
            suppressed_alerts,
            tuning_map=tuning_map,
            alert={
                "id": "queue_pressure_spike",
                "severity": _alert_severity("queue_pressure_spike", tuning_map=tuning_map),
                "title": "Queue pressure spike",
                "message": (
                    f"Latest queue pressure is {latest_queue_total_before}, above the recent average of "
                    f"{avg_queue_total_before:.1f}."
                ),
            },
            stages=(dominant_stage,) if dominant_stage else (),
        )
    source_churn_tuning = _effective_source_churn_tuning(
        tuning_map=tuning_map,
        watch_profiles=watch_profiles,
        watch_ids=changed_watch_ids,
    )
    if history_count >= int(source_churn_tuning.get("forecast_min_history") or min_history) and latest_changed_count >= max(
        3.0,
        avg_changed_count
        * float(source_churn_tuning.get("source_churn_spike_factor") or DEFAULT_SOURCE_CHURN_SPIKE_FACTOR),
    ):
        _append_forecast_alert(
            alerts,
            suppressed_alerts,
            tuning_map=tuning_map,
            alert={
                "id": "source_churn_spike",
                "severity": _alert_severity("source_churn_spike", tuning_map=tuning_map),
                "title": "Source churn spike",
                "message": (
                    f"Changed watched sources jumped to {latest_changed_count}, above the recent average of "
                    f"{avg_changed_count:.1f}."
                ),
            },
            watch_ids=changed_watch_ids,
            watch_profiles=watch_profiles,
        )
    if (
        history_count >= min_history
        and latest_queue_total_before > max(2.0, avg_queue_total_before)
        and latest_processed_job_count
        <= max(
            1.0,
            avg_processed_job_count
            * float(stage_threshold_tuning.get("throughput_drop_factor") or DEFAULT_THROUGHPUT_DROP_FACTOR),
        )
    ):
        _append_forecast_alert(
            alerts,
            suppressed_alerts,
            tuning_map=tuning_map,
            alert={
                "id": "throughput_drop",
                "severity": _alert_severity("throughput_drop", tuning_map=tuning_map),
                "title": "Processing throughput dropped",
                "message": (
                    f"Processed jobs fell to {latest_processed_job_count} while queue pressure is still {latest_queue_total_before}."
                ),
            },
            stages=(dominant_stage,) if dominant_stage else (),
        )
    if latest_failed_job_count > 0 or latest_failed_check_count > 0:
        _append_forecast_alert(
            alerts,
            suppressed_alerts,
            tuning_map=tuning_map,
            alert={
                "id": "failure_burst",
                "severity": _alert_severity("failure_burst", tuning_map=tuning_map),
                "title": "Failures detected in the latest cycle",
                "message": (
                    f"Latest cycle recorded {latest_failed_job_count} failed jobs and {latest_failed_check_count} failed source checks."
                ),
            },
            stages=tuple(_failed_stages(status_map)),
            watch_ids=failed_watch_ids,
            watch_profiles=watch_profiles,
        )

    return {
        "summary": {
            "history_count": history_count,
            "avg_queue_total_before": avg_queue_total_before,
            "avg_queue_total_after": avg_queue_total_after,
            "avg_processed_job_count": avg_processed_job_count,
            "avg_completed_job_count": avg_completed_job_count,
            "avg_changed_count": avg_changed_count,
            "avg_failed_job_count": avg_failed_job_count,
            "avg_executed_check_count": avg_executed_check_count,
            "avg_intake_delta": avg_intake_delta,
            "predicted_next_queue_total_before": predicted_next_queue_total_before,
            "predicted_backlog_drain_cycles": predicted_backlog_drain_cycles,
            "queue_pressure_state": _forecast_state(latest_queue_total_before, avg_queue_total_before),
            "throughput_state": _forecast_state(latest_processed_job_count, avg_processed_job_count),
            "alert_count": len(alerts),
            "suppressed_alert_count": len(suppressed_alerts),
            "highest_alert_severity": _highest_alert_severity(alerts),
            "active_watch_profile_count": sum(
                1
                for watch_id in changed_watch_ids
                if _watch_profile_has_overrides(watch_profiles.get(watch_id, {}))
            ),
            "dominant_stage": dominant_stage,
            "active_stage_override_count": sum(
                1
                for value in dict(tuning_map.get("stage_threshold_overrides") or {}).values()
                if isinstance(value, dict) and value
            ),
            "active_alert_severity_override_count": len(dict(tuning_map.get("alert_severity_overrides") or {})),
            "effective_source_churn_forecast_min_history": int(
                source_churn_tuning.get("forecast_min_history") or min_history
            ),
            "effective_source_churn_spike_factor": float(
                source_churn_tuning.get("source_churn_spike_factor") or DEFAULT_SOURCE_CHURN_SPIKE_FACTOR
            ),
            "effective_queue_spike_factor": float(
                stage_threshold_tuning.get("queue_spike_factor") or DEFAULT_QUEUE_SPIKE_FACTOR
            ),
            "effective_throughput_drop_factor": float(
                stage_threshold_tuning.get("throughput_drop_factor") or DEFAULT_THROUGHPUT_DROP_FACTOR
            ),
        },
        "alerts": alerts,
        "suppressed_alerts": suppressed_alerts,
        "tuning": tuning_map,
    }


def _default_monitor_forecast() -> dict[str, object]:
    return {
        "summary": {
            "history_count": 0,
            "avg_queue_total_before": 0.0,
            "avg_queue_total_after": 0.0,
            "avg_processed_job_count": 0.0,
            "avg_completed_job_count": 0.0,
            "avg_changed_count": 0.0,
            "avg_failed_job_count": 0.0,
            "avg_executed_check_count": 0.0,
            "avg_intake_delta": 0.0,
            "predicted_next_queue_total_before": 0,
            "predicted_backlog_drain_cycles": 0,
            "queue_pressure_state": "steady",
            "throughput_state": "steady",
            "alert_count": 0,
            "suppressed_alert_count": 0,
            "highest_alert_severity": "none",
            "active_watch_profile_count": 0,
            "dominant_stage": "",
            "active_stage_override_count": 0,
            "active_alert_severity_override_count": 0,
            "effective_source_churn_forecast_min_history": DEFAULT_FORECAST_MIN_HISTORY,
            "effective_source_churn_spike_factor": DEFAULT_SOURCE_CHURN_SPIKE_FACTOR,
            "effective_queue_spike_factor": DEFAULT_QUEUE_SPIKE_FACTOR,
            "effective_throughput_drop_factor": DEFAULT_THROUGHPUT_DROP_FACTOR,
        },
        "alerts": [],
        "suppressed_alerts": [],
        "tuning": _normalized_forecast_tuning(None),
    }


def _average_metric(rows: list[dict[str, object]], key: str) -> float:
    if not rows:
        return 0.0
    return float(sum(float(item.get(key) or 0.0) for item in rows) / len(rows))


def _forecast_state(latest_value: int, average_value: float) -> str:
    if average_value <= 0.0:
        return "steady" if latest_value <= 0 else "rising"
    if latest_value >= average_value * 1.5:
        return "rising"
    if latest_value <= average_value * 0.5:
        return "falling"
    return "steady"


def _highest_alert_severity(alerts: list[dict[str, object]]) -> str:
    if not alerts:
        return "none"
    severities = [str(item.get("severity") or "").strip().lower() for item in alerts]
    if "critical" in severities:
        return "critical"
    if "warning" in severities:
        return "warning"
    if "info" in severities:
        return "info"
    return "none"


def _normalized_forecast_tuning(tuning: dict[str, object] | None) -> dict[str, object]:
    return normalize_monitor_tuning(dict(tuning or {}), case_id=str(dict(tuning or {}).get("case_id") or ""))


def _alert_severity(alert_id: str, *, tuning_map: dict[str, object]) -> str:
    if not alert_id:
        return DEFAULT_ALERT_SEVERITY
    value = str(dict(tuning_map.get("alert_severity_overrides") or {}).get(alert_id) or "").strip().lower()
    if value in {"info", "warning", "critical"}:
        return value
    return DEFAULT_ALERT_SEVERITY


def _append_forecast_alert(
    alerts: list[dict[str, object]],
    suppressed_alerts: list[dict[str, object]],
    *,
    tuning_map: dict[str, object],
    alert: dict[str, object],
    stages: tuple[str, ...] = (),
    watch_ids: tuple[str, ...] = (),
    watch_profiles: dict[str, dict[str, object]] | None = None,
) -> None:
    suppressed, reason = _forecast_alert_suppressed(
        str(alert.get("id") or ""),
        tuning_map=tuning_map,
        stages=stages,
        watch_ids=watch_ids,
        watch_profiles=dict(watch_profiles or {}),
    )
    payload = {
        **alert,
        "stages": [stage for stage in stages if stage],
        "watch_ids": [watch_id for watch_id in watch_ids if watch_id],
    }
    if suppressed:
        suppressed_alerts.append({**payload, "suppression_reason": reason})
    else:
        alerts.append(payload)


def _forecast_alert_suppressed(
    alert_id: str,
    *,
    tuning_map: dict[str, object],
    stages: tuple[str, ...],
    watch_ids: tuple[str, ...],
    watch_profiles: dict[str, dict[str, object]],
) -> tuple[bool, str]:
    if not alert_id:
        return False, ""
    global_alerts = set(str(item).strip() for item in list(tuning_map.get("suppressed_alert_ids") or []) if str(item).strip())
    if alert_id in global_alerts:
        return True, "global alert suppression"

    stage_map = {
        str(key).strip(): set(str(item).strip() for item in list(values or []) if str(item).strip())
        for key, values in dict(tuning_map.get("suppressed_stage_alerts") or {}).items()
        if str(key).strip()
    }
    for stage in stages:
        normalized_stage = str(stage or "").strip()
        if normalized_stage and alert_id in stage_map.get(normalized_stage, set()):
            return True, f"stage suppression:{normalized_stage}"

    watch_map = {
        str(key).strip(): set(str(item).strip() for item in list(values or []) if str(item).strip())
        for key, values in dict(tuning_map.get("suppressed_watch_alerts") or {}).items()
        if str(key).strip()
    }
    normalized_watch_ids = [str(item).strip() for item in watch_ids if str(item).strip()]
    if normalized_watch_ids:
        combined_watch_suppressions = {
            watch_id: set(watch_map.get(watch_id, set()))
            | set(
                str(item).strip()
                for item in list(
                    normalize_watch_tuning_profile(dict(watch_profiles.get(watch_id) or {})).get("suppressed_alert_ids") or []
                )
                if str(item).strip()
            )
            for watch_id in normalized_watch_ids
        }
        if all(alert_id in combined_watch_suppressions.get(watch_id, set()) for watch_id in normalized_watch_ids):
            if any(alert_id in watch_map.get(watch_id, set()) for watch_id in normalized_watch_ids):
                return True, f"watch suppression:{','.join(normalized_watch_ids)}"
            return True, f"watch profile suppression:{','.join(normalized_watch_ids)}"

    return False, ""


def _watch_profile_map(status: dict[str, object]) -> dict[str, dict[str, object]]:
    rows: dict[str, dict[str, object]] = {}
    source_checks = dict(status.get("source_checks") or {})
    for item in list(source_checks.get("results") or []):
        if not isinstance(item, dict):
            continue
        watch_id = str(item.get("watch_id") or "").strip()
        if not watch_id:
            continue
        rows[watch_id] = normalize_watch_tuning_profile(dict(item.get("tuning_profile") or {}))
    for watch_id, payload in dict(status.get("watch_tuning_profiles") or {}).items():
        normalized_watch_id = str(watch_id or "").strip()
        if not normalized_watch_id:
            continue
        rows[normalized_watch_id] = normalize_watch_tuning_profile(dict(payload or {}))
    return rows


def _watch_profile_has_overrides(profile: dict[str, object]) -> bool:
    payload = normalize_watch_tuning_profile(dict(profile or {}))
    return bool(
        int(payload.get("forecast_min_history") or 0) > 0
        or float(payload.get("source_churn_spike_factor") or 0.0) > 0.0
        or list(payload.get("suppressed_alert_ids") or [])
    )


def _effective_source_churn_tuning(
    *,
    tuning_map: dict[str, object],
    watch_profiles: dict[str, dict[str, object]],
    watch_ids: tuple[str, ...],
) -> dict[str, object]:
    min_history = int(tuning_map.get("forecast_min_history") or DEFAULT_FORECAST_MIN_HISTORY)
    source_churn_spike_factor = float(
        tuning_map.get("source_churn_spike_factor") or DEFAULT_SOURCE_CHURN_SPIKE_FACTOR
    )
    for watch_id in watch_ids:
        profile = normalize_watch_tuning_profile(dict(watch_profiles.get(watch_id) or {}))
        min_history = max(min_history, int(profile.get("forecast_min_history") or 0))
        source_churn_spike_factor = max(
            source_churn_spike_factor,
            float(profile.get("source_churn_spike_factor") or 0.0),
        )
    return {
        "forecast_min_history": min_history,
        "source_churn_spike_factor": source_churn_spike_factor,
    }


def _effective_stage_threshold_tuning(
    *,
    tuning_map: dict[str, object],
    stage: str,
) -> dict[str, float]:
    normalized_stage = str(stage or "").strip()
    stage_overrides = dict(tuning_map.get("stage_threshold_overrides") or {})
    override = dict(stage_overrides.get(normalized_stage) or {})
    return {
        "queue_spike_factor": float(override.get("queue_spike_factor") or tuning_map.get("queue_spike_factor") or DEFAULT_QUEUE_SPIKE_FACTOR),
        "throughput_drop_factor": float(
            override.get("throughput_drop_factor")
            or tuning_map.get("throughput_drop_factor")
            or DEFAULT_THROUGHPUT_DROP_FACTOR
        ),
    }


def _dominant_stage(queue_counts: dict[str, object]) -> str:
    dominant = ""
    highest = 0
    for stage, value in dict(queue_counts or {}).items():
        count = int(value or 0)
        if count > highest:
            highest = count
            dominant = str(stage or "")
    return dominant


def _active_watch_ids(status: dict[str, object], *, only_failures: bool) -> tuple[str, ...]:
    source_checks = dict(status.get("source_checks") or {})
    rows = [dict(item) for item in list(source_checks.get("results") or []) if isinstance(item, dict)]
    watch_ids: list[str] = []
    for row in rows:
        watch_id = str(row.get("watch_id") or "").strip()
        if not watch_id:
            continue
        if only_failures:
            if bool(row.get("ok", True)):
                continue
        else:
            if not bool(row.get("changed")) and str(row.get("priority_label") or "") not in {"urgent", "high"}:
                continue
        if watch_id not in watch_ids:
            watch_ids.append(watch_id)
    return tuple(watch_ids)


def _failed_stages(status: dict[str, object]) -> tuple[str, ...]:
    last_result = dict(status.get("last_result") or {})
    stages: list[str] = []
    for row in list(last_result.get("stage_results") or []):
        if not isinstance(row, dict):
            continue
        stage = str(row.get("stage") or "").strip()
        if not stage:
            continue
        if int(row.get("failed_job_count") or 0) > 0 and stage not in stages:
            stages.append(stage)
    return tuple(stages)


@dataclass(slots=True)
class MonitorRuntime:
    app: PlatformApp = field(default_factory=PlatformApp)
    output_root: Path = field(default_factory=lambda: Path("./pipeline_output/platform").resolve())
    workspace_root: Path = field(default_factory=lambda: Path(".").resolve())
    database_path: str | None = None
    case_id: str = ""
    stages: tuple[str, ...] = field(default_factory=tuple)
    max_jobs: int = 0
    poll_interval: float = 5.0
    cleanup_completed_days: float = 0.0
    cleanup_failed_days: float = 0.0
    cleanup_watch_delta_days: float = 0.0

    def __post_init__(self) -> None:
        self.output_root = Path(self.output_root).resolve()
        self.workspace_root = Path(self.workspace_root).resolve()
        self.database_path = str(self.database_path or "").strip() or None
        self.case_id = str(self.case_id or "").strip()
        self.stages = tuple(self._normalize_stages(self.stages))
        self.max_jobs = max(0, int(self.max_jobs or 0))
        self.poll_interval = max(0.0, float(self.poll_interval or 0.0))
        self.cleanup_completed_days = max(0.0, float(self.cleanup_completed_days or 0.0))
        self.cleanup_failed_days = max(0.0, float(self.cleanup_failed_days or 0.0))
        self.cleanup_watch_delta_days = max(0.0, float(self.cleanup_watch_delta_days or 0.0))
        ensure_workspace_layout(self.output_root)
        self.store.initialize()
        self.status_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def status_path(self) -> Path:
        return (self.output_root / "monitor" / DEFAULT_MONITOR_STATUS_NAME).resolve()

    @property
    def history_path(self) -> Path:
        return (self.output_root / "monitor" / DEFAULT_MONITOR_HISTORY_NAME).resolve()

    @property
    def database_file(self) -> Path:
        if self.database_path:
            return Path(self.database_path).resolve()
        return (self.output_root / "storage" / DEFAULT_DATABASE_NAME).resolve()

    @property
    def store(self) -> SQLiteIntelligenceStore:
        return SQLiteIntelligenceStore(self.database_file)

    @property
    def tuning(self) -> dict[str, object]:
        return load_monitor_tuning(self.output_root, case_id=self.case_id)

    @property
    def watcher_id(self) -> str:
        return stable_record_id(
            "watcher",
            "queue_monitor",
            self.case_id or "",
            str(self.output_root),
            list(self.stage_filter),
        )

    def read_status(self) -> dict[str, object]:
        default = self._default_status()
        if not self.status_path.exists():
            return default
        try:
            payload = json.loads(self.status_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default
        if not isinstance(payload, dict):
            return default
        runtime_cleanup_policy = self._cleanup_policy()
        persisted_cleanup_policy = dict(payload.get("cleanup_policy") or {})
        tuning = self.tuning
        watch_tuning_profiles = self._watch_tuning_profiles()
        automation = _normalize_monitor_automation_snapshot(
            dict(payload.get("automation") or {}),
            mode=str(tuning.get("automation_mode") or DEFAULT_AUTOMATION_MODE),
        )
        # Forecasts are derived data, so recompute them from the latest history and
        # current tuning instead of trusting a stale persisted snapshot.
        forecast = build_monitor_forecast(
            self.read_history(limit=FORECAST_LOOKBACK_CYCLES),
            tuning=tuning,
            status={**payload, "watch_tuning_profiles": watch_tuning_profiles},
        )
        return {
            **default,
            **payload,
            "output_root": str(self.output_root),
            "workspace_root": str(self.workspace_root),
            "database_path": str(self.database_file),
            "case_id": self.case_id,
            "stage_filter": list(self.stage_filter),
            "cleanup_policy": (
                runtime_cleanup_policy
                if bool(runtime_cleanup_policy.get("enabled"))
                else {
                    **runtime_cleanup_policy,
                    **persisted_cleanup_policy,
                }
            ),
            "tuning": tuning,
            "watch_tuning_profiles": watch_tuning_profiles,
            "automation": automation,
            "forecast": forecast,
            "status_path": str(self.status_path),
            "history_path": str(self.history_path),
            "monitor_dir": str(self.status_path.parent),
            "watcher_id": self.watcher_id,
            "watcher_summary": self.store.watcher_summary(case_id=self.case_id),
            "watchers": self._load_watcher_states(),
            "watched_source_summary": self.store.watched_source_summary(case_id=self.case_id),
            "watched_sources": self._load_watched_sources(),
        }

    def read_history(self, *, limit: int = 24) -> list[dict[str, object]]:
        if not self.history_path.exists():
            return []
        try:
            lines = self.history_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []

        rows: list[dict[str, object]] = []
        max_rows = max(1, int(limit or 24))
        requested_case_id = str(self.case_id or "").strip()
        for line in reversed(lines):
            text = line.strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            if requested_case_id and str(payload.get("case_id") or "") != requested_case_id:
                continue
            rows.append(payload)
            if len(rows) >= max_rows:
                break
        rows.reverse()
        return rows

    def run_once(self) -> dict[str, object]:
        previous = self.read_status()
        cycle_count = int(previous.get("cycle_count") or 0) + 1
        idle_cycle_count = int(previous.get("idle_cycle_count") or 0)
        total_processed_job_count = int(previous.get("total_processed_job_count") or 0)
        total_completed_job_count = int(previous.get("total_completed_job_count") or 0)
        total_failed_job_count = int(previous.get("total_failed_job_count") or 0)
        total_source_check_count = int(previous.get("total_source_check_count") or 0)
        total_source_change_count = int(previous.get("total_source_change_count") or 0)
        total_source_failure_count = int(previous.get("total_source_failure_count") or 0)
        previous_hot_cycle_streak = int(previous.get("hot_cycle_streak") or 0)
        previous_drain_cycle_streak = int(previous.get("drain_cycle_streak") or 0)
        started_at = str(previous.get("started_at") or utc_now())
        previous_watcher = self._current_watcher_state()
        source_checks = self._run_registered_source_checks()
        total_source_check_count += int(source_checks.get("executed_check_count") or 0)
        total_source_change_count += int(source_checks.get("changed_count") or 0)
        total_source_failure_count += int(source_checks.get("failed_count") or 0)

        queue_counts_before = self._queue_counts()
        queue_priority_counts_before = self._queue_priority_counts()
        queue_stage_priority_counts_before = self._queue_stage_priority_counts()
        queue_stage_age_stats_before = self._queue_stage_age_stats()
        queue_total_before = sum(queue_counts_before.values())
        stage_budget = self._stage_budget_plan(
            queue_counts=queue_counts_before,
            queue_priority_counts=queue_priority_counts_before,
            queue_stage_priority_counts=queue_stage_priority_counts_before,
            queue_stage_age_stats=queue_stage_age_stats_before,
            source_checks=source_checks,
            previous_hot_cycle_streak=previous_hot_cycle_streak,
        )

        if queue_total_before == 0:
            if int(source_checks.get("changed_count") or 0) == 0:
                idle_cycle_count += 1
            result_summary = {
                "ok": int(source_checks.get("failed_count") or 0) == 0,
                "executed": False,
                "reason": "watch_errors" if int(source_checks.get("failed_count") or 0) > 0 else "idle",
                "processed_job_count": 0,
                "completed_job_count": 0,
                "failed_job_count": 0,
                "remaining_queue_count": 0,
                "warning_count": 0,
                "error_count": int(source_checks.get("failed_count") or 0),
                "artifact_path_count": int(source_checks.get("artifact_path_count") or 0),
                "processed_priority_counts": {"urgent": 0, "high": 0, "normal": 0, "low": 0},
                "stage_budget_mode": str(stage_budget.get("mode") or "idle"),
                "stage_budget_plan": dict(stage_budget.get("stage_budgets") or {}),
                "fairness_stage": str(stage_budget.get("fairness_stage") or ""),
                "stage_results": [],
                "warnings": list(source_checks.get("warnings") or []),
                "errors": list(source_checks.get("errors") or []),
            }
            queue_counts_after = dict(queue_counts_before)
            queue_priority_counts_after = dict(queue_priority_counts_before)
        else:
            result = self._run_queue_cycle(
                source_checks=source_checks,
                stage_budget=stage_budget,
            )
            total_processed_job_count += int(result.metrics.get("processed_job_count") or 0)
            total_completed_job_count += int(result.metrics.get("completed_job_count") or 0)
            total_failed_job_count += int(result.metrics.get("failed_job_count") or 0)
            queue_counts_after = self._queue_counts()
            queue_priority_counts_after = self._queue_priority_counts()
            result_summary = {
                "ok": bool(result.ok and int(source_checks.get("failed_count") or 0) == 0),
                "executed": True,
                "reason": "processed" if result.ok else "failed",
                "processed_job_count": int(result.metrics.get("processed_job_count") or 0),
                "completed_job_count": int(result.metrics.get("completed_job_count") or 0),
                "failed_job_count": int(result.metrics.get("failed_job_count") or 0),
                "remaining_queue_count": int(result.metrics.get("remaining_queue_count") or 0),
                "warning_count": len(result.warnings) + len(tuple(source_checks.get("warnings") or ())),
                "error_count": len(result.errors) + int(source_checks.get("failed_count") or 0),
                "artifact_path_count": len(result.artifact_paths) + int(source_checks.get("artifact_path_count") or 0),
                "processed_priority_counts": dict(result.metrics.get("processed_priority_counts") or {}),
                "stage_budget_mode": str(result.metrics.get("stage_budget_mode") or stage_budget.get("mode") or "unlimited"),
                "stage_budget_plan": dict(result.metrics.get("stage_budget_plan") or stage_budget.get("stage_budgets") or {}),
                "fairness_stage": str(result.metrics.get("fairness_stage") or stage_budget.get("fairness_stage") or ""),
                "stage_results": list(result.metrics.get("stage_results") or []),
                "warnings": [*list(source_checks.get("warnings") or []), *list(result.warnings)],
                "errors": [*list(source_checks.get("errors") or []), *list(result.errors)],
            }

        cleanup_summary = self._run_cleanup_cycle()
        cleanup_warnings = list(cleanup_summary.get("warnings") or [])
        cleanup_errors = list(cleanup_summary.get("errors") or [])
        cleanup_artifact_paths = list(cleanup_summary.get("artifact_paths") or [])
        if cleanup_warnings:
            result_summary["warnings"] = [
                *list(result_summary.get("warnings") or []),
                *cleanup_warnings,
            ]
        if cleanup_errors:
            result_summary["errors"] = [
                *list(result_summary.get("errors") or []),
                *cleanup_errors,
            ]
            result_summary["ok"] = False
            result_summary["reason"] = "cleanup_failed"
        result_summary["warning_count"] = len(list(result_summary.get("warnings") or []))
        result_summary["error_count"] = len(list(result_summary.get("errors") or []))
        result_summary["artifact_path_count"] = int(result_summary.get("artifact_path_count") or 0) + len(cleanup_artifact_paths)
        result_summary["cleanup_removed_count"] = int(cleanup_summary.get("removed_count") or 0)
        result_summary["cleanup_removed_bytes"] = int(cleanup_summary.get("removed_bytes") or 0)

        backlog_pointer = next((stage for stage, count in queue_counts_after.items() if int(count) > 0), "")
        change_detected = bool(
            queue_total_before > 0
            or queue_counts_after != queue_counts_before
            or int(source_checks.get("changed_count") or 0) > 0
        )
        consecutive_no_change_count = 0 if change_detected else int(previous_watcher.get("consecutive_no_change_count") or 0) + 1
        total_change_count = int(previous_watcher.get("total_change_count") or 0) + (1 if change_detected else 0)
        checked_at = utc_now()
        watcher_status = "error" if not bool(result_summary.get("ok", True)) else ("active" if change_detected else "idle")
        stage_budget_mode = str(result_summary.get("stage_budget_mode") or stage_budget.get("mode") or "")
        if stage_budget_mode == "collection_hot":
            hot_cycle_streak = previous_hot_cycle_streak + 1
            drain_cycle_streak = 0
        elif stage_budget_mode == "processing_drain":
            hot_cycle_streak = 0
            drain_cycle_streak = previous_drain_cycle_streak + 1
        else:
            hot_cycle_streak = 0
            drain_cycle_streak = 0
        watcher_payload = {
            "watcher_id": self.watcher_id,
            "source_id": "",
            "case_id": self.case_id,
            "watcher_type": "queue_monitor",
            "source_type": "queue",
            "locator": f"queue://{','.join(self.stage_filter)}",
            "status": watcher_status,
            "last_checked_at": checked_at,
            "last_seen_at": checked_at,
            "last_changed_at": checked_at if change_detected else str(previous_watcher.get("last_changed_at") or ""),
            "cursor": f"cycle:{cycle_count}",
            "content_hash": stable_record_id("watcher_state", self.watcher_id, queue_counts_after, result_summary),
            "suppression_until": "",
            "backlog_pointer": backlog_pointer,
            "consecutive_no_change_count": consecutive_no_change_count,
            "total_check_count": cycle_count,
            "total_change_count": total_change_count,
            "last_error": "; ".join(result_summary["errors"][:2]),
            "queue_counts_before": dict(queue_counts_before),
            "queue_counts_after": dict(queue_counts_after),
            "queue_priority_counts_before": dict(queue_priority_counts_before),
            "queue_priority_counts_after": dict(queue_priority_counts_after),
            "queue_stage_age_stats_before": dict(queue_stage_age_stats_before),
            "hot_cycle_streak": hot_cycle_streak,
            "drain_cycle_streak": drain_cycle_streak,
            "stage_budget_mode": str(result_summary.get("stage_budget_mode") or stage_budget.get("mode") or ""),
            "stage_budget_plan": dict(result_summary.get("stage_budget_plan") or stage_budget.get("stage_budgets") or {}),
            "fairness_stage": str(result_summary.get("fairness_stage") or stage_budget.get("fairness_stage") or ""),
            "last_result": dict(result_summary),
        }
        self.store.persist_watcher_states((watcher_payload,))
        watcher_summary = self.store.watcher_summary(case_id=self.case_id)
        watcher_states = self._load_watcher_states()
        watched_source_summary = self.store.watched_source_summary(case_id=self.case_id)
        watched_sources = self._load_watched_sources()
        tuning = self.tuning
        watch_tuning_profiles = self._watch_tuning_profiles()

        snapshot = {
            "schema_version": 1,
            "runtime": "passive_monitor",
            "started_at": started_at,
            "last_heartbeat_at": checked_at,
            "cycle_count": cycle_count,
            "idle_cycle_count": idle_cycle_count,
            "total_processed_job_count": total_processed_job_count,
            "total_completed_job_count": total_completed_job_count,
            "total_failed_job_count": total_failed_job_count,
            "total_source_check_count": total_source_check_count,
            "total_source_change_count": total_source_change_count,
            "total_source_failure_count": total_source_failure_count,
            "source_checks": source_checks,
            "queue_counts_before": queue_counts_before,
            "queue_counts_after": queue_counts_after,
            "queue_priority_counts_before": queue_priority_counts_before,
            "queue_priority_counts_after": queue_priority_counts_after,
            "queue_stage_priority_counts_before": queue_stage_priority_counts_before,
            "queue_stage_age_stats_before": queue_stage_age_stats_before,
            "queue_total_before": queue_total_before,
            "queue_total_after": sum(queue_counts_after.values()),
            "hot_cycle_streak": hot_cycle_streak,
            "drain_cycle_streak": drain_cycle_streak,
            "stage_budget_mode": str(result_summary.get("stage_budget_mode") or stage_budget.get("mode") or ""),
            "stage_budget_plan": dict(result_summary.get("stage_budget_plan") or stage_budget.get("stage_budgets") or {}),
            "fairness_stage": str(result_summary.get("fairness_stage") or stage_budget.get("fairness_stage") or ""),
            "last_result": result_summary,
            "output_root": str(self.output_root),
            "workspace_root": str(self.workspace_root),
            "database_path": str(self.database_file),
            "case_id": self.case_id,
            "stage_filter": list(self.stage_filter),
            "max_jobs": self.max_jobs,
            "poll_interval_seconds": self.poll_interval,
            "cleanup_policy": self._cleanup_policy(),
            "cleanup": cleanup_summary,
            "tuning": tuning,
            "watch_tuning_profiles": watch_tuning_profiles,
            "status_path": str(self.status_path),
            "history_path": str(self.history_path),
            "monitor_dir": str(self.status_path.parent),
            "watcher_id": self.watcher_id,
            "watcher_summary": watcher_summary,
            "watchers": watcher_states,
            "watched_source_summary": watched_source_summary,
            "watched_sources": watched_sources,
        }
        snapshot["forecast"] = build_monitor_forecast(
            [
                *self.read_history(limit=FORECAST_LOOKBACK_CYCLES),
                self._history_entry(snapshot),
            ],
            tuning=tuning,
            status={**snapshot, "watch_tuning_profiles": watch_tuning_profiles},
        )
        automation = self._run_automation_cycle(
            snapshot=snapshot,
            tuning=tuning,
            watch_tuning_profiles=watch_tuning_profiles,
        )
        snapshot["automation"] = automation
        if int(dict(automation.get("summary") or {}).get("applied_count") or 0) > 0:
            tuning = self.tuning
            watch_tuning_profiles = self._watch_tuning_profiles()
            snapshot["tuning"] = tuning
            snapshot["watch_tuning_profiles"] = watch_tuning_profiles
            snapshot["forecast"] = build_monitor_forecast(
                [
                    *self.read_history(limit=FORECAST_LOOKBACK_CYCLES),
                    self._history_entry(snapshot),
                ],
                tuning=tuning,
                status={**snapshot, "watch_tuning_profiles": watch_tuning_profiles},
            )
            snapshot["automation"] = _normalize_monitor_automation_snapshot(
                dict(snapshot.get("automation") or {}),
                mode=str(tuning.get("automation_mode") or DEFAULT_AUTOMATION_MODE),
            )
        self._write_status(snapshot)
        self._append_history(snapshot)
        return snapshot

    def run_forever(self, *, iterations: int = 0) -> dict[str, object]:
        completed_iterations = 0
        last_snapshot = self.read_status()
        while iterations <= 0 or completed_iterations < iterations:
            last_snapshot = self.run_once()
            completed_iterations += 1
            if iterations > 0 and completed_iterations >= iterations:
                break
            time.sleep(self.poll_interval)
        return last_snapshot

    def _run_automation_cycle(
        self,
        *,
        snapshot: dict[str, object],
        tuning: dict[str, object],
        watch_tuning_profiles: dict[str, dict[str, object]],
    ) -> dict[str, object]:
        mode = _normalize_automation_mode(tuning.get("automation_mode"))
        automation = _default_monitor_automation(mode=mode)
        automation["evaluated_at"] = str(snapshot.get("last_heartbeat_at") or utc_now())
        if mode == "off":
            return automation

        watched_sources = {
            str(row.get("watch_id") or ""): dict(row)
            for row in self.store.fetch_watched_sources(case_id=self.case_id, limit=500)
            if str(row.get("watch_id") or "").strip()
        }
        watcher_states = {
            watch_id: self._source_monitor_state_for_row(row)
            for watch_id, row in watched_sources.items()
        }
        recommendations: list[dict[str, object]] = []
        case_recommendation = self._case_preset_recommendation(snapshot=snapshot, tuning=tuning)
        if case_recommendation:
            recommendations.append(case_recommendation)
        recommendations.extend(
            self._watch_preset_recommendations(
                snapshot=snapshot,
                watch_tuning_profiles=watch_tuning_profiles,
                watched_sources=watched_sources,
                watcher_states=watcher_states,
            )
        )

        applied_actions: list[dict[str, object]] = []
        if mode == "apply":
            for index, recommendation in enumerate(recommendations):
                scope = str(recommendation.get("scope") or "")
                if not bool(recommendation.get("safe_to_apply")):
                    continue
                if scope == "case":
                    result = self.app.update_monitor_tuning(
                        case_id=str(recommendation.get("case_id") or self.case_id or ""),
                        output_root=str(self.output_root),
                        automation_mode=mode,
                        change_origin="automation",
                        automation_direction=str(recommendation.get("direction") or ""),
                        automation_reason=str(recommendation.get("reason") or ""),
                        preset_name=str(recommendation.get("recommended_preset_name") or ""),
                    )
                elif scope == "watch":
                    result = self.app.update_watch_source_settings(
                        case_id=str(recommendation.get("case_id") or ""),
                        watch_id=str(recommendation.get("watch_id") or ""),
                        tuning_preset_name=str(recommendation.get("recommended_preset_name") or ""),
                        change_origin="automation",
                        automation_direction=str(recommendation.get("direction") or ""),
                        automation_reason=str(recommendation.get("reason") or ""),
                        output_root=str(self.output_root),
                        database_path=str(self.database_file),
                    )
                else:
                    continue
                applied_action = {
                    **recommendation,
                    "action": "applied" if bool(result.get("ok")) else "failed",
                    "artifact_paths": list(result.get("artifact_paths") or []),
                    "ok": bool(result.get("ok")),
                }
                applied_actions.append(applied_action)
                recommendations[index] = {**recommendation, "action": applied_action["action"]}

        for index, recommendation in enumerate(recommendations):
            if str(recommendation.get("action") or "").strip():
                continue
            recommendations[index] = {**recommendation, "action": "recommend"}

        automation["recommendations"] = recommendations
        automation["applied_actions"] = applied_actions
        automation["summary"] = {
            "recommendation_count": len(recommendations),
            "active_recommendation_count": sum(
                1 for item in recommendations if str(item.get("action") or "recommend") == "recommend"
            ),
            "case_recommendation_count": sum(1 for item in recommendations if str(item.get("scope") or "") == "case"),
            "watch_recommendation_count": sum(1 for item in recommendations if str(item.get("scope") or "") == "watch"),
            "safe_to_apply_count": sum(1 for item in recommendations if bool(item.get("safe_to_apply"))),
            "applied_count": sum(1 for item in applied_actions if bool(item.get("ok"))),
            "case_applied_count": sum(
                1
                for item in applied_actions
                if bool(item.get("ok")) and str(item.get("scope") or "") == "case"
            ),
            "watch_applied_count": sum(
                1
                for item in applied_actions
                if bool(item.get("ok")) and str(item.get("scope") or "") == "watch"
            ),
            "already_count": sum(
                1
                for item in recommendations
                if str(item.get("action") or "") in {"already_applied", "already_rolled_back"}
            ),
            "manual_override_count": sum(
                1 for item in recommendations if str(item.get("action") or "") == "manual_override"
            ),
        }
        return automation

    def _case_preset_recommendation(
        self,
        *,
        snapshot: dict[str, object],
        tuning: dict[str, object],
    ) -> dict[str, object] | None:
        if not self.case_id:
            return None
        forecast = dict(snapshot.get("forecast") or {})
        forecast_summary = dict(forecast.get("summary") or {})
        alert_ids = {str(item.get("id") or "").strip() for item in list(forecast.get("alerts") or []) if isinstance(item, dict)}
        alert_ids.discard("")
        current_preset_name = str(tuning.get("preset_name") or DEFAULT_MONITOR_TUNING_PRESET)
        automation_state = normalize_preset_automation_state(dict(tuning.get("automation_state") or {}))
        changed_count = int(dict(snapshot.get("source_checks") or {}).get("changed_count") or 0)
        hot_cycle_streak = int(snapshot.get("hot_cycle_streak") or 0)
        queue_total_before = int(snapshot.get("queue_total_before") or 0)
        predicted_drain_cycles = int(forecast_summary.get("predicted_backlog_drain_cycles") or 0)
        recent_rows = [
            *self.read_history(limit=FORECAST_LOOKBACK_CYCLES),
            self._history_entry(snapshot),
        ]
        calm_cycle_count = _trailing_calm_cycle_count(recent_rows)

        recommended_preset_name = ""
        reason = ""
        trigger_alert_ids: list[str] = []
        direction = ""
        if (
            hot_cycle_streak >= AUTOMATION_MIN_HOT_STREAK
            and bool({"queue_pressure_spike", "throughput_drop"} & alert_ids)
        ):
            recommended_preset_name = "collection_first"
            direction = "escalate"
            trigger_alert_ids = [
                alert_id
                for alert_id in ("queue_pressure_spike", "throughput_drop")
                if alert_id in alert_ids
            ]
            reason = (
                "Sustained queue pressure is keeping this case in collection_hot mode; "
                "collection_first will bias the monitor toward intake and slower downstream drain."
            )
        elif (
            "source_churn_spike" in alert_ids
            and not bool({"queue_pressure_spike", "throughput_drop"} & alert_ids)
            and changed_count >= 2
        ):
            recommended_preset_name = "quiet"
            direction = "escalate"
            trigger_alert_ids = ["source_churn_spike"]
            reason = (
                "Repeated source churn is creating alert noise without dominant queue pressure; "
                "quiet will raise the threshold for churn-based forecast warnings."
            )
        elif (
            not alert_ids
            and calm_cycle_count >= AUTOMATION_MIN_CALM_CYCLES
            and (
                current_preset_name != DEFAULT_MONITOR_TUNING_PRESET
                or (
                    current_preset_name == DEFAULT_MONITOR_TUNING_PRESET
                    and str(automation_state.get("last_automation_preset_name") or "") == DEFAULT_MONITOR_TUNING_PRESET
                    and str(automation_state.get("last_automation_direction") or "") == "rollback"
                )
            )
        ):
            recommended_preset_name = DEFAULT_MONITOR_TUNING_PRESET
            direction = "rollback"
            reason = (
                f"This case has stayed calm for {calm_cycle_count} monitor cycles; "
                "rolling back to balanced will restore the default passive scheduler sensitivity."
            )
        if not recommended_preset_name:
            return None
        action = "recommend"
        safe_to_apply = _monitor_tuning_is_auto_apply_safe(tuning)
        if current_preset_name == recommended_preset_name:
            if (
                str(automation_state.get("last_automation_preset_name") or "") == recommended_preset_name
                and str(automation_state.get("last_automation_direction") or "") == direction
                and not bool(automation_state.get("manual_override_active"))
            ):
                action = "already_rolled_back" if direction == "rollback" else "already_applied"
                safe_to_apply = False
            else:
                return None
        elif bool(automation_state.get("manual_override_active")):
            action = "manual_override"
            safe_to_apply = False
            reason = (
                f"An operator manually changed this case to {current_preset_name}; "
                f"the monitor is leaving it alone instead of forcing {recommended_preset_name}."
            )
        return {
            "scope": "case",
            "case_id": self.case_id,
            "target_id": self.case_id,
            "target_label": self.case_id,
            "current_preset_name": current_preset_name,
            "recommended_preset_name": recommended_preset_name,
            "direction": direction,
            "reason": reason,
            "trigger_alert_ids": trigger_alert_ids,
            "hot_cycle_streak": hot_cycle_streak,
            "calm_cycle_count": calm_cycle_count,
            "queue_total_before": queue_total_before,
            "predicted_backlog_drain_cycles": predicted_drain_cycles,
            "action": action,
            "safe_to_apply": safe_to_apply,
            "automation_state": automation_state,
        }

    def _watch_preset_recommendations(
        self,
        *,
        snapshot: dict[str, object],
        watch_tuning_profiles: dict[str, dict[str, object]],
        watched_sources: dict[str, dict[str, object]],
        watcher_states: dict[str, dict[str, object]],
    ) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for result in list(dict(snapshot.get("source_checks") or {}).get("results") or []):
            if not isinstance(result, dict):
                continue
            watch_id = str(result.get("watch_id") or "").strip()
            source_type = str(result.get("source_type") or "").strip()
            if not watch_id or not source_type:
                continue
            recommended_preset_name = watch_tuning_preset_name_for_source_type(source_type)
            if recommended_preset_name in {"", DEFAULT_WATCH_TUNING_PRESET}:
                continue
            profile = normalize_watch_tuning_profile(
                dict(
                    result.get("tuning_profile")
                    or watch_tuning_profiles.get(watch_id)
                    or dict(watched_sources.get(watch_id, {}).get("tuning_profile") or {})
                )
            )
            watcher_state = dict(watcher_states.get(watch_id) or {})
            automation_state = normalize_preset_automation_state(
                dict(watched_sources.get(watch_id, {}).get("automation_state") or {})
            )
            current_preset_name = str(
                profile.get("preset_name")
                or watched_sources.get(watch_id, {}).get("tuning_preset_name")
                or ""
            )
            priority_label = str(result.get("priority_label") or "").strip().lower()
            poll_adaptation = str(result.get("poll_adaptation") or "").strip().lower()
            next_poll_adaptation = str(result.get("next_poll_adaptation") or "").strip().lower()
            change_kind = str(result.get("change_kind") or "").strip().lower()
            active = bool(
                bool(result.get("changed"))
                or bool(result.get("delta_ingest"))
                or priority_label in AUTOMATION_ACTIVE_PRIORITY_LABELS
                or poll_adaptation in AUTOMATION_ACTIVE_POLL_MODES
                or next_poll_adaptation in AUTOMATION_ACTIVE_POLL_MODES
                or change_kind == "append_only"
            )
            consecutive_no_change_count = int(watcher_state.get("consecutive_no_change_count") or 0)
            backlogged = bool(str(watcher_state.get("backlog_pointer") or "").strip())
            calm = bool(
                not active
                and consecutive_no_change_count >= AUTOMATION_MIN_CALM_CYCLES
                and not backlogged
                and priority_label not in AUTOMATION_ACTIVE_PRIORITY_LABELS
            )
            transition_preset_name = ""
            transition_reason = ""
            trigger_alert_ids: list[str] = []
            direction = ""
            if (
                active
                and recommended_preset_name not in {"", DEFAULT_WATCH_TUNING_PRESET}
            ):
                transition_preset_name = recommended_preset_name
                direction = "escalate"
                transition_reason = self._watch_preset_reason(
                    source_type=source_type,
                    change_kind=change_kind,
                    poll_adaptation=next_poll_adaptation or poll_adaptation,
                )
                trigger_alert_ids = ["source_churn_spike"] if bool(result.get("changed")) else []
            elif (
                calm
                and (
                    current_preset_name not in {"", DEFAULT_WATCH_TUNING_PRESET}
                    or (
                        current_preset_name in {"", DEFAULT_WATCH_TUNING_PRESET}
                        and str(automation_state.get("last_automation_preset_name") or "") == DEFAULT_WATCH_TUNING_PRESET
                        and str(automation_state.get("last_automation_direction") or "") == "rollback"
                    )
                )
            ):
                transition_preset_name = DEFAULT_WATCH_TUNING_PRESET
                direction = "rollback"
                transition_reason = (
                    f"This source has stayed calm for {consecutive_no_change_count} checks; "
                    "rolling back to source:default will remove the temporary source-specific preset."
                )
            if not transition_preset_name:
                continue
            action = "recommend"
            safe_to_apply = _watch_profile_is_auto_apply_safe(profile)
            if current_preset_name == transition_preset_name:
                if (
                    str(automation_state.get("last_automation_preset_name") or "") == transition_preset_name
                    and str(automation_state.get("last_automation_direction") or "") == direction
                    and not bool(automation_state.get("manual_override_active"))
                ):
                    action = "already_rolled_back" if direction == "rollback" else "already_applied"
                    safe_to_apply = False
                else:
                    continue
            else:
                if bool(automation_state.get("manual_override_active")):
                    action = "manual_override"
                    safe_to_apply = False
                    transition_reason = (
                        f"An operator manually changed this source to {current_preset_name or DEFAULT_WATCH_TUNING_PRESET}; "
                        f"the monitor is leaving it alone instead of forcing {transition_preset_name}."
                    )
                elif direction == "escalate" and (
                    current_preset_name not in {"", DEFAULT_WATCH_TUNING_PRESET}
                    or _watch_profile_has_overrides(profile)
                ):
                    continue
            if not active:
                if not calm:
                    continue
            watched_source = dict(watched_sources.get(watch_id) or {})
            target_label = str(
                watched_source.get("display_name")
                or watched_source.get("locator")
                or result.get("locator")
                or watch_id
            )
            rows.append(
                {
                    "scope": "watch",
                    "case_id": str(watched_source.get("case_id") or result.get("case_id") or self.case_id or ""),
                    "watch_id": watch_id,
                    "target_id": watch_id,
                    "target_label": target_label,
                    "source_type": source_type,
                    "current_preset_name": current_preset_name or DEFAULT_WATCH_TUNING_PRESET,
                    "recommended_preset_name": transition_preset_name,
                    "direction": direction,
                    "reason": transition_reason,
                    "trigger_alert_ids": trigger_alert_ids,
                    "priority_label": priority_label or "low",
                    "priority_score": int(result.get("priority_score") or 0),
                    "poll_adaptation": next_poll_adaptation or poll_adaptation or "base",
                    "change_kind": change_kind,
                    "calm_cycle_count": consecutive_no_change_count,
                    "action": action,
                    "safe_to_apply": safe_to_apply,
                    "automation_state": automation_state,
                }
            )
        rows.sort(
            key=lambda item: (
                -int(item.get("priority_score") or 0),
                str(item.get("target_label") or ""),
            )
        )
        return rows[:8]

    def _watch_preset_reason(self, *, source_type: str, change_kind: str, poll_adaptation: str) -> str:
        normalized_source_type = str(source_type or "").strip().lower()
        if normalized_source_type in {"log", "log-bundle"}:
            return "This log source is staying active enough to benefit from the append-heavy source:log preset."
        if normalized_source_type in {"pcap", "pcapng", "wifi-capture"}:
            return "This capture source is staying hot, so the source:pcap preset will reduce churn noise while preserving frequent checks."
        if normalized_source_type in {"directory"}:
            return "This directory source is producing repeated changes, and the source:directory preset better matches moderate nested churn."
        if normalized_source_type in {"system-artifact", "system-artifact-bundle"}:
            return "This system-artifact source is active enough to benefit from the source:system preset."
        if change_kind == "append_only":
            return "This source is showing append-only growth and would benefit from a source-specific watch preset."
        if poll_adaptation in AUTOMATION_ACTIVE_POLL_MODES:
            return "This source is staying in a fast-poll lane and would benefit from its source-specific watch preset."
        return "This source is active enough to benefit from its source-specific watch preset."

    @property
    def stage_filter(self) -> tuple[str, ...]:
        return self.stages or tuple(QUEUE_STAGE_ORDER)

    def _queue_counts(self) -> dict[str, int]:
        counts = {stage: 0 for stage in self.stage_filter}
        for item in self.app.list_queued_jobs(
            output_root=str(self.output_root),
            case_id=self.case_id,
            stages=self.stage_filter,
        ):
            stage = str(item.get("stage") or "").strip()
            if stage in counts:
                counts[stage] += 1
        return counts

    def _queue_priority_counts(self) -> dict[str, int]:
        counts = {"urgent": 0, "high": 0, "normal": 0, "low": 0}
        for item in self.app.list_queued_jobs(
            output_root=str(self.output_root),
            case_id=self.case_id,
            stages=self.stage_filter,
        ):
            label = str(item.get("priority_label") or "").strip().lower()
            if label not in counts:
                label = "low"
            counts[label] += 1
        return counts

    def _queue_stage_priority_counts(self) -> dict[str, dict[str, int]]:
        counts = {stage: {"urgent": 0, "high": 0, "normal": 0, "low": 0} for stage in self.stage_filter}
        for item in self.app.list_queued_jobs(
            output_root=str(self.output_root),
            case_id=self.case_id,
            stages=self.stage_filter,
        ):
            stage = str(item.get("stage") or "").strip()
            if stage not in counts:
                continue
            label = str(item.get("priority_label") or "").strip().lower()
            if label not in counts[stage]:
                label = "low"
            counts[stage][label] += 1
        return counts

    def _queue_stage_age_stats(self) -> dict[str, dict[str, int]]:
        stats = {
            stage: {
                "oldest_age_seconds": 0,
                "aged_job_count_soft": 0,
                "aged_job_count_hard": 0,
            }
            for stage in self.stage_filter
        }
        for item in self.app.list_queued_jobs(
            output_root=str(self.output_root),
            case_id=self.case_id,
            stages=self.stage_filter,
        ):
            stage = str(item.get("stage") or "").strip()
            if stage not in stats:
                continue
            age_seconds = max(0, int(item.get("queued_age_seconds") or 0))
            stats[stage]["oldest_age_seconds"] = max(int(stats[stage]["oldest_age_seconds"]), age_seconds)
            if age_seconds >= QUEUE_AGE_SOFT_THRESHOLD_SECONDS:
                stats[stage]["aged_job_count_soft"] += 1
            if age_seconds >= QUEUE_AGE_HARD_THRESHOLD_SECONDS:
                stats[stage]["aged_job_count_hard"] += 1
        return stats

    def _stage_budget_plan(
        self,
        *,
        queue_counts: dict[str, int],
        queue_priority_counts: dict[str, int],
        queue_stage_priority_counts: dict[str, dict[str, int]],
        queue_stage_age_stats: dict[str, dict[str, int]],
        source_checks: dict[str, object],
        previous_hot_cycle_streak: int,
    ) -> dict[str, object]:
        if self.max_jobs <= 0:
            return {
                "mode": "unlimited",
                "planned_jobs": 0,
                "stage_budgets": {stage: 0 for stage in self.stage_filter},
                "fairness_stage": "",
            }

        active_counts = {stage: int(queue_counts.get(stage) or 0) for stage in self.stage_filter}
        active_stages = [stage for stage, count in active_counts.items() if count > 0]
        if not active_stages:
            return {
                "mode": "idle",
                "planned_jobs": 0,
                "stage_budgets": {stage: 0 for stage in self.stage_filter},
                "fairness_stage": "",
            }

        hot_source_priority = dict(source_checks.get("priority_counts") or {})
        early_stages = tuple(stage for stage in self.stage_filter if stage in {"extract", "recover"})
        hot_collection = bool(
            int(source_checks.get("changed_count") or 0) > 0
            or int(source_checks.get("append_only_count") or 0) > 0
            or int(hot_source_priority.get("urgent") or 0) > 0
            or int(hot_source_priority.get("high") or 0) > 0
            or any(
                int((queue_stage_priority_counts.get(stage) or {}).get("urgent") or 0) > 0
                or int((queue_stage_priority_counts.get(stage) or {}).get("high") or 0) > 0
                for stage in early_stages
            )
        )
        mode = "collection_hot" if hot_collection else "processing_drain"

        weights: dict[str, int] = {}
        stage_bias_hot = {"extract": 6, "recover": 4, "normalize": 2, "correlate": 1, "store": 1, "present": 1}
        stage_bias_quiet = {"extract": 2, "recover": 2, "normalize": 5, "correlate": 4, "store": 3, "present": 2}
        for stage in self.stage_filter:
            count = active_counts.get(stage, 0)
            if count <= 0:
                continue
            priority_counts = dict(queue_stage_priority_counts.get(stage) or {})
            age_stats = dict(queue_stage_age_stats.get(stage) or {})
            priority_weight = (
                int(priority_counts.get("urgent") or 0) * 5
                + int(priority_counts.get("high") or 0) * 3
                + int(priority_counts.get("normal") or 0) * 2
                + int(priority_counts.get("low") or 0)
            )
            base_bias = stage_bias_hot if hot_collection else stage_bias_quiet
            age_weight = min(10, int(age_stats.get("oldest_age_seconds") or 0) // QUEUE_AGE_SOFT_THRESHOLD_SECONDS)
            age_weight += int(age_stats.get("aged_job_count_hard") or 0) * 2
            age_weight += int(age_stats.get("aged_job_count_soft") or 0)
            weights[stage] = 1 + int(base_bias.get(stage, 1)) + min(4, count) + priority_weight + age_weight

        fairness_stage = ""
        reserved_budgets = {stage: 0 for stage in self.stage_filter}
        if hot_collection and previous_hot_cycle_streak >= HOT_FAIRNESS_TRIGGER_STREAK:
            late_candidates = [
                stage
                for stage in active_stages
                if stage not in early_stages
                and int((queue_stage_age_stats.get(stage) or {}).get("aged_job_count_soft") or 0) > 0
            ]
            if late_candidates:
                fairness_stage = max(
                    late_candidates,
                    key=lambda stage: (
                        int((queue_stage_age_stats.get(stage) or {}).get("oldest_age_seconds") or 0),
                        -self.stage_filter.index(stage),
                    ),
                )
                reserved_budgets[fairness_stage] = 1
                mode = "collection_hot_fairness"

        remaining_budget = max(0, self.max_jobs - sum(reserved_budgets.values()))
        stage_budgets = _allocate_stage_budgets(
            total_budget=remaining_budget,
            stage_order=self.stage_filter,
            stage_counts=active_counts,
            stage_weights=weights,
        )
        for stage, reserved in reserved_budgets.items():
            stage_budgets[stage] = int(stage_budgets.get(stage) or 0) + int(reserved or 0)
        planned_jobs = sum(stage_budgets.values())
        return {
            "mode": mode,
            "planned_jobs": planned_jobs,
            "stage_budgets": stage_budgets,
            "queue_priority_counts": dict(queue_priority_counts),
            "queue_stage_age_stats": dict(queue_stage_age_stats),
            "fairness_stage": fairness_stage,
            "fairness_trigger_streak": HOT_FAIRNESS_TRIGGER_STREAK,
        }

    def _run_queue_cycle(
        self,
        *,
        source_checks: dict[str, object],
        stage_budget: dict[str, object],
    ) -> PluginResult:
        if self.max_jobs <= 0:
            result = self.app.run_queued(
                output_root=str(self.output_root),
                workspace_root=str(self.workspace_root),
                database_path=self.database_path,
                case_id=self.case_id,
                stages=self.stages,
                max_jobs=self.max_jobs,
            )
            metrics = dict(result.metrics)
            metrics.setdefault("stage_budget_mode", str(stage_budget.get("mode") or "unlimited"))
            metrics.setdefault("stage_budget_plan", dict(stage_budget.get("stage_budgets") or {}))
            metrics.setdefault("stage_results", [])
            return PluginResult(
                records=result.records,
                artifact_paths=result.artifact_paths,
                warnings=result.warnings,
                errors=result.errors,
                metrics=metrics,
            )

        records = []
        artifact_paths: list[str] = []
        warnings: list[str] = []
        errors: list[str] = []
        processed_job_count = 0
        completed_job_count = 0
        failed_job_count = 0
        processed_priority_counts = {"urgent": 0, "high": 0, "normal": 0, "low": 0}
        completed_priority_counts = {"urgent": 0, "high": 0, "normal": 0, "low": 0}
        failed_priority_counts = {"urgent": 0, "high": 0, "normal": 0, "low": 0}
        stage_results: list[dict[str, object]] = []
        remaining_budget = int(stage_budget.get("planned_jobs") or self.max_jobs)
        carry_budget = 0
        stage_budgets = dict(stage_budget.get("stage_budgets") or {})

        for stage in self.stage_filter:
            planned_budget = int(stage_budgets.get(stage) or 0)
            effective_budget = min(remaining_budget, planned_budget + carry_budget) if remaining_budget > 0 else 0
            if effective_budget <= 0:
                stage_results.append(
                    {
                        "stage": stage,
                        "planned_budget": planned_budget,
                        "effective_budget": 0,
                        "processed_job_count": 0,
                        "remaining_budget": remaining_budget,
                    }
                )
                continue

            before_count = int(self._queue_counts().get(stage) or 0)
            if before_count <= 0:
                carry_budget += planned_budget
                stage_results.append(
                    {
                        "stage": stage,
                        "planned_budget": planned_budget,
                        "effective_budget": 0,
                        "processed_job_count": 0,
                        "remaining_budget": remaining_budget,
                    }
                )
                continue

            result = self.app.run_queued(
                output_root=str(self.output_root),
                workspace_root=str(self.workspace_root),
                database_path=self.database_path,
                case_id=self.case_id,
                stages=(stage,),
                max_jobs=effective_budget,
            )
            used_budget = int(result.metrics.get("processed_job_count") or 0)
            unused_budget = max(0, effective_budget - used_budget)
            remaining_budget = max(0, remaining_budget - used_budget)
            carry_budget = unused_budget

            records.extend(result.records)
            artifact_paths.extend(path for path in result.artifact_paths if path not in artifact_paths)
            warnings.extend(warning for warning in result.warnings if warning not in warnings)
            errors.extend(error for error in result.errors if error not in errors)
            processed_job_count += used_budget
            completed_job_count += int(result.metrics.get("completed_job_count") or 0)
            failed_job_count += int(result.metrics.get("failed_job_count") or 0)
            _merge_priority_counts(processed_priority_counts, dict(result.metrics.get("processed_priority_counts") or {}))
            _merge_priority_counts(completed_priority_counts, dict(result.metrics.get("completed_priority_counts") or {}))
            _merge_priority_counts(failed_priority_counts, dict(result.metrics.get("failed_priority_counts") or {}))
            stage_results.append(
                {
                    "stage": stage,
                    "planned_budget": planned_budget,
                    "effective_budget": effective_budget,
                    "processed_job_count": used_budget,
                    "completed_job_count": int(result.metrics.get("completed_job_count") or 0),
                    "failed_job_count": int(result.metrics.get("failed_job_count") or 0),
                    "remaining_budget": remaining_budget,
                }
            )
            if remaining_budget <= 0:
                break

        remaining_queue_count = len(
            self.app.list_queued_jobs(
                output_root=str(self.output_root),
                case_id=self.case_id,
                stages=self.stage_filter,
            )
        )
        return PluginResult(
            records=tuple(records),
            artifact_paths=tuple(artifact_paths),
            warnings=tuple(warnings),
            errors=tuple(errors),
            metrics={
                "processed_job_count": processed_job_count,
                "completed_job_count": completed_job_count,
                "failed_job_count": failed_job_count,
                "remaining_queue_count": remaining_queue_count,
                "processed_priority_counts": processed_priority_counts,
                "completed_priority_counts": completed_priority_counts,
                "failed_priority_counts": failed_priority_counts,
                "stage_budget_mode": str(stage_budget.get("mode") or "unlimited"),
                "stage_budget_plan": dict(stage_budgets),
                "fairness_stage": str(stage_budget.get("fairness_stage") or ""),
                "stage_results": stage_results,
            },
        )

    def _write_status(self, payload: dict[str, object]) -> None:
        self.status_path.parent.mkdir(parents=True, exist_ok=True)
        self.status_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _append_history(self, payload: dict[str, object]) -> None:
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        entry = self._history_entry(payload)
        with self.history_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True, ensure_ascii=True))
            handle.write("\n")

    def _history_entry(self, payload: dict[str, object]) -> dict[str, object]:
        source_checks = dict(payload.get("source_checks") or {})
        last_result = dict(payload.get("last_result") or {})
        queue_counts_before = dict(payload.get("queue_counts_before") or {})
        queue_counts_after = dict(payload.get("queue_counts_after") or {})
        cleanup = dict(payload.get("cleanup") or {})
        cleanup_metrics = dict(cleanup.get("metrics") or {})
        return {
            "schema_version": 1,
            "recorded_at": str(payload.get("last_heartbeat_at") or utc_now()),
            "case_id": str(payload.get("case_id") or ""),
            "cycle_count": int(payload.get("cycle_count") or 0),
            "last_heartbeat_at": str(payload.get("last_heartbeat_at") or ""),
            "stage_budget_mode": str(payload.get("stage_budget_mode") or last_result.get("stage_budget_mode") or ""),
            "queue_total_before": int(payload.get("queue_total_before") or 0),
            "queue_total_after": int(payload.get("queue_total_after") or 0),
            "queue_counts_before": queue_counts_before,
            "queue_counts_after": queue_counts_after,
            "executed_check_count": int(source_checks.get("executed_check_count") or 0),
            "changed_count": int(source_checks.get("changed_count") or 0),
            "failed_check_count": int(source_checks.get("failed_count") or 0),
            "processed_job_count": int(last_result.get("processed_job_count") or 0),
            "completed_job_count": int(last_result.get("completed_job_count") or 0),
            "failed_job_count": int(last_result.get("failed_job_count") or 0),
            "hot_source_count": int(source_checks.get("priority_counts", {}).get("urgent") or 0)
            + int(source_checks.get("priority_counts", {}).get("high") or 0),
            "artifact_path_count": int(last_result.get("artifact_path_count") or 0),
            "cleanup_removed_count": int(cleanup.get("removed_count") or cleanup_metrics.get("removed_count") or 0),
            "cleanup_removed_bytes": int(cleanup.get("removed_bytes") or cleanup_metrics.get("removed_bytes") or 0),
            "fairness_stage": str(payload.get("fairness_stage") or last_result.get("fairness_stage") or ""),
            "ok": bool(last_result.get("ok", True)),
        }

    def _default_status(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "runtime": "passive_monitor",
            "started_at": "",
            "last_heartbeat_at": "",
            "cycle_count": 0,
            "idle_cycle_count": 0,
            "total_processed_job_count": 0,
            "total_completed_job_count": 0,
            "total_failed_job_count": 0,
            "total_source_check_count": 0,
            "total_source_change_count": 0,
            "total_source_failure_count": 0,
            "hot_cycle_streak": 0,
            "drain_cycle_streak": 0,
            "source_checks": {
                "registered_count": 0,
                "eligible_count": 0,
                "executed_check_count": 0,
                "changed_count": 0,
                "ingested_count": 0,
                "skipped_count": 0,
                "cooldown_skip_count": 0,
                "suppressed_count": 0,
                "snoozed_count": 0,
                "failed_count": 0,
                "reused_hash_count": 0,
                "full_hash_count": 0,
                "append_only_count": 0,
                "priority_counts": {"urgent": 0, "high": 0, "normal": 0, "low": 0},
                "poll_adaptation_counts": {
                    "always_on": 0,
                    "base": 0,
                    "burst": 0,
                    "hot": 0,
                    "idle_backoff": 0,
                    "snoozed": 0,
                    "suppressed": 0,
                },
                "artifact_path_count": 0,
                "warnings": [],
                "errors": [],
                "results": [],
            },
            "queue_counts_before": {},
            "queue_priority_counts_before": {"urgent": 0, "high": 0, "normal": 0, "low": 0},
            "queue_counts_after": self._queue_counts(),
            "queue_priority_counts_after": self._queue_priority_counts(),
            "queue_stage_age_stats_before": {
                stage: {"oldest_age_seconds": 0, "aged_job_count_soft": 0, "aged_job_count_hard": 0}
                for stage in self.stage_filter
            },
            "queue_total_before": 0,
            "queue_total_after": sum(self._queue_counts().values()),
            "stage_budget_mode": "idle",
            "stage_budget_plan": {stage: 0 for stage in self.stage_filter},
            "fairness_stage": "",
            "last_result": {
                "ok": True,
                "executed": False,
                "reason": "never_ran",
                "processed_job_count": 0,
                "completed_job_count": 0,
                "failed_job_count": 0,
                "remaining_queue_count": sum(self._queue_counts().values()),
                "warning_count": 0,
                "error_count": 0,
                "artifact_path_count": 0,
                "cleanup_removed_count": 0,
                "cleanup_removed_bytes": 0,
                "processed_priority_counts": {"urgent": 0, "high": 0, "normal": 0, "low": 0},
                "stage_budget_mode": "idle",
                "stage_budget_plan": {stage: 0 for stage in self.stage_filter},
                "fairness_stage": "",
                "warnings": [],
                "errors": [],
            },
            "output_root": str(self.output_root),
            "workspace_root": str(self.workspace_root),
            "database_path": str(self.database_file),
            "case_id": self.case_id,
            "stage_filter": list(self.stage_filter),
            "max_jobs": self.max_jobs,
            "poll_interval_seconds": self.poll_interval,
            "cleanup_policy": self._cleanup_policy(),
            "cleanup": self._default_cleanup_summary(),
            "tuning": self.tuning,
            "watch_tuning_profiles": self._watch_tuning_profiles(),
            "automation": _default_monitor_automation(
                mode=str(self.tuning.get("automation_mode") or DEFAULT_AUTOMATION_MODE)
            ),
            "forecast": _default_monitor_forecast(),
            "status_path": str(self.status_path),
            "history_path": str(self.history_path),
            "monitor_dir": str(self.status_path.parent),
            "watcher_id": self.watcher_id,
            "watcher_summary": self.store.watcher_summary(case_id=self.case_id),
            "watchers": self._load_watcher_states(),
            "watched_source_summary": self.store.watched_source_summary(case_id=self.case_id),
            "watched_sources": self._load_watched_sources(),
        }

    def _cleanup_policy(self) -> dict[str, object]:
        return {
            "enabled": bool(
                self.cleanup_completed_days > 0.0
                or self.cleanup_failed_days > 0.0
                or self.cleanup_watch_delta_days > 0.0
            ),
            "cleanup_completed_days": self.cleanup_completed_days,
            "cleanup_failed_days": self.cleanup_failed_days,
            "cleanup_watch_delta_days": self.cleanup_watch_delta_days,
            "workspace_scoped_only": True,
        }

    def _default_cleanup_summary(self) -> dict[str, object]:
        return {
            "configured": bool(self._cleanup_policy()["enabled"]),
            "executed": False,
            "skipped": not bool(self._cleanup_policy()["enabled"]),
            "reason": "not_configured" if not bool(self._cleanup_policy()["enabled"]) else "pending",
            "removed_count": 0,
            "removed_bytes": 0,
            "report_path": "",
            "artifact_paths": [],
            "categories": {},
            "warnings": [],
            "errors": [],
            "metrics": {
                "candidate_count": 0,
                "candidate_bytes": 0,
                "removed_count": 0,
                "removed_bytes": 0,
                "warning_count": 0,
                "error_count": 0,
            },
        }

    def _run_cleanup_cycle(self) -> dict[str, object]:
        policy = self._cleanup_policy()
        if not bool(policy.get("enabled")):
            return self._default_cleanup_summary()
        if self.case_id:
            return {
                **self._default_cleanup_summary(),
                "configured": True,
                "executed": False,
                "skipped": True,
                "reason": "case_scoped_skip",
            }

        payload = self.app.cleanup_workspace(
            output_root=str(self.output_root),
            queue_completed_max_age_seconds=self.cleanup_completed_days * 86400.0,
            queue_failed_max_age_seconds=self.cleanup_failed_days * 86400.0,
            watch_delta_max_age_seconds=self.cleanup_watch_delta_days * 86400.0,
            dry_run=False,
        )
        cleanup_payload = dict(payload.get("cleanup") or {})
        return {
            "configured": True,
            "executed": True,
            "skipped": False,
            "reason": "completed" if bool(payload.get("ok", False)) else "failed",
            "removed_count": int(dict(payload.get("metrics") or {}).get("removed_count") or 0),
            "removed_bytes": int(dict(payload.get("metrics") or {}).get("removed_bytes") or 0),
            "report_path": str(cleanup_payload.get("report_path") or ""),
            "artifact_paths": list(payload.get("artifact_paths") or []),
            "categories": dict(cleanup_payload.get("categories") or {}),
            "warnings": list(payload.get("warnings") or []),
            "errors": list(payload.get("errors") or []),
            "metrics": dict(payload.get("metrics") or {}),
        }

    def _load_watcher_states(self) -> list[dict[str, object]]:
        return self.store.fetch_watcher_states(case_id=self.case_id, limit=100)

    def _current_watcher_state(self) -> dict[str, object]:
        for watcher in self._load_watcher_states():
            if str(watcher.get("watcher_id") or "") == self.watcher_id:
                return watcher
        return {}

    def _load_watched_sources(self) -> list[dict[str, object]]:
        return self.store.fetch_watched_sources(case_id=self.case_id, limit=100)

    def _run_registered_source_checks(self) -> dict[str, object]:
        watched_sources = self.store.fetch_watched_sources(case_id=self.case_id, enabled_only=True, limit=500)
        results: list[dict[str, object]] = []
        warnings: list[str] = []
        errors: list[str] = []
        artifact_path_count = 0
        executed_check_count = 0
        changed_count = 0
        ingested_count = 0
        skipped_count = 0
        cooldown_skip_count = 0
        suppressed_count = 0
        snoozed_count = 0
        failed_count = 0
        reused_hash_count = 0
        full_hash_count = 0
        append_only_count = 0
        priority_counts = {"urgent": 0, "high": 0, "normal": 0, "low": 0}
        poll_adaptation_counts = {
            "always_on": 0,
            "base": 0,
            "burst": 0,
            "hot": 0,
            "idle_backoff": 0,
            "snoozed": 0,
            "suppressed": 0,
        }

        for row in watched_sources:
            watch_id = str(row.get("watch_id") or "")
            tuning_profile = normalize_watch_tuning_profile(dict(row.get("tuning_profile") or {}))
            watcher = self._source_monitor_state_for_row(row)
            poll_schedule = self._watched_source_schedule(row=row, watcher=watcher)
            poll_adaptation = str(poll_schedule.get("poll_adaptation") or "base")
            if poll_adaptation not in poll_adaptation_counts:
                poll_adaptation = "base"
            poll_adaptation_counts[poll_adaptation] += 1
            if not bool(poll_schedule.get("due")):
                if poll_adaptation == "snoozed":
                    snoozed_count += 1
                else:
                    cooldown_skip_count += 1
                if poll_adaptation == "suppressed":
                    suppressed_count += 1
                suppression_remaining_seconds = float(poll_schedule.get("suppression_remaining_seconds") or 0.0)
                results.append(
                    {
                        "watch_id": watch_id,
                        "locator": str(row.get("locator") or ""),
                        "source_type": str(row.get("source_type") or ""),
                        "ok": True,
                        "executed": False,
                        "reason": (
                            "snoozed"
                            if poll_adaptation == "snoozed"
                            else ("suppressed" if poll_adaptation == "suppressed" else "cooldown")
                        ),
                        "changed": False,
                        "ingested": False,
                        "skipped": True,
                        "enabled": bool(row.get("enabled", True)),
                        "notes": str(row.get("notes") or ""),
                        "tags": list(row.get("tags") or []),
                        "tuning_profile": tuning_profile,
                        "priority_label": str(watcher.get("triage_priority") or "low"),
                        "priority_score": int(watcher.get("triage_score") or 0),
                        "base_poll_interval_seconds": float(poll_schedule.get("base_poll_interval_seconds") or 0.0),
                        "effective_poll_interval_seconds": float(poll_schedule.get("effective_poll_interval_seconds") or 0.0),
                        "cooldown_remaining_seconds": float(poll_schedule.get("cooldown_remaining_seconds") or 0.0),
                        "snooze_until": str(poll_schedule.get("snooze_until") or ""),
                        "snooze_remaining_seconds": float(poll_schedule.get("snooze_remaining_seconds") or 0.0),
                        "suppressed_until": str(poll_schedule.get("suppressed_until") or ""),
                        "suppression_remaining_seconds": suppression_remaining_seconds,
                        "snoozed": poll_adaptation == "snoozed",
                        "suppressed": poll_adaptation == "suppressed",
                        "burst_mode": poll_adaptation == "burst",
                        "burst_change_streak": int(watcher.get("burst_change_streak") or 0),
                        "poll_adaptation": poll_adaptation,
                    }
                )
                continue

            executed_check_count += 1
            payload = self.app.watch_source(
                IngestRequest(
                    source_type=str(row.get("source_type") or ""),
                    locator=str(row.get("locator") or ""),
                    display_name=str(row.get("display_name") or ""),
                    options={"recursive": bool(row.get("recursive"))},
                ),
                case_id=str(row.get("case_id") or ""),
                output_root=str(self.output_root),
                workspace_root=str(self.workspace_root),
                database_path=str(self.database_file),
            )
            artifact_path_count += len(list(payload.get("artifact_paths") or []))
            reused_hash_count += int(dict(payload.get("metrics") or {}).get("reused_hash_count") or 0)
            full_hash_count += int(dict(payload.get("metrics") or {}).get("full_hash_count") or 0)
            append_only_count += int(dict(payload.get("metrics") or {}).get("append_only_file_count") or 0)
            priority_label = str(dict(payload.get("metrics") or {}).get("triage_priority") or "").strip().lower()
            if priority_label not in priority_counts:
                priority_label = "low"
            priority_counts[priority_label] += 1
            updated_watcher = dict(payload.get("watcher_state") or self._source_monitor_state_for_row(row))
            next_poll_schedule = self._watched_source_schedule(row=row, watcher=updated_watcher)
            warnings.extend(
                warning
                for warning in list(payload.get("warnings") or [])
                if warning not in warnings
            )
            errors.extend(
                error
                for error in list(payload.get("errors") or [])
                if error not in errors
            )
            if bool(payload.get("changed")):
                changed_count += 1
            if bool(payload.get("ingested")):
                ingested_count += 1
            if bool(payload.get("skipped")):
                skipped_count += 1
            if not bool(payload.get("ok")):
                failed_count += 1
            results.append(
                {
                    "watch_id": watch_id,
                    "locator": str(row.get("locator") or ""),
                    "source_type": str(row.get("source_type") or ""),
                    "ok": bool(payload.get("ok")),
                    "executed": True,
                    "reason": "changed" if bool(payload.get("changed")) else ("skipped" if bool(payload.get("skipped")) else "checked"),
                    "changed": bool(payload.get("changed")),
                    "ingested": bool(payload.get("ingested")),
                    "skipped": bool(payload.get("skipped")),
                    "enabled": bool(row.get("enabled", True)),
                    "notes": str(row.get("notes") or ""),
                    "tags": list(row.get("tags") or []),
                    "tuning_profile": tuning_profile,
                    "change_kind": str(dict(payload.get("metrics") or {}).get("change_kind") or ""),
                    "priority_label": priority_label,
                    "priority_score": int(dict(payload.get("metrics") or {}).get("triage_score") or 0),
                    "delta_ingest": bool(dict(payload.get("metrics") or {}).get("delta_ingest")),
                    "base_poll_interval_seconds": float(poll_schedule.get("base_poll_interval_seconds") or 0.0),
                    "effective_poll_interval_seconds": float(poll_schedule.get("effective_poll_interval_seconds") or 0.0),
                    "next_effective_poll_interval_seconds": float(next_poll_schedule.get("effective_poll_interval_seconds") or 0.0),
                    "cooldown_remaining_seconds": float(next_poll_schedule.get("cooldown_remaining_seconds") or 0.0),
                    "snooze_until": str(row.get("snooze_until") or ""),
                    "snooze_remaining_seconds": float(next_poll_schedule.get("snooze_remaining_seconds") or 0.0),
                    "suppressed_until": str(updated_watcher.get("suppression_until") or ""),
                    "suppression_remaining_seconds": float(next_poll_schedule.get("suppression_remaining_seconds") or 0.0),
                    "snoozed": str(next_poll_schedule.get("poll_adaptation") or "") == "snoozed",
                    "suppressed": str(next_poll_schedule.get("poll_adaptation") or "") == "suppressed",
                    "burst_mode": poll_adaptation == "burst" or str(next_poll_schedule.get("poll_adaptation") or "") == "burst",
                    "burst_change_streak": int(updated_watcher.get("burst_change_streak") or 0),
                    "poll_adaptation": poll_adaptation,
                    "next_poll_adaptation": str(next_poll_schedule.get("poll_adaptation") or "base"),
                    "errors": list(payload.get("errors") or []),
                }
            )

        return {
            "registered_count": len(watched_sources),
            "eligible_count": len(watched_sources),
            "executed_check_count": executed_check_count,
            "changed_count": changed_count,
            "ingested_count": ingested_count,
            "skipped_count": skipped_count,
            "cooldown_skip_count": cooldown_skip_count,
            "suppressed_count": suppressed_count,
            "snoozed_count": snoozed_count,
            "failed_count": failed_count,
            "reused_hash_count": reused_hash_count,
            "full_hash_count": full_hash_count,
            "append_only_count": append_only_count,
            "priority_counts": priority_counts,
            "poll_adaptation_counts": poll_adaptation_counts,
            "artifact_path_count": artifact_path_count,
            "warnings": warnings,
            "errors": errors,
            "results": results,
        }

    def _watch_tuning_profiles(self) -> dict[str, dict[str, object]]:
        rows = self.store.fetch_watched_sources(case_id=self.case_id, limit=500)
        return {
            str(row.get("watch_id") or ""): normalize_watch_tuning_profile(dict(row.get("tuning_profile") or {}))
            for row in rows
            if str(row.get("watch_id") or "").strip()
        }

    def _watched_source_due(self, row: dict[str, object]) -> bool:
        watcher = self._source_monitor_state_for_row(row)
        return bool(self._watched_source_schedule(row=row, watcher=watcher).get("due"))

    def _source_monitor_state_for_row(self, row: dict[str, object]) -> dict[str, object]:
        watcher_id = stable_record_id(
            "watcher",
            "source_monitor",
            str(row.get("case_id") or ""),
            str(row.get("source_type") or ""),
            str(row.get("locator") or ""),
            str(bool(row.get("recursive"))),
        )
        watchers = self.store.fetch_watcher_states(
            case_id=str(row.get("case_id") or ""),
            watcher_id=watcher_id,
            watcher_type="source_monitor",
            limit=1,
        )
        return watchers[0] if watchers else {}

    def _watched_source_schedule(
        self,
        *,
        row: dict[str, object],
        watcher: dict[str, object],
    ) -> dict[str, object]:
        base_interval = max(0.0, float(row.get("poll_interval_seconds") or 0.0))
        now = datetime.now(timezone.utc)
        snooze_until = _parse_utc_timestamp(str(row.get("snooze_until") or ""))
        if snooze_until is not None:
            snooze_remaining_seconds = max(0.0, (snooze_until - now).total_seconds())
            if snooze_remaining_seconds > 0.0:
                return {
                    "base_poll_interval_seconds": base_interval,
                    "effective_poll_interval_seconds": max(base_interval, snooze_remaining_seconds),
                    "cooldown_remaining_seconds": snooze_remaining_seconds,
                    "snooze_remaining_seconds": snooze_remaining_seconds,
                    "snooze_until": snooze_until.isoformat().replace("+00:00", "Z"),
                    "suppression_remaining_seconds": 0.0,
                    "suppressed_until": "",
                    "poll_adaptation": "snoozed",
                    "poll_factor": 1.0,
                    "due": False,
                }

        suppression_until = _parse_utc_timestamp(str(watcher.get("suppression_until") or ""))
        if suppression_until is not None:
            suppression_remaining_seconds = max(0.0, (suppression_until - now).total_seconds())
            if suppression_remaining_seconds > 0.0:
                return {
                    "base_poll_interval_seconds": base_interval,
                    "effective_poll_interval_seconds": max(base_interval, suppression_remaining_seconds),
                    "cooldown_remaining_seconds": suppression_remaining_seconds,
                    "snooze_remaining_seconds": 0.0,
                    "snooze_until": "",
                    "suppression_remaining_seconds": suppression_remaining_seconds,
                    "suppressed_until": suppression_until.isoformat().replace("+00:00", "Z"),
                    "poll_adaptation": "suppressed",
                    "poll_factor": 1.0,
                    "due": False,
                }

        if base_interval <= 0:
            return {
                "base_poll_interval_seconds": 0.0,
                "effective_poll_interval_seconds": 0.0,
                "cooldown_remaining_seconds": 0.0,
                "snooze_remaining_seconds": 0.0,
                "snooze_until": "",
                "suppression_remaining_seconds": 0.0,
                "suppressed_until": "",
                "poll_adaptation": "always_on",
                "poll_factor": 1.0,
                "due": True,
            }

        consecutive_no_change_count = int(watcher.get("consecutive_no_change_count") or 0)
        burst_change_streak = int(watcher.get("burst_change_streak") or 0)
        last_checked_at = _parse_utc_timestamp(str(watcher.get("last_checked_at") or ""))
        last_changed_at = _parse_utc_timestamp(str(watcher.get("last_changed_at") or ""))

        factor = 1.0
        poll_adaptation = "base"
        burst_window_seconds = max(BURST_POLL_LOOKBACK_MIN_SECONDS, int(base_interval * 3))
        hot_window_seconds = max(HOT_POLL_LOOKBACK_MIN_SECONDS, int(base_interval * 2))
        if (
            last_changed_at is not None
            and burst_change_streak >= BURST_CHANGE_STREAK_THRESHOLD
            and (now - last_changed_at).total_seconds() <= burst_window_seconds
        ):
            factor = BURST_POLL_INTERVAL_FACTOR
            poll_adaptation = "burst"
        elif (
            last_changed_at is not None
            and consecutive_no_change_count <= 1
            and (now - last_changed_at).total_seconds() <= hot_window_seconds
        ):
            factor = HOT_POLL_INTERVAL_FACTOR
            poll_adaptation = "hot"
        else:
            for threshold, candidate_factor in IDLE_POLL_BACKOFF_FACTORS:
                if consecutive_no_change_count >= threshold:
                    factor = candidate_factor
                    poll_adaptation = "idle_backoff"
                    break

        effective_interval = max(1.0, base_interval * factor)
        if last_checked_at is None:
            return {
                "base_poll_interval_seconds": base_interval,
                "effective_poll_interval_seconds": effective_interval,
                "cooldown_remaining_seconds": 0.0,
                "snooze_remaining_seconds": 0.0,
                "snooze_until": "",
                "suppression_remaining_seconds": 0.0,
                "suppressed_until": "",
                "poll_adaptation": poll_adaptation,
                "poll_factor": factor,
                "due": True,
            }

        elapsed_seconds = max(0.0, (now - last_checked_at).total_seconds())
        cooldown_remaining_seconds = max(0.0, effective_interval - elapsed_seconds)
        return {
            "base_poll_interval_seconds": base_interval,
            "effective_poll_interval_seconds": effective_interval,
            "cooldown_remaining_seconds": cooldown_remaining_seconds,
            "snooze_remaining_seconds": 0.0,
            "snooze_until": "",
            "suppression_remaining_seconds": 0.0,
            "suppressed_until": "",
            "poll_adaptation": poll_adaptation,
            "poll_factor": factor,
            "due": elapsed_seconds >= effective_interval,
        }

    @staticmethod
    def _normalize_stages(stages: tuple[str, ...] | list[str] | object) -> tuple[str, ...]:
        values = [stages] if isinstance(stages, str) else list(stages or ())
        rows: list[str] = []
        seen: set[str] = set()
        for value in values:
            text = str(value or "").strip().lower()
            if not text or text in seen:
                continue
            if text not in QUEUE_STAGE_ORDER:
                raise ValueError(f"unsupported queue stage: {text}")
            seen.add(text)
            rows.append(text)
        return tuple(rows)


def _parse_utc_timestamp(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _allocate_stage_budgets(
    *,
    total_budget: int,
    stage_order: tuple[str, ...],
    stage_counts: dict[str, int],
    stage_weights: dict[str, int],
) -> dict[str, int]:
    budgets = {stage: 0 for stage in stage_order}
    active = [stage for stage in stage_order if int(stage_counts.get(stage) or 0) > 0]
    if total_budget <= 0 or not active:
        return budgets

    ordered = sorted(
        active,
        key=lambda stage: (-int(stage_weights.get(stage) or 0), stage_order.index(stage)),
    )
    remaining = total_budget
    for stage in ordered:
        if remaining <= 0:
            break
        budgets[stage] += 1
        remaining -= 1
    if remaining <= 0:
        return budgets

    total_weight = sum(max(1, int(stage_weights.get(stage) or 1)) for stage in active)
    remainders: list[tuple[float, str]] = []
    for stage in active:
        weight = max(1, int(stage_weights.get(stage) or 1))
        raw_share = remaining * (weight / total_weight)
        extra = int(raw_share)
        budgets[stage] += extra
        remainders.append((raw_share - extra, stage))
    used = sum(budgets.values())
    leftover = max(0, total_budget - used)
    for _fraction, stage in sorted(remainders, key=lambda item: (-item[0], stage_order.index(item[1]))):
        if leftover <= 0:
            break
        budgets[stage] += 1
        leftover -= 1
    return budgets


def _merge_priority_counts(target: dict[str, int], source: dict[str, object]) -> None:
    for label in ("urgent", "high", "normal", "low"):
        target[label] = int(target.get(label, 0)) + int(source.get(label) or 0)
