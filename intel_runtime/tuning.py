from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from intel_core import utc_now
from intel_storage import ensure_workspace_layout

DEFAULT_MONITOR_TUNING_NAME = "monitor_tuning.json"
DEFAULT_FORECAST_MIN_HISTORY = 3
DEFAULT_QUEUE_SPIKE_FACTOR = 1.75
DEFAULT_SOURCE_CHURN_SPIKE_FACTOR = 2.0
DEFAULT_THROUGHPUT_DROP_FACTOR = 0.5
DEFAULT_ALERT_SEVERITY = "warning"
DEFAULT_MONITOR_TUNING_PRESET = "balanced"
DEFAULT_WATCH_TUNING_PRESET = "source:default"
DEFAULT_AUTOMATION_MODE = "recommend"
VALID_ALERT_SEVERITIES = {"info", "warning", "critical"}
VALID_AUTOMATION_MODES = {"off", "recommend", "apply"}
VALID_STAGE_THRESHOLD_KEYS = {
    "queue_spike_factor",
    "throughput_drop_factor",
}

MONITOR_TUNING_PRESETS: dict[str, dict[str, object]] = {
    "balanced": {
        "label": "Balanced",
        "description": "General-purpose passive monitoring defaults.",
        "forecast_min_history": DEFAULT_FORECAST_MIN_HISTORY,
        "queue_spike_factor": DEFAULT_QUEUE_SPIKE_FACTOR,
        "source_churn_spike_factor": DEFAULT_SOURCE_CHURN_SPIKE_FACTOR,
        "throughput_drop_factor": DEFAULT_THROUGHPUT_DROP_FACTOR,
    },
    "collection_first": {
        "label": "Collection First",
        "description": "Bias monitor sensitivity toward intake pressure while tolerating slower downstream drain.",
        "forecast_min_history": 4,
        "queue_spike_factor": 2.0,
        "source_churn_spike_factor": 2.5,
        "throughput_drop_factor": 0.4,
    },
    "quiet": {
        "label": "Quiet",
        "description": "Reduce alert noise for slow-moving or low-change cases.",
        "forecast_min_history": 5,
        "queue_spike_factor": 2.25,
        "source_churn_spike_factor": 3.0,
        "throughput_drop_factor": 0.35,
    },
}

WATCH_TUNING_PRESETS: dict[str, dict[str, object]] = {
    "source:default": {
        "label": "Source Default",
        "description": "Inherit case-wide churn sensitivity without adding source-specific overrides.",
        "forecast_min_history": 0,
        "source_churn_spike_factor": 0.0,
        "suppressed_alert_ids": [],
    },
    "source:file": {
        "label": "File",
        "description": "Stable-file preset with more conservative churn sensitivity.",
        "forecast_min_history": 4,
        "source_churn_spike_factor": 3.0,
        "suppressed_alert_ids": [],
    },
    "source:directory": {
        "label": "Directory",
        "description": "Directory preset that expects moderate change across nested artifacts.",
        "forecast_min_history": 4,
        "source_churn_spike_factor": 2.5,
        "suppressed_alert_ids": [],
    },
    "source:log": {
        "label": "Log",
        "description": "Append-heavy preset tuned for frequently changing logs.",
        "forecast_min_history": 2,
        "source_churn_spike_factor": 1.5,
        "suppressed_alert_ids": [],
    },
    "source:pcap": {
        "label": "Capture",
        "description": "High-activity preset for packet captures and live capture artifacts.",
        "forecast_min_history": 2,
        "source_churn_spike_factor": 1.5,
        "suppressed_alert_ids": [],
    },
    "source:system": {
        "label": "System Artifact",
        "description": "Moderate preset for databases, plists, registry hives, and event logs.",
        "forecast_min_history": 3,
        "source_churn_spike_factor": 2.0,
        "suppressed_alert_ids": [],
    },
}

WATCH_SOURCE_TYPE_PRESET_NAMES: dict[str, str] = {
    "file": "source:file",
    "directory": "source:directory",
    "log": "source:log",
    "log-bundle": "source:log",
    "pcap": "source:pcap",
    "pcapng": "source:pcap",
    "wifi-capture": "source:pcap",
    "system-artifact": "source:system",
    "system-artifact-bundle": "source:system",
}


def default_preset_automation_state() -> dict[str, object]:
    return {
        "last_automation_applied_at": "",
        "last_automation_preset_name": "",
        "last_automation_direction": "",
        "last_automation_reason": "",
        "last_manual_change_at": "",
        "last_manual_preset_name": "",
        "manual_override_active": False,
    }


def normalize_preset_automation_state(payload: dict[str, object] | None) -> dict[str, object]:
    source = dict(payload or {})
    base = default_preset_automation_state()
    return {
        **base,
        "last_automation_applied_at": str(source.get("last_automation_applied_at") or "").strip(),
        "last_automation_preset_name": str(source.get("last_automation_preset_name") or "").strip(),
        "last_automation_direction": str(source.get("last_automation_direction") or "").strip(),
        "last_automation_reason": str(source.get("last_automation_reason") or "").strip(),
        "last_manual_change_at": str(source.get("last_manual_change_at") or "").strip(),
        "last_manual_preset_name": str(source.get("last_manual_preset_name") or "").strip(),
        "manual_override_active": bool(source.get("manual_override_active")),
    }


def default_watch_tuning_profile(*, preset_name: str = "") -> dict[str, object]:
    return {
        "preset_name": _normalize_watch_preset_name(preset_name),
        "forecast_min_history": 0,
        "source_churn_spike_factor": 0.0,
        "suppressed_alert_ids": [],
        "updated_at": "",
    }


def default_monitor_tuning(*, case_id: str = "", preset_name: str = DEFAULT_MONITOR_TUNING_PRESET) -> dict[str, object]:
    normalized_preset_name = _normalize_monitor_preset_name(preset_name)
    preset = dict(MONITOR_TUNING_PRESETS.get(normalized_preset_name) or MONITOR_TUNING_PRESETS[DEFAULT_MONITOR_TUNING_PRESET])
    return {
        "schema_version": 1,
        "case_id": str(case_id or "").strip(),
        "preset_name": normalized_preset_name,
        "automation_mode": DEFAULT_AUTOMATION_MODE,
        "forecast_min_history": int(preset.get("forecast_min_history") or DEFAULT_FORECAST_MIN_HISTORY),
        "queue_spike_factor": float(preset.get("queue_spike_factor") or DEFAULT_QUEUE_SPIKE_FACTOR),
        "source_churn_spike_factor": float(preset.get("source_churn_spike_factor") or DEFAULT_SOURCE_CHURN_SPIKE_FACTOR),
        "throughput_drop_factor": float(preset.get("throughput_drop_factor") or DEFAULT_THROUGHPUT_DROP_FACTOR),
        "suppressed_alert_ids": [],
        "suppressed_stage_alerts": {},
        "suppressed_watch_alerts": {},
        "alert_severity_overrides": {},
        "stage_threshold_overrides": {},
        "automation_state": default_preset_automation_state(),
        "updated_at": "",
    }


def normalize_monitor_tuning(payload: dict[str, object] | None, *, case_id: str = "") -> dict[str, object]:
    source = dict(payload or {})
    base = default_monitor_tuning(
        case_id=case_id,
        preset_name=_normalize_monitor_preset_name(source.get("preset_name") or DEFAULT_MONITOR_TUNING_PRESET),
    )
    suppressed_stage_alerts = _normalize_nested_alert_map(source.get("suppressed_stage_alerts"))
    suppressed_watch_alerts = _normalize_nested_alert_map(source.get("suppressed_watch_alerts"))
    alert_severity_overrides = _normalize_alert_severity_overrides(source.get("alert_severity_overrides"))
    stage_threshold_overrides = _normalize_stage_threshold_overrides(source.get("stage_threshold_overrides"))
    return {
        **base,
        "preset_name": _normalize_monitor_preset_name(source.get("preset_name") or base["preset_name"]),
        "automation_mode": _normalize_automation_mode(source.get("automation_mode") or base["automation_mode"]),
        "forecast_min_history": max(1, int(source.get("forecast_min_history") or base["forecast_min_history"])),
        "queue_spike_factor": max(1.0, float(source.get("queue_spike_factor") or base["queue_spike_factor"])),
        "source_churn_spike_factor": max(
            1.0,
            float(source.get("source_churn_spike_factor") or base["source_churn_spike_factor"]),
        ),
        "throughput_drop_factor": min(
            1.0,
            max(0.1, float(source.get("throughput_drop_factor") or base["throughput_drop_factor"])),
        ),
        "suppressed_alert_ids": _normalize_alert_list(source.get("suppressed_alert_ids")),
        "suppressed_stage_alerts": suppressed_stage_alerts,
        "suppressed_watch_alerts": suppressed_watch_alerts,
        "alert_severity_overrides": alert_severity_overrides,
        "stage_threshold_overrides": stage_threshold_overrides,
        "automation_state": normalize_preset_automation_state(source.get("automation_state")),
        "updated_at": str(source.get("updated_at") or "").strip(),
    }


def normalize_watch_tuning_profile(payload: dict[str, object] | None) -> dict[str, object]:
    source = dict(payload or {})
    base = default_watch_tuning_profile(preset_name=source.get("preset_name") or "")
    forecast_min_history = 0
    if source.get("forecast_min_history") not in {None, ""}:
        try:
            requested_forecast_min_history = int(source.get("forecast_min_history") or 0)
        except (TypeError, ValueError):
            requested_forecast_min_history = 0
        forecast_min_history = max(1, requested_forecast_min_history) if requested_forecast_min_history > 0 else 0
    source_churn_spike_factor = 0.0
    if source.get("source_churn_spike_factor") not in {None, ""}:
        try:
            requested_source_churn_spike_factor = float(source.get("source_churn_spike_factor") or 0.0)
        except (TypeError, ValueError):
            requested_source_churn_spike_factor = 0.0
        source_churn_spike_factor = (
            max(1.0, requested_source_churn_spike_factor)
            if requested_source_churn_spike_factor > 0.0
            else 0.0
        )
    return {
        **base,
        "preset_name": _normalize_watch_preset_name(source.get("preset_name") or base["preset_name"]),
        "forecast_min_history": forecast_min_history,
        "source_churn_spike_factor": source_churn_spike_factor,
        "suppressed_alert_ids": _normalize_alert_list(source.get("suppressed_alert_ids")),
        "updated_at": str(source.get("updated_at") or "").strip(),
    }


def apply_monitor_tuning_preset(name: str, *, case_id: str = "") -> dict[str, object]:
    preset_name = _normalize_monitor_preset_name(name)
    return default_monitor_tuning(case_id=case_id, preset_name=preset_name)


def apply_watch_tuning_preset(name: str) -> dict[str, object]:
    preset_name = _normalize_watch_preset_name(name) or DEFAULT_WATCH_TUNING_PRESET
    preset = dict(WATCH_TUNING_PRESETS.get(preset_name) or WATCH_TUNING_PRESETS[DEFAULT_WATCH_TUNING_PRESET])
    return normalize_watch_tuning_profile(
        {
            "preset_name": preset_name,
            "forecast_min_history": int(preset.get("forecast_min_history") or 0),
            "source_churn_spike_factor": float(preset.get("source_churn_spike_factor") or 0.0),
            "suppressed_alert_ids": list(preset.get("suppressed_alert_ids") or []),
            "updated_at": "",
        }
    )


def monitor_tuning_presets() -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "name": name,
            "label": str(payload.get("label") or name),
            "description": str(payload.get("description") or ""),
            "tuning": default_monitor_tuning(case_id="", preset_name=name),
        }
        for name, payload in MONITOR_TUNING_PRESETS.items()
    )


def monitor_automation_modes() -> tuple[str, ...]:
    return ("off", "recommend", "apply")


def watch_tuning_presets() -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "name": name,
            "label": str(payload.get("label") or name),
            "description": str(payload.get("description") or ""),
            "tuning_profile": apply_watch_tuning_preset(name),
        }
        for name, payload in WATCH_TUNING_PRESETS.items()
    )


def watch_tuning_preset_name_for_source_type(source_type: str) -> str:
    normalized_source_type = str(source_type or "").strip().lower()
    return str(WATCH_SOURCE_TYPE_PRESET_NAMES.get(normalized_source_type) or DEFAULT_WATCH_TUNING_PRESET)


def load_monitor_tuning(output_root: str | Path, *, case_id: str = "") -> dict[str, object]:
    root = ensure_workspace_layout(output_root)["root"]
    path = (root / "monitor" / DEFAULT_MONITOR_TUNING_NAME).resolve()
    requested_case_id = str(case_id or "").strip()
    raw = _read_tuning_file(path)
    default_payload = normalize_monitor_tuning(dict(raw.get("default") or {}), case_id="")
    if not requested_case_id:
        return default_payload
    case_payload = dict(dict(raw.get("cases") or {}).get(requested_case_id) or {})
    merged = {
        **default_payload,
        **case_payload,
        "suppressed_alert_ids": case_payload.get("suppressed_alert_ids", default_payload["suppressed_alert_ids"]),
        "suppressed_stage_alerts": case_payload.get("suppressed_stage_alerts", default_payload["suppressed_stage_alerts"]),
        "suppressed_watch_alerts": case_payload.get("suppressed_watch_alerts", default_payload["suppressed_watch_alerts"]),
        "alert_severity_overrides": case_payload.get(
            "alert_severity_overrides",
            default_payload["alert_severity_overrides"],
        ),
        "stage_threshold_overrides": case_payload.get(
            "stage_threshold_overrides",
            default_payload["stage_threshold_overrides"],
        ),
    }
    return normalize_monitor_tuning(merged, case_id=requested_case_id)


def update_monitor_tuning(
    output_root: str | Path,
    *,
    case_id: str = "",
    updates: dict[str, object] | None = None,
) -> dict[str, object]:
    root = ensure_workspace_layout(output_root)["root"]
    monitor_dir = (root / "monitor").resolve()
    monitor_dir.mkdir(parents=True, exist_ok=True)
    path = (monitor_dir / DEFAULT_MONITOR_TUNING_NAME).resolve()
    raw = _read_tuning_file(path)
    normalized_updates = dict(updates or {})
    requested_case_id = str(case_id or "").strip()

    if requested_case_id:
        existing = load_monitor_tuning(root, case_id=requested_case_id)
        merged = normalize_monitor_tuning({**existing, **normalized_updates, "updated_at": utc_now()}, case_id=requested_case_id)
        cases = dict(raw.get("cases") or {})
        cases[requested_case_id] = merged
        document = {
            "schema_version": 1,
            "updated_at": utc_now(),
            "default": normalize_monitor_tuning(dict(raw.get("default") or {}), case_id=""),
            "cases": cases,
        }
    else:
        existing = load_monitor_tuning(root, case_id="")
        merged = normalize_monitor_tuning({**existing, **normalized_updates, "updated_at": utc_now()}, case_id="")
        document = {
            "schema_version": 1,
            "updated_at": utc_now(),
            "default": merged,
            "cases": dict(raw.get("cases") or {}),
        }

    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return merged


def _read_tuning_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "schema_version": 1,
            "updated_at": "",
            "default": default_monitor_tuning(case_id=""),
            "cases": {},
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "schema_version": 1,
            "updated_at": "",
            "default": default_monitor_tuning(case_id=""),
            "cases": {},
        }
    if not isinstance(payload, dict):
        return {
            "schema_version": 1,
            "updated_at": "",
            "default": default_monitor_tuning(case_id=""),
            "cases": {},
        }
    return payload


def _normalize_alert_list(value: object) -> list[str]:
    values = value if isinstance(value, list) else ([value] if value not in {None, ""} else [])
    rows: list[str] = []
    for item in values:
        if isinstance(item, str):
            pieces = [piece.strip() for piece in item.replace(";", ",").split(",")]
        else:
            pieces = [str(item).strip()]
        for piece in pieces:
            if not piece or piece in rows:
                continue
            rows.append(piece)
    return rows


def _normalize_nested_alert_map(value: object) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        return {}
    rows: dict[str, list[str]] = {}
    for key, item in value.items():
        normalized_key = str(key or "").strip()
        if not normalized_key:
            continue
        alerts = _normalize_alert_list(item)
        if alerts:
            rows[normalized_key] = alerts
    return rows


def _normalize_alert_severity_overrides(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    rows: dict[str, str] = {}
    for key, item in value.items():
        normalized_key = str(key or "").strip()
        normalized_value = str(item or "").strip().lower()
        if not normalized_key or normalized_value not in VALID_ALERT_SEVERITIES:
            continue
        rows[normalized_key] = normalized_value
    return rows


def _normalize_stage_threshold_overrides(value: object) -> dict[str, dict[str, float]]:
    if not isinstance(value, dict):
        return {}
    rows: dict[str, dict[str, float]] = {}
    for key, item in value.items():
        normalized_key = str(key or "").strip()
        if not normalized_key or not isinstance(item, dict):
            continue
        normalized_item: dict[str, float] = {}
        for threshold_key, threshold_value in item.items():
            normalized_threshold_key = str(threshold_key or "").strip()
            if normalized_threshold_key not in VALID_STAGE_THRESHOLD_KEYS:
                continue
            try:
                numeric_value = float(threshold_value)
            except (TypeError, ValueError):
                continue
            if normalized_threshold_key == "queue_spike_factor":
                normalized_item[normalized_threshold_key] = max(1.0, numeric_value)
            elif normalized_threshold_key == "throughput_drop_factor":
                normalized_item[normalized_threshold_key] = min(1.0, max(0.1, numeric_value))
        if normalized_item:
            rows[normalized_key] = normalized_item
    return rows


def _normalize_monitor_preset_name(value: object) -> str:
    normalized = str(value or "").strip()
    if normalized in MONITOR_TUNING_PRESETS:
        return normalized
    return DEFAULT_MONITOR_TUNING_PRESET


def _normalize_watch_preset_name(value: object) -> str:
    normalized = str(value or "").strip()
    if normalized in WATCH_TUNING_PRESETS:
        return normalized
    return ""


def _normalize_automation_mode(value: object) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in VALID_AUTOMATION_MODES:
        return normalized
    return DEFAULT_AUTOMATION_MODE
