from __future__ import annotations

import json

from intel_runtime.tuning import (
    DEFAULT_MONITOR_TUNING_PRESET,
    DEFAULT_WATCH_TUNING_PRESET,
    apply_monitor_tuning_preset,
    apply_watch_tuning_preset,
    default_monitor_tuning,
    default_preset_automation_state,
    default_watch_tuning_profile,
    load_monitor_tuning,
    monitor_automation_modes,
    monitor_tuning_presets,
    normalize_monitor_tuning,
    normalize_preset_automation_state,
    normalize_watch_tuning_profile,
    update_monitor_tuning,
    watch_tuning_preset_name_for_source_type,
    watch_tuning_presets,
)


def test_default_monitor_tuning_includes_expected_defaults() -> None:
    payload = default_monitor_tuning(case_id="case-1")

    assert payload["case_id"] == "case-1"
    assert payload["preset_name"] == DEFAULT_MONITOR_TUNING_PRESET
    assert payload["automation_mode"] == "recommend"
    assert payload["automation_state"] == default_preset_automation_state()


def test_normalize_preset_automation_state_fills_defaults() -> None:
    payload = normalize_preset_automation_state(
        {
            "last_automation_applied_at": " 2026-04-08T12:00:00Z ",
            "last_automation_preset_name": " collection_first ",
            "manual_override_active": 1,
        }
    )

    assert payload["last_automation_applied_at"] == "2026-04-08T12:00:00Z"
    assert payload["last_automation_preset_name"] == "collection_first"
    assert payload["last_automation_direction"] == ""
    assert payload["last_manual_change_at"] == ""
    assert payload["manual_override_active"] is True


def test_normalize_monitor_tuning_clamps_and_normalizes_values() -> None:
    payload = normalize_monitor_tuning(
        {
            "preset_name": "not-a-real-preset",
            "automation_mode": "APPLY",
            "forecast_min_history": 0,
            "queue_spike_factor": 0.1,
            "source_churn_spike_factor": "0",
            "throughput_drop_factor": 9.0,
            "suppressed_alert_ids": "failure_burst, queue_pressure_spike; failure_burst",
            "suppressed_stage_alerts": {
                "extract": "queue_pressure_spike, queue_pressure_spike",
                "": "skip-me",
            },
            "suppressed_watch_alerts": {
                "watch-1": ["source_churn_spike", "source_churn_spike"],
                "": ["skip-me"],
            },
            "alert_severity_overrides": {
                "queue_pressure_spike": "CRITICAL",
                "ignore-me": "loud",
            },
            "stage_threshold_overrides": {
                "extract": {
                    "queue_spike_factor": 0.5,
                    "throughput_drop_factor": 0.01,
                    "ignore-me": 99,
                }
            },
            "automation_state": {
                "last_automation_preset_name": "collection_first",
                "manual_override_active": True,
            },
        },
        case_id="case-x",
    )

    assert payload["case_id"] == "case-x"
    assert payload["preset_name"] == DEFAULT_MONITOR_TUNING_PRESET
    assert payload["automation_mode"] == "apply"
    assert payload["forecast_min_history"] == 3
    assert payload["queue_spike_factor"] == 1.0
    assert payload["source_churn_spike_factor"] == 1.0
    assert payload["throughput_drop_factor"] == 1.0
    assert payload["suppressed_alert_ids"] == ["failure_burst", "queue_pressure_spike"]
    assert payload["suppressed_stage_alerts"] == {"extract": ["queue_pressure_spike"]}
    assert payload["suppressed_watch_alerts"] == {"watch-1": ["source_churn_spike"]}
    assert payload["alert_severity_overrides"] == {"queue_pressure_spike": "critical"}
    assert payload["stage_threshold_overrides"] == {
        "extract": {
            "queue_spike_factor": 1.0,
            "throughput_drop_factor": 0.1,
        }
    }
    assert payload["automation_state"]["last_automation_preset_name"] == "collection_first"
    assert payload["automation_state"]["manual_override_active"] is True


def test_normalize_watch_tuning_profile_clamps_and_deduplicates() -> None:
    payload = normalize_watch_tuning_profile(
        {
            "preset_name": "source:log",
            "forecast_min_history": "0",
            "source_churn_spike_factor": "0.2",
            "suppressed_alert_ids": "source_churn_spike, source_churn_spike; failure_burst",
            "updated_at": " 2026-04-08T12:00:00Z ",
        }
    )

    assert payload["preset_name"] == "source:log"
    assert payload["forecast_min_history"] == 0
    assert payload["source_churn_spike_factor"] == 1.0
    assert payload["suppressed_alert_ids"] == ["source_churn_spike", "failure_burst"]
    assert payload["updated_at"] == "2026-04-08T12:00:00Z"


def test_apply_monitor_tuning_preset_falls_back_to_balanced() -> None:
    payload = apply_monitor_tuning_preset("missing-preset", case_id="case-preset")

    assert payload["case_id"] == "case-preset"
    assert payload["preset_name"] == DEFAULT_MONITOR_TUNING_PRESET


def test_apply_watch_tuning_preset_falls_back_to_default() -> None:
    payload = apply_watch_tuning_preset("missing-preset")

    assert payload["preset_name"] == DEFAULT_WATCH_TUNING_PRESET
    assert payload["forecast_min_history"] == 0
    assert payload["source_churn_spike_factor"] == 0.0


def test_watch_tuning_preset_name_for_source_type_maps_expected_values() -> None:
    assert watch_tuning_preset_name_for_source_type("log") == "source:log"
    assert watch_tuning_preset_name_for_source_type("pcapng") == "source:pcap"
    assert watch_tuning_preset_name_for_source_type("system-artifact") == "source:system"
    assert watch_tuning_preset_name_for_source_type("unknown") == DEFAULT_WATCH_TUNING_PRESET


def test_update_monitor_tuning_persists_default_and_case_scopes(tmp_path) -> None:
    output_root = tmp_path / "out"

    default_payload = update_monitor_tuning(
        output_root,
        updates={
            "preset_name": "quiet",
            "suppressed_alert_ids": ["failure_burst"],
        },
    )
    case_payload = update_monitor_tuning(
        output_root,
        case_id="case-1",
        updates={
            "preset_name": "collection_first",
            "suppressed_stage_alerts": {"extract": ["queue_pressure_spike"]},
        },
    )

    loaded_default = load_monitor_tuning(output_root)
    loaded_case = load_monitor_tuning(output_root, case_id="case-1")
    loaded_other_case = load_monitor_tuning(output_root, case_id="case-2")

    assert default_payload["preset_name"] == "quiet"
    assert case_payload["preset_name"] == "collection_first"
    assert loaded_default["preset_name"] == "quiet"
    assert loaded_default["suppressed_alert_ids"] == ["failure_burst"]
    assert loaded_case["preset_name"] == "collection_first"
    assert loaded_case["suppressed_alert_ids"] == ["failure_burst"]
    assert loaded_case["suppressed_stage_alerts"] == {"extract": ["queue_pressure_spike"]}
    assert loaded_other_case["preset_name"] == "quiet"
    assert loaded_other_case["suppressed_alert_ids"] == ["failure_burst"]


def test_load_monitor_tuning_recovers_from_invalid_json(tmp_path) -> None:
    monitor_dir = tmp_path / "out" / "monitor"
    monitor_dir.mkdir(parents=True, exist_ok=True)
    (monitor_dir / "monitor_tuning.json").write_text("{not-json", encoding="utf-8")

    payload = load_monitor_tuning(tmp_path / "out", case_id="case-corrupt")

    assert payload["preset_name"] == DEFAULT_MONITOR_TUNING_PRESET
    assert payload["case_id"] == "case-corrupt"


def test_monitor_tuning_catalogs_expose_named_entries() -> None:
    preset_names = {item["name"] for item in monitor_tuning_presets()}
    automation_modes = set(monitor_automation_modes())

    assert {"balanced", "collection_first", "quiet"} <= preset_names
    assert automation_modes == {"off", "recommend", "apply"}


def test_watch_tuning_catalogs_expose_source_presets() -> None:
    preset_names = {item["name"] for item in watch_tuning_presets()}

    assert {"source:default", "source:file", "source:directory", "source:log", "source:pcap", "source:system"} <= preset_names


def test_default_watch_tuning_profile_is_empty_default() -> None:
    payload = default_watch_tuning_profile()

    assert payload["preset_name"] == ""
    assert payload["forecast_min_history"] == 0
    assert payload["source_churn_spike_factor"] == 0.0
    assert payload["suppressed_alert_ids"] == []


def test_update_monitor_tuning_writes_json_document(tmp_path) -> None:
    output_root = tmp_path / "out"
    update_monitor_tuning(
        output_root,
        updates={
            "preset_name": "collection_first",
            "alert_severity_overrides": {"queue_pressure_spike": "critical"},
        },
    )

    document = json.loads((output_root / "monitor" / "monitor_tuning.json").read_text(encoding="utf-8"))

    assert document["schema_version"] == 1
    assert document["default"]["preset_name"] == "collection_first"
    assert document["default"]["alert_severity_overrides"] == {"queue_pressure_spike": "critical"}
