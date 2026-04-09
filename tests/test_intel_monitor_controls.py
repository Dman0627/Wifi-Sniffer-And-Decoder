from __future__ import annotations

from intel_api import PlatformApp
from intel_core import IngestRequest


def test_platform_app_monitor_tuning_tracks_automation_and_manual_override_state(tmp_path) -> None:
    app = PlatformApp()
    output_root = str(tmp_path / "out")

    app.update_monitor_tuning(
        case_id="case-monitor",
        output_root=output_root,
        preset_name="collection_first",
        change_origin="automation",
        automation_direction="escalate",
        automation_reason="queue pressure",
    )
    payload = app.update_monitor_tuning(
        case_id="case-monitor",
        output_root=output_root,
        preset_name="quiet",
    )

    state = payload["tuning"]["automation_state"]

    assert payload["metrics"]["manual_override_active"] is True
    assert state["last_automation_preset_name"] == "collection_first"
    assert state["last_automation_direction"] == "escalate"
    assert state["last_automation_reason"] == "queue pressure"
    assert state["last_manual_preset_name"] == "quiet"
    assert state["manual_override_active"] is True


def test_platform_app_monitor_tuning_manual_change_back_to_automation_preset_clears_override(tmp_path) -> None:
    app = PlatformApp()
    output_root = str(tmp_path / "out")

    app.update_monitor_tuning(
        case_id="case-monitor",
        output_root=output_root,
        preset_name="collection_first",
        change_origin="automation",
        automation_direction="escalate",
        automation_reason="queue pressure",
    )
    payload = app.update_monitor_tuning(
        case_id="case-monitor",
        output_root=output_root,
        preset_name="collection_first",
    )

    state = payload["tuning"]["automation_state"]

    assert payload["metrics"]["manual_override_active"] is False
    assert state["last_automation_preset_name"] == "collection_first"
    assert state["manual_override_active"] is False


def test_platform_app_watch_settings_track_automation_and_manual_override_state(tmp_path) -> None:
    app = PlatformApp()
    watched_log = tmp_path / "watched.log"
    watched_log.write_text("line1\n", encoding="utf-8")
    output_root = str(tmp_path / "out")

    register_payload = app.register_watch_source(
        IngestRequest(source_type="log", locator=str(watched_log)),
        case_id="case-watch",
        output_root=output_root,
        workspace_root=str(tmp_path),
    )
    watch_id = str(register_payload["watched_source"]["watch_id"])
    app.update_watch_source_settings(
        case_id="case-watch",
        watch_id=watch_id,
        clear_tuning_profile=True,
        output_root=output_root,
    )
    app.update_watch_source_settings(
        case_id="case-watch",
        watch_id=watch_id,
        tuning_preset_name="source:log",
        change_origin="automation",
        automation_direction="escalate",
        automation_reason="append-heavy log",
        output_root=output_root,
    )
    payload = app.update_watch_source_settings(
        case_id="case-watch",
        watch_id=watch_id,
        tuning_preset_name="source:pcap",
        output_root=output_root,
    )

    state = payload["watched_source"]["automation_state"]

    assert payload["metrics"]["watch_profile_manual_override_active"] is True
    assert state["last_automation_preset_name"] == "source:log"
    assert state["last_automation_direction"] == "escalate"
    assert state["last_automation_reason"] == "append-heavy log"
    assert state["last_manual_preset_name"] == "source:pcap"
    assert state["manual_override_active"] is True


def test_platform_app_watch_settings_manual_change_back_to_last_automation_preset_clears_override(tmp_path) -> None:
    app = PlatformApp()
    watched_log = tmp_path / "watched.log"
    watched_log.write_text("line1\n", encoding="utf-8")
    output_root = str(tmp_path / "out")

    register_payload = app.register_watch_source(
        IngestRequest(source_type="log", locator=str(watched_log)),
        case_id="case-watch",
        output_root=output_root,
        workspace_root=str(tmp_path),
    )
    watch_id = str(register_payload["watched_source"]["watch_id"])
    app.update_watch_source_settings(
        case_id="case-watch",
        watch_id=watch_id,
        clear_tuning_profile=True,
        output_root=output_root,
    )
    app.update_watch_source_settings(
        case_id="case-watch",
        watch_id=watch_id,
        tuning_preset_name="source:log",
        change_origin="automation",
        automation_direction="escalate",
        automation_reason="append-heavy log",
        output_root=output_root,
    )
    payload = app.update_watch_source_settings(
        case_id="case-watch",
        watch_id=watch_id,
        tuning_preset_name="source:log",
        output_root=output_root,
    )

    state = payload["watched_source"]["automation_state"]

    assert payload["metrics"]["watch_profile_manual_override_active"] is False
    assert state["last_automation_preset_name"] == "source:log"
    assert state["manual_override_active"] is False


def test_platform_app_watch_settings_noop_change_preserves_automation_state(tmp_path) -> None:
    app = PlatformApp()
    watched_log = tmp_path / "watched.log"
    watched_log.write_text("line1\n", encoding="utf-8")
    output_root = str(tmp_path / "out")

    register_payload = app.register_watch_source(
        IngestRequest(source_type="log", locator=str(watched_log)),
        case_id="case-watch",
        output_root=output_root,
        workspace_root=str(tmp_path),
    )
    watch_id = str(register_payload["watched_source"]["watch_id"])
    app.update_watch_source_settings(
        case_id="case-watch",
        watch_id=watch_id,
        clear_tuning_profile=True,
        output_root=output_root,
    )
    first_payload = app.update_watch_source_settings(
        case_id="case-watch",
        watch_id=watch_id,
        tuning_preset_name="source:log",
        change_origin="automation",
        automation_direction="escalate",
        automation_reason="append-heavy log",
        output_root=output_root,
    )
    second_payload = app.update_watch_source_settings(
        case_id="case-watch",
        watch_id=watch_id,
        tuning_preset_name="source:log",
        change_origin="automation",
        automation_direction="escalate",
        automation_reason="should-not-overwrite",
        output_root=output_root,
    )

    assert (
        second_payload["watched_source"]["automation_state"]["last_automation_applied_at"]
        == first_payload["watched_source"]["automation_state"]["last_automation_applied_at"]
    )
    assert second_payload["watched_source"]["automation_state"]["last_automation_reason"] == "append-heavy log"
