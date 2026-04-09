from __future__ import annotations

import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from intel_api import PlatformApp
from intel_api.cli import main
from intel_core import IngestRequest


def _wait_for_server(host: str, port: int, *, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"server on {host}:{port} did not become ready")


def _set_age_days(path: Path, *, days: float) -> None:
    timestamp = time.time() - (float(days) * 86400.0)
    os.utime(path, (timestamp, timestamp))


def _start_http_fixture_server(fixtures: dict[str, dict[str, object]]) -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib interface
            payload = fixtures.get(self.path)
            if payload is None:
                self.send_response(404)
                self.end_headers()
                return
            body = bytes(payload.get("body") or b"")
            headers = dict(payload.get("headers") or {})
            self.send_response(int(payload.get("status", 200)))
            self.send_header("Content-Type", str(payload.get("content_type") or "application/octet-stream"))
            self.send_header("Content-Length", str(len(body)))
            for key, value in headers.items():
                self.send_header(str(key), str(value))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args) -> None:  # noqa: A003 - stdlib interface
            _unused = (format, args)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    _wait_for_server(host, port)
    return server, thread, f"http://{host}:{port}"


def test_plugins_command_outputs_json_status(capsys) -> None:
    exit_code = main(["plugins", "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["summary"]["plugin_count"] >= 1
    assert any(item["name"] == "metadata_extractor" for item in payload["plugins"])


def test_plugins_command_can_disable_plugin_and_save_profile(capsys, tmp_path) -> None:
    output_root = str(tmp_path / "out")

    disable_code = main(
        [
            "plugins",
            "--output-root",
            output_root,
            "--disable",
            "string_indicator_extractor",
            "--json",
        ]
    )
    disable_payload = json.loads(capsys.readouterr().out)

    save_code = main(
        [
            "plugins",
            "--output-root",
            output_root,
            "--save-profile",
            "no-strings",
            "--json",
        ]
    )
    save_payload = json.loads(capsys.readouterr().out)

    activate_code = main(
        [
            "plugins",
            "--output-root",
            output_root,
            "--profile",
            "no-strings",
            "--json",
        ]
    )
    activate_payload = json.loads(capsys.readouterr().out)

    assert disable_code == 0
    assert save_code == 0
    assert activate_code == 0
    assert disable_payload["plugins"]
    assert any(
        item["name"] == "string_indicator_extractor" and item["status"] == "disabled"
        for item in activate_payload["plugins"]
    )
    assert activate_payload["active_profile"] == "no-strings"
    assert any(item["name"] == "no-strings" for item in save_payload["profiles"])


def test_run_queued_command_processes_active_jobs(capsys, tmp_path) -> None:
    sample = tmp_path / "queued_cli.txt"
    sample.write_text("email=test@example.com https://example.com/path", encoding="utf-8")

    app = PlatformApp()
    app.ingest(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="cli-queue-case",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    exit_code = main(
        [
            "run-queued",
            "--output-root",
            str(tmp_path / "out"),
            "--workspace-root",
            str(tmp_path),
            "--json",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["metrics"]["processed_job_count"] >= 1
    assert "processed_priority_counts" in payload["metrics"]
    assert payload["metrics"]["remaining_queue_count"] == 0
    assert any(Path(path).name == "presentation_report.json" for path in payload["artifact_paths"])


def test_monitor_command_runs_fixed_iterations_and_updates_status(capsys, tmp_path) -> None:
    sample = tmp_path / "monitor_cli.txt"
    sample.write_text("email=test@example.com https://example.com/path", encoding="utf-8")

    app = PlatformApp()
    app.ingest(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="cli-monitor-case",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    exit_code = main(
        [
            "monitor",
            "--output-root",
            str(tmp_path / "out"),
            "--workspace-root",
            str(tmp_path),
            "--poll-interval",
            "0",
            "--iterations",
            "2",
            "--json",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["cycle_count"] == 2
    assert payload["idle_cycle_count"] >= 1
    assert payload["total_processed_job_count"] >= 6
    assert "stage_budget_mode" in payload
    assert payload["last_result"]["reason"] == "idle"
    assert Path(payload["status_path"]).exists()


def test_monitor_status_command_reads_persisted_snapshot(capsys, tmp_path) -> None:
    sample = tmp_path / "monitor_status_cli.txt"
    sample.write_text("email=test@example.com https://example.com/path", encoding="utf-8")

    app = PlatformApp()
    app.ingest(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="cli-monitor-status-case",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    once_exit_code = main(
        [
            "monitor-once",
            "--output-root",
            str(tmp_path / "out"),
            "--workspace-root",
            str(tmp_path),
            "--json",
        ]
    )
    capsys.readouterr()
    status_exit_code = main(
        [
            "monitor-status",
            "--output-root",
            str(tmp_path / "out"),
            "--workspace-root",
            str(tmp_path),
            "--json",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert once_exit_code == 0
    assert status_exit_code == 0
    assert payload["cycle_count"] == 1
    assert payload["last_result"]["reason"] == "processed"
    assert payload["total_processed_job_count"] >= 6


def test_watch_command_skips_unchanged_source(capsys, tmp_path) -> None:
    sample = tmp_path / "watch_cli.txt"
    sample.write_text("email=test@example.com https://example.com/path", encoding="utf-8")

    first_exit_code = main(
        [
            "watch",
            str(sample),
            "--output-root",
            str(tmp_path / "out"),
            "--workspace-root",
            str(tmp_path),
            "--json",
        ]
    )
    capsys.readouterr()
    second_exit_code = main(
        [
            "watch",
            str(sample),
            "--output-root",
            str(tmp_path / "out"),
            "--workspace-root",
            str(tmp_path),
            "--json",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert first_exit_code == 0
    assert second_exit_code == 0
    assert payload["ok"] is True
    assert payload["changed"] is False
    assert payload["skipped"] is True
    assert payload["watcher_state"]["total_check_count"] == 2


def test_ingest_command_auto_detects_http_feed_locator(capsys, tmp_path) -> None:
    server, thread, base_url = _start_http_fixture_server(
        {
            "/feed.json": {
                "content_type": "application/json",
                "body": json.dumps({"items": ["alpha"]}).encode("utf-8"),
            }
        }
    )
    try:
        exit_code = main(
            [
                "ingest",
                f"{base_url}/feed.json",
                "--output-root",
                str(tmp_path / "out"),
                "--workspace-root",
                str(tmp_path),
                "--json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)

        assert exit_code == 0
        assert payload["ok"] is True
        assert payload["records"][0]["source_type"] == "http-feed"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_watch_add_and_watch_list_commands_surface_registered_sources(capsys, tmp_path) -> None:
    sample = tmp_path / "watch_add_cli.txt"
    sample.write_text("watch add cli", encoding="utf-8")

    add_exit_code = main(
        [
            "watch-add",
            str(sample),
            "--output-root",
            str(tmp_path / "out"),
            "--workspace-root",
            str(tmp_path),
            "--poll-interval",
            "30",
            "--forecast-min-history",
            "5",
            "--source-churn-factor",
            "4.0",
            "--suppressed-alerts",
            "source_churn_spike",
            "--json",
        ]
    )
    capsys.readouterr()
    list_exit_code = main(
        [
            "watch-list",
            "--output-root",
            str(tmp_path / "out"),
            "--json",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert add_exit_code == 0
    assert list_exit_code == 0
    assert payload["metrics"]["watched_source_count"] == 1
    assert payload["watched_sources"][0]["locator"] == str(sample.resolve())
    assert payload["watched_sources"][0]["tuning_profile"]["preset_name"] == "source:file"
    assert payload["watched_sources"][0]["tuning_profile"]["forecast_min_history"] == 5
    assert payload["watched_sources"][0]["tuning_profile"]["source_churn_spike_factor"] == 4.0
    assert payload["watched_sources"][0]["tuning_profile"]["suppressed_alert_ids"] == ["source_churn_spike"]


def test_cleanup_command_prunes_old_workspace_artifacts(capsys, tmp_path) -> None:
    output_root = tmp_path / "out"
    completed = output_root / "queues" / "completed" / "extract"
    failed = output_root / "queues" / "failed" / "recover"
    delta = output_root / "objects" / "derived" / "watch_delta" / "source-1"
    completed.mkdir(parents=True, exist_ok=True)
    failed.mkdir(parents=True, exist_ok=True)
    delta.mkdir(parents=True, exist_ok=True)

    old_completed = completed / "old.json"
    old_completed.write_text("{}", encoding="utf-8")
    old_failed = failed / "old.json"
    old_failed.write_text("{}", encoding="utf-8")
    old_delta = delta / "old.bin"
    old_delta.write_bytes(b"delta")
    fresh_delta = delta / "fresh.bin"
    fresh_delta.write_bytes(b"fresh")
    _set_age_days(old_completed, days=2.0)
    _set_age_days(old_failed, days=2.0)
    _set_age_days(old_delta, days=2.0)

    exit_code = main(
        [
            "cleanup",
            "--output-root",
            str(output_root),
            "--completed-days",
            "1",
            "--failed-days",
            "1",
            "--watch-delta-days",
            "1",
            "--json",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["metrics"]["removed_count"] == 3
    assert not old_completed.exists()
    assert not old_failed.exists()
    assert not old_delta.exists()
    assert fresh_delta.exists()


def test_monitor_tuning_command_updates_and_clears_case_scope(capsys, tmp_path) -> None:
    output_root = tmp_path / "out"

    view_exit_code = main(
        [
            "monitor-tuning",
            "--case-id",
            "cli-tuning-case",
            "--output-root",
            str(output_root),
            "--json",
        ]
    )
    view_payload = json.loads(capsys.readouterr().out)

    update_exit_code = main(
        [
            "monitor-tuning",
            "--case-id",
            "cli-tuning-case",
            "--output-root",
            str(output_root),
            "--preset",
            "quiet",
            "--automation-mode",
            "apply",
            "--queue-spike-factor",
            "2.5",
            "--suppressed-alerts",
            "failure_burst, queue_pressure_spike",
            "--stage-suppressions",
            "recover:failure_burst",
            "--watch-suppressions",
            "watch-hot:source_churn_spike",
            "--alert-severity-overrides",
            "queue_pressure_spike:critical, throughput_drop:info",
            "--stage-thresholds",
            "extract:queue_spike_factor=2.25, normalize:throughput_drop_factor=0.4",
            "--json",
        ]
    )
    update_payload = json.loads(capsys.readouterr().out)

    clear_exit_code = main(
        [
            "monitor-tuning",
            "--case-id",
            "cli-tuning-case",
            "--output-root",
            str(output_root),
            "--clear-suppressions",
            "--clear-alert-severities",
            "--clear-stage-thresholds",
            "--json",
        ]
    )
    clear_payload = json.loads(capsys.readouterr().out)

    assert view_exit_code == 0
    assert view_payload["tuning"]["forecast_min_history"] >= 1
    assert any(item["name"] == "quiet" for item in view_payload["available_presets"])
    assert set(view_payload["available_automation_modes"]) == {"off", "recommend", "apply"}
    assert update_exit_code == 0
    assert update_payload["tuning"]["preset_name"] == "quiet"
    assert update_payload["tuning"]["automation_mode"] == "apply"
    assert update_payload["tuning"]["forecast_min_history"] == 5
    assert update_payload["tuning"]["queue_spike_factor"] == 2.5
    assert update_payload["tuning"]["source_churn_spike_factor"] == 3.0
    assert update_payload["tuning"]["suppressed_alert_ids"] == ["failure_burst", "queue_pressure_spike"]
    assert update_payload["tuning"]["suppressed_stage_alerts"] == {"recover": ["failure_burst"]}
    assert update_payload["tuning"]["suppressed_watch_alerts"] == {"watch-hot": ["source_churn_spike"]}
    assert update_payload["tuning"]["alert_severity_overrides"] == {
        "queue_pressure_spike": "critical",
        "throughput_drop": "info",
    }
    assert update_payload["tuning"]["stage_threshold_overrides"] == {
        "extract": {"queue_spike_factor": 2.25},
        "normalize": {"throughput_drop_factor": 0.4},
    }
    assert clear_exit_code == 0
    assert clear_payload["tuning"]["preset_name"] == "quiet"
    assert clear_payload["tuning"]["automation_mode"] == "apply"
    assert clear_payload["tuning"]["queue_spike_factor"] == 2.5
    assert clear_payload["tuning"]["suppressed_alert_ids"] == []
    assert clear_payload["tuning"]["suppressed_stage_alerts"] == {}
    assert clear_payload["tuning"]["suppressed_watch_alerts"] == {}
    assert clear_payload["tuning"]["alert_severity_overrides"] == {}
    assert clear_payload["tuning"]["stage_threshold_overrides"] == {}
