from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from intel_api import PlatformApp
from intel_core import IngestRequest, PluginExecutionContext
from intel_core.registry import PluginRegistry
from intel_plugins import build_builtin_registry
from intel_plugins.wifi import WifiPipelinePlugin
from intel_storage import SQLiteIntelligenceStore


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
    return server, thread, f"http://{host}:{port}"


def test_builtin_registry_registers_wifi_plugin() -> None:
    registry = build_builtin_registry()

    assert isinstance(registry, PluginRegistry)
    assert "wifi_pipeline" in registry
    assert "log_collector" in registry
    assert "file_collector" in registry
    assert "http_feed_connector" in registry
    assert "pcap_collector" in registry
    assert "rdap_domain_connector" in registry
    assert "system_artifact_collector" in registry
    assert "archive_inventory_extractor" in registry
    assert "binary_metadata_extractor" in registry
    assert "document_structure_extractor" in registry
    assert "metadata_extractor" in registry
    assert "string_indicator_extractor" in registry
    assert "system_artifact_metadata_extractor" in registry
    assert "exiftool_metadata_extractor" in registry
    assert "yara_rule_extractor" in registry
    assert "passive_decode_recovery" in registry
    assert "canonical_record_normalizer" in registry
    assert "graph_correlator" in registry
    manifests = registry.manifests(enabled_only=True)
    assert any(manifest.name == "wifi_pipeline" for manifest in manifests)


def test_platform_app_preloads_builtin_plugins() -> None:
    app = PlatformApp()

    names = [manifest.name for manifest in app.plugin_manifests()]
    assert "wifi_pipeline" in names
    assert "file_collector" in names
    assert "http_feed_connector" in names
    assert "log_collector" in names
    assert "rdap_domain_connector" in names
    assert "system_artifact_collector" in names
    assert "archive_inventory_extractor" in names
    assert "binary_metadata_extractor" in names
    assert "document_structure_extractor" in names
    assert "metadata_extractor" in names
    assert "system_artifact_metadata_extractor" in names
    assert "exiftool_metadata_extractor" in names
    assert "yara_rule_extractor" in names
    assert "passive_decode_recovery" in names
    assert "canonical_record_normalizer" in names
    assert "graph_correlator" in names


def test_platform_app_plugin_statuses_surface_optional_tool_availability(monkeypatch) -> None:
    def fake_which(name: str) -> str | None:
        if name in {"exiftool", "yara"}:
            return None
        return f"C:/tools/{name}.exe"

    monkeypatch.setattr("intel_api.app.shutil.which", fake_which)
    monkeypatch.setattr("intel_extractors.external.shutil.which", fake_which)

    app = PlatformApp()
    statuses = {item["name"]: item for item in app.plugin_statuses()}
    summary = app.plugin_status_summary()

    assert statuses["metadata_extractor"]["status"] == "ready"
    assert statuses["exiftool_metadata_extractor"]["status"] == "optional_tool_missing"
    assert statuses["yara_rule_extractor"]["status"] == "optional_tool_missing"
    assert summary["plugin_count"] >= 1
    assert summary["optional_tool_missing_count"] >= 2


def test_platform_app_plugin_settings_can_disable_and_switch_profiles(tmp_path) -> None:
    app = PlatformApp()
    output_root = str(tmp_path / "out")

    initial = app.plugin_settings(output_root=output_root)
    assert initial["active_profile"] == "default"
    assert any(item["name"] == "default" and item["active"] for item in initial["profiles"])

    disable_payload = app.update_plugin_settings(
        output_root=output_root,
        plugin_name="string_indicator_extractor",
        enabled=False,
    )
    saved_payload = app.update_plugin_settings(
        output_root=output_root,
        save_profile_as="no-strings",
    )
    app.update_plugin_settings(
        output_root=output_root,
        plugin_name="string_indicator_extractor",
        enabled=True,
    )
    active_payload = app.update_plugin_settings(
        output_root=output_root,
        set_active_profile="no-strings",
    )
    statuses = {item["name"]: item for item in app.plugin_statuses(output_root=output_root)}

    assert disable_payload["ok"] is True
    assert saved_payload["ok"] is True
    assert active_payload["active_profile"] == "no-strings"
    assert statuses["string_indicator_extractor"]["status"] == "disabled"
    assert "string_indicator_extractor" not in app.extractor_names(output_root=output_root)
    assert any(item["name"] == "no-strings" and item["active"] for item in active_payload["profiles"])


def test_platform_app_extract_respects_disabled_string_indicator_plugin(tmp_path) -> None:
    sample = tmp_path / "disabled_plugin_extract.txt"
    sample.write_text("email=disabled@example.com https://example.com/path", encoding="utf-8")

    app = PlatformApp()
    output_root = str(tmp_path / "out")
    app.update_plugin_settings(
        output_root=output_root,
        plugin_name="string_indicator_extractor",
        enabled=False,
    )
    ingest_result = app.ingest(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="plugin-disable-case",
        output_root=output_root,
        workspace_root=str(tmp_path),
    )
    extract_result = app.extract(
        ingest_result.artifact_paths[0],
        workspace_root=str(tmp_path),
        output_root=output_root,
    )

    indicator_values = {
        getattr(record, "value", "")
        for record in extract_result.records
        if getattr(record, "record_type", "") == "indicator"
    }

    assert extract_result.ok is True
    assert "disabled@example.com" not in indicator_values
    assert "https://example.com/path" not in indicator_values


def test_platform_app_ingest_routes_to_file_collector(tmp_path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("platform ingest", encoding="utf-8")

    app = PlatformApp()
    result = app.ingest(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="case-9",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    assert result.ok is True
    assert result.metrics["file_count"] == 1


def test_platform_app_ingest_routes_to_log_collector(tmp_path) -> None:
    sample = tmp_path / "app.log"
    sample.write_text("line 1\n", encoding="utf-8")

    app = PlatformApp()
    result = app.ingest(
        IngestRequest(source_type="log", locator=str(sample)),
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    assert result.ok is True
    assert result.metrics["artifact_count"] == 1


def test_platform_app_ingest_routes_to_http_feed_connector(tmp_path) -> None:
    server, thread, base_url = _start_http_fixture_server(
        {
            "/feed.json": {
                "content_type": "application/json",
                "body": json.dumps({"items": [{"email": "feed@example.test"}]}).encode("utf-8"),
            }
        }
    )
    try:
        app = PlatformApp()
        result = app.ingest(
            IngestRequest(source_type="http-feed", locator=f"{base_url}/feed.json"),
            output_root=str(tmp_path / "out"),
            workspace_root=str(tmp_path),
        )

        assert result.ok is True
        assert result.metrics["artifact_count"] == 1
        assert result.metrics["request_url"] == f"{base_url}/feed.json"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_platform_app_watch_source_skips_unchanged_http_feed(tmp_path) -> None:
    server, thread, base_url = _start_http_fixture_server(
        {
            "/watch.json": {
                "content_type": "application/json",
                "body": json.dumps({"status": "steady"}).encode("utf-8"),
                "headers": {"ETag": '"steady-v1"'},
            }
        }
    )
    try:
        app = PlatformApp()
        first = app.watch_source(
            IngestRequest(source_type="http-feed", locator=f"{base_url}/watch.json"),
            case_id="case-http-watch",
            output_root=str(tmp_path / "out"),
            workspace_root=str(tmp_path),
        )
        second = app.watch_source(
            IngestRequest(source_type="http-feed", locator=f"{base_url}/watch.json"),
            case_id="case-http-watch",
            output_root=str(tmp_path / "out"),
            workspace_root=str(tmp_path),
        )

        assert first["ok"] is True
        assert first["changed"] is True
        assert second["ok"] is True
        assert second["changed"] is False
        assert second["skipped"] is True
        assert second["watcher_state"]["total_check_count"] == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_platform_app_extracts_indicators_and_queues_recover_job(tmp_path) -> None:
    sample = tmp_path / "intel_sample.bin"
    sample.write_bytes(
        b"prefix data https://example.com/path email=test@example.com domain=example.org ip=10.0.0.5 "
        b"\x89PNG\r\n\x1a\nembedded"
    )

    app = PlatformApp()
    ingest_result = app.ingest(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="case-42",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    manifest_path = ingest_result.artifact_paths[0]

    extract_result = app.extract(manifest_path, workspace_root=str(tmp_path))

    assert extract_result.ok is True
    assert extract_result.metrics["artifact_count"] == 1
    assert extract_result.metrics["record_count"] > 0
    assert any(getattr(record, "record_type", "") == "indicator" for record in extract_result.records)
    assert any(getattr(record, "record_type", "") == "job" and getattr(record, "stage", "") == "recover" for record in extract_result.records)
    assert any(path.endswith("extract_report.json") for path in extract_result.artifact_paths)


def test_platform_app_recovers_artifacts_and_queues_normalize_job(tmp_path) -> None:
    import base64

    sample = tmp_path / "recover_sample.txt"
    sample.write_text(
        base64.b64encode(b"https://decoded.example/path email=decoded@example.com").decode("ascii"),
        encoding="utf-8",
    )

    app = PlatformApp()
    ingest_result = app.ingest(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="case-77",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    extract_result = app.extract(ingest_result.artifact_paths[0], workspace_root=str(tmp_path))
    recover_result = app.recover(
        next(path for path in extract_result.artifact_paths if path.endswith("extract_report.json")),
        workspace_root=str(tmp_path),
    )

    assert recover_result.ok is True
    assert recover_result.metrics["recovered_artifact_count"] >= 1
    assert any(getattr(record, "record_type", "") == "artifact" for record in recover_result.records)
    assert any(getattr(record, "record_type", "") == "indicator" and getattr(record, "indicator_type", "") == "url" for record in recover_result.records)
    assert any(getattr(record, "record_type", "") == "job" and getattr(record, "stage", "") == "normalize" for record in recover_result.records)
    assert any(path.endswith("recover_report.json") for path in recover_result.artifact_paths)


def test_platform_app_normalizes_records_and_queues_correlate_job(tmp_path) -> None:
    sample = tmp_path / "normalize_sample.txt"
    sample.write_text("email=test@example.com email=TEST@example.com https://example.com/path#frag", encoding="utf-8")

    app = PlatformApp()
    ingest_result = app.ingest(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="case-77",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    extract_result = app.extract(ingest_result.artifact_paths[0], workspace_root=str(tmp_path))
    recover_result = app.recover(
        next(path for path in extract_result.artifact_paths if path.endswith("extract_report.json")),
        workspace_root=str(tmp_path),
    )
    normalize_result = app.normalize(
        next(path for path in recover_result.artifact_paths if path.endswith("recover_report.json")),
        workspace_root=str(tmp_path),
    )

    assert normalize_result.ok is True
    assert normalize_result.metrics["normalized_record_count"] > 0
    assert any(getattr(record, "record_type", "") == "identity" for record in normalize_result.records)
    assert any(getattr(record, "record_type", "") == "job" and getattr(record, "stage", "") == "correlate" for record in normalize_result.records)
    assert any(path.endswith("normalize_report.json") for path in normalize_result.artifact_paths)


def test_platform_app_correlates_records_and_queues_store_job(tmp_path) -> None:
    sample = tmp_path / "correlate_sample.txt"
    sample.write_text(
        "email=test@example.com https://example.com/path https://example.com/other domain=example.org",
        encoding="utf-8",
    )

    app = PlatformApp()
    ingest_result = app.ingest(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="case-88",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    extract_result = app.extract(ingest_result.artifact_paths[0], workspace_root=str(tmp_path))
    recover_result = app.recover(
        next(path for path in extract_result.artifact_paths if path.endswith("extract_report.json")),
        workspace_root=str(tmp_path),
    )
    normalize_result = app.normalize(
        next(path for path in recover_result.artifact_paths if path.endswith("recover_report.json")),
        workspace_root=str(tmp_path),
    )
    correlate_result = app.correlate(
        next(path for path in normalize_result.artifact_paths if path.endswith("normalize_report.json")),
        workspace_root=str(tmp_path),
    )

    assert correlate_result.ok is True
    assert correlate_result.metrics["correlated_record_count"] > 0
    assert any(getattr(record, "record_type", "") == "timeline" for record in correlate_result.records)
    assert any(getattr(record, "record_type", "") == "job" and getattr(record, "stage", "") == "store" for record in correlate_result.records)
    assert any(
        getattr(record, "record_type", "") == "relationship"
        and getattr(record, "relationship_type", "") == "identity_shares_domain_with_url"
        for record in correlate_result.records
    )
    assert any(path.endswith("correlation_report.json") for path in correlate_result.artifact_paths)


def test_platform_app_stores_records_in_sqlite_and_queues_present_job(tmp_path) -> None:
    sample = tmp_path / "store_sample.txt"
    sample.write_text(
        "email=test@example.com https://example.com/path domain=example.org",
        encoding="utf-8",
    )

    app = PlatformApp()
    ingest_result = app.ingest(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="case-99",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    extract_result = app.extract(ingest_result.artifact_paths[0], workspace_root=str(tmp_path))
    recover_result = app.recover(
        next(path for path in extract_result.artifact_paths if path.endswith("extract_report.json")),
        workspace_root=str(tmp_path),
    )
    normalize_result = app.normalize(
        next(path for path in recover_result.artifact_paths if path.endswith("recover_report.json")),
        workspace_root=str(tmp_path),
    )
    correlate_result = app.correlate(
        next(path for path in normalize_result.artifact_paths if path.endswith("normalize_report.json")),
        workspace_root=str(tmp_path),
    )
    store_result = app.store(
        next(path for path in correlate_result.artifact_paths if path.endswith("correlation_report.json")),
        workspace_root=str(tmp_path),
    )

    assert store_result.ok is True
    assert store_result.metrics["record_count"] > 0
    assert any(getattr(record, "record_type", "") == "job" and getattr(record, "stage", "") == "present" for record in store_result.records)
    assert any(path.endswith("store_report.json") for path in store_result.artifact_paths)
    database_path = next(path for path in store_result.artifact_paths if path.endswith(".sqlite3"))

    with sqlite3.connect(database_path) as connection:
        stored_records = connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    assert stored_records > 0


def test_platform_app_materializes_presentation_views_from_store(tmp_path) -> None:
    sample = tmp_path / "present_sample.txt"
    sample.write_text(
        "email=test@example.com https://example.com/path domain=example.org",
        encoding="utf-8",
    )

    app = PlatformApp()
    ingest_result = app.ingest(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="case-100",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    extract_result = app.extract(ingest_result.artifact_paths[0], workspace_root=str(tmp_path))
    recover_result = app.recover(
        next(path for path in extract_result.artifact_paths if path.endswith("extract_report.json")),
        workspace_root=str(tmp_path),
    )
    normalize_result = app.normalize(
        next(path for path in recover_result.artifact_paths if path.endswith("recover_report.json")),
        workspace_root=str(tmp_path),
    )
    correlate_result = app.correlate(
        next(path for path in normalize_result.artifact_paths if path.endswith("normalize_report.json")),
        workspace_root=str(tmp_path),
    )
    store_result = app.store(
        next(path for path in correlate_result.artifact_paths if path.endswith("correlation_report.json")),
        workspace_root=str(tmp_path),
    )
    present_result = app.present(
        next(path for path in store_result.artifact_paths if path.endswith("store_report.json")),
        workspace_root=str(tmp_path),
    )

    assert present_result.ok is True
    assert present_result.metrics["record_count"] > 0
    assert any(getattr(record, "record_type", "") == "job" and getattr(record, "stage", "") == "present" for record in present_result.records)
    assert any(path.endswith("case_summary.json") for path in present_result.artifact_paths)
    assert any(path.endswith("graph_view.json") for path in present_result.artifact_paths)
    assert any(path.endswith("dataset_export.json") for path in present_result.artifact_paths)


def test_platform_app_run_pipeline_is_rerun_safe_and_persists_audit_history(tmp_path) -> None:
    sample = tmp_path / "rerun_sample.txt"
    sample.write_text(
        "email=test@example.com https://example.com/path domain=example.org",
        encoding="utf-8",
    )

    app = PlatformApp()
    first_result = app.run_pipeline(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="case-rerun",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    second_result = app.run_pipeline(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="case-rerun",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    assert first_result.ok is True
    assert second_result.ok is True
    assert any(path.endswith("presentation_report.json") for path in second_result.artifact_paths)
    database_path = next(path for path in second_result.artifact_paths if path.endswith(".sqlite3"))

    store = SQLiteIntelligenceStore(database_path)
    summary = store.summary(case_id="case-rerun")

    assert summary["source_count"] == 1
    assert summary["record_count"] == first_result.metrics["record_count"]
    assert summary["record_count"] == second_result.metrics["record_count"]
    assert summary["job_count"] >= 6
    assert summary["audit_event_count"] >= 14

    with sqlite3.connect(database_path) as connection:
        stored_sources = connection.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
        audit_rows = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    assert stored_sources == 1
    assert audit_rows >= 14


def test_platform_app_run_queued_processes_full_pipeline_and_archives_jobs(tmp_path) -> None:
    sample = tmp_path / "queued_sample.txt"
    sample.write_text("email=test@example.com https://example.com/path domain=example.org", encoding="utf-8")

    app = PlatformApp()
    ingest_result = app.ingest(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="case-queue",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    queued_before = app.list_queued_jobs(output_root=str(tmp_path / "out"))
    run_result = app.run_queued(
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    queued_after = app.list_queued_jobs(output_root=str(tmp_path / "out"))

    assert ingest_result.ok is True
    assert any(item["stage"] == "extract" for item in queued_before)
    assert run_result.ok is True
    assert run_result.metrics["processed_job_count"] >= 6
    assert run_result.metrics["completed_job_count"] >= 6
    assert run_result.metrics["remaining_queue_count"] == 0
    assert queued_after == ()
    assert any(path.endswith("presentation_report.json") for path in run_result.artifact_paths)
    assert (tmp_path / "out" / "queues" / "completed" / "extract").exists()
    assert (tmp_path / "out" / "queues" / "completed" / "present").exists()


def test_platform_app_run_queued_archives_invalid_queue_payload(tmp_path) -> None:
    output_root = tmp_path / "out"
    broken_dir = output_root / "queues" / "recover"
    broken_dir.mkdir(parents=True, exist_ok=True)
    broken_queue = broken_dir / "broken.json"
    broken_queue.write_text("{not-json", encoding="utf-8")

    app = PlatformApp()
    result = app.run_queued(output_root=str(output_root), workspace_root=str(tmp_path))

    failed_dir = output_root / "queues" / "failed" / "recover"
    archived = sorted(failed_dir.glob("broken__*.json"))

    assert result.ok is False
    assert result.metrics["failed_job_count"] == 1
    assert not broken_queue.exists()
    assert archived
    archived_payload = json.loads(archived[0].read_text(encoding="utf-8"))
    assert archived_payload["archive_state"] == "failed"
    assert archived_payload["stage"] == "recover"


def test_platform_app_cleanup_workspace_prunes_old_archives_and_watch_deltas(tmp_path) -> None:
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
    fresh_completed = completed / "fresh.json"
    fresh_completed.write_text("{}", encoding="utf-8")
    _set_age_days(old_completed, days=3.0)
    _set_age_days(old_failed, days=3.0)
    _set_age_days(old_delta, days=3.0)

    app = PlatformApp()
    payload = app.cleanup_workspace(
        output_root=str(output_root),
        queue_completed_max_age_seconds=86400.0,
        queue_failed_max_age_seconds=86400.0,
        watch_delta_max_age_seconds=86400.0,
    )

    assert payload["ok"] is True
    assert payload["metrics"]["removed_count"] == 3
    assert not old_completed.exists()
    assert not old_failed.exists()
    assert not old_delta.exists()
    assert fresh_completed.exists()
    assert any(path.endswith("cleanup_report.json") for path in payload["artifact_paths"])


def test_platform_app_watch_source_skips_unchanged_content(tmp_path) -> None:
    sample = tmp_path / "watch_sample.txt"
    sample.write_text("email=test@example.com https://example.com/path", encoding="utf-8")

    app = PlatformApp()
    first = app.watch_source(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="case-watch-source",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    second = app.watch_source(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="case-watch-source",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    assert first["ok"] is True
    assert first["changed"] is True
    assert first["ingested"] is True
    assert second["ok"] is True
    assert second["changed"] is False
    assert second["skipped"] is True
    assert second["metrics"]["source_id"] == first["metrics"]["source_id"]

    store = SQLiteIntelligenceStore(first["metrics"]["database_path"])
    watchers = store.fetch_watcher_states(case_id="case-watch-source", watcher_type="source_monitor")

    assert watchers
    assert watchers[0]["watcher_id"] == first["watcher_id"]
    assert watchers[0]["total_check_count"] == 2
    assert watchers[0]["consecutive_no_change_count"] >= 1
    assert store.summary(case_id="case-watch-source")["watcher_count"] == 1


def test_platform_app_watch_source_persists_suppression_for_repeated_low_priority_changes(tmp_path) -> None:
    sample = tmp_path / "watch_low_priority.txt"
    sample.write_text("first version", encoding="utf-8")

    app = PlatformApp()
    app.register_watch_source(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="case-watch-suppression",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
        poll_interval_seconds=20.0,
    )
    first = app.watch_source(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="case-watch-suppression",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    sample.write_text("second version", encoding="utf-8")
    second = app.watch_source(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="case-watch-suppression",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    assert first["ok"] is True
    assert second["ok"] is True
    assert second["changed"] is True
    assert second["metrics"]["triage_priority"] == "low"
    assert second["metrics"]["suppression_seconds"] >= 30.0
    assert second["watcher_state"]["suppression_until"]
    assert second["watcher_state"]["low_signal_change_streak"] >= 2


def test_platform_app_registers_and_lists_watched_sources(tmp_path) -> None:
    sample = tmp_path / "watch_registry.txt"
    sample.write_text("watch registry", encoding="utf-8")

    app = PlatformApp()
    register_payload = app.register_watch_source(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="case-watch-registry",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
        poll_interval_seconds=15.0,
    )
    listed = app.list_watch_sources(
        case_id="case-watch-registry",
        output_root=str(tmp_path / "out"),
    )

    assert register_payload["ok"] is True
    assert register_payload["watched_source"]["poll_interval_seconds"] == 15.0
    assert listed["ok"] is True
    assert listed["metrics"]["watched_source_count"] == 1
    assert listed["watched_sources"][0]["watch_id"] == register_payload["watch_id"]


def test_platform_app_watch_source_marks_log_growth_as_append_only(tmp_path, monkeypatch) -> None:
    sample = tmp_path / "events.log"
    sample.write_text("line1\n", encoding="utf-8")

    app = PlatformApp()
    first = app.watch_source(
        IngestRequest(source_type="log", locator=str(sample)),
        case_id="case-watch-log",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    sample.write_text("line1\nline2\n", encoding="utf-8")
    original_sha256 = __import__("intel_collectors.filesystem", fromlist=["_sha256_hex"])._sha256_hex
    calls = {"count": 0}

    def counting_sha256(path):
        calls["count"] += 1
        return original_sha256(path)

    monkeypatch.setattr("intel_collectors.filesystem._sha256_hex", counting_sha256)
    second = app.watch_source(
        IngestRequest(source_type="log", locator=str(sample)),
        case_id="case-watch-log",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    assert first["ok"] is True
    assert second["ok"] is True
    assert second["changed"] is True
    assert second["metrics"]["change_kind"] == "append_only"
    assert second["metrics"]["append_only_file_count"] == 1
    assert second["metrics"]["delta_ingest"] is True
    assert second["metrics"]["delta_artifact_count"] == 1
    assert second["metrics"]["triage_score"] > 0
    assert second["metrics"]["triage_priority"] in {"urgent", "high", "normal", "low"}
    assert second["watcher_state"]["file_rows"][0]["change_kind"] == "appended"
    assert second["watcher_state"]["file_rows"][0]["appended_bytes"] > 0
    assert second["watcher_state"]["triage_priority"] == second["metrics"]["triage_priority"]
    assert calls["count"] == 1

    manifest_path = next(path for path in second["artifact_paths"] if path.endswith("source_manifest.json"))
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    delta_artifact = manifest["artifacts"][0]
    expected_start_offset = str(first["watcher_state"]["file_rows"][0]["size_bytes"])
    expected_end_offset = str(
        int(expected_start_offset) + len(Path(delta_artifact["path"]).read_bytes())
    )

    assert "#append-only:" in manifest["source"]["locator"]
    assert manifest["source"]["attributes"]["delta"] == "true"
    assert delta_artifact["artifact_type"] == "log"
    assert delta_artifact["attributes"]["delta_start_offset"] == expected_start_offset
    assert delta_artifact["attributes"]["delta_end_offset"] == expected_end_offset
    assert "objects\\derived" in delta_artifact["path"] or "objects/derived" in delta_artifact["path"]
    assert Path(delta_artifact["path"]).read_text(encoding="utf-8") == "line2\n"


def test_platform_app_run_queued_prefers_higher_priority_extract_jobs(tmp_path) -> None:
    low_value = tmp_path / "low_value.txt"
    low_value.write_text("plain text artifact", encoding="utf-8")
    high_value = tmp_path / "high_value.log"
    high_value.write_text("event=login user=test@example.com\n", encoding="utf-8")

    app = PlatformApp()
    app.ingest(
        IngestRequest(source_type="file", locator=str(low_value)),
        case_id="case-priority-queue",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    app.ingest(
        IngestRequest(source_type="log", locator=str(high_value)),
        case_id="case-priority-queue",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )

    queued_before = app.list_queued_jobs(
        output_root=str(tmp_path / "out"),
        case_id="case-priority-queue",
        stages=("extract",),
    )
    result = app.run_queued(
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
        case_id="case-priority-queue",
        stages=("extract",),
        max_jobs=1,
    )
    queued_after = app.list_queued_jobs(
        output_root=str(tmp_path / "out"),
        case_id="case-priority-queue",
        stages=("extract",),
    )

    assert len(queued_before) == 2
    assert queued_before[0]["source_type"] == "log"
    assert queued_before[0]["priority_score"] > queued_before[1]["priority_score"]
    assert result.ok is True
    assert result.metrics["processed_job_count"] == 1
    assert result.metrics["processed_priority_counts"]["normal"] + result.metrics["processed_priority_counts"]["high"] + result.metrics["processed_priority_counts"]["urgent"] >= 1
    assert len(queued_after) == 1
    assert queued_after[0]["source_type"] == "file"


def test_wifi_plugin_delegates_extract_with_context_output_dir(monkeypatch, tmp_path) -> None:
    calls: dict[str, object] = {}

    def fake_run_extract(config, pcap_path):
        calls["config"] = dict(config)
        calls["pcap_path"] = pcap_path
        return {"streams": []}

    monkeypatch.setattr("intel_plugins.wifi.plugin.wifi_cli.run_extract", fake_run_extract)

    plugin = WifiPipelinePlugin()
    result = plugin.run_extract(
        PluginExecutionContext(output_root=tmp_path / "platform-output", config={"interface": "wlan0"}),
        "capture.pcapng",
    )

    assert result == {"streams": []}
    assert calls["pcap_path"] == "capture.pcapng"
    assert calls["config"]["interface"] == "wlan0"
    assert calls["config"]["output_dir"] == str((tmp_path / "platform-output").resolve())
