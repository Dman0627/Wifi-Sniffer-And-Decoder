from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from intel_collectors import (
    ApprovedConnectorStubPlugin,
    FileCollectorPlugin,
    HttpFeedCollectorPlugin,
    LogCollectorPlugin,
    PcapCollectorPlugin,
    RdapDomainCollectorPlugin,
    SystemArtifactCollectorPlugin,
)
from intel_core import IngestRequest, PluginExecutionContext


def _wait_for_server(host: str, port: int, *, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"server on {host}:{port} did not become ready")


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


def test_file_collector_ingests_single_file_and_writes_manifest(tmp_path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("intel collector sample", encoding="utf-8")

    plugin = FileCollectorPlugin()
    result = plugin.collect(
        PluginExecutionContext(case_id="case-1", output_root=tmp_path / "out", workspace_root=tmp_path),
        IngestRequest(source_type="file", locator=str(sample)),
    )

    assert result.ok is True
    assert result.metrics["file_count"] == 1
    assert len(result.records) == 3
    manifest_path = tmp_path / "out" / "intake" / result.metrics["source_id"] / result.metrics["job_id"] / "source_manifest.json"
    queue_path = tmp_path / "out" / "queues" / "extract" / f"{result.metrics['job_id']}.json"
    assert manifest_path.exists()
    assert queue_path.exists()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["source"]["source_type"] == "file"
    assert manifest["queued_jobs"][0]["stage"] == "extract"
    assert manifest["artifacts"][0]["artifact_type"] == "file"
    assert manifest["source"]["content_hash"]
    assert manifest["artifacts"][0]["path"].endswith("sample.txt")
    assert "objects\\raw" in manifest["artifacts"][0]["path"] or "objects/raw" in manifest["artifacts"][0]["path"]
    assert manifest["artifacts"][0]["attributes"]["original_path"] == str(sample.resolve())


def test_file_collector_ingests_directory_when_recursive_enabled(tmp_path) -> None:
    source_dir = tmp_path / "samples"
    nested = source_dir / "nested"
    nested.mkdir(parents=True)
    (source_dir / "a.txt").write_text("a", encoding="utf-8")
    (nested / "b.txt").write_text("b", encoding="utf-8")

    plugin = FileCollectorPlugin()
    result = plugin.collect(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        IngestRequest(source_type="directory", locator=str(source_dir), options={"recursive": True}),
    )

    assert result.ok is True
    assert result.metrics["file_count"] == 2


def test_file_collector_snapshot_source_is_stable_for_unchanged_input(tmp_path) -> None:
    sample = tmp_path / "stable.txt"
    sample.write_text("stable collector sample", encoding="utf-8")

    plugin = FileCollectorPlugin()
    first = plugin.snapshot_source(IngestRequest(source_type="file", locator=str(sample)))
    second = plugin.snapshot_source(IngestRequest(source_type="file", locator=str(sample)))

    assert first.content_hash == second.content_hash
    assert first.file_count == 1


def test_file_collector_snapshot_reuses_hashes_for_unchanged_files(tmp_path, monkeypatch) -> None:
    sample = tmp_path / "reused.txt"
    sample.write_text("reuse me", encoding="utf-8")

    plugin = FileCollectorPlugin()
    first = plugin.snapshot_source(IngestRequest(source_type="file", locator=str(sample)))
    calls = {"count": 0}

    def fake_sha256(_path):
        calls["count"] += 1
        return "unexpected"

    monkeypatch.setattr("intel_collectors.filesystem._sha256_hex", fake_sha256)
    second = plugin.snapshot_source(
        IngestRequest(source_type="file", locator=str(sample)),
        previous_watcher_state={
            "file_rows": [
                {
                    "relative_path": row["relative_path"],
                    "sha256": row["sha256"],
                    "size_bytes": row["size_bytes"],
                    "mtime_ns": row["mtime_ns"],
                }
                for row in first.file_rows
            ]
        },
    )

    assert calls["count"] == 0
    assert second.reused_hash_count == 1
    assert second.full_hash_count == 0
    assert second.content_hash == first.content_hash


def test_pcap_collector_sets_pcap_media_type_and_artifact_kind(tmp_path) -> None:
    pcap = tmp_path / "capture.pcapng"
    pcap.write_bytes(b"pcap-data")

    plugin = PcapCollectorPlugin()
    result = plugin.collect(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        IngestRequest(source_type="pcapng", locator=str(pcap)),
    )

    assert result.ok is True
    artifact = next(record for record in result.records if getattr(record, "record_type", "") == "artifact")
    assert artifact.artifact_type == "pcap"
    assert artifact.media_type == "application/x-pcapng"


def test_pcap_collector_rejects_non_pcap_suffix(tmp_path) -> None:
    wrong = tmp_path / "capture.bin"
    wrong.write_bytes(b"not-a-pcap")

    plugin = PcapCollectorPlugin()
    result = plugin.collect(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        IngestRequest(source_type="pcap", locator=str(wrong)),
    )

    assert result.ok is False
    assert "does not accept source type" in result.errors[0]


def test_log_collector_ingests_log_file_with_log_artifact_type(tmp_path) -> None:
    log_path = tmp_path / "events.log"
    log_path.write_text("2026-04-08 event=boot\n", encoding="utf-8")

    plugin = LogCollectorPlugin()
    result = plugin.collect(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        IngestRequest(source_type="log", locator=str(log_path)),
    )

    assert result.ok is True
    artifact = next(record for record in result.records if getattr(record, "record_type", "") == "artifact")
    assert artifact.artifact_type == "log"
    assert "log" in artifact.tags


def test_system_artifact_collector_ingests_event_log_file(tmp_path) -> None:
    event_log = tmp_path / "security.evtx"
    event_log.write_bytes(b"EVTX")

    plugin = SystemArtifactCollectorPlugin()
    result = plugin.collect(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        IngestRequest(source_type="system-artifact", locator=str(event_log)),
    )

    assert result.ok is True
    artifact = next(record for record in result.records if getattr(record, "record_type", "") == "artifact")
    assert artifact.artifact_type == "system_artifact"
    assert "event-log" in artifact.tags


def test_http_feed_connector_ingests_json_response_and_writes_manifest(tmp_path) -> None:
    server, thread, base_url = _start_http_fixture_server(
        {
            "/feed.json": {
                "content_type": "application/json",
                "body": json.dumps({"title": "Feed", "items": [{"url": "https://example.test/path"}]}).encode("utf-8"),
                "headers": {"ETag": '"feed-v1"'},
            }
        }
    )
    try:
        plugin = HttpFeedCollectorPlugin()
        result = plugin.collect(
            PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
            IngestRequest(source_type="http-feed", locator=f"{base_url}/feed.json"),
        )

        assert result.ok is True
        assert result.metrics["artifact_count"] == 1
        manifest_path = tmp_path / "out" / "intake" / result.metrics["source_id"] / result.metrics["job_id"] / "source_manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert manifest["source"]["source_type"] == "http-feed"
        assert manifest["source"]["attributes"]["etag"] == '"feed-v1"'
        assert manifest["artifacts"][0]["artifact_type"] == "public_source"
        assert manifest["artifacts"][0]["media_type"] == "application/json"
        assert "objects\\raw" in manifest["artifacts"][0]["path"] or "objects/raw" in manifest["artifacts"][0]["path"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_rdap_domain_connector_collects_domain_record_via_overridden_base_url(tmp_path) -> None:
    server, thread, base_url = _start_http_fixture_server(
        {
            "/domain/example.test": {
                "content_type": "application/rdap+json",
                "body": json.dumps({"ldhName": "example.test", "status": ["active"]}).encode("utf-8"),
            }
        }
    )
    try:
        plugin = RdapDomainCollectorPlugin()
        result = plugin.collect(
            PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
            IngestRequest(
                source_type="domain",
                locator="example.test",
                options={"rdap_base_url": f"{base_url}/domain/{{domain}}"},
            ),
        )

        assert result.ok is True
        assert result.metrics["request_url"] == f"{base_url}/domain/example.test"
        artifact = next(record for record in result.records if getattr(record, "record_type", "") == "artifact")
        assert artifact.media_type == "application/rdap+json"
        assert "rdap" in artifact.tags
        assert "example.test" in artifact.tags
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_connector_stub_returns_explicit_not_implemented_error(tmp_path) -> None:
    plugin = ApprovedConnectorStubPlugin()
    result = plugin.collect(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        IngestRequest(source_type="public-source-stub", locator="example:query"),
    )

    assert result.ok is False
    assert "not implemented yet" in result.errors[0]
