from __future__ import annotations

import http.client
import json
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

from wifi_pipeline.config import load_config, save_config
from wifi_pipeline.webapp import ActionLog, DashboardHandler, DashboardState
from wifi_pipeline.webapp_render import render_dashboard_html


def test_dashboard_update_config_persists_form_values(tmp_path) -> None:
    config_path = tmp_path / "lab.json"
    save_config({"output_dir": str(tmp_path / "pipeline_output")}, str(config_path), quiet=True)
    state = DashboardState(config_path=config_path)

    message = state.update_config(
        {
            "interface": ["wlan1"],
            "protocol": ["TCP"],
            "video_port": ["9000"],
            "capture_duration": ["120"],
            "output_dir": [str(tmp_path / "custom_output")],
            "target_macs": ["aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66"],
            "ap_essid": ["LabNet"],
            "custom_header_size": ["32"],
            "custom_magic_hex": ["de ad be ef"],
            "preferred_stream_id": ["stream-42"],
            "min_candidate_bytes": ["8192"],
            "replay_format_hint": ["png"],
            "playback_mode": ["FFPLAY"],
            "jitter_buffer_packets": ["48"],
            "corpus_review_threshold": ["0.7"],
            "corpus_auto_reuse_threshold": ["0.95"],
            "wpa_password_env": ["LAB_WPA_PASSWORD"],
            "monitor_method": ["Tcpdump"],
            "ap_bssid": ["00:11:22:33:44:55"],
            "ap_channel": ["11"],
            "wordlist_path": ["/tmp/wordlist.txt"],
            "deauth_count": ["0"],
        }
    )

    saved = load_config(str(config_path), quiet=True)

    assert message == "Saved configuration."
    assert saved["interface"] == "wlan1"
    assert saved["protocol"] == "tcp"
    assert saved["video_port"] == 9000
    assert saved["capture_duration"] == 120
    assert saved["output_dir"] == str(tmp_path / "custom_output")
    assert saved["target_macs"] == ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]
    assert saved["ap_essid"] == "LabNet"
    assert saved["custom_header_size"] == 32
    assert saved["custom_magic_hex"] == "deadbeef"
    assert saved["preferred_stream_id"] == "stream-42"
    assert saved["min_candidate_bytes"] == 8192
    assert saved["replay_format_hint"] == "png"
    assert saved["video_codec"] == "png"
    assert saved["playback_mode"] == "ffplay"
    assert saved["jitter_buffer_packets"] == 48
    assert saved["corpus_review_threshold"] == 0.7
    assert saved["corpus_auto_reuse_threshold"] == 0.95
    assert saved["wpa_password_env"] == "LAB_WPA_PASSWORD"
    assert saved["monitor_method"] == "tcpdump"
    assert saved["ap_bssid"] == "00:11:22:33:44:55"
    assert saved["ap_channel"] == 11
    assert saved["wordlist_path"] == "/tmp/wordlist.txt"
    assert saved["deauth_count"] == 0
    assert state.logs[-1].action == "config"
    assert state.logs[-1].status == "ok"


def test_dashboard_execute_all_dispatches_pipeline(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "lab.json"
    save_config({"output_dir": str(tmp_path / "pipeline_output")}, str(config_path), quiet=True)
    state = DashboardState(config_path=config_path)
    pcap_path = tmp_path / "sample.pcapng"
    pcap_path.write_bytes(b"pcap")

    seen: dict[str, object] = {}

    class FakeExtractor:
        def __init__(self, config):
            seen["extract_config"] = config

        def extract(self, source: str):
            seen["extract_source"] = source
            return {"manifest": True}

    class FakeDetector:
        def __init__(self, config):
            seen["detect_config"] = config

        def detect(self):
            seen["detect_called"] = True
            return {"selected_candidate_stream": {"stream_id": "stream-42"}}

    class FakeAnalyzer:
        def __init__(self, config):
            seen["analyze_config"] = config

        def analyze(self, decrypted_dir=None):
            seen["decrypted_dir"] = decrypted_dir
            return {"candidate_material": ["bytes"], "selected_candidate_stream": {"stream_id": "stream-42"}}

    class FakeEnricher:
        def __init__(self, config):
            seen["enrich_config"] = config

        def enrich(self):
            seen["enrich_called"] = True
            return {"units_analyzed": 2}

    monkeypatch.setattr("wifi_pipeline.webapp.StreamExtractor", FakeExtractor)
    monkeypatch.setattr("wifi_pipeline.webapp.FormatDetector", FakeDetector)
    monkeypatch.setattr("wifi_pipeline.webapp.CryptoAnalyzer", FakeAnalyzer)
    monkeypatch.setattr("wifi_pipeline.webapp.ArtifactEnricher", FakeEnricher)
    monkeypatch.setattr("wifi_pipeline.webapp.infer_replay_hint", lambda config, report: "png")
    monkeypatch.setattr("wifi_pipeline.webapp.reconstruct_from_capture", lambda config, report: str(tmp_path / "replay.png"))

    message = state._execute_action(
        "all",
        {
            "pcap_path": [str(pcap_path)],
            "decrypted_dir": [str(tmp_path / "decrypted")],
        },
    )

    assert message == f"Full pipeline finished and wrote reconstructed output to {tmp_path / 'replay.png'}"
    assert seen["extract_source"] == str(pcap_path)
    assert seen["detect_called"] is True
    assert seen["enrich_called"] is True
    assert seen["decrypted_dir"] == str(tmp_path / "decrypted")


def test_render_dashboard_html_shows_busy_state_and_escaped_logs() -> None:
    html = render_dashboard_html(
        {
            "config": {
                "interface": "wlan0",
                "protocol": "udp",
                "video_port": 5004,
                "capture_duration": 60,
                "output_dir": "./pipeline_output",
                "target_macs": [],
                "monitor_method": "airodump",
                "playback_mode": "both",
            },
            "bundle": {
                "detection": {"selected_candidate_stream": {"stream_id": "stream-1", "candidate_class": "jpeg", "score": 0.9}},
                "analysis": {"selected_candidate_stream": {"stream_id": "stream-1"}, "recommendations": ["Use <safe> replay"]},
                "status_bundle": {
                    "machine_summary": {
                        "headline": "Windows controller + Linux appliance / privilege=user",
                        "items": [
                            {
                                "label": "Local capture",
                                "status": "limited",
                                "summary": "This machine can capture a pcap locally, but monitor work is still limited.",
                                "reason": "Windows capture depends on Npcap.",
                                "next_step": "Prefer the Linux appliance path for full Wi-Fi lab work.",
                            }
                        ],
                    },
                    "workflow": [
                        {
                            "area": "monitor mode + Wi-Fi lab capture",
                            "status": "limited",
                            "summary": "Run monitor-mode capture, handshake collection, and other Wi-Fi lab steps.",
                            "detail": "Capture tooling is present, but the path is still limited.",
                            "reasons": ["Adapter support is still limited."],
                            "next_steps": ["Prefer the Linux appliance path for full monitor-mode work."],
                        }
                    ],
                    "selection": {
                        "status": "limited",
                        "summary": "Replay can proceed, but there are caveats you should see first.",
                        "decode_level": "heuristic",
                        "replay_level": "heuristic",
                        "dominant_unit_type": "jpeg_image",
                        "signal_strength": "mixed",
                        "notes": ["Thin capture sample."],
                        "next_steps": ["Capture more payload before replaying."],
                    },
                    "replay": {
                        "status": "limited",
                        "summary": "Replay can proceed, but there are caveats you should see first.",
                        "decode_level": "heuristic",
                        "replay_level": "heuristic",
                        "dominant_unit_type": "jpeg_image",
                        "reasons": ["Thin capture sample."],
                        "next_steps": ["Capture more payload before replaying."],
                        "confidence": {
                            "confidence_band": "limited",
                            "confidence_label": "heuristic",
                            "confidence_score": 0.58,
                            "delivery_mode": "replay_or_export",
                        },
                    },
                    "wpa": {
                        "status": "blocked",
                        "summary": "A usable WPA artifact is still missing.",
                        "state": "unsupported",
                        "handshake_artifact": "missing",
                        "reasons": ["No handshake or PMKID capture is available."],
                        "next_steps": ["Capture a handshake before retrying WPA decrypt."],
                    },
                },
                "candidate_rows": [],
                "corpus_entries": [],
                "corpus_status": {},
                "interfaces": [],
                "artifacts": [{"label": "Capture", "path": "C:/tmp/capture.pcapng", "exists": True}],
            },
            "logs": [ActionLog(timestamp=time.time(), action="detect", status="ok", message="Saved <config>", output="A&B")],
            "busy": True,
            "current_action": "detect",
            "last_status": "running",
            "last_message": "Working <now>",
            "config_path": "C:/tmp/lab.json",
        },
        capture_path="C:/tmp/capture.pcapng",
    )

    assert "<meta http-equiv='refresh' content='4'>" in html
    assert "Current action: detect" in html
    assert "Saved &lt;config&gt;" in html
    assert "Working &lt;now&gt;" in html
    assert "Use &lt;safe&gt; replay" in html
    assert "A&amp;B" in html
    assert "What This Machine Can Do" in html
    assert "Windows controller + Linux appliance / privilege=user" in html
    assert "Prefer the Linux appliance path for full Wi-Fi lab work." in html
    assert "Workflow Capabilities" in html
    assert "Replay + WPA Readiness" in html
    assert "Capture more payload before replaying." in html
    assert "Capture a handshake before retrying WPA decrypt." in html


def test_dashboard_snapshot_includes_shared_status_bundle(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "lab.json"
    output_dir = tmp_path / "pipeline_output"
    output_dir.mkdir()
    save_config({"output_dir": str(output_dir)}, str(config_path), quiet=True)
    state = DashboardState(config_path=config_path)

    monkeypatch.setattr(
        "wifi_pipeline.webapp.build_surface_status_bundle",
        lambda config, detection, analysis: {
            "machine_summary": {
                "headline": "Ubuntu standalone / privilege=root",
                "items": [{"label": "Local capture", "status": "supported", "summary": "Capture locally."}],
            },
            "workflow": [{"area": "local packet capture", "status": "supported", "summary": "Capture locally."}],
            "selection": {"status": "ready", "summary": "Selection is ready."},
            "replay": {"status": "ready", "summary": "Replay is ready."},
            "wpa": {"status": "blocked", "summary": "WPA is blocked."},
        },
    )

    snapshot = state.snapshot()

    assert snapshot["bundle"]["status_bundle"]["machine_summary"]["headline"] == "Ubuntu standalone / privilege=root"
    assert snapshot["bundle"]["status_bundle"]["workflow"][0]["area"] == "local packet capture"
    assert snapshot["bundle"]["status_bundle"]["replay"]["status"] == "ready"


def test_dashboard_http_routes_smoke(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "lab.json"
    output_dir = tmp_path / "pipeline_output"
    output_dir.mkdir()
    analysis_report = output_dir / "analysis_report.json"
    analysis_report.write_text(json.dumps({"ok": True}), encoding="utf-8")
    save_config({"output_dir": str(output_dir)}, str(config_path), quiet=True)

    state = DashboardState(config_path=config_path)
    started: list[str] = []

    def fake_report_bundle(config):
        return {
            "manifest": {},
            "detection": {},
            "analysis": {},
            "candidate_rows": [],
            "corpus_status": {},
            "corpus_entries": [],
            "artifacts": [{"label": "Analysis Report", "path": str(analysis_report), "exists": True}],
            "interfaces": [],
        }

    def fake_start_action(self, action: str, form):
        started.append(action)
        return True

    monkeypatch.setattr("wifi_pipeline.webapp._report_bundle", fake_report_bundle)
    monkeypatch.setattr(DashboardState, "start_action", fake_start_action)

    server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
    server.app_state = state  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)

        conn.request("GET", "/")
        response = conn.getresponse()
        body = response.read().decode("utf-8")
        assert response.status == 200
        assert "WiFi Stream Dashboard" in body

        conn.request("GET", "/api/state")
        response = conn.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        assert response.status == 200
        assert payload["config_path"] == str(config_path)

        conn.request("GET", "/reports/analysis")
        response = conn.getresponse()
        report_payload = json.loads(response.read().decode("utf-8"))
        assert response.status == 200
        assert report_payload == {"ok": True}

        conn.request(
            "POST",
            "/pin",
            body=urlencode({"stream_id": "stream-99"}),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response = conn.getresponse()
        response.read()
        assert response.status == 303
        assert load_config(str(config_path), quiet=True)["preferred_stream_id"] == "stream-99"

        conn.request(
            "POST",
            "/action",
            body=urlencode({"action": "detect"}),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response = conn.getresponse()
        response.read()
        assert response.status == 303
        assert started == ["detect"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
