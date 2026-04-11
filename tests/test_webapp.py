from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

from wifi_pipeline.config import load_config, save_config
from wifi_pipeline.webapp import ActionLog, DashboardHandler, DashboardState
from wifi_pipeline.webapp_render import render_dashboard_html
from wifi_pipeline.wifi_discovery import AUTO_TARGET_VALUE, MANUAL_TARGET_VALUE


def _wait_for_server(host: str, port: int, *, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"server on {host}:{port} did not become ready")


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
            "remote_host": ["david@raspi-sniffer"],
            "remote_path": ["/home/david/wifi-pipeline/captures/"],
            "remote_port": ["2222"],
            "remote_identity": ["C:/Users/dwdow/.ssh/id_ed25519"],
            "remote_interface": ["wlan0"],
            "remote_install_mode": ["bundle"],
            "remote_install_profile": ["standard"],
            "remote_health_port": ["9876"],
            "remote_dest_dir": [str(tmp_path / "remote_imports")],
            "remote_poll_interval": ["3"],
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
    assert saved["remote_host"] == "david@raspi-sniffer"
    assert saved["remote_path"] == "/home/david/wifi-pipeline/captures/"
    assert saved["remote_port"] == 2222
    assert saved["remote_identity"] == "C:/Users/dwdow/.ssh/id_ed25519"
    assert saved["remote_interface"] == "wlan0"
    assert saved["remote_install_mode"] == "bundle"
    assert saved["remote_install_profile"] == "standard"
    assert saved["remote_health_port"] == 9876
    assert saved["remote_dest_dir"] == str(tmp_path / "remote_imports")
    assert saved["remote_poll_interval"] == 3
    assert state.logs[-1].action == "config"
    assert state.logs[-1].status == "ok"


def test_dashboard_update_config_recovers_from_invalid_saved_numeric_values(tmp_path) -> None:
    config_path = tmp_path / "lab.json"
    config_path.write_text(
        json.dumps(
            {
                "output_dir": str(tmp_path / "pipeline_output"),
                "target_macs": "aa:bb:cc:dd:ee:ff",
                "video_port": "not-a-port",
                "capture_duration": "not-a-duration",
                "custom_header_size": "not-a-size",
                "min_candidate_bytes": "not-a-byte-count",
                "jitter_buffer_packets": "not-a-buffer",
                "corpus_review_threshold": "not-a-float",
                "corpus_auto_reuse_threshold": "also-not-a-float",
                "ap_channel": "not-a-channel",
                "deauth_count": "not-a-count",
                "remote_port": "not-a-port",
                "remote_health_port": "not-a-health-port",
                "remote_poll_interval": "not-an-interval",
            }
        ),
        encoding="utf-8",
    )
    state = DashboardState(config_path=config_path)

    message = state.update_config(
        {
            "video_port": ["still-bad"],
            "capture_duration": ["still-bad"],
            "custom_header_size": ["still-bad"],
            "min_candidate_bytes": ["still-bad"],
            "jitter_buffer_packets": ["still-bad"],
            "corpus_review_threshold": ["still-bad"],
            "corpus_auto_reuse_threshold": ["still-bad"],
            "ap_channel": ["still-bad"],
            "deauth_count": ["still-bad"],
            "remote_port": ["still-bad"],
            "remote_health_port": ["still-bad"],
            "remote_poll_interval": ["still-bad"],
        }
    )

    saved = load_config(str(config_path), quiet=True)

    assert message == "Saved configuration."
    assert saved["target_macs"] == ["aa:bb:cc:dd:ee:ff"]
    assert saved["video_port"] == 5004
    assert saved["capture_duration"] == 60
    assert saved["custom_header_size"] == 0
    assert saved["min_candidate_bytes"] == 4096
    assert saved["jitter_buffer_packets"] == 24
    assert saved["corpus_review_threshold"] == 0.62
    assert saved["corpus_auto_reuse_threshold"] == 0.88
    assert saved["ap_channel"] == 6
    assert saved["deauth_count"] == 10
    assert saved["remote_port"] == 22
    assert saved["remote_health_port"] == 8741
    assert saved["remote_poll_interval"] == 8


def test_dashboard_update_config_can_auto_select_discovered_wifi_target(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "lab.json"
    save_config({"output_dir": str(tmp_path / "pipeline_output")}, str(config_path), quiet=True)
    state = DashboardState(config_path=config_path)
    targets = [
        {
            "ssid": "LabNet",
            "bssid": "00:11:22:33:44:55",
            "channel": 11,
            "signal": 82,
            "signal_label": "82%",
            "security": "WPA2-Personal",
            "source": "test",
            "connected": True,
        }
    ]
    monkeypatch.setattr("wifi_pipeline.webapp.discover_wifi_targets", lambda *args, **kwargs: targets)

    message = state.update_config({"ap_target": [AUTO_TARGET_VALUE]})
    saved = load_config(str(config_path), quiet=True)

    assert message == "Saved configuration."
    assert saved["wifi_target_mode"] == "auto"
    assert saved["ap_essid"] == "LabNet"
    assert saved["ap_bssid"] == "00:11:22:33:44:55"
    assert saved["ap_channel"] == 11
    assert saved["wifi_target_source"] == "test"


def test_dashboard_update_config_manual_wifi_target_keeps_overrides(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "lab.json"
    save_config({"output_dir": str(tmp_path / "pipeline_output")}, str(config_path), quiet=True)
    state = DashboardState(config_path=config_path)
    monkeypatch.setattr("wifi_pipeline.webapp.discover_wifi_targets", lambda *args, **kwargs: [])

    state.update_config(
        {
            "ap_target": [MANUAL_TARGET_VALUE],
            "ap_essid": ["HiddenLab"],
            "ap_bssid": ["aa:bb:cc:dd:ee:ff"],
            "ap_channel": ["3"],
        }
    )
    saved = load_config(str(config_path), quiet=True)

    assert saved["wifi_target_mode"] == "manual"
    assert saved["ap_essid"] == "HiddenLab"
    assert saved["ap_bssid"] == "aa:bb:cc:dd:ee:ff"
    assert saved["ap_channel"] == 3


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


def test_dashboard_monitor_action_resolves_auto_wifi_target(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "lab.json"
    save_config(
        {
            "output_dir": str(tmp_path / "pipeline_output"),
            "wifi_target_mode": "auto",
            "monitor_method": "airodump",
        },
        str(config_path),
        quiet=True,
    )
    state = DashboardState(config_path=config_path)
    seen: dict[str, object] = {}
    monkeypatch.setattr(
        "wifi_pipeline.webapp.discover_wifi_targets",
        lambda *args, **kwargs: [
            {
                "ssid": "LabNet",
                "bssid": "00:11:22:33:44:55",
                "channel": 11,
                "signal": 82,
                "signal_label": "82%",
                "security": "WPA2-Personal",
                "source": "test",
                "connected": True,
            }
        ],
    )

    class FakeCapture:
        def __init__(self, config):
            seen["config"] = config

        def run_monitor(self, method: str, interactive: bool = False):
            seen["method"] = method
            seen["interactive"] = interactive
            return "monitor.cap"

    monkeypatch.setattr("wifi_pipeline.webapp.Capture", FakeCapture)

    message = state._execute_action("monitor", {})
    saved = load_config(str(config_path), quiet=True)

    assert message == "monitor.cap"
    assert seen["config"]["ap_essid"] == "LabNet"
    assert seen["config"]["ap_bssid"] == "00:11:22:33:44:55"
    assert seen["config"]["ap_channel"] == 11
    assert seen["method"] == "airodump"
    assert seen["interactive"] is False
    assert saved["ap_essid"] == "LabNet"
    assert saved["wifi_target_mode"] == "auto"


def test_dashboard_execute_remote_actions_and_records_reports(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "lab.json"
    output_dir = tmp_path / "pipeline_output"
    save_config(
        {
            "output_dir": str(output_dir),
            "remote_host": "david@raspi-sniffer",
            "remote_interface": "wlan0",
            "remote_dest_dir": str(tmp_path / "remote_imports"),
            "capture_duration": 7,
        },
        str(config_path),
        quiet=True,
    )
    state = DashboardState(config_path=config_path)
    pulled_path = tmp_path / "remote_imports" / "capture.pcap"

    monkeypatch.setattr(
        "wifi_pipeline.webapp.discover_remote_appliances",
        lambda config: [
            {
                "host": "raspi-sniffer",
                "ssh_target": "david@raspi-sniffer",
                "health_endpoint": "http://raspi-sniffer:8741/health",
                "health_port": "8741",
                "capture_dir": "/home/david/wifi-pipeline/captures",
            }
        ],
    )
    monkeypatch.setattr(
        "wifi_pipeline.webapp.doctor_remote_host",
        lambda config, **kwargs: {
            "ok": True,
            "remote": {
                "reachable": True,
                "service_status": "idle",
                "tcpdump": True,
                "iw": True,
                "health_endpoint": "http://raspi-sniffer:8741/health",
                "health_probe_ok": True,
            },
        },
    )
    monkeypatch.setattr(
        "wifi_pipeline.webapp.bootstrap_remote_host",
        lambda config, **kwargs: {"capture_dir": "/home/david/wifi-pipeline/captures"},
    )
    monkeypatch.setattr(
        "wifi_pipeline.webapp.remote_service_host",
        lambda config, action, **kwargs: {"service_status": "idle", "last_capture": "/tmp/last.pcap", "output": "/tmp/new.pcap"},
    )
    monkeypatch.setattr("wifi_pipeline.webapp.start_remote_capture", lambda config, **kwargs: pulled_path)
    monkeypatch.setattr("wifi_pipeline.webapp.pull_remote_capture", lambda config, **kwargs: pulled_path)

    assert "Discovered 1 remote appliance" in state._execute_action("discover_remote", {})
    assert (output_dir / "remote_discovery.json").exists()

    assert state._execute_action("remote_doctor", {}) == "Remote doctor passed."
    assert (output_dir / "remote_doctor_report.json").exists()

    assert "Remote bootstrap complete" in state._execute_action("bootstrap_remote", {})
    assert "Remote service status: idle" == state._execute_action("remote_status", {})
    assert "Remote capture imported" in state._execute_action("start_remote", {})
    assert "Remote capture pulled" in state._execute_action("pull_remote", {})


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
                "remote_host": "david@raspi-sniffer",
                "remote_interface": "wlan0",
                "remote_path": "/home/david/wifi-pipeline/captures/",
                "remote_port": 22,
                "remote_dest_dir": "./pipeline_output/remote_imports",
                "remote_health_port": 8741,
                "remote_poll_interval": 8,
                "remote_install_mode": "auto",
                "remote_install_profile": "appliance",
                "wifi_target_mode": "auto",
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
                "wifi_targets": [
                    {
                        "ssid": "LabNet <main>",
                        "bssid": "00:11:22:33:44:55",
                        "channel": 11,
                        "signal": 82,
                        "signal_label": "82%",
                        "security": "WPA2-Personal",
                        "source": "test",
                        "connected": True,
                    }
                ],
                "wifi_auto_target": {
                    "ssid": "LabNet <main>",
                    "bssid": "00:11:22:33:44:55",
                    "channel": 11,
                    "signal": 82,
                    "signal_label": "82%",
                    "security": "WPA2-Personal",
                    "source": "test",
                    "connected": True,
                },
                "wifi_target_mode": "auto",
                "artifacts": [{"label": "Capture", "path": "C:/tmp/capture.pcapng", "exists": True}],
                "operator_inventory": {
                    "headline": "1 ready tool, 0 blocked tools, 1 device.",
                    "tools": [
                        {
                            "label": "Remote capture + pull",
                            "category": "Raspberry Pi",
                            "status": "ready",
                            "summary": "Capture on the Pi and import locally.",
                            "action": "start_remote",
                            "next_step": "Run Capture + Pull.",
                            "requirements": [
                                {
                                    "label": "Remote host",
                                    "value": "david@raspi-sniffer",
                                    "status": "ready",
                                    "detail": "Configured.",
                                    "required": True,
                                }
                            ],
                        }
                    ],
                    "devices": [
                        {
                            "name": "david@raspi-sniffer",
                            "scope": "Raspberry Pi appliance",
                            "status": "ready",
                            "role": "Configured remote capture node",
                            "summary": "http://raspi-sniffer:8741/health",
                            "details": ["Interface: wlan0", "Service: idle"],
                        }
                    ],
                },
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
    assert "Operator Console" in html
    assert "Tool Requirements" in html
    assert "Detected Devices" in html
    assert "Auto Wi-Fi Targeting" in html
    assert "LabNet &lt;main&gt;" in html
    assert "Manual / keep override fields below" in html
    assert "Remote capture + pull" in html
    assert "david@raspi-sniffer" in html
    assert "Remote Doctor" in html
    assert "Remote Host" in html
    assert "Replay + WPA Readiness" in html
    assert "Capture more payload before replaying." in html
    assert "Capture a handshake before retrying WPA decrypt." in html


def test_render_dashboard_html_tolerates_malformed_snapshot_sections() -> None:
    html = render_dashboard_html(
        {
            "config": {
                "target_macs": "aa:bb:cc:dd:ee:ff",
                "protocol": "udp",
                "monitor_method": "airodump",
                "playback_mode": "both",
            },
            "bundle": {
                "analysis": {
                    "hypotheses": "not-a-list",
                    "recommendations": "Capture more <payload>.",
                    "ciphertext_observations": "not-a-dict",
                },
                "status_bundle": {
                    "machine_summary": {
                        "headline": "Controller view",
                        "items": [
                            "bad-machine-row",
                            {
                                "label": "Controller <A>",
                                "status": "limited",
                                "summary": "Usable with caveats.",
                                "reason": "Missing optional adapter.",
                                "next_step": "Use the Pi.",
                            },
                        ],
                    },
                    "workflow": [
                        "bad-workflow-row",
                        {
                            "area": "Capture <flow>",
                            "status": "limited",
                            "summary": "Flow survives malformed rows.",
                            "reasons": "Single reason <ok>",
                            "next_steps": "Single next step <ok>",
                        },
                    ],
                    "selection": {"status": "limited", "notes": "single note", "next_steps": "single selection step"},
                    "replay": {
                        "status": "limited",
                        "reasons": "single replay reason",
                        "next_steps": "single replay step",
                        "confidence": "not-a-dict",
                    },
                    "wpa": {"status": "blocked", "reasons": "single WPA reason", "next_steps": "single WPA step"},
                },
                "operator_inventory": {
                    "tools": [
                        "bad-tool-row",
                        {
                            "label": "Tool <x>",
                            "category": "Raspberry Pi",
                            "status": "ready",
                            "summary": "Runs safely.",
                            "requirements": "malformed requirement row",
                            "next_step": "Run it.",
                        },
                    ],
                    "devices": [
                        "bad-device-row",
                        {
                            "name": "Device <x>",
                            "scope": "secure mesh",
                            "status": "ready",
                            "role": "Peer",
                            "summary": "Detected.",
                            "details": "single detail",
                        },
                    ],
                },
                "candidate_rows": [
                    "bad-candidate-row",
                    {"candidate_class": "jpeg", "score": 0.5, "stream_id": "stream<1>", "byte_count": 123},
                ],
                "corpus_entries": [
                    "bad-corpus-row",
                    {
                        "entry_id": "entry<1>",
                        "candidate_class": "jpeg",
                        "dominant_unit_type": "image",
                        "candidate_material_available": True,
                        "stream_id": "stream<1>",
                    },
                ],
                "corpus_status": {"latest_entry": "not-a-dict"},
                "interfaces": ["bad-interface-row", ("1", "wlan0", "Wireless <adapter>")],
                "artifacts": ["bad-artifact-row", {"label": "Capture <cap>", "path": "C:/tmp/<cap>.pcap", "exists": True}],
            },
            "logs": [
                "bad-log-row",
                {"timestamp": "not-a-timestamp", "action": "detect", "status": "ok<script>", "message": "Saved <x>", "output": "A&B"},
            ],
        },
        capture_path="C:/tmp/capture.pcap",
    )

    assert "Controller &lt;A&gt;" in html
    assert "Capture &lt;flow&gt;" in html
    assert "Single reason &lt;ok&gt;" in html
    assert "Tool &lt;x&gt;" in html
    assert "Device &lt;x&gt;" in html
    assert "stream&lt;1&gt;" in html
    assert "entry&lt;1&gt;" in html
    assert "Wireless &lt;adapter&gt;" in html
    assert "Capture &lt;cap&gt;" in html
    assert "Saved &lt;x&gt;" in html
    assert "A&amp;B" in html
    assert "Capture more &lt;payload&gt;." in html


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
    monkeypatch.setattr(
        "wifi_pipeline.webapp.discover_wifi_targets",
        lambda *args, **kwargs: [
            {
                "ssid": "LabNet",
                "bssid": "00:11:22:33:44:55",
                "channel": 11,
                "signal": 82,
                "signal_label": "82%",
                "security": "WPA2-Personal",
                "source": "test",
                "connected": True,
            }
        ],
    )

    snapshot = state.snapshot()

    assert snapshot["bundle"]["status_bundle"]["machine_summary"]["headline"] == "Ubuntu standalone / privilege=root"
    assert snapshot["bundle"]["status_bundle"]["workflow"][0]["area"] == "local packet capture"
    assert snapshot["bundle"]["status_bundle"]["replay"]["status"] == "ready"
    assert snapshot["bundle"]["wifi_auto_target"]["ssid"] == "LabNet"
    assert snapshot["bundle"]["operator_inventory"]["tools"]
    assert any(tool["label"] == "Remote doctor" for tool in snapshot["bundle"]["operator_inventory"]["tools"])


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
        _wait_for_server("127.0.0.1", server.server_address[1])
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
