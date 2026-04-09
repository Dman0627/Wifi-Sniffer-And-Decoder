from __future__ import annotations

import argparse
import io
from pathlib import Path

import pytest

from wifi_pipeline import cli


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("extract", ["extract"]),
        ("detect", ["extract", "detect"]),
        ("analyze", ["extract", "detect", "analyze"]),
        ("play", ["extract", "detect", "analyze", "play"]),
        ("all", ["extract", "detect", "analyze", "play"]),
    ],
)
def test_run_after_pull_dispatches_expected_stages(monkeypatch, mode: str, expected: list[str]) -> None:
    calls: list[str] = []

    monkeypatch.setattr(cli, "run_extract", lambda config, pcap: calls.append("extract"))
    monkeypatch.setattr(cli, "run_detect", lambda config, manifest_path=None: calls.append("detect"))
    monkeypatch.setattr(cli, "run_analyze", lambda config, decrypted_dir=None: calls.append("analyze"))
    monkeypatch.setattr(cli, "run_play", lambda config: calls.append("play"))

    cli._run_after_pull({}, "capture.pcapng", mode)

    assert calls == expected


def test_map_legacy_stage_maps_old_commands() -> None:
    args = argparse.Namespace(stage="live", command=None)

    mapped = cli._map_legacy_stage(args)

    assert mapped.command == "play"


def test_build_parser_parses_remote_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(
        ["remote", "--host", "pi@raspberrypi", "--path", "/tmp/capture.pcapng", "--run", "all"]
    )

    assert args.command == "remote"
    assert args.host == "pi@raspberrypi"
    assert args.run == "all"


def test_build_parser_parses_pair_remote_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(["pair-remote", "--host", "pi@raspberrypi"])

    assert args.command == "pair-remote"
    assert args.host == "pi@raspberrypi"


def test_build_parser_help_renders_to_cp1252_stream() -> None:
    parser = cli.build_parser()
    buffer = io.BytesIO()
    stream = io.TextIOWrapper(buffer, encoding="cp1252")

    parser.print_help(file=stream)
    stream.flush()

    output = buffer.getvalue().decode("cp1252")
    assert "WiFi payload pipeline - official product modes:" in output
    assert "Full Wi-Fi pipeline: monitor mode -> handshake capture" in output
    assert "-> WPA2 crack -> airdecap-ng" in output


def test_build_parser_parses_discover_remote_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(
        ["discover-remote", "--network", "192.168.1.0/24", "--health-port", "9001", "--timeout", "0.5", "--max-hosts", "20"]
    )

    assert args.command == "discover-remote"
    assert args.network == ["192.168.1.0/24"]
    assert args.health_port == 9001
    assert args.timeout == 0.5
    assert args.max_hosts == 20


def test_build_parser_parses_bootstrap_remote_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(
        [
            "bootstrap-remote",
            "--host",
            "pi@raspberrypi",
            "--install-mode",
            "bundle",
            "--install-profile",
            "appliance",
            "--health-port",
            "9001",
            "--skip-packages",
            "--skip-pair",
        ]
    )

    assert args.command == "bootstrap-remote"
    assert args.host == "pi@raspberrypi"
    assert args.install_mode == "bundle"
    assert args.install_profile == "appliance"
    assert args.health_port == 9001
    assert args.skip_packages is True
    assert args.skip_pair is True


def test_build_parser_parses_start_remote_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(
        ["start-remote", "--host", "pi@raspberrypi", "--interface", "wlan0", "--duration", "60"]
    )

    assert args.command == "start-remote"
    assert args.host == "pi@raspberrypi"
    assert args.interface == "wlan0"
    assert args.duration == 60


def test_build_parser_parses_doctor_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(["doctor", "--host", "pi@raspberrypi", "--interface", "wlan0"])

    assert args.command == "doctor"
    assert args.host == "pi@raspberrypi"
    assert args.interface == "wlan0"


def test_build_parser_parses_remote_service_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(
        ["remote-service", "start", "--host", "pi@raspberrypi", "--interface", "wlan0", "--duration", "45"]
    )

    assert args.command == "remote-service"
    assert args.action == "start"
    assert args.host == "pi@raspberrypi"
    assert args.interface == "wlan0"
    assert args.duration == 45


def test_build_parser_parses_setup_remote_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(
        [
            "setup-remote",
            "--host",
            "pi@raspberrypi",
            "--interface",
            "wlan0",
            "--duration",
            "30",
            "--install-mode",
            "native",
            "--install-profile",
            "standard",
            "--health-port",
            "9002",
            "--smoke-test",
        ]
    )

    assert args.command == "setup-remote"
    assert args.host == "pi@raspberrypi"
    assert args.interface == "wlan0"
    assert args.duration == 30
    assert args.install_mode == "native"
    assert args.install_profile == "standard"
    assert args.health_port == 9002
    assert args.smoke_test is True


def test_build_parser_parses_validate_remote_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(
        ["validate-remote", "--host", "pi@raspberrypi", "--interface", "wlan0", "--duration", "12", "--skip-smoke"]
    )

    assert args.command == "validate-remote"
    assert args.host == "pi@raspberrypi"
    assert args.interface == "wlan0"
    assert args.duration == 12
    assert args.skip_smoke is True


def test_build_parser_parses_validate_local_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(["validate-local", "--interface", "wlan0", "--duration", "12", "--skip-smoke"])

    assert args.command == "validate-local"
    assert args.interface == "wlan0"
    assert args.duration == 12
    assert args.skip_smoke is True


def test_build_parser_parses_hardware_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(["hardware"])

    assert args.command == "hardware"


def test_build_parser_parses_crack_status_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(["crack-status", "--cap", "capture.cap"])

    assert args.command == "crack-status"
    assert args.cap == "capture.cap"


def test_build_parser_parses_preflight_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(["preflight"])

    assert args.command == "preflight"


def test_build_parser_parses_enrich_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(["enrich", "--manifest", "manifest.json"])

    assert args.command == "enrich"
    assert args.manifest == "manifest.json"


def test_build_parser_parses_release_gate_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(
        [
            "release-gate",
            "--ubuntu-report",
            "u.json",
            "--pi-report",
            "p.json",
            "--windows-report",
            "w.json",
            "--sample-report",
            "sample.json",
            "--write-summary",
            "summary.json",
        ]
    )

    assert args.command == "release-gate"
    assert args.ubuntu_report == "u.json"
    assert args.pi_report == "p.json"
    assert args.windows_report == "w.json"
    assert args.sample_report == ["sample.json"]
    assert args.write_summary == "summary.json"


def test_run_play_prefers_offline_reconstruction(monkeypatch) -> None:
    report = {
        "candidate_material": {"mode": "static_xor_candidate", "key_hex": "01"},
        "selected_candidate_stream": {"stream_id": "stream-1", "unit_type_counts": {"plain_text": 1}},
    }
    started: list[bool] = []

    class DummyPlayback:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def start(self) -> str:
            started.append(True)
            return "live-output"

    monkeypatch.setattr(cli, "_load_report", lambda config: report)
    monkeypatch.setattr(cli, "infer_replay_hint", lambda config, current_report: "txt")
    monkeypatch.setattr(cli, "reconstruct_from_capture", lambda config, current_report: "offline-output")
    monkeypatch.setattr(cli, "ExperimentalPlayback", DummyPlayback)

    result = cli.run_play({"output_dir": "."})

    assert result == "offline-output"
    assert started == []


def test_run_play_refuses_unsupported_replay_family(monkeypatch) -> None:
    report = {
        "candidate_material": {"mode": "static_xor_candidate", "key_hex": "01"},
        "selected_candidate_stream": {"stream_id": "stream-1", "unit_type_counts": {"opaque_chunk": 1}},
        "selected_protocol_support": {"replay_level": "unsupported", "detail": "unsupported family"},
    }

    monkeypatch.setattr(cli, "_load_report", lambda config: report)
    monkeypatch.setattr(cli, "reconstruct_from_capture", lambda config, current_report: "should-not-run")

    result = cli.run_play({"output_dir": "."})

    assert result is None


def test_run_preflight_returns_false_when_blocked(monkeypatch) -> None:
    monkeypatch.setattr(
        cli,
        "print_pipeline_feasibility",
        lambda config, report: {"status": "blocked", "replay": {"status": "blocked"}, "capabilities": {}},
    )
    monkeypatch.setattr(cli, "_load_report", lambda config: None)

    assert cli.run_preflight({"output_dir": "."}) is False


def test_show_report_summary_uses_shared_status_language(monkeypatch, capsys) -> None:
    detection = {
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "candidate_class": "png",
            "score": 88,
        },
        "selected_protocol_support": {
            "decode_level": "high_confidence",
            "replay_level": "heuristic",
        },
        "protocol_hits": {"opaque": 0},
    }
    analysis = {
        "selected_candidate_stream": {"stream_id": "stream-1"},
        "ciphertext_observations": {"chi_squared": 1.23},
        "total_units": 12,
        "hypotheses": [{"name": "PNG"}],
        "recommendations": ["Capture more payload."],
    }

    monkeypatch.setattr(
        cli,
        "_load_json",
        lambda path: detection if path.name == "detection_report.json" else analysis if path.name == "analysis_report.json" else None,
    )
    monkeypatch.setattr(
        cli,
        "build_surface_status_bundle",
        lambda config, current_detection, current_analysis: {
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
            "replay": {
                "status": "limited",
                "summary": "Replay can proceed, but there are caveats you should see first.",
                "warnings": ["Thin capture sample."],
                "blockers": [],
                "next_steps": ["Capture more payload before replaying."],
                "confidence": {
                    "confidence_band": "limited",
                    "confidence_label": "heuristic",
                    "confidence_score": 0.58,
                },
            },
            "wpa": {
                "status": "blocked",
                "summary": "A usable WPA artifact is still missing.",
                "reasons": ["No handshake or PMKID capture is available."],
                "next_steps": ["Capture a handshake before retrying WPA decrypt."],
            },
        },
    )

    cli._show_report_summary({"output_dir": "."})
    output = capsys.readouterr().out

    assert "Replay Path" in output
    assert "Replay Summary" in output
    assert "Top Caveat" in output
    assert "Capture more payload before replaying." in output
    assert "WPA Path" in output
    assert "A usable WPA artifact is still missing." in output
    assert "What This Machine Can Do" in output
    assert "Windows controller + Linux appliance / privilege=user" in output
    assert "Prefer the Linux appliance path for full Wi-Fi lab work." in output


def test_run_hardware_uses_capability_report(monkeypatch) -> None:
    seen = {}

    monkeypatch.setattr(cli, "build_capability_report", lambda config: {"config": dict(config)})
    monkeypatch.setattr(cli, "print_capability_hardware", lambda report: seen.setdefault("report", report))

    assert cli.run_hardware({"interface": "wlan0"}) is True
    assert seen["report"] == {"config": {"interface": "wlan0"}}


def test_run_analyze_attaches_feasibility(monkeypatch) -> None:
    report = {"selected_candidate_stream": {"stream_id": "stream-1"}, "candidate_material": {}}

    class DummyAnalyzer:
        def __init__(self, config) -> None:
            self.config = config

        def analyze(self, decrypted_dir=None):
            return report

    monkeypatch.setattr(cli, "CryptoAnalyzer", DummyAnalyzer)
    monkeypatch.setattr(
        cli,
        "attach_feasibility_to_report",
        lambda config, current_report, report_path: {**current_report, "feasibility": {"status": "blocked"}},
    )

    result = cli.run_analyze({"output_dir": "."}, None)

    assert result["feasibility"]["status"] == "blocked"


def test_run_enrich_uses_artifact_enricher(monkeypatch) -> None:
    report = {"units_analyzed": 3}

    class DummyEnricher:
        def __init__(self, config) -> None:
            self.config = config

        def enrich(self, manifest_path=None):
            return report

    monkeypatch.setattr(cli, "ArtifactEnricher", DummyEnricher)

    result = cli.run_enrich({"output_dir": "."}, "manifest.json")

    assert result == report


def test_run_all_includes_enrich_before_replay(monkeypatch) -> None:
    calls: list[str] = []

    monkeypatch.setattr(cli, "run_extract", lambda config, pcap: calls.append("extract"))
    monkeypatch.setattr(cli, "run_detect", lambda config, manifest_path=None: calls.append("detect"))
    monkeypatch.setattr(cli, "run_analyze", lambda config, decrypted_dir=None: calls.append("analyze") or {"candidate_material": {"mode": "x"}})
    monkeypatch.setattr(cli, "run_enrich", lambda config, manifest_path=None: calls.append("enrich"))
    monkeypatch.setattr(cli, "run_play", lambda config: calls.append("play"))

    cli.run_all({}, "capture.pcapng", None, False)

    assert calls == ["extract", "detect", "analyze", "enrich", "play"]


def test_run_release_gate_returns_true_when_fully_validated(monkeypatch, tmp_path) -> None:
    written = {}
    monkeypatch.setattr(cli, "evaluate_release_gate", lambda **kwargs: {"status": "ready", "fully_validated": True, "matrix": {}, "sample_reports": []})
    monkeypatch.setattr(cli, "print_release_gate", lambda result: result)

    from wifi_pipeline import release_gate as release_gate_module

    monkeypatch.setattr(
        release_gate_module,
        "write_release_gate_summary",
        lambda result, path: written.setdefault("path", str(path)) or path,
    )

    assert cli.run_release_gate({}, write_summary=str(tmp_path / "summary.json")) is True


def test_run_start_remote_runs_followup_stages(monkeypatch) -> None:
    calls: list[str] = []

    monkeypatch.setattr(cli, "start_remote_capture", lambda *args, **kwargs: Path("capture.pcap"))
    monkeypatch.setattr(cli, "_run_after_pull", lambda config, path, mode: calls.extend([path, mode]))

    result = cli.run_start_remote({}, host="pi@raspberrypi", interface="wlan0", duration=60, run_mode="all")

    assert result == "capture.pcap"
    assert calls == ["capture.pcap", "all"]


def test_run_doctor_combines_local_and_remote_checks(monkeypatch) -> None:
    monkeypatch.setattr(cli, "check_environment", lambda config=None: True)
    monkeypatch.setattr(
        cli,
        "doctor_remote_host",
        lambda config, host=None, port=None, identity=None, interface=None: {
            "ok": True,
            "host": host,
            "local": {"ssh": True, "scp": True, "public_key": True},
            "remote": {
                "reachable": True,
                "home": "/home/pi",
                "agent": True,
                "agent_path": "/home/pi/.local/bin/wifi-pipeline-agent",
                "agent_protocol": "capture-agent/v1",
                "control_mode": "agent",
                "install_profile": "appliance",
                "health_endpoint": "http://0.0.0.0:8741/health",
                "health_socket_enabled": True,
                "appliance_service_enabled": True,
                "tcpdump": True,
                "helper": True,
                "helper_path": "/home/pi/.local/bin/wifi-pipeline-capture",
                "service": True,
                "service_path": "/home/pi/.local/bin/wifi-pipeline-service",
                "service_status": "idle",
                "privileged_runner": True,
                "privileged_runner_path": "/usr/local/bin/wifi-pipeline-capture-privileged",
                "privilege_mode": "sudoers_runner",
                "capture_dir": "/home/pi/wifi-pipeline/captures",
                "capture_dir_exists": True,
                "capture_dir_writable": True,
                "interface": "wlan0",
                "interface_exists": True,
            },
        },
    )

    assert cli.run_doctor({"remote_host": "pi@raspberrypi"}, interface="wlan0") is True


def test_run_discover_remote_returns_results(monkeypatch) -> None:
    monkeypatch.setattr(
        cli,
        "discover_remote_appliances",
        lambda *args, **kwargs: [
            {
                "device_name": "pi-node",
                "host": "192.168.1.10",
                "ssh_target": "pi@192.168.1.10",
                "health_endpoint": "http://192.168.1.10:8741/health",
                "install_profile": "appliance",
            }
        ],
    )

    results = cli.run_discover_remote({}, max_hosts=8)

    assert results[0]["ssh_target"] == "pi@192.168.1.10"


def test_run_remote_service_calls_remote_helper(monkeypatch) -> None:
    monkeypatch.setattr(cli, "remote_service_host", lambda *args, **kwargs: {"service_status": "idle"})

    assert cli.run_remote_service({}, "status", host="pi@raspberrypi") is True


def test_run_setup_remote_saves_config_and_smoke_tests(monkeypatch) -> None:
    saved: dict[str, object] = {}
    smoke_calls: list[dict[str, object]] = []
    bootstrap_calls: list[dict[str, object]] = []

    monkeypatch.setattr(cli, "IS_WINDOWS", True)
    monkeypatch.setattr(
        cli,
        "discover_remote_appliances",
        lambda *args, **kwargs: [{"device_name": "pi-node", "host": "192.168.1.10", "ssh_target": "pi@192.168.1.10"}],
    )
    monkeypatch.setattr(cli, "run_pair_remote", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        cli,
        "run_bootstrap_remote",
        lambda *args, **kwargs: bootstrap_calls.append(dict(kwargs)) or {
            "capture_dir": "/home/pi/wifi-pipeline/captures",
            "service_cmd": "/home/pi/wifi-pipeline/bin/wifi-pipeline-service",
            "health_endpoint": "http://0.0.0.0:8741/health",
        },
    )
    monkeypatch.setattr(cli, "run_doctor", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        cli,
        "run_start_remote",
        lambda config, **kwargs: smoke_calls.append(kwargs) or "capture.pcap",
    )
    monkeypatch.setattr(
        cli,
        "save_config",
        lambda config, path="lab.json": saved.update({"path": path, "config": dict(config)}),
    )

    config = {}
    result = cli.run_setup_remote(
        config,
        config_path="custom.json",
        host=None,
        port=2222,
        identity="C:\\keys\\pi",
        interface="wlan0",
        dest_dir="./imports",
        duration=30,
        install_mode="bundle",
        install_profile="appliance",
        health_port=8741,
        smoke_test=True,
    )

    assert result is True
    assert saved["path"] == "custom.json"
    assert saved["config"]["remote_host"] == "pi@192.168.1.10"
    assert saved["config"]["remote_port"] == 2222
    assert saved["config"]["remote_identity"] == "C:\\keys\\pi"
    assert saved["config"]["remote_interface"] == "wlan0"
    assert saved["config"]["remote_install_mode"] == "bundle"
    assert saved["config"]["remote_install_profile"] == "appliance"
    assert saved["config"]["remote_health_port"] == 8741
    assert saved["config"]["remote_dest_dir"] == "./imports"
    assert saved["config"]["remote_path"] == "/home/pi/wifi-pipeline/captures/"
    assert bootstrap_calls[0]["install_mode"] == "bundle"
    assert bootstrap_calls[0]["install_profile"] == "appliance"
    assert bootstrap_calls[0]["health_port"] == 8741
    assert smoke_calls == [
        {
            "host": "pi@192.168.1.10",
            "port": 2222,
            "identity": "C:\\keys\\pi",
            "interface": "wlan0",
            "duration": 15,
            "run_mode": "none",
        }
    ]


def test_run_validate_remote_writes_report(monkeypatch, tmp_path) -> None:
    report_path = tmp_path / "validation.json"
    capture_path = tmp_path / "capture.pcap"
    capture_path.write_bytes(b"pcap")

    monkeypatch.setattr(cli, "check_environment", lambda config=None: True)
    monkeypatch.setattr(
        cli,
        "doctor_remote_host",
        lambda *args, **kwargs: {"ok": True, "host": "pi@raspberrypi", "local": {}, "remote": {}},
    )
    monkeypatch.setattr(cli, "_print_remote_doctor", lambda report: None)
    monkeypatch.setattr(
        cli,
        "remote_service_host",
        lambda config, action, **kwargs: {"service_status": "idle", "action": action},
    )
    monkeypatch.setattr(cli, "start_remote_capture", lambda *args, **kwargs: capture_path)

    result = cli.run_validate_remote(
        {"output_dir": str(tmp_path), "remote_host": "pi@raspberrypi", "remote_interface": "wlan0"},
        host="pi@raspberrypi",
        interface="wlan0",
        duration=12,
        report_path=str(report_path),
    )

    assert result is True
    data = __import__("json").loads(report_path.read_text(encoding="utf-8"))
    assert data["overall_ok"] is True
    assert data["smoke_capture"]["success"] is True
    assert data["smoke_capture"]["size_bytes"] == 4
    assert data["capability_report"]["platform"]["product_profile_label"]
    assert data["status_bundle"]["machine_summary"]["items"]
    assert data["status_bundle"]["workflow"]


def test_run_validate_remote_skip_smoke_can_still_pass(monkeypatch, tmp_path) -> None:
    report_path = tmp_path / "validation.json"

    monkeypatch.setattr(cli, "check_environment", lambda config=None: True)
    monkeypatch.setattr(
        cli,
        "doctor_remote_host",
        lambda *args, **kwargs: {"ok": True, "host": "pi@raspberrypi", "local": {}, "remote": {}},
    )
    monkeypatch.setattr(cli, "_print_remote_doctor", lambda report: None)
    monkeypatch.setattr(
        cli,
        "remote_service_host",
        lambda config, action, **kwargs: {"service_status": "idle", "action": action},
    )
    monkeypatch.setattr(cli, "start_remote_capture", lambda *args, **kwargs: None)

    result = cli.run_validate_remote(
        {"output_dir": str(tmp_path), "remote_host": "pi@raspberrypi"},
        host="pi@raspberrypi",
        report_path=str(report_path),
        skip_smoke=True,
    )

    assert result is True
    data = __import__("json").loads(report_path.read_text(encoding="utf-8"))
    assert data["capability_report"]["capture_methods"]
    assert data["status_bundle"]["replay"]["status"]


def test_run_validate_local_writes_report(monkeypatch, tmp_path) -> None:
    capture_path = tmp_path / "capture.pcapng"
    capture_path.write_bytes(b"pcap")
    report_path = tmp_path / "standalone-validation.json"

    monkeypatch.setattr(cli, "check_environment", lambda config=None: True)
    monkeypatch.setattr(cli, "list_interfaces", lambda: [("1", "wlan0", "wireless")])
    monkeypatch.setattr(cli, "run_capture", lambda config, strip_wifi=False: str(capture_path))
    monkeypatch.setattr(cli, "run_extract", lambda config, pcap: {"streams": 1})
    monkeypatch.setattr(cli, "run_detect", lambda config, manifest_path=None: {"selected_candidate_stream": {"stream_id": "s1"}})
    monkeypatch.setattr(
        cli,
        "run_analyze",
        lambda config, decrypted_dir=None: {
            "candidate_material": {"mode": "static_xor_candidate"},
            "selected_protocol_support": {"replay_level": "guaranteed", "dominant_unit_type": "plain_text"},
            "selected_replay_confidence": {
                "handler_id": "txt",
                "confidence_label": "guaranteed",
                "supported": True,
            },
        },
    )

    result = cli.run_validate_local(
        {"output_dir": str(tmp_path), "interface": "wlan0", "capture_duration": 20},
        interface="wlan0",
        duration=12,
        report_path=str(report_path),
    )

    assert result is True
    data = __import__("json").loads(report_path.read_text(encoding="utf-8"))
    assert data["overall_ok"] is True
    assert data["smoke_capture"]["success"] is True
    assert data["processing_smoke"]["success"] is True
    assert data["interface_check"]["present"] is True
    assert data["processing_smoke"]["selected_replay_confidence"]["handler_id"] == "txt"
    assert data["capability_report"]["platform"]["product_profile_label"]
    assert data["status_bundle"]["machine_summary"]["items"]


def test_run_validate_local_skip_smoke_can_still_pass(monkeypatch, tmp_path) -> None:
    report_path = tmp_path / "standalone-validation.json"

    monkeypatch.setattr(cli, "check_environment", lambda config=None: True)
    monkeypatch.setattr(cli, "list_interfaces", lambda: [("1", "wlan0", "wireless")])

    result = cli.run_validate_local(
        {"output_dir": str(tmp_path), "interface": "wlan0"},
        interface="wlan0",
        report_path=str(report_path),
        skip_smoke=True,
    )

    assert result is True
    data = __import__("json").loads(report_path.read_text(encoding="utf-8"))
    assert data["overall_ok"] is True
    assert data["capability_report"]["capture_methods"]
    assert data["status_bundle"]["wpa"]["status"]
    assert data["smoke_capture"]["requested"] is False
