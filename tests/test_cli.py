from __future__ import annotations

import argparse
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


def test_build_parser_parses_bootstrap_remote_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(
        ["bootstrap-remote", "--host", "pi@raspberrypi", "--skip-packages", "--skip-pair"]
    )

    assert args.command == "bootstrap-remote"
    assert args.host == "pi@raspberrypi"
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
        ["setup-remote", "--host", "pi@raspberrypi", "--interface", "wlan0", "--duration", "30", "--smoke-test"]
    )

    assert args.command == "setup-remote"
    assert args.host == "pi@raspberrypi"
    assert args.interface == "wlan0"
    assert args.duration == 30
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


def test_run_start_remote_runs_followup_stages(monkeypatch) -> None:
    calls: list[str] = []

    monkeypatch.setattr(cli, "start_remote_capture", lambda *args, **kwargs: Path("capture.pcap"))
    monkeypatch.setattr(cli, "_run_after_pull", lambda config, path, mode: calls.extend([path, mode]))

    result = cli.run_start_remote({}, host="pi@raspberrypi", interface="wlan0", duration=60, run_mode="all")

    assert result == "capture.pcap"
    assert calls == ["capture.pcap", "all"]


def test_run_doctor_combines_local_and_remote_checks(monkeypatch) -> None:
    monkeypatch.setattr(cli, "check_environment", lambda: True)
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


def test_run_remote_service_calls_remote_helper(monkeypatch) -> None:
    monkeypatch.setattr(cli, "remote_service_host", lambda *args, **kwargs: {"service_status": "idle"})

    assert cli.run_remote_service({}, "status", host="pi@raspberrypi") is True


def test_run_setup_remote_saves_config_and_smoke_tests(monkeypatch) -> None:
    saved: dict[str, object] = {}
    smoke_calls: list[dict[str, object]] = []

    monkeypatch.setattr(cli, "IS_WINDOWS", True)
    monkeypatch.setattr(cli, "run_pair_remote", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        cli,
        "run_bootstrap_remote",
        lambda *args, **kwargs: {
            "capture_dir": "/home/pi/wifi-pipeline/captures",
            "service_cmd": "/home/pi/wifi-pipeline/bin/wifi-pipeline-service",
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
        host="pi@raspberrypi",
        port=2222,
        identity="C:\\keys\\pi",
        interface="wlan0",
        dest_dir="./imports",
        duration=30,
        smoke_test=True,
    )

    assert result is True
    assert saved["path"] == "custom.json"
    assert saved["config"]["remote_host"] == "pi@raspberrypi"
    assert saved["config"]["remote_port"] == 2222
    assert saved["config"]["remote_identity"] == "C:\\keys\\pi"
    assert saved["config"]["remote_interface"] == "wlan0"
    assert saved["config"]["remote_dest_dir"] == "./imports"
    assert saved["config"]["remote_path"] == "/home/pi/wifi-pipeline/captures/"
    assert smoke_calls == [
        {
            "host": "pi@raspberrypi",
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

    monkeypatch.setattr(cli, "check_environment", lambda: True)
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


def test_run_validate_remote_skip_smoke_can_still_pass(monkeypatch, tmp_path) -> None:
    report_path = tmp_path / "validation.json"

    monkeypatch.setattr(cli, "check_environment", lambda: True)
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
