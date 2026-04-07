from __future__ import annotations

import json
from pathlib import Path

import pytest

from wifi_pipeline import cli, environment


def _set_windows_remote(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", True)
    monkeypatch.setattr(environment, "IS_LINUX", False)
    monkeypatch.setattr(environment, "IS_MACOS", False)


def _set_linux_profile(monkeypatch, *, distro_id: str, pretty_name: str, model: str = "") -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(
        environment,
        "_read_os_release",
        lambda: {"ID": distro_id, "PRETTY_NAME": pretty_name},
    )
    monkeypatch.setattr(environment, "_linux_machine_model", lambda: model)


@pytest.mark.parametrize(
    ("distro_id", "pretty_name", "model", "expected_label"),
    [
        ("ubuntu", "Ubuntu 24.04 LTS", "", "Ubuntu standalone"),
        ("raspbian", "Raspberry Pi OS", "Raspberry Pi 5", "Raspberry Pi OS standalone"),
    ],
)
def test_simulated_step6_linux_validation_matrix(
    monkeypatch,
    tmp_path: Path,
    distro_id: str,
    pretty_name: str,
    model: str,
    expected_label: str,
) -> None:
    _set_linux_profile(monkeypatch, distro_id=distro_id, pretty_name=pretty_name, model=model)

    capture_path = tmp_path / f"{distro_id}-capture.pcapng"
    capture_path.write_bytes(b"pcap")
    report_path = tmp_path / f"{distro_id}-validation.json"

    monkeypatch.setattr(cli, "check_environment", lambda config=None: True)
    monkeypatch.setattr(cli, "list_interfaces", lambda: [("1", "wlan0", "wireless")])
    monkeypatch.setattr(cli, "run_capture", lambda config, strip_wifi=False: str(capture_path))
    monkeypatch.setattr(cli, "run_extract", lambda config, pcap: {"streams": 1})
    monkeypatch.setattr(cli, "run_detect", lambda config, manifest_path=None: {"selected_candidate_stream": {"stream_id": "demo"}})
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

    support = environment.command_support("validate-local", {})
    assert support.status == "official"
    assert support.profile.label == expected_label
    assert cli._active_validation_command({}) == "validate-local"

    result = cli.run_validate_local(
        {"output_dir": str(tmp_path), "interface": "wlan0", "capture_duration": 20},
        interface="wlan0",
        duration=12,
        report_path=str(report_path),
    )

    assert result is True
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["supported_target"] == expected_label
    assert data["environment_ok"] is True
    assert data["interface_check"]["present"] is True
    assert data["smoke_capture"]["success"] is True
    assert data["processing_smoke"]["success"] is True
    assert data["processing_smoke"]["selected_replay_confidence"]["handler_id"] == "txt"
    assert data["capability_report"]["platform"]["product_profile_label"] == expected_label
    assert data["status_bundle"]["machine_summary"]["items"]
    assert data["overall_ok"] is True


def test_simulated_step6_windows_remote_validation_matrix(monkeypatch, tmp_path: Path) -> None:
    _set_windows_remote(monkeypatch)

    capture_path = tmp_path / "remote-capture.pcapng"
    capture_path.write_bytes(b"pcap")
    report_path = tmp_path / "remote-validation.json"

    monkeypatch.setattr(cli, "check_environment", lambda config=None: True)
    monkeypatch.setattr(
        cli,
        "doctor_remote_host",
        lambda *args, **kwargs: {
            "ok": True,
            "host": "pi@raspberrypi",
            "local": {"ssh": True, "scp": True, "public_key": True},
            "remote": {
                "reachable": True,
                "tcpdump": True,
                "helper": True,
                "service": True,
                "service_status": "idle",
                "privileged_runner": True,
                "privilege_mode": "sudoers_runner",
                "capture_dir_exists": True,
                "capture_dir_writable": True,
                "state_dir_exists": True,
                "state_dir_writable": True,
                "interface": "wlan0",
                "interface_exists": True,
            },
        },
    )
    monkeypatch.setattr(cli, "_print_remote_doctor", lambda report: None)
    monkeypatch.setattr(
        cli,
        "remote_service_host",
        lambda config, action, **kwargs: {
            "service_status": "idle",
            "action": action,
            "last_capture": "/home/pi/wifi-pipeline/captures/demo.pcapng",
        },
    )
    monkeypatch.setattr(cli, "start_remote_capture", lambda *args, **kwargs: capture_path)

    support = environment.command_support("validate-remote", {})
    assert support.status == "official"
    assert support.profile.key == "windows_remote"
    assert cli._active_validation_command({}) == "validate-remote"

    result = cli.run_validate_remote(
        {"output_dir": str(tmp_path), "remote_host": "pi@raspberrypi", "remote_interface": "wlan0"},
        host="pi@raspberrypi",
        interface="wlan0",
        duration=12,
        report_path=str(report_path),
    )

    assert result is True
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["supported_target"] == "Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture"
    assert data["environment_ok"] is True
    assert data["doctor"]["ok"] is True
    assert data["smoke_capture"]["success"] is True
    assert data["capability_report"]["platform"]["product_profile_label"] == support.profile.label
    assert data["status_bundle"]["machine_summary"]["items"]
    assert data["overall_ok"] is True
