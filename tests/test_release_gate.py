from __future__ import annotations

import json
from pathlib import Path

from wifi_pipeline.release_gate import evaluate_release_gate, write_release_gate_summary


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _capability_report(expected_target: str) -> dict:
    return {
        "platform": {
            "os_name": "linux",
            "os_version": "24.04",
            "distribution": expected_target,
            "architecture": "x86_64",
            "product_profile_key": expected_target.lower().replace(" ", "_"),
            "product_profile_label": expected_target,
            "official": True,
        },
        "privilege_mode": "sudoers_runner",
        "capture_methods": [
            {
                "key": "local_capture",
                "label": "Local capture",
                "status": "supported",
                "available": True,
                "requires_privilege": True,
                "detail": "Capture is available locally.",
                "tooling": ["tcpdump"],
                "reasons": [],
            },
            {
                "key": "monitor_capture",
                "label": "Monitor capture",
                "status": "supported_with_limits",
                "available": True,
                "requires_privilege": True,
                "detail": "Monitor mode is available with limits.",
                "tooling": ["iw"],
                "reasons": [],
            },
            {
                "key": "remote_capture",
                "label": "Remote capture",
                "status": "supported",
                "available": True,
                "requires_privilege": False,
                "detail": "Remote appliance control is available.",
                "tooling": ["ssh", "scp"],
                "reasons": [],
            },
        ],
        "wpa": {"status": "supported_with_limits", "detail": "Handshake-based WPA path is available.", "reasons": []},
        "remote": {"status": "supported", "detail": "Linux appliance path is available.", "reasons": []},
        "replay_families": [
            {
                "family": "structured_text",
                "decode_status": "supported",
                "export_status": "supported",
                "replay_status": "supported",
                "detail": "Structured text replay/export is supported.",
                "reasons": [],
            }
        ],
    }


def _status_bundle() -> dict:
    return {
        "machine_summary": {
            "headline": "Ubuntu standalone / privilege=sudoers_runner",
            "items": [
                {"key": "local_capture", "label": "Local capture", "status": "supported", "summary": "Capture locally.", "reason": "", "next_step": ""},
                {"key": "monitor_capture", "label": "Monitor mode", "status": "limited", "summary": "Monitor mode available with limits.", "reason": "", "next_step": ""},
                {"key": "wpa", "label": "WPA crack/decrypt", "status": "limited", "summary": "WPA path depends on real artifacts.", "reason": "", "next_step": ""},
                {"key": "remote_capture", "label": "Remote appliance", "status": "supported", "summary": "Remote appliance available.", "reason": "", "next_step": ""},
                {"key": "replay_export", "label": "Replay/export families", "status": "limited", "summary": "Known families can replay or export.", "reason": "", "next_step": ""},
            ],
        },
        "workflow": [
            {"area": "capture", "status": "supported", "summary": "Capture is supported.", "detail": "Capture is supported.", "reasons": [], "next_steps": []}
        ],
        "replay": {"status": "ready", "summary": "Replay is ready.", "confidence": {"handler_id": "txt"}},
        "wpa": {"status": "limited", "summary": "WPA depends on captured artifacts."},
    }


def _sample_report_payload() -> dict:
    return {
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "candidate_metadata": {"signal_strength": "strong"},
        },
        "selected_protocol_support": {"replay_level": "guaranteed"},
        "selected_replay_confidence": {
            "handler_id": "txt",
            "confidence_label": "guaranteed",
            "supported": True,
        },
        "feasibility": {"replay": {"status": "ready"}},
        "candidate_material": {"mode": "static_xor_candidate"},
    }


def test_evaluate_release_gate_ready(tmp_path: Path) -> None:
    ubuntu = _write_json(
        tmp_path / "ubuntu.json",
        {
            "supported_target": "Ubuntu standalone",
            "environment_ok": True,
            "overall_ok": True,
            "interface_check": {"present": True},
            "capability_report": _capability_report("Ubuntu standalone"),
            "status_bundle": _status_bundle(),
            "hardware_qualification": [{"area": "capture_adapter", "status": "supported"}],
            "processing_smoke": {
                "success": True,
                "selected_protocol_support": {"replay_level": "guaranteed"},
                "selected_replay_confidence": {
                    "handler_id": "txt",
                    "confidence_label": "guaranteed",
                    "supported": True,
                },
                "analysis_preflight": {"replay": {"status": "ready"}},
            },
        },
    )
    pi = _write_json(
        tmp_path / "pi.json",
        {
            "supported_target": "Raspberry Pi OS standalone",
            "environment_ok": True,
            "overall_ok": True,
            "interface_check": {"present": True},
            "capability_report": _capability_report("Raspberry Pi OS standalone"),
            "status_bundle": _status_bundle(),
            "hardware_qualification": [{"area": "capture_adapter", "status": "supported_with_limits"}],
            "processing_smoke": {
                "success": True,
                "selected_protocol_support": {"replay_level": "high_confidence"},
                "selected_replay_confidence": {
                    "handler_id": "mpegts",
                    "confidence_label": "high_confidence",
                    "supported": True,
                },
                "analysis_preflight": {"replay": {"status": "ready"}},
            },
        },
    )
    windows = _write_json(
        tmp_path / "windows.json",
        {
            "supported_target": "Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture",
            "environment_ok": True,
            "overall_ok": True,
            "capability_report": _capability_report("Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture"),
            "status_bundle": _status_bundle(),
            "doctor": {
                "ok": True,
                "remote": {"service": True, "privileged_runner": True, "privilege_mode": "sudoers_runner"},
            },
            "hardware_qualification": [
                {"area": "host", "status": "supported"},
                {"area": "capture_node", "status": "supported_with_limits"},
            ],
        },
    )
    sample = _write_json(
        tmp_path / "sample.json",
        _sample_report_payload(),
    )

    result = evaluate_release_gate(
        ubuntu_report=ubuntu,
        pi_report=pi,
        windows_report=windows,
        sample_reports=[sample],
    )

    assert result["fully_validated"] is True
    assert result["status"] == "ready"


def test_evaluate_release_gate_blocks_without_sample_reports(tmp_path: Path) -> None:
    report = _write_json(
        tmp_path / "report.json",
        {
            "supported_target": "Ubuntu standalone",
            "environment_ok": True,
            "overall_ok": True,
            "interface_check": {"present": True},
            "capability_report": _capability_report("Ubuntu standalone"),
            "status_bundle": _status_bundle(),
            "hardware_qualification": [{"area": "capture_adapter", "status": "supported"}],
            "processing_smoke": {
                "success": True,
                "selected_protocol_support": {"replay_level": "guaranteed"},
                "selected_replay_confidence": {
                    "handler_id": "txt",
                    "confidence_label": "guaranteed",
                    "supported": True,
                },
                "analysis_preflight": {"replay": {"status": "ready"}},
            },
        },
    )
    windows = _write_json(
        tmp_path / "windows.json",
        {
            "supported_target": "Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture",
            "environment_ok": True,
            "overall_ok": True,
            "capability_report": _capability_report("Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture"),
            "status_bundle": _status_bundle(),
            "doctor": {"ok": True, "remote": {"service": True}},
            "hardware_qualification": [{"area": "host", "status": "supported"}, {"area": "capture_node", "status": "supported"}],
        },
    )

    result = evaluate_release_gate(
        ubuntu_report=report,
        pi_report=report,
        windows_report=windows,
        sample_reports=[],
    )

    assert result["fully_validated"] is False
    assert result["status"] == "blocked"


def test_evaluate_release_gate_blocks_without_capability_snapshot(tmp_path: Path) -> None:
    report = _write_json(
        tmp_path / "report.json",
        {
            "supported_target": "Ubuntu standalone",
            "environment_ok": True,
            "overall_ok": True,
            "interface_check": {"present": True},
            "hardware_qualification": [{"area": "capture_adapter", "status": "supported"}],
            "processing_smoke": {
                "success": True,
                "selected_protocol_support": {"replay_level": "guaranteed"},
                "selected_replay_confidence": {
                    "handler_id": "txt",
                    "confidence_label": "guaranteed",
                    "supported": True,
                },
                "analysis_preflight": {"replay": {"status": "ready"}},
            },
        },
    )
    windows = _write_json(
        tmp_path / "windows.json",
        {
            "supported_target": "Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture",
            "environment_ok": True,
            "overall_ok": True,
            "capability_report": _capability_report("Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture"),
            "status_bundle": _status_bundle(),
            "doctor": {"ok": True, "remote": {"service": True, "privileged_runner": True, "privilege_mode": "sudoers_runner"}},
            "hardware_qualification": [{"area": "host", "status": "supported"}, {"area": "capture_node", "status": "supported"}],
        },
    )
    sample = _write_json(tmp_path / "sample.json", _sample_report_payload())

    result = evaluate_release_gate(
        ubuntu_report=report,
        pi_report=report,
        windows_report=windows,
        sample_reports=[sample],
    )

    assert result["fully_validated"] is False
    assert "capability_report is missing." in result["blockers"]


def test_evaluate_release_gate_blocks_without_replay_confidence_reporting(tmp_path: Path) -> None:
    linux_report = {
        "supported_target": "Ubuntu standalone",
        "environment_ok": True,
        "overall_ok": True,
        "interface_check": {"present": True},
        "capability_report": _capability_report("Ubuntu standalone"),
        "status_bundle": _status_bundle(),
        "hardware_qualification": [{"area": "capture_adapter", "status": "supported"}],
        "processing_smoke": {
            "success": True,
            "selected_protocol_support": {"replay_level": "guaranteed"},
            "selected_replay_confidence": {
                "handler_id": "txt",
                "confidence_label": "guaranteed",
                "supported": True,
            },
            "analysis_preflight": {"replay": {"status": "ready"}},
        },
    }
    windows_report = {
        "supported_target": "Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture",
        "environment_ok": True,
        "overall_ok": True,
        "capability_report": _capability_report("Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture"),
        "status_bundle": _status_bundle(),
        "doctor": {"ok": True, "remote": {"service": True, "privileged_runner": True, "privilege_mode": "sudoers_runner"}},
        "hardware_qualification": [{"area": "host", "status": "supported"}, {"area": "capture_node", "status": "supported"}],
    }
    sample_payload = _sample_report_payload()
    sample_payload.pop("selected_replay_confidence")

    result = evaluate_release_gate(
        ubuntu_report=_write_json(tmp_path / "ubuntu.json", linux_report),
        pi_report=_write_json(tmp_path / "pi.json", {**linux_report, "supported_target": "Raspberry Pi OS standalone", "capability_report": _capability_report("Raspberry Pi OS standalone")}),
        windows_report=_write_json(tmp_path / "windows.json", windows_report),
        sample_reports=[_write_json(tmp_path / "sample.json", sample_payload)],
    )

    assert result["fully_validated"] is False
    assert "selected_replay_confidence is missing." in result["blockers"]


def test_write_release_gate_summary(tmp_path: Path) -> None:
    path = write_release_gate_summary({"status": "ready", "fully_validated": True}, tmp_path / "summary.json")
    assert path.exists()
