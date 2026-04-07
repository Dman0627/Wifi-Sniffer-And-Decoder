from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from .ui import err, info, ok, section, warn


DEFAULT_UBUNTU_REPORT = Path("validation_matrix/ubuntu_standalone_validation.json")
DEFAULT_PI_REPORT = Path("validation_matrix/pi_standalone_validation.json")
DEFAULT_WINDOWS_REPORT = Path("validation_matrix/windows_remote_validation.json")
DEFAULT_GATE_SUMMARY = Path("validation_matrix/release_gate.json")


def _read_json(path: Path) -> Optional[Dict[str, object]]:
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def _row_status(rows: Sequence[Dict[str, object]], *, area: str) -> List[str]:
    return [str(row.get("status") or "") for row in rows if str(row.get("area") or "") == area]


def _validate_capability_artifacts(
    report: Dict[str, object],
    *,
    expected_target: str,
    blockers: List[str],
) -> None:
    capability_report = dict(report.get("capability_report") or {})
    if not capability_report:
        blockers.append("capability_report is missing.")
        return

    platform = dict(capability_report.get("platform") or {})
    if str(platform.get("product_profile_label") or "") != expected_target:
        blockers.append(f"capability_report.platform.product_profile_label is {platform.get('product_profile_label')!r}, expected {expected_target!r}.")
    if not str(capability_report.get("privilege_mode") or "").strip():
        blockers.append("capability_report.privilege_mode is missing.")
    if not list(capability_report.get("capture_methods") or []):
        blockers.append("capability_report.capture_methods is empty.")
    if not list(capability_report.get("replay_families") or []):
        blockers.append("capability_report.replay_families is empty.")

    wpa = dict(capability_report.get("wpa") or {})
    if not str(wpa.get("status") or "").strip():
        blockers.append("capability_report.wpa.status is missing.")

    remote = dict(capability_report.get("remote") or {})
    if not str(remote.get("status") or "").strip():
        blockers.append("capability_report.remote.status is missing.")

    status_bundle = dict(report.get("status_bundle") or {})
    if not status_bundle:
        blockers.append("status_bundle is missing.")
        return

    machine_summary = dict(status_bundle.get("machine_summary") or {})
    machine_items = list(machine_summary.get("items") or [])
    if not str(machine_summary.get("headline") or "").strip():
        blockers.append("status_bundle.machine_summary.headline is missing.")
    expected_machine_keys = {"local_capture", "monitor_capture", "wpa", "remote_capture", "replay_export"}
    seen_machine_keys = {str(item.get("key") or "") for item in machine_items if isinstance(item, dict)}
    missing_machine_keys = sorted(expected_machine_keys - seen_machine_keys)
    if missing_machine_keys:
        blockers.append(f"status_bundle.machine_summary.items is missing keys: {', '.join(missing_machine_keys)}.")

    workflow = list(status_bundle.get("workflow") or [])
    if not workflow:
        blockers.append("status_bundle.workflow is empty.")

    replay = dict(status_bundle.get("replay") or {})
    if not str(replay.get("status") or "").strip():
        blockers.append("status_bundle.replay.status is missing.")

    wpa_status = dict(status_bundle.get("wpa") or {})
    if not str(wpa_status.get("status") or "").strip():
        blockers.append("status_bundle.wpa.status is missing.")


def _evaluate_linux_validation(path: Path, expected_target: str) -> Dict[str, object]:
    report = _read_json(path)
    blockers: List[str] = []
    warnings: List[str] = []

    if not report:
        return {
            "path": str(path),
            "status": "blocked",
            "summary": "Validation report is missing or unreadable.",
            "blockers": [f"Expected report at {path}."],
            "warnings": [],
            "supported_target": expected_target,
        }

    if str(report.get("supported_target") or "") != expected_target:
        blockers.append(f"supported_target is {report.get('supported_target')!r}, expected {expected_target!r}.")
    if not bool(report.get("environment_ok")):
        blockers.append("environment_ok is not true.")
    interface_check = dict(report.get("interface_check") or {})
    if not bool(interface_check.get("present")):
        blockers.append("interface_check.present is not true.")
    if not bool(report.get("overall_ok")):
        blockers.append("overall_ok is not true.")

    _validate_capability_artifacts(report, expected_target=expected_target, blockers=blockers)

    processing = dict(report.get("processing_smoke") or {})
    if not bool(processing.get("success")):
        blockers.append("processing_smoke.success is not true.")

    hardware = list(report.get("hardware_qualification") or [])
    adapter_statuses = _row_status(hardware, area="capture_adapter")
    if not any(status in ("supported", "supported_with_limits") for status in adapter_statuses):
        blockers.append("No qualified capture_adapter row was recorded in hardware_qualification.")

    support = dict(processing.get("selected_protocol_support") or {})
    replay_level = str(support.get("replay_level") or "")
    if replay_level not in ("guaranteed", "high_confidence", "heuristic"):
        blockers.append("processing_smoke.selected_protocol_support.replay_level is missing or unsupported.")

    feasibility = dict(processing.get("analysis_preflight") or {})
    replay = dict(feasibility.get("replay") or {})
    replay_status = str(replay.get("status") or "")
    if replay_status == "blocked":
        blockers.append("analysis_preflight.replay.status is blocked.")
    elif replay_status == "limited":
        warnings.append("analysis_preflight.replay.status is limited.")
    elif not replay_status:
        blockers.append("analysis_preflight.replay.status is missing.")

    replay_confidence = dict(processing.get("selected_replay_confidence") or {})
    if not replay_confidence:
        blockers.append("processing_smoke.selected_replay_confidence is missing.")
    else:
        if not str(replay_confidence.get("handler_id") or "").strip():
            blockers.append("processing_smoke.selected_replay_confidence.handler_id is missing.")
        if not str(replay_confidence.get("confidence_label") or "").strip():
            blockers.append("processing_smoke.selected_replay_confidence.confidence_label is missing.")
        if "supported" not in replay_confidence:
            blockers.append("processing_smoke.selected_replay_confidence.supported is missing.")

    return {
        "path": str(path),
        "status": "blocked" if blockers else ("limited" if warnings else "ready"),
        "summary": "Linux validation report checked.",
        "blockers": blockers,
        "warnings": warnings,
        "supported_target": expected_target,
    }


def _evaluate_windows_validation(path: Path) -> Dict[str, object]:
    expected_target = "Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture"
    report = _read_json(path)
    blockers: List[str] = []
    warnings: List[str] = []

    if not report:
        return {
            "path": str(path),
            "status": "blocked",
            "summary": "Validation report is missing or unreadable.",
            "blockers": [f"Expected report at {path}."],
            "warnings": [],
            "supported_target": expected_target,
        }

    if str(report.get("supported_target") or "") != expected_target:
        blockers.append(f"supported_target is {report.get('supported_target')!r}, expected {expected_target!r}.")
    if not bool(report.get("environment_ok")):
        blockers.append("environment_ok is not true.")
    if not bool(report.get("overall_ok")):
        blockers.append("overall_ok is not true.")

    _validate_capability_artifacts(report, expected_target=expected_target, blockers=blockers)

    doctor = dict(report.get("doctor") or {})
    if not bool(doctor.get("ok")):
        blockers.append("doctor.ok is not true.")
    remote = dict(doctor.get("remote") or {})
    if not bool(remote.get("service")):
        blockers.append("doctor.remote.service is not true.")
    if not bool(remote.get("privileged_runner")):
        warnings.append("doctor.remote.privileged_runner is not true.")
    if str(remote.get("privilege_mode") or "") not in ("sudoers_runner", "capabilities", "agent_managed"):
        warnings.append("doctor.remote.privilege_mode is not one of the hardened modes.")

    hardware = list(report.get("hardware_qualification") or [])
    host_statuses = _row_status(hardware, area="host")
    capture_node_statuses = _row_status(hardware, area="capture_node")
    if "supported" not in host_statuses:
        blockers.append("hardware_qualification does not show a supported Windows controller host.")
    if not any(status in ("supported", "supported_with_limits") for status in capture_node_statuses):
        blockers.append("hardware_qualification does not show a capture-node row.")

    return {
        "path": str(path),
        "status": "blocked" if blockers else ("limited" if warnings else "ready"),
        "summary": "Windows remote validation report checked.",
        "blockers": blockers,
        "warnings": warnings,
        "supported_target": expected_target,
    }


def _evaluate_sample_analysis(path: Path) -> Dict[str, object]:
    report = _read_json(path)
    blockers: List[str] = []
    warnings: List[str] = []
    if not report:
        return {
            "path": str(path),
            "status": "blocked",
            "summary": "Analysis report is missing or unreadable.",
            "blockers": [f"Expected analysis report at {path}."],
            "warnings": [],
        }

    support = dict(report.get("selected_protocol_support") or {})
    replay_level = str(support.get("replay_level") or "")
    if replay_level not in ("guaranteed", "high_confidence", "heuristic"):
        blockers.append("selected_protocol_support.replay_level is missing or unsupported.")
    elif replay_level == "heuristic":
        warnings.append("selected_protocol_support.replay_level is heuristic.")

    feasibility = dict(report.get("feasibility") or {})
    replay = dict(feasibility.get("replay") or {})
    replay_status = str(replay.get("status") or "")
    if replay_status == "blocked":
        blockers.append("feasibility.replay.status is blocked.")
    elif replay_status == "limited":
        warnings.append("feasibility.replay.status is limited.")
    elif not replay_status:
        blockers.append("feasibility.replay.status is missing.")

    candidate = dict(report.get("candidate_material") or {})
    if not candidate:
        blockers.append("candidate_material is empty.")

    selected_stream = dict(report.get("selected_candidate_stream") or {})
    candidate_metadata = dict(selected_stream.get("candidate_metadata") or {})
    if not candidate_metadata:
        blockers.append("selected_candidate_stream.candidate_metadata is missing.")

    replay_confidence = dict(report.get("selected_replay_confidence") or {})
    if not replay_confidence:
        blockers.append("selected_replay_confidence is missing.")
    else:
        if not str(replay_confidence.get("handler_id") or "").strip():
            blockers.append("selected_replay_confidence.handler_id is missing.")
        if not str(replay_confidence.get("confidence_label") or "").strip():
            blockers.append("selected_replay_confidence.confidence_label is missing.")
        if "supported" not in replay_confidence:
            blockers.append("selected_replay_confidence.supported is missing.")

    return {
        "path": str(path),
        "status": "blocked" if blockers else ("limited" if warnings else "ready"),
        "summary": "Sample analysis report checked.",
        "blockers": blockers,
        "warnings": warnings,
        "replay_level": replay_level,
    }


def evaluate_release_gate(
    *,
    ubuntu_report: Path = DEFAULT_UBUNTU_REPORT,
    pi_report: Path = DEFAULT_PI_REPORT,
    windows_report: Path = DEFAULT_WINDOWS_REPORT,
    sample_reports: Optional[Iterable[Path]] = None,
) -> Dict[str, object]:
    sample_paths = list(sample_reports or [])
    matrix = {
        "ubuntu_standalone": _evaluate_linux_validation(ubuntu_report, "Ubuntu standalone"),
        "pi_standalone": _evaluate_linux_validation(pi_report, "Raspberry Pi OS standalone"),
        "windows_remote": _evaluate_windows_validation(windows_report),
    }
    samples = [_evaluate_sample_analysis(path) for path in sample_paths]

    blockers: List[str] = []
    warnings: List[str] = []
    for entry in matrix.values():
        blockers.extend(entry.get("blockers", []))
        warnings.extend(entry.get("warnings", []))
    for entry in samples:
        blockers.extend(entry.get("blockers", []))
        warnings.extend(entry.get("warnings", []))

    if not sample_paths:
        blockers.append("No sample analysis reports were provided.")

    status = "blocked" if blockers else ("limited" if warnings else "ready")
    return {
        "status": status,
        "fully_validated": status == "ready",
        "required_reports": {
            "ubuntu_report": str(ubuntu_report),
            "pi_report": str(pi_report),
            "windows_report": str(windows_report),
            "sample_reports": [str(path) for path in sample_paths],
        },
        "matrix": matrix,
        "sample_reports": samples,
        "summary": (
            "Release gate passed with real validation artifacts."
            if status == "ready"
            else "Release gate is not satisfied yet."
        ),
        "blockers": list(dict.fromkeys(blockers)),
        "warnings": list(dict.fromkeys(warnings)),
    }


def print_release_gate(result: Dict[str, object]) -> Dict[str, object]:
    section("Release Gate")
    printer = {"ready": ok, "limited": warn, "blocked": err}[str(result.get("status") or "blocked")]
    printer(str(result.get("summary") or "Release gate result unavailable."))
    for name, entry in dict(result.get("matrix") or {}).items():
        entry_status = str(entry.get("status") or "blocked")
        entry_printer = {"ready": ok, "limited": warn, "blocked": err}[entry_status]
        entry_printer(f"{name}: {entry_status}")
        for blocker in entry.get("blockers", []):
            err(f"  blocker: {blocker}")
        for warning in entry.get("warnings", []):
            warn(f"  warning: {warning}")
    for entry in list(result.get("sample_reports") or []):
        entry_status = str(entry.get("status") or "blocked")
        entry_printer = {"ready": ok, "limited": warn, "blocked": err}[entry_status]
        entry_printer(f"sample {entry.get('path')}: {entry_status}")
        for blocker in entry.get("blockers", []):
            err(f"  blocker: {blocker}")
        for warning in entry.get("warnings", []):
            warn(f"  warning: {warning}")
    if result.get("blockers"):
        info("To satisfy the release gate, collect the missing validation artifacts and rerun the gate command.")
    elif result.get("warnings"):
        warn("The release gate is limited rather than fully validated. Review the warnings before shipping.")
    return result


def write_release_gate_summary(result: Dict[str, object], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return path
