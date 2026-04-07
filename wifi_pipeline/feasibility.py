from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from .capture import Capture
from .environment import build_capability_report
from .protocols import summarize_stream_support
from .ui import err, info, ok, section, warn


def _status_rank(status: str) -> int:
    return {"ready": 0, "limited": 1, "blocked": 2}.get(status, 99)


def _merge_statuses(*statuses: str) -> str:
    return max(statuses, key=_status_rank)


def _replay_support(report: Dict[str, object]) -> Dict[str, object]:
    selected_stream = dict(report.get("selected_candidate_stream") or {})
    support = dict(report.get("selected_protocol_support") or {})
    if support:
        return support
    return summarize_stream_support(dict(selected_stream.get("unit_type_counts") or {}))


def evaluate_capture_feasibility(config: Dict[str, object], report: Dict[str, object]) -> Dict[str, object]:
    selected = dict(report.get("selected_candidate_stream") or {})
    if not selected:
        return {
            "status": "blocked",
            "summary": "No candidate stream has been selected yet.",
            "reasons": ["Run detect and analyze before expecting replay feasibility."],
            "next_steps": ["Run `python videopipeline.py detect` and `python videopipeline.py analyze`."],
        }

    byte_count = int(selected.get("byte_count", 0) or 0)
    score = float(selected.get("score", 0.0) or 0.0)
    min_bytes = int(config.get("min_candidate_bytes", 4096) or 4096)
    support = _replay_support(report)
    decode_level = str(support.get("decode_level") or "heuristic")
    has_metrics = "byte_count" in selected or "score" in selected

    if not has_metrics:
        base_status = "ready" if decode_level in ("guaranteed", "high_confidence") else "limited"
        return {
            "status": base_status,
            "summary": "The selected stream is missing newer strength metrics, so preflight is using protocol support only.",
            "reasons": ["This report predates detailed score/byte-count preflight metrics."],
            "next_steps": ["Re-run detect/analyze if you want a stricter capture-quality check."],
        }

    if byte_count <= 0:
        return {
            "status": "blocked",
            "summary": "The selected stream carries no payload bytes.",
            "reasons": ["The chosen stream does not contain usable payload data."],
            "next_steps": ["Capture more traffic or choose a different ranked stream."],
        }

    if decode_level in ("guaranteed", "high_confidence"):
        if score < 10 or byte_count < 64:
            return {
                "status": "blocked",
                "summary": "The selected stream is too thin to trust for decode/replay.",
                "reasons": [f"score={score} and byte_count={byte_count} are below the minimum useful threshold."],
                "next_steps": ["Capture a fuller sample before retrying replay."],
            }
        if score < 40 or byte_count < 512:
            return {
                "status": "limited",
                "summary": "The selected stream is real, but still a thin capture.",
                "reasons": [f"score={score} and byte_count={byte_count} suggest incomplete capture quality."],
                "next_steps": ["A longer capture will improve replay confidence."],
            }
    else:
        if score < 30 or byte_count < max(256, min_bytes // 2):
            return {
                "status": "blocked",
                "summary": "The selected stream is too weak for a heuristic replay attempt.",
                "reasons": [f"score={score} and byte_count={byte_count} do not support a safe heuristic replay path."],
                "next_steps": ["Capture more data or focus on a stronger candidate stream."],
            }
        return {
            "status": "limited",
            "summary": "The selected stream is present, but only suitable for heuristic follow-up.",
            "reasons": [f"Protocol family support is {decode_level} rather than deterministic."],
            "next_steps": ["Inspect the ranked stream manually before trusting replay output."],
        }

    return {
        "status": "ready",
        "summary": "The selected stream has enough signal to justify decode/replay work.",
        "reasons": [f"score={score} and byte_count={byte_count} look healthy for the selected protocol family."],
        "next_steps": ["Proceed to replay or reconstruction."],
    }


def evaluate_candidate_material_feasibility(report: Dict[str, object]) -> Dict[str, object]:
    candidate = dict(report.get("candidate_material") or {})
    if not candidate:
        return {
            "status": "blocked",
            "summary": "The analysis report did not produce replay material.",
            "reasons": ["No keystream or XOR candidate was produced."],
            "next_steps": ["Provide decrypted reference data, improve capture quality, or revisit the selected stream."],
        }

    mode = str(candidate.get("mode") or "").strip()
    if mode in ("static_xor_candidate", "keystream_samples"):
        status = "ready" if mode == "static_xor_candidate" else "limited"
        summary = (
            "Deterministic replay material is present."
            if mode == "static_xor_candidate"
            else "Experimental keystream samples are present."
        )
        next_steps = (
            ["Proceed with replay or offline reconstruction."]
            if mode == "static_xor_candidate"
            else ["Proceed carefully; verify output because replay material is still experimental."]
        )
        return {
            "status": status,
            "summary": summary,
            "reasons": [f"candidate_material.mode={mode}"],
            "next_steps": next_steps,
        }

    return {
        "status": "blocked",
        "summary": "The analysis report produced an unknown replay-material mode.",
        "reasons": [f"candidate_material.mode={mode or '(missing)'} is not recognized by the replay path."],
        "next_steps": ["Regenerate analysis output or inspect the report manually before replay."],
    }


def evaluate_replay_feasibility(config: Dict[str, object], report: Dict[str, object]) -> Dict[str, object]:
    support = _replay_support(report)
    replay_level = str(support.get("replay_level") or "unsupported")
    capture_check = evaluate_capture_feasibility(config, report)
    material_check = evaluate_candidate_material_feasibility(report)

    blockers: List[str] = []
    warnings: List[str] = []
    next_steps: List[str] = []

    if replay_level == "unsupported":
        blockers.append(str(support.get("detail") or "This protocol family is outside the supported replay registry."))
        next_steps.append("Stay on supported text, image, audio, archive, document, or recognized video families.")
    elif replay_level == "heuristic":
        warnings.append(str(support.get("detail") or "Replay remains heuristic for this stream."))
        next_steps.append("Validate any replay output manually before trusting it.")

    if capture_check["status"] == "blocked":
        blockers.extend(capture_check["reasons"])
    elif capture_check["status"] == "limited":
        warnings.extend(capture_check["reasons"])
    if capture_check["status"] != "ready":
        next_steps.extend(capture_check["next_steps"])

    if material_check["status"] == "blocked":
        blockers.extend(material_check["reasons"])
    elif material_check["status"] == "limited":
        warnings.extend(material_check["reasons"])
    if material_check["status"] != "ready":
        next_steps.extend(material_check["next_steps"])

    status = "ready"
    if blockers:
        status = "blocked"
    elif warnings or replay_level == "high_confidence":
        status = "limited"

    if status == "ready" and not next_steps:
        next_steps.append("Proceed to replay or reconstruction.")

    summary = {
        "ready": "Replay can proceed on the current selected stream.",
        "limited": "Replay can proceed, but there are caveats you should see first.",
        "blocked": "Replay should not start yet because the current path is missing prerequisites.",
    }[status]

    return {
        "status": status,
        "summary": summary,
        "protocol_support": support,
        "capture": capture_check,
        "candidate_material": material_check,
        "blockers": list(dict.fromkeys(item for item in blockers if item)),
        "warnings": list(dict.fromkeys(item for item in warnings if item)),
        "next_steps": list(dict.fromkeys(item for item in next_steps if item)),
    }


def evaluate_wpa_feasibility(config: Dict[str, object]) -> Dict[str, object]:
    handshake_present = any(
        (
            (Path(str(config.get("output_dir") or "./pipeline_output")) / name).exists()
            for name in ("airodump_hs-01.cap", "besside_handshakes.cap", "monitor_raw.pcap")
        )
    )
    wifi_context = handshake_present or any(
        str(config.get(key) or "").strip()
        for key in ("ap_essid", "ap_bssid", "wpa_password", "wordlist_path")
    )
    if not wifi_context:
        return {
            "status": "ready",
            "summary": "WPA feasibility is not relevant to the current workflow.",
            "reasons": [],
            "next_steps": [],
            "state": "not_applicable",
        }

    readiness = Capture(config).inspect_wpa_crack_path()
    status_map = {
        "supported": "ready",
        "supported_with_limits": "limited",
        "unsupported": "blocked",
    }
    status = status_map.get(readiness.status, "blocked")
    next_steps: List[str] = list(readiness.next_steps)
    if not next_steps and readiness.state == "unsupported":
        next_steps.append("Install the missing WPA prerequisites or supply a known PSK.")

    return {
        "status": status,
        "summary": readiness.summary,
        "reasons": [readiness.detail] if readiness.detail else [],
        "next_steps": next_steps,
        "state": readiness.state,
        "handshake_cap": readiness.handshake_cap,
        "handshake_artifact": readiness.handshake_artifact,
    }


def evaluate_pipeline_feasibility(config: Dict[str, object], report: Optional[Dict[str, object]]) -> Dict[str, object]:
    capability_report = build_capability_report(config)
    replay = (
        evaluate_replay_feasibility(config, report)
        if report
        else {
            "status": "blocked",
            "summary": "No analysis report is available yet.",
            "blockers": ["Run analyze before expecting replay feasibility."],
            "warnings": [],
            "next_steps": ["Run `python videopipeline.py analyze`."],
            "protocol_support": summarize_stream_support({}),
        }
    )
    wpa = evaluate_wpa_feasibility(config)
    overall_status = _merge_statuses(replay["status"], "limited" if wpa["status"] == "blocked" else wpa["status"])
    return {
        "status": overall_status,
        "summary": "Replay and WPA preflight evaluated.",
        "capabilities": {
            "platform": capability_report.platform.__dict__,
            "privilege_mode": capability_report.privilege_mode,
            "capture_methods": {
                method.key: {
                    "status": method.status,
                    "available": method.available,
                    "reason_codes": [reason.code for reason in method.reasons],
                }
                for method in capability_report.capture_methods
            },
            "wpa": {
                "status": capability_report.wpa.status,
                "state": capability_report.wpa.state,
                "reason_codes": [reason.code for reason in capability_report.wpa.reasons],
            },
            "remote": {
                "status": capability_report.remote.status,
                "configured_host": capability_report.remote.configured_host,
                "reason_codes": [reason.code for reason in capability_report.remote.reasons],
            },
        },
        "replay": replay,
        "wpa": wpa,
    }


def print_pipeline_feasibility(config: Dict[str, object], report: Optional[Dict[str, object]]) -> Dict[str, object]:
    feasibility = evaluate_pipeline_feasibility(config, report)
    section("Pipeline Preflight")

    capabilities = dict(feasibility.get("capabilities") or {})
    methods = dict(capabilities.get("capture_methods") or {})
    platform = dict(capabilities.get("platform") or {})
    if platform:
        info(
            "Capabilities: "
            f"{platform.get('product_profile_label', '(unknown profile)')} / "
            f"privilege={capabilities.get('privilege_mode', 'unknown')} / "
            f"local={dict(methods.get('local_capture') or {}).get('status', 'unknown')} / "
            f"monitor={dict(methods.get('monitor_capture') or {}).get('status', 'unknown')} / "
            f"remote={dict(methods.get('remote_capture') or {}).get('status', 'unknown')}"
        )

    replay = feasibility["replay"]
    replay_printer = {"ready": ok, "limited": warn, "blocked": err}[replay["status"]]
    replay_printer(f"Replay: {replay['summary']}")
    for blocker in replay.get("blockers", []):
        err(f"  blocker: {blocker}")
    for warning in replay.get("warnings", []):
        warn(f"  warning: {warning}")
    for step in replay.get("next_steps", []):
        info(f"  next: {step}")

    wpa = feasibility["wpa"]
    wpa_printer = {"ready": ok, "limited": warn, "blocked": err}[wpa["status"]]
    wpa_printer(f"WPA: {wpa['summary']}")
    for reason in wpa.get("reasons", []):
        info(f"  detail: {reason}")
    for step in wpa.get("next_steps", []):
        info(f"  next: {step}")

    return feasibility


def attach_feasibility_to_report(config: Dict[str, object], report: Dict[str, object], report_path: Path) -> Dict[str, object]:
    updated = dict(report)
    updated["feasibility"] = evaluate_pipeline_feasibility(config, updated)
    report_path.write_text(json.dumps(updated, indent=2), encoding="utf-8")
    return updated
