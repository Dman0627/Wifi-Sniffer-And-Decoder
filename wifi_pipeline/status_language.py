from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from .environment import build_capability_report, workflow_support_matrix
from .feasibility import evaluate_pipeline_feasibility
from .playback import replay_confidence_summary, replay_support_summary


def _unique_nonempty(values: Iterable[object], limit: int = 3) -> List[str]:
    items: List[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        items.append(text)
        if len(items) >= limit:
            break
    return items


def normalize_capability_status(status: str) -> str:
    value = str(status or "").strip().lower()
    if value == "supported":
        return "supported"
    if value in ("supported_with_limits", "heuristic", "experimental", "limited", "unknown"):
        return "limited"
    return "blocked"


def normalize_preflight_status(status: str) -> str:
    value = str(status or "").strip().lower()
    if value in ("supported", "ready", "ok"):
        return "ready"
    if value in ("supported_with_limits", "heuristic", "experimental", "limited", "warning"):
        return "limited"
    return "blocked"


def status_pill_class(status: str) -> str:
    value = str(status or "").strip().lower()
    if value in ("supported", "ready", "ok", "present", "enabled", "yes"):
        return "ok"
    if value == "running":
        return "running"
    if value in ("supported_with_limits", "heuristic", "experimental", "limited", "warning"):
        return "warning"
    return "error"


def _primary_reason_summary(reasons: Iterable[object]) -> str:
    for reason in reasons:
        summary = str(getattr(reason, "summary", "") or "").strip()
        if summary:
            return summary
    return ""


def _primary_reason_next_step(reasons: Iterable[object]) -> str:
    for reason in reasons:
        remediation = str(getattr(reason, "remediation", "") or "").strip()
        if remediation:
            return remediation
    return ""


def _join_labels(labels: List[str]) -> str:
    values = [label for label in labels if label]
    if not values:
        return ""
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return ", ".join(values[:-1]) + f", and {values[-1]}"


def _family_label(family: str) -> str:
    labels = {
        "structured_text": "structured text",
        "still_images": "still images",
        "audio_video_media": "audio/video media",
        "archives_documents": "archives/documents",
        "opaque_unknown": "opaque/raw payloads",
    }
    return labels.get(str(family or "").strip(), str(family or "").replace("_", " "))


def _machine_summary_item(
    key: str,
    label: str,
    status: str,
    summary: str,
    *,
    reason: str = "",
    next_step: str = "",
) -> Dict[str, str]:
    return {
        "key": key,
        "label": label,
        "status": status,
        "summary": summary,
        "reason": reason,
        "next_step": next_step,
    }


def build_machine_summary(config: Dict[str, object], *, wpa_status: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    report = build_capability_report(config)
    methods = {method.key: method for method in report.capture_methods}
    local_capture = methods.get("local_capture")
    monitor_capture = methods.get("monitor_capture")
    remote_capture = methods.get("remote_capture")

    supported_replay = [_family_label(family.family) for family in report.replay_families if family.replay_status == "supported"]
    limited_replay = [
        _family_label(family.family)
        for family in report.replay_families
        if family.replay_status in ("supported_with_limits", "heuristic")
    ]
    export_only = [
        _family_label(family.family)
        for family in report.replay_families
        if family.export_status in ("supported", "supported_with_limits") and family.replay_status == "unsupported"
    ]
    replay_status = (
        "supported"
        if supported_replay and not limited_replay and not export_only
        else "limited"
        if supported_replay or limited_replay or export_only
        else "blocked"
    )
    replay_bits: List[str] = []
    if supported_replay:
        replay_bits.append(f"Best replay path: {_join_labels(supported_replay[:2])}.")
    if limited_replay:
        replay_bits.append(f"Limited replay: {_join_labels(limited_replay[:2])}.")
    if export_only:
        replay_bits.append(f"Export-only: {_join_labels(export_only[:2])}.")
    replay_summary = " ".join(replay_bits) or "Replay/export family support is not available on this machine."
    replay_reasons = [
        _primary_reason_summary(family.reasons)
        for family in report.replay_families
        if family.replay_status != "supported" or family.export_status != "supported"
    ]
    replay_next_steps = [
        _primary_reason_next_step(family.reasons)
        for family in report.replay_families
        if family.replay_status != "supported" or family.export_status != "supported"
    ]

    active_wpa = dict(wpa_status or {})
    wpa_item_status = normalize_preflight_status(active_wpa.get("status") or report.wpa.status or "blocked")
    wpa_item_summary = str(
        active_wpa.get("summary")
        or report.wpa.detail
        or "WPA readiness is not configured for the current workflow."
    )
    wpa_reason = (list(active_wpa.get("reasons") or []) or [_primary_reason_summary(report.wpa.reasons)] or [""])[0]
    wpa_next = (list(active_wpa.get("next_steps") or []) or [_primary_reason_next_step(report.wpa.reasons)] or [""])[0]

    items = [
        _machine_summary_item(
            "local_capture",
            "Local capture",
            normalize_capability_status(getattr(local_capture, "status", "blocked")),
            str(getattr(local_capture, "detail", "") or "Capture a pcap on this machine."),
            reason=_primary_reason_summary(getattr(local_capture, "reasons", ())),
            next_step=_primary_reason_next_step(getattr(local_capture, "reasons", ())),
        ),
        _machine_summary_item(
            "monitor_capture",
            "Monitor mode",
            normalize_capability_status(getattr(monitor_capture, "status", "blocked")),
            str(getattr(monitor_capture, "detail", "") or "Run monitor-mode Wi-Fi capture on this machine."),
            reason=_primary_reason_summary(getattr(monitor_capture, "reasons", ())),
            next_step=_primary_reason_next_step(getattr(monitor_capture, "reasons", ())),
        ),
        _machine_summary_item(
            "wpa",
            "WPA crack/decrypt",
            wpa_item_status,
            wpa_item_summary,
            reason=str(wpa_reason or ""),
            next_step=str(wpa_next or ""),
        ),
        _machine_summary_item(
            "remote_capture",
            "Remote appliance",
            normalize_capability_status(getattr(remote_capture, "status", "blocked")),
            str(report.remote.detail or getattr(remote_capture, "detail", "") or "Control a Linux capture appliance remotely."),
            reason=_primary_reason_summary(report.remote.reasons or getattr(remote_capture, "reasons", ())),
            next_step=_primary_reason_next_step(report.remote.reasons or getattr(remote_capture, "reasons", ())),
        ),
        _machine_summary_item(
            "replay_export",
            "Replay/export families",
            replay_status,
            replay_summary,
            reason=_unique_nonempty(replay_reasons[:1], limit=1)[0] if _unique_nonempty(replay_reasons[:1], limit=1) else "",
            next_step=_unique_nonempty(replay_next_steps[:1], limit=1)[0] if _unique_nonempty(replay_next_steps[:1], limit=1) else "",
        ),
    ]
    return {
        "headline": f"{report.platform.product_profile_label} / privilege={report.privilege_mode}",
        "items": items,
    }


def build_workflow_status_rows(config: Dict[str, object]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for row in workflow_support_matrix(config):
        reasons = _unique_nonempty(reason.summary for reason in row.reasons)
        next_steps = _unique_nonempty(reason.remediation for reason in row.reasons)
        rows.append(
            {
                "area": row.area,
                "status": normalize_capability_status(row.tier),
                "summary": row.summary,
                "detail": row.detail,
                "reasons": reasons,
                "next_steps": next_steps,
            }
        )
    return rows


def build_surface_status_bundle(
    config: Dict[str, object],
    detection_report: Optional[Dict[str, object]] = None,
    analysis_report: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    detection = dict(detection_report or {})
    analysis = dict(analysis_report or {})
    active_report = analysis or detection
    feasibility = dict(analysis.get("feasibility") or evaluate_pipeline_feasibility(config, active_report or None))
    replay = dict(feasibility.get("replay") or {})
    wpa = dict(feasibility.get("wpa") or {})
    selected_detection = dict(detection.get("selected_candidate_stream") or {})
    selected_analysis = dict(analysis.get("selected_candidate_stream") or {})
    selected = dict(selected_analysis or selected_detection)
    support = dict(
        analysis.get("selected_protocol_support")
        or detection.get("selected_protocol_support")
        or replay_support_summary(active_report)
    )
    confidence = dict(
        analysis.get("selected_replay_confidence")
        or (replay_confidence_summary(config, active_report) if active_report else {})
    )

    replay_reasons = _unique_nonempty(
        list(replay.get("blockers") or [])
        + list(replay.get("warnings") or [])
        + list(confidence.get("reasons") or [])
        + [support.get("detail")],
        limit=4,
    )
    replay_next_steps = _unique_nonempty(replay.get("next_steps") or [], limit=3)
    wpa_reasons = _unique_nonempty(wpa.get("reasons") or [], limit=3)
    wpa_next_steps = _unique_nonempty(wpa.get("next_steps") or [], limit=3)

    detection_score = selected_detection.get("score")
    if detection_score in (None, ""):
        detection_score = selected.get("score")
    selection_signal = str((selected.get("candidate_metadata") or {}).get("signal_strength") or "").strip().lower()
    selection_notes = _unique_nonempty(
        [
            replay.get("blockers", [None])[0] if replay.get("blockers") else None,
            replay.get("warnings", [None])[0] if replay.get("warnings") else None,
            (confidence.get("reasons") or [None])[0] if confidence.get("reasons") else None,
            support.get("detail"),
        ],
        limit=2,
    )

    return {
        "machine_summary": build_machine_summary(config, wpa_status=wpa),
        "workflow": build_workflow_status_rows(config),
        "selection": {
            "stream_id": str(selected.get("stream_id") or "(none)"),
            "candidate_class": str(selected_detection.get("candidate_class") or selected.get("candidate_class") or "(none)"),
            "score": str(detection_score if detection_score not in (None, "") else "?"),
            "decode_level": str(support.get("decode_level") or "heuristic"),
            "replay_level": str(support.get("replay_level") or "unsupported"),
            "dominant_unit_type": str(support.get("dominant_unit_type") or "opaque_chunk"),
            "signal_strength": selection_signal or "unknown",
            "status": normalize_preflight_status(replay.get("status") or "blocked"),
            "summary": str(replay.get("summary") or confidence.get("summary") or "Run analyze to evaluate replay readiness."),
            "notes": selection_notes,
            "next_steps": replay_next_steps[:1],
        },
        "replay": {
            "status": normalize_preflight_status(replay.get("status") or "blocked"),
            "summary": str(replay.get("summary") or "Run analyze to evaluate replay readiness."),
            "blockers": list(replay.get("blockers") or []),
            "warnings": list(replay.get("warnings") or []),
            "reasons": replay_reasons,
            "next_steps": replay_next_steps,
            "decode_level": str(support.get("decode_level") or "heuristic"),
            "replay_level": str(support.get("replay_level") or "unsupported"),
            "dominant_unit_type": str(support.get("dominant_unit_type") or "opaque_chunk"),
            "detail": str(support.get("detail") or ""),
            "confidence": confidence,
        },
        "wpa": {
            "status": normalize_preflight_status(wpa.get("status") or "ready"),
            "summary": str(wpa.get("summary") or "WPA feasibility is not relevant to the current workflow."),
            "reasons": wpa_reasons,
            "next_steps": wpa_next_steps,
            "state": str(wpa.get("state") or "not_applicable"),
            "handshake_artifact": str(wpa.get("handshake_artifact") or ""),
        },
    }
