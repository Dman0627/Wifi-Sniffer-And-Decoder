from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from intel_core import new_record_id, utc_now

AUDIT_LOG_NAME = "audit_log.jsonl"
CLEANUP_REPORT_NAME = "cleanup_report.json"


def ensure_workspace_layout(output_root: str | Path) -> dict[str, Path]:
    root = Path(output_root).resolve()
    layout = {
        "root": root,
        "objects": root / "objects",
        "objects_raw": root / "objects" / "raw",
        "objects_derived": root / "objects" / "derived",
        "audit": root / "audit",
        "queues": root / "queues",
        "retention": root / "retention",
    }
    for path in layout.values():
        path.mkdir(parents=True, exist_ok=True)
    return layout


def materialize_raw_artifact(
    output_root: str | Path,
    input_path: str | Path,
    *,
    content_hash: str,
    preferred_name: str = "",
) -> Path:
    source_path = Path(input_path).expanduser().resolve()
    if not source_path.is_file():
        raise FileNotFoundError(f"raw artifact source must be a file: {source_path}")

    layout = ensure_workspace_layout(output_root)
    object_dir = layout["objects_raw"] / str(content_hash or "unknown")[:2] / str(content_hash or "unknown")
    object_dir.mkdir(parents=True, exist_ok=True)

    name = preferred_name or source_path.name or "artifact.bin"
    target_path = object_dir / _sanitize_path_part(name)
    if not target_path.exists():
        shutil.copy2(source_path, target_path)
    return target_path.resolve()


def materialize_raw_content(
    output_root: str | Path,
    *,
    content: bytes,
    content_hash: str = "",
    preferred_name: str = "",
) -> tuple[Path, str]:
    payload = bytes(content or b"")
    digest = str(content_hash or hashlib.sha256(payload).hexdigest()).strip().lower() or "unknown"
    layout = ensure_workspace_layout(output_root)
    object_dir = layout["objects_raw"] / digest[:2] / digest
    object_dir.mkdir(parents=True, exist_ok=True)

    name = preferred_name or "artifact.bin"
    target_path = object_dir / _sanitize_path_part(name)
    if not target_path.exists():
        target_path.write_bytes(payload)
    return target_path.resolve(), digest


def materialize_derived_artifact(
    output_root: str | Path,
    *,
    stage: str,
    source_id: str,
    content: bytes,
    preferred_name: str = "",
    content_hash: str = "",
    parts: tuple[str, ...] = (),
) -> tuple[Path, str]:
    payload = bytes(content or b"")
    digest = str(content_hash or hashlib.sha256(payload).hexdigest()).strip().lower() or "unknown"
    object_dir = stage_object_dir(output_root, stage, source_id, *parts, digest[:2], digest)
    name = preferred_name or "artifact.bin"
    target_path = object_dir / _sanitize_path_part(name)
    if not target_path.exists():
        target_path.write_bytes(payload)
    return target_path.resolve(), digest


def stage_object_dir(output_root: str | Path, stage: str, source_id: str, *parts: str) -> Path:
    layout = ensure_workspace_layout(output_root)
    path = layout["objects_derived"] / _sanitize_path_part(stage) / _sanitize_path_part(source_id or "source")
    for part in parts:
        path = path / _sanitize_path_part(part)
    path.mkdir(parents=True, exist_ok=True)
    return path.resolve()


def append_audit_event(output_root: str | Path, payload: dict[str, Any]) -> Path:
    layout = ensure_workspace_layout(output_root)
    audit_path = layout["audit"] / AUDIT_LOG_NAME
    event = {
        "schema_version": 1,
        "audit_id": str(payload.get("audit_id") or new_record_id("audit")),
        "created_at": str(payload.get("created_at") or utc_now()),
        **payload,
    }
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True, ensure_ascii=True))
        handle.write("\n")
    return audit_path.resolve()


def read_audit_events(output_root: str | Path, *, source_id: str = "", case_id: str = "") -> list[dict[str, Any]]:
    layout = ensure_workspace_layout(output_root)
    audit_path = layout["audit"] / AUDIT_LOG_NAME
    if not audit_path.exists():
        return []

    rows: list[dict[str, Any]] = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        payload = json.loads(text)
        if source_id and str(payload.get("source_id") or "") != source_id:
            continue
        if case_id and str(payload.get("case_id") or "") != case_id:
            continue
        rows.append(payload)
    return rows


def list_queue_archives(
    output_root: str | Path,
    *,
    case_id: str = "",
    archive_state: str = "",
    stage: str = "",
    limit: int = 25,
) -> list[dict[str, Any]]:
    layout = ensure_workspace_layout(output_root)
    queues_root = layout["queues"]
    requested_case_id = str(case_id or "").strip()
    requested_state = str(archive_state or "").strip().lower()
    requested_stage = str(stage or "").strip().lower()
    states = [requested_state] if requested_state else ["completed", "failed"]

    rows: list[dict[str, Any]] = []
    for state_name in states:
        state_root = queues_root / state_name
        if not state_root.exists():
            continue
        if requested_stage:
            stage_roots = [state_root / requested_stage]
        else:
            stage_roots = sorted(path for path in state_root.iterdir() if path.is_dir())
        for stage_root in stage_roots:
            if not stage_root.exists():
                continue
            for archive_path in sorted(stage_root.glob("*.json")):
                payload, parse_error = _read_json_object(archive_path)
                row = _queue_archive_row(
                    archive_path=archive_path,
                    archive_payload=payload,
                    parse_error=parse_error,
                )
                if requested_case_id and str(row.get("case_id") or "") != requested_case_id:
                    continue
                rows.append(row)

    rows.sort(
        key=lambda item: (
            str(item.get("archived_at") or ""),
            str(item.get("archive_name") or ""),
        ),
        reverse=True,
    )
    max_rows = max(1, int(limit or 25))
    return rows[:max_rows]


def list_cleanup_reports(output_root: str | Path, *, limit: int = 10) -> list[dict[str, Any]]:
    layout = ensure_workspace_layout(output_root)
    retention_root = layout["retention"]
    history_root = retention_root / "history"

    report_paths = sorted(history_root.glob("*.json")) if history_root.exists() else []
    if not report_paths:
        current_report = retention_root / CLEANUP_REPORT_NAME
        if current_report.exists():
            report_paths = [current_report]

    rows: list[dict[str, Any]] = []
    for report_path in report_paths:
        payload, parse_error = _read_json_object(report_path)
        rows.append(
            _cleanup_report_row(
                report_path=report_path,
                report_payload=payload,
                parse_error=parse_error,
            )
        )

    rows.sort(
        key=lambda item: (
            str(item.get("completed_at") or item.get("started_at") or ""),
            str(item.get("report_name") or ""),
        ),
        reverse=True,
    )
    max_rows = max(1, int(limit or 10))
    return rows[:max_rows]


def cleanup_workspace(
    output_root: str | Path,
    *,
    queue_completed_max_age_seconds: float = 0.0,
    queue_failed_max_age_seconds: float = 0.0,
    watch_delta_max_age_seconds: float = 0.0,
    dry_run: bool = False,
) -> dict[str, Any]:
    layout = ensure_workspace_layout(output_root)
    root = layout["root"]
    started_at = utc_now()
    categories = {
        "queue_completed": _cleanup_category(
            root / "queues" / "completed",
            max_age_seconds=max(0.0, float(queue_completed_max_age_seconds or 0.0)),
            dry_run=bool(dry_run),
            suffixes={".json"},
        ),
        "queue_failed": _cleanup_category(
            root / "queues" / "failed",
            max_age_seconds=max(0.0, float(queue_failed_max_age_seconds or 0.0)),
            dry_run=bool(dry_run),
            suffixes={".json"},
        ),
        "watch_delta": _cleanup_category(
            root / "objects" / "derived" / "watch_delta",
            max_age_seconds=max(0.0, float(watch_delta_max_age_seconds or 0.0)),
            dry_run=bool(dry_run),
        ),
    }

    candidate_count = sum(int(item["candidate_count"]) for item in categories.values())
    candidate_bytes = sum(int(item["candidate_bytes"]) for item in categories.values())
    removed_count = sum(int(item["removed_count"]) for item in categories.values())
    removed_bytes = sum(int(item["removed_bytes"]) for item in categories.values())
    warnings = [
        warning
        for item in categories.values()
        for warning in list(item.get("warnings") or [])
        if str(warning).strip()
    ]
    errors = [
        error
        for item in categories.values()
        for error in list(item.get("errors") or [])
        if str(error).strip()
    ]

    report = {
        "schema_version": 1,
        "started_at": started_at,
        "completed_at": utc_now(),
        "ok": not errors,
        "dry_run": bool(dry_run),
        "output_root": str(root),
        "targets": {
            "queue_completed_max_age_seconds": max(0.0, float(queue_completed_max_age_seconds or 0.0)),
            "queue_failed_max_age_seconds": max(0.0, float(queue_failed_max_age_seconds or 0.0)),
            "watch_delta_max_age_seconds": max(0.0, float(watch_delta_max_age_seconds or 0.0)),
        },
        "metrics": {
            "candidate_count": candidate_count,
            "candidate_bytes": candidate_bytes,
            "removed_count": removed_count,
            "removed_bytes": removed_bytes,
            "warning_count": len(warnings),
            "error_count": len(errors),
        },
        "categories": categories,
        "warnings": warnings,
        "errors": errors,
    }

    report_path = layout["retention"] / CLEANUP_REPORT_NAME
    history_root = layout["retention"] / "history"
    history_root.mkdir(parents=True, exist_ok=True)
    history_name = f"{report_path.stem}__{_timestamp_slug(str(report.get('completed_at') or report.get('started_at') or ''))}{report_path.suffix}"
    history_path = _ensure_unique_path(history_root / history_name)

    report["report_path"] = str(report_path.resolve())
    report["history_path"] = str(history_path.resolve())
    report["artifact_paths"] = [report["report_path"], report["history_path"]]

    report_text = json.dumps(report, indent=2)
    report_path.write_text(report_text, encoding="utf-8")
    history_path.write_text(report_text, encoding="utf-8")
    return report


def _cleanup_category(
    root: Path,
    *,
    max_age_seconds: float,
    dry_run: bool,
    suffixes: set[str] | None = None,
) -> dict[str, Any]:
    payload = {
        "root": str(root.resolve()),
        "max_age_seconds": max(0.0, float(max_age_seconds or 0.0)),
        "candidate_count": 0,
        "candidate_bytes": 0,
        "removed_count": 0,
        "removed_bytes": 0,
        "removed_paths": [],
        "warnings": [],
        "errors": [],
    }
    if max_age_seconds <= 0.0 or not root.exists():
        return payload

    now = datetime.now(timezone.utc).timestamp()
    candidates: list[tuple[Path, int]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if suffixes and path.suffix.lower() not in suffixes:
            continue
        try:
            stat = path.stat()
        except OSError as exc:
            payload["warnings"].append(f"stat failed for {path}: {exc}")
            continue
        age_seconds = max(0.0, now - float(stat.st_mtime))
        if age_seconds < max_age_seconds:
            continue
        size_bytes = int(stat.st_size)
        candidates.append((path, size_bytes))

    payload["candidate_count"] = len(candidates)
    payload["candidate_bytes"] = sum(size for _path, size in candidates)

    for path, size_bytes in candidates:
        if dry_run:
            payload["removed_paths"].append(str(path.resolve()))
            continue
        try:
            path.unlink()
            payload["removed_count"] += 1
            payload["removed_bytes"] += size_bytes
            payload["removed_paths"].append(str(path.resolve()))
            _remove_empty_parent_dirs(path.parent, stop_at=root)
        except OSError as exc:
            payload["errors"].append(f"delete failed for {path}: {exc}")
    return payload


def _remove_empty_parent_dirs(path: Path, *, stop_at: Path) -> None:
    current = path.resolve()
    boundary = stop_at.resolve()
    while current != boundary and boundary in current.parents:
        try:
            current.rmdir()
        except OSError:
            break
        current = current.parent


def _read_json_object(path: Path) -> tuple[dict[str, Any], str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, str(exc)
    if not isinstance(payload, dict):
        return {}, "JSON payload must be an object"
    return payload, ""


def _queue_archive_row(
    *,
    archive_path: Path,
    archive_payload: dict[str, Any],
    parse_error: str,
) -> dict[str, Any]:
    queue_payload = dict(archive_payload.get("queue") or {})
    result_payload = dict(archive_payload.get("result") or {})
    job_payload = dict(queue_payload.get("job") or {})
    source_payload = dict(queue_payload.get("source") or {})
    triage_payload = dict(queue_payload.get("triage") or {})
    locator = str(source_payload.get("locator") or "")
    display_name = str(source_payload.get("display_name") or Path(locator).name or locator or archive_path.stem)
    artifact_paths = [str(item).strip() for item in list(result_payload.get("artifact_paths") or []) if str(item).strip()]
    warnings = [str(item).strip() for item in list(result_payload.get("warnings") or []) if str(item).strip()]
    errors = [str(item).strip() for item in list(result_payload.get("errors") or []) if str(item).strip()]
    stage = str(archive_payload.get("stage") or archive_path.parent.name or "")
    archived_at = str(archive_payload.get("archived_at") or "")
    ok = bool(result_payload.get("ok")) if "ok" in result_payload else str(archive_payload.get("archive_state") or "") == "completed"
    return {
        "archive_path": str(archive_path.resolve()),
        "archive_name": archive_path.name,
        "archived_at": archived_at,
        "archive_state": str(archive_payload.get("archive_state") or archive_path.parent.parent.name or ""),
        "stage": stage,
        "queue_path": str(archive_payload.get("queue_path") or ""),
        "reference_path": _queue_reference_path(queue_payload, stage=stage),
        "case_id": str(source_payload.get("case_id") or job_payload.get("case_id") or ""),
        "source_id": str(source_payload.get("id") or source_payload.get("source_id") or job_payload.get("source_id") or ""),
        "source_type": str(source_payload.get("source_type") or ""),
        "display_name": display_name,
        "locator": locator,
        "job_id": str(job_payload.get("id") or archive_path.stem),
        "priority_label": str(triage_payload.get("priority_label") or ""),
        "priority_score": int(triage_payload.get("priority_score") or 0),
        "ok": ok,
        "warning_count": len(warnings),
        "error_count": len(errors),
        "artifact_path_count": len(artifact_paths),
        "artifact_paths": artifact_paths,
        "warnings": warnings,
        "errors": errors,
        "parse_error": str(parse_error or ""),
    }


def _cleanup_report_row(
    *,
    report_path: Path,
    report_payload: dict[str, Any],
    parse_error: str,
) -> dict[str, Any]:
    metrics = dict(report_payload.get("metrics") or {})
    categories = {
        str(name): {
            "candidate_count": int(dict(values or {}).get("candidate_count") or 0),
            "candidate_bytes": int(dict(values or {}).get("candidate_bytes") or 0),
            "removed_count": int(dict(values or {}).get("removed_count") or 0),
            "removed_bytes": int(dict(values or {}).get("removed_bytes") or 0),
        }
        for name, values in dict(report_payload.get("categories") or {}).items()
        if str(name).strip()
    }
    warnings = [str(item).strip() for item in list(report_payload.get("warnings") or []) if str(item).strip()]
    errors = [str(item).strip() for item in list(report_payload.get("errors") or []) if str(item).strip()]
    return {
        "report_path": str(report_path.resolve()),
        "report_name": report_path.name,
        "started_at": str(report_payload.get("started_at") or ""),
        "completed_at": str(report_payload.get("completed_at") or ""),
        "ok": bool(report_payload.get("ok")) if "ok" in report_payload else not bool(errors or parse_error),
        "dry_run": bool(report_payload.get("dry_run")),
        "candidate_count": int(metrics.get("candidate_count") or 0),
        "candidate_bytes": int(metrics.get("candidate_bytes") or 0),
        "removed_count": int(metrics.get("removed_count") or 0),
        "removed_bytes": int(metrics.get("removed_bytes") or 0),
        "warning_count": int(metrics.get("warning_count") or len(warnings)),
        "error_count": int(metrics.get("error_count") or len(errors) or bool(parse_error)),
        "categories": categories,
        "warnings": warnings,
        "errors": errors,
        "parse_error": str(parse_error or ""),
    }


def _queue_reference_path(queue_payload: dict[str, Any], *, stage: str) -> str:
    normalized_stage = str(stage or "").strip().lower()
    if normalized_stage == "extract":
        return str(queue_payload.get("source_manifest_path") or "")
    if normalized_stage == "recover":
        return str(queue_payload.get("extract_report_path") or "")
    if normalized_stage == "normalize":
        return str(queue_payload.get("recover_report_path") or queue_payload.get("extract_report_path") or "")
    if normalized_stage == "correlate":
        return str(queue_payload.get("normalize_report_path") or "")
    if normalized_stage == "store":
        return str(queue_payload.get("correlation_report_path") or "")
    if normalized_stage == "present":
        return str(queue_payload.get("store_report_path") or "")
    return ""


def _timestamp_slug(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "unknown"
    return "".join(char for char in text if char.isdigit())[:14] or "unknown"


def _ensure_unique_path(path: Path) -> Path:
    candidate = path
    index = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.stem}__{index}{path.suffix}")
        index += 1
    return candidate


def _sanitize_path_part(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "item"
    return "".join(char if char.isalnum() or char in {"-", "_", "."} else "_" for char in text)[:120] or "item"
