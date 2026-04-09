from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from intel_core import (
    ArtifactRecord,
    Confidence,
    IngestRequest,
    JobRecord,
    PluginExecutionContext,
    PluginResult,
    Provenance,
    RecordBase,
    SourceRecord,
    record_from_dict,
    record_to_dict,
    stable_record_id,
    utc_now,
)
from intel_core.registry import PluginRegistry
from intel_plugins import build_builtin_registry
from intel_plugins.config import (
    DEFAULT_PLUGIN_PROFILE_NAME,
    active_plugin_profile,
    load_plugin_settings,
    normalize_plugin_profile_name,
    persist_plugin_settings,
    plugin_profile_summaries,
    plugin_settings_path,
)
from intel_runtime.tuning import (
    apply_monitor_tuning_preset,
    apply_watch_tuning_preset,
    default_preset_automation_state,
    default_watch_tuning_profile,
    load_monitor_tuning,
    monitor_automation_modes,
    monitor_tuning_presets,
    normalize_preset_automation_state,
    normalize_watch_tuning_profile,
    update_monitor_tuning as persist_monitor_tuning,
    watch_tuning_preset_name_for_source_type,
    watch_tuning_presets,
)
from intel_storage import (
    DEFAULT_DATABASE_NAME,
    SQLiteIntelligenceStore,
    append_audit_event,
    cleanup_workspace,
    ensure_workspace_layout,
    materialize_derived_artifact,
    read_audit_events,
)

QUEUE_STAGE_ORDER = ("extract", "recover", "normalize", "correlate", "store", "present")
WATCH_ACTIVITY_RECENCY_MIN_SECONDS = 60.0
LOW_SIGNAL_SUPPRESSION_MIN_SECONDS = 30.0
LOW_SIGNAL_SUPPRESSION_FACTOR = 3.0
LOW_SIGNAL_SUPPRESSION_STREAK_THRESHOLD = 2


@dataclass(slots=True)
class PlatformApp:
    registry: PluginRegistry = field(default_factory=build_builtin_registry)

    def plugin_manifests(self, *, output_root: str | Path = "./pipeline_output/platform") -> tuple[object, ...]:
        return tuple(
            manifest
            for manifest, _registered, _enabled in self._effective_plugin_rows(
                output_root=output_root,
                enabled_only=True,
            )
        )

    def plugin_settings(self, *, output_root: str | Path = "./pipeline_output/platform") -> dict[str, object]:
        settings = load_plugin_settings(output_root, registry=self.registry)
        active_profile_name = str(settings.get("active_profile") or DEFAULT_PLUGIN_PROFILE_NAME).strip()
        return {
            "settings_path": str(plugin_settings_path(output_root)),
            "settings": settings,
            "active_profile": active_profile_name,
            "active_profile_settings": active_plugin_profile(settings),
            "profiles": list(plugin_profile_summaries(settings)),
        }

    def plugin_statuses(
        self,
        *,
        config: dict[str, object] | None = None,
        workspace_root: str | Path | None = None,
        output_root: str | Path = "./pipeline_output/platform",
        enabled_only: bool = False,
    ) -> tuple[dict[str, object], ...]:
        config_map = dict(config or {})
        workspace = Path(workspace_root).resolve() if workspace_root else Path(".").resolve()
        settings = load_plugin_settings(output_root, registry=self.registry)
        active_profile_name = str(settings.get("active_profile") or DEFAULT_PLUGIN_PROFILE_NAME).strip()
        rows: list[dict[str, object]] = []
        for manifest, registered, enabled in self._effective_plugin_rows(
            output_root=output_root,
            enabled_only=enabled_only,
        ):
            default_enabled = bool(registered.enabled) if registered is not None else bool(manifest.enabled_by_default)
            tool_statuses = tuple(_plugin_tool_statuses(manifest.required_tools, config_map, workspace))

            raw_health_messages: tuple[str, ...]
            try:
                plugin = self.registry.create(manifest.name)
                raw_health_messages = tuple(
                    str(item).strip()
                    for item in list(plugin.healthcheck() or ())
                    if str(item).strip()
                )
            except Exception as exc:  # pragma: no cover - defensive guard for unstable plugins
                raw_health_messages = (f"healthcheck failed: {exc}",)

            health_messages = _filter_health_messages(raw_health_messages, tool_statuses)
            missing_tools = tuple(status["tool"] for status in tool_statuses if not bool(status["available"]))
            status = _plugin_status_label(enabled=enabled, missing_tools=missing_tools, health_messages=health_messages)
            rows.append(
                {
                    "name": manifest.name,
                    "plugin_type": manifest.plugin_type,
                    "version": manifest.version,
                    "description": manifest.description,
                    "enabled": enabled,
                    "configured_enabled": enabled,
                    "default_enabled": default_enabled,
                    "enabled_by_default": bool(manifest.enabled_by_default),
                    "active_profile": active_profile_name,
                    "available": bool(enabled and status == "ready"),
                    "status": status,
                    "summary": _plugin_status_summary_text(status=status, missing_tools=missing_tools, health_messages=health_messages),
                    "capabilities": list(manifest.capabilities),
                    "input_types": list(manifest.input_types),
                    "output_types": list(manifest.output_types),
                    "required_tools": list(manifest.required_tools),
                    "policy_tags": list(manifest.policy_tags),
                    "tool_statuses": [dict(item) for item in tool_statuses],
                    "health_messages": list(health_messages),
                }
            )
        return tuple(rows)

    def plugin_status_summary(
        self,
        *,
        config: dict[str, object] | None = None,
        workspace_root: str | Path | None = None,
        output_root: str | Path = "./pipeline_output/platform",
        enabled_only: bool = False,
    ) -> dict[str, object]:
        statuses = self.plugin_statuses(
            config=config,
            workspace_root=workspace_root,
            output_root=output_root,
            enabled_only=enabled_only,
        )
        return _summarize_plugin_statuses(statuses)

    def update_plugin_settings(
        self,
        *,
        output_root: str | Path = "./pipeline_output/platform",
        plugin_name: str = "",
        enabled: bool | None = None,
        profile_name: str = "",
        set_active_profile: str = "",
        save_profile_as: str = "",
        source_profile_name: str = "",
        delete_profile_name: str = "",
    ) -> dict[str, object]:
        root = Path(output_root).resolve()
        settings = load_plugin_settings(root, registry=self.registry)
        profiles = {
            str(name): dict(payload or {})
            for name, payload in dict(settings.get("profiles") or {}).items()
        }
        active_name = str(settings.get("active_profile") or DEFAULT_PLUGIN_PROFILE_NAME).strip() or DEFAULT_PLUGIN_PROFILE_NAME
        warnings: list[str] = []
        errors: list[str] = []
        metrics: dict[str, object] = {}
        updated = False

        if plugin_name:
            normalized_plugin_name = str(plugin_name or "").strip()
            if normalized_plugin_name not in self.registry:
                errors.append(f"unknown plugin: {normalized_plugin_name}")
            elif enabled is None:
                errors.append("enabled must be provided when plugin_name is set")
            else:
                target_profile_name = normalize_plugin_profile_name(profile_name or active_name) or active_name
                source_profile_payload = dict(profiles.get(target_profile_name) or profiles.get(active_name) or {})
                if target_profile_name not in profiles:
                    profiles[target_profile_name] = {
                        **source_profile_payload,
                        "name": target_profile_name,
                    }
                target_profile = dict(profiles.get(target_profile_name) or {})
                plugin_map = dict(target_profile.get("plugins") or {})
                plugin_map[normalized_plugin_name] = {"enabled": bool(enabled)}
                target_profile["name"] = target_profile_name
                target_profile["plugins"] = plugin_map
                target_profile["updated_at"] = utc_now()
                profiles[target_profile_name] = target_profile
                metrics["updated_plugin_name"] = normalized_plugin_name
                metrics["updated_plugin_enabled"] = bool(enabled)
                metrics["updated_profile_name"] = target_profile_name
                updated = True

        if save_profile_as:
            normalized_save_name = normalize_plugin_profile_name(save_profile_as)
            if not normalized_save_name:
                errors.append("profile name is required")
            else:
                source_name = normalize_plugin_profile_name(source_profile_name or profile_name or active_name) or active_name
                if source_name not in profiles:
                    errors.append(f"unknown source profile: {source_name}")
                else:
                    source_payload = dict(profiles[source_name] or {})
                    profiles[normalized_save_name] = {
                        **source_payload,
                        "name": normalized_save_name,
                        "updated_at": utc_now(),
                    }
                    metrics["saved_profile_name"] = normalized_save_name
                    metrics["saved_from_profile_name"] = source_name
                    updated = True

        if delete_profile_name:
            normalized_delete_name = normalize_plugin_profile_name(delete_profile_name)
            if normalized_delete_name == DEFAULT_PLUGIN_PROFILE_NAME:
                errors.append("cannot delete the default plugin profile")
            elif normalized_delete_name not in profiles:
                errors.append(f"unknown profile: {normalized_delete_name}")
            else:
                del profiles[normalized_delete_name]
                if active_name == normalized_delete_name:
                    active_name = DEFAULT_PLUGIN_PROFILE_NAME
                    warnings.append("deleted active profile; reverted to default")
                metrics["deleted_profile_name"] = normalized_delete_name
                updated = True

        if set_active_profile:
            normalized_active_name = normalize_plugin_profile_name(set_active_profile)
            if normalized_active_name not in profiles:
                errors.append(f"unknown profile: {normalized_active_name}")
            else:
                active_name = normalized_active_name
                metrics["active_profile_changed_to"] = normalized_active_name
                updated = True

        if errors:
            current = load_plugin_settings(root, registry=self.registry)
            return {
                "ok": False,
                "settings_path": str(plugin_settings_path(root)),
                "settings": current,
                "active_profile": str(current.get("active_profile") or DEFAULT_PLUGIN_PROFILE_NAME).strip(),
                "active_profile_settings": active_plugin_profile(current),
                "profiles": list(plugin_profile_summaries(current)),
                "plugin_statuses": list(self.plugin_statuses(output_root=root)),
                "plugin_summary": self.plugin_status_summary(output_root=root),
                "artifact_paths": [],
                "warnings": warnings,
                "errors": errors,
                "metrics": metrics,
            }

        next_settings = {
            **settings,
            "updated_at": utc_now() if updated else str(settings.get("updated_at") or ""),
            "active_profile": active_name,
            "profiles": profiles,
        }
        persisted = persist_plugin_settings(root, registry=self.registry, payload=next_settings)
        artifact_paths: list[str] = [str(plugin_settings_path(root))]
        if updated:
            audit_path = _append_stage_audit(
                root,
                stage="plugin_control",
                plugin="plugin_control",
                source_id="",
                case_id="",
                job_id="",
                ok=True,
                warnings=tuple(warnings),
                errors=(),
                metrics={
                    **metrics,
                    "active_profile": str(persisted.get("active_profile") or DEFAULT_PLUGIN_PROFILE_NAME).strip(),
                    "profile_count": len(dict(persisted.get("profiles") or {})),
                },
                artifact_paths=tuple(artifact_paths),
                details={},
            )
            artifact_paths.append(str(audit_path))
        return {
            "ok": True,
            "settings_path": str(plugin_settings_path(root)),
            "settings": persisted,
            "active_profile": str(persisted.get("active_profile") or DEFAULT_PLUGIN_PROFILE_NAME).strip(),
            "active_profile_settings": active_plugin_profile(persisted),
            "profiles": list(plugin_profile_summaries(persisted)),
            "plugin_statuses": list(self.plugin_statuses(output_root=root)),
            "plugin_summary": self.plugin_status_summary(output_root=root),
            "artifact_paths": artifact_paths,
            "warnings": warnings,
            "errors": [],
            "metrics": {
                **metrics,
                "active_profile": str(persisted.get("active_profile") or DEFAULT_PLUGIN_PROFILE_NAME).strip(),
                "profile_count": len(dict(persisted.get("profiles") or {})),
            },
        }

    def _effective_plugin_rows(
        self,
        *,
        output_root: str | Path = "./pipeline_output/platform",
        plugin_type: str = "",
        enabled_only: bool = False,
    ) -> tuple[tuple[object, object | None, bool], ...]:
        settings = load_plugin_settings(output_root, registry=self.registry)
        active_profile_payload = active_plugin_profile(settings)
        plugin_map = dict(active_profile_payload.get("plugins") or {})
        rows: list[tuple[object, object | None, bool]] = []
        for manifest in self.registry.manifests(enabled_only=False):
            if plugin_type and str(manifest.plugin_type or "").strip() != str(plugin_type or "").strip():
                continue
            registered = self.registry.get(manifest.name)
            default_enabled = bool(registered.enabled) if registered is not None else bool(manifest.enabled_by_default)
            enabled = bool(dict(plugin_map.get(manifest.name) or {}).get("enabled", default_enabled))
            if enabled_only and not enabled:
                continue
            rows.append((manifest, registered, enabled))
        rows.sort(key=lambda item: str(item[0].name or ""))
        return tuple(rows)

    def list_queued_jobs(
        self,
        *,
        output_root: str | Path = "./pipeline_output/platform",
        case_id: str = "",
        stages: tuple[str, ...] | list[str] = (),
    ) -> tuple[dict[str, object], ...]:
        root = Path(output_root).resolve()
        stage_names = _normalize_queue_stages(stages)
        rows: list[dict[str, object]] = []
        for stage in stage_names:
            stage_dir = root / "queues" / stage
            if not stage_dir.exists():
                continue
            for queue_path in sorted(stage_dir.glob("*.json")):
                payload, parse_error = _read_json_payload(queue_path)
                job_payload = payload.get("job") if isinstance(payload, dict) else {}
                source_payload = payload.get("source") if isinstance(payload, dict) else {}
                queue_case_id = str(
                    (job_payload.get("case_id") if isinstance(job_payload, dict) else "")
                    or (source_payload.get("case_id") if isinstance(source_payload, dict) else "")
                    or ""
                ).strip()
                if case_id and queue_case_id != case_id:
                    continue
                triage = _resolve_queue_triage(
                    stage=stage,
                    queue_payload=payload if isinstance(payload, dict) else {},
                    source_payload=source_payload if isinstance(source_payload, dict) else {},
                    job_payload=job_payload if isinstance(job_payload, dict) else {},
                )
                rows.append(
                    {
                        "stage": stage,
                        "queue_path": str(queue_path.resolve()),
                        "job_id": str((job_payload.get("id") if isinstance(job_payload, dict) else "") or queue_path.stem),
                        "source_id": str(
                            (source_payload.get("id") if isinstance(source_payload, dict) else "")
                            or (source_payload.get("source_id") if isinstance(source_payload, dict) else "")
                            or ""
                        ).strip(),
                        "case_id": queue_case_id,
                        "source_type": str(
                            (source_payload.get("source_type") if isinstance(source_payload, dict) else "")
                            or ((job_payload.get("attributes") or {}).get("requested_source_type") if isinstance(job_payload, dict) else "")
                            or ""
                        ).strip(),
                        "generated_at": str((payload.get("generated_at") if isinstance(payload, dict) else "") or "").strip(),
                        "queued_age_seconds": _timestamp_age_seconds(
                            str((payload.get("generated_at") if isinstance(payload, dict) else "") or "").strip()
                        ),
                        "parse_error": parse_error,
                        "reference_path": _queued_reference_path(payload if isinstance(payload, dict) else {}, stage=stage),
                        "priority_score": int(triage["score"]),
                        "priority_label": str(triage["priority"]),
                        "priority_reasons": list(triage["reasons"]),
                        "triage": dict(triage),
                    }
                )
        rows.sort(
            key=lambda item: (
                _queue_stage_index(str(item.get("stage") or "")),
                -int(item.get("priority_score") or 0),
                str(item.get("queue_path") or ""),
            )
        )
        return tuple(rows)

    def run_queued(
        self,
        *,
        output_root: str | Path = "./pipeline_output/platform",
        workspace_root: str | Path = ".",
        database_path: str | None = None,
        case_id: str = "",
        stages: tuple[str, ...] | list[str] = (),
        max_jobs: int = 0,
        config: dict[str, object] | None = None,
    ) -> PluginResult:
        root = Path(output_root).resolve()
        workspace = Path(workspace_root).resolve()
        stage_names = _normalize_queue_stages(stages)
        ensure_workspace_layout(root)
        initial_queue_count = len(self.list_queued_jobs(output_root=root, case_id=case_id, stages=stage_names))

        records: list[RecordBase] = []
        artifact_paths: list[str] = []
        warnings: list[str] = []
        errors: list[str] = []
        processed_job_count = 0
        completed_job_count = 0
        failed_job_count = 0
        processed_priority_counts = _empty_priority_counts()
        completed_priority_counts = _empty_priority_counts()
        failed_priority_counts = _empty_priority_counts()

        stop_processing = False
        for stage in stage_names:
            if stop_processing:
                break
            queue_items = self.list_queued_jobs(output_root=root, case_id=case_id, stages=(stage,))
            for item in queue_items:
                if max_jobs > 0 and processed_job_count >= max_jobs:
                    stop_processing = True
                    break
                processed_job_count += 1
                _increment_priority_count(processed_priority_counts, str(item.get("priority_label") or ""))
                queue_path = Path(str(item["queue_path"])).resolve()
                payload, parse_error = _read_json_payload(queue_path)
                if parse_error:
                    failed_job_count += 1
                    _increment_priority_count(failed_priority_counts, str(item.get("priority_label") or ""))
                    archive_path = _archive_queue_payload(
                        root,
                        stage=stage,
                        queue_path=queue_path,
                        queue_payload={},
                        archive_state="failed",
                        result={
                            "ok": False,
                            "warnings": [],
                            "errors": [parse_error],
                            "metrics": {},
                        },
                    )
                    artifact_paths.append(str(archive_path))
                    errors.append(f"{stage}:{queue_path.name}: {parse_error}")
                    continue

                result = self._run_single_queued_job(
                    stage=stage,
                    queue_payload=payload,
                    output_root=root,
                    workspace_root=workspace,
                    database_path=database_path,
                    config=config,
                    case_id=case_id,
                )
                records.extend(result.records)
                artifact_paths.extend(path for path in result.artifact_paths if path not in artifact_paths)
                warnings.extend(warning for warning in result.warnings if warning not in warnings)
                result_errors = tuple(result.errors)
                if result.ok:
                    completed_job_count += 1
                    _increment_priority_count(completed_priority_counts, str(item.get("priority_label") or ""))
                else:
                    failed_job_count += 1
                    _increment_priority_count(failed_priority_counts, str(item.get("priority_label") or ""))
                    _remove_generated_queue_files(root, result.artifact_paths)
                    errors.extend(
                        error
                        for error in (f"{stage}:{queue_path.name}: {message}" for message in result_errors)
                        if error not in errors
                    )

                archive_path = _archive_queue_payload(
                    root,
                    stage=stage,
                    queue_path=queue_path,
                    queue_payload=payload,
                    archive_state="completed" if result.ok else "failed",
                    result={
                        "ok": result.ok,
                        "warnings": list(result.warnings),
                        "errors": list(result.errors),
                        "metrics": dict(result.metrics),
                    },
                )
                artifact_paths.append(str(archive_path))

        remaining_queue_count = len(self.list_queued_jobs(output_root=root, case_id=case_id, stages=stage_names))
        return PluginResult(
            records=tuple(records),
            artifact_paths=tuple(artifact_paths),
            warnings=tuple(warnings),
            errors=tuple(errors),
            metrics={
                "initial_queue_count": initial_queue_count,
                "processed_job_count": processed_job_count,
                "completed_job_count": completed_job_count,
                "failed_job_count": failed_job_count,
                "remaining_queue_count": remaining_queue_count,
                "processed_priority_counts": processed_priority_counts,
                "completed_priority_counts": completed_priority_counts,
                "failed_priority_counts": failed_priority_counts,
            },
        )

    def collector_names(self, *, output_root: str | Path = "./pipeline_output/platform") -> tuple[str, ...]:
        return tuple(
            manifest.name
            for manifest, _registered, _enabled in self._effective_plugin_rows(
                output_root=output_root,
                plugin_type="collector",
                enabled_only=True,
            )
        )

    def cleanup_workspace(
        self,
        *,
        output_root: str | Path = "./pipeline_output/platform",
        queue_completed_max_age_seconds: float = 0.0,
        queue_failed_max_age_seconds: float = 0.0,
        watch_delta_max_age_seconds: float = 0.0,
        dry_run: bool = False,
    ) -> dict[str, object]:
        root = Path(output_root).resolve()
        ensure_workspace_layout(root)
        cleanup = cleanup_workspace(
            root,
            queue_completed_max_age_seconds=max(0.0, float(queue_completed_max_age_seconds or 0.0)),
            queue_failed_max_age_seconds=max(0.0, float(queue_failed_max_age_seconds or 0.0)),
            watch_delta_max_age_seconds=max(0.0, float(watch_delta_max_age_seconds or 0.0)),
            dry_run=bool(dry_run),
        )
        artifact_paths = [
            str(cleanup.get("report_path") or ""),
            str(cleanup.get("history_path") or ""),
        ]
        warnings = [str(item).strip() for item in list(cleanup.get("warnings") or []) if str(item).strip()]
        errors = [str(item).strip() for item in list(cleanup.get("errors") or []) if str(item).strip()]
        metrics = dict(cleanup.get("metrics") or {})
        categories = dict(cleanup.get("categories") or {})

        if int(metrics.get("removed_count") or 0) > 0 or warnings or errors:
            audit_path = _append_stage_audit(
                root,
                stage="cleanup",
                plugin="workspace_cleanup",
                source_id="",
                case_id="",
                job_id="",
                ok=not errors,
                warnings=tuple(warnings),
                errors=tuple(errors),
                metrics={
                    **metrics,
                    "dry_run": bool(dry_run),
                    "queue_completed_max_age_seconds": max(0.0, float(queue_completed_max_age_seconds or 0.0)),
                    "queue_failed_max_age_seconds": max(0.0, float(queue_failed_max_age_seconds or 0.0)),
                    "watch_delta_max_age_seconds": max(0.0, float(watch_delta_max_age_seconds or 0.0)),
                },
                artifact_paths=tuple(path for path in artifact_paths if path),
                details={
                    "categories": categories,
                },
            )
            artifact_paths.append(str(audit_path))

        return {
            "ok": not errors,
            "artifact_paths": [path for path in artifact_paths if path],
            "warnings": warnings,
            "errors": errors,
            "cleanup": cleanup,
            "metrics": {
                **metrics,
                "dry_run": bool(dry_run),
                "queue_completed_max_age_seconds": max(0.0, float(queue_completed_max_age_seconds or 0.0)),
                "queue_failed_max_age_seconds": max(0.0, float(queue_failed_max_age_seconds or 0.0)),
                "watch_delta_max_age_seconds": max(0.0, float(watch_delta_max_age_seconds or 0.0)),
            },
        }

    def extractor_names(self, *, output_root: str | Path = "./pipeline_output/platform") -> tuple[str, ...]:
        return tuple(
            manifest.name
            for manifest, _registered, _enabled in self._effective_plugin_rows(
                output_root=output_root,
                plugin_type="extractor",
                enabled_only=True,
            )
        )

    def recovery_names(self, *, output_root: str | Path = "./pipeline_output/platform") -> tuple[str, ...]:
        return tuple(
            manifest.name
            for manifest, _registered, _enabled in self._effective_plugin_rows(
                output_root=output_root,
                plugin_type="recovery",
                enabled_only=True,
            )
        )

    def normalizer_names(self, *, output_root: str | Path = "./pipeline_output/platform") -> tuple[str, ...]:
        return tuple(
            manifest.name
            for manifest, _registered, _enabled in self._effective_plugin_rows(
                output_root=output_root,
                plugin_type="normalizer",
                enabled_only=True,
            )
        )

    def correlator_names(self, *, output_root: str | Path = "./pipeline_output/platform") -> tuple[str, ...]:
        return tuple(
            manifest.name
            for manifest, _registered, _enabled in self._effective_plugin_rows(
                output_root=output_root,
                plugin_type="correlator",
                enabled_only=True,
            )
        )

    def resolve_collector_name(
        self,
        source_type: str,
        *,
        output_root: str | Path = "./pipeline_output/platform",
    ) -> str:
        normalized = str(source_type or "").strip().lower()
        for manifest, _registered, _enabled in self._effective_plugin_rows(
            output_root=output_root,
            plugin_type="collector",
            enabled_only=True,
        ):
            if normalized in tuple(value.lower() for value in manifest.input_types):
                return manifest.name
        raise ValueError(f"no collector registered for source type {normalized!r}")

    def ingest(
        self,
        request: IngestRequest,
        *,
        case_id: str = "",
        output_root: str | None = None,
        workspace_root: str | None = None,
        config: dict[str, object] | None = None,
    ) -> PluginResult:
        collector_name = self.resolve_collector_name(request.source_type, output_root=output_root or "./pipeline_output/platform")
        collector = self.registry.create(collector_name)
        context = PluginExecutionContext(
            case_id=case_id,
            output_root=output_root or "./pipeline_output/platform",
            workspace_root=workspace_root or ".",
            config=dict(config or {}),
        )
        ensure_workspace_layout(context.output_root)
        result = collector.collect(context, request)

        source = _first_source_record(result.records)
        queued_job = _first_job_record(result.records, stage="extract")
        extra_paths: list[str] = []
        if source is not None:
            audit_path = _append_stage_audit(
                context.output_root,
                stage="ingest",
                plugin=collector_name,
                source_id=source.id,
                case_id=context.case_id,
                job_id=queued_job.id if queued_job is not None else "",
                ok=result.ok,
                warnings=result.warnings,
                errors=result.errors,
                metrics=result.metrics,
                artifact_paths=result.artifact_paths,
                details={"collector": collector_name, "locator": request.locator},
            )
            extra_paths.append(str(audit_path))

        return PluginResult(
            records=result.records,
            artifact_paths=(*result.artifact_paths, *extra_paths),
            warnings=result.warnings,
            errors=result.errors,
            metrics=dict(result.metrics),
        )

    def watch_source(
        self,
        request: IngestRequest,
        *,
        case_id: str = "",
        output_root: str | None = None,
        workspace_root: str | None = None,
        database_path: str | None = None,
        config: dict[str, object] | None = None,
        force: bool = False,
    ) -> dict[str, object]:
        collector_name = self.resolve_collector_name(request.source_type, output_root=output_root or "./pipeline_output/platform")
        collector = self.registry.create(collector_name)
        context = PluginExecutionContext(
            case_id=case_id,
            output_root=output_root or "./pipeline_output/platform",
            workspace_root=workspace_root or ".",
            config=dict(config or {}),
        )
        ensure_workspace_layout(context.output_root)
        database_file = Path(database_path).resolve() if database_path else context.output_root / "storage" / DEFAULT_DATABASE_NAME
        store = SQLiteIntelligenceStore(database_file)
        store.initialize()

        snapshot_source = getattr(collector, "snapshot_source", None)
        if not callable(snapshot_source):
            return {
                "ok": False,
                "changed": False,
                "ingested": False,
                "skipped": False,
                "watcher_id": "",
                "watcher_state": {},
                "watcher_summary": store.watcher_summary(case_id=context.case_id),
                "artifact_paths": [],
                "warnings": [],
                "errors": [f"{collector_name} does not support delta-aware source snapshots"],
                "metrics": {
                    "source_type": request.source_type,
                    "locator": request.locator,
                    "database_path": str(database_file.resolve()),
                },
            }

        checked_at = utc_now()
        previous: dict[str, object] = {}
        try:
            provisional_watcher_id = _source_monitor_watcher_id(
                case_id=context.case_id,
                source_type=str(request.source_type or "").strip().lower(),
                locator=str(request.locator or ""),
                recursive=bool(request.options.get("recursive", True)),
            )
            previous = _find_watcher_state(
                store.fetch_watcher_states(
                    case_id=context.case_id,
                    watcher_id=provisional_watcher_id,
                    watcher_type="source_monitor",
                    limit=1,
                ),
                watcher_id=provisional_watcher_id,
            )
            snapshot = snapshot_source(request, previous_watcher_state=previous)
        except (FileNotFoundError, ValueError) as exc:
            return {
                "ok": False,
                "changed": False,
                "ingested": False,
                "skipped": False,
                "watcher_id": "",
                "watcher_state": {},
                "watcher_summary": store.watcher_summary(case_id=context.case_id),
                "artifact_paths": [],
                "warnings": [],
                "errors": [str(exc)],
                "metrics": {
                    "source_type": request.source_type,
                    "locator": request.locator,
                    "database_path": str(database_file.resolve()),
                    "checked_at": checked_at,
                },
            }

        watcher_id = stable_record_id(
            "watcher",
            "source_monitor",
            context.case_id,
            snapshot.requested_type,
            str(snapshot.path),
            str(snapshot.recursive),
        )
        if not previous or str(previous.get("watcher_id") or "") != watcher_id:
            previous = _find_watcher_state(
                store.fetch_watcher_states(
                    case_id=context.case_id,
                    watcher_id=watcher_id,
                    watcher_type="source_monitor",
                    limit=1,
                ),
                watcher_id=watcher_id,
            )
        previous_content_hash = str(previous.get("content_hash") or "")
        previous_source_id = str(previous.get("source_id") or "")
        changed = bool(force or not previous or previous_content_hash != snapshot.content_hash)
        if force and not changed:
            changed = True

        if changed:
            if snapshot.removed_file_count > 0:
                change_kind = "structural"
            elif snapshot.append_only_file_count > 0 and snapshot.changed_file_count == snapshot.append_only_file_count:
                change_kind = "append_only"
            else:
                change_kind = "modified"
        else:
            change_kind = "unchanged"

        watch_triage = _build_watch_triage(
            source_type=snapshot.requested_type,
            change_kind=change_kind,
            changed=changed,
            delta_ingest=False,
            file_count=snapshot.file_count,
            changed_file_count=snapshot.changed_file_count,
            append_only_file_count=snapshot.append_only_file_count,
            removed_file_count=snapshot.removed_file_count,
            force=bool(force),
        )

        ingest_result = PluginResult()
        source = None
        queued_job = None
        warnings: list[str] = []
        errors: list[str] = []
        artifact_paths: list[str] = []
        source_id = previous_source_id
        delta_ingest = False
        delta_artifact_count = 0
        delta_bytes = 0
        if changed:
            collect_from_snapshot = getattr(collector, "collect_from_snapshot", None)
            if change_kind == "append_only":
                try:
                    ingest_result = _build_append_only_delta_ingest_result(
                        collector=collector,
                        context=context,
                        request=request,
                        snapshot=snapshot,
                        previous_source_id=previous_source_id,
                    )
                except OSError as exc:
                    warnings.append(f"append-only delta ingest failed, falling back to full ingest: {exc}")
                    ingest_result = PluginResult()
                else:
                    delta_ingest = ingest_result.ok and bool(ingest_result.metrics.get("delta_ingest"))
                    delta_artifact_count = int(ingest_result.metrics.get("delta_artifact_count") or 0)
                    delta_bytes = int(ingest_result.metrics.get("delta_bytes") or 0)
                    if not ingest_result.ok:
                        errors.extend(ingest_result.errors)
            if not ingest_result.records and not errors:
                if callable(collect_from_snapshot):
                    ingest_result = collect_from_snapshot(context, request, snapshot)
                else:
                    ingest_result = self.ingest(
                        request,
                        case_id=context.case_id,
                        output_root=str(context.output_root),
                        workspace_root=str(context.workspace_root),
                        config=context.config,
                    )
            source = _first_source_record(ingest_result.records)
            queued_job = _first_job_record(ingest_result.records, stage="extract")
            warnings.extend(list(ingest_result.warnings))
            errors.extend(list(ingest_result.errors))
            artifact_paths = list(ingest_result.artifact_paths)
            if source is not None:
                source_id = source.id
                if callable(collect_from_snapshot):
                    ingest_audit_path = _append_stage_audit(
                        context.output_root,
                        stage="ingest",
                        plugin=collector_name,
                        source_id=source.id,
                        case_id=context.case_id,
                        job_id=queued_job.id if queued_job is not None else "",
                        ok=ingest_result.ok,
                        warnings=ingest_result.warnings,
                        errors=ingest_result.errors,
                        metrics=ingest_result.metrics,
                        artifact_paths=ingest_result.artifact_paths,
                        details={
                            "collector": collector_name,
                            "locator": request.locator,
                            "delta_ingest": bool(delta_ingest),
                        },
                    )
                    artifact_paths.append(str(ingest_audit_path))

        watch_triage = _build_watch_triage(
            source_type=snapshot.requested_type,
            change_kind=change_kind,
            changed=changed,
            delta_ingest=bool(delta_ingest),
            file_count=snapshot.file_count,
            changed_file_count=snapshot.changed_file_count,
            append_only_file_count=snapshot.append_only_file_count,
            removed_file_count=snapshot.removed_file_count,
            force=bool(force),
        )
        triage_priority = str(watch_triage["priority"])
        registered_watch = _find_registered_watch_source(
            store,
            case_id=context.case_id,
            source_type=snapshot.requested_type,
            locator=str(snapshot.path),
        )
        registered_poll_interval_seconds = max(0.0, float(registered_watch.get("poll_interval_seconds") or 0.0))
        recent_activity_window_seconds = max(
            WATCH_ACTIVITY_RECENCY_MIN_SECONDS,
            registered_poll_interval_seconds * 4.0,
        )
        previous_status = str(previous.get("status") or "").strip().lower()
        previous_priority = str(previous.get("triage_priority") or "").strip().lower()
        previous_change_age_seconds = _timestamp_age_seconds(str(previous.get("last_changed_at") or ""))

        burst_change_streak = 0
        if changed and not errors and triage_priority in {"high", "urgent"}:
            if (
                previous_status == "changed"
                and previous_priority in {"high", "urgent"}
                and previous_change_age_seconds <= recent_activity_window_seconds
            ):
                burst_change_streak = int(previous.get("burst_change_streak") or 0) + 1
            else:
                burst_change_streak = 1

        low_signal_change_streak = 0
        low_signal_change = bool(
            changed
            and not errors
            and triage_priority == "low"
            and not bool(delta_ingest)
            and snapshot.append_only_file_count <= 0
            and snapshot.removed_file_count <= 0
            and not bool(force)
        )
        if low_signal_change:
            if (
                previous_status == "changed"
                and previous_priority == "low"
                and previous_change_age_seconds <= recent_activity_window_seconds
            ):
                low_signal_change_streak = int(previous.get("low_signal_change_streak") or 0) + 1
            else:
                low_signal_change_streak = 1

        suppression_seconds = 0.0
        suppression_reason = ""
        suppression_until = ""
        if low_signal_change and low_signal_change_streak >= LOW_SIGNAL_SUPPRESSION_STREAK_THRESHOLD:
            suppression_seconds = max(
                LOW_SIGNAL_SUPPRESSION_MIN_SECONDS,
                max(registered_poll_interval_seconds, 10.0) * LOW_SIGNAL_SUPPRESSION_FACTOR,
            )
            suppression_until = _timestamp_after_seconds(checked_at, seconds=suppression_seconds)
            suppression_reason = "repeated low-priority changes"

        watcher_state = {
            "watcher_id": watcher_id,
            "source_id": source_id,
            "case_id": context.case_id,
            "watcher_type": "source_monitor",
            "source_type": snapshot.requested_type,
            "locator": str(snapshot.path),
            "status": "error" if errors else ("changed" if changed else "unchanged"),
            "last_checked_at": checked_at,
            "last_seen_at": checked_at,
            "last_changed_at": checked_at if changed else str(previous.get("last_changed_at") or ""),
            "cursor": snapshot.cursor,
            "content_hash": snapshot.content_hash,
            "suppression_until": suppression_until,
            "backlog_pointer": "extract" if changed and not errors and queued_job is not None else "",
            "consecutive_no_change_count": 0 if changed else int(previous.get("consecutive_no_change_count") or 0) + 1,
            "total_check_count": int(previous.get("total_check_count") or 0) + 1,
            "total_change_count": int(previous.get("total_change_count") or 0) + (1 if changed else 0),
            "last_error": "; ".join(errors[:2]),
            "change_kind": change_kind,
            "display_name": snapshot.display_name,
            "media_type": snapshot.media_type,
            "size_bytes": snapshot.size_bytes,
            "file_count": snapshot.file_count,
            "reused_hash_count": snapshot.reused_hash_count,
            "full_hash_count": snapshot.full_hash_count,
            "changed_file_count": snapshot.changed_file_count,
            "append_only_file_count": snapshot.append_only_file_count,
            "removed_file_count": snapshot.removed_file_count,
            "delta_ingest": bool(delta_ingest),
            "delta_artifact_count": delta_artifact_count,
            "delta_bytes": delta_bytes,
            "triage_score": int(watch_triage["score"]),
            "triage_priority": triage_priority,
            "triage_reasons": list(watch_triage["reasons"]),
            "registered_poll_interval_seconds": registered_poll_interval_seconds,
            "burst_change_streak": burst_change_streak,
            "low_signal_change_streak": low_signal_change_streak,
            "suppression_seconds": suppression_seconds,
            "suppression_reason": suppression_reason,
            "file_rows": [
                {
                    "relative_path": str(row["relative_path"]),
                    "sha256": str(row["sha256"]),
                    "size_bytes": int(row["size_bytes"]),
                    "media_type": str(row["media_type"]),
                    "mtime_ns": int(row["mtime_ns"]),
                    "hash_reused": bool(row["hash_reused"]),
                    "change_kind": str(row["change_kind"]),
                    "previous_size_bytes": int(row["previous_size_bytes"]),
                    "previous_mtime_ns": int(row["previous_mtime_ns"]),
                    "appended_bytes": int(row["appended_bytes"]),
                }
                for row in snapshot.file_rows
            ],
            "cursor_rows": [
                {
                    "relative_path": str(row["relative_path"]),
                    "size_bytes": int(row["size_bytes"]),
                    "mtime_ns": int(row["mtime_ns"]),
                }
                for row in snapshot.file_rows
            ],
        }
        store.persist_watcher_states((watcher_state,))
        watcher_rows = store.fetch_watcher_states(
            case_id=context.case_id,
            watcher_id=watcher_id,
            watcher_type="source_monitor",
            limit=1,
        )
        watcher_summary = store.watcher_summary(case_id=context.case_id)
        audit_path = _append_stage_audit(
            context.output_root,
            stage="watch",
            plugin=collector_name,
            source_id=source_id,
            case_id=context.case_id,
            job_id=queued_job.id if queued_job is not None else "",
            ok=not errors,
            warnings=warnings,
            errors=errors,
            metrics={
                "watcher_id": watcher_id,
                "changed": changed,
                "ingested": bool(changed and not errors and source_id),
                "skipped": bool(not changed),
                "file_count": snapshot.file_count,
                "content_hash": snapshot.content_hash,
                "previous_content_hash": previous_content_hash,
                "cursor": snapshot.cursor,
                "change_kind": change_kind,
                "reused_hash_count": snapshot.reused_hash_count,
                "full_hash_count": snapshot.full_hash_count,
                "changed_file_count": snapshot.changed_file_count,
                "append_only_file_count": snapshot.append_only_file_count,
                "removed_file_count": snapshot.removed_file_count,
                "delta_ingest": bool(delta_ingest),
                "delta_artifact_count": delta_artifact_count,
                "delta_bytes": delta_bytes,
                "triage_score": int(watch_triage["score"]),
                "triage_priority": triage_priority,
                "burst_change_streak": burst_change_streak,
                "low_signal_change_streak": low_signal_change_streak,
                "suppression_until": suppression_until,
                "suppression_seconds": suppression_seconds,
                "force": bool(force),
            },
            artifact_paths=artifact_paths,
            details={
                "collector": collector_name,
                "locator": str(snapshot.path),
                "source_type": snapshot.requested_type,
                "watcher_type": "source_monitor",
            },
        )
        artifact_paths.append(str(audit_path))

        return {
            "ok": not errors,
            "changed": changed,
            "ingested": bool(changed and not errors and source_id),
            "skipped": bool(not changed),
            "watcher_id": watcher_id,
            "watcher_state": dict(watcher_rows[0]) if watcher_rows else dict(watcher_state),
            "watcher_summary": watcher_summary,
            "artifact_paths": artifact_paths,
            "warnings": warnings,
            "errors": errors,
            "metrics": {
                "source_type": snapshot.requested_type,
                "locator": str(snapshot.path),
                "file_count": snapshot.file_count,
                "content_hash": snapshot.content_hash,
                "previous_content_hash": previous_content_hash,
                "cursor": snapshot.cursor,
                "change_kind": change_kind,
                "reused_hash_count": snapshot.reused_hash_count,
                "full_hash_count": snapshot.full_hash_count,
                "changed_file_count": snapshot.changed_file_count,
                "append_only_file_count": snapshot.append_only_file_count,
                "removed_file_count": snapshot.removed_file_count,
                "delta_ingest": bool(delta_ingest),
                "delta_artifact_count": delta_artifact_count,
                "delta_bytes": delta_bytes,
                "triage_score": int(watch_triage["score"]),
                "triage_priority": triage_priority,
                "triage_reasons": list(watch_triage["reasons"]),
                "burst_change_streak": burst_change_streak,
                "low_signal_change_streak": low_signal_change_streak,
                "registered_poll_interval_seconds": registered_poll_interval_seconds,
                "suppression_until": suppression_until,
                "suppression_seconds": suppression_seconds,
                "suppression_reason": suppression_reason,
                "database_path": str(database_file.resolve()),
                "checked_at": checked_at,
                "source_id": source_id,
                "job_id": queued_job.id if queued_job is not None else "",
                "force": bool(force),
            },
        }

    def register_watch_source(
        self,
        request: IngestRequest,
        *,
        case_id: str = "",
        output_root: str | None = None,
        workspace_root: str | None = None,
        database_path: str | None = None,
        config: dict[str, object] | None = None,
        enabled: bool = True,
        poll_interval_seconds: float = 0.0,
        tuning_preset_name: str = "",
        forecast_min_history: int | None = None,
        source_churn_spike_factor: float | None = None,
        suppressed_alert_ids: list[str] | tuple[str, ...] | None = None,
    ) -> dict[str, object]:
        collector_name = self.resolve_collector_name(request.source_type, output_root=output_root or "./pipeline_output/platform")
        collector = self.registry.create(collector_name)
        context = PluginExecutionContext(
            case_id=case_id,
            output_root=output_root or "./pipeline_output/platform",
            workspace_root=workspace_root or ".",
            config=dict(config or {}),
        )
        ensure_workspace_layout(context.output_root)
        database_file = Path(database_path).resolve() if database_path else context.output_root / "storage" / DEFAULT_DATABASE_NAME
        store = SQLiteIntelligenceStore(database_file)
        store.initialize()

        snapshot_source = getattr(collector, "snapshot_source", None)
        if not callable(snapshot_source):
            return {
                "ok": False,
                "watch_id": "",
                "watched_source": {},
                "watched_source_summary": store.watched_source_summary(case_id=context.case_id),
                "artifact_paths": [],
                "warnings": [],
                "errors": [f"{collector_name} does not support watched-source registration"],
                "metrics": {
                    "source_type": request.source_type,
                    "locator": request.locator,
                    "database_path": str(database_file.resolve()),
                },
            }

        try:
            snapshot = snapshot_source(request)
        except (FileNotFoundError, ValueError) as exc:
            return {
                "ok": False,
                "watch_id": "",
                "watched_source": {},
                "watched_source_summary": store.watched_source_summary(case_id=context.case_id),
                "artifact_paths": [],
                "warnings": [],
                "errors": [str(exc)],
                "metrics": {
                    "source_type": request.source_type,
                    "locator": request.locator,
                    "database_path": str(database_file.resolve()),
                },
            }

        watch_id = stable_record_id(
            "watchsrc",
            context.case_id,
            snapshot.requested_type,
            str(snapshot.path),
            str(snapshot.recursive),
        )
        previous = _find_watched_source(
            store.fetch_watched_sources(case_id=context.case_id, watch_id=watch_id, limit=1),
            watch_id=watch_id,
        )
        registered_at = str(previous.get("created_at") or utc_now())
        updated_at = utc_now()
        resolved_tuning_preset_name = str(tuning_preset_name or "").strip() or watch_tuning_preset_name_for_source_type(
            snapshot.requested_type
        )
        tuning_profile = _watch_tuning_profile_from_updates(
            preset_name=resolved_tuning_preset_name,
            forecast_min_history=forecast_min_history,
            source_churn_spike_factor=source_churn_spike_factor,
            suppressed_alert_ids=suppressed_alert_ids,
        )
        watched_source = {
            "watch_id": watch_id,
            "case_id": context.case_id,
            "source_type": snapshot.requested_type,
            "locator": str(snapshot.path),
            "display_name": snapshot.display_name,
            "recursive": snapshot.recursive,
            "enabled": bool(enabled),
            "poll_interval_seconds": max(0.0, float(poll_interval_seconds or 0.0)),
            "status": "active" if enabled else "disabled",
            "created_at": registered_at,
            "updated_at": updated_at,
            "collector": collector_name,
            "media_type": snapshot.media_type,
            "content_hash": snapshot.content_hash,
            "file_count": snapshot.file_count,
            "snooze_until": "",
            "notes": "",
            "tags": [],
            "tuning_preset_name": str(tuning_profile.get("preset_name") or ""),
            "tuning_profile": tuning_profile,
            "automation_state": _materialize_preset_automation_state(previous.get("automation_state")),
        }
        store.persist_watched_sources((watched_source,))
        persisted = store.fetch_watched_sources(case_id=context.case_id, watch_id=watch_id, limit=1)
        audit_path = _append_stage_audit(
            context.output_root,
            stage="watch_register",
            plugin=collector_name,
            source_id=str(previous.get("source_id") or ""),
            case_id=context.case_id,
            job_id="",
            ok=True,
            warnings=(),
            errors=(),
            metrics={
                "watch_id": watch_id,
                "enabled": bool(enabled),
                "poll_interval_seconds": max(0.0, float(poll_interval_seconds or 0.0)),
                "file_count": snapshot.file_count,
                "watch_profile_preset_name": str(tuning_profile.get("preset_name") or ""),
                "watch_profile_suppressed_alert_count": len(list(tuning_profile.get("suppressed_alert_ids") or [])),
                "watch_profile_source_churn_spike_factor": float(tuning_profile.get("source_churn_spike_factor") or 0.0),
            },
            artifact_paths=(),
            details={
                "collector": collector_name,
                "locator": str(snapshot.path),
                "source_type": snapshot.requested_type,
            },
        )
        return {
            "ok": True,
            "watch_id": watch_id,
            "watched_source": _materialize_watched_source(dict(persisted[0]) if persisted else watched_source),
            "available_watch_presets": list(watch_tuning_presets()),
            "watched_source_summary": store.watched_source_summary(case_id=context.case_id),
            "artifact_paths": [str(audit_path)],
            "warnings": [],
            "errors": [],
            "metrics": {
                "watch_id": watch_id,
                "source_type": snapshot.requested_type,
                "locator": str(snapshot.path),
                "file_count": snapshot.file_count,
                "database_path": str(database_file.resolve()),
                "poll_interval_seconds": max(0.0, float(poll_interval_seconds or 0.0)),
                "enabled": bool(enabled),
                "watch_profile_preset_name": str(tuning_profile.get("preset_name") or ""),
                "watch_profile_suppressed_alert_count": len(list(tuning_profile.get("suppressed_alert_ids") or [])),
                "watch_profile_source_churn_spike_factor": float(tuning_profile.get("source_churn_spike_factor") or 0.0),
            },
        }

    def list_watch_sources(
        self,
        *,
        case_id: str = "",
        output_root: str | None = None,
        database_path: str | None = None,
        enabled_only: bool = False,
    ) -> dict[str, object]:
        effective_output_root = Path(output_root or "./pipeline_output/platform").resolve()
        database_file = Path(database_path).resolve() if database_path else effective_output_root / "storage" / DEFAULT_DATABASE_NAME
        store = SQLiteIntelligenceStore(database_file)
        store.initialize()
        rows = store.fetch_watched_sources(case_id=case_id, enabled_only=enabled_only, limit=500)
        return {
            "ok": True,
            "watched_sources": [_materialize_watched_source(row) for row in rows],
            "available_watch_presets": list(watch_tuning_presets()),
            "watched_source_summary": store.watched_source_summary(case_id=case_id),
            "metrics": {
                "database_path": str(database_file.resolve()),
                "watched_source_count": len(rows),
                "enabled_only": bool(enabled_only),
            },
        }

    def get_watch_source_detail(
        self,
        *,
        case_id: str = "",
        watch_id: str,
        output_root: str | None = None,
        database_path: str | None = None,
    ) -> dict[str, object]:
        effective_output_root = Path(output_root or "./pipeline_output/platform").resolve()
        database_file = Path(database_path).resolve() if database_path else effective_output_root / "storage" / DEFAULT_DATABASE_NAME
        store = SQLiteIntelligenceStore(database_file)
        store.initialize()
        watched_source = _find_watched_source(
            store.fetch_watched_sources(case_id=case_id, watch_id=watch_id, limit=1),
            watch_id=watch_id,
        )
        if not watched_source:
            return {
                "ok": False,
                "watched_source": {},
                "watcher_state": {},
                "watched_source_summary": store.watched_source_summary(case_id=case_id),
                "watcher_summary": store.watcher_summary(case_id=case_id),
                "artifact_paths": [],
                "warnings": [],
                "errors": [f"unknown watch_id: {watch_id}"],
                "metrics": {
                    "watch_id": watch_id,
                    "database_path": str(database_file.resolve()),
                },
            }
        watcher_state = _find_source_monitor_watcher(store, watched_source)
        return {
            "ok": True,
            "watched_source": _materialize_watched_source(dict(watched_source)),
            "available_watch_presets": list(watch_tuning_presets()),
            "watcher_state": dict(watcher_state),
            "watched_source_summary": store.watched_source_summary(case_id=case_id),
            "watcher_summary": store.watcher_summary(case_id=case_id),
            "artifact_paths": [],
            "warnings": [],
            "errors": [],
            "metrics": {
                "watch_id": watch_id,
                "database_path": str(database_file.resolve()),
                "has_watcher_state": bool(watcher_state),
            },
        }

    def set_watch_source_enabled(
        self,
        *,
        case_id: str = "",
        watch_id: str,
        enabled: bool,
        output_root: str | None = None,
        database_path: str | None = None,
    ) -> dict[str, object]:
        effective_output_root = Path(output_root or "./pipeline_output/platform").resolve()
        database_file = Path(database_path).resolve() if database_path else effective_output_root / "storage" / DEFAULT_DATABASE_NAME
        store = SQLiteIntelligenceStore(database_file)
        store.initialize()

        watched_source = _find_watched_source(
            store.fetch_watched_sources(case_id=case_id, watch_id=watch_id, limit=1),
            watch_id=watch_id,
        )
        if not watched_source:
            return {
                "ok": False,
                "watched_source": {},
                "watcher_state": {},
                "watched_source_summary": store.watched_source_summary(case_id=case_id),
                "watcher_summary": store.watcher_summary(case_id=case_id),
                "artifact_paths": [],
                "warnings": [],
                "errors": [f"unknown watch_id: {watch_id}"],
                "metrics": {
                    "watch_id": watch_id,
                    "database_path": str(database_file.resolve()),
                },
            }

        updated_watched_source = {
            **watched_source,
            "enabled": bool(enabled),
            "status": "active" if enabled else "disabled",
            "updated_at": utc_now(),
        }
        store.persist_watched_sources((updated_watched_source,))

        watcher_state = _find_source_monitor_watcher(store, updated_watched_source)
        if watcher_state:
            updated_watcher_state = dict(watcher_state)
            updated_watcher_state["enabled"] = bool(enabled)
            if not enabled:
                updated_watcher_state["status"] = "disabled"
            elif str(updated_watcher_state.get("status") or "").strip().lower() == "disabled":
                updated_watcher_state["status"] = "unchanged"
            store.persist_watcher_states((updated_watcher_state,))
            watcher_state = updated_watcher_state

        audit_path = _append_stage_audit(
            effective_output_root,
            stage="watch_control",
            plugin="monitor_control",
            source_id=str(watcher_state.get("source_id") or watched_source.get("source_id") or ""),
            case_id=str(updated_watched_source.get("case_id") or case_id or ""),
            job_id="",
            ok=True,
            warnings=(),
            errors=(),
            metrics={
                "watch_id": watch_id,
                "enabled": bool(enabled),
                "action": "enable" if enabled else "disable",
            },
            artifact_paths=(),
            details={
                "locator": str(updated_watched_source.get("locator") or ""),
                "source_type": str(updated_watched_source.get("source_type") or ""),
            },
        )
        persisted = _find_watched_source(
            store.fetch_watched_sources(case_id=case_id, watch_id=watch_id, limit=1),
            watch_id=watch_id,
        )
        return {
            "ok": True,
            "watched_source": _materialize_watched_source(dict(persisted)),
            "available_watch_presets": list(watch_tuning_presets()),
            "watcher_state": dict(_find_source_monitor_watcher(store, persisted)),
            "watched_source_summary": store.watched_source_summary(case_id=case_id),
            "watcher_summary": store.watcher_summary(case_id=case_id),
            "artifact_paths": [str(audit_path)],
            "warnings": [],
            "errors": [],
            "metrics": {
                "watch_id": watch_id,
                "enabled": bool(enabled),
                "database_path": str(database_file.resolve()),
            },
        }

    def set_watch_source_suppression(
        self,
        *,
        case_id: str = "",
        watch_id: str,
        seconds: float,
        output_root: str | None = None,
        database_path: str | None = None,
        mode: str = "set",
    ) -> dict[str, object]:
        effective_output_root = Path(output_root or "./pipeline_output/platform").resolve()
        database_file = Path(database_path).resolve() if database_path else effective_output_root / "storage" / DEFAULT_DATABASE_NAME
        store = SQLiteIntelligenceStore(database_file)
        store.initialize()

        watched_source = _find_watched_source(
            store.fetch_watched_sources(case_id=case_id, watch_id=watch_id, limit=1),
            watch_id=watch_id,
        )
        if not watched_source:
            return {
                "ok": False,
                "watched_source": {},
                "watcher_state": {},
                "watched_source_summary": store.watched_source_summary(case_id=case_id),
                "watcher_summary": store.watcher_summary(case_id=case_id),
                "artifact_paths": [],
                "warnings": [],
                "errors": [f"unknown watch_id: {watch_id}"],
                "metrics": {
                    "watch_id": watch_id,
                    "database_path": str(database_file.resolve()),
                },
            }

        watcher_state = _find_source_monitor_watcher(store, watched_source)
        if not watcher_state:
            return {
                "ok": False,
                "watched_source": dict(watched_source),
                "watcher_state": {},
                "watched_source_summary": store.watched_source_summary(case_id=case_id),
                "watcher_summary": store.watcher_summary(case_id=case_id),
                "artifact_paths": [],
                "warnings": [],
                "errors": [f"watch source {watch_id} has no source_monitor state yet"],
                "metrics": {
                    "watch_id": watch_id,
                    "database_path": str(database_file.resolve()),
                },
            }

        requested_seconds = max(0.0, float(seconds or 0.0))
        current_remaining_seconds = float(_timestamp_remaining_seconds(str(watcher_state.get("suppression_until") or "")))
        normalized_mode = str(mode or "set").strip().lower()
        if normalized_mode == "clear":
            effective_seconds = 0.0
        elif normalized_mode == "shorten" and current_remaining_seconds > 0.0:
            effective_seconds = min(current_remaining_seconds, requested_seconds or current_remaining_seconds)
        else:
            effective_seconds = requested_seconds
        suppression_until = ""
        if effective_seconds > 0.0:
            suppression_until = _timestamp_after_seconds(utc_now(), seconds=effective_seconds)

        updated_watcher_state = {
            **watcher_state,
            "suppression_until": suppression_until,
            "suppression_seconds": effective_seconds,
            "suppression_reason": "" if effective_seconds <= 0.0 else "manual monitor control",
            "low_signal_change_streak": 0 if effective_seconds <= 0.0 else int(watcher_state.get("low_signal_change_streak") or 0),
        }
        store.persist_watcher_states((updated_watcher_state,))

        audit_path = _append_stage_audit(
            effective_output_root,
            stage="watch_control",
            plugin="monitor_control",
            source_id=str(updated_watcher_state.get("source_id") or watched_source.get("source_id") or ""),
            case_id=str(watched_source.get("case_id") or case_id or ""),
            job_id="",
            ok=True,
            warnings=(),
            errors=(),
            metrics={
                "watch_id": watch_id,
                "mode": normalized_mode,
                "requested_seconds": requested_seconds,
                "effective_seconds": effective_seconds,
                "suppression_until": suppression_until,
            },
            artifact_paths=(),
            details={
                "locator": str(watched_source.get("locator") or ""),
                "source_type": str(watched_source.get("source_type") or ""),
            },
        )
        persisted_watcher_state = _find_source_monitor_watcher(store, watched_source)
        return {
            "ok": True,
            "watched_source": _materialize_watched_source(dict(watched_source)),
            "watcher_state": dict(persisted_watcher_state),
            "watched_source_summary": store.watched_source_summary(case_id=case_id),
            "watcher_summary": store.watcher_summary(case_id=case_id),
            "artifact_paths": [str(audit_path)],
            "warnings": [],
            "errors": [],
            "metrics": {
                "watch_id": watch_id,
                "mode": normalized_mode,
                "requested_seconds": requested_seconds,
                "effective_seconds": effective_seconds,
                "database_path": str(database_file.resolve()),
            },
        }

    def set_watch_source_snooze(
        self,
        *,
        case_id: str = "",
        watch_id: str,
        seconds: float,
        output_root: str | None = None,
        database_path: str | None = None,
        mode: str = "set",
    ) -> dict[str, object]:
        effective_output_root = Path(output_root or "./pipeline_output/platform").resolve()
        database_file = Path(database_path).resolve() if database_path else effective_output_root / "storage" / DEFAULT_DATABASE_NAME
        store = SQLiteIntelligenceStore(database_file)
        store.initialize()

        watched_source = _find_watched_source(
            store.fetch_watched_sources(case_id=case_id, watch_id=watch_id, limit=1),
            watch_id=watch_id,
        )
        if not watched_source:
            return {
                "ok": False,
                "watched_source": {},
                "watcher_state": {},
                "watched_source_summary": store.watched_source_summary(case_id=case_id),
                "watcher_summary": store.watcher_summary(case_id=case_id),
                "artifact_paths": [],
                "warnings": [],
                "errors": [f"unknown watch_id: {watch_id}"],
                "metrics": {
                    "watch_id": watch_id,
                    "database_path": str(database_file.resolve()),
                },
            }

        requested_seconds = max(0.0, float(seconds or 0.0))
        current_remaining_seconds = float(_timestamp_remaining_seconds(str(watched_source.get("snooze_until") or "")))
        normalized_mode = str(mode or "set").strip().lower()
        if normalized_mode == "clear":
            effective_seconds = 0.0
        elif normalized_mode == "shorten" and current_remaining_seconds > 0.0:
            effective_seconds = min(current_remaining_seconds, requested_seconds or current_remaining_seconds)
        else:
            effective_seconds = requested_seconds
        snooze_until = ""
        if effective_seconds > 0.0:
            snooze_until = _timestamp_after_seconds(utc_now(), seconds=effective_seconds)

        updated_watched_source = {
            **watched_source,
            "snooze_until": snooze_until,
            "status": "snoozed" if snooze_until else ("active" if bool(watched_source.get("enabled", True)) else "disabled"),
            "updated_at": utc_now(),
        }
        store.persist_watched_sources((updated_watched_source,))
        watcher_state = _find_source_monitor_watcher(store, updated_watched_source)

        audit_path = _append_stage_audit(
            effective_output_root,
            stage="watch_control",
            plugin="monitor_control",
            source_id=str(watcher_state.get("source_id") or watched_source.get("source_id") or ""),
            case_id=str(updated_watched_source.get("case_id") or case_id or ""),
            job_id="",
            ok=True,
            warnings=(),
            errors=(),
            metrics={
                "watch_id": watch_id,
                "mode": normalized_mode,
                "requested_seconds": requested_seconds,
                "effective_seconds": effective_seconds,
                "snooze_until": snooze_until,
            },
            artifact_paths=(),
            details={
                "locator": str(updated_watched_source.get("locator") or ""),
                "source_type": str(updated_watched_source.get("source_type") or ""),
            },
        )
        persisted = _find_watched_source(
            store.fetch_watched_sources(case_id=case_id, watch_id=watch_id, limit=1),
            watch_id=watch_id,
        )
        return {
            "ok": True,
            "watched_source": _materialize_watched_source(dict(persisted)),
            "watcher_state": dict(_find_source_monitor_watcher(store, persisted)),
            "watched_source_summary": store.watched_source_summary(case_id=case_id),
            "watcher_summary": store.watcher_summary(case_id=case_id),
            "artifact_paths": [str(audit_path)],
            "warnings": [],
            "errors": [],
            "metrics": {
                "watch_id": watch_id,
                "mode": normalized_mode,
                "requested_seconds": requested_seconds,
                "effective_seconds": effective_seconds,
                "database_path": str(database_file.resolve()),
            },
        }

    def update_watch_source_settings(
        self,
        *,
        case_id: str = "",
        watch_id: str,
        poll_interval_seconds: float | None = None,
        notes: str | None = None,
        tags: object = None,
        tuning_preset_name: str | None = None,
        forecast_min_history: int | None = None,
        source_churn_spike_factor: float | None = None,
        suppressed_alert_ids: list[str] | tuple[str, ...] | None = None,
        clear_tuning_profile: bool = False,
        change_origin: str = "manual",
        automation_direction: str = "",
        automation_reason: str = "",
        output_root: str | None = None,
        database_path: str | None = None,
    ) -> dict[str, object]:
        effective_output_root = Path(output_root or "./pipeline_output/platform").resolve()
        database_file = Path(database_path).resolve() if database_path else effective_output_root / "storage" / DEFAULT_DATABASE_NAME
        store = SQLiteIntelligenceStore(database_file)
        store.initialize()

        watched_source = _find_watched_source(
            store.fetch_watched_sources(case_id=case_id, watch_id=watch_id, limit=1),
            watch_id=watch_id,
        )
        if not watched_source:
            return {
                "ok": False,
                "watched_source": {},
                "watcher_state": {},
                "watched_source_summary": store.watched_source_summary(case_id=case_id),
                "watcher_summary": store.watcher_summary(case_id=case_id),
                "artifact_paths": [],
                "warnings": [],
                "errors": [f"unknown watch_id: {watch_id}"],
                "metrics": {
                    "watch_id": watch_id,
                    "database_path": str(database_file.resolve()),
                },
            }

        updated_watched_source = dict(watched_source)
        if poll_interval_seconds is not None:
            updated_watched_source["poll_interval_seconds"] = max(0.0, float(poll_interval_seconds or 0.0))
        if notes is not None:
            updated_watched_source["notes"] = str(notes or "").strip()
        if tags is not None:
            updated_watched_source["tags"] = _normalize_tags(tags)
        current_tuning_profile = _materialize_watch_tuning_profile(updated_watched_source.get("tuning_profile"))
        previous_preset_name = str(
            dict(updated_watched_source.get("tuning_profile") or {}).get("preset_name")
            or updated_watched_source.get("tuning_preset_name")
            or ""
        )
        updated_tuning_profile = default_watch_tuning_profile() if clear_tuning_profile else _watch_tuning_profile_from_updates(
            base_profile=current_tuning_profile,
            preset_name=tuning_preset_name,
            forecast_min_history=forecast_min_history,
            source_churn_spike_factor=source_churn_spike_factor,
            suppressed_alert_ids=suppressed_alert_ids,
        )
        updated_watched_source["tuning_preset_name"] = str(updated_tuning_profile.get("preset_name") or "")
        updated_watched_source["tuning_profile"] = normalize_watch_tuning_profile(updated_tuning_profile)
        updated_at = utc_now()
        updated_watched_source["automation_state"] = _update_preset_automation_state(
            updated_watched_source.get("automation_state"),
            change_origin=change_origin,
            previous_preset_name=previous_preset_name,
            new_preset_name=str(updated_tuning_profile.get("preset_name") or ""),
            changed_at=updated_at,
            automation_direction=automation_direction,
            automation_reason=automation_reason,
        )
        updated_watched_source["updated_at"] = updated_at
        if _timestamp_remaining_seconds(str(updated_watched_source.get("snooze_until") or "")) > 0.0:
            updated_watched_source["status"] = "snoozed"
        else:
            updated_watched_source["status"] = "active" if bool(updated_watched_source.get("enabled", True)) else "disabled"
        store.persist_watched_sources((updated_watched_source,))

        audit_path = _append_stage_audit(
            effective_output_root,
            stage="watch_control",
            plugin="monitor_control",
            source_id=str(watched_source.get("source_id") or ""),
            case_id=str(updated_watched_source.get("case_id") or case_id or ""),
            job_id="",
            ok=True,
            warnings=(),
            errors=(),
            metrics={
                "watch_id": watch_id,
                "poll_interval_seconds": float(updated_watched_source.get("poll_interval_seconds") or 0.0),
                "notes_length": len(str(updated_watched_source.get("notes") or "")),
                "tag_count": len(list(updated_watched_source.get("tags") or [])),
                "watch_profile_preset_name": str(
                    dict(updated_watched_source.get("tuning_profile") or {}).get("preset_name") or ""
                ),
                "watch_profile_change_origin": _normalize_change_origin(change_origin),
                "watch_profile_forecast_min_history": int(
                    dict(updated_watched_source.get("tuning_profile") or {}).get("forecast_min_history") or 0
                ),
                "watch_profile_source_churn_spike_factor": float(
                    dict(updated_watched_source.get("tuning_profile") or {}).get("source_churn_spike_factor") or 0.0
                ),
                "watch_profile_suppressed_alert_count": len(
                    list(dict(updated_watched_source.get("tuning_profile") or {}).get("suppressed_alert_ids") or [])
                ),
            },
            artifact_paths=(),
            details={
                "locator": str(updated_watched_source.get("locator") or ""),
                "source_type": str(updated_watched_source.get("source_type") or ""),
            },
        )
        persisted = _find_watched_source(
            store.fetch_watched_sources(case_id=case_id, watch_id=watch_id, limit=1),
            watch_id=watch_id,
        )
        return {
            "ok": True,
            "watched_source": _materialize_watched_source(dict(persisted)),
            "watcher_state": dict(_find_source_monitor_watcher(store, persisted)),
            "watched_source_summary": store.watched_source_summary(case_id=case_id),
            "watcher_summary": store.watcher_summary(case_id=case_id),
            "artifact_paths": [str(audit_path)],
            "warnings": [],
            "errors": [],
            "metrics": {
                "watch_id": watch_id,
                "database_path": str(database_file.resolve()),
                "poll_interval_seconds": float(persisted.get("poll_interval_seconds") or 0.0),
                "watch_profile_preset_name": str(dict(persisted.get("tuning_profile") or {}).get("preset_name") or ""),
                "watch_profile_manual_override_active": bool(
                    dict(persisted.get("automation_state") or {}).get("manual_override_active")
                ),
                "watch_profile_suppressed_alert_count": len(
                    list(dict(persisted.get("tuning_profile") or {}).get("suppressed_alert_ids") or [])
                ),
            },
        }

    def get_monitor_tuning(
        self,
        *,
        case_id: str = "",
        output_root: str | None = None,
    ) -> dict[str, object]:
        effective_output_root = Path(output_root or "./pipeline_output/platform").resolve()
        tuning = load_monitor_tuning(effective_output_root, case_id=case_id)
        return {
            "ok": True,
            "case_id": str(case_id or "").strip(),
            "tuning": dict(tuning),
            "available_presets": list(monitor_tuning_presets()),
            "available_automation_modes": list(monitor_automation_modes()),
            "artifact_paths": [],
            "warnings": [],
            "errors": [],
            "metrics": {
                "output_root": str(effective_output_root),
                "preset_name": str(tuning.get("preset_name") or ""),
                "automation_mode": str(tuning.get("automation_mode") or ""),
                "manual_override_active": bool(dict(tuning.get("automation_state") or {}).get("manual_override_active")),
                "suppressed_alert_count": len(list(tuning.get("suppressed_alert_ids") or [])),
                "suppressed_stage_count": len(dict(tuning.get("suppressed_stage_alerts") or {})),
                "suppressed_watch_count": len(dict(tuning.get("suppressed_watch_alerts") or {})),
                "alert_severity_override_count": len(dict(tuning.get("alert_severity_overrides") or {})),
                "stage_threshold_override_count": len(dict(tuning.get("stage_threshold_overrides") or {})),
            },
        }

    def update_monitor_tuning(
        self,
        *,
        case_id: str = "",
        output_root: str | None = None,
        preset_name: str | None = None,
        automation_mode: str | None = None,
        change_origin: str = "manual",
        automation_direction: str = "",
        automation_reason: str = "",
        forecast_min_history: int | None = None,
        queue_spike_factor: float | None = None,
        source_churn_spike_factor: float | None = None,
        throughput_drop_factor: float | None = None,
        suppressed_alert_ids: list[str] | tuple[str, ...] | None = None,
        suppressed_stage_alerts: dict[str, list[str] | tuple[str, ...]] | None = None,
        suppressed_watch_alerts: dict[str, list[str] | tuple[str, ...]] | None = None,
        alert_severity_overrides: dict[str, str] | None = None,
        stage_threshold_overrides: dict[str, dict[str, float]] | None = None,
    ) -> dict[str, object]:
        effective_output_root = Path(output_root or "./pipeline_output/platform").resolve()
        previous_tuning = load_monitor_tuning(effective_output_root, case_id=case_id)
        updates: dict[str, object] = {}
        if preset_name is not None and str(preset_name).strip():
            preset_payload = apply_monitor_tuning_preset(str(preset_name).strip(), case_id=case_id)
            updates.update(
                {
                    "preset_name": str(preset_payload.get("preset_name") or ""),
                    "forecast_min_history": int(preset_payload.get("forecast_min_history") or 0),
                    "queue_spike_factor": float(preset_payload.get("queue_spike_factor") or 0.0),
                    "source_churn_spike_factor": float(preset_payload.get("source_churn_spike_factor") or 0.0),
                    "throughput_drop_factor": float(preset_payload.get("throughput_drop_factor") or 0.0),
                }
            )
        if automation_mode is not None and str(automation_mode).strip():
            updates["automation_mode"] = str(automation_mode).strip().lower()
        if forecast_min_history is not None:
            updates["forecast_min_history"] = max(1, int(forecast_min_history))
        if queue_spike_factor is not None:
            updates["queue_spike_factor"] = max(1.0, float(queue_spike_factor))
        if source_churn_spike_factor is not None:
            updates["source_churn_spike_factor"] = max(1.0, float(source_churn_spike_factor))
        if throughput_drop_factor is not None:
            updates["throughput_drop_factor"] = min(1.0, max(0.1, float(throughput_drop_factor)))
        if suppressed_alert_ids is not None:
            updates["suppressed_alert_ids"] = [str(item).strip() for item in list(suppressed_alert_ids) if str(item).strip()]
        if suppressed_stage_alerts is not None:
            updates["suppressed_stage_alerts"] = {
                str(stage).strip(): [str(item).strip() for item in list(alerts) if str(item).strip()]
                for stage, alerts in dict(suppressed_stage_alerts).items()
                if str(stage).strip()
            }
        if suppressed_watch_alerts is not None:
            updates["suppressed_watch_alerts"] = {
                str(watch_id).strip(): [str(item).strip() for item in list(alerts) if str(item).strip()]
                for watch_id, alerts in dict(suppressed_watch_alerts).items()
                if str(watch_id).strip()
            }
        if alert_severity_overrides is not None:
            updates["alert_severity_overrides"] = {
                str(alert_id).strip(): str(severity).strip().lower()
                for alert_id, severity in dict(alert_severity_overrides).items()
                if str(alert_id).strip() and str(severity).strip()
            }
        if stage_threshold_overrides is not None:
            updates["stage_threshold_overrides"] = {
                str(stage).strip(): {
                    str(key).strip(): float(value)
                    for key, value in dict(thresholds or {}).items()
                    if str(key).strip()
                }
                for stage, thresholds in dict(stage_threshold_overrides).items()
                if str(stage).strip()
            }

        next_preset_name = str(
            updates.get("preset_name")
            or previous_tuning.get("preset_name")
            or ""
        ).strip()
        updates["automation_state"] = _update_preset_automation_state(
            previous_tuning.get("automation_state"),
            change_origin=change_origin,
            previous_preset_name=str(previous_tuning.get("preset_name") or ""),
            new_preset_name=next_preset_name,
            changed_at=utc_now(),
            automation_direction=automation_direction,
            automation_reason=automation_reason,
        )

        tuning = persist_monitor_tuning(
            effective_output_root,
            case_id=case_id,
            updates=updates,
        )
        audit_path = _append_stage_audit(
            effective_output_root,
            stage="monitor_tuning",
            plugin="monitor_control",
            source_id="",
            case_id=str(case_id or ""),
            job_id="",
            ok=True,
            warnings=(),
            errors=(),
            metrics={
                "change_origin": _normalize_change_origin(change_origin),
                "automation_mode": str(tuning.get("automation_mode") or ""),
                "forecast_min_history": int(tuning.get("forecast_min_history") or 0),
                "queue_spike_factor": float(tuning.get("queue_spike_factor") or 0.0),
                "source_churn_spike_factor": float(tuning.get("source_churn_spike_factor") or 0.0),
                "throughput_drop_factor": float(tuning.get("throughput_drop_factor") or 0.0),
                "suppressed_alert_count": len(list(tuning.get("suppressed_alert_ids") or [])),
                "suppressed_stage_count": len(dict(tuning.get("suppressed_stage_alerts") or {})),
                "suppressed_watch_count": len(dict(tuning.get("suppressed_watch_alerts") or {})),
                "alert_severity_override_count": len(dict(tuning.get("alert_severity_overrides") or {})),
                "stage_threshold_override_count": len(dict(tuning.get("stage_threshold_overrides") or {})),
            },
            artifact_paths=(),
            details={
                "updates": updates,
                "tuning": tuning,
            },
        )
        return {
            "ok": True,
            "case_id": str(case_id or "").strip(),
            "tuning": dict(tuning),
            "available_presets": list(monitor_tuning_presets()),
            "available_automation_modes": list(monitor_automation_modes()),
            "artifact_paths": [str(audit_path)],
            "warnings": [],
            "errors": [],
            "metrics": {
                "output_root": str(effective_output_root),
                "preset_name": str(tuning.get("preset_name") or ""),
                "automation_mode": str(tuning.get("automation_mode") or ""),
                "manual_override_active": bool(dict(tuning.get("automation_state") or {}).get("manual_override_active")),
                "suppressed_alert_count": len(list(tuning.get("suppressed_alert_ids") or [])),
                "suppressed_stage_count": len(dict(tuning.get("suppressed_stage_alerts") or {})),
                "suppressed_watch_count": len(dict(tuning.get("suppressed_watch_alerts") or {})),
                "alert_severity_override_count": len(dict(tuning.get("alert_severity_overrides") or {})),
                "stage_threshold_override_count": len(dict(tuning.get("stage_threshold_overrides") or {})),
            },
        }

    def run_pipeline(
        self,
        request: IngestRequest,
        *,
        case_id: str = "",
        output_root: str | None = None,
        workspace_root: str | None = None,
        database_path: str | None = None,
        config: dict[str, object] | None = None,
    ) -> PluginResult:
        ingest_result = self.ingest(
            request,
            case_id=case_id,
            output_root=output_root,
            workspace_root=workspace_root,
            config=config,
        )
        if not ingest_result.ok:
            return ingest_result

        manifest_path = next((path for path in ingest_result.artifact_paths if path.endswith("source_manifest.json")), "")
        if not manifest_path:
            return PluginResult(
                records=ingest_result.records,
                artifact_paths=ingest_result.artifact_paths,
                errors=("ingest stage did not produce a source manifest",),
                metrics=dict(ingest_result.metrics),
            )

        extract_result = self.extract(
            manifest_path,
            case_id=case_id,
            output_root=output_root,
            workspace_root=workspace_root,
            config=config,
        )
        if not extract_result.ok:
            return _merge_stage_results(ingest_result, extract_result)

        extract_report_path = next((path for path in extract_result.artifact_paths if path.endswith("extract_report.json")), "")
        recover_result = self.recover(
            extract_report_path,
            case_id=case_id,
            output_root=output_root,
            workspace_root=workspace_root,
            config=config,
        )
        if not recover_result.ok:
            return _merge_stage_results(ingest_result, extract_result, recover_result)

        recover_report_path = next((path for path in recover_result.artifact_paths if path.endswith("recover_report.json")), "")
        normalize_result = self.normalize(
            recover_report_path or extract_report_path,
            case_id=case_id,
            output_root=output_root,
            workspace_root=workspace_root,
            config=config,
        )
        if not normalize_result.ok:
            return _merge_stage_results(ingest_result, extract_result, recover_result, normalize_result)

        normalize_report_path = next((path for path in normalize_result.artifact_paths if path.endswith("normalize_report.json")), "")
        correlate_result = self.correlate(
            normalize_report_path,
            case_id=case_id,
            output_root=output_root,
            workspace_root=workspace_root,
            config=config,
        )
        if not correlate_result.ok:
            return _merge_stage_results(ingest_result, extract_result, recover_result, normalize_result, correlate_result)

        correlation_report_path = next((path for path in correlate_result.artifact_paths if path.endswith("correlation_report.json")), "")
        store_result = self.store(
            correlation_report_path,
            case_id=case_id,
            output_root=output_root,
            workspace_root=workspace_root,
            database_path=database_path,
            config=config,
        )
        if not store_result.ok:
            return _merge_stage_results(ingest_result, extract_result, recover_result, normalize_result, correlate_result, store_result)

        store_report_path = next((path for path in store_result.artifact_paths if path.endswith("store_report.json")), "")
        present_result = self.present(
            store_report_path,
            case_id=case_id,
            output_root=output_root,
            workspace_root=workspace_root,
            database_path=database_path,
            config=config,
        )
        return _merge_stage_results(
            ingest_result,
            extract_result,
            recover_result,
            normalize_result,
            correlate_result,
            store_result,
            present_result,
        )

    def _run_single_queued_job(
        self,
        *,
        stage: str,
        queue_payload: dict[str, object],
        output_root: Path,
        workspace_root: Path,
        database_path: str | None,
        config: dict[str, object] | None,
        case_id: str,
    ) -> PluginResult:
        requested_case_id = str(case_id or "").strip()
        job_payload = queue_payload.get("job")
        source_payload = queue_payload.get("source")
        queued_case_id = str(
            (job_payload.get("case_id") if isinstance(job_payload, dict) else "")
            or (source_payload.get("case_id") if isinstance(source_payload, dict) else "")
            or ""
        ).strip()
        effective_case_id = requested_case_id or queued_case_id

        if stage == "extract":
            manifest_path = str(queue_payload.get("source_manifest_path") or "").strip()
            if not manifest_path:
                source_id = str(
                    (source_payload.get("id") if isinstance(source_payload, dict) else "")
                    or (source_payload.get("source_id") if isinstance(source_payload, dict) else "")
                    or ""
                ).strip()
                job_id = str((job_payload.get("id") if isinstance(job_payload, dict) else "") or "").strip()
                if source_id and job_id:
                    manifest_path = str((output_root / "intake" / source_id / job_id / "source_manifest.json").resolve())
            if not manifest_path:
                return PluginResult(errors=("extract queue payload did not contain a source manifest path",))
            return self.extract(
                manifest_path,
                case_id=effective_case_id,
                output_root=str(output_root),
                workspace_root=str(workspace_root),
                config=config,
            )
        if stage == "recover":
            report_path = str(queue_payload.get("extract_report_path") or "").strip()
            if not report_path:
                return PluginResult(errors=("recover queue payload did not contain an extract_report_path",))
            return self.recover(
                report_path,
                case_id=effective_case_id,
                output_root=str(output_root),
                workspace_root=str(workspace_root),
                config=config,
            )
        if stage == "normalize":
            report_path = str(
                queue_payload.get("recover_report_path")
                or queue_payload.get("extract_report_path")
                or ""
            ).strip()
            if not report_path:
                return PluginResult(errors=("normalize queue payload did not contain a recover_report_path",))
            return self.normalize(
                report_path,
                case_id=effective_case_id,
                output_root=str(output_root),
                workspace_root=str(workspace_root),
                config=config,
            )
        if stage == "correlate":
            report_path = str(queue_payload.get("normalize_report_path") or "").strip()
            if not report_path:
                return PluginResult(errors=("correlate queue payload did not contain a normalize_report_path",))
            return self.correlate(
                report_path,
                case_id=effective_case_id,
                output_root=str(output_root),
                workspace_root=str(workspace_root),
                config=config,
            )
        if stage == "store":
            report_path = str(queue_payload.get("correlation_report_path") or "").strip()
            if not report_path:
                return PluginResult(errors=("store queue payload did not contain a correlation_report_path",))
            return self.store(
                report_path,
                case_id=effective_case_id,
                output_root=str(output_root),
                workspace_root=str(workspace_root),
                database_path=database_path,
                config=config,
            )
        if stage == "present":
            report_path = str(queue_payload.get("store_report_path") or "").strip()
            queued_database_path = str(queue_payload.get("database_path") or "").strip()
            if not report_path:
                return PluginResult(errors=("present queue payload did not contain a store_report_path",))
            return self.present(
                report_path,
                case_id=effective_case_id,
                output_root=str(output_root),
                workspace_root=str(workspace_root),
                database_path=database_path or queued_database_path or None,
                config=config,
            )
        return PluginResult(errors=(f"unsupported queue stage: {stage}",))

    def extract(
        self,
        manifest_path: str,
        *,
        case_id: str = "",
        output_root: str | None = None,
        workspace_root: str | None = None,
        config: dict[str, object] | None = None,
    ) -> PluginResult:
        source, artifacts, queued_extract_job, source_manifest_path = _load_source_manifest(Path(manifest_path))
        effective_case_id = case_id or source.case_id
        effective_output_root = Path(output_root).resolve() if output_root else _derive_output_root(source_manifest_path, stage_dir="intake")
        effective_workspace_root = Path(workspace_root).resolve() if workspace_root else Path(".").resolve()
        ensure_workspace_layout(effective_output_root)
        context = PluginExecutionContext(
            case_id=effective_case_id,
            output_root=effective_output_root,
            workspace_root=effective_workspace_root,
            config=dict(config or {}),
        )

        extracted_records: list[RecordBase] = []
        artifact_paths: list[str] = []
        warnings: list[str] = []
        errors: list[str] = []
        metrics = {
            "artifact_count": len(artifacts),
            "extractor_count": 0,
            "record_count": 0,
        }
        extractor_runs: list[dict[str, object]] = []

        for artifact in artifacts:
            for manifest, _registered, _enabled in self._effective_plugin_rows(
                output_root=effective_output_root,
                plugin_type="extractor",
                enabled_only=True,
            ):
                if not _extractor_accepts(tuple(manifest.input_types), artifact):
                    continue
                extractor = self.registry.create(manifest.name)
                result = extractor.extract(context, artifact)
                metrics["extractor_count"] += 1
                extractor_runs.append(
                    {
                        "extractor": manifest.name,
                        "artifact_id": artifact.id,
                        "ok": result.ok,
                        "record_count": len(result.records),
                        "artifact_path_count": len(result.artifact_paths),
                    }
                )
                extracted_records.extend(result.records)
                artifact_paths.extend(result.artifact_paths)
                warnings.extend(result.warnings)
                errors.extend(result.errors)

        metrics["record_count"] = len(extracted_records)
        extract_job_id = queued_extract_job.id if queued_extract_job else stable_record_id("job", source.id, "extract", "completed")
        recover_job_id = stable_record_id("job", source.id, "recover", "queued")
        extract_status = "completed" if not errors else "completed_with_errors"

        completed_extract_job = JobRecord(
            id=extract_job_id,
            source_id=source.source_id,
            case_id=effective_case_id,
            job_type="pipeline-stage",
            stage="extract",
            status=extract_status,
            input_refs=tuple(artifact.id for artifact in artifacts),
            output_refs=tuple(record.id for record in extracted_records),
            worker="platform_extract",
            started_at=queued_extract_job.created_at if queued_extract_job else "",
            finished_at=utc_now(),
            provenance=Provenance(
                plugin="platform_extract",
                method="run_extractors",
                source_refs=(source.id,),
                parent_refs=tuple(artifact.id for artifact in artifacts),
            ),
            confidence=Confidence(score=1.0 if not errors else 0.7),
            tags=("job", "extract", extract_status),
            attributes={
                "extractor_count": str(metrics["extractor_count"]),
                "record_count": str(metrics["record_count"]),
            },
        )

        recover_job = JobRecord(
            id=recover_job_id,
            source_id=source.source_id,
            case_id=effective_case_id,
            job_type="pipeline-stage",
            stage="recover",
            status="queued",
            input_refs=tuple(record.id for record in extracted_records),
            output_refs=(),
            worker="platform_extract",
            provenance=Provenance(
                plugin="platform_extract",
                method="queue_recover",
                source_refs=(source.id,),
                parent_refs=(completed_extract_job.id,),
            ),
            confidence=Confidence(score=1.0),
            tags=("job", "recover", "queued"),
            attributes={
                "input_record_count": str(len(extracted_records)),
                "source_manifest": str(source_manifest_path),
            },
        )

        report_dir = effective_output_root / "extract" / source.id / extract_job_id
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "extract_report.json"

        report_payload = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "source_manifest_path": str(source_manifest_path),
            "source": record_to_dict(source),
            "input_artifacts": [record_to_dict(artifact) for artifact in artifacts],
            "extractor_runs": extractor_runs,
            "extracted_records": [record_to_dict(record) for record in extracted_records],
            "completed_extract_job": record_to_dict(completed_extract_job),
            "queued_recover_job": record_to_dict(recover_job),
            "warnings": warnings,
            "errors": errors,
            "metrics": metrics,
        }
        report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")

        recover_queue_dir = effective_output_root / "queues" / "recover"
        recover_queue_dir.mkdir(parents=True, exist_ok=True)
        recover_queue_path = recover_queue_dir / f"{recover_job.id}.json"

        queue_payload = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "job": record_to_dict(recover_job),
            "source": record_to_dict(source),
            "record_refs": [record.id for record in extracted_records],
            "extract_report_path": str(report_path),
        }
        recover_queue_path.write_text(json.dumps(queue_payload, indent=2), encoding="utf-8")
        audit_path = _append_stage_audit(
            effective_output_root,
            stage="extract",
            plugin="platform_extract",
            source_id=source.id,
            case_id=effective_case_id,
            job_id=extract_job_id,
            ok=not errors,
            warnings=warnings,
            errors=errors,
            metrics=metrics,
            artifact_paths=(str(report_path), str(recover_queue_path), *artifact_paths),
            details={"extractor_runs": extractor_runs},
        )

        return PluginResult(
            records=(*extracted_records, completed_extract_job, recover_job),
            artifact_paths=(str(report_path), str(recover_queue_path), *artifact_paths, str(audit_path)),
            warnings=tuple(warnings),
            errors=tuple(errors),
            metrics={
                **metrics,
                "extract_job_id": extract_job_id,
                "recover_job_id": recover_job_id,
                "source_id": source.id,
            },
        )

    def recover(
        self,
        extract_report_path: str,
        *,
        case_id: str = "",
        output_root: str | None = None,
        workspace_root: str | None = None,
        config: dict[str, object] | None = None,
    ) -> PluginResult:
        source, input_artifacts, extracted_records, queued_recover_job, report_path = _load_extract_report(Path(extract_report_path))
        effective_case_id = case_id or source.case_id
        effective_output_root = Path(output_root).resolve() if output_root else _derive_output_root(report_path, stage_dir="extract")
        effective_workspace_root = Path(workspace_root).resolve() if workspace_root else Path(".").resolve()
        ensure_workspace_layout(effective_output_root)
        context = PluginExecutionContext(
            case_id=effective_case_id,
            output_root=effective_output_root,
            workspace_root=effective_workspace_root,
            config=dict(config or {}),
        )

        recovery_artifacts = _collect_artifact_records(input_artifacts, extracted_records)
        recovered_records: list[RecordBase] = []
        recovered_extracted_records: list[RecordBase] = []
        artifact_paths: list[str] = []
        warnings: list[str] = []
        errors: list[str] = []
        recovery_runs: list[dict[str, object]] = []
        extractor_runs: list[dict[str, object]] = []

        for artifact in recovery_artifacts:
            for manifest, _registered, _enabled in self._effective_plugin_rows(
                output_root=effective_output_root,
                plugin_type="recovery",
                enabled_only=True,
            ):
                if not _artifact_accepts(tuple(manifest.input_types), artifact):
                    continue
                recoverer = self.registry.create(manifest.name)
                result = recoverer.recover(context, artifact)
                recovery_runs.append(
                    {
                        "recoverer": manifest.name,
                        "artifact_id": artifact.id,
                        "ok": result.ok,
                        "record_count": len(result.records),
                        "artifact_path_count": len(result.artifact_paths),
                    }
                )
                recovered_records.extend(result.records)
                artifact_paths.extend(result.artifact_paths)
                warnings.extend(result.warnings)
                errors.extend(result.errors)

        recovered_artifacts = [record for record in recovered_records if isinstance(record, ArtifactRecord)]
        for artifact in recovered_artifacts:
            for manifest, _registered, _enabled in self._effective_plugin_rows(
                output_root=effective_output_root,
                plugin_type="extractor",
                enabled_only=True,
            ):
                if not _artifact_accepts(tuple(manifest.input_types), artifact):
                    continue
                extractor = self.registry.create(manifest.name)
                result = extractor.extract(context, artifact)
                extractor_runs.append(
                    {
                        "extractor": manifest.name,
                        "artifact_id": artifact.id,
                        "ok": result.ok,
                        "record_count": len(result.records),
                        "artifact_path_count": len(result.artifact_paths),
                    }
                )
                recovered_extracted_records.extend(result.records)
                artifact_paths.extend(result.artifact_paths)
                warnings.extend(result.warnings)
                errors.extend(result.errors)

        combined_records = _dedupe_records_by_id([*extracted_records, *recovered_records, *recovered_extracted_records])
        recover_job_id = queued_recover_job.id if queued_recover_job else stable_record_id("job", source.id, "recover", "completed")
        normalize_job_id = stable_record_id("job", source.id, "normalize", "queued")
        recover_status = "completed" if not errors else "completed_with_errors"

        completed_recover_job = JobRecord(
            id=recover_job_id,
            source_id=source.source_id,
            case_id=effective_case_id,
            job_type="pipeline-stage",
            stage="recover",
            status=recover_status,
            input_refs=tuple(record.id for record in extracted_records),
            output_refs=tuple(record.id for record in combined_records),
            worker="platform_recover",
            started_at=queued_recover_job.created_at if queued_recover_job else "",
            finished_at=utc_now(),
            provenance=Provenance(
                plugin="platform_recover",
                method="run_recoverers",
                source_refs=(source.id,),
                parent_refs=tuple(artifact.id for artifact in recovery_artifacts),
            ),
            confidence=Confidence(score=1.0 if not errors else 0.7),
            tags=("job", "recover", recover_status),
            attributes={
                "recoverer_count": str(len(recovery_runs)),
                "recovered_record_count": str(len(recovered_records)),
                "recovered_extracted_record_count": str(len(recovered_extracted_records)),
            },
        )

        normalize_job = JobRecord(
            id=normalize_job_id,
            source_id=source.source_id,
            case_id=effective_case_id,
            job_type="pipeline-stage",
            stage="normalize",
            status="queued",
            input_refs=tuple(record.id for record in combined_records),
            output_refs=(),
            worker="platform_recover",
            provenance=Provenance(
                plugin="platform_recover",
                method="queue_normalize",
                source_refs=(source.id,),
                parent_refs=(completed_recover_job.id,),
            ),
            confidence=Confidence(score=1.0),
            tags=("job", "normalize", "queued"),
            attributes={
                "input_record_count": str(len(combined_records)),
                "extract_report_path": str(report_path),
            },
        )

        recover_dir = effective_output_root / "recover" / source.id / recover_job_id
        recover_dir.mkdir(parents=True, exist_ok=True)
        recover_report_path = recover_dir / "recover_report.json"
        normalize_queue_dir = effective_output_root / "queues" / "normalize"
        normalize_queue_dir.mkdir(parents=True, exist_ok=True)
        normalize_queue_path = normalize_queue_dir / f"{normalize_job.id}.json"

        recover_report = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "extract_report_path": str(report_path),
            "source": record_to_dict(source),
            "input_artifacts": [record_to_dict(artifact) for artifact in input_artifacts],
            "input_records": [record_to_dict(record) for record in extracted_records],
            "recovery_runs": recovery_runs,
            "recovered_records": [record_to_dict(record) for record in recovered_records],
            "recovered_extractor_runs": extractor_runs,
            "recovered_extracted_records": [record_to_dict(record) for record in recovered_extracted_records],
            "all_records": [record_to_dict(record) for record in combined_records],
            "completed_recover_job": record_to_dict(completed_recover_job),
            "queued_normalize_job": record_to_dict(normalize_job),
            "warnings": warnings,
            "errors": errors,
            "metrics": {
                "input_record_count": len(extracted_records),
                "recoverer_count": len(recovery_runs),
                "recovered_artifact_count": len(recovered_artifacts),
                "recovered_record_count": len(recovered_records),
                "recovered_extracted_record_count": len(recovered_extracted_records),
                "all_record_count": len(combined_records),
            },
        }
        recover_report_path.write_text(json.dumps(recover_report, indent=2), encoding="utf-8")

        normalize_queue = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "job": record_to_dict(normalize_job),
            "source": record_to_dict(source),
            "record_refs": [record.id for record in combined_records],
            "recover_report_path": str(recover_report_path),
        }
        normalize_queue_path.write_text(json.dumps(normalize_queue, indent=2), encoding="utf-8")
        audit_path = _append_stage_audit(
            effective_output_root,
            stage="recover",
            plugin="platform_recover",
            source_id=source.id,
            case_id=effective_case_id,
            job_id=recover_job_id,
            ok=not errors,
            warnings=warnings,
            errors=errors,
            metrics=recover_report["metrics"],
            artifact_paths=(str(recover_report_path), str(normalize_queue_path), *artifact_paths),
            details={"recovery_runs": recovery_runs, "recovered_extractor_runs": extractor_runs},
        )

        return PluginResult(
            records=(*recovered_records, *recovered_extracted_records, completed_recover_job, normalize_job),
            artifact_paths=(str(recover_report_path), str(normalize_queue_path), *artifact_paths, str(audit_path)),
            warnings=tuple(warnings),
            errors=tuple(errors),
            metrics={
                **recover_report["metrics"],
                "recover_job_id": recover_job_id,
                "normalize_job_id": normalize_job_id,
                "source_id": source.id,
            },
        )

    def normalize(
        self,
        report_input_path: str,
        *,
        case_id: str = "",
        output_root: str | None = None,
        workspace_root: str | None = None,
        config: dict[str, object] | None = None,
    ) -> PluginResult:
        source, input_artifacts, pre_normalize_records, queued_normalize_job, report_path, upstream_stage = _load_pre_normalize_report(Path(report_input_path))
        effective_case_id = case_id or source.case_id
        effective_output_root = Path(output_root).resolve() if output_root else _derive_output_root(report_path, stage_dir=upstream_stage)
        effective_workspace_root = Path(workspace_root).resolve() if workspace_root else Path(".").resolve()
        ensure_workspace_layout(effective_output_root)
        context = PluginExecutionContext(
            case_id=effective_case_id,
            output_root=effective_output_root,
            workspace_root=effective_workspace_root,
            config=dict(config or {}),
        )

        current_records = list(pre_normalize_records)
        artifact_paths: list[str] = []
        warnings: list[str] = []
        errors: list[str] = []
        normalizer_runs: list[dict[str, object]] = []

        for manifest, _registered, _enabled in self._effective_plugin_rows(
            output_root=effective_output_root,
            plugin_type="normalizer",
            enabled_only=True,
        ):
            normalizer = self.registry.create(manifest.name)
            result = normalizer.normalize(context, current_records)
            normalizer_runs.append(
                {
                    "normalizer": manifest.name,
                    "ok": result.ok,
                    "record_count": len(result.records),
                    "artifact_path_count": len(result.artifact_paths),
                }
            )
            current_records = list(result.records)
            artifact_paths.extend(result.artifact_paths)
            warnings.extend(result.warnings)
            errors.extend(result.errors)

        normalize_job_id = queued_normalize_job.id if queued_normalize_job else stable_record_id("job", source.id, "normalize", "completed")
        correlate_job_id = stable_record_id("job", source.id, "correlate", "queued")
        normalize_status = "completed" if not errors else "completed_with_errors"

        completed_normalize_job = JobRecord(
            id=normalize_job_id,
            source_id=source.source_id,
            case_id=effective_case_id,
            job_type="pipeline-stage",
            stage="normalize",
            status=normalize_status,
            input_refs=tuple(record.id for record in pre_normalize_records),
            output_refs=tuple(record.id for record in current_records),
            worker="platform_normalize",
            started_at=queued_normalize_job.created_at if queued_normalize_job else "",
            finished_at=utc_now(),
            provenance=Provenance(
                plugin="platform_normalize",
                method="run_normalizers",
                source_refs=(source.id,),
                parent_refs=tuple(record.id for record in pre_normalize_records),
            ),
            confidence=Confidence(score=1.0 if not errors else 0.7),
            tags=("job", "normalize", normalize_status),
            attributes={
                "normalizer_count": str(len(normalizer_runs)),
                "record_count": str(len(current_records)),
            },
        )

        correlate_job = JobRecord(
            id=correlate_job_id,
            source_id=source.source_id,
            case_id=effective_case_id,
            job_type="pipeline-stage",
            stage="correlate",
            status="queued",
            input_refs=tuple(record.id for record in current_records),
            output_refs=(),
            worker="platform_normalize",
            provenance=Provenance(
                plugin="platform_normalize",
                method="queue_correlate",
                source_refs=(source.id,),
                parent_refs=(completed_normalize_job.id,),
            ),
            confidence=Confidence(score=1.0),
            tags=("job", "correlate", "queued"),
            attributes={
                "input_record_count": str(len(current_records)),
                "upstream_report_path": str(report_path),
            },
        )

        normalize_dir = effective_output_root / "normalize" / source.id / normalize_job_id
        normalize_dir.mkdir(parents=True, exist_ok=True)
        normalize_report_path = normalize_dir / "normalize_report.json"
        correlate_queue_dir = effective_output_root / "queues" / "correlate"
        correlate_queue_dir.mkdir(parents=True, exist_ok=True)
        correlate_queue_path = correlate_queue_dir / f"{correlate_job.id}.json"

        normalize_report = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "input_report_path": str(report_path),
            "source": record_to_dict(source),
            "input_artifacts": [record_to_dict(artifact) for artifact in input_artifacts],
            "input_records": [record_to_dict(record) for record in pre_normalize_records],
            "normalizer_runs": normalizer_runs,
            "normalized_records": [record_to_dict(record) for record in current_records],
            "completed_normalize_job": record_to_dict(completed_normalize_job),
            "queued_correlate_job": record_to_dict(correlate_job),
            "warnings": warnings,
            "errors": errors,
            "metrics": {
                "input_record_count": len(pre_normalize_records),
                "normalized_record_count": len(current_records),
                "normalizer_count": len(normalizer_runs),
            },
        }
        if upstream_stage == "recover":
            normalize_report["recover_report_path"] = str(report_path)
        else:
            normalize_report["extract_report_path"] = str(report_path)
        normalize_report_path.write_text(json.dumps(normalize_report, indent=2), encoding="utf-8")

        correlate_queue = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "job": record_to_dict(correlate_job),
            "source": record_to_dict(source),
            "record_refs": [record.id for record in current_records],
            "normalize_report_path": str(normalize_report_path),
        }
        correlate_queue_path.write_text(json.dumps(correlate_queue, indent=2), encoding="utf-8")
        audit_path = _append_stage_audit(
            effective_output_root,
            stage="normalize",
            plugin="platform_normalize",
            source_id=source.id,
            case_id=effective_case_id,
            job_id=normalize_job_id,
            ok=not errors,
            warnings=warnings,
            errors=errors,
            metrics=normalize_report["metrics"],
            artifact_paths=(str(normalize_report_path), str(correlate_queue_path), *artifact_paths),
            details={"normalizer_runs": normalizer_runs},
        )

        return PluginResult(
            records=(*current_records, completed_normalize_job, correlate_job),
            artifact_paths=(str(normalize_report_path), str(correlate_queue_path), *artifact_paths, str(audit_path)),
            warnings=tuple(warnings),
            errors=tuple(errors),
            metrics={
                "input_record_count": len(pre_normalize_records),
                "normalized_record_count": len(current_records),
                "normalizer_count": len(normalizer_runs),
                "normalize_job_id": normalize_job_id,
                "correlate_job_id": correlate_job_id,
                "source_id": source.id,
            },
        )

    def correlate(
        self,
        normalize_report_path: str,
        *,
        case_id: str = "",
        output_root: str | None = None,
        workspace_root: str | None = None,
        config: dict[str, object] | None = None,
    ) -> PluginResult:
        source, input_artifacts, normalized_records, queued_correlate_job, report_path = _load_normalize_report(Path(normalize_report_path))
        effective_case_id = case_id or source.case_id
        effective_output_root = Path(output_root).resolve() if output_root else _derive_output_root(report_path, stage_dir="normalize")
        effective_workspace_root = Path(workspace_root).resolve() if workspace_root else Path(".").resolve()
        ensure_workspace_layout(effective_output_root)
        context = PluginExecutionContext(
            case_id=effective_case_id,
            output_root=effective_output_root,
            workspace_root=effective_workspace_root,
            config=dict(config or {}),
        )

        current_records = list(normalized_records)
        artifact_paths: list[str] = []
        warnings: list[str] = []
        errors: list[str] = []
        correlator_runs: list[dict[str, object]] = []

        for manifest, _registered, _enabled in self._effective_plugin_rows(
            output_root=effective_output_root,
            plugin_type="correlator",
            enabled_only=True,
        ):
            correlator = self.registry.create(manifest.name)
            result = correlator.correlate(context, current_records)
            correlator_runs.append(
                {
                    "correlator": manifest.name,
                    "ok": result.ok,
                    "record_count": len(result.records),
                    "artifact_path_count": len(result.artifact_paths),
                }
            )
            current_records = list(result.records)
            artifact_paths.extend(result.artifact_paths)
            warnings.extend(result.warnings)
            errors.extend(result.errors)

        correlate_job_id = queued_correlate_job.id if queued_correlate_job else stable_record_id("job", source.id, "correlate", "completed")
        store_job_id = stable_record_id("job", source.id, "store", "queued")
        correlate_status = "completed" if not errors else "completed_with_errors"

        completed_correlate_job = JobRecord(
            id=correlate_job_id,
            source_id=source.source_id,
            case_id=effective_case_id,
            job_type="pipeline-stage",
            stage="correlate",
            status=correlate_status,
            input_refs=tuple(record.id for record in normalized_records),
            output_refs=tuple(record.id for record in current_records),
            worker="platform_correlate",
            started_at=queued_correlate_job.created_at if queued_correlate_job else "",
            finished_at=utc_now(),
            provenance=Provenance(
                plugin="platform_correlate",
                method="run_correlators",
                source_refs=(source.id,),
                parent_refs=tuple(record.id for record in normalized_records),
            ),
            confidence=Confidence(score=1.0 if not errors else 0.7),
            tags=("job", "correlate", correlate_status),
            attributes={
                "correlator_count": str(len(correlator_runs)),
                "record_count": str(len(current_records)),
            },
        )

        store_job = JobRecord(
            id=store_job_id,
            source_id=source.source_id,
            case_id=effective_case_id,
            job_type="pipeline-stage",
            stage="store",
            status="queued",
            input_refs=tuple(record.id for record in current_records),
            output_refs=(),
            worker="platform_correlate",
            provenance=Provenance(
                plugin="platform_correlate",
                method="queue_store",
                source_refs=(source.id,),
                parent_refs=(completed_correlate_job.id,),
            ),
            confidence=Confidence(score=1.0),
            tags=("job", "store", "queued"),
            attributes={
                "input_record_count": str(len(current_records)),
                "normalize_report_path": str(report_path),
            },
        )

        correlate_dir = effective_output_root / "correlate" / source.id / correlate_job_id
        correlate_dir.mkdir(parents=True, exist_ok=True)
        correlation_report_path = correlate_dir / "correlation_report.json"
        store_queue_dir = effective_output_root / "queues" / "store"
        store_queue_dir.mkdir(parents=True, exist_ok=True)
        store_queue_path = store_queue_dir / f"{store_job.id}.json"

        correlation_report = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "normalize_report_path": str(report_path),
            "source": record_to_dict(source),
            "input_artifacts": [record_to_dict(artifact) for artifact in input_artifacts],
            "input_records": [record_to_dict(record) for record in normalized_records],
            "correlator_runs": correlator_runs,
            "correlated_records": [record_to_dict(record) for record in current_records],
            "completed_correlate_job": record_to_dict(completed_correlate_job),
            "queued_store_job": record_to_dict(store_job),
            "warnings": warnings,
            "errors": errors,
            "metrics": {
                "input_record_count": len(normalized_records),
                "correlated_record_count": len(current_records),
                "correlator_count": len(correlator_runs),
            },
        }
        correlation_report_path.write_text(json.dumps(correlation_report, indent=2), encoding="utf-8")

        store_queue = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "job": record_to_dict(store_job),
            "source": record_to_dict(source),
            "record_refs": [record.id for record in current_records],
            "correlation_report_path": str(correlation_report_path),
        }
        store_queue_path.write_text(json.dumps(store_queue, indent=2), encoding="utf-8")
        audit_path = _append_stage_audit(
            effective_output_root,
            stage="correlate",
            plugin="platform_correlate",
            source_id=source.id,
            case_id=effective_case_id,
            job_id=correlate_job_id,
            ok=not errors,
            warnings=warnings,
            errors=errors,
            metrics=correlation_report["metrics"],
            artifact_paths=(str(correlation_report_path), str(store_queue_path), *artifact_paths),
            details={"correlator_runs": correlator_runs},
        )

        return PluginResult(
            records=(*current_records, completed_correlate_job, store_job),
            artifact_paths=(str(correlation_report_path), str(store_queue_path), *artifact_paths, str(audit_path)),
            warnings=tuple(warnings),
            errors=tuple(errors),
            metrics={
                "input_record_count": len(normalized_records),
                "correlated_record_count": len(current_records),
                "correlator_count": len(correlator_runs),
                "correlate_job_id": correlate_job_id,
                "store_job_id": store_job_id,
                "source_id": source.id,
            },
        )

    def store(
        self,
        correlation_report_path: str,
        *,
        case_id: str = "",
        output_root: str | None = None,
        workspace_root: str | None = None,
        database_path: str | None = None,
        config: dict[str, object] | None = None,
    ) -> PluginResult:
        source, input_artifacts, correlated_records, completed_correlate_job, queued_store_job, report_path = _load_correlation_report(Path(correlation_report_path))
        effective_case_id = case_id or source.case_id
        effective_output_root = Path(output_root).resolve() if output_root else _derive_output_root(report_path, stage_dir="correlate")
        _unused = workspace_root, config
        ensure_workspace_layout(effective_output_root)

        database_file = Path(database_path).resolve() if database_path else effective_output_root / "storage" / DEFAULT_DATABASE_NAME
        store = SQLiteIntelligenceStore(database_file)

        store_job_id = queued_store_job.id if queued_store_job else stable_record_id("job", source.id, "store", "completed")
        present_job_id = stable_record_id("job", source.id, "present", "queued")
        store_status = "completed"

        completed_store_job = JobRecord(
            id=store_job_id,
            source_id=source.source_id,
            case_id=effective_case_id,
            job_type="pipeline-stage",
            stage="store",
            status=store_status,
            input_refs=tuple(record.id for record in correlated_records),
            output_refs=tuple(record.id for record in correlated_records),
            worker="platform_store",
            started_at=queued_store_job.created_at if queued_store_job else "",
            finished_at=utc_now(),
            provenance=Provenance(
                plugin="platform_store",
                method="sqlite_persist",
                source_refs=(source.id,),
                parent_refs=tuple(record.id for record in correlated_records),
            ),
            confidence=Confidence(score=1.0),
            tags=("job", "store", store_status),
            attributes={"database_path": str(database_file)},
        )

        present_job = JobRecord(
            id=present_job_id,
            source_id=source.source_id,
            case_id=effective_case_id,
            job_type="pipeline-stage",
            stage="present",
            status="queued",
            input_refs=tuple(record.id for record in correlated_records),
            output_refs=(),
            worker="platform_store",
            provenance=Provenance(
                plugin="platform_store",
                method="queue_present",
                source_refs=(source.id,),
                parent_refs=(completed_store_job.id,),
            ),
            confidence=Confidence(score=1.0),
            tags=("job", "present", "queued"),
            attributes={"database_path": str(database_file)},
        )

        records_to_store: list[RecordBase] = [*_collect_upstream_jobs(report_path), *correlated_records]
        if completed_correlate_job is not None:
            records_to_store.append(completed_correlate_job)
        records_to_store.extend((completed_store_job, present_job))
        records_to_store = _dedupe_records_by_id(records_to_store)
        storage_summary = store.persist(source=source, records=records_to_store)
        audit_events = read_audit_events(effective_output_root, source_id=source.id, case_id=effective_case_id)
        if audit_events:
            store.persist_audit_events(audit_events)

        store_dir = effective_output_root / "store" / source.id / store_job_id
        store_dir.mkdir(parents=True, exist_ok=True)
        store_report_path = store_dir / "store_report.json"
        present_queue_dir = effective_output_root / "queues" / "present"
        present_queue_dir.mkdir(parents=True, exist_ok=True)
        present_queue_path = present_queue_dir / f"{present_job.id}.json"

        store_report = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "correlation_report_path": str(report_path),
            "database_path": str(database_file),
            "source": record_to_dict(source),
            "input_artifacts": [record_to_dict(artifact) for artifact in input_artifacts],
            "stored_records": [record_to_dict(record) for record in records_to_store],
            "completed_correlate_job": record_to_dict(completed_correlate_job) if completed_correlate_job is not None else None,
            "completed_store_job": record_to_dict(completed_store_job),
            "queued_present_job": record_to_dict(present_job),
            "storage_summary": storage_summary,
            "audit_event_count": len(audit_events),
        }
        store_report_path.write_text(json.dumps(store_report, indent=2), encoding="utf-8")

        present_queue = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "job": record_to_dict(present_job),
            "source": record_to_dict(source),
            "database_path": str(database_file),
            "store_report_path": str(store_report_path),
            "record_refs": [record.id for record in correlated_records],
        }
        present_queue_path.write_text(json.dumps(present_queue, indent=2), encoding="utf-8")
        audit_path = _append_stage_audit(
            effective_output_root,
            stage="store",
            plugin="platform_store",
            source_id=source.id,
            case_id=effective_case_id,
            job_id=store_job_id,
            ok=True,
            warnings=(),
            errors=(),
            metrics={**storage_summary, "audit_event_count": len(audit_events)},
            artifact_paths=(str(store_report_path), str(database_file), str(present_queue_path)),
            details={"database_path": str(database_file)},
        )
        store.persist_audit_events(read_audit_events(effective_output_root, source_id=source.id, case_id=effective_case_id))

        return PluginResult(
            records=(*correlated_records, completed_store_job, present_job),
            artifact_paths=(str(store_report_path), str(database_file), str(present_queue_path), str(audit_path)),
            metrics={
                **storage_summary,
                "audit_event_count": len(audit_events),
                "store_job_id": store_job_id,
                "present_job_id": present_job_id,
                "source_id": source.id,
            },
        )

    def present(
        self,
        store_report_path: str,
        *,
        case_id: str = "",
        output_root: str | None = None,
        workspace_root: str | None = None,
        database_path: str | None = None,
        config: dict[str, object] | None = None,
    ) -> PluginResult:
        source, input_artifacts, completed_store_job, queued_present_job, report_path, report_database_path = _load_store_report(Path(store_report_path))
        effective_case_id = case_id or source.case_id
        effective_output_root = Path(output_root).resolve() if output_root else _derive_output_root(report_path, stage_dir="store")
        effective_workspace_root = Path(workspace_root).resolve() if workspace_root else Path(".").resolve()
        _unused = config
        ensure_workspace_layout(effective_output_root)

        database_file = Path(database_path).resolve() if database_path else report_database_path
        store = SQLiteIntelligenceStore(database_file)
        store.initialize()

        completed_present_job = JobRecord(
            id=queued_present_job.id if queued_present_job is not None else stable_record_id("job", source.id, "present", "completed"),
            source_id=source.source_id,
            case_id=effective_case_id,
            job_type="pipeline-stage",
            stage="present",
            status="completed",
            input_refs=queued_present_job.input_refs if queued_present_job is not None else (),
            output_refs=(),
            worker="platform_present",
            started_at=queued_present_job.created_at if queued_present_job is not None else "",
            finished_at=utc_now(),
            provenance=Provenance(
                plugin="platform_present",
                method="materialize_views",
                source_refs=(source.id,),
                parent_refs=(completed_store_job.id,) if completed_store_job is not None else (),
            ),
            confidence=Confidence(score=1.0),
            tags=("job", "present", "completed"),
            attributes={"database_path": str(database_file)},
        )
        store.persist(source=source, records=(completed_present_job,))

        query_case_id = effective_case_id
        query_source_id = "" if query_case_id else source.source_id
        case_summary = store.case_summary(case_id=query_case_id, source_id=query_source_id)
        graph_view = store.graph_view(case_id=query_case_id, source_id=query_source_id)
        timelines = store.fetch_timelines(case_id=query_case_id, source_id=query_source_id, limit=100)
        dataset_export = store.export_dataset(case_id=query_case_id, source_id=query_source_id)
        plugin_statuses = self.plugin_statuses(
            config=config,
            workspace_root=effective_workspace_root,
            output_root=effective_output_root,
        )
        plugin_summary = _summarize_plugin_statuses(plugin_statuses)
        dashboard_view = {
            "summary": case_summary,
            "graph": graph_view,
            "timelines": timelines,
            "plugins": {
                "summary": plugin_summary,
                "items": list(plugin_statuses),
            },
            "highlights": {
                "recent_events": case_summary.get("recent_events", []),
                "recent_jobs": case_summary.get("recent_jobs", []),
                "identities": case_summary.get("top_identities", []),
                "indicators": case_summary.get("top_indicators", []),
                "relationship_type_counts": case_summary.get("relationship_type_counts", {}),
            },
        }

        present_dir = effective_output_root / "present" / source.id / completed_present_job.id
        present_dir.mkdir(parents=True, exist_ok=True)
        case_summary_path = present_dir / "case_summary.json"
        graph_view_path = present_dir / "graph_view.json"
        timeline_view_path = present_dir / "timeline_view.json"
        dataset_export_path = present_dir / "dataset_export.json"
        dashboard_view_path = present_dir / "dashboard_view.json"
        presentation_report_path = present_dir / "presentation_report.json"

        case_summary_path.write_text(json.dumps(case_summary, indent=2), encoding="utf-8")
        graph_view_path.write_text(json.dumps(graph_view, indent=2), encoding="utf-8")
        timeline_view_path.write_text(json.dumps({"timelines": timelines}, indent=2), encoding="utf-8")
        dataset_export_path.write_text(json.dumps(dataset_export, indent=2), encoding="utf-8")
        dashboard_view_path.write_text(json.dumps(dashboard_view, indent=2), encoding="utf-8")

        presentation_report = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "store_report_path": str(report_path),
            "database_path": str(database_file),
            "source": record_to_dict(source),
            "input_artifacts": [record_to_dict(artifact) for artifact in input_artifacts],
            "completed_store_job": record_to_dict(completed_store_job) if completed_store_job is not None else None,
            "completed_present_job": record_to_dict(completed_present_job),
            "artifacts": {
                "case_summary": str(case_summary_path),
                "graph_view": str(graph_view_path),
                "timeline_view": str(timeline_view_path),
                "dataset_export": str(dataset_export_path),
                "dashboard_view": str(dashboard_view_path),
            },
            "api_examples": {
                "health": "/health",
                "plugins": "/plugins",
                "cases": "/cases",
                "case_summary": f"/cases/{effective_case_id or source.source_id}/summary",
                "case_search": f"/cases/{effective_case_id or source.source_id}/search?q=example",
                "case_jobs": f"/cases/{effective_case_id or source.source_id}/jobs",
                "case_audit": f"/cases/{effective_case_id or source.source_id}/audit",
                "case_graph": f"/cases/{effective_case_id or source.source_id}/graph",
                "case_graph_neighbors": f"/cases/{effective_case_id or source.source_id}/graph?node_id=<record-id>&depth=1",
                "case_export": f"/cases/{effective_case_id or source.source_id}/export",
            },
            "metrics": {
                "record_count": case_summary.get("record_count", 0),
                "relationship_edge_count": case_summary.get("relationship_edge_count", 0),
                "timeline_count": case_summary.get("timeline_count", 0),
                "source_count": case_summary.get("source_count", 0),
                "plugin_count": plugin_summary.get("plugin_count", 0),
                "ready_plugin_count": plugin_summary.get("ready_count", 0),
            },
        }
        presentation_report_path.write_text(json.dumps(presentation_report, indent=2), encoding="utf-8")
        audit_path = _append_stage_audit(
            effective_output_root,
            stage="present",
            plugin="platform_present",
            source_id=source.id,
            case_id=effective_case_id,
            job_id=completed_present_job.id,
            ok=True,
            warnings=(),
            errors=(),
            metrics=presentation_report["metrics"],
            artifact_paths=(
                str(presentation_report_path),
                str(case_summary_path),
                str(graph_view_path),
                str(timeline_view_path),
                str(dataset_export_path),
                str(dashboard_view_path),
            ),
            details={"database_path": str(database_file)},
        )
        store.persist_audit_events(read_audit_events(effective_output_root, source_id=source.id, case_id=effective_case_id))

        return PluginResult(
            records=(completed_present_job,),
            artifact_paths=(
                str(presentation_report_path),
                str(case_summary_path),
                str(graph_view_path),
                str(timeline_view_path),
                str(dataset_export_path),
                str(dashboard_view_path),
                str(audit_path),
            ),
            metrics={
                "record_count": case_summary.get("record_count", 0),
                "relationship_edge_count": case_summary.get("relationship_edge_count", 0),
                "timeline_count": case_summary.get("timeline_count", 0),
                "source_count": case_summary.get("source_count", 0),
                "present_job_id": completed_present_job.id,
                "source_id": source.id,
            },
        )


def _merge_stage_results(*results: PluginResult) -> PluginResult:
    records: list[RecordBase] = []
    artifact_paths: list[str] = []
    warnings: list[str] = []
    errors: list[str] = []
    metrics: dict[str, object] = {}
    for result in results:
        records.extend(result.records)
        artifact_paths.extend(path for path in result.artifact_paths if path not in artifact_paths)
        warnings.extend(warning for warning in result.warnings if warning not in warnings)
        errors.extend(error for error in result.errors if error not in errors)
        metrics.update(result.metrics)
    metrics["stage_count"] = len(results)
    return PluginResult(
        records=tuple(records),
        artifact_paths=tuple(artifact_paths),
        warnings=tuple(warnings),
        errors=tuple(errors),
        metrics=metrics,
    )


def _append_stage_audit(
    output_root: Path,
    *,
    stage: str,
    plugin: str,
    source_id: str,
    case_id: str,
    job_id: str,
    ok: bool,
    warnings: tuple[str, ...] | list[str],
    errors: tuple[str, ...] | list[str],
    metrics: dict[str, object],
    artifact_paths: tuple[str, ...] | list[str],
    details: dict[str, object] | None = None,
) -> Path:
    return append_audit_event(
        output_root,
        {
            "stage": stage,
            "plugin": plugin,
            "source_id": source_id,
            "case_id": case_id,
            "job_id": job_id,
            "ok": bool(ok),
            "status": "completed" if ok else "completed_with_errors",
            "warnings": list(warnings),
            "errors": list(errors),
            "metrics": dict(metrics),
            "artifact_paths": list(artifact_paths),
            "details": dict(details or {}),
        },
    )


def _first_source_record(records: tuple[RecordBase, ...]) -> SourceRecord | None:
    for record in records:
        if isinstance(record, SourceRecord):
            return record
    return None


def _first_job_record(records: tuple[RecordBase, ...], *, stage: str) -> JobRecord | None:
    for record in records:
        if isinstance(record, JobRecord) and record.stage == stage:
            return record
    return None


def _find_watcher_state(rows: list[dict[str, object]], *, watcher_id: str) -> dict[str, object]:
    for row in rows:
        if str(row.get("watcher_id") or "") == watcher_id:
            return row
    return {}


def _find_watched_source(rows: list[dict[str, object]], *, watch_id: str) -> dict[str, object]:
    for row in rows:
        if str(row.get("watch_id") or "") == watch_id:
            return row
    return {}


def _find_registered_watch_source(
    store: SQLiteIntelligenceStore,
    *,
    case_id: str,
    source_type: str,
    locator: str,
) -> dict[str, object]:
    normalized_locator = _normalize_watch_locator(locator)
    for row in store.fetch_watched_sources(case_id=case_id, source_type=source_type, limit=500):
        if _normalize_watch_locator(str(row.get("locator") or "")) == normalized_locator:
            return row
    return {}


def _find_source_monitor_watcher(
    store: SQLiteIntelligenceStore,
    watched_source: dict[str, object],
) -> dict[str, object]:
    watcher_id = _source_monitor_watcher_id(
        case_id=str(watched_source.get("case_id") or ""),
        source_type=str(watched_source.get("source_type") or ""),
        locator=str(watched_source.get("locator") or ""),
        recursive=bool(watched_source.get("recursive")),
    )
    watcher = _find_watcher_state(
        store.fetch_watcher_states(
            case_id=str(watched_source.get("case_id") or ""),
            watcher_id=watcher_id,
            watcher_type="source_monitor",
            limit=1,
        ),
        watcher_id=watcher_id,
    )
    if watcher:
        return watcher
    normalized_locator = _normalize_watch_locator(str(watched_source.get("locator") or ""))
    for row in store.fetch_watcher_states(
        case_id=str(watched_source.get("case_id") or ""),
        watcher_type="source_monitor",
        limit=500,
    ):
        if str(row.get("source_type") or "").strip() != str(watched_source.get("source_type") or "").strip():
            continue
        if _normalize_watch_locator(str(row.get("locator") or "")) == normalized_locator:
            return row
    return {}


def _source_monitor_watcher_id(
    *,
    case_id: str,
    source_type: str,
    locator: str,
    recursive: bool,
) -> str:
    return stable_record_id(
        "watcher",
        "source_monitor",
        str(case_id or ""),
        str(source_type or ""),
        _normalize_watch_locator(locator),
        str(bool(recursive)),
    )


def _build_append_only_delta_ingest_result(
    *,
    collector: object,
    context: PluginExecutionContext,
    request: IngestRequest,
    snapshot: object,
    previous_source_id: str = "",
) -> PluginResult:
    requested_type = str(getattr(snapshot, "requested_type", "") or "").strip().lower()
    if requested_type not in {"log", "log-bundle"}:
        return PluginResult()

    source_path = Path(str(getattr(snapshot, "path", "") or "")).resolve()
    delta_rows: list[dict[str, object]] = []
    artifact_records: list[ArtifactRecord] = []
    total_delta_bytes = 0
    collector_name = str(getattr(getattr(collector, "manifest", None), "name", "") or type(collector).__name__)
    collector_version = str(getattr(getattr(collector, "manifest", None), "version", "") or "0.1.0")
    collector_plugin_type = str(getattr(getattr(collector, "manifest", None), "plugin_type", "") or "collector")
    artifact_type = str(getattr(collector, "artifact_type", "") or requested_type or "file")
    source_id = stable_record_id(
        "source",
        context.case_id,
        requested_type,
        str(source_path),
        "append_only",
        str(getattr(snapshot, "cursor", "") or ""),
    )

    for row in list(getattr(snapshot, "file_rows", ())):
        if str(row.get("change_kind") or "") != "appended":
            continue
        file_path = Path(str(row.get("path") or "")).resolve()
        relative_path = str(row.get("relative_path") or file_path.name)
        start_offset = max(0, int(row.get("previous_size_bytes") or 0))
        appended_bytes = max(0, int(row.get("appended_bytes") or 0))
        if appended_bytes <= 0:
            continue

        with file_path.open("rb") as handle:
            handle.seek(start_offset)
            delta_bytes = handle.read(appended_bytes)
        if not delta_bytes:
            continue

        end_offset = start_offset + len(delta_bytes)
        object_path, delta_sha256 = materialize_derived_artifact(
            context.output_root,
            stage="watch_delta",
            source_id=source_id,
            content=delta_bytes,
            preferred_name=_delta_artifact_name(file_path=file_path, start_offset=start_offset, end_offset=end_offset),
            parts=("append_only",),
        )
        artifact = ArtifactRecord(
            id=stable_record_id(
                "artifact",
                source_id,
                artifact_type,
                relative_path,
                str(start_offset),
                str(end_offset),
                delta_sha256,
            ),
            source_id=source_id,
            case_id=context.case_id,
            artifact_type=artifact_type,
            path=str(object_path),
            media_type=str(row.get("media_type") or ""),
            sha256=delta_sha256,
            size_bytes=len(delta_bytes),
            provenance=Provenance(
                plugin=collector_name,
                method="watch-append-delta",
                source_refs=(source_id,),
                parent_refs=tuple(value for value in (previous_source_id, str(source_path)) if value),
                notes="append-only delta artifact captured from watched source",
            ),
            confidence=Confidence(score=1.0),
            tags=_delta_artifact_tags(collector, file_path),
            attributes={
                "file_name": file_path.name,
                "suffix": file_path.suffix.lower(),
                "original_path": str(file_path),
                "relative_path": relative_path,
                "object_path": str(object_path),
                "delta": "true",
                "delta_kind": "append_only",
                "delta_start_offset": str(start_offset),
                "delta_end_offset": str(end_offset),
                "delta_parent_source_id": previous_source_id,
                "full_file_sha256": str(row.get("sha256") or ""),
            },
        )
        artifact_records.append(artifact)
        total_delta_bytes += len(delta_bytes)
        delta_rows.append(
            {
                "relative_path": relative_path,
                "start_offset": start_offset,
                "end_offset": end_offset,
                "sha256": delta_sha256,
                "size_bytes": len(delta_bytes),
            }
        )

    if not artifact_records:
        return PluginResult()

    source_content_hash = hashlib.sha256(
        json.dumps(delta_rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    delta_locator = _append_only_delta_locator(source_path, delta_rows)
    source_record = SourceRecord(
        id=source_id,
        source_id=source_id,
        case_id=context.case_id,
        source_type=requested_type,
        locator=delta_locator,
        display_name=_append_only_delta_display_name(
            display_name=str(getattr(snapshot, "display_name", "") or source_path.name or str(source_path)),
            delta_rows=delta_rows,
        ),
        collector=collector_name,
        media_type=str(getattr(snapshot, "media_type", "") or ""),
        content_hash=source_content_hash,
        size_bytes=total_delta_bytes,
        provenance=Provenance(
            plugin=collector_name,
            method="watch-append-delta",
            source_refs=(str(source_path),),
            parent_refs=tuple(value for value in (previous_source_id,) if value),
            notes="append-only delta source created from watched input",
        ),
        confidence=Confidence(score=1.0),
        tags=(requested_type, "source", "delta_source", "append_only"),
        attributes={
            "recursive": str(bool(request.options.get("recursive", True))).lower(),
            "workspace_root": str(context.workspace_root),
            "object_store_root": str((context.output_root / "objects" / "derived").resolve()),
            "delta": "true",
            "delta_kind": "append_only",
            "delta_parent_source_id": previous_source_id,
            "delta_file_count": str(len(delta_rows)),
            "delta_bytes": str(total_delta_bytes),
            "original_locator": str(source_path),
            "delta_rows_json": json.dumps(delta_rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
        },
    )

    job_id = stable_record_id("job", source_id, "extract", "queued")
    ensure_workspace_layout(context.output_root)
    job_dir = context.output_root / "intake" / source_id / job_id
    queue_dir = context.output_root / "queues" / "extract"
    job_dir.mkdir(parents=True, exist_ok=True)
    queue_dir.mkdir(parents=True, exist_ok=True)

    queued_job = JobRecord(
        id=job_id,
        source_id=source_id,
        case_id=context.case_id,
        job_type="pipeline-stage",
        stage="extract",
        status="queued",
        input_refs=tuple(artifact.id for artifact in artifact_records),
        output_refs=(),
        worker=collector_name,
        provenance=Provenance(
            plugin=collector_name,
            method="queue",
            source_refs=(source_id,),
            parent_refs=tuple(value for value in (source_id, previous_source_id) if value),
            notes="queued extract stage after append-only delta ingestion",
        ),
        confidence=Confidence(score=1.0),
        tags=("job", "queued", "extract", "delta"),
        attributes={
            "requested_source_type": requested_type,
            "file_count": str(len(artifact_records)),
            "delta_ingest": "true",
        },
    )

    manifest_payload = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "plugin": {
            "name": collector_name,
            "version": collector_version,
            "type": collector_plugin_type,
        },
        "request": {
            "source_type": requested_type,
            "locator": delta_locator,
            "display_name": source_record.display_name,
            "options": dict(request.options or {}),
        },
        "source": record_to_dict(source_record),
        "artifacts": [record_to_dict(artifact) for artifact in artifact_records],
        "queued_jobs": [record_to_dict(queued_job)],
    }
    manifest_path = job_dir / "source_manifest.json"
    manifest_path.write_text(json.dumps(manifest_payload, indent=2), encoding="utf-8")

    queue_payload = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "job": record_to_dict(queued_job),
        "source": record_to_dict(source_record),
        "artifact_refs": [artifact.id for artifact in artifact_records],
        "source_manifest_path": str(manifest_path),
    }
    queue_path = queue_dir / f"{job_id}.json"
    queue_path.write_text(json.dumps(queue_payload, indent=2), encoding="utf-8")

    return PluginResult(
        records=(source_record, *artifact_records, queued_job),
        artifact_paths=(str(manifest_path), str(queue_path)),
        metrics={
            "source_id": source_id,
            "job_id": job_id,
            "file_count": len(artifact_records),
            "artifact_count": len(artifact_records),
            "delta_ingest": True,
            "delta_artifact_count": len(artifact_records),
            "delta_bytes": total_delta_bytes,
        },
    )


def _delta_artifact_tags(collector: object, file_path: Path) -> tuple[str, ...]:
    build_tags = getattr(collector, "_artifact_tags", None)
    artifact_tags = tuple(str(tag) for tag in tuple(build_tags(file_path))) if callable(build_tags) else ()
    if not artifact_tags:
        suffix = file_path.suffix.lower().lstrip(".")
        artifact_tags = tuple(value for value in ("artifact", suffix) if value)
    return tuple(dict.fromkeys((*artifact_tags, "delta", "append_only")))


def _delta_artifact_name(*, file_path: Path, start_offset: int, end_offset: int) -> str:
    suffix = file_path.suffix or ".bin"
    stem = file_path.stem or file_path.name or "artifact"
    return f"{stem}__delta_{start_offset}_{end_offset}{suffix}"


def _append_only_delta_locator(source_path: Path, delta_rows: list[dict[str, object]]) -> str:
    segments = [
        f"{str(row.get('relative_path') or '')}:{int(row.get('start_offset') or 0)}-{int(row.get('end_offset') or 0)}"
        for row in delta_rows
    ]
    return f"{source_path}#append-only:{'|'.join(segments)}"


def _append_only_delta_display_name(*, display_name: str, delta_rows: list[dict[str, object]]) -> str:
    if len(delta_rows) == 1:
        row = delta_rows[0]
        return f"{display_name} (delta {int(row.get('start_offset') or 0)}-{int(row.get('end_offset') or 0)})"
    return f"{display_name} ({len(delta_rows)} append-only deltas)"


def _empty_priority_counts() -> dict[str, int]:
    return {"urgent": 0, "high": 0, "normal": 0, "low": 0}


def _increment_priority_count(counter: dict[str, int], priority: str) -> None:
    normalized = _priority_label_from_score(_safe_int(priority)) if str(priority).isdigit() else str(priority or "").strip().lower()
    if normalized not in counter:
        normalized = "low"
    counter[normalized] = int(counter.get(normalized, 0)) + 1


def _priority_label_from_score(score: int) -> str:
    if score >= 75:
        return "urgent"
    if score >= 55:
        return "high"
    if score >= 40:
        return "normal"
    return "low"


def _queue_stage_index(stage: str) -> int:
    try:
        return QUEUE_STAGE_ORDER.index(str(stage or "").strip().lower())
    except ValueError:
        return len(QUEUE_STAGE_ORDER)


def _resolve_queue_triage(
    *,
    stage: str,
    queue_payload: dict[str, object],
    source_payload: dict[str, object],
    job_payload: dict[str, object],
) -> dict[str, object]:
    stored = queue_payload.get("triage") if isinstance(queue_payload, dict) else None
    if isinstance(stored, dict):
        normalized = _normalize_triage_payload(stored)
        if normalized:
            return normalized
    return _build_queue_triage(stage=stage, source_payload=source_payload, job_payload=job_payload)


def _normalize_triage_payload(payload: dict[str, object]) -> dict[str, object]:
    score = max(0, min(100, _safe_int(payload.get("score"), default=-1)))
    if score < 0:
        return {}
    reasons = [str(item).strip() for item in list(payload.get("reasons") or []) if str(item).strip()]
    priority = str(payload.get("priority") or "").strip().lower() or _priority_label_from_score(score)
    if priority not in _empty_priority_counts():
        priority = _priority_label_from_score(score)
    return {
        "score": score,
        "priority": priority,
        "reasons": reasons,
    }


def _build_queue_triage(
    *,
    stage: str,
    source_payload: dict[str, object],
    job_payload: dict[str, object],
) -> dict[str, object]:
    source_attributes = dict(source_payload.get("attributes") or {}) if isinstance(source_payload, dict) else {}
    job_attributes = dict(job_payload.get("attributes") or {}) if isinstance(job_payload, dict) else {}
    source_type = str(
        (source_payload.get("source_type") if isinstance(source_payload, dict) else "")
        or job_attributes.get("requested_source_type")
        or ""
    ).strip().lower()
    score = 18
    reasons: list[str] = []

    stage_bonus = {
        "extract": 24,
        "recover": 20,
        "normalize": 15,
        "correlate": 13,
        "store": 10,
        "present": 8,
    }
    score += int(stage_bonus.get(str(stage).strip().lower(), 0))
    reasons.append(f"{stage} queue")

    source_bonus = {
        "wifi-capture": 18,
        "pcap": 18,
        "pcapng": 18,
        "system-artifact": 14,
        "system-artifact-bundle": 14,
        "log": 11,
        "log-bundle": 11,
        "directory": 8,
        "file": 6,
    }
    if source_type in source_bonus:
        score += source_bonus[source_type]
        reasons.append(f"{source_type} source")

    if str(source_attributes.get("delta") or "").strip().lower() == "true" or str(job_attributes.get("delta_ingest") or "").strip().lower() == "true":
        score += 12
        reasons.append("delta artifact flow")

    delta_kind = str(source_attributes.get("delta_kind") or "").strip().lower()
    if delta_kind == "append_only":
        score += 6
        reasons.append("append-only delta")

    watch_change_kind = str(source_attributes.get("watch_change_kind") or "").strip().lower()
    if watch_change_kind == "structural":
        score += 10
        reasons.append("structural source change")
    elif watch_change_kind == "modified":
        score += 6
        reasons.append("modified source")
    elif watch_change_kind == "append_only":
        score += 5
        reasons.append("append-only source change")

    delta_bytes = _safe_int(source_attributes.get("delta_bytes"))
    if delta_bytes > 0:
        score += min(6, max(1, delta_bytes // 4096 + 1))
        reasons.append("new delta bytes")

    file_count = max(
        _safe_int(job_attributes.get("file_count")),
        _safe_int(source_attributes.get("delta_file_count")),
    )
    if file_count > 10:
        score += 5
        reasons.append("multi-artifact batch")
    elif file_count > 1:
        score += 2
        reasons.append("multiple artifacts")

    score = max(0, min(100, score))
    return {
        "score": score,
        "priority": _priority_label_from_score(score),
        "reasons": reasons[:4],
    }


def _build_watch_triage(
    *,
    source_type: str,
    change_kind: str,
    changed: bool,
    delta_ingest: bool,
    file_count: int,
    changed_file_count: int,
    append_only_file_count: int,
    removed_file_count: int,
    force: bool,
) -> dict[str, object]:
    normalized_type = str(source_type or "").strip().lower()
    normalized_change_kind = str(change_kind or "").strip().lower()
    score = 12
    reasons: list[str] = []

    source_bonus = {
        "wifi-capture": 18,
        "pcap": 18,
        "pcapng": 18,
        "system-artifact": 14,
        "system-artifact-bundle": 14,
        "log": 12,
        "log-bundle": 12,
        "directory": 8,
        "file": 6,
    }
    if normalized_type in source_bonus:
        score += source_bonus[normalized_type]
        reasons.append(f"{normalized_type} source")

    if not changed:
        reasons.append("unchanged source")
    else:
        change_bonus = {
            "append_only": 14,
            "structural": 13,
            "modified": 9,
        }
        score += int(change_bonus.get(normalized_change_kind, 6))
        reasons.append(f"{normalized_change_kind or 'changed'} source")

    if delta_ingest:
        score += 12
        reasons.append("delta-only ingest")
    if append_only_file_count > 0:
        score += 5
        reasons.append("append-only growth")
    if removed_file_count > 0:
        score += 8
        reasons.append("removed artifacts detected")
    if changed_file_count > 3:
        score += min(6, changed_file_count)
        reasons.append("multiple files changed")
    elif file_count > 1:
        score += 2
        reasons.append("bundle source")
    if force:
        score += 1
        reasons.append("forced check")

    score = max(0, min(100, score))
    return {
        "score": score,
        "priority": _priority_label_from_score(score),
        "reasons": reasons[:4],
    }


def _safe_int(value: object, *, default: int = 0) -> int:
    try:
        return int(str(value or "").strip())
    except (TypeError, ValueError):
        return default


def _timestamp_age_seconds(value: str) -> int:
    text = str(value or "").strip()
    if not text:
        return 0
    try:
        then = datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return 0
    return max(0, int((datetime.now(timezone.utc) - then).total_seconds()))


def _timestamp_after_seconds(value: str, *, seconds: float) -> str:
    text = str(value or "").strip()
    try:
        anchor = datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        anchor = datetime.now(timezone.utc)
    future = anchor + timedelta(seconds=max(0.0, float(seconds or 0.0)))
    return future.isoformat().replace("+00:00", "Z")


def _timestamp_remaining_seconds(value: str) -> float:
    text = str(value or "").strip()
    if not text:
        return 0.0
    try:
        then = datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return 0.0
    return max(0.0, (then - datetime.now(timezone.utc)).total_seconds())


def _normalize_watch_locator(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlparse(text)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return text
    candidate = Path(text).expanduser()
    if candidate.exists() or candidate.is_absolute() or candidate.drive or text.startswith((".", "~")) or any(
        separator in text for separator in ("/", "\\")
    ):
        try:
            return str(candidate.resolve())
        except OSError:
            return text
    if ":" not in text and "." in text:
        return text.lower()
    try:
        return str(candidate.resolve())
    except OSError:
        return text


def _materialize_watched_source(row: dict[str, object]) -> dict[str, object]:
    payload = dict(row or {})
    payload["enabled"] = bool(payload.get("enabled", True))
    payload["recursive"] = bool(payload.get("recursive"))
    payload["poll_interval_seconds"] = float(payload.get("poll_interval_seconds") or 0.0)
    payload["snooze_until"] = str(payload.get("snooze_until") or "").strip()
    payload["notes"] = str(payload.get("notes") or "").strip()
    payload["tags"] = _normalize_tags(payload.get("tags"))
    payload["tuning_profile"] = _materialize_watch_tuning_profile(payload.get("tuning_profile"))
    payload["tuning_preset_name"] = str(
        payload.get("tuning_preset_name") or dict(payload.get("tuning_profile") or {}).get("preset_name") or ""
    ).strip()
    payload["automation_state"] = _materialize_preset_automation_state(payload.get("automation_state"))
    return payload


def _materialize_watch_tuning_profile(value: object) -> dict[str, object]:
    return normalize_watch_tuning_profile(value if isinstance(value, dict) else {})


def _materialize_preset_automation_state(value: object) -> dict[str, object]:
    return normalize_preset_automation_state(value if isinstance(value, dict) else {})


def _normalize_change_origin(value: object) -> str:
    normalized = str(value or "").strip().lower()
    if normalized == "automation":
        return "automation"
    return "manual"


def _update_preset_automation_state(
    current_state: dict[str, object] | None,
    *,
    change_origin: str,
    previous_preset_name: str,
    new_preset_name: str,
    changed_at: str,
    automation_direction: str = "",
    automation_reason: str = "",
) -> dict[str, object]:
    state = _materialize_preset_automation_state(current_state)
    origin = _normalize_change_origin(change_origin)
    previous = str(previous_preset_name or "").strip()
    current = str(new_preset_name or "").strip()
    if previous == current:
        return state
    if origin == "automation":
        return {
            **state,
            "last_automation_applied_at": str(changed_at or "").strip(),
            "last_automation_preset_name": current,
            "last_automation_direction": str(automation_direction or "").strip(),
            "last_automation_reason": str(automation_reason or "").strip(),
            "manual_override_active": False,
        }
    manual_override_active = bool(
        str(state.get("last_automation_preset_name") or "").strip()
        and current != str(state.get("last_automation_preset_name") or "").strip()
    )
    return {
        **state,
        "last_manual_change_at": str(changed_at or "").strip(),
        "last_manual_preset_name": current,
        "manual_override_active": manual_override_active,
    }


def _watch_tuning_profile_has_overrides(profile: dict[str, object]) -> bool:
    payload = _materialize_watch_tuning_profile(profile)
    return bool(
        (
            str(payload.get("preset_name") or "").strip()
            and str(payload.get("preset_name") or "").strip() != "source:default"
        )
        or int(payload.get("forecast_min_history") or 0) > 0
        or float(payload.get("source_churn_spike_factor") or 0.0) > 0.0
        or list(payload.get("suppressed_alert_ids") or [])
    )


def _watch_tuning_profile_from_updates(
    *,
    base_profile: dict[str, object] | None = None,
    preset_name: str | None = None,
    forecast_min_history: int | None = None,
    source_churn_spike_factor: float | None = None,
    suppressed_alert_ids: list[str] | tuple[str, ...] | None = None,
) -> dict[str, object]:
    if preset_name is not None and str(preset_name).strip():
        payload = apply_watch_tuning_preset(str(preset_name).strip())
    elif base_profile is not None:
        payload = _materialize_watch_tuning_profile(base_profile)
    else:
        payload = default_watch_tuning_profile()
    if forecast_min_history is not None:
        payload["forecast_min_history"] = max(1, int(forecast_min_history))
    if source_churn_spike_factor is not None:
        payload["source_churn_spike_factor"] = max(1.0, float(source_churn_spike_factor))
    if suppressed_alert_ids is not None:
        payload["suppressed_alert_ids"] = [
            str(item).strip()
            for item in list(suppressed_alert_ids)
            if str(item).strip()
        ]
    payload["updated_at"] = utc_now() if _watch_tuning_profile_has_overrides(payload) else ""
    return normalize_watch_tuning_profile(payload)


def _normalize_tags(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        candidates = value.replace("\n", ",").split(",")
    else:
        try:
            candidates = list(value)
        except TypeError:
            candidates = [value]
    rows: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        text = str(item or "").strip()
        if not text:
            continue
        normalized = text.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        rows.append(text)
    return rows


def _dedupe_records_by_id(records: list[RecordBase]) -> list[RecordBase]:
    rows: list[RecordBase] = []
    seen: set[str] = set()
    for record in records:
        if record.id in seen:
            continue
        seen.add(record.id)
        rows.append(record)
    return rows


def _collect_upstream_jobs(correlation_report_path: Path) -> tuple[JobRecord, ...]:
    job_records: list[JobRecord] = []
    seen: set[str] = set()

    def append_job(payload: object) -> None:
        if not isinstance(payload, dict):
            return
        record = record_from_dict(payload)
        if not isinstance(record, JobRecord):
            return
        if record.id in seen:
            return
        seen.add(record.id)
        job_records.append(record)

    correlation_payload = json.loads(correlation_report_path.read_text(encoding="utf-8"))
    append_job(correlation_payload.get("completed_correlate_job"))
    append_job(correlation_payload.get("queued_store_job"))

    normalize_report_value = str(correlation_payload.get("normalize_report_path") or "").strip()
    if normalize_report_value:
        normalize_report_path = Path(normalize_report_value).resolve()
    else:
        normalize_report_path = None
    if normalize_report_path is not None and normalize_report_path.exists():
        normalize_payload = json.loads(normalize_report_path.read_text(encoding="utf-8"))
        append_job(normalize_payload.get("completed_normalize_job"))
        append_job(normalize_payload.get("queued_correlate_job"))

        recover_report_value = str(
            normalize_payload.get("recover_report_path")
            or normalize_payload.get("input_report_path")
            or normalize_payload.get("extract_report_path")
            or ""
        ).strip()
        if recover_report_value:
            upstream_report_path = Path(recover_report_value).resolve()
        else:
            upstream_report_path = None
        if upstream_report_path is not None and upstream_report_path.exists():
            upstream_payload = json.loads(upstream_report_path.read_text(encoding="utf-8"))
            if "all_records" in upstream_payload:
                append_job(upstream_payload.get("completed_recover_job"))
                append_job(upstream_payload.get("queued_normalize_job"))
                extract_report_value = str(upstream_payload.get("extract_report_path") or "").strip()
            else:
                extract_report_value = str(upstream_payload.get("extract_report_path") or "").strip()
            if extract_report_value:
                extract_report_path = Path(extract_report_value).resolve()
            else:
                extract_report_path = None
            if extract_report_path is not None and extract_report_path.exists():
                extract_payload = json.loads(extract_report_path.read_text(encoding="utf-8"))
                append_job(extract_payload.get("completed_extract_job"))
                append_job(extract_payload.get("queued_recover_job"))
                append_job(extract_payload.get("queued_normalize_job"))

                source_manifest_value = str(extract_payload.get("source_manifest_path") or "").strip()
                if source_manifest_value:
                    source_manifest_path = Path(source_manifest_value).resolve()
                else:
                    source_manifest_path = None
                if source_manifest_path is not None and source_manifest_path.exists():
                    source_manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))
                    for payload in source_manifest.get("queued_jobs", []):
                        append_job(payload)

    return tuple(job_records)


def _load_source_manifest(path: Path) -> tuple[SourceRecord, tuple[ArtifactRecord, ...], JobRecord | None, Path]:
    resolved = path.resolve()
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    source = record_from_dict(payload["source"])
    if not isinstance(source, SourceRecord):
        raise TypeError("source manifest did not contain a SourceRecord")
    artifacts = tuple(
        record
        for record in (record_from_dict(item) for item in payload.get("artifacts", []))
        if isinstance(record, ArtifactRecord)
    )
    queued_extract_job = None
    for item in payload.get("queued_jobs", []):
        record = record_from_dict(item)
        if isinstance(record, JobRecord) and record.stage == "extract":
            queued_extract_job = record
            break
    return source, artifacts, queued_extract_job, resolved


def _load_extract_report(path: Path) -> tuple[SourceRecord, tuple[ArtifactRecord, ...], tuple[RecordBase, ...], JobRecord | None, Path]:
    resolved = path.resolve()
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    source = record_from_dict(payload["source"])
    if not isinstance(source, SourceRecord):
        raise TypeError("extract report did not contain a SourceRecord")
    artifacts = tuple(
        record
        for record in (record_from_dict(item) for item in payload.get("input_artifacts", []))
        if isinstance(record, ArtifactRecord)
    )
    extracted_records = tuple(record_from_dict(item) for item in payload.get("extracted_records", []))
    queued_recover_job = None
    maybe_job = payload.get("queued_recover_job")
    if isinstance(maybe_job, dict):
        record = record_from_dict(maybe_job)
        if isinstance(record, JobRecord) and record.stage == "recover":
            queued_recover_job = record
    if queued_recover_job is None:
        maybe_job = payload.get("queued_normalize_job")
    if isinstance(maybe_job, dict):
        record = record_from_dict(maybe_job)
        if isinstance(record, JobRecord) and record.stage in {"recover", "normalize"}:
            queued_recover_job = record
    return source, artifacts, extracted_records, queued_recover_job, resolved


def _load_recover_report(path: Path) -> tuple[SourceRecord, tuple[ArtifactRecord, ...], tuple[RecordBase, ...], JobRecord | None, Path]:
    resolved = path.resolve()
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    source = record_from_dict(payload["source"])
    if not isinstance(source, SourceRecord):
        raise TypeError("recover report did not contain a SourceRecord")
    artifacts = tuple(
        record
        for record in (record_from_dict(item) for item in payload.get("input_artifacts", []))
        if isinstance(record, ArtifactRecord)
    )
    all_records = tuple(record_from_dict(item) for item in payload.get("all_records", []))
    queued_normalize_job = None
    maybe_job = payload.get("queued_normalize_job")
    if isinstance(maybe_job, dict):
        record = record_from_dict(maybe_job)
        if isinstance(record, JobRecord) and record.stage == "normalize":
            queued_normalize_job = record
    return source, artifacts, all_records, queued_normalize_job, resolved


def _load_pre_normalize_report(
    path: Path,
) -> tuple[SourceRecord, tuple[ArtifactRecord, ...], tuple[RecordBase, ...], JobRecord | None, Path, str]:
    resolved = path.resolve()
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    if "all_records" in payload:
        source, artifacts, records, queued_job, _resolved = _load_recover_report(resolved)
        return source, artifacts, records, queued_job, _resolved, "recover"
    source, artifacts, records, queued_job, _resolved = _load_extract_report(resolved)
    normalize_job = queued_job if isinstance(queued_job, JobRecord) and queued_job.stage == "normalize" else None
    return source, artifacts, records, normalize_job, _resolved, "extract"


def _load_normalize_report(path: Path) -> tuple[SourceRecord, tuple[ArtifactRecord, ...], tuple[RecordBase, ...], JobRecord | None, Path]:
    resolved = path.resolve()
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    source = record_from_dict(payload["source"])
    if not isinstance(source, SourceRecord):
        raise TypeError("normalize report did not contain a SourceRecord")
    artifacts = tuple(
        record
        for record in (record_from_dict(item) for item in payload.get("input_artifacts", []))
        if isinstance(record, ArtifactRecord)
    )
    normalized_records = tuple(record_from_dict(item) for item in payload.get("normalized_records", []))
    queued_correlate_job = None
    maybe_job = payload.get("queued_correlate_job")
    if isinstance(maybe_job, dict):
        record = record_from_dict(maybe_job)
        if isinstance(record, JobRecord) and record.stage == "correlate":
            queued_correlate_job = record
    return source, artifacts, normalized_records, queued_correlate_job, resolved


def _load_correlation_report(
    path: Path,
) -> tuple[SourceRecord, tuple[ArtifactRecord, ...], tuple[RecordBase, ...], JobRecord | None, JobRecord | None, Path]:
    resolved = path.resolve()
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    source = record_from_dict(payload["source"])
    if not isinstance(source, SourceRecord):
        raise TypeError("correlation report did not contain a SourceRecord")
    artifacts = tuple(
        record
        for record in (record_from_dict(item) for item in payload.get("input_artifacts", []))
        if isinstance(record, ArtifactRecord)
    )
    correlated_records = tuple(record_from_dict(item) for item in payload.get("correlated_records", []))
    completed_correlate_job = None
    maybe_completed = payload.get("completed_correlate_job")
    if isinstance(maybe_completed, dict):
        record = record_from_dict(maybe_completed)
        if isinstance(record, JobRecord) and record.stage == "correlate":
            completed_correlate_job = record
    queued_store_job = None
    maybe_queued = payload.get("queued_store_job")
    if isinstance(maybe_queued, dict):
        record = record_from_dict(maybe_queued)
        if isinstance(record, JobRecord) and record.stage == "store":
            queued_store_job = record
    return source, artifacts, correlated_records, completed_correlate_job, queued_store_job, resolved


def _load_store_report(
    path: Path,
) -> tuple[SourceRecord, tuple[ArtifactRecord, ...], JobRecord | None, JobRecord | None, Path, Path]:
    resolved = path.resolve()
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    source = record_from_dict(payload["source"])
    if not isinstance(source, SourceRecord):
        raise TypeError("store report did not contain a SourceRecord")
    artifacts = tuple(
        record
        for record in (record_from_dict(item) for item in payload.get("input_artifacts", []))
        if isinstance(record, ArtifactRecord)
    )
    completed_store_job = None
    maybe_completed = payload.get("completed_store_job")
    if isinstance(maybe_completed, dict):
        record = record_from_dict(maybe_completed)
        if isinstance(record, JobRecord) and record.stage == "store":
            completed_store_job = record
    queued_present_job = None
    maybe_queued = payload.get("queued_present_job")
    if isinstance(maybe_queued, dict):
        record = record_from_dict(maybe_queued)
        if isinstance(record, JobRecord) and record.stage == "present":
            queued_present_job = record
    database_path = Path(str(payload.get("database_path") or "")).resolve()
    return source, artifacts, completed_store_job, queued_present_job, resolved, database_path


def _derive_output_root(path: Path, *, stage_dir: str) -> Path:
    if stage_dir == "intake" and len(path.parents) >= 4 and path.parents[2].name == "intake":
        return path.parents[3]
    if stage_dir == "extract" and len(path.parents) >= 4 and path.parents[2].name == "extract":
        return path.parents[3]
    if stage_dir == "recover" and len(path.parents) >= 4 and path.parents[2].name == "recover":
        return path.parents[3]
    if stage_dir == "normalize" and len(path.parents) >= 4 and path.parents[2].name == "normalize":
        return path.parents[3]
    if stage_dir == "correlate" and len(path.parents) >= 4 and path.parents[2].name == "correlate":
        return path.parents[3]
    if stage_dir == "store" and len(path.parents) >= 4 and path.parents[2].name == "store":
        return path.parents[3]
    return path.parent


def _artifact_accepts(input_types: tuple[str, ...], artifact: ArtifactRecord) -> bool:
    accepted = {value.lower() for value in input_types}
    if "*" in accepted:
        return True
    if artifact.artifact_type.lower() in accepted:
        return True
    if artifact.media_type.lower() in accepted:
        return True
    return False


def _extractor_accepts(input_types: tuple[str, ...], artifact: ArtifactRecord) -> bool:
    return _artifact_accepts(input_types, artifact)


def _collect_artifact_records(
    input_artifacts: tuple[ArtifactRecord, ...],
    records: tuple[RecordBase, ...] | list[RecordBase],
) -> tuple[ArtifactRecord, ...]:
    rows: list[ArtifactRecord] = []
    seen: set[str] = set()
    for artifact in (*input_artifacts, *(record for record in records if isinstance(record, ArtifactRecord))):
        if artifact.id in seen:
            continue
        seen.add(artifact.id)
        rows.append(artifact)
    return tuple(rows)


def _normalize_queue_stages(stages: tuple[str, ...] | list[str] | object) -> tuple[str, ...]:
    rows: list[str] = []
    seen: set[str] = set()
    values = [stages] if isinstance(stages, str) else list(stages or QUEUE_STAGE_ORDER)
    for value in values:
        text = str(value or "").strip().lower()
        if not text or text in seen:
            continue
        if text not in QUEUE_STAGE_ORDER:
            raise ValueError(f"unsupported queue stage: {text}")
        seen.add(text)
        rows.append(text)
    return tuple(rows or QUEUE_STAGE_ORDER)


def _read_json_payload(path: Path) -> tuple[dict[str, object], str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, str(exc)
    if not isinstance(payload, dict):
        return {}, "queue payload must be a JSON object"
    return payload, ""


def _queued_reference_path(queue_payload: dict[str, object], *, stage: str) -> str:
    if stage == "extract":
        return str(queue_payload.get("source_manifest_path") or "")
    if stage == "recover":
        return str(queue_payload.get("extract_report_path") or "")
    if stage == "normalize":
        return str(queue_payload.get("recover_report_path") or queue_payload.get("extract_report_path") or "")
    if stage == "correlate":
        return str(queue_payload.get("normalize_report_path") or "")
    if stage == "store":
        return str(queue_payload.get("correlation_report_path") or "")
    if stage == "present":
        return str(queue_payload.get("store_report_path") or "")
    return ""


def _archive_queue_payload(
    output_root: Path,
    *,
    stage: str,
    queue_path: Path,
    queue_payload: dict[str, object],
    archive_state: str,
    result: dict[str, object],
) -> Path:
    archive_dir = output_root / "queues" / archive_state / stage
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_name = f"{queue_path.stem}__{_timestamp_slug(utc_now())}.json"
    archive_path = archive_dir / archive_name
    archive_payload = {
        "schema_version": 1,
        "archived_at": utc_now(),
        "archive_state": archive_state,
        "stage": stage,
        "queue_path": str(queue_path),
        "queue": dict(queue_payload),
        "result": dict(result),
    }
    archive_path.write_text(json.dumps(archive_payload, indent=2), encoding="utf-8")
    if queue_path.exists():
        queue_path.unlink()
    return archive_path.resolve()


def _timestamp_slug(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "unknown"
    return "".join(char if char.isalnum() else "_" for char in text)


def _remove_generated_queue_files(output_root: Path, artifact_paths: tuple[str, ...]) -> None:
    queues_root = (output_root / "queues").resolve()
    for value in artifact_paths:
        path = Path(str(value)).resolve()
        if not path.exists() or path.suffix.lower() != ".json":
            continue
        try:
            relative = path.relative_to(queues_root)
        except ValueError:
            continue
        parts = relative.parts
        if not parts or parts[0] not in QUEUE_STAGE_ORDER:
            continue
        path.unlink()


def _plugin_tool_statuses(
    tool_names: tuple[str, ...],
    config: dict[str, object],
    workspace_root: Path,
) -> tuple[dict[str, object], ...]:
    return tuple(_plugin_tool_status(tool_name, config, workspace_root) for tool_name in tool_names)


def _plugin_tool_status(tool_name: str, config: dict[str, object], workspace_root: Path) -> dict[str, object]:
    configured_command = config.get(f"{tool_name}_command")
    if isinstance(configured_command, (list, tuple)):
        parts = tuple(str(item).strip() for item in configured_command if str(item).strip())
        if parts:
            executable = parts[0]
            resolved = _resolve_executable(executable, workspace_root)
            return {
                "tool": tool_name,
                "available": bool(resolved),
                "source": "configured_command",
                "location": str(resolved or executable),
            }
    elif str(configured_command or "").strip():
        executable = str(configured_command).strip().split()[0]
        resolved = _resolve_executable(executable, workspace_root)
        return {
            "tool": tool_name,
            "available": bool(resolved),
            "source": "configured_command",
            "location": str(resolved or executable),
        }

    configured_path = str(config.get(f"{tool_name}_path") or "").strip()
    if configured_path:
        candidate = Path(configured_path).expanduser()
        if not candidate.is_absolute():
            candidate = (workspace_root / candidate).resolve()
        else:
            candidate = candidate.resolve()
        return {
            "tool": tool_name,
            "available": candidate.exists(),
            "source": "configured_path",
            "location": str(candidate),
        }

    resolved = shutil.which(tool_name)
    return {
        "tool": tool_name,
        "available": bool(resolved),
        "source": "path_lookup",
        "location": str(resolved or ""),
    }


def _resolve_executable(executable: str, workspace_root: Path) -> Path | str | None:
    text = str(executable or "").strip()
    if not text:
        return None
    candidate = Path(text).expanduser()
    if candidate.is_absolute() or any(sep in text for sep in ("/", "\\")):
        resolved = (workspace_root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
        return resolved if resolved.exists() else None
    resolved_text = shutil.which(text)
    if resolved_text:
        return Path(resolved_text).resolve()
    return None


def _filter_health_messages(
    messages: tuple[str, ...],
    tool_statuses: tuple[dict[str, object], ...],
) -> tuple[str, ...]:
    available_tools = {
        str(item.get("tool") or "").strip()
        for item in tool_statuses
        if bool(item.get("available"))
    }
    rows: list[str] = []
    for message in messages:
        text = str(message or "").strip()
        if not text:
            continue
        if text.startswith("optional tool unavailable:"):
            tool_name = text.split(":", 1)[1].strip()
            if tool_name in available_tools:
                continue
        if text in rows:
            continue
        rows.append(text)
    return tuple(rows)


def _plugin_status_label(
    *,
    enabled: bool,
    missing_tools: tuple[str, ...],
    health_messages: tuple[str, ...],
) -> str:
    if not enabled:
        return "disabled"
    if missing_tools:
        return "optional_tool_missing"
    if health_messages:
        return "attention"
    return "ready"


def _plugin_status_summary_text(
    *,
    status: str,
    missing_tools: tuple[str, ...],
    health_messages: tuple[str, ...],
) -> str:
    if status == "ready":
        return "Ready"
    if status == "disabled":
        return "Disabled"
    if status == "optional_tool_missing":
        return f"Missing optional tool: {', '.join(missing_tools)}"
    if health_messages:
        return "; ".join(health_messages[:2])
    return "Needs attention"


def _summarize_plugin_statuses(statuses: tuple[dict[str, object], ...]) -> dict[str, object]:
    counts = {
        "plugin_count": len(statuses),
        "ready_count": 0,
        "attention_count": 0,
        "optional_tool_missing_count": 0,
        "disabled_count": 0,
    }
    type_counts: dict[str, int] = {}
    for item in statuses:
        status = str(item.get("status") or "")
        if status == "ready":
            counts["ready_count"] += 1
        elif status == "optional_tool_missing":
            counts["optional_tool_missing_count"] += 1
        elif status == "disabled":
            counts["disabled_count"] += 1
        else:
            counts["attention_count"] += 1
        plugin_type = str(item.get("plugin_type") or "")
        if plugin_type:
            type_counts[plugin_type] = type_counts.get(plugin_type, 0) + 1
    return {
        **counts,
        "type_counts": type_counts,
    }
