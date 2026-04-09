from __future__ import annotations

import json
import shutil
import subprocess
from hashlib import sha256
from pathlib import Path
from typing import Iterable

from intel_core import (
    ArtifactRecord,
    Confidence,
    EventRecord,
    IndicatorRecord,
    PluginExecutionContext,
    PluginManifest,
    PluginResult,
    Provenance,
    RelationshipRecord,
    stable_record_id,
)
from intel_storage import stage_object_dir


class ExifToolMetadataExtractorPlugin:
    manifest = PluginManifest(
        name="exiftool_metadata_extractor",
        version="0.1.0",
        plugin_type="extractor",
        description="Optionally enrich artifacts with passive metadata from exiftool when it is installed.",
        capabilities=("external-metadata", "exiftool-enrichment"),
        input_types=("*",),
        output_types=("event",),
        required_tools=("exiftool",),
        policy_tags=("passive-analysis",),
    )

    def healthcheck(self) -> tuple[str, ...]:
        return () if shutil.which("exiftool") else ("optional tool unavailable: exiftool",)

    def extract(self, context: PluginExecutionContext, artifact: ArtifactRecord) -> PluginResult:
        path = Path(artifact.path)
        if not path.exists():
            return PluginResult(errors=(f"artifact path not found: {path}",))

        command, explicitly_configured = _resolve_command(context, "exiftool")
        if not command:
            warnings = ("configured exiftool command was not found",) if explicitly_configured else ()
            return PluginResult(
                warnings=warnings,
                metrics={"exiftool_available": False, "exiftool_field_count": 0},
            )

        try:
            completed = subprocess.run(
                [*command, "-json", str(path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except OSError as exc:
            return PluginResult(
                warnings=(f"exiftool execution failed for {path.name}: {exc}",),
                metrics={"exiftool_available": True, "exiftool_field_count": 0},
            )

        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or f"exit code {completed.returncode}").strip()
            return PluginResult(
                warnings=(f"exiftool failed for {path.name}: {detail}",),
                metrics={"exiftool_available": True, "exiftool_field_count": 0},
            )

        try:
            payload = json.loads(completed.stdout or "[]")
        except json.JSONDecodeError as exc:
            return PluginResult(
                warnings=(f"exiftool returned invalid JSON for {path.name}: {exc}",),
                metrics={"exiftool_available": True, "exiftool_field_count": 0},
            )

        metadata = payload[0] if isinstance(payload, list) and payload else {}
        if not isinstance(metadata, dict):
            metadata = {}

        report_dir = stage_object_dir(context.output_root, "extract", artifact.source_id, artifact.id, "external")
        report_path = report_dir / "exiftool.json"
        report_text = json.dumps(metadata, indent=2, ensure_ascii=True)
        report_path.write_text(report_text, encoding="utf-8")

        filtered_items = [(str(key), _stringify(value)) for key, value in metadata.items() if str(key) != "SourceFile"]
        selected = _selected_metadata_fields(metadata)
        sample_fields = " | ".join(f"{key}={value}" for key, value in filtered_items[:8])

        event = EventRecord(
            id=stable_record_id("event", artifact.id, "external_metadata_enrichment", "exiftool"),
            source_id=artifact.source_id,
            case_id=context.case_id or artifact.case_id,
            event_type="external_metadata_enrichment",
            title=f"External metadata enrichment for {path.name}",
            artifact_refs=(artifact.id,),
            summary="Captured passive file metadata through an optional exiftool adapter.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="exiftool-json",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
                details={"report_path": str(report_path)},
            ),
            confidence=Confidence(score=0.9),
            tags=("extract", "external", "exiftool"),
            attributes={
                "artifact_id": artifact.id,
                "tool": "exiftool",
                "report_path": str(report_path),
                "field_count": str(len(filtered_items)),
                "sample_fields": sample_fields,
                **selected,
            },
        )
        return PluginResult(
            records=(event,),
            artifact_paths=(str(report_path),),
            metrics={"exiftool_available": True, "exiftool_field_count": len(filtered_items)},
        )


class YaraRuleExtractorPlugin:
    manifest = PluginManifest(
        name="yara_rule_extractor",
        version="0.1.0",
        plugin_type="extractor",
        description="Optionally scan artifacts with YARA rules when both yara and a rules path are configured.",
        capabilities=("external-rules", "yara-enrichment"),
        input_types=("*",),
        output_types=("event", "indicator", "relationship"),
        required_tools=("yara",),
        policy_tags=("passive-analysis",),
    )

    def healthcheck(self) -> tuple[str, ...]:
        return () if shutil.which("yara") else ("optional tool unavailable: yara",)

    def extract(self, context: PluginExecutionContext, artifact: ArtifactRecord) -> PluginResult:
        path = Path(artifact.path)
        if not path.exists():
            return PluginResult(errors=(f"artifact path not found: {path}",))

        rules_path = _resolve_optional_path(
            context,
            context.config.get("yara_rules_path") or context.config.get("yara_rules"),
        )
        if rules_path is None:
            return PluginResult(metrics={"yara_available": bool(shutil.which("yara")), "yara_configured": False, "yara_match_count": 0})
        if not rules_path.exists():
            return PluginResult(
                warnings=(f"configured YARA rules path was not found: {rules_path}",),
                metrics={"yara_available": bool(shutil.which("yara")), "yara_configured": True, "yara_match_count": 0},
            )

        command, explicitly_configured = _resolve_command(context, "yara")
        if not command:
            warnings = ("configured yara command was not found",) if explicitly_configured else ()
            return PluginResult(
                warnings=warnings,
                metrics={"yara_available": False, "yara_configured": True, "yara_match_count": 0},
            )

        try:
            completed = subprocess.run(
                [*command, str(rules_path), str(path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except OSError as exc:
            return PluginResult(
                warnings=(f"yara execution failed for {path.name}: {exc}",),
                metrics={"yara_available": True, "yara_configured": True, "yara_match_count": 0},
            )

        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()
        if completed.returncode != 0 and not stdout:
            detail = stderr or f"exit code {completed.returncode}"
            return PluginResult(
                warnings=(f"yara failed for {path.name}: {detail}",),
                metrics={"yara_available": True, "yara_configured": True, "yara_match_count": 0},
            )

        rule_names = _parse_yara_rule_names(stdout.splitlines())
        report_dir = stage_object_dir(context.output_root, "extract", artifact.source_id, artifact.id, "external")
        report_path = report_dir / "yara_matches.txt"
        report_path.write_text(stdout, encoding="utf-8")

        if not rule_names:
            return PluginResult(
                artifact_paths=(str(report_path),),
                metrics={"yara_available": True, "yara_configured": True, "yara_match_count": 0},
            )

        indicators = []
        relationships = []
        for rule_name in rule_names:
            indicator = IndicatorRecord(
                id=stable_record_id("indicator", artifact.id, "yara_rule", rule_name.lower()),
                source_id=artifact.source_id,
                case_id=context.case_id or artifact.case_id,
                indicator_type="yara_rule",
                value=rule_name,
                normalized_value=rule_name.lower(),
                provenance=Provenance(
                    plugin=self.manifest.name,
                    method="yara-match",
                    source_refs=(artifact.source_id,),
                    parent_refs=(artifact.id,),
                ),
                confidence=Confidence(score=0.91),
                tags=("extract", "external", "yara"),
                attributes={"artifact_id": artifact.id, "rules_path": str(rules_path)},
            )
            indicators.append(indicator)
            relationships.append(
                RelationshipRecord(
                    id=stable_record_id("relationship", artifact.id, indicator.id, "artifact_matches_indicator"),
                    source_id=artifact.source_id,
                    case_id=context.case_id or artifact.case_id,
                    relationship_type="artifact_matches_indicator",
                    source_ref=artifact.id,
                    target_ref=indicator.id,
                    reason=f"{self.manifest.name} matched YARA rule {rule_name}",
                    provenance=Provenance(
                        plugin=self.manifest.name,
                        method="yara-link",
                        source_refs=(artifact.source_id,),
                        parent_refs=(artifact.id, indicator.id),
                    ),
                    confidence=Confidence(score=0.91),
                    tags=("extract", "external", "link"),
                )
            )

        event = EventRecord(
            id=stable_record_id("event", artifact.id, "external_rule_match", "yara"),
            source_id=artifact.source_id,
            case_id=context.case_id or artifact.case_id,
            event_type="external_rule_match",
            title=f"YARA rule matches for {path.name}",
            artifact_refs=(artifact.id,),
            actor_refs=tuple(indicator.id for indicator in indicators),
            summary="Matched configured passive YARA rules against the artifact.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="yara-cli",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
                details={"report_path": str(report_path), "rules_path": str(rules_path)},
            ),
            confidence=Confidence(score=0.91),
            tags=("extract", "external", "yara"),
            attributes={
                "artifact_id": artifact.id,
                "tool": "yara",
                "report_path": str(report_path),
                "rules_path": str(rules_path),
                "match_count": str(len(rule_names)),
                "rule_names": ", ".join(rule_names),
            },
        )
        return PluginResult(
            records=(event, *indicators, *relationships),
            artifact_paths=(str(report_path),),
            metrics={"yara_available": True, "yara_configured": True, "yara_match_count": len(rule_names)},
        )


def _resolve_command(
    context: PluginExecutionContext,
    tool_name: str,
) -> tuple[tuple[str, ...], bool]:
    configured_command = context.config.get(f"{tool_name}_command")
    if isinstance(configured_command, (list, tuple)):
        parts = tuple(str(item).strip() for item in configured_command if str(item).strip())
        if parts:
            return parts, True

    configured_path = str(context.config.get(f"{tool_name}_path") or "").strip()
    if configured_path:
        candidate = _resolve_optional_path(context, configured_path)
        if candidate is not None and candidate.exists():
            return (str(candidate),), True
        return (), True

    resolved = shutil.which(tool_name)
    return ((str(resolved),), False) if resolved else ((), False)


def _resolve_optional_path(context: PluginExecutionContext, value: object) -> Path | None:
    text = str(value or "").strip()
    if not text:
        return None
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = (context.workspace_root / path).resolve()
    else:
        path = path.resolve()
    return path


def _selected_metadata_fields(metadata: dict[str, object]) -> dict[str, str]:
    rows = {
        "file_type": _stringify(metadata.get("FileType")),
        "mime_type": _stringify(metadata.get("MIMEType")),
        "title": _stringify(metadata.get("Title")),
        "author": _stringify(metadata.get("Author")),
        "creator": _stringify(metadata.get("Creator")),
        "software": _stringify(metadata.get("Software")),
        "producer": _stringify(metadata.get("Producer")),
        "company_name": _stringify(metadata.get("CompanyName")),
        "create_date": _stringify(metadata.get("CreateDate")),
        "modify_date": _stringify(metadata.get("ModifyDate")),
    }
    return {key: value for key, value in rows.items() if value}


def _parse_yara_rule_names(lines: Iterable[str]) -> tuple[str, ...]:
    rows: list[str] = []
    seen = set()
    for line in lines:
        text = str(line or "").strip()
        if not text or text.startswith("0x") or text.startswith("$"):
            continue
        rule_name = text.split(maxsplit=1)[0]
        if not rule_name or rule_name.lower().startswith("warning"):
            continue
        if rule_name in seen:
            continue
        seen.add(rule_name)
        rows.append(rule_name)
    return tuple(rows)


def _stringify(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_stringify(item) for item in value if _stringify(item))
    if isinstance(value, dict):
        encoded = json.dumps(value, sort_keys=True, ensure_ascii=True)
        return encoded[:240]
    return str(value).strip()
