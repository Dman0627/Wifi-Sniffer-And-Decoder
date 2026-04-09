from __future__ import annotations

import json
import plistlib
import sqlite3
from pathlib import Path

from intel_core import (
    ArtifactRecord,
    Confidence,
    EventRecord,
    PluginExecutionContext,
    PluginManifest,
    PluginResult,
    Provenance,
    stable_record_id,
)

MAX_SQLITE_TABLES = 12


class SystemArtifactMetadataExtractorPlugin:
    manifest = PluginManifest(
        name="system_artifact_metadata_extractor",
        version="0.1.0",
        plugin_type="extractor",
        description="Extract passive summaries from SQLite databases, plists, EVTX files, and registry artifacts.",
        capabilities=("sqlite-schema-summary", "plist-summary", "evtx-header-summary", "registry-summary"),
        input_types=("*",),
        output_types=("event",),
        policy_tags=("passive-analysis", "system-artifact"),
    )

    def healthcheck(self) -> tuple[str, ...]:
        return ()

    def extract(self, context: PluginExecutionContext, artifact: ArtifactRecord) -> PluginResult:
        path = Path(artifact.path)
        if not path.exists():
            return PluginResult(errors=(f"artifact path not found: {path}",))

        event = (
            self._extract_sqlite(context, artifact, path)
            or self._extract_plist(context, artifact, path)
            or self._extract_evtx(context, artifact, path)
            or self._extract_registry(context, artifact, path)
        )
        if event is None:
            return PluginResult(metrics={"system_artifact_event_count": 0})
        return PluginResult(records=(event,), metrics={"system_artifact_event_count": 1})

    def _extract_sqlite(
        self,
        context: PluginExecutionContext,
        artifact: ArtifactRecord,
        path: Path,
    ) -> EventRecord | None:
        if path.suffix.lower() not in {".sqlite", ".db"}:
            return None
        try:
            with path.open("rb") as handle:
                signature = handle.read(16)
        except OSError:
            return None
        if signature != b"SQLite format 3\x00":
            return None

        table_names: list[str] = []
        index_count = 0
        view_count = 0
        trigger_count = 0
        row_samples: list[str] = []
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
            rows = connection.execute(
                """
                SELECT type, name
                FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                ORDER BY type, name
                """
            ).fetchall()
            for row_type, name in rows:
                row_type = str(row_type)
                name = str(name)
                if row_type == "table":
                    table_names.append(name)
                elif row_type == "index":
                    index_count += 1
                elif row_type == "view":
                    view_count += 1
                elif row_type == "trigger":
                    trigger_count += 1
            for table_name in table_names[:5]:
                try:
                    row_count = connection.execute(f'SELECT COUNT(*) FROM "{table_name}"').fetchone()[0]
                except sqlite3.DatabaseError:
                    continue
                row_samples.append(f"{table_name}:{row_count}")

        return EventRecord(
            id=stable_record_id("event", artifact.id, "system_artifact_metadata", "sqlite"),
            source_id=artifact.source_id,
            case_id=context.case_id or artifact.case_id,
            event_type="system_artifact_metadata",
            title=f"System artifact summary for {path.name}",
            artifact_refs=(artifact.id,),
            summary="Extracted passive SQLite schema and object inventory metadata.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="sqlite-master",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
            ),
            confidence=Confidence(score=0.93),
            tags=("extract", "system-artifact", "sqlite"),
            attributes={
                "artifact_id": artifact.id,
                "artifact_format": "sqlite",
                "table_count": str(len(table_names)),
                "table_names": ", ".join(table_names[:MAX_SQLITE_TABLES]),
                "index_count": str(index_count),
                "view_count": str(view_count),
                "trigger_count": str(trigger_count),
                "row_samples": ", ".join(row_samples),
            },
        )

    def _extract_plist(
        self,
        context: PluginExecutionContext,
        artifact: ArtifactRecord,
        path: Path,
    ) -> EventRecord | None:
        if path.suffix.lower() != ".plist":
            return None
        try:
            with path.open("rb") as handle:
                payload = plistlib.load(handle)
        except (OSError, plistlib.InvalidFileException, ValueError):
            return None

        top_level_type = type(payload).__name__.lower()
        top_level_keys = []
        item_count = 0
        if isinstance(payload, dict):
            top_level_keys = sorted(str(key) for key in payload.keys())
            item_count = len(payload)
        elif isinstance(payload, list):
            item_count = len(payload)

        return EventRecord(
            id=stable_record_id("event", artifact.id, "system_artifact_metadata", "plist"),
            source_id=artifact.source_id,
            case_id=context.case_id or artifact.case_id,
            event_type="system_artifact_metadata",
            title=f"System artifact summary for {path.name}",
            artifact_refs=(artifact.id,),
            summary="Extracted passive plist structure and top-level metadata.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="plistlib",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
            ),
            confidence=Confidence(score=0.92),
            tags=("extract", "system-artifact", "plist"),
            attributes={
                "artifact_id": artifact.id,
                "artifact_format": "plist",
                "top_level_type": top_level_type,
                "item_count": str(item_count),
                "top_level_keys": ", ".join(top_level_keys[:12]),
                "payload_preview": _preview_payload(payload),
            },
        )

    def _extract_evtx(
        self,
        context: PluginExecutionContext,
        artifact: ArtifactRecord,
        path: Path,
    ) -> EventRecord | None:
        if path.suffix.lower() != ".evtx":
            return None
        try:
            data = path.read_bytes()[:4096]
        except OSError:
            return None
        if not data.startswith(b"ElfFile\x00"):
            return None

        chunk_count = data.count(b"ElfChnk")
        return EventRecord(
            id=stable_record_id("event", artifact.id, "system_artifact_metadata", "evtx"),
            source_id=artifact.source_id,
            case_id=context.case_id or artifact.case_id,
            event_type="system_artifact_metadata",
            title=f"System artifact summary for {path.name}",
            artifact_refs=(artifact.id,),
            summary="Extracted passive EVTX header metadata and quick chunk heuristics.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="evtx-header",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
            ),
            confidence=Confidence(score=0.88),
            tags=("extract", "system-artifact", "evtx"),
            attributes={
                "artifact_id": artifact.id,
                "artifact_format": "evtx",
                "header_signature": "ElfFile",
                "header_scan_chunk_markers": str(chunk_count),
                "size_bytes": str(path.stat().st_size),
            },
        )

    def _extract_registry(
        self,
        context: PluginExecutionContext,
        artifact: ArtifactRecord,
        path: Path,
    ) -> EventRecord | None:
        suffix = path.suffix.lower()
        try:
            data = path.read_bytes()[:4096]
        except OSError:
            return None

        artifact_format = ""
        summary = ""
        attributes = {
            "artifact_id": artifact.id,
            "size_bytes": str(path.stat().st_size),
        }

        if suffix in {".hve", ".dat"} and data.startswith(b"regf"):
            artifact_format = "registry_hive"
            summary = "Extracted passive Windows registry hive header metadata."
            sequence_primary = int.from_bytes(data[4:8], "little", signed=False) if len(data) >= 8 else 0
            sequence_secondary = int.from_bytes(data[8:12], "little", signed=False) if len(data) >= 12 else 0
            hive_name = data[48:112].split(b"\x00", 1)[0].decode("utf-16-le", errors="ignore").strip("\x00 ")
            attributes.update(
                {
                    "artifact_format": artifact_format,
                    "header_signature": "regf",
                    "sequence_primary": str(sequence_primary),
                    "sequence_secondary": str(sequence_secondary),
                    "hive_name": hive_name,
                }
            )
        elif suffix == ".reg":
            text = data.decode("utf-16", errors="ignore") if data.startswith(b"\xff\xfe") else data.decode("utf-8", errors="ignore")
            if "Windows Registry Editor" not in text:
                return None
            artifact_format = "registry_export"
            summary = "Extracted passive registry export summary metadata."
            preview_lines = [line.strip() for line in text.splitlines() if line.strip()][:5]
            attributes.update(
                {
                    "artifact_format": artifact_format,
                    "header_signature": "Windows Registry Editor",
                    "preview_lines": " | ".join(preview_lines),
                }
            )
        else:
            return None

        return EventRecord(
            id=stable_record_id("event", artifact.id, "system_artifact_metadata", artifact_format),
            source_id=artifact.source_id,
            case_id=context.case_id or artifact.case_id,
            event_type="system_artifact_metadata",
            title=f"System artifact summary for {path.name}",
            artifact_refs=(artifact.id,),
            summary=summary,
            provenance=Provenance(
                plugin=self.manifest.name,
                method="registry-header",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
            ),
            confidence=Confidence(score=0.9),
            tags=("extract", "system-artifact", "registry"),
            attributes=attributes,
        )


def _preview_payload(payload: object) -> str:
    try:
        encoded = json.dumps(payload, sort_keys=True, default=str)
    except TypeError:
        encoded = repr(payload)
    return encoded[:240]
