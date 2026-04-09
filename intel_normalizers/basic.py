from __future__ import annotations

from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit

from intel_core import (
    Confidence,
    EventRecord,
    IdentityRecord,
    IndicatorRecord,
    PluginExecutionContext,
    PluginManifest,
    PluginResult,
    Provenance,
    RecordBase,
    RelationshipRecord,
    canonical_fingerprint,
    record_from_dict,
    record_to_dict,
    stable_record_id,
)


class CanonicalRecordNormalizerPlugin:
    manifest = PluginManifest(
        name="canonical_record_normalizer",
        version="0.1.0",
        plugin_type="normalizer",
        description="Normalize extracted records, derive canonical identity records, and deduplicate by canonical fingerprint.",
        capabilities=("record-normalization", "record-deduplication", "identity-derivation"),
        input_types=("record-batch",),
        output_types=("record-batch",),
        policy_tags=("passive-analysis",),
    )

    def healthcheck(self) -> tuple[str, ...]:
        return ()

    def normalize(self, context: PluginExecutionContext, records: Iterable[RecordBase]) -> PluginResult:
        input_records = list(records)
        base_records = [self._normalize_record(record) for record in input_records]

        derived_records: list[RecordBase] = []
        for record in base_records:
            derived_records.extend(self._derive_records(context, record))

        combined = [*base_records, *derived_records]
        deduped_records, duplicate_map = self._dedupe_records(combined)
        remapped_records = [self._remap_references(record, duplicate_map) for record in deduped_records]
        final_records, secondary_duplicate_map = self._dedupe_records(remapped_records)
        all_duplicate_map = {**duplicate_map, **secondary_duplicate_map}

        summary = EventRecord(
            id=stable_record_id(
                "event",
                next((record.source_id for record in final_records if record.source_id), ""),
                context.case_id,
                "normalization_summary",
            ),
            source_id=next((record.source_id for record in final_records if record.source_id), ""),
            case_id=context.case_id,
            event_type="normalization_summary",
            title="Record normalization summary",
            summary="Normalized extracted records, derived canonical identity records, and removed duplicate rows.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="normalize+dedupe",
                notes="Normalization stage summary",
            ),
            confidence=Confidence(score=0.92),
            tags=("normalize", "summary"),
            attributes={
                "input_count": str(len(input_records)),
                "normalized_count": str(len(final_records)),
                "duplicate_count": str(len(all_duplicate_map)),
            },
        )

        return PluginResult(
            records=(*final_records, summary),
            metrics={
                "normalized_count": len(final_records),
                "duplicate_count": len(all_duplicate_map),
                "identity_count": sum(1 for record in final_records if getattr(record, "record_type", "") == "identity"),
            },
            warnings=tuple(
                f"deduplicated {source_id} -> {target_id}"
                for source_id, target_id in sorted(all_duplicate_map.items())
            ),
        )

    def _normalize_record(self, record: RecordBase) -> RecordBase:
        payload = record_to_dict(record)

        if isinstance(record, IndicatorRecord):
            payload["value"] = self._normalize_indicator_value(record.indicator_type, record.value)
            payload["normalized_value"] = self._normalize_indicator_value(
                record.indicator_type,
                record.normalized_value or record.value,
            )
        elif getattr(record, "record_type", "") == "artifact" and payload.get("path"):
            path = Path(str(payload["path"]))
            if path.exists():
                payload["path"] = str(path.resolve())
        elif getattr(record, "record_type", "") == "event":
            timestamp = str(payload.get("timestamp") or payload.get("observed_at") or "").strip()
            if timestamp:
                payload["timestamp"] = timestamp

        payload["tags"] = tuple(dict.fromkeys(str(tag).strip() for tag in payload.get("tags", []) if str(tag).strip()))
        payload["attributes"] = {
            str(key): str(value)
            for key, value in dict(payload.get("attributes", {}) or {}).items()
            if str(key).strip()
        }
        return record_from_dict(payload)

    def _derive_records(self, context: PluginExecutionContext, record: RecordBase) -> list[RecordBase]:
        if not isinstance(record, IndicatorRecord):
            return []
        if record.indicator_type != "email":
            return []

        identity = IdentityRecord(
            id=stable_record_id("identity", record.id, record.normalized_value or record.value, "email"),
            source_id=record.source_id,
            case_id=context.case_id or record.case_id,
            identity_type="email",
            value=record.value,
            normalized_value=record.normalized_value or record.value.lower(),
            provenance=Provenance(
                plugin=self.manifest.name,
                method="derive_identity_from_indicator",
                source_refs=(record.source_id,),
                parent_refs=(record.id,),
            ),
            confidence=Confidence(score=0.88),
            tags=("normalize", "identity", "email"),
            attributes={"indicator_id": record.id},
        )
        relationship = RelationshipRecord(
            id=stable_record_id(
                "relationship",
                record.id,
                identity.id,
                "indicator_identifies_identity",
            ),
            source_id=record.source_id,
            case_id=context.case_id or record.case_id,
            relationship_type="indicator_identifies_identity",
            source_ref=record.id,
            target_ref=identity.id,
            reason="canonical normalizer derived an identity from an email indicator",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="derive_identity_link",
                source_refs=(record.source_id,),
                parent_refs=(record.id, identity.id),
            ),
            confidence=Confidence(score=0.88),
            tags=("normalize", "identity-link"),
        )
        return [identity, relationship]

    def _dedupe_records(self, records: Iterable[RecordBase]) -> tuple[list[RecordBase], dict[str, str]]:
        deduped: list[RecordBase] = []
        fingerprint_to_id: dict[str, str] = {}
        duplicate_map: dict[str, str] = {}
        for record in records:
            fingerprint = canonical_fingerprint(record)
            canonical_id = fingerprint_to_id.get(fingerprint)
            if canonical_id:
                duplicate_map[record.id] = canonical_id
                continue
            fingerprint_to_id[fingerprint] = record.id
            deduped.append(record)
        return deduped, duplicate_map

    def _remap_references(self, record: RecordBase, duplicate_map: dict[str, str]) -> RecordBase:
        if not duplicate_map:
            return record
        payload = record_to_dict(record)
        if isinstance(record, RelationshipRecord):
            payload["source_ref"] = duplicate_map.get(record.source_ref, record.source_ref)
            payload["target_ref"] = duplicate_map.get(record.target_ref, record.target_ref)
        if getattr(record, "record_type", "") == "event":
            payload["actor_refs"] = tuple(duplicate_map.get(value, value) for value in payload.get("actor_refs", []))
            payload["artifact_refs"] = tuple(duplicate_map.get(value, value) for value in payload.get("artifact_refs", []))
        if getattr(record, "record_type", "") == "timeline":
            payload["event_refs"] = tuple(duplicate_map.get(value, value) for value in payload.get("event_refs", []))
        if getattr(record, "record_type", "") == "job":
            payload["input_refs"] = tuple(duplicate_map.get(value, value) for value in payload.get("input_refs", []))
            payload["output_refs"] = tuple(duplicate_map.get(value, value) for value in payload.get("output_refs", []))
        if getattr(record, "record_type", "") == "artifact" and payload.get("parent_artifact_id"):
            payload["parent_artifact_id"] = duplicate_map.get(str(payload["parent_artifact_id"]), str(payload["parent_artifact_id"]))
        return record_from_dict(payload)

    def _normalize_indicator_value(self, indicator_type: str, value: str) -> str:
        text = str(value or "").strip()
        normalized_type = str(indicator_type or "").strip().lower()
        if not text:
            return ""
        if normalized_type in {"email", "domain"}:
            return text.lower().rstrip(".")
        if normalized_type == "url":
            try:
                split = urlsplit(text)
            except ValueError:
                return text
            netloc = split.netloc.lower()
            scheme = split.scheme.lower()
            path = split.path or "/"
            return urlunsplit((scheme, netloc, path, split.query, ""))
        if normalized_type == "ipv4":
            parts = text.split(".")
            if len(parts) != 4:
                return text
            normalized_parts = []
            for part in parts:
                try:
                    number = int(part, 10)
                except ValueError:
                    return text
                if number < 0 or number > 255:
                    return text
                normalized_parts.append(str(number))
            return ".".join(normalized_parts)
        return text
