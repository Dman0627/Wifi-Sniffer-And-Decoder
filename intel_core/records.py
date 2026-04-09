from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, ClassVar, Mapping
from uuid import uuid4

CURRENT_SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_record_id(prefix: str) -> str:
    cleaned = "".join(char for char in str(prefix or "record").lower() if char.isalnum() or char == "_")
    cleaned = cleaned or "record"
    return f"{cleaned}_{uuid4().hex}"


def stable_record_id(prefix: str, *parts: object) -> str:
    cleaned = "".join(char for char in str(prefix or "record").lower() if char.isalnum() or char == "_")
    cleaned = cleaned or "record"
    payload = json.dumps(
        [_stable_part(value) for value in parts],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return f"{cleaned}_{sha256(payload.encode('utf-8')).hexdigest()[:32]}"


def _stable_part(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _stable_part(item) for key, item in sorted(value.items(), key=lambda entry: str(entry[0]))}
    if isinstance(value, (list, tuple, set)):
        return [_stable_part(item) for item in value]
    if isinstance(value, RecordBase):
        return record_to_dict(value)
    return "" if value is None else str(value)


def _tuple_of_strings(values: object) -> tuple[str, ...]:
    rows: list[str] = []
    seen = set()
    for value in list(values or []):
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        rows.append(text)
    return tuple(rows)


def _dict_of_strings(values: object) -> dict[str, str]:
    if not isinstance(values, Mapping):
        return {}
    return {
        str(key): str(value)
        for key, value in values.items()
        if str(key).strip()
    }


@dataclass(slots=True, kw_only=True)
class Provenance:
    plugin: str = ""
    method: str = ""
    source_refs: tuple[str, ...] = field(default_factory=tuple)
    parent_refs: tuple[str, ...] = field(default_factory=tuple)
    notes: str = ""
    details: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.plugin = str(self.plugin or "").strip()
        self.method = str(self.method or "").strip()
        self.source_refs = _tuple_of_strings(self.source_refs)
        self.parent_refs = _tuple_of_strings(self.parent_refs)
        self.notes = str(self.notes or "").strip()
        self.details = _dict_of_strings(self.details)

    @classmethod
    def from_dict(cls, payload: object) -> "Provenance":
        if not isinstance(payload, Mapping):
            return cls()
        return cls(
            plugin=str(payload.get("plugin") or ""),
            method=str(payload.get("method") or ""),
            source_refs=_tuple_of_strings(payload.get("source_refs")),
            parent_refs=_tuple_of_strings(payload.get("parent_refs")),
            notes=str(payload.get("notes") or ""),
            details=_dict_of_strings(payload.get("details")),
        )


@dataclass(slots=True, kw_only=True)
class Confidence:
    score: float = 0.5
    label: str = ""
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        self.score = float(self.score)
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("confidence score must be between 0.0 and 1.0")
        self.label = str(self.label or "").strip() or _confidence_label(self.score)
        self.reasons = _tuple_of_strings(self.reasons)

    @classmethod
    def from_dict(cls, payload: object) -> "Confidence":
        if not isinstance(payload, Mapping):
            return cls()
        return cls(
            score=float(payload.get("score", 0.5) or 0.5),
            label=str(payload.get("label") or ""),
            reasons=_tuple_of_strings(payload.get("reasons")),
        )


def _confidence_label(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.6:
        return "medium"
    if score >= 0.3:
        return "low"
    return "tentative"


@dataclass(slots=True, kw_only=True)
class RecordBase:
    id: str
    source_id: str = ""
    case_id: str = ""
    created_at: str = field(default_factory=utc_now)
    observed_at: str = ""
    provenance: Provenance = field(default_factory=Provenance)
    confidence: Confidence = field(default_factory=Confidence)
    tags: tuple[str, ...] = field(default_factory=tuple)
    attributes: dict[str, str] = field(default_factory=dict)
    schema_version: int = CURRENT_SCHEMA_VERSION

    record_type: ClassVar[str] = "record"

    def __post_init__(self) -> None:
        self.id = str(self.id or "").strip()
        if not self.id:
            raise ValueError("record id is required")
        self.source_id = str(self.source_id or self.id).strip()
        self.case_id = str(self.case_id or "").strip()
        self.created_at = str(self.created_at or utc_now()).strip()
        self.observed_at = str(self.observed_at or "").strip()
        self.tags = _tuple_of_strings(self.tags)
        self.attributes = _dict_of_strings(self.attributes)
        self.schema_version = int(self.schema_version or CURRENT_SCHEMA_VERSION)
        if self.schema_version <= 0:
            raise ValueError("schema_version must be positive")

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "RecordBase":
        kwargs = _record_kwargs(cls, payload)
        return cls(**kwargs)


@dataclass(slots=True, kw_only=True)
class SourceRecord(RecordBase):
    source_type: str
    locator: str
    display_name: str = ""
    collector: str = ""
    media_type: str = ""
    content_hash: str = ""
    size_bytes: int = 0

    record_type: ClassVar[str] = "source"

    def __post_init__(self) -> None:
        RecordBase.__post_init__(self)
        self.source_type = str(self.source_type or "").strip()
        self.locator = str(self.locator or "").strip()
        self.display_name = str(self.display_name or "").strip()
        self.collector = str(self.collector or "").strip()
        self.media_type = str(self.media_type or "").strip()
        self.content_hash = str(self.content_hash or "").strip().lower()
        self.size_bytes = int(self.size_bytes or 0)


@dataclass(slots=True, kw_only=True)
class ArtifactRecord(RecordBase):
    artifact_type: str
    path: str = ""
    media_type: str = ""
    sha256: str = ""
    size_bytes: int = 0
    parent_artifact_id: str = ""

    record_type: ClassVar[str] = "artifact"

    def __post_init__(self) -> None:
        RecordBase.__post_init__(self)
        self.artifact_type = str(self.artifact_type or "").strip()
        self.path = str(self.path or "").strip()
        self.media_type = str(self.media_type or "").strip()
        self.sha256 = str(self.sha256 or "").strip().lower()
        self.size_bytes = int(self.size_bytes or 0)
        self.parent_artifact_id = str(self.parent_artifact_id or "").strip()


@dataclass(slots=True, kw_only=True)
class IndicatorRecord(RecordBase):
    indicator_type: str
    value: str
    normalized_value: str = ""
    first_seen_at: str = ""
    last_seen_at: str = ""

    record_type: ClassVar[str] = "indicator"

    def __post_init__(self) -> None:
        RecordBase.__post_init__(self)
        self.indicator_type = str(self.indicator_type or "").strip()
        self.value = str(self.value or "").strip()
        self.normalized_value = str(self.normalized_value or "").strip()
        self.first_seen_at = str(self.first_seen_at or "").strip()
        self.last_seen_at = str(self.last_seen_at or "").strip()


@dataclass(slots=True, kw_only=True)
class IdentityRecord(RecordBase):
    identity_type: str
    value: str
    normalized_value: str = ""
    aliases: tuple[str, ...] = field(default_factory=tuple)

    record_type: ClassVar[str] = "identity"

    def __post_init__(self) -> None:
        RecordBase.__post_init__(self)
        self.identity_type = str(self.identity_type or "").strip()
        self.value = str(self.value or "").strip()
        self.normalized_value = str(self.normalized_value or "").strip()
        self.aliases = _tuple_of_strings(self.aliases)


@dataclass(slots=True, kw_only=True)
class CredentialRecord(RecordBase):
    material_type: str
    identifier: str = ""
    username: str = ""
    hash_type: str = ""
    secret_ref: str = ""
    status: str = "unverified"

    record_type: ClassVar[str] = "credential"

    def __post_init__(self) -> None:
        RecordBase.__post_init__(self)
        self.material_type = str(self.material_type or "").strip()
        self.identifier = str(self.identifier or "").strip()
        self.username = str(self.username or "").strip()
        self.hash_type = str(self.hash_type or "").strip()
        self.secret_ref = str(self.secret_ref or "").strip()
        self.status = str(self.status or "unverified").strip()


@dataclass(slots=True, kw_only=True)
class RelationshipRecord(RecordBase):
    relationship_type: str
    source_ref: str
    target_ref: str
    directed: bool = True
    reason: str = ""

    record_type: ClassVar[str] = "relationship"

    def __post_init__(self) -> None:
        RecordBase.__post_init__(self)
        self.relationship_type = str(self.relationship_type or "").strip()
        self.source_ref = str(self.source_ref or "").strip()
        self.target_ref = str(self.target_ref or "").strip()
        self.directed = bool(self.directed)
        self.reason = str(self.reason or "").strip()


@dataclass(slots=True, kw_only=True)
class EventRecord(RecordBase):
    event_type: str
    title: str
    timestamp: str = ""
    actor_refs: tuple[str, ...] = field(default_factory=tuple)
    artifact_refs: tuple[str, ...] = field(default_factory=tuple)
    summary: str = ""

    record_type: ClassVar[str] = "event"

    def __post_init__(self) -> None:
        RecordBase.__post_init__(self)
        self.event_type = str(self.event_type or "").strip()
        self.title = str(self.title or "").strip()
        self.timestamp = str(self.timestamp or "").strip()
        self.actor_refs = _tuple_of_strings(self.actor_refs)
        self.artifact_refs = _tuple_of_strings(self.artifact_refs)
        self.summary = str(self.summary or "").strip()


@dataclass(slots=True, kw_only=True)
class TimelineRecord(RecordBase):
    title: str
    start_time: str = ""
    end_time: str = ""
    event_refs: tuple[str, ...] = field(default_factory=tuple)
    summary: str = ""

    record_type: ClassVar[str] = "timeline"

    def __post_init__(self) -> None:
        RecordBase.__post_init__(self)
        self.title = str(self.title or "").strip()
        self.start_time = str(self.start_time or "").strip()
        self.end_time = str(self.end_time or "").strip()
        self.event_refs = _tuple_of_strings(self.event_refs)
        self.summary = str(self.summary or "").strip()


@dataclass(slots=True, kw_only=True)
class JobRecord(RecordBase):
    job_type: str
    stage: str
    status: str
    input_refs: tuple[str, ...] = field(default_factory=tuple)
    output_refs: tuple[str, ...] = field(default_factory=tuple)
    started_at: str = ""
    finished_at: str = ""
    worker: str = ""

    record_type: ClassVar[str] = "job"

    def __post_init__(self) -> None:
        RecordBase.__post_init__(self)
        self.job_type = str(self.job_type or "").strip()
        self.stage = str(self.stage or "").strip()
        self.status = str(self.status or "").strip()
        self.input_refs = _tuple_of_strings(self.input_refs)
        self.output_refs = _tuple_of_strings(self.output_refs)
        self.started_at = str(self.started_at or "").strip()
        self.finished_at = str(self.finished_at or "").strip()
        self.worker = str(self.worker or "").strip()


RECORD_TYPES: dict[str, type[RecordBase]] = {
    SourceRecord.record_type: SourceRecord,
    ArtifactRecord.record_type: ArtifactRecord,
    IndicatorRecord.record_type: IndicatorRecord,
    IdentityRecord.record_type: IdentityRecord,
    CredentialRecord.record_type: CredentialRecord,
    RelationshipRecord.record_type: RelationshipRecord,
    EventRecord.record_type: EventRecord,
    TimelineRecord.record_type: TimelineRecord,
    JobRecord.record_type: JobRecord,
}


def _record_kwargs(cls: type[RecordBase], payload: Mapping[str, object]) -> dict[str, object]:
    kwargs: dict[str, object] = {}
    tuple_fields = {
        "tags",
        "aliases",
        "source_refs",
        "parent_refs",
        "reasons",
        "actor_refs",
        "artifact_refs",
        "event_refs",
        "input_refs",
        "output_refs",
    }
    dict_fields = {"attributes", "details"}
    for entry in fields(cls):
        if not entry.init or entry.name not in payload:
            continue
        value = payload[entry.name]
        if entry.name == "provenance":
            kwargs[entry.name] = Provenance.from_dict(value)
        elif entry.name == "confidence":
            kwargs[entry.name] = Confidence.from_dict(value)
        elif entry.name in tuple_fields:
            kwargs[entry.name] = _tuple_of_strings(value)
        elif entry.name in dict_fields:
            kwargs[entry.name] = _dict_of_strings(value)
        else:
            kwargs[entry.name] = value
    return kwargs


def record_to_dict(record: RecordBase) -> dict[str, object]:
    payload = asdict(record)
    payload["record_type"] = record.record_type
    return payload


def record_from_dict(payload: Mapping[str, object]) -> RecordBase:
    record_type = str(payload.get("record_type") or "").strip()
    cls = RECORD_TYPES.get(record_type)
    if cls is None:
        raise ValueError(f"unknown record_type: {record_type!r}")
    return cls.from_dict(payload)


def canonical_fingerprint(record: RecordBase) -> str:
    fields_by_type: dict[str, tuple[str, ...]] = {
        "source": ("source_type", "locator", "content_hash", "media_type"),
        "artifact": ("artifact_type", "path", "sha256", "media_type", "parent_artifact_id"),
        "indicator": ("indicator_type", "normalized_value", "value"),
        "identity": ("identity_type", "normalized_value", "value"),
        "credential": ("material_type", "identifier", "username", "hash_type", "secret_ref", "status"),
        "relationship": ("relationship_type", "source_ref", "target_ref", "directed"),
        "event": ("event_type", "title", "timestamp", "actor_refs", "artifact_refs"),
        "timeline": ("title", "start_time", "end_time", "event_refs"),
        "job": ("job_type", "stage", "status", "input_refs", "worker"),
    }
    selected = fields_by_type.get(record.record_type, ())
    payload = {
        "record_type": record.record_type,
        "schema_version": record.schema_version,
    }
    canonical_value = ""
    if record.record_type in {"indicator", "identity"}:
        canonical_value = str(
            getattr(record, "normalized_value", "") or getattr(record, "value", "")
        ).strip()
    for name in selected:
        if record.record_type in {"indicator", "identity"} and name in {"normalized_value", "value"}:
            payload[name] = canonical_value
            continue
        payload[name] = getattr(record, name, "")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode("utf-8")).hexdigest()
