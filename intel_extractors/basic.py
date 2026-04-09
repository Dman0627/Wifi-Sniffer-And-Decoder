from __future__ import annotations

import re
from pathlib import Path
from hashlib import sha256

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

MAX_READ_BYTES = 2 * 1024 * 1024
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE)


def _read_bytes(path: str, *, limit: int = MAX_READ_BYTES) -> bytes:
    try:
        return Path(path).read_bytes()[:limit]
    except OSError:
        return b""


def _text_sample(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * __import__("math").log2(p)
    return round(entropy, 3)


def _extract_domains(text: str) -> tuple[str, ...]:
    rows = []
    seen = set()
    for match in DOMAIN_RE.findall(text):
        normalized = match.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        rows.append(normalized)
    return tuple(rows)


class MetadataExtractorPlugin:
    manifest = PluginManifest(
        name="metadata_extractor",
        version="0.1.0",
        plugin_type="extractor",
        description="Extract basic file metadata and entropy summaries from collected artifacts.",
        capabilities=("artifact-metadata", "entropy-summary"),
        input_types=("*",),
        output_types=("event",),
        policy_tags=("passive-analysis",),
    )

    def healthcheck(self) -> tuple[str, ...]:
        return ()

    def extract(self, context: PluginExecutionContext, artifact: ArtifactRecord) -> PluginResult:
        path = Path(artifact.path)
        if not path.exists():
            return PluginResult(errors=(f"artifact path not found: {path}",))

        sample = _read_bytes(str(path))
        summary = EventRecord(
            id=stable_record_id("event", artifact.id, "artifact_metadata"),
            source_id=artifact.source_id,
            case_id=context.case_id,
            event_type="artifact_metadata",
            title=f"Metadata for {path.name}",
            artifact_refs=(artifact.id,),
            summary="Extracted basic path, size, media type, and entropy metadata.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="stat+sample",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
            ),
            confidence=Confidence(score=0.95),
            tags=("extract", "metadata"),
            attributes={
                "artifact_id": artifact.id,
                "file_name": path.name,
                "suffix": path.suffix.lower(),
                "size_bytes": str(path.stat().st_size),
                "media_type": artifact.media_type,
                "sha256": artifact.sha256,
                "entropy": str(_entropy(sample)),
            },
        )
        return PluginResult(records=(summary,), metrics={"event_count": 1})


class StringIndicatorExtractorPlugin:
    manifest = PluginManifest(
        name="string_indicator_extractor",
        version="0.1.0",
        plugin_type="extractor",
        description="Extract URLs, emails, domains, IPs, and printable string summaries from artifacts.",
        capabilities=("string-scan", "url-extraction", "indicator-extraction"),
        input_types=("*",),
        output_types=("event", "indicator", "relationship"),
        policy_tags=("passive-analysis",),
    )

    def healthcheck(self) -> tuple[str, ...]:
        return ()

    def _indicator_records(
        self,
        *,
        artifact: ArtifactRecord,
        context: PluginExecutionContext,
        indicator_type: str,
        values: tuple[str, ...],
    ) -> tuple[tuple[IndicatorRecord, ...], tuple[RelationshipRecord, ...]]:
        indicators = []
        relationships = []
        for value in values:
            normalized_value = value.lower() if indicator_type in {"domain", "email"} else value
            indicator = IndicatorRecord(
                id=stable_record_id("indicator", artifact.id, indicator_type, normalized_value or value),
                source_id=artifact.source_id,
                case_id=context.case_id,
                indicator_type=indicator_type,
                value=value,
                normalized_value=normalized_value,
                provenance=Provenance(
                    plugin=self.manifest.name,
                    method="regex",
                    source_refs=(artifact.source_id,),
                    parent_refs=(artifact.id,),
                ),
                confidence=Confidence(score=0.8),
                tags=("extract", indicator_type),
                attributes={"artifact_id": artifact.id},
            )
            indicators.append(indicator)
            relationships.append(
                RelationshipRecord(
                    id=stable_record_id("relationship", artifact.id, indicator.id, "artifact_contains_indicator"),
                    source_id=artifact.source_id,
                    case_id=context.case_id,
                    relationship_type="artifact_contains_indicator",
                    source_ref=artifact.id,
                    target_ref=indicator.id,
                    reason=f"{self.manifest.name} extracted {indicator_type}",
                    provenance=Provenance(
                        plugin=self.manifest.name,
                        method="link",
                        source_refs=(artifact.source_id,),
                        parent_refs=(artifact.id, indicator.id),
                    ),
                    confidence=Confidence(score=0.8),
                    tags=("extract", "link"),
                )
            )
        return tuple(indicators), tuple(relationships)

    def extract(self, context: PluginExecutionContext, artifact: ArtifactRecord) -> PluginResult:
        path = Path(artifact.path)
        if not path.exists():
            return PluginResult(errors=(f"artifact path not found: {path}",))

        data = _read_bytes(str(path))
        text = _text_sample(data)
        printable_strings = tuple(
            match.decode("utf-8", errors="replace")[:200]
            for match in PRINTABLE_RE.findall(data)
        )
        urls = tuple(dict.fromkeys(URL_RE.findall(text)))
        emails = tuple(dict.fromkeys(match.lower() for match in EMAIL_RE.findall(text)))
        ips = tuple(dict.fromkeys(IPV4_RE.findall(text)))
        domains = tuple(
            value
            for value in _extract_domains(text)
            if value not in {email.split("@", 1)[1] for email in emails}
        )

        indicator_records = []
        relationship_records = []
        for indicator_type, values in (
            ("url", urls),
            ("email", emails),
            ("ipv4", ips),
            ("domain", domains),
        ):
            indicators, relationships = self._indicator_records(
                artifact=artifact,
                context=context,
                indicator_type=indicator_type,
                values=values,
            )
            indicator_records.extend(indicators)
            relationship_records.extend(relationships)

        summary = EventRecord(
            id=stable_record_id("event", artifact.id, "string_indicator_scan"),
            source_id=artifact.source_id,
            case_id=context.case_id,
            event_type="string_indicator_scan",
            title=f"String and indicator scan for {path.name}",
            artifact_refs=(artifact.id,),
            summary="Extracted printable string counts and network/identity indicators.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="printable+regex",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
            ),
            confidence=Confidence(score=0.82),
            tags=("extract", "strings", "indicators"),
            attributes={
                "artifact_id": artifact.id,
                "string_count": str(len(printable_strings)),
                "sample_strings": " | ".join(printable_strings[:5]),
                "url_count": str(len(urls)),
                "email_count": str(len(emails)),
                "domain_count": str(len(domains)),
                "ipv4_count": str(len(ips)),
            },
        )

        return PluginResult(
            records=(summary, *indicator_records, *relationship_records),
            metrics={
                "string_count": len(printable_strings),
                "indicator_count": len(indicator_records),
            },
        )


class EmbeddedSignatureExtractorPlugin:
    manifest = PluginManifest(
        name="embedded_signature_extractor",
        version="0.1.0",
        plugin_type="extractor",
        description="Find simple embedded file signatures and carve candidate child artifacts.",
        capabilities=("embedded-signature-scan", "artifact-carving"),
        input_types=("file", "log", "system_artifact"),
        output_types=("artifact", "event", "relationship"),
        policy_tags=("passive-analysis",),
    )

    _signatures = (
        ("png_image", b"\x89PNG\r\n\x1a\n", ".png"),
        ("pdf_document", b"%PDF-", ".pdf"),
        ("zip_archive", b"PK\x03\x04", ".zip"),
        ("gzip_archive", b"\x1f\x8b\x08", ".gz"),
    )

    def healthcheck(self) -> tuple[str, ...]:
        return ()

    def extract(self, context: PluginExecutionContext, artifact: ArtifactRecord) -> PluginResult:
        path = Path(artifact.path)
        if not path.exists():
            return PluginResult(errors=(f"artifact path not found: {path}",))

        data = _read_bytes(str(path), limit=MAX_READ_BYTES)
        carved_dir = stage_object_dir(context.output_root, "extract", artifact.source_id, artifact.id, "carved")

        derived_artifacts = []
        relationships = []
        carved_paths = []
        carve_index = 0
        for label, signature, extension in self._signatures:
            start = data.find(signature, 1)
            if start <= 0:
                continue
            carve_index += 1
            carved_path = carved_dir / f"carved_{carve_index:03d}{extension}"
            carved_bytes = data[start:]
            carved_path.write_bytes(carved_bytes)
            carved_paths.append(str(carved_path))
            child = ArtifactRecord(
                id=stable_record_id("artifact", artifact.id, label, str(start), extension),
                source_id=artifact.source_id,
                case_id=context.case_id,
                artifact_type="embedded_artifact",
                path=str(carved_path),
                media_type=_guess_child_media_type(extension, artifact.media_type),
                sha256=sha256(carved_bytes).hexdigest(),
                size_bytes=len(carved_bytes),
                parent_artifact_id=artifact.id,
                provenance=Provenance(
                    plugin=self.manifest.name,
                    method=f"magic:{label}",
                    source_refs=(artifact.source_id,),
                    parent_refs=(artifact.id,),
                ),
                confidence=Confidence(score=0.72),
                tags=("extract", "embedded", label),
                attributes={
                    "parent_artifact_id": artifact.id,
                    "offset": str(start),
                    "signature_label": label,
                },
            )
            derived_artifacts.append(child)
            relationships.append(
                RelationshipRecord(
                    id=stable_record_id(
                        "relationship",
                        artifact.id,
                        child.id,
                        "artifact_contains_embedded_artifact",
                    ),
                    source_id=artifact.source_id,
                    case_id=context.case_id,
                    relationship_type="artifact_contains_embedded_artifact",
                    source_ref=artifact.id,
                    target_ref=child.id,
                    reason=f"{self.manifest.name} carved embedded {label}",
                    provenance=Provenance(
                        plugin=self.manifest.name,
                        method="carve-link",
                        source_refs=(artifact.source_id,),
                        parent_refs=(artifact.id, child.id),
                    ),
                    confidence=Confidence(score=0.72),
                    tags=("extract", "embedded", "link"),
                )
            )

        if not derived_artifacts:
            return PluginResult(metrics={"embedded_artifact_count": 0})

        summary = EventRecord(
            id=stable_record_id("event", artifact.id, "embedded_signature_scan"),
            source_id=artifact.source_id,
            case_id=context.case_id,
            event_type="embedded_signature_scan",
            title=f"Embedded signature scan for {path.name}",
            artifact_refs=(artifact.id,),
            summary="Carved candidate embedded artifacts from simple magic-byte signatures.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="magic-scan",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
            ),
            confidence=Confidence(score=0.7),
            tags=("extract", "embedded"),
            attributes={
                "artifact_id": artifact.id,
                "embedded_artifact_count": str(len(derived_artifacts)),
            },
        )
        return PluginResult(
            records=(summary, *derived_artifacts, *relationships),
            artifact_paths=tuple(carved_paths),
            metrics={"embedded_artifact_count": len(derived_artifacts)},
        )


def _guess_child_media_type(extension: str, fallback: str) -> str:
    mapping = {
        ".png": "image/png",
        ".pdf": "application/pdf",
        ".zip": "application/zip",
        ".gz": "application/gzip",
    }
    return mapping.get(extension.lower(), fallback)
