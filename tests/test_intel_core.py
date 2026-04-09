from __future__ import annotations

from pathlib import Path

from intel_core import (
    ArtifactRecord,
    CollectorPlugin,
    Confidence,
    IndicatorRecord,
    IngestRequest,
    PluginExecutionContext,
    PluginManifest,
    PluginResult,
    Provenance,
    record_from_dict,
    record_to_dict,
    stable_record_id,
)
from intel_core.records import IdentityRecord, canonical_fingerprint, new_record_id


def _fake_path(*parts: str) -> str:
    return str((Path.cwd() / "_ci_fixtures" / Path(*parts)).resolve())


def test_record_round_trip_preserves_nested_schema_fields() -> None:
    report_path = _fake_path("tmp", "report.pdf")
    record = ArtifactRecord(
        id=new_record_id("artifact"),
        source_id="source-1",
        artifact_type="file",
        path=report_path,
        media_type="application/pdf",
        sha256="abc123",
        size_bytes=128,
        tags=("document", "pdf", "document"),
        attributes={"family": "document"},
        provenance=Provenance(
            plugin="file-metadata",
            method="stat",
            source_refs=("source-1",),
            parent_refs=("artifact-parent",),
            notes="derived from local file",
        ),
        confidence=Confidence(score=0.91, reasons=("strong signature",)),
    )

    payload = record_to_dict(record)
    restored = record_from_dict(payload)

    assert isinstance(restored, ArtifactRecord)
    assert restored.record_type == "artifact"
    assert restored.path == report_path
    assert restored.tags == ("document", "pdf")
    assert restored.provenance.plugin == "file-metadata"
    assert restored.confidence.label == "high"


def test_confidence_rejects_invalid_scores() -> None:
    try:
        Confidence(score=1.5)
    except ValueError as exc:
        assert "confidence score" in str(exc)
    else:  # pragma: no cover - defensive failure path
        raise AssertionError("expected invalid confidence score to raise")


def test_canonical_fingerprint_is_deterministic_for_canonical_identity_values() -> None:
    left = IdentityRecord(
        id="identity-1",
        source_id="source-1",
        identity_type="email",
        value="Alice@example.com",
        normalized_value="alice@example.com",
    )
    right = IdentityRecord(
        id="identity-2",
        source_id="source-2",
        identity_type="email",
        value="alice@example.com",
        normalized_value="alice@example.com",
    )

    assert canonical_fingerprint(left) == canonical_fingerprint(right)


def test_indicator_round_trip_uses_record_type_dispatch() -> None:
    payload = {
        "record_type": "indicator",
        "id": "indicator-1",
        "source_id": "source-1",
        "indicator_type": "url",
        "value": "https://example.com/a?b=1",
        "normalized_value": "https://example.com/a?b=1",
        "tags": ["network", "url"],
    }

    restored = record_from_dict(payload)

    assert isinstance(restored, IndicatorRecord)
    assert restored.tags == ("network", "url")


def test_stable_record_id_is_deterministic() -> None:
    left = stable_record_id("indicator", "artifact-1", "email", "alice@example.com")
    right = stable_record_id("indicator", "artifact-1", "email", "alice@example.com")

    assert left == right
    assert left.startswith("indicator_")


def test_plugin_result_ok_is_false_when_errors_exist() -> None:
    result = PluginResult(errors=("tool missing",))

    assert result.ok is False


def test_collector_plugin_protocol_accepts_structural_implementation(tmp_path) -> None:
    class DummyCollector:
        manifest = PluginManifest(
            name="dummy-file-collector",
            version="0.1.0",
            plugin_type="collector",
            capabilities=("file-intake",),
            input_types=("file",),
            output_types=("source", "artifact"),
            policy_tags=("approved-source",),
        )

        def healthcheck(self):
            return ()

        def collect(self, context: PluginExecutionContext, request: IngestRequest) -> PluginResult:
            artifact = ArtifactRecord(
                id="artifact-1",
                source_id="source-1",
                artifact_type="file",
                path=request.locator,
            )
            return PluginResult(records=(artifact,))

    plugin = DummyCollector()

    assert isinstance(plugin, CollectorPlugin)
    result = plugin.collect(
        PluginExecutionContext(workspace_root=tmp_path, output_root=tmp_path / "out"),
        IngestRequest(source_type="file", locator=str(tmp_path / "sample.txt")),
    )
    assert result.ok is True
    assert isinstance(result.records[0], ArtifactRecord)
