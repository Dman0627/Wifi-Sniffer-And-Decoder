from __future__ import annotations

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
from intel_storage import stage_object_dir
from wifi_pipeline import cli as wifi_cli


class PcapSessionExtractorPlugin:
    manifest = PluginManifest(
        name="pcap_session_extractor",
        version="0.1.0",
        plugin_type="extractor",
        description="Delegate pcap session extraction to the existing wifi_pipeline extractor.",
        capabilities=("pcap-session-extraction", "wifi-pipeline-bridge"),
        input_types=("pcap",),
        output_types=("artifact", "event"),
        policy_tags=("passive-analysis", "network-ingest"),
    )

    def healthcheck(self) -> tuple[str, ...]:
        return ()

    def extract(self, context: PluginExecutionContext, artifact: ArtifactRecord) -> PluginResult:
        if artifact.artifact_type != "pcap":
            return PluginResult(metrics={"pcap_manifests": 0})

        output_dir = stage_object_dir(context.output_root, "extract", artifact.source_id, artifact.id, "wifi_extract")
        config = dict(context.config or {})
        config["output_dir"] = str(output_dir)

        manifest = wifi_cli.run_extract(config, artifact.path)
        manifest_path = output_dir / "manifest.json"
        if not manifest or not manifest_path.exists():
            return PluginResult(errors=(f"wifi_pipeline extraction failed for {artifact.path}",))

        derived_manifest = ArtifactRecord(
            id=stable_record_id("artifact", artifact.id, "network_manifest"),
            source_id=artifact.source_id,
            case_id=context.case_id,
            artifact_type="network_manifest",
            path=str(manifest_path),
            media_type="application/json",
            parent_artifact_id=artifact.id,
            provenance=Provenance(
                plugin=self.manifest.name,
                method="wifi_pipeline.run_extract",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
            ),
            confidence=Confidence(score=0.9),
            tags=("extract", "pcap", "network-manifest"),
            attributes={
                "parent_artifact_id": artifact.id,
                "stream_count": str(len(list(manifest.get("streams", [])))),
                "unit_count": str(len(list(manifest.get("units", [])))),
            },
        )

        summary = EventRecord(
            id=stable_record_id("event", artifact.id, "pcap_session_extraction"),
            source_id=artifact.source_id,
            case_id=context.case_id,
            event_type="pcap_session_extraction",
            title=f"Pcap session extraction for {Path(artifact.path).name}",
            artifact_refs=(artifact.id, derived_manifest.id),
            summary="Delegated pcap session extraction to wifi_pipeline and produced a manifest artifact.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="wifi_pipeline.run_extract",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id, derived_manifest.id),
            ),
            confidence=Confidence(score=0.9),
            tags=("extract", "pcap", "session-extraction"),
            attributes={
                "artifact_id": artifact.id,
                "manifest_path": str(manifest_path),
            },
        )
        return PluginResult(
            records=(derived_manifest, summary),
            artifact_paths=(str(manifest_path),),
            metrics={"pcap_manifests": 1},
        )
