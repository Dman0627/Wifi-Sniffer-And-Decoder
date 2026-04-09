from __future__ import annotations

import json

from wifi_pipeline.enrich import ArtifactEnricher


def test_artifact_enricher_builds_report_from_manifest(tmp_path) -> None:
    output_dir = tmp_path / "pipeline_output"
    output_dir.mkdir()

    text_unit = output_dir / "unit_001.txt"
    png_unit = output_dir / "unit_002.png"
    text_unit.write_bytes(b"hello wifi pipeline")
    png_unit.write_bytes(b"\x89PNG\r\n\x1a\npayload")

    manifest = {
        "streams": [
            {"stream_id": "tcp:1", "protocol": "tcp", "unit_count": 1, "byte_count": text_unit.stat().st_size},
            {"stream_id": "udp:2", "protocol": "udp", "unit_count": 1, "byte_count": png_unit.stat().st_size},
        ],
        "units": [
            {
                "unit_index": 1,
                "stream_id": "tcp:1",
                "file": str(text_unit),
                "unit_type": "plain_text",
                "length": text_unit.stat().st_size,
            },
            {
                "unit_index": 2,
                "stream_id": "udp:2",
                "file": str(png_unit),
                "unit_type": "png_image",
                "length": png_unit.stat().st_size,
            },
        ],
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = ArtifactEnricher({"output_dir": str(output_dir)}).enrich()

    assert report["units_analyzed"] == 2
    assert report["streams_analyzed"] == 2
    assert report["payload_family_counts"]["text"] == 1
    assert report["payload_family_counts"]["image"] == 1
    assert {row["payload_family"] for row in report["top_artifacts"][:2]} == {"text", "image"}

    streams = {row["stream_id"]: row for row in report["streams"]}
    assert streams["tcp:1"]["dominant_unit_type"] == "plain_text"
    assert streams["udp:2"]["recognized_artifact_count"] == 1
    assert (output_dir / "enrichment_report.json").exists()
