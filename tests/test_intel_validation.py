from __future__ import annotations

import json
from pathlib import Path

from intel_api import PlatformApp
from intel_core import IngestRequest


FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "intel"


def _fixture_path(name: str) -> Path:
    return (FIXTURE_ROOT / name).resolve()


def test_fixture_text_pipeline_preserves_lineage_and_produces_views(tmp_path) -> None:
    app = PlatformApp()
    sample = _fixture_path("sample_case.txt")

    ingest_result = app.ingest(
        IngestRequest(source_type="file", locator=str(sample)),
        case_id="fixture-case-1",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    extract_result = app.extract(ingest_result.artifact_paths[0], workspace_root=str(tmp_path))
    recover_result = app.recover(
        next(path for path in extract_result.artifact_paths if path.endswith("extract_report.json")),
        workspace_root=str(tmp_path),
    )
    normalize_result = app.normalize(
        next(path for path in recover_result.artifact_paths if path.endswith("recover_report.json")),
        workspace_root=str(tmp_path),
    )
    correlate_result = app.correlate(
        next(path for path in normalize_result.artifact_paths if path.endswith("normalize_report.json")),
        workspace_root=str(tmp_path),
    )
    store_result = app.store(
        next(path for path in correlate_result.artifact_paths if path.endswith("correlation_report.json")),
        workspace_root=str(tmp_path),
    )
    present_result = app.present(
        next(path for path in store_result.artifact_paths if path.endswith("store_report.json")),
        workspace_root=str(tmp_path),
    )

    assert present_result.ok is True
    for stage_result in (ingest_result, extract_result, recover_result, normalize_result, correlate_result):
        for record in stage_result.records:
            assert record.id
            assert record.source_id
            assert record.created_at
            assert record.schema_version == 1
            assert record.provenance.plugin
            assert record.provenance.method

    presentation_report_path = next(path for path in present_result.artifact_paths if path.endswith("presentation_report.json"))
    report = json.loads(Path(presentation_report_path).read_text(encoding="utf-8"))
    assert report["metrics"]["record_count"] > 0
    assert report["metrics"]["plugin_count"] >= 1
    assert report["artifacts"]["case_summary"].endswith("case_summary.json")
    assert report["artifacts"]["dataset_export"].endswith("dataset_export.json")
    dashboard_view_path = next(path for path in present_result.artifact_paths if path.endswith("dashboard_view.json"))
    dashboard_view = json.loads(Path(dashboard_view_path).read_text(encoding="utf-8"))
    assert dashboard_view["plugins"]["summary"]["plugin_count"] >= 1
    assert dashboard_view["plugins"]["items"]


def test_fixture_log_pipeline_reaches_presentation_and_timeline_output(tmp_path) -> None:
    app = PlatformApp()
    sample = _fixture_path("sample_events.log")

    ingest_result = app.ingest(
        IngestRequest(source_type="log", locator=str(sample)),
        case_id="fixture-case-2",
        output_root=str(tmp_path / "out"),
        workspace_root=str(tmp_path),
    )
    extract_result = app.extract(ingest_result.artifact_paths[0], workspace_root=str(tmp_path))
    recover_result = app.recover(
        next(path for path in extract_result.artifact_paths if path.endswith("extract_report.json")),
        workspace_root=str(tmp_path),
    )
    normalize_result = app.normalize(
        next(path for path in recover_result.artifact_paths if path.endswith("recover_report.json")),
        workspace_root=str(tmp_path),
    )
    correlate_result = app.correlate(
        next(path for path in normalize_result.artifact_paths if path.endswith("normalize_report.json")),
        workspace_root=str(tmp_path),
    )
    store_result = app.store(
        next(path for path in correlate_result.artifact_paths if path.endswith("correlation_report.json")),
        workspace_root=str(tmp_path),
    )
    present_result = app.present(
        next(path for path in store_result.artifact_paths if path.endswith("store_report.json")),
        workspace_root=str(tmp_path),
    )

    assert present_result.ok is True
    timeline_view_path = next(path for path in present_result.artifact_paths if path.endswith("timeline_view.json"))
    timeline_payload = json.loads(Path(timeline_view_path).read_text(encoding="utf-8"))
    assert "timelines" in timeline_payload
    assert timeline_payload["timelines"]
