from __future__ import annotations

import sqlite3
from pathlib import Path

from intel_core import (
    ArtifactRecord,
    EventRecord,
    IdentityRecord,
    IndicatorRecord,
    JobRecord,
    RelationshipRecord,
    SourceRecord,
    TimelineRecord,
)
from intel_storage import SQLiteIntelligenceStore


def _fake_path(*parts: str) -> str:
    return str((Path.cwd() / "_ci_fixtures" / Path(*parts)).resolve())


def test_sqlite_store_persists_sources_records_relationships_and_timelines(tmp_path) -> None:
    database_path = tmp_path / "intel.sqlite3"
    store = SQLiteIntelligenceStore(database_path)
    sample_path = _fake_path("evidence", "sample.txt")

    source = SourceRecord(
        id="source-1",
        source_id="source-1",
        case_id="case-1",
        source_type="file",
        locator=sample_path,
        display_name="sample.txt",
    )
    records = [
        ArtifactRecord(id="artifact-1", source_id="source-1", case_id="case-1", artifact_type="file", path=sample_path),
        IndicatorRecord(
            id="indicator-1",
            source_id="source-1",
            case_id="case-1",
            indicator_type="email",
            value="alice@example.com",
            normalized_value="alice@example.com",
        ),
        IdentityRecord(
            id="identity-1",
            source_id="source-1",
            case_id="case-1",
            identity_type="email",
            value="alice@example.com",
            normalized_value="alice@example.com",
        ),
        RelationshipRecord(
            id="rel-1",
            source_id="source-1",
            case_id="case-1",
            relationship_type="identity_uses_domain",
            source_ref="identity-1",
            target_ref="indicator-1",
        ),
        EventRecord(
            id="event-1",
            source_id="source-1",
            case_id="case-1",
            event_type="artifact_metadata",
            title="Metadata",
            timestamp="2026-04-08T12:00:00Z",
        ),
        TimelineRecord(
            id="timeline-1",
            source_id="source-1",
            case_id="case-1",
            title="Timeline",
            start_time="2026-04-08T12:00:00Z",
            end_time="2026-04-08T12:00:00Z",
            event_refs=("event-1",),
        ),
    ]

    summary = store.persist(source=source, records=records)

    assert summary["record_count"] == len(records)
    assert summary["relationship_edge_count"] == 1
    assert summary["timeline_count"] == 1

    with sqlite3.connect(database_path) as connection:
        source_count = connection.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
        record_count = connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        relationship_count = connection.execute("SELECT COUNT(*) FROM relationships").fetchone()[0]
        timeline_event_count = connection.execute("SELECT COUNT(*) FROM timeline_events").fetchone()[0]

    assert source_count == 1
    assert record_count == len(records)
    assert relationship_count == 1
    assert timeline_event_count == 1


def test_sqlite_store_upserts_without_duplicate_rows(tmp_path) -> None:
    database_path = tmp_path / "intel.sqlite3"
    store = SQLiteIntelligenceStore(database_path)
    sample_path = _fake_path("evidence", "sample.txt")
    source = SourceRecord(
        id="source-1",
        source_id="source-1",
        case_id="case-1",
        source_type="file",
        locator=sample_path,
    )
    record = IndicatorRecord(
        id="indicator-1",
        source_id="source-1",
        case_id="case-1",
        indicator_type="domain",
        value="example.com",
        normalized_value="example.com",
    )

    store.persist(source=source, records=(record,))
    summary = store.persist(source=source, records=(record,))

    assert summary["record_count"] == 1
    with sqlite3.connect(database_path) as connection:
        record_count = connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    assert record_count == 1


def test_sqlite_store_query_helpers_return_case_summary_and_graph(tmp_path) -> None:
    database_path = tmp_path / "intel.sqlite3"
    store = SQLiteIntelligenceStore(database_path)
    sample_path = _fake_path("evidence", "sample.txt")
    source = SourceRecord(
        id="source-1",
        source_id="source-1",
        case_id="case-graph",
        source_type="file",
        locator=sample_path,
    )
    records = [
        ArtifactRecord(id="artifact-1", source_id="source-1", case_id="case-graph", artifact_type="file", path=sample_path),
        IndicatorRecord(
            id="indicator-1",
            source_id="source-1",
            case_id="case-graph",
            indicator_type="domain",
            value="example.com",
            normalized_value="example.com",
        ),
        IdentityRecord(
            id="identity-1",
            source_id="source-1",
            case_id="case-graph",
            identity_type="email",
            value="alice@example.com",
            normalized_value="alice@example.com",
        ),
        RelationshipRecord(
            id="rel-1",
            source_id="source-1",
            case_id="case-graph",
            relationship_type="identity_uses_domain",
            source_ref="identity-1",
            target_ref="indicator-1",
        ),
        EventRecord(
            id="event-1",
            source_id="source-1",
            case_id="case-graph",
            event_type="artifact_metadata",
            title="Metadata",
            timestamp="2026-04-08T12:00:00Z",
        ),
    ]
    store.persist(source=source, records=records)

    cases = store.list_cases()
    summary = store.case_summary(case_id="case-graph")
    graph = store.graph_view(case_id="case-graph")
    export_bundle = store.export_dataset(case_id="case-graph")

    assert any(item["case_id"] == "case-graph" for item in cases)
    assert summary["record_type_counts"]["relationship"] == 1
    assert summary["relationship_type_counts"]["identity_uses_domain"] == 1
    assert "recent_events" in summary
    assert "job_stage_counts" in summary
    assert graph["nodes"]
    assert graph["edges"][0]["type"] == "identity_uses_domain"
    assert export_bundle["summary"]["case_id"] == "case-graph"


def test_sqlite_store_search_jobs_audit_and_neighbors_queries(tmp_path) -> None:
    database_path = tmp_path / "intel.sqlite3"
    store = SQLiteIntelligenceStore(database_path)
    sample_path = _fake_path("evidence", "sample.txt")
    report_path = _fake_path("tmp", "extract_report.json")
    source = SourceRecord(
        id="source-1",
        source_id="source-1",
        case_id="case-query",
        source_type="file",
        locator=sample_path,
    )
    records = [
        IndicatorRecord(
            id="indicator-1",
            source_id="source-1",
            case_id="case-query",
            indicator_type="domain",
            value="example.com",
            normalized_value="example.com",
        ),
        IdentityRecord(
            id="identity-1",
            source_id="source-1",
            case_id="case-query",
            identity_type="email",
            value="alice@example.com",
            normalized_value="alice@example.com",
        ),
        RelationshipRecord(
            id="rel-1",
            source_id="source-1",
            case_id="case-query",
            relationship_type="identity_uses_domain",
            source_ref="identity-1",
            target_ref="indicator-1",
        ),
        EventRecord(
            id="event-1",
            source_id="source-1",
            case_id="case-query",
            event_type="artifact_metadata",
            title="Metadata event",
            timestamp="2026-04-08T12:00:00Z",
        ),
        TimelineRecord(
            id="timeline-1",
            source_id="source-1",
            case_id="case-query",
            title="Case timeline",
            start_time="2026-04-08T12:00:00Z",
            end_time="2026-04-08T12:00:00Z",
            event_refs=("event-1",),
        ),
        JobRecord(
            id="job-1",
            source_id="source-1",
            case_id="case-query",
            job_type="pipeline-stage",
            stage="extract",
            status="completed",
            worker="platform_extract",
            finished_at="2026-04-08T12:05:00Z",
        ),
    ]
    store.persist(source=source, records=records)
    store.persist_audit_events(
        (
            {
                "audit_id": "audit-1",
                "created_at": "2026-04-08T12:06:00Z",
                "source_id": "source-1",
                "case_id": "case-query",
                "stage": "extract",
                "plugin": "platform_extract",
                "job_id": "job-1",
                "ok": True,
                "status": "completed",
                "metrics": {"record_count": 5},
                "warnings": [],
                "errors": [],
                "artifact_paths": [report_path],
            },
        )
    )

    search_results = store.search_records(case_id="case-query", query="alice@example.com")
    jobs = store.fetch_jobs(case_id="case-query", stage="extract")
    audit_events = store.fetch_audit_events(case_id="case-query", stage="extract")
    timeline_detail = store.timeline_detail(case_id="case-query", timeline_id="timeline-1")
    neighbors = store.graph_neighbors(case_id="case-query", node_id="identity-1", depth=1)

    assert search_results[0]["id"] == "identity-1"
    assert jobs[0]["id"] == "job-1"
    assert audit_events[0]["audit_id"] == "audit-1"
    assert timeline_detail is not None
    assert timeline_detail["timeline"]["id"] == "timeline-1"
    assert timeline_detail["events"][0]["id"] == "event-1"
    assert any(edge["relationship_type"] == "identity_uses_domain" for edge in neighbors["edges"])


def test_sqlite_store_persists_job_rows_and_audit_events(tmp_path) -> None:
    database_path = tmp_path / "intel.sqlite3"
    store = SQLiteIntelligenceStore(database_path)
    sample_path = _fake_path("evidence", "sample.txt")
    report_path = _fake_path("tmp", "extract_report.json")
    source = SourceRecord(
        id="source-1",
        source_id="source-1",
        case_id="case-audit",
        source_type="file",
        locator=sample_path,
    )

    store.persist(
        source=source,
        records=(
            JobRecord(
                id="job-extract",
                source_id="source-1",
                case_id="case-audit",
                job_type="pipeline-stage",
                stage="extract",
                status="completed",
                worker="platform_extract",
            ),
        ),
    )
    store.persist_audit_events(
        (
            {
                "audit_id": "audit-1",
                "created_at": "2026-04-08T12:00:00Z",
                "source_id": "source-1",
                "case_id": "case-audit",
                "stage": "extract",
                "plugin": "platform_extract",
                "job_id": "job-extract",
                "ok": True,
                "status": "completed",
                "metrics": {"record_count": 3},
                "warnings": [],
                "errors": [],
                "artifact_paths": [report_path],
            },
        )
    )

    summary = store.summary(case_id="case-audit")

    assert summary["job_count"] == 1
    assert summary["audit_event_count"] == 1
    with sqlite3.connect(database_path) as connection:
        job_count = connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
        audit_count = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    assert job_count == 1
    assert audit_count == 1


def test_sqlite_store_persists_and_queries_watcher_states(tmp_path) -> None:
    database_path = tmp_path / "intel.sqlite3"
    store = SQLiteIntelligenceStore(database_path)
    store.initialize()

    store.persist_watcher_states(
        (
            {
                "watcher_id": "watcher-1",
                "case_id": "case-watch",
                "watcher_type": "queue_monitor",
                "source_type": "queue",
                "locator": "queue://extract,recover",
                "status": "idle",
                "last_checked_at": "2026-04-08T12:00:00Z",
                "last_seen_at": "2026-04-08T12:00:00Z",
                "last_changed_at": "2026-04-08T11:59:00Z",
                "cursor": "cycle:1",
                "content_hash": "hash-1",
                "backlog_pointer": "",
                "consecutive_no_change_count": 2,
                "total_check_count": 3,
                "total_change_count": 1,
                "last_error": "",
            },
        )
    )

    summary = store.summary(case_id="case-watch")
    watcher_summary = store.watcher_summary(case_id="case-watch")
    watchers = store.fetch_watcher_states(case_id="case-watch", watcher_type="queue_monitor")
    export_bundle = store.export_dataset(case_id="case-watch")

    assert summary["watcher_count"] == 1
    assert watcher_summary["watcher_count"] == 1
    assert watcher_summary["status_counts"]["idle"] == 1
    assert watchers[0]["watcher_id"] == "watcher-1"
    assert export_bundle["watcher_states"][0]["watcher_id"] == "watcher-1"


def test_sqlite_store_persists_and_queries_watched_sources(tmp_path) -> None:
    database_path = tmp_path / "intel.sqlite3"
    store = SQLiteIntelligenceStore(database_path)
    store.initialize()
    sample_path = _fake_path("evidence", "sample.txt")

    store.persist_watched_sources(
        (
            {
                "watch_id": "watch-src-1",
                "case_id": "case-watch-registry",
                "source_type": "file",
                "locator": sample_path,
                "display_name": "sample.txt",
                "recursive": False,
                "enabled": True,
                "poll_interval_seconds": 30.0,
                "status": "active",
                "created_at": "2026-04-08T12:00:00Z",
                "updated_at": "2026-04-08T12:00:00Z",
            },
        )
    )

    summary = store.summary(case_id="case-watch-registry")
    watched_source_summary = store.watched_source_summary(case_id="case-watch-registry")
    watched_sources = store.fetch_watched_sources(case_id="case-watch-registry", enabled_only=True)
    export_bundle = store.export_dataset(case_id="case-watch-registry")

    assert summary["watched_source_count"] == 1
    assert watched_source_summary["watched_source_count"] == 1
    assert watched_source_summary["enabled_counts"]["enabled"] == 1
    assert watched_sources[0]["watch_id"] == "watch-src-1"
    assert export_bundle["watched_sources"][0]["watch_id"] == "watch-src-1"
