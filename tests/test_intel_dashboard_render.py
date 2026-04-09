from __future__ import annotations

from pathlib import Path

from intel_api.dashboard_render import (
    render_case_dashboard_html,
    render_case_index_html,
    render_graph_html,
    render_monitor_html,
    render_timeline_html,
)
from intel_core import EventRecord, IndicatorRecord, RelationshipRecord, SourceRecord, TimelineRecord
from intel_storage import SQLiteIntelligenceStore


def _fake_path(*parts: str) -> str:
    return str((Path.cwd() / "_ci_fixtures" / Path(*parts)).resolve())


def _seed_store(database_path, *, case_id: str = "case-render") -> SQLiteIntelligenceStore:
    store = SQLiteIntelligenceStore(database_path)
    source = SourceRecord(
        id="source-1",
        source_id="source-1",
        case_id=case_id,
        source_type="file",
        locator=_fake_path("evidence", "render.txt"),
        display_name="render.txt",
    )
    store.persist(
        source=source,
        records=(
            IndicatorRecord(
                id="indicator-1",
                source_id="source-1",
                case_id=case_id,
                indicator_type="email",
                value="alice@example.com",
                normalized_value="alice@example.com",
            ),
            EventRecord(
                id="event-1",
                source_id="source-1",
                case_id=case_id,
                event_type="artifact_metadata",
                title="Metadata event",
                timestamp="2026-04-08T12:00:00Z",
            ),
            TimelineRecord(
                id="timeline-1",
                source_id="source-1",
                case_id=case_id,
                title="Rendered timeline",
                start_time="2026-04-08T12:00:00Z",
                end_time="2026-04-08T12:00:00Z",
                event_refs=("event-1",),
            ),
            RelationshipRecord(
                id="rel-1",
                source_id="source-1",
                case_id=case_id,
                relationship_type="indicator_mentions_identity",
                source_ref="indicator-1",
                target_ref="identity-1",
            ),
        ),
    )
    return store


def _sample_monitor_view(*, case_id: str = "case-render") -> dict[str, object]:
    return {
        "overview": {
            "cycle_count": 4,
            "watched_source_count": 2,
            "hot_source_count": 1,
            "suppressed_count": 1,
            "snoozed_source_count": 1,
            "cleanup_removed_count": 3,
            "recent_archive_count": 2,
            "history_cycle_count": 4,
            "forecast_alert_count": 2,
            "automation_recommendation_count": 3,
        },
        "cleanup": {
            "policy": {
                "enabled": True,
                "cleanup_completed_days": 7.0,
                "cleanup_failed_days": 30.0,
                "cleanup_watch_delta_days": 3.0,
            },
            "summary": {
                "removed_count": 3,
                "removed_bytes": 256,
                "report_path": _fake_path("reports", "cleanup_report.json"),
            },
        },
        "trends": {
            "queue_pressure": [
                {"recorded_at": "2026-04-08T12:00:00Z", "queue_total_before": 4, "queue_total_after": 1},
            ],
            "throughput": [
                {
                    "recorded_at": "2026-04-08T12:00:00Z",
                    "processed_job_count": 3,
                    "completed_job_count": 2,
                    "failed_job_count": 1,
                    "executed_check_count": 2,
                },
            ],
        },
        "forecast": {
            "summary": {
                "predicted_next_queue_total": 5,
                "predicted_backlog_drain_cycles": 3,
            },
            "alerts": [
                {"id": "queue_pressure_spike", "severity": "warning", "title": "Queue pressure spike"},
                {"id": "failure_burst", "severity": "critical", "title": "Failure burst"},
            ],
        },
        "tuning": {
            "preset_name": "collection_first",
            "automation_mode": "apply",
            "forecast_min_history": 4,
            "queue_spike_factor": 2.0,
            "source_churn_spike_factor": 2.5,
            "throughput_drop_factor": 0.4,
            "suppressed_alert_ids": ["failure_burst"],
            "suppressed_stage_alerts": {"recover": ["failure_burst"]},
            "suppressed_watch_alerts": {"watch-1": ["source_churn_spike"]},
            "alert_severity_overrides": {"queue_pressure_spike": "critical"},
            "stage_threshold_overrides": {"extract": {"queue_spike_factor": 2.5}},
        },
        "automation": {
            "mode": "recommend",
            "evaluated_at": "2026-04-08T12:10:00Z",
            "summary": {
                "recommendation_count": 3,
                "case_recommendation_count": 1,
                "watch_recommendation_count": 2,
                "safe_to_apply_count": 1,
                "applied_count": 1,
                "case_applied_count": 1,
                "watch_applied_count": 0,
            },
            "recommendations": [
                {
                    "scope": "case",
                    "target_id": case_id,
                    "target_label": case_id,
                    "action": "manual_override",
                    "current_preset_name": "balanced",
                    "recommended_preset_name": "collection_first",
                    "safe_to_apply": False,
                    "reason": "Operator override is active.",
                },
                {
                    "scope": "watch",
                    "watch_id": "watch-1",
                    "target_id": "watch-1",
                    "target_label": "hot.log",
                    "action": "already_applied",
                    "current_preset_name": "source:log",
                    "recommended_preset_name": "source:log",
                    "safe_to_apply": False,
                    "reason": "Already applied.",
                },
            ],
        },
        "history": [
            {
                "recorded_at": "2026-04-08T12:10:00Z",
                "queue_total_before": 4,
                "queue_total_after": 1,
                "processed_job_count": 3,
                "completed_job_count": 2,
            },
        ],
        "recent_archives": [
            {
                "archived_at": "2026-04-08T12:11:00Z",
                "archive_state": "completed",
                "stage": "extract",
                "display_name": "hot.log",
                "archive_name": "job-archive-completed.json",
                "result": {"ok": True},
            }
        ],
        "cleanup_reports": [
            {
                "report_name": "cleanup_report__20260408121005.json",
                "completed_at": "2026-04-08T12:10:05Z",
                "removed_count": 3,
            }
        ],
        "hot_sources": [
            {
                "case_id": case_id,
                "watch_id": "watch-1",
                "display_name": "hot.log",
                "source_type": "log",
                "priority_label": "high",
                "poll_adaptation": "burst",
                "backlog_pointer": "extract",
                "enabled": True,
                "poll_interval_seconds": 60.0,
                "notes": "hot source",
                "tags": ["priority"],
                "tuning_profile": {"preset_name": "source:log", "suppressed_alert_ids": []},
            }
        ],
        "suppressed_sources": [
            {
                "case_id": case_id,
                "watch_id": "watch-2",
                "display_name": "cool.txt",
                "source_type": "file",
                "priority_label": "low",
                "poll_adaptation": "suppressed",
                "reason": "suppressed",
                "enabled": True,
                "suppressed": True,
                "poll_interval_seconds": 20.0,
                "notes": "",
                "tags": [],
                "tuning_profile": {"preset_name": "source:file", "suppressed_alert_ids": ["source_churn_spike"]},
            }
        ],
        "snoozed_sources": [
            {
                "case_id": case_id,
                "watch_id": "watch-3",
                "display_name": "paused.log",
                "source_type": "log",
                "priority_label": "low",
                "poll_adaptation": "snoozed",
                "reason": "snoozed",
                "enabled": True,
                "snoozed": True,
                "poll_interval_seconds": 60.0,
                "notes": "",
                "tags": [],
                "tuning_profile": {"preset_name": "source:log", "suppressed_alert_ids": []},
            }
        ],
        "burst_sources": [
            {
                "case_id": case_id,
                "watch_id": "watch-1",
                "display_name": "hot.log",
                "source_type": "log",
                "priority_label": "high",
                "poll_adaptation": "burst",
                "backlog_pointer": "extract",
                "enabled": True,
                "poll_interval_seconds": 60.0,
                "notes": "hot source",
                "tags": ["priority"],
                "tuning_profile": {"preset_name": "source:log", "suppressed_alert_ids": []},
            }
        ],
        "backlogged_sources": [
            {
                "case_id": case_id,
                "watch_id": "watch-1",
                "display_name": "hot.log",
                "source_type": "log",
                "priority_label": "high",
                "poll_adaptation": "burst",
                "backlog_pointer": "extract",
                "enabled": True,
                "poll_interval_seconds": 60.0,
                "notes": "hot source",
                "tags": ["priority"],
                "tuning_profile": {"preset_name": "source:log", "suppressed_alert_ids": []},
            }
        ],
        "backlog_stages": [
            {
                "stage": "extract",
                "pending_before": 2,
                "oldest_age_seconds": 120,
                "aged_job_count_soft": 1,
                "aged_job_count_hard": 0,
            }
        ],
    }


def test_render_case_index_html_includes_monitor_cleanup_and_automation_sections(tmp_path) -> None:
    store = _seed_store(tmp_path / "intel.sqlite3")

    html = render_case_index_html(
        store,
        plugin_statuses=[{"name": "metadata_extractor", "ready": True, "status": "ready"}],
        monitor_view=_sample_monitor_view(),
    )

    assert "Passive Runtime Overview" in html
    assert "Workspace Cleanup" in html
    assert "Backlog Outlook" in html
    assert "Preset Recommendations" in html
    assert "cleanup_report__20260408121005.json" in html
    assert "metadata_extractor" in html


def test_render_case_dashboard_html_includes_monitor_controls_and_recommendations(tmp_path) -> None:
    store = _seed_store(tmp_path / "intel.sqlite3")

    html = render_case_dashboard_html(
        store,
        case_id="case-render",
        search_query="alice@example.com",
        node_id="indicator-1",
        timeline_id="timeline-1",
        plugin_statuses=[{"name": "metadata_extractor", "ready": True, "status": "ready"}],
        monitor_view=_sample_monitor_view(),
    )

    assert "Case Dashboard" in html
    assert "Record Search" in html
    assert "Forecast Tuning" in html
    assert "Preset Recommendations" in html
    assert "manual_override" in html
    assert "already_applied" in html
    assert "/cases/case-render/watch-sources?watch_id=watch-1" in html
    assert "Rendered timeline" in html


def test_render_monitor_html_includes_source_controls_and_cleanup_views() -> None:
    html = render_monitor_html(case_id="case-render", monitor_view=_sample_monitor_view())

    assert ">case-render<" in html
    assert "Recently Active Sources" in html
    assert "Fast-Poll Sources" in html
    assert "Cooling-Off Windows" in html
    assert "Paused Watch Windows" in html
    assert "Recent Queue Archives" in html
    assert "Cleanup Reports" in html
    assert "Disable" in html
    assert "Snooze 10m" in html
    assert "Clear Suppression" in html
    assert "Save Tuning" in html


def test_render_timeline_and_graph_views_include_seeded_records(tmp_path) -> None:
    store = _seed_store(tmp_path / "intel.sqlite3")

    timeline_html = render_timeline_html(store, case_id="case-render", timeline_id="timeline-1")
    graph_html = render_graph_html(store, case_id="case-render", node_id="indicator-1", depth=1)

    assert "Rendered timeline" in timeline_html
    assert "Metadata event" in timeline_html
    assert "indicator-1" in graph_html
    assert "indicator_mentions_identity" in graph_html
