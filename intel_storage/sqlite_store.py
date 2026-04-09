from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from intel_core import (
    ArtifactRecord,
    CredentialRecord,
    EventRecord,
    IdentityRecord,
    IndicatorRecord,
    JobRecord,
    RecordBase,
    RelationshipRecord,
    SourceRecord,
    TimelineRecord,
    canonical_fingerprint,
    record_to_dict,
)

DEFAULT_DATABASE_NAME = "intelligence.sqlite3"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    locator TEXT NOT NULL,
    display_name TEXT NOT NULL,
    collector TEXT NOT NULL,
    media_type TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
    record_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    record_type TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    title TEXT NOT NULL,
    value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_records_case_type ON records(case_id, record_type);
CREATE INDEX IF NOT EXISTS idx_records_source_type ON records(source_id, record_type);
CREATE INDEX IF NOT EXISTS idx_records_fingerprint ON records(fingerprint);
CREATE INDEX IF NOT EXISTS idx_records_normalized_value ON records(normalized_value);

CREATE TABLE IF NOT EXISTS relationships (
    relationship_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    directed INTEGER NOT NULL,
    reason TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_relationships_case_type ON relationships(case_id, relationship_type);
CREATE INDEX IF NOT EXISTS idx_relationships_source_ref ON relationships(source_ref);
CREATE INDEX IF NOT EXISTS idx_relationships_target_ref ON relationships(target_ref);

CREATE TABLE IF NOT EXISTS timeline_events (
    timeline_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    sort_order INTEGER NOT NULL,
    PRIMARY KEY (timeline_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_timeline_events_case ON timeline_events(case_id, timeline_id, sort_order);

CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    status TEXT NOT NULL,
    worker TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jobs_case_stage ON jobs(case_id, stage, status);
CREATE INDEX IF NOT EXISTS idx_jobs_source_stage ON jobs(source_id, stage, status);

CREATE TABLE IF NOT EXISTS audit_events (
    audit_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    plugin TEXT NOT NULL,
    job_id TEXT NOT NULL,
    ok INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    warnings_json TEXT NOT NULL,
    errors_json TEXT NOT NULL,
    artifact_paths_json TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_case_stage ON audit_events(case_id, stage, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_source_stage ON audit_events(source_id, stage, created_at);

CREATE TABLE IF NOT EXISTS watcher_states (
    watcher_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    watcher_type TEXT NOT NULL,
    source_type TEXT NOT NULL,
    locator TEXT NOT NULL,
    status TEXT NOT NULL,
    last_checked_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_changed_at TEXT NOT NULL,
    cursor TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    suppression_until TEXT NOT NULL,
    backlog_pointer TEXT NOT NULL,
    consecutive_no_change_count INTEGER NOT NULL,
    total_check_count INTEGER NOT NULL,
    total_change_count INTEGER NOT NULL,
    last_error TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_watcher_states_case_type ON watcher_states(case_id, watcher_type, status);
CREATE INDEX IF NOT EXISTS idx_watcher_states_source_type ON watcher_states(source_id, source_type, status);

CREATE TABLE IF NOT EXISTS watched_sources (
    watch_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    locator TEXT NOT NULL,
    display_name TEXT NOT NULL,
    recursive INTEGER NOT NULL,
    enabled INTEGER NOT NULL,
    poll_interval_seconds REAL NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_watched_sources_case_status ON watched_sources(case_id, status, enabled);
CREATE INDEX IF NOT EXISTS idx_watched_sources_type_status ON watched_sources(source_type, status, enabled);
"""


@dataclass(slots=True)
class SQLiteIntelligenceStore:
    database_path: Path

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path).resolve()

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            self._initialize_schema(connection)
            connection.commit()

    def persist(self, *, source: SourceRecord, records: Iterable[RecordBase]) -> dict[str, object]:
        rows = list(records)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            self._initialize_schema(connection)
            self._upsert_source(connection, source)
            for record in rows:
                self._upsert_record(connection, record)
                if isinstance(record, JobRecord):
                    self._upsert_job(connection, record)
            connection.commit()
        return self.summary(case_id=source.case_id, source_id=source.source_id)

    def persist_audit_events(self, events: Iterable[dict[str, object]]) -> None:
        rows = list(events)
        if not rows:
            return
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            self._initialize_schema(connection)
            for event in rows:
                self._upsert_audit_event(connection, event)
            connection.commit()

    def persist_watcher_states(self, states: Iterable[dict[str, object]]) -> None:
        rows = [self._normalize_watcher_state(item) for item in states]
        rows = [row for row in rows if str(row.get("watcher_id") or "").strip()]
        if not rows:
            return
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            self._initialize_schema(connection)
            for row in rows:
                self._upsert_watcher_state(connection, row)
            connection.commit()

    def persist_watched_sources(self, sources: Iterable[dict[str, object]]) -> None:
        rows = [self._normalize_watched_source(item) for item in sources]
        rows = [row for row in rows if str(row.get("watch_id") or "").strip()]
        if not rows:
            return
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            self._initialize_schema(connection)
            for row in rows:
                self._upsert_watched_source(connection, row)
            connection.commit()

    def summary(self, *, case_id: str = "", source_id: str = "") -> dict[str, object]:
        with self._connect() as connection:
            self._initialize_schema(connection)
            where_sql, params = self._record_filters(case_id=case_id, source_id=source_id)
            record_count = int(
                connection.execute(f"SELECT COUNT(*) FROM records {where_sql}", params).fetchone()[0]
            )
            source_where_sql, source_params = self._source_filters(case_id=case_id, source_id=source_id)
            source_count = int(
                connection.execute(f"SELECT COUNT(*) FROM sources {source_where_sql}", source_params).fetchone()[0]
            )
            relationship_count = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM relationships {where_sql}",
                    params,
                ).fetchone()[0]
            )
            timeline_count = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM records {where_sql} {'AND' if where_sql else 'WHERE'} record_type = ?",
                    (*params, "timeline"),
                ).fetchone()[0]
            )
            job_count = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM jobs {source_where_sql}",
                    source_params,
                ).fetchone()[0]
            )
            audit_count = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM audit_events {source_where_sql}",
                    source_params,
                ).fetchone()[0]
            )
            watcher_count = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM watcher_states {source_where_sql}",
                    source_params,
                ).fetchone()[0]
            )
            watched_source_where_sql, watched_source_params = self._watched_source_filters(case_id=case_id, source_id=source_id)
            watched_source_count = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM watched_sources {watched_source_where_sql}",
                    watched_source_params,
                ).fetchone()[0]
            )
        return {
            "database_path": str(self.database_path),
            "source_count": source_count,
            "record_count": record_count,
            "relationship_edge_count": relationship_count,
            "timeline_count": timeline_count,
            "job_count": job_count,
            "audit_event_count": audit_count,
            "watcher_count": watcher_count,
            "watched_source_count": watched_source_count,
        }

    def list_cases(self) -> list[dict[str, object]]:
        with self._connect() as connection:
            self._initialize_schema(connection)
            rows = connection.execute(
                """
                SELECT
                    case_id,
                    COUNT(DISTINCT source_id) AS source_count,
                    COUNT(*) AS record_count,
                    SUM(CASE WHEN record_type = 'timeline' THEN 1 ELSE 0 END) AS timeline_count,
                    SUM(CASE WHEN record_type = 'job' THEN 1 ELSE 0 END) AS job_count
                FROM records
                WHERE case_id <> ''
                GROUP BY case_id
                ORDER BY case_id
                """
            ).fetchall()
        return [
            {
                "case_id": str(row["case_id"]),
                "source_count": int(row["source_count"]),
                "record_count": int(row["record_count"]),
                "timeline_count": int(row["timeline_count"] or 0),
                "job_count": int(row["job_count"] or 0),
            }
            for row in rows
        ]

    def case_summary(self, *, case_id: str = "", source_id: str = "") -> dict[str, object]:
        summary = self.summary(case_id=case_id, source_id=source_id)
        with self._connect() as connection:
            self._initialize_schema(connection)
            record_where_sql, record_params = self._record_filters(case_id=case_id, source_id=source_id)
            source_where_sql, source_params = self._source_filters(case_id=case_id, source_id=source_id)
            relationship_where_sql, relationship_params = self._relationship_filters(case_id=case_id, source_id=source_id)
            job_where_sql, job_params = self._job_filters(case_id=case_id, source_id=source_id)
            audit_where_sql, audit_params = self._audit_filters(case_id=case_id, source_id=source_id)

            record_type_rows = connection.execute(
                f"""
                SELECT record_type, COUNT(*) AS record_count
                FROM records
                {record_where_sql}
                GROUP BY record_type
                ORDER BY record_type
                """,
                record_params,
            ).fetchall()
            relationship_type_rows = connection.execute(
                f"""
                SELECT relationship_type, COUNT(*) AS relationship_count
                FROM relationships
                {relationship_where_sql}
                GROUP BY relationship_type
                ORDER BY relationship_type
                """,
                relationship_params,
            ).fetchall()
            job_stage_rows = connection.execute(
                f"""
                SELECT stage, COUNT(*) AS job_count
                FROM jobs
                {job_where_sql}
                GROUP BY stage
                ORDER BY stage
                """,
                job_params,
            ).fetchall()
            job_status_rows = connection.execute(
                f"""
                SELECT status, COUNT(*) AS job_count
                FROM jobs
                {job_where_sql}
                GROUP BY status
                ORDER BY status
                """,
                job_params,
            ).fetchall()
            audit_stage_rows = connection.execute(
                f"""
                SELECT stage, COUNT(*) AS audit_count
                FROM audit_events
                {audit_where_sql}
                GROUP BY stage
                ORDER BY stage
                """,
                audit_params,
            ).fetchall()
            watcher_where_sql, watcher_params = self._watcher_filters(case_id=case_id, source_id=source_id)
            watcher_status_rows = connection.execute(
                f"""
                SELECT status, COUNT(*) AS watcher_count
                FROM watcher_states
                {watcher_where_sql}
                GROUP BY status
                ORDER BY status
                """,
                watcher_params,
            ).fetchall()
            watcher_type_rows = connection.execute(
                f"""
                SELECT watcher_type, COUNT(*) AS watcher_count
                FROM watcher_states
                {watcher_where_sql}
                GROUP BY watcher_type
                ORDER BY watcher_type
                """,
                watcher_params,
            ).fetchall()
            watched_source_where_sql, watched_source_params = self._watched_source_filters(case_id=case_id, source_id=source_id)
            watched_source_status_rows = connection.execute(
                f"""
                SELECT status, COUNT(*) AS watched_source_count
                FROM watched_sources
                {watched_source_where_sql}
                GROUP BY status
                ORDER BY status
                """,
                watched_source_params,
            ).fetchall()
            watched_source_enabled_rows = connection.execute(
                f"""
                SELECT enabled, COUNT(*) AS watched_source_count
                FROM watched_sources
                {watched_source_where_sql}
                GROUP BY enabled
                ORDER BY enabled DESC
                """,
                watched_source_params,
            ).fetchall()
            time_bounds = connection.execute(
                f"""
                SELECT
                    MIN(NULLIF(timestamp, '')) AS first_event_at,
                    MAX(NULLIF(timestamp, '')) AS last_event_at
                FROM records
                {record_where_sql}
                """,
                record_params,
            ).fetchone()
            source_rows = connection.execute(
                f"""
                SELECT payload_json
                FROM sources
                {source_where_sql}
                ORDER BY created_at, id
                """,
                source_params,
            ).fetchall()

        sources = [json.loads(str(row["payload_json"])) for row in source_rows]
        artifacts = self.fetch_records(case_id=case_id, source_id=source_id, record_type="artifact", limit=25)
        identities = self.fetch_records(case_id=case_id, source_id=source_id, record_type="identity", limit=25)
        indicators = self.fetch_records(case_id=case_id, source_id=source_id, record_type="indicator", limit=25)
        timelines = self.fetch_timelines(case_id=case_id, source_id=source_id)
        recent_events = self.fetch_recent_events(case_id=case_id, source_id=source_id, limit=10)
        recent_jobs = self.fetch_jobs(case_id=case_id, source_id=source_id, limit=10)
        recent_audit_events = self.fetch_audit_events(case_id=case_id, source_id=source_id, limit=10)
        watcher_states = self.fetch_watcher_states(case_id=case_id, source_id=source_id, limit=25)
        watched_sources = self.fetch_watched_sources(case_id=case_id, source_id=source_id, limit=25)
        return {
            **summary,
            "case_id": case_id,
            "source_id": source_id,
            "record_type_counts": {
                str(row["record_type"]): int(row["record_count"])
                for row in record_type_rows
            },
            "relationship_type_counts": {
                str(row["relationship_type"]): int(row["relationship_count"])
                for row in relationship_type_rows
            },
            "job_stage_counts": {
                str(row["stage"]): int(row["job_count"])
                for row in job_stage_rows
            },
            "job_status_counts": {
                str(row["status"]): int(row["job_count"])
                for row in job_status_rows
            },
            "audit_stage_counts": {
                str(row["stage"]): int(row["audit_count"])
                for row in audit_stage_rows
            },
            "watcher_status_counts": {
                str(row["status"]): int(row["watcher_count"])
                for row in watcher_status_rows
            },
            "watcher_type_counts": {
                str(row["watcher_type"]): int(row["watcher_count"])
                for row in watcher_type_rows
            },
            "watched_source_status_counts": {
                str(row["status"]): int(row["watched_source_count"])
                for row in watched_source_status_rows
            },
            "watched_source_enabled_counts": {
                ("enabled" if int(row["enabled"] or 0) else "disabled"): int(row["watched_source_count"])
                for row in watched_source_enabled_rows
            },
            "first_event_at": str(time_bounds["first_event_at"] or ""),
            "last_event_at": str(time_bounds["last_event_at"] or ""),
            "sources": sources,
            "top_artifacts": artifacts[:10],
            "top_identities": identities[:10],
            "top_indicators": indicators[:10],
            "timelines": [item["timeline"] for item in timelines],
            "recent_events": recent_events,
            "recent_jobs": recent_jobs,
            "recent_audit_events": recent_audit_events,
            "watcher_states": watcher_states,
            "watched_sources": watched_sources,
        }

    def fetch_sources(self, *, case_id: str = "", source_id: str = "", limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection:
            self._initialize_schema(connection)
            where_sql, params = self._source_filters(case_id=case_id, source_id=source_id)
            rows = connection.execute(
                f"""
                SELECT payload_json
                FROM sources
                {where_sql}
                ORDER BY created_at, id
                LIMIT ?
                """,
                (*params, int(limit)),
            ).fetchall()
        return [json.loads(str(row["payload_json"])) for row in rows]

    def fetch_records(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        record_type: str = "",
        limit: int = 500,
    ) -> list[dict[str, object]]:
        extra_filters: list[tuple[str, str]] = []
        if record_type:
            extra_filters.append(("record_type", record_type))
        where_sql, params = self._record_filters(case_id=case_id, source_id=source_id, extra_filters=extra_filters)
        with self._connect() as connection:
            self._initialize_schema(connection)
            rows = connection.execute(
                f"""
                SELECT payload_json
                FROM records
                {where_sql}
                ORDER BY created_at, record_id
                LIMIT ?
                """,
                (*params, int(limit)),
            ).fetchall()
        return [json.loads(str(row["payload_json"])) for row in rows]

    def search_records(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        query: str,
        record_type: str = "",
        limit: int = 100,
    ) -> list[dict[str, object]]:
        text = str(query or "").strip()
        if not text:
            return []
        extra_filters: list[tuple[str, str]] = []
        if record_type:
            extra_filters.append(("record_type", record_type))
        where_sql, params = self._record_filters(case_id=case_id, source_id=source_id, extra_filters=extra_filters)
        connector = "AND" if where_sql else "WHERE"
        like_value = f"%{text}%"
        with self._connect() as connection:
            self._initialize_schema(connection)
            rows = connection.execute(
                f"""
                SELECT payload_json
                FROM records
                {where_sql}
                {connector} (
                    title LIKE ?
                    OR value LIKE ?
                    OR normalized_value LIKE ?
                    OR payload_json LIKE ?
                )
                ORDER BY
                    CASE WHEN timestamp <> '' THEN timestamp ELSE created_at END DESC,
                    record_id
                LIMIT ?
                """,
                (*params, like_value, like_value, like_value, like_value, int(limit)),
            ).fetchall()
        return [json.loads(str(row["payload_json"])) for row in rows]

    def fetch_relationships(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        relationship_type: str = "",
        limit: int = 500,
    ) -> list[dict[str, object]]:
        extra_filters: list[tuple[str, str]] = []
        if relationship_type:
            extra_filters.append(("relationship_type", relationship_type))
        where_sql, params = self._relationship_filters(case_id=case_id, source_id=source_id, extra_filters=extra_filters)
        with self._connect() as connection:
            self._initialize_schema(connection)
            rows = connection.execute(
                f"""
                SELECT payload_json
                FROM relationships
                {where_sql}
                ORDER BY relationship_id
                LIMIT ?
                """,
                (*params, int(limit)),
            ).fetchall()
        return [json.loads(str(row["payload_json"])) for row in rows]

    def fetch_jobs(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        stage: str = "",
        status: str = "",
        limit: int = 200,
    ) -> list[dict[str, object]]:
        extra_filters: list[tuple[str, str]] = []
        if stage:
            extra_filters.append(("stage", stage))
        if status:
            extra_filters.append(("status", status))
        where_sql, params = self._job_filters(case_id=case_id, source_id=source_id, extra_filters=extra_filters)
        with self._connect() as connection:
            self._initialize_schema(connection)
            rows = connection.execute(
                f"""
                SELECT payload_json
                FROM jobs
                {where_sql}
                ORDER BY
                    CASE WHEN finished_at <> '' THEN finished_at ELSE started_at END DESC,
                    job_id
                LIMIT ?
                """,
                (*params, int(limit)),
            ).fetchall()
        return [json.loads(str(row["payload_json"])) for row in rows]

    def fetch_audit_events(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        stage: str = "",
        status: str = "",
        limit: int = 200,
    ) -> list[dict[str, object]]:
        extra_filters: list[tuple[str, str]] = []
        if stage:
            extra_filters.append(("stage", stage))
        if status:
            extra_filters.append(("status", status))
        where_sql, params = self._audit_filters(case_id=case_id, source_id=source_id, extra_filters=extra_filters)
        with self._connect() as connection:
            self._initialize_schema(connection)
            rows = connection.execute(
                f"""
                SELECT payload_json
                FROM audit_events
                {where_sql}
                ORDER BY created_at DESC, audit_id
                LIMIT ?
                """,
                (*params, int(limit)),
            ).fetchall()
        return [json.loads(str(row["payload_json"])) for row in rows]

    def fetch_watcher_states(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        watcher_id: str = "",
        watcher_type: str = "",
        status: str = "",
        limit: int = 200,
    ) -> list[dict[str, object]]:
        extra_filters: list[tuple[str, str]] = []
        if watcher_id:
            extra_filters.append(("watcher_id", watcher_id))
        if watcher_type:
            extra_filters.append(("watcher_type", watcher_type))
        if status:
            extra_filters.append(("status", status))
        where_sql, params = self._watcher_filters(case_id=case_id, source_id=source_id, extra_filters=extra_filters)
        with self._connect() as connection:
            self._initialize_schema(connection)
            rows = connection.execute(
                f"""
                SELECT payload_json
                FROM watcher_states
                {where_sql}
                ORDER BY
                    CASE WHEN last_checked_at <> '' THEN last_checked_at ELSE last_seen_at END DESC,
                    watcher_id
                LIMIT ?
                """,
                (*params, int(limit)),
            ).fetchall()
        return [json.loads(str(row["payload_json"])) for row in rows]

    def watcher_summary(self, *, case_id: str = "", source_id: str = "") -> dict[str, object]:
        with self._connect() as connection:
            self._initialize_schema(connection)
            where_sql, params = self._watcher_filters(case_id=case_id, source_id=source_id)
            status_rows = connection.execute(
                f"""
                SELECT status, COUNT(*) AS watcher_count
                FROM watcher_states
                {where_sql}
                GROUP BY status
                ORDER BY status
                """,
                params,
            ).fetchall()
            type_rows = connection.execute(
                f"""
                SELECT watcher_type, COUNT(*) AS watcher_count
                FROM watcher_states
                {where_sql}
                GROUP BY watcher_type
                ORDER BY watcher_type
                """,
                params,
            ).fetchall()
            bounds = connection.execute(
                f"""
                SELECT
                    MAX(NULLIF(last_checked_at, '')) AS last_checked_at,
                    MAX(NULLIF(last_changed_at, '')) AS last_changed_at
                FROM watcher_states
                {where_sql}
                """,
                params,
            ).fetchone()
        return {
            "watcher_count": sum(int(row["watcher_count"]) for row in status_rows),
            "status_counts": {
                str(row["status"]): int(row["watcher_count"])
                for row in status_rows
            },
            "watcher_type_counts": {
                str(row["watcher_type"]): int(row["watcher_count"])
                for row in type_rows
            },
            "last_checked_at": str(bounds["last_checked_at"] or ""),
            "last_changed_at": str(bounds["last_changed_at"] or ""),
        }

    def fetch_watched_sources(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        watch_id: str = "",
        source_type: str = "",
        status: str = "",
        enabled_only: bool = False,
        limit: int = 200,
    ) -> list[dict[str, object]]:
        extra_filters: list[tuple[str, str]] = []
        if watch_id:
            extra_filters.append(("watch_id", watch_id))
        if source_type:
            extra_filters.append(("source_type", source_type))
        if status:
            extra_filters.append(("status", status))
        if enabled_only:
            extra_filters.append(("enabled", "1"))
        where_sql, params = self._watched_source_filters(case_id=case_id, source_id=source_id, extra_filters=extra_filters)
        with self._connect() as connection:
            self._initialize_schema(connection)
            rows = connection.execute(
                f"""
                SELECT payload_json
                FROM watched_sources
                {where_sql}
                ORDER BY updated_at DESC, watch_id
                LIMIT ?
                """,
                (*params, int(limit)),
            ).fetchall()
        return [json.loads(str(row["payload_json"])) for row in rows]

    def watched_source_summary(self, *, case_id: str = "", source_id: str = "") -> dict[str, object]:
        with self._connect() as connection:
            self._initialize_schema(connection)
            where_sql, params = self._watched_source_filters(case_id=case_id, source_id=source_id)
            status_rows = connection.execute(
                f"""
                SELECT status, COUNT(*) AS watched_source_count
                FROM watched_sources
                {where_sql}
                GROUP BY status
                ORDER BY status
                """,
                params,
            ).fetchall()
            enabled_rows = connection.execute(
                f"""
                SELECT enabled, COUNT(*) AS watched_source_count
                FROM watched_sources
                {where_sql}
                GROUP BY enabled
                ORDER BY enabled DESC
                """,
                params,
            ).fetchall()
            source_type_rows = connection.execute(
                f"""
                SELECT source_type, COUNT(*) AS watched_source_count
                FROM watched_sources
                {where_sql}
                GROUP BY source_type
                ORDER BY source_type
                """,
                params,
            ).fetchall()
            bounds = connection.execute(
                f"""
                SELECT
                    MAX(NULLIF(updated_at, '')) AS updated_at,
                    MAX(NULLIF(created_at, '')) AS created_at
                FROM watched_sources
                {where_sql}
                """,
                params,
            ).fetchone()
        return {
            "watched_source_count": sum(int(row["watched_source_count"]) for row in status_rows),
            "status_counts": {
                str(row["status"]): int(row["watched_source_count"])
                for row in status_rows
            },
            "enabled_counts": {
                ("enabled" if int(row["enabled"] or 0) else "disabled"): int(row["watched_source_count"])
                for row in enabled_rows
            },
            "source_type_counts": {
                str(row["source_type"]): int(row["watched_source_count"])
                for row in source_type_rows
            },
            "last_updated_at": str(bounds["updated_at"] or ""),
            "first_registered_at": str(bounds["created_at"] or ""),
        }

    def fetch_recent_events(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        limit: int = 25,
    ) -> list[dict[str, object]]:
        where_sql, params = self._record_filters(
            case_id=case_id,
            source_id=source_id,
            extra_filters=(("record_type", "event"),),
        )
        with self._connect() as connection:
            self._initialize_schema(connection)
            rows = connection.execute(
                f"""
                SELECT payload_json
                FROM records
                {where_sql}
                ORDER BY
                    CASE WHEN timestamp <> '' THEN timestamp ELSE created_at END DESC,
                    record_id
                LIMIT ?
                """,
                (*params, int(limit)),
            ).fetchall()
        return [json.loads(str(row["payload_json"])) for row in rows]

    def fetch_timelines(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        limit: int = 50,
    ) -> list[dict[str, object]]:
        timelines = self.fetch_records(case_id=case_id, source_id=source_id, record_type="timeline", limit=limit)
        records_by_id = {
            record["id"]: record
            for record in self.fetch_records(case_id=case_id, source_id=source_id, limit=5000)
        }
        rows = []
        for timeline in timelines:
            event_refs = [str(value) for value in list(timeline.get("event_refs") or [])]
            rows.append(
                {
                    "timeline": timeline,
                    "events": [records_by_id[event_id] for event_id in event_refs if event_id in records_by_id],
                }
            )
        return rows

    def timeline_detail(
        self,
        *,
        timeline_id: str,
        case_id: str = "",
        source_id: str = "",
    ) -> dict[str, object] | None:
        timeline_id = str(timeline_id or "").strip()
        if not timeline_id:
            return None
        with self._connect() as connection:
            self._initialize_schema(connection)
            where_sql, params = self._record_filters(
                case_id=case_id,
                source_id=source_id,
                extra_filters=(("record_type", "timeline"),),
            )
            connector = "AND" if where_sql else "WHERE"
            timeline_row = connection.execute(
                f"""
                SELECT payload_json
                FROM records
                {where_sql}
                {connector} record_id = ?
                LIMIT 1
                """,
                (*params, timeline_id),
            ).fetchone()
            if timeline_row is None:
                return None
            event_rows = connection.execute(
                """
                SELECT records.payload_json
                FROM timeline_events
                JOIN records ON records.record_id = timeline_events.event_id
                WHERE timeline_events.timeline_id = ?
                ORDER BY timeline_events.sort_order
                """,
                (timeline_id,),
            ).fetchall()
        return {
            "timeline": json.loads(str(timeline_row["payload_json"])),
            "events": [json.loads(str(row["payload_json"])) for row in event_rows],
        }

    def graph_view(self, *, case_id: str = "", source_id: str = "") -> dict[str, object]:
        sources = self.fetch_sources(case_id=case_id, source_id=source_id, limit=500)
        records = self.fetch_records(case_id=case_id, source_id=source_id, limit=5000)
        relationships = self.fetch_relationships(case_id=case_id, source_id=source_id, limit=5000)
        nodes: dict[str, dict[str, object]] = {}

        for source in sources:
            node_id = str(source.get("id") or source.get("source_id") or "")
            if not node_id:
                continue
            nodes[node_id] = {
                "id": node_id,
                "kind": "source",
                "label": str(source.get("display_name") or source.get("locator") or node_id),
                "record_type": "source",
            }

        for record in records:
            record_type = str(record.get("record_type") or "")
            if record_type in {"relationship", "job"}:
                continue
            record_id = str(record.get("id") or "")
            if not record_id:
                continue
            nodes[record_id] = {
                "id": record_id,
                "kind": record_type or "record",
                "label": self._node_label(record),
                "record_type": record_type,
            }

        edges = []
        for relationship in relationships:
            edges.append(
                {
                    "id": str(relationship.get("id") or ""),
                    "type": str(relationship.get("relationship_type") or ""),
                    "source": str(relationship.get("source_ref") or ""),
                    "target": str(relationship.get("target_ref") or ""),
                    "directed": bool(relationship.get("directed", True)),
                    "reason": str(relationship.get("reason") or ""),
                }
            )
        return {
            "nodes": sorted(nodes.values(), key=lambda item: (str(item["kind"]), str(item["label"]), str(item["id"]))),
            "edges": edges,
        }

    def graph_neighbors(
        self,
        *,
        node_id: str,
        case_id: str = "",
        source_id: str = "",
        depth: int = 1,
        limit: int = 500,
    ) -> dict[str, object]:
        root_id = str(node_id or "").strip()
        if not root_id:
            return {"root_id": "", "depth": 0, "nodes": [], "edges": []}

        max_depth = max(1, min(int(depth or 1), 4))
        max_edges = max(1, min(int(limit or 500), 5000))
        seen_nodes = {root_id}
        frontier = {root_id}
        relationships: list[dict[str, object]] = []
        seen_edges: set[str] = set()

        with self._connect() as connection:
            self._initialize_schema(connection)
            base_where_sql, base_params = self._relationship_filters(case_id=case_id, source_id=source_id)
            for _level in range(max_depth):
                if not frontier or len(relationships) >= max_edges:
                    break
                placeholders = ", ".join("?" for _ in frontier)
                connector = "AND" if base_where_sql else "WHERE"
                rows = connection.execute(
                    f"""
                    SELECT payload_json
                    FROM relationships
                    {base_where_sql}
                    {connector} (source_ref IN ({placeholders}) OR target_ref IN ({placeholders}))
                    LIMIT ?
                    """,
                    (*base_params, *frontier, *frontier, max_edges - len(relationships)),
                ).fetchall()
                next_frontier: set[str] = set()
                for row in rows:
                    payload = json.loads(str(row["payload_json"]))
                    edge_id = str(payload.get("id") or payload.get("relationship_id") or "")
                    if edge_id in seen_edges:
                        continue
                    seen_edges.add(edge_id)
                    relationships.append(payload)
                    source_ref = str(payload.get("source_ref") or "")
                    target_ref = str(payload.get("target_ref") or "")
                    if source_ref and source_ref not in seen_nodes:
                        seen_nodes.add(source_ref)
                        next_frontier.add(source_ref)
                    if target_ref and target_ref not in seen_nodes:
                        seen_nodes.add(target_ref)
                        next_frontier.add(target_ref)
                frontier = next_frontier

        nodes = self._fetch_nodes_by_ids(seen_nodes)
        if root_id not in {str(node.get("id") or "") for node in nodes}:
            nodes.append({"id": root_id, "kind": "unknown", "label": root_id, "record_type": "unknown"})
        return {
            "root_id": root_id,
            "depth": max_depth,
            "nodes": sorted(nodes, key=lambda item: (str(item.get("kind") or ""), str(item.get("label") or ""), str(item.get("id") or ""))),
            "edges": relationships,
        }

    def export_dataset(self, *, case_id: str = "", source_id: str = "") -> dict[str, object]:
        return {
            "summary": self.case_summary(case_id=case_id, source_id=source_id),
            "sources": self.fetch_sources(case_id=case_id, source_id=source_id, limit=500),
            "records": self.fetch_records(case_id=case_id, source_id=source_id, limit=5000),
            "jobs": self.fetch_jobs(case_id=case_id, source_id=source_id, limit=500),
            "audit_events": self.fetch_audit_events(case_id=case_id, source_id=source_id, limit=500),
            "watcher_states": self.fetch_watcher_states(case_id=case_id, source_id=source_id, limit=500),
            "watched_sources": self.fetch_watched_sources(case_id=case_id, source_id=source_id, limit=500),
            "relationships": self.fetch_relationships(case_id=case_id, source_id=source_id, limit=5000),
            "timelines": self.fetch_timelines(case_id=case_id, source_id=source_id, limit=100),
            "graph": self.graph_view(case_id=case_id, source_id=source_id),
        }

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_schema(self, connection: sqlite3.Connection) -> None:
        connection.executescript(SCHEMA_SQL)
        connection.execute(
            """
            INSERT INTO metadata(key, value)
            VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            ("schema_version", "1"),
        )

    def _upsert_source(self, connection: sqlite3.Connection, source: SourceRecord) -> None:
        payload_json = json.dumps(record_to_dict(source), sort_keys=True, ensure_ascii=True)
        connection.execute(
            """
            INSERT INTO sources(
                id,
                source_id,
                case_id,
                source_type,
                locator,
                display_name,
                collector,
                media_type,
                content_hash,
                size_bytes,
                created_at,
                payload_json
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                source_id = excluded.source_id,
                case_id = excluded.case_id,
                source_type = excluded.source_type,
                locator = excluded.locator,
                display_name = excluded.display_name,
                collector = excluded.collector,
                media_type = excluded.media_type,
                content_hash = excluded.content_hash,
                size_bytes = excluded.size_bytes,
                created_at = excluded.created_at,
                payload_json = excluded.payload_json
            """,
            (
                source.id,
                source.source_id,
                source.case_id,
                source.source_type,
                source.locator,
                source.display_name,
                source.collector,
                source.media_type,
                source.content_hash,
                source.size_bytes,
                source.created_at,
                payload_json,
            ),
        )

    def _upsert_record(self, connection: sqlite3.Connection, record: RecordBase) -> None:
        payload_json = json.dumps(record_to_dict(record), sort_keys=True, ensure_ascii=True)
        scalar_fields = self._record_scalar_fields(record)
        connection.execute(
            """
            INSERT INTO records(
                record_id,
                source_id,
                case_id,
                record_type,
                fingerprint,
                created_at,
                observed_at,
                title,
                value,
                normalized_value,
                relationship_type,
                source_ref,
                target_ref,
                event_type,
                timestamp,
                start_time,
                end_time,
                payload_json
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(record_id) DO UPDATE SET
                source_id = excluded.source_id,
                case_id = excluded.case_id,
                record_type = excluded.record_type,
                fingerprint = excluded.fingerprint,
                created_at = excluded.created_at,
                observed_at = excluded.observed_at,
                title = excluded.title,
                value = excluded.value,
                normalized_value = excluded.normalized_value,
                relationship_type = excluded.relationship_type,
                source_ref = excluded.source_ref,
                target_ref = excluded.target_ref,
                event_type = excluded.event_type,
                timestamp = excluded.timestamp,
                start_time = excluded.start_time,
                end_time = excluded.end_time,
                payload_json = excluded.payload_json
            """,
            (
                record.id,
                record.source_id,
                record.case_id,
                record.record_type,
                canonical_fingerprint(record),
                record.created_at,
                record.observed_at,
                scalar_fields["title"],
                scalar_fields["value"],
                scalar_fields["normalized_value"],
                scalar_fields["relationship_type"],
                scalar_fields["source_ref"],
                scalar_fields["target_ref"],
                scalar_fields["event_type"],
                scalar_fields["timestamp"],
                scalar_fields["start_time"],
                scalar_fields["end_time"],
                payload_json,
            ),
        )

        if isinstance(record, RelationshipRecord):
            connection.execute(
                """
                INSERT INTO relationships(
                    relationship_id,
                    source_id,
                    case_id,
                    relationship_type,
                    source_ref,
                    target_ref,
                    directed,
                    reason,
                    payload_json
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(relationship_id) DO UPDATE SET
                    source_id = excluded.source_id,
                    case_id = excluded.case_id,
                    relationship_type = excluded.relationship_type,
                    source_ref = excluded.source_ref,
                    target_ref = excluded.target_ref,
                    directed = excluded.directed,
                    reason = excluded.reason,
                    payload_json = excluded.payload_json
                """,
                (
                    record.id,
                    record.source_id,
                    record.case_id,
                    record.relationship_type,
                    record.source_ref,
                    record.target_ref,
                    int(record.directed),
                    record.reason,
                    payload_json,
                ),
            )
        else:
            connection.execute("DELETE FROM relationships WHERE relationship_id = ?", (record.id,))

        if isinstance(record, TimelineRecord):
            connection.execute("DELETE FROM timeline_events WHERE timeline_id = ?", (record.id,))
            for sort_order, event_id in enumerate(record.event_refs, start=1):
                connection.execute(
                    """
                    INSERT INTO timeline_events(timeline_id, event_id, source_id, case_id, sort_order)
                    VALUES(?, ?, ?, ?, ?)
                    """,
                    (record.id, event_id, record.source_id, record.case_id, sort_order),
                )
        else:
            connection.execute("DELETE FROM timeline_events WHERE timeline_id = ?", (record.id,))

    def _upsert_job(self, connection: sqlite3.Connection, record: JobRecord) -> None:
        payload_json = json.dumps(record_to_dict(record), sort_keys=True, ensure_ascii=True)
        connection.execute(
            """
            INSERT INTO jobs(
                job_id,
                source_id,
                case_id,
                stage,
                status,
                worker,
                started_at,
                finished_at,
                payload_json
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                source_id = excluded.source_id,
                case_id = excluded.case_id,
                stage = excluded.stage,
                status = excluded.status,
                worker = excluded.worker,
                started_at = excluded.started_at,
                finished_at = excluded.finished_at,
                payload_json = excluded.payload_json
            """,
            (
                record.id,
                record.source_id,
                record.case_id,
                record.stage,
                record.status,
                record.worker,
                record.started_at,
                record.finished_at,
                payload_json,
            ),
        )

    def _upsert_audit_event(self, connection: sqlite3.Connection, payload: dict[str, object]) -> None:
        audit_id = str(payload.get("audit_id") or "").strip()
        if not audit_id:
            return
        payload_json = json.dumps(payload, sort_keys=True, ensure_ascii=True)
        connection.execute(
            """
            INSERT INTO audit_events(
                audit_id,
                source_id,
                case_id,
                stage,
                plugin,
                job_id,
                ok,
                status,
                created_at,
                metrics_json,
                warnings_json,
                errors_json,
                artifact_paths_json,
                payload_json
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(audit_id) DO UPDATE SET
                source_id = excluded.source_id,
                case_id = excluded.case_id,
                stage = excluded.stage,
                plugin = excluded.plugin,
                job_id = excluded.job_id,
                ok = excluded.ok,
                status = excluded.status,
                created_at = excluded.created_at,
                metrics_json = excluded.metrics_json,
                warnings_json = excluded.warnings_json,
                errors_json = excluded.errors_json,
                artifact_paths_json = excluded.artifact_paths_json,
                payload_json = excluded.payload_json
            """,
            (
                audit_id,
                str(payload.get("source_id") or ""),
                str(payload.get("case_id") or ""),
                str(payload.get("stage") or ""),
                str(payload.get("plugin") or ""),
                str(payload.get("job_id") or ""),
                int(bool(payload.get("ok"))),
                str(payload.get("status") or ""),
                str(payload.get("created_at") or ""),
                json.dumps(dict(payload.get("metrics") or {}), sort_keys=True, ensure_ascii=True),
                json.dumps(list(payload.get("warnings") or []), ensure_ascii=True),
                json.dumps(list(payload.get("errors") or []), ensure_ascii=True),
                json.dumps(list(payload.get("artifact_paths") or []), ensure_ascii=True),
                payload_json,
            ),
        )

    def _upsert_watcher_state(self, connection: sqlite3.Connection, payload: dict[str, object]) -> None:
        watcher_id = str(payload.get("watcher_id") or "").strip()
        if not watcher_id:
            return
        payload_json = json.dumps(payload, sort_keys=True, ensure_ascii=True)
        connection.execute(
            """
            INSERT INTO watcher_states(
                watcher_id,
                source_id,
                case_id,
                watcher_type,
                source_type,
                locator,
                status,
                last_checked_at,
                last_seen_at,
                last_changed_at,
                cursor,
                content_hash,
                suppression_until,
                backlog_pointer,
                consecutive_no_change_count,
                total_check_count,
                total_change_count,
                last_error,
                payload_json
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(watcher_id) DO UPDATE SET
                source_id = excluded.source_id,
                case_id = excluded.case_id,
                watcher_type = excluded.watcher_type,
                source_type = excluded.source_type,
                locator = excluded.locator,
                status = excluded.status,
                last_checked_at = excluded.last_checked_at,
                last_seen_at = excluded.last_seen_at,
                last_changed_at = excluded.last_changed_at,
                cursor = excluded.cursor,
                content_hash = excluded.content_hash,
                suppression_until = excluded.suppression_until,
                backlog_pointer = excluded.backlog_pointer,
                consecutive_no_change_count = excluded.consecutive_no_change_count,
                total_check_count = excluded.total_check_count,
                total_change_count = excluded.total_change_count,
                last_error = excluded.last_error,
                payload_json = excluded.payload_json
            """,
            (
                watcher_id,
                str(payload.get("source_id") or ""),
                str(payload.get("case_id") or ""),
                str(payload.get("watcher_type") or ""),
                str(payload.get("source_type") or ""),
                str(payload.get("locator") or ""),
                str(payload.get("status") or ""),
                str(payload.get("last_checked_at") or ""),
                str(payload.get("last_seen_at") or ""),
                str(payload.get("last_changed_at") or ""),
                str(payload.get("cursor") or ""),
                str(payload.get("content_hash") or ""),
                str(payload.get("suppression_until") or ""),
                str(payload.get("backlog_pointer") or ""),
                int(payload.get("consecutive_no_change_count") or 0),
                int(payload.get("total_check_count") or 0),
                int(payload.get("total_change_count") or 0),
                str(payload.get("last_error") or ""),
                payload_json,
            ),
        )

    def _upsert_watched_source(self, connection: sqlite3.Connection, payload: dict[str, object]) -> None:
        watch_id = str(payload.get("watch_id") or "").strip()
        if not watch_id:
            return
        payload_json = json.dumps(payload, sort_keys=True, ensure_ascii=True)
        connection.execute(
            """
            INSERT INTO watched_sources(
                watch_id,
                case_id,
                source_type,
                locator,
                display_name,
                recursive,
                enabled,
                poll_interval_seconds,
                status,
                created_at,
                updated_at,
                payload_json
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(watch_id) DO UPDATE SET
                case_id = excluded.case_id,
                source_type = excluded.source_type,
                locator = excluded.locator,
                display_name = excluded.display_name,
                recursive = excluded.recursive,
                enabled = excluded.enabled,
                poll_interval_seconds = excluded.poll_interval_seconds,
                status = excluded.status,
                created_at = excluded.created_at,
                updated_at = excluded.updated_at,
                payload_json = excluded.payload_json
            """,
            (
                watch_id,
                str(payload.get("case_id") or ""),
                str(payload.get("source_type") or ""),
                str(payload.get("locator") or ""),
                str(payload.get("display_name") or ""),
                int(payload.get("recursive") or 0),
                int(payload.get("enabled") or 0),
                float(payload.get("poll_interval_seconds") or 0.0),
                str(payload.get("status") or ""),
                str(payload.get("created_at") or ""),
                str(payload.get("updated_at") or ""),
                payload_json,
            ),
        )

    def _normalize_watcher_state(self, payload: dict[str, object]) -> dict[str, object]:
        row = dict(payload or {})
        return {
            **row,
            "watcher_id": str(row.get("watcher_id") or row.get("id") or "").strip(),
            "source_id": str(row.get("source_id") or "").strip(),
            "case_id": str(row.get("case_id") or "").strip(),
            "watcher_type": str(row.get("watcher_type") or "").strip(),
            "source_type": str(row.get("source_type") or "").strip(),
            "locator": str(row.get("locator") or "").strip(),
            "status": str(row.get("status") or "").strip(),
            "last_checked_at": str(row.get("last_checked_at") or "").strip(),
            "last_seen_at": str(row.get("last_seen_at") or "").strip(),
            "last_changed_at": str(row.get("last_changed_at") or "").strip(),
            "cursor": str(row.get("cursor") or "").strip(),
            "content_hash": str(row.get("content_hash") or "").strip(),
            "suppression_until": str(row.get("suppression_until") or "").strip(),
            "backlog_pointer": str(row.get("backlog_pointer") or "").strip(),
            "consecutive_no_change_count": int(row.get("consecutive_no_change_count") or 0),
            "total_check_count": int(row.get("total_check_count") or 0),
            "total_change_count": int(row.get("total_change_count") or 0),
            "last_error": str(row.get("last_error") or "").strip(),
        }

    def _normalize_watched_source(self, payload: dict[str, object]) -> dict[str, object]:
        row = dict(payload or {})
        return {
            **row,
            "watch_id": str(row.get("watch_id") or row.get("id") or "").strip(),
            "case_id": str(row.get("case_id") or "").strip(),
            "source_type": str(row.get("source_type") or "").strip(),
            "locator": str(row.get("locator") or "").strip(),
            "display_name": str(row.get("display_name") or "").strip(),
            "recursive": int(bool(row.get("recursive"))),
            "enabled": int(bool(row.get("enabled", True))),
            "poll_interval_seconds": float(row.get("poll_interval_seconds") or 0.0),
            "status": str(row.get("status") or "").strip(),
            "created_at": str(row.get("created_at") or "").strip(),
            "updated_at": str(row.get("updated_at") or "").strip(),
        }

    def _record_scalar_fields(self, record: RecordBase) -> dict[str, str]:
        title = ""
        value = ""
        normalized_value = ""
        relationship_type = ""
        source_ref = ""
        target_ref = ""
        event_type = ""
        timestamp = ""
        start_time = ""
        end_time = ""

        if isinstance(record, ArtifactRecord):
            value = record.path
        elif isinstance(record, IndicatorRecord):
            value = record.value
            normalized_value = record.normalized_value or record.value
        elif isinstance(record, IdentityRecord):
            value = record.value
            normalized_value = record.normalized_value or record.value
        elif isinstance(record, CredentialRecord):
            value = record.identifier or record.username or record.secret_ref
            normalized_value = record.identifier or record.username
        elif isinstance(record, RelationshipRecord):
            relationship_type = record.relationship_type
            source_ref = record.source_ref
            target_ref = record.target_ref
        elif isinstance(record, EventRecord):
            title = record.title
            event_type = record.event_type
            timestamp = record.timestamp or record.observed_at
        elif isinstance(record, TimelineRecord):
            title = record.title
            start_time = record.start_time
            end_time = record.end_time
        elif isinstance(record, JobRecord):
            title = f"{record.stage}:{record.status}"

        return {
            "title": title,
            "value": value,
            "normalized_value": normalized_value,
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
            "event_type": event_type,
            "timestamp": timestamp,
            "start_time": start_time,
            "end_time": end_time,
        }

    def _record_filters(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        extra_filters: Iterable[tuple[str, str]] = (),
    ) -> tuple[str, tuple[str, ...]]:
        return self._build_filters(case_id=case_id, source_id=source_id, extra_filters=extra_filters)

    def _source_filters(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        extra_filters: Iterable[tuple[str, str]] = (),
    ) -> tuple[str, tuple[str, ...]]:
        return self._build_filters(case_id=case_id, source_id=source_id, extra_filters=extra_filters)

    def _relationship_filters(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        extra_filters: Iterable[tuple[str, str]] = (),
    ) -> tuple[str, tuple[str, ...]]:
        return self._build_filters(case_id=case_id, source_id=source_id, extra_filters=extra_filters)

    def _job_filters(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        extra_filters: Iterable[tuple[str, str]] = (),
    ) -> tuple[str, tuple[str, ...]]:
        return self._build_filters(case_id=case_id, source_id=source_id, extra_filters=extra_filters)

    def _audit_filters(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        extra_filters: Iterable[tuple[str, str]] = (),
    ) -> tuple[str, tuple[str, ...]]:
        return self._build_filters(case_id=case_id, source_id=source_id, extra_filters=extra_filters)

    def _watcher_filters(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        extra_filters: Iterable[tuple[str, str]] = (),
    ) -> tuple[str, tuple[str, ...]]:
        return self._build_filters(case_id=case_id, source_id=source_id, extra_filters=extra_filters)

    def _watched_source_filters(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        extra_filters: Iterable[tuple[str, str]] = (),
    ) -> tuple[str, tuple[str, ...]]:
        effective_source_id = ""
        return self._build_filters(case_id=case_id, source_id=effective_source_id, extra_filters=extra_filters)

    def _build_filters(
        self,
        *,
        case_id: str = "",
        source_id: str = "",
        extra_filters: Iterable[tuple[str, str]] = (),
    ) -> tuple[str, tuple[str, ...]]:
        clauses: list[str] = []
        params: list[str] = []
        if case_id:
            clauses.append("case_id = ?")
            params.append(case_id)
        elif source_id:
            clauses.append("source_id = ?")
            params.append(source_id)
        for field_name, field_value in extra_filters:
            text = str(field_value or "").strip()
            if not text:
                continue
            clauses.append(f"{field_name} = ?")
            params.append(text)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where_sql, tuple(params)

    def _node_label(self, payload: dict[str, object]) -> str:
        for key in ("title", "normalized_value", "value", "locator", "display_name", "id"):
            value = str(payload.get(key) or "").strip()
            if value:
                return value
        return str(payload.get("id") or "record")

    def _fetch_nodes_by_ids(self, node_ids: Iterable[str]) -> list[dict[str, object]]:
        ids = [str(node_id).strip() for node_id in node_ids if str(node_id).strip()]
        if not ids:
            return []

        nodes: dict[str, dict[str, object]] = {}
        with self._connect() as connection:
            self._initialize_schema(connection)
            record_placeholders = ", ".join("?" for _ in ids)
            record_rows = connection.execute(
                f"""
                SELECT payload_json
                FROM records
                WHERE record_id IN ({record_placeholders})
                """,
                tuple(ids),
            ).fetchall()
            source_rows = connection.execute(
                f"""
                SELECT payload_json
                FROM sources
                WHERE id IN ({record_placeholders})
                """,
                tuple(ids),
            ).fetchall()

        for row in source_rows:
            payload = json.loads(str(row["payload_json"]))
            node_id = str(payload.get("id") or payload.get("source_id") or "")
            if not node_id:
                continue
            nodes[node_id] = {
                "id": node_id,
                "kind": "source",
                "label": str(payload.get("display_name") or payload.get("locator") or node_id),
                "record_type": "source",
            }
        for row in record_rows:
            payload = json.loads(str(row["payload_json"]))
            record_type = str(payload.get("record_type") or "")
            if record_type == "relationship":
                continue
            node_id = str(payload.get("id") or "")
            if not node_id:
                continue
            nodes[node_id] = {
                "id": node_id,
                "kind": record_type or "record",
                "label": self._node_label(payload),
                "record_type": record_type or "record",
            }
        return list(nodes.values())
