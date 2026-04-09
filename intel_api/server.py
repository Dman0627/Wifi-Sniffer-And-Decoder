from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from intel_runtime import MonitorRuntime
from intel_runtime.monitor import build_monitor_forecast
from intel_storage import SQLiteIntelligenceStore, list_cleanup_reports, list_queue_archives

from .app import PlatformApp
from .dashboard_render import (
    render_case_dashboard_html,
    render_case_index_html,
    render_graph_html,
    render_monitor_html,
    render_timeline_html,
)


def create_api_server(
    database_path: str | Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> ThreadingHTTPServer:
    store = SQLiteIntelligenceStore(database_path)
    store.initialize()
    app = PlatformApp()
    monitor_output_root = _derive_monitor_output_root(store.database_path)

    class IntelligenceApiHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler interface
            parsed = urlsplit(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query, keep_blank_values=False)

            try:
                if self._is_html_route(path):
                    payload = self._route_html(path, query)
                    self._write_html(200, payload)
                else:
                    payload = self._route(path, query)
                    self._write_json(200, payload)
            except KeyError as exc:
                self._write_json(404, {"error": f"not found: {exc.args[0]}"})
            except ValueError as exc:
                self._write_json(400, {"error": str(exc)})

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler interface
            parsed = urlsplit(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query, keep_blank_values=False)
            body = self._read_post_body()

            try:
                payload, redirect_to = self._route_post(path, query, body)
                if redirect_to:
                    self._write_redirect(303, redirect_to)
                else:
                    self._write_json(200, payload)
            except KeyError as exc:
                self._write_json(404, {"error": f"not found: {exc.args[0]}"})
            except ValueError as exc:
                self._write_json(400, {"error": str(exc)})

        def log_message(self, format: str, *args) -> None:  # noqa: A003 - standard library signature
            _unused = format, args

        def _is_html_route(self, path: str) -> bool:
            if path in {"/", "/dashboard", "/monitor-view"}:
                return True
            parts = [unquote(part) for part in path.split("/") if part]
            return len(parts) == 3 and parts[0] == "cases" and parts[2] in {
                "dashboard",
                "monitor-view",
                "timeline-view",
                "graph-view",
            }

        def _route_html(self, path: str, query: dict[str, list[str]]) -> str:
            if path in {"/", "/dashboard"}:
                return render_case_index_html(
                    store,
                    plugin_statuses=app.plugin_statuses(output_root=str(monitor_output_root)),
                    plugin_settings=app.plugin_settings(output_root=str(monitor_output_root)),
                    monitor_view=_build_monitor_view(case_id=""),
                )
            if path == "/monitor-view":
                return render_monitor_html(
                    case_id="",
                    monitor_view=_build_monitor_view(case_id=""),
                )

            parts = [unquote(part) for part in path.split("/") if part]
            if len(parts) != 3 or parts[0] != "cases":
                raise KeyError(path)
            case_id = parts[1]
            view_name = parts[2]
            if view_name == "dashboard":
                return render_case_dashboard_html(
                    store,
                    case_id=case_id,
                    search_query=self._single(query, "q"),
                    record_type=self._single(query, "record_type"),
                    node_id=self._single(query, "node_id"),
                    depth=self._depth(query),
                    timeline_id=self._single(query, "timeline_id"),
                    plugin_statuses=app.plugin_statuses(output_root=str(monitor_output_root)),
                    plugin_settings=app.plugin_settings(output_root=str(monitor_output_root)),
                    monitor_view=_build_monitor_view(case_id=case_id),
                )
            if view_name == "monitor-view":
                return render_monitor_html(
                    case_id=case_id,
                    monitor_view=_build_monitor_view(case_id=case_id),
                )
            if view_name == "timeline-view":
                return render_timeline_html(
                    store,
                    case_id=case_id,
                    timeline_id=self._single(query, "timeline_id"),
                )
            if view_name == "graph-view":
                return render_graph_html(
                    store,
                    case_id=case_id,
                    node_id=self._single(query, "node_id"),
                    depth=self._depth(query),
                )
            raise KeyError(path)

        def _route(self, path: str, query: dict[str, list[str]]) -> dict[str, object]:
            if path == "/health":
                return {
                    "ok": True,
                    "database_path": str(store.database_path),
                    "plugin_summary": app.plugin_status_summary(output_root=str(monitor_output_root)),
                    "plugin_settings": app.plugin_settings(output_root=str(monitor_output_root)),
                    "monitor": _build_monitor_view(case_id=""),
                }
            if path == "/plugins":
                statuses = app.plugin_statuses(output_root=str(monitor_output_root))
                settings = app.plugin_settings(output_root=str(monitor_output_root))
                return {
                    "summary": app.plugin_status_summary(output_root=str(monitor_output_root)),
                    "plugins": list(statuses),
                    "settings": settings["settings"],
                    "active_profile": settings["active_profile"],
                    "profiles": settings["profiles"],
                    "settings_path": settings["settings_path"],
                }
            if path == "/monitor":
                return {"monitor": _build_monitor_view(case_id="")}
            if path == "/monitor-tuning":
                return app.get_monitor_tuning(output_root=str(monitor_output_root))
            if path == "/monitor-forecast":
                runtime = MonitorRuntime(
                    app=app,
                    output_root=monitor_output_root,
                    database_path=str(store.database_path),
                    case_id="",
                )
                history = runtime.read_history(limit=48)
                status = runtime.read_status()
                return {
                    "forecast": dict(
                        status.get("forecast")
                        or build_monitor_forecast(
                            history,
                            tuning=dict(status.get("tuning") or {}),
                            status=status,
                        )
                    )
                }
            if path == "/monitor-history":
                runtime = MonitorRuntime(
                    app=app,
                    output_root=monitor_output_root,
                    database_path=str(store.database_path),
                    case_id="",
                )
                return {"history": runtime.read_history(limit=self._limit(query, default=100))}
            if path == "/archives":
                return {
                    "archives": list_queue_archives(
                        monitor_output_root,
                        archive_state=self._single(query, "archive_state"),
                        stage=self._single(query, "stage"),
                        limit=self._limit(query, default=100),
                    )
                }
            if path == "/cleanup-reports":
                return {
                    "cleanup_reports": list_cleanup_reports(
                        monitor_output_root,
                        limit=self._limit(query, default=25),
                    )
                }
            if path == "/cases":
                return {"cases": store.list_cases()}

            parts = [unquote(part) for part in path.split("/") if part]
            if len(parts) < 2 or parts[0] != "cases":
                raise KeyError(path)
            case_id = parts[1]
            if len(parts) == 2:
                return {"summary": store.case_summary(case_id=case_id)}
            if len(parts) != 3:
                raise KeyError(path)

            view_name = parts[2]
            if view_name == "summary":
                return {"summary": store.case_summary(case_id=case_id)}
            if view_name == "monitor":
                return {"monitor": _build_monitor_view(case_id=case_id)}
            if view_name == "monitor-tuning":
                return app.get_monitor_tuning(case_id=case_id, output_root=str(monitor_output_root))
            if view_name == "monitor-forecast":
                runtime = MonitorRuntime(
                    app=app,
                    output_root=monitor_output_root,
                    database_path=str(store.database_path),
                    case_id=case_id,
                )
                history = runtime.read_history(limit=48)
                status = runtime.read_status()
                return {
                    "forecast": dict(
                        status.get("forecast")
                        or build_monitor_forecast(
                            history,
                            tuning=dict(status.get("tuning") or {}),
                            status=status,
                        )
                    )
                }
            if view_name == "monitor-history":
                runtime = MonitorRuntime(
                    app=app,
                    output_root=monitor_output_root,
                    database_path=str(store.database_path),
                    case_id=case_id,
                )
                return {"history": runtime.read_history(limit=self._limit(query, default=100))}
            if view_name == "archives":
                return {
                    "archives": list_queue_archives(
                        monitor_output_root,
                        case_id=case_id,
                        archive_state=self._single(query, "archive_state"),
                        stage=self._single(query, "stage"),
                        limit=self._limit(query, default=100),
                    )
                }
            if view_name == "cleanup-reports":
                return {
                    "cleanup_reports": list_cleanup_reports(
                        monitor_output_root,
                        limit=self._limit(query, default=25),
                    )
                }
            if view_name == "watch-sources":
                watch_id = self._single(query, "watch_id")
                if watch_id:
                    return app.get_watch_source_detail(
                        case_id=case_id,
                        watch_id=watch_id,
                        output_root=str(monitor_output_root),
                        database_path=str(store.database_path),
                    )
                return app.list_watch_sources(
                    case_id=case_id,
                    output_root=str(monitor_output_root),
                    database_path=str(store.database_path),
                )
            if view_name == "watchers":
                watch_id = self._single(query, "watch_id")
                if watch_id:
                    detail = app.get_watch_source_detail(
                        case_id=case_id,
                        watch_id=watch_id,
                        output_root=str(monitor_output_root),
                        database_path=str(store.database_path),
                    )
                    return {
                        "watcher_state": detail.get("watcher_state", {}),
                        "watched_source": detail.get("watched_source", {}),
                        "watcher_summary": detail.get("watcher_summary", {}),
                    }
                watcher_id = self._single(query, "watcher_id")
                rows = store.fetch_watcher_states(
                    case_id=case_id,
                    watcher_id=watcher_id,
                    watcher_type="source_monitor",
                    limit=500,
                )
                return {
                    "watchers": rows,
                    "watcher_summary": store.watcher_summary(case_id=case_id),
                }
            if view_name == "records":
                record_type = self._single(query, "record_type")
                search_query = self._single(query, "q")
                limit = self._limit(query)
                if search_query:
                    return {
                        "records": store.search_records(
                            case_id=case_id,
                            query=search_query,
                            record_type=record_type,
                            limit=limit,
                        )
                    }
                return {"records": store.fetch_records(case_id=case_id, record_type=record_type, limit=limit)}
            if view_name == "search":
                search_query = self._single(query, "q")
                if not search_query:
                    raise ValueError("q is required")
                record_type = self._single(query, "record_type")
                limit = self._limit(query, default=100)
                return {
                    "records": store.search_records(
                        case_id=case_id,
                        query=search_query,
                        record_type=record_type,
                        limit=limit,
                    )
                }
            if view_name == "relationships":
                relationship_type = self._single(query, "relationship_type")
                limit = self._limit(query)
                return {
                    "relationships": store.fetch_relationships(
                        case_id=case_id,
                        relationship_type=relationship_type,
                        limit=limit,
                    )
                }
            if view_name == "timeline":
                timeline_id = self._single(query, "timeline_id")
                if timeline_id:
                    detail = store.timeline_detail(case_id=case_id, timeline_id=timeline_id)
                    if detail is None:
                        raise KeyError(path)
                    return detail
                limit = self._limit(query, default=50)
                return {"timelines": store.fetch_timelines(case_id=case_id, limit=limit)}
            if view_name == "graph":
                node_id = self._single(query, "node_id")
                if node_id:
                    depth = self._depth(query)
                    limit = self._limit(query, default=250)
                    return {
                        "graph": store.graph_neighbors(
                            case_id=case_id,
                            node_id=node_id,
                            depth=depth,
                            limit=limit,
                        )
                    }
                return {"graph": store.graph_view(case_id=case_id)}
            if view_name == "jobs":
                stage = self._single(query, "stage")
                status = self._single(query, "status")
                limit = self._limit(query, default=100)
                return {
                    "jobs": store.fetch_jobs(
                        case_id=case_id,
                        stage=stage,
                        status=status,
                        limit=limit,
                    )
                }
            if view_name == "audit":
                stage = self._single(query, "stage")
                status = self._single(query, "status")
                limit = self._limit(query, default=100)
                return {
                    "audit_events": store.fetch_audit_events(
                        case_id=case_id,
                        stage=stage,
                        status=status,
                        limit=limit,
                    )
                }
            if view_name == "export":
                return {"export": store.export_dataset(case_id=case_id)}
            raise KeyError(path)

        def _route_post(
            self,
            path: str,
            query: dict[str, list[str]],
            body: dict[str, object],
        ) -> tuple[dict[str, object], str]:
            if path == "/plugins":
                return_to = self._body_single(body, "return_to")
                action = self._body_single(body, "action").lower()
                profile_name = self._body_single(body, "profile_name")
                plugin_name = self._body_single(body, "plugin_name")
                if action == "enable":
                    payload = app.update_plugin_settings(
                        output_root=str(monitor_output_root),
                        plugin_name=plugin_name,
                        enabled=True,
                        profile_name=profile_name,
                    )
                elif action == "disable":
                    payload = app.update_plugin_settings(
                        output_root=str(monitor_output_root),
                        plugin_name=plugin_name,
                        enabled=False,
                        profile_name=profile_name,
                    )
                elif action == "set-active-profile":
                    payload = app.update_plugin_settings(
                        output_root=str(monitor_output_root),
                        set_active_profile=profile_name,
                    )
                elif action == "save-profile":
                    payload = app.update_plugin_settings(
                        output_root=str(monitor_output_root),
                        save_profile_as=profile_name,
                        source_profile_name=self._body_single(body, "source_profile_name"),
                    )
                elif action == "delete-profile":
                    payload = app.update_plugin_settings(
                        output_root=str(monitor_output_root),
                        delete_profile_name=profile_name,
                    )
                else:
                    raise ValueError("unsupported plugin action")
                return payload, return_to

            if path == "/monitor-tuning":
                return_to = self._body_single(body, "return_to")
                payload = app.update_monitor_tuning(
                    output_root=str(monitor_output_root),
                    **self._monitor_tuning_updates(body),
                )
                return payload, return_to

            parts = [unquote(part) for part in path.split("/") if part]
            if len(parts) != 3 or parts[0] != "cases":
                raise KeyError(path)
            case_id = parts[1]
            view_name = parts[2]
            return_to = self._body_single(body, "return_to")

            if view_name == "monitor-tuning":
                payload = app.update_monitor_tuning(
                    case_id=case_id,
                    output_root=str(monitor_output_root),
                    **self._monitor_tuning_updates(body),
                )
                return payload, return_to

            if view_name == "watch-sources":
                watch_id = self._body_single(body, "watch_id")
                if not watch_id:
                    raise ValueError("watch_id is required")
                action = self._body_single(body, "action").lower()
                enabled_value = self._body_single(body, "enabled")
                if action == "enable":
                    enabled = True
                    payload = app.set_watch_source_enabled(
                        case_id=case_id,
                        watch_id=watch_id,
                        enabled=enabled,
                        output_root=str(monitor_output_root),
                        database_path=str(store.database_path),
                    )
                elif action == "disable":
                    enabled = False
                    payload = app.set_watch_source_enabled(
                        case_id=case_id,
                        watch_id=watch_id,
                        enabled=enabled,
                        output_root=str(monitor_output_root),
                        database_path=str(store.database_path),
                    )
                elif action in {"snooze", "resume"}:
                    payload = app.set_watch_source_snooze(
                        case_id=case_id,
                        watch_id=watch_id,
                        seconds=self._float_body(body, "seconds", default=600.0),
                        mode="clear" if action == "resume" else "set",
                        output_root=str(monitor_output_root),
                        database_path=str(store.database_path),
                    )
                elif action == "update":
                    poll_value = self._body_single(body, "poll_interval_seconds")
                    tuning_preset_name = self._body_single(body, "tuning_preset_name")
                    forecast_min_history_value = self._body_single(body, "forecast_min_history")
                    source_churn_spike_factor_value = self._body_single(body, "source_churn_spike_factor")
                    payload = app.update_watch_source_settings(
                        case_id=case_id,
                        watch_id=watch_id,
                        poll_interval_seconds=self._float_body(body, "poll_interval_seconds") if poll_value else None,
                        notes=self._body_single(body, "notes") if "notes" in body else None,
                        tags=self._body_single(body, "tags") if "tags" in body else None,
                        tuning_preset_name=tuning_preset_name if tuning_preset_name else None,
                        forecast_min_history=int(float(forecast_min_history_value)) if forecast_min_history_value else None,
                        source_churn_spike_factor=(
                            self._float_body(body, "source_churn_spike_factor")
                            if source_churn_spike_factor_value
                            else None
                        ),
                        suppressed_alert_ids=(
                            _coerce_csv_list(body.get("suppressed_alert_ids"))
                            if "suppressed_alert_ids" in body
                            else None
                        ),
                        clear_tuning_profile=(
                            _coerce_bool(self._body_single(body, "clear_tuning_profile"))
                            if self._body_single(body, "clear_tuning_profile")
                            else False
                        ),
                        output_root=str(monitor_output_root),
                        database_path=str(store.database_path),
                    )
                elif enabled_value:
                    payload = app.set_watch_source_enabled(
                        case_id=case_id,
                        watch_id=watch_id,
                        enabled=_coerce_bool(enabled_value),
                        output_root=str(monitor_output_root),
                        database_path=str(store.database_path),
                    )
                else:
                    raise ValueError("action or enabled is required")
                return payload, return_to

            if view_name == "watchers":
                watch_id = self._body_single(body, "watch_id")
                if not watch_id:
                    raise ValueError("watch_id is required")
                action = self._body_single(body, "action").lower()
                seconds = self._float_body(body, "seconds", default=60.0)
                if action in {"clear", "clear_suppression"}:
                    payload = app.set_watch_source_suppression(
                        case_id=case_id,
                        watch_id=watch_id,
                        seconds=0.0,
                        mode="clear",
                        output_root=str(monitor_output_root),
                        database_path=str(store.database_path),
                    )
                elif action in {"shorten", "shorten_suppression"}:
                    payload = app.set_watch_source_suppression(
                        case_id=case_id,
                        watch_id=watch_id,
                        seconds=seconds,
                        mode="shorten",
                        output_root=str(monitor_output_root),
                        database_path=str(store.database_path),
                    )
                else:
                    raise ValueError("unsupported watcher action")
                return payload, return_to

            raise KeyError(path)

        def _limit(self, query: dict[str, list[str]], *, default: int = 500) -> int:
            text = self._single(query, "limit")
            if not text:
                return default
            value = int(text)
            if value <= 0:
                raise ValueError("limit must be positive")
            return min(value, 5000)

        def _depth(self, query: dict[str, list[str]], *, default: int = 1) -> int:
            text = self._single(query, "depth")
            if not text:
                return default
            value = int(text)
            if value <= 0:
                raise ValueError("depth must be positive")
            return min(value, 4)

        def _single(self, query: dict[str, list[str]], key: str) -> str:
            values = query.get(key, [])
            return str(values[0]).strip() if values else ""

        def _body_single(self, body: dict[str, object], key: str) -> str:
            value = body.get(key, "")
            if isinstance(value, list):
                return str(value[0]).strip() if value else ""
            return str(value).strip() if value is not None else ""

        def _float_body(self, body: dict[str, object], key: str, *, default: float = 0.0) -> float:
            text = self._body_single(body, key)
            if not text:
                return default
            try:
                return float(text)
            except ValueError as exc:
                raise ValueError(f"{key} must be numeric") from exc

        def _monitor_tuning_updates(self, body: dict[str, object]) -> dict[str, object]:
            updates: dict[str, object] = {}
            preset_name = self._body_single(body, "preset_name")
            if preset_name:
                updates["preset_name"] = preset_name
            automation_mode = self._body_single(body, "automation_mode")
            if automation_mode:
                updates["automation_mode"] = automation_mode
            forecast_min_history = self._body_single(body, "forecast_min_history")
            if forecast_min_history:
                updates["forecast_min_history"] = int(float(forecast_min_history))
            queue_spike_factor = self._body_single(body, "queue_spike_factor")
            if queue_spike_factor:
                updates["queue_spike_factor"] = float(queue_spike_factor)
            source_churn_spike_factor = self._body_single(body, "source_churn_spike_factor")
            if source_churn_spike_factor:
                updates["source_churn_spike_factor"] = float(source_churn_spike_factor)
            throughput_drop_factor = self._body_single(body, "throughput_drop_factor")
            if throughput_drop_factor:
                updates["throughput_drop_factor"] = float(throughput_drop_factor)
            clear_suppressions_text = self._body_single(body, "clear_suppressions")
            if clear_suppressions_text:
                clear_suppressions = _coerce_bool(clear_suppressions_text)
                if clear_suppressions:
                    updates["suppressed_alert_ids"] = []
                    updates["suppressed_stage_alerts"] = {}
                    updates["suppressed_watch_alerts"] = {}
            clear_alert_severities_text = self._body_single(body, "clear_alert_severities")
            if clear_alert_severities_text and _coerce_bool(clear_alert_severities_text):
                updates["alert_severity_overrides"] = {}
            clear_stage_thresholds_text = self._body_single(body, "clear_stage_thresholds")
            if clear_stage_thresholds_text and _coerce_bool(clear_stage_thresholds_text):
                updates["stage_threshold_overrides"] = {}
            if "suppressed_alert_ids" in body:
                updates["suppressed_alert_ids"] = _coerce_csv_list(body.get("suppressed_alert_ids"))
            if "suppressed_stage_alerts" in body:
                updates["suppressed_stage_alerts"] = _coerce_alert_mapping(body.get("suppressed_stage_alerts"))
            if "suppressed_watch_alerts" in body:
                updates["suppressed_watch_alerts"] = _coerce_alert_mapping(body.get("suppressed_watch_alerts"))
            if "alert_severity_overrides" in body:
                updates["alert_severity_overrides"] = _coerce_severity_mapping(body.get("alert_severity_overrides"))
            if "stage_threshold_overrides" in body:
                updates["stage_threshold_overrides"] = _coerce_stage_threshold_mapping(body.get("stage_threshold_overrides"))
            return updates

        def _read_post_body(self) -> dict[str, object]:
            length_text = str(self.headers.get("Content-Length") or "0").strip()
            try:
                length = max(0, int(length_text))
            except ValueError:
                length = 0
            raw_body = self.rfile.read(length) if length > 0 else b""
            content_type = str(self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            if not raw_body:
                return {}
            if content_type == "application/json":
                payload = json.loads(raw_body.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("JSON body must be an object")
                return payload
            form = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True)
            return {key: values[0] if len(values) == 1 else values for key, values in form.items()}

        def _write_json(self, status: int, payload: dict[str, object]) -> None:
            body = json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _write_html(self, status: int, payload: str) -> None:
            body = payload.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _write_redirect(self, status: int, location: str) -> None:
            body = json.dumps({"redirect_to": location}, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Location", location)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def _build_monitor_view(*, case_id: str) -> dict[str, object]:
        runtime = MonitorRuntime(
            app=app,
            output_root=monitor_output_root,
            database_path=str(store.database_path),
            case_id=case_id,
        )
        status = runtime.read_status()
        history = runtime.read_history(limit=48)
        return _build_monitor_payload(store, status=status, case_id=case_id, output_root=monitor_output_root, history=history)

    return ThreadingHTTPServer((host, int(port)), IntelligenceApiHandler)


def run_api_server(
    database_path: str | Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> None:
    server = create_api_server(database_path, host=host, port=port)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def _derive_monitor_output_root(database_path: str | Path) -> Path:
    path = Path(database_path).resolve()
    if path.parent.name == "storage":
        return path.parent.parent.resolve()
    return path.parent.resolve()


def _build_monitor_payload(
    store: SQLiteIntelligenceStore,
    *,
    status: dict[str, object],
    case_id: str = "",
    output_root: str | Path,
    history: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    source_checks = dict(status.get("source_checks") or {})
    cleanup = dict(status.get("cleanup") or {})
    cleanup_metrics = dict(cleanup.get("metrics") or {})
    cleanup_policy = dict(status.get("cleanup_policy") or {})
    recent_archives = list_queue_archives(output_root, case_id=case_id, limit=12)
    cleanup_reports = list_cleanup_reports(output_root, limit=6)
    monitor_history = list(history or [])
    trend_view = _monitor_trend_view(monitor_history)
    forecast_view = dict(status.get("forecast") or build_monitor_forecast(monitor_history))
    tuning_view = dict(status.get("tuning") or dict(forecast_view.get("tuning") or {}))
    automation_view = dict(status.get("automation") or {})
    automation_summary = dict(automation_view.get("summary") or {})
    watched_sources = list(store.fetch_watched_sources(case_id=case_id, limit=500))
    watcher_rows = list(store.fetch_watcher_states(case_id=case_id, watcher_type="source_monitor", limit=500))

    watched_by_id = {
        str(row.get("watch_id") or ""): dict(row)
        for row in watched_sources
        if str(row.get("watch_id") or "").strip()
    }
    watched_by_key = {
        _monitor_source_key(
            case_id=str(row.get("case_id") or ""),
            source_type=str(row.get("source_type") or ""),
            locator=str(row.get("locator") or ""),
        ): dict(row)
        for row in watched_sources
    }
    watcher_by_key = {
        _monitor_source_key(
            case_id=str(row.get("case_id") or ""),
            source_type=str(row.get("source_type") or ""),
            locator=str(row.get("locator") or ""),
        ): dict(row)
        for row in watcher_rows
    }

    source_rows: list[dict[str, object]] = []
    for result in list(source_checks.get("results") or []):
        if not isinstance(result, dict):
            continue
        watched = watched_by_id.get(str(result.get("watch_id") or ""), {})
        resolved_case_id = str(watched.get("case_id") or case_id or "")
        watcher = watcher_by_key.get(
            _monitor_source_key(
                case_id=resolved_case_id,
                source_type=str(result.get("source_type") or ""),
                locator=str(result.get("locator") or ""),
            ),
            {},
        )
        source_rows.append(_monitor_result_row(result=result, watched=watched, watcher=watcher, fallback_case_id=case_id))

    seen_source_keys = {
        _monitor_source_key(
            case_id=str(row.get("case_id") or ""),
            source_type=str(row.get("source_type") or ""),
            locator=str(row.get("locator") or ""),
        )
        for row in source_rows
    }

    suppressed_sources = [
        dict(row)
        for row in source_rows
        if bool(row.get("suppressed")) or str(row.get("reason") or "") == "suppressed"
    ]
    snoozed_sources = [
        dict(row)
        for row in source_rows
        if bool(row.get("snoozed")) or str(row.get("reason") or "") == "snoozed"
    ]
    for watcher in watcher_rows:
        if not _timestamp_is_future(str(watcher.get("suppression_until") or "")):
            continue
        key = _monitor_source_key(
            case_id=str(watcher.get("case_id") or ""),
            source_type=str(watcher.get("source_type") or ""),
            locator=str(watcher.get("locator") or ""),
        )
        if key in seen_source_keys:
            continue
        suppressed_sources.append(_watcher_monitor_row(watcher, watched=watched_by_key.get(key, {})))
    for watched in watched_sources:
        snooze_until = str(watched.get("snooze_until") or "")
        if not _timestamp_is_future(snooze_until):
            continue
        key = _monitor_source_key(
            case_id=str(watched.get("case_id") or ""),
            source_type=str(watched.get("source_type") or ""),
            locator=str(watched.get("locator") or ""),
        )
        if key in seen_source_keys:
            continue
        snoozed_sources.append(_watched_source_monitor_row(watched))

    hot_sources = [
        dict(row)
        for row in source_rows
        if bool(row.get("changed"))
        or str(row.get("priority_label") or "") in {"urgent", "high"}
        or str(row.get("poll_adaptation") or "") in {"burst", "hot"}
        or str(row.get("next_poll_adaptation") or "") in {"burst", "hot"}
    ]
    burst_sources = [
        dict(row)
        for row in source_rows
        if bool(row.get("burst_mode"))
        or str(row.get("poll_adaptation") or "") == "burst"
        or str(row.get("next_poll_adaptation") or "") == "burst"
    ]
    backlogged_sources = [
        _watcher_monitor_row(
            watcher,
            watched=watched_by_key.get(
                _monitor_source_key(
                    case_id=str(watcher.get("case_id") or ""),
                    source_type=str(watcher.get("source_type") or ""),
                    locator=str(watcher.get("locator") or ""),
                ),
                {},
            ),
        )
        for watcher in watcher_rows
        if str(watcher.get("backlog_pointer") or "").strip()
    ]
    backlog_stages = _backlog_stage_rows(status)

    hot_sources.sort(key=_monitor_source_sort_key)
    burst_sources.sort(key=_monitor_source_sort_key)
    suppressed_sources.sort(key=_monitor_source_sort_key)
    snoozed_sources.sort(key=_monitor_source_sort_key)
    backlogged_sources.sort(key=_monitor_source_sort_key)

    overview = {
        "case_id": case_id,
        "cycle_count": int(status.get("cycle_count") or 0),
        "last_heartbeat_at": str(status.get("last_heartbeat_at") or ""),
        "stage_budget_mode": str(status.get("stage_budget_mode") or ""),
        "hot_cycle_streak": int(status.get("hot_cycle_streak") or 0),
        "drain_cycle_streak": int(status.get("drain_cycle_streak") or 0),
        "queue_total_before": int(status.get("queue_total_before") or 0),
        "queue_total_after": int(status.get("queue_total_after") or 0),
        "registered_count": int(source_checks.get("registered_count") or 0),
        "executed_check_count": int(source_checks.get("executed_check_count") or 0),
        "changed_count": int(source_checks.get("changed_count") or 0),
        "suppressed_count": int(source_checks.get("suppressed_count") or 0),
        "cooldown_skip_count": int(source_checks.get("cooldown_skip_count") or 0),
        "snoozed_count": int(source_checks.get("snoozed_count") or 0) or len(snoozed_sources),
        "watched_source_count": int((status.get("watched_source_summary") or {}).get("watched_source_count") or 0),
        "backlogged_source_count": len(backlogged_sources),
        "hot_source_count": len(hot_sources),
        "burst_source_count": len(burst_sources),
        "snoozed_source_count": len(snoozed_sources),
        "cleanup_configured": bool(cleanup_policy.get("enabled")),
        "cleanup_executed": bool(cleanup.get("executed")),
        "cleanup_reason": str(cleanup.get("reason") or ""),
        "cleanup_removed_count": int(cleanup.get("removed_count") or cleanup_metrics.get("removed_count") or 0),
        "cleanup_removed_bytes": int(cleanup.get("removed_bytes") or cleanup_metrics.get("removed_bytes") or 0),
        "cleanup_candidate_count": int(cleanup_metrics.get("candidate_count") or 0),
        "cleanup_candidate_bytes": int(cleanup_metrics.get("candidate_bytes") or 0),
        "recent_archive_count": len(recent_archives),
        "recent_completed_archive_count": sum(1 for item in recent_archives if str(item.get("archive_state") or "") == "completed"),
        "recent_failed_archive_count": sum(1 for item in recent_archives if str(item.get("archive_state") or "") == "failed"),
        "cleanup_report_count": len(cleanup_reports),
        "history_cycle_count": len(monitor_history),
        "history_max_queue_total_before": int(trend_view["summary"].get("max_queue_total_before") or 0),
        "history_avg_processed_job_count": float(trend_view["summary"].get("avg_processed_job_count") or 0.0),
        "forecast_alert_count": int(dict(forecast_view.get("summary") or {}).get("alert_count") or 0),
        "forecast_highest_alert_severity": str(dict(forecast_view.get("summary") or {}).get("highest_alert_severity") or "none"),
        "forecast_predicted_next_queue_total_before": int(
            dict(forecast_view.get("summary") or {}).get("predicted_next_queue_total_before") or 0
        ),
        "forecast_predicted_backlog_drain_cycles": int(
            dict(forecast_view.get("summary") or {}).get("predicted_backlog_drain_cycles") or 0
        ),
        "automation_mode": str(automation_view.get("mode") or ""),
        "automation_recommendation_count": int(automation_summary.get("recommendation_count") or 0),
        "automation_applied_count": int(automation_summary.get("applied_count") or 0),
        "tuning_suppressed_alert_count": len(list(tuning_view.get("suppressed_alert_ids") or [])),
        "tuning_suppressed_stage_count": len(dict(tuning_view.get("suppressed_stage_alerts") or {})),
        "tuning_suppressed_watch_count": len(dict(tuning_view.get("suppressed_watch_alerts") or {})),
        "tuning_alert_severity_override_count": len(dict(tuning_view.get("alert_severity_overrides") or {})),
        "tuning_stage_threshold_override_count": len(dict(tuning_view.get("stage_threshold_overrides") or {})),
    }

    return {
        "overview": overview,
        "status": status,
        "backlog_stages": backlog_stages,
        "hot_sources": hot_sources[:12],
        "burst_sources": burst_sources[:12],
        "snoozed_sources": snoozed_sources[:12],
        "suppressed_sources": suppressed_sources[:12],
        "backlogged_sources": backlogged_sources[:12],
        "cleanup": _cleanup_view(policy=cleanup_policy, summary=cleanup),
        "recent_archives": recent_archives,
        "cleanup_reports": cleanup_reports,
        "history": monitor_history,
        "trends": trend_view,
        "forecast": forecast_view,
        "tuning": tuning_view,
        "automation": automation_view,
    }


def _coerce_csv_list(value: object) -> list[str]:
    if isinstance(value, list):
        pieces = [str(item).strip() for item in value]
    elif isinstance(value, str):
        pieces = [part.strip() for part in value.replace(";", ",").split(",")]
    elif value in {None, ""}:
        pieces = []
    else:
        pieces = [str(value).strip()]
    rows: list[str] = []
    for piece in pieces:
        if not piece or piece in rows:
            continue
        rows.append(piece)
    return rows


def _coerce_alert_mapping(value: object) -> dict[str, list[str]]:
    if isinstance(value, dict):
        rows = {
            str(key).strip(): _coerce_csv_list(item)
            for key, item in value.items()
            if str(key).strip()
        }
        return {key: item for key, item in rows.items() if item}
    rows: dict[str, list[str]] = {}
    if value in {None, ""}:
        return rows
    text = str(value)
    entries = [item.strip() for item in text.replace(";", ",").split(",") if item.strip()]
    for entry in entries:
        key, separator, raw_alert = entry.partition(":")
        normalized_key = key.strip()
        normalized_alert = raw_alert.strip() if separator else ""
        if not normalized_key or not normalized_alert:
            continue
        rows.setdefault(normalized_key, [])
        if normalized_alert not in rows[normalized_key]:
            rows[normalized_key].append(normalized_alert)
    return rows


def _coerce_severity_mapping(value: object) -> dict[str, str]:
    if isinstance(value, dict):
        rows = {
            str(key).strip(): str(item).strip().lower()
            for key, item in value.items()
            if str(key).strip()
        }
    elif value in {None, ""}:
        rows = {}
    else:
        rows = {}
        entries = [item.strip() for item in str(value).replace(";", ",").split(",") if item.strip()]
        for entry in entries:
            key, separator, severity = entry.partition(":")
            normalized_key = key.strip()
            normalized_severity = severity.strip().lower() if separator else ""
            if not normalized_key or not normalized_severity:
                continue
            rows[normalized_key] = normalized_severity
    return {
        key: item
        for key, item in rows.items()
        if item in {"info", "warning", "critical"}
    }


def _coerce_stage_threshold_mapping(value: object) -> dict[str, dict[str, float]]:
    if isinstance(value, dict):
        rows: dict[str, dict[str, float]] = {}
        for key, item in value.items():
            normalized_key = str(key).strip()
            if not normalized_key or not isinstance(item, dict):
                continue
            normalized_item: dict[str, float] = {}
            for threshold_key, threshold_value in item.items():
                normalized_threshold_key = str(threshold_key).strip()
                if normalized_threshold_key not in {"queue_spike_factor", "throughput_drop_factor"}:
                    continue
                try:
                    normalized_item[normalized_threshold_key] = float(threshold_value)
                except (TypeError, ValueError):
                    continue
            if normalized_item:
                rows[normalized_key] = normalized_item
        return rows
    rows = {}
    if value in {None, ""}:
        return rows
    entries = [item.strip() for item in str(value).replace(";", ",").split(",") if item.strip()]
    for entry in entries:
        stage, separator, remainder = entry.partition(":")
        threshold_key, equals, threshold_value = remainder.partition("=")
        normalized_stage = stage.strip()
        normalized_threshold_key = threshold_key.strip()
        if (
            not separator
            or not equals
            or not normalized_stage
            or normalized_threshold_key not in {"queue_spike_factor", "throughput_drop_factor"}
        ):
            continue
        try:
            numeric_value = float(threshold_value.strip())
        except ValueError:
            continue
        rows.setdefault(normalized_stage, {})
        rows[normalized_stage][normalized_threshold_key] = numeric_value
    return rows


def _backlog_stage_rows(status: dict[str, object]) -> list[dict[str, object]]:
    counts_before = dict(status.get("queue_counts_before") or {})
    counts_after = dict(status.get("queue_counts_after") or {})
    age_stats = dict(status.get("queue_stage_age_stats_before") or {})
    priority_stats = dict(status.get("queue_stage_priority_counts_before") or {})
    rows: list[dict[str, object]] = []
    for stage in ("extract", "recover", "normalize", "correlate", "store", "present"):
        pending_before = int(counts_before.get(stage) or 0)
        pending_after = int(counts_after.get(stage) or 0)
        age_row = dict(age_stats.get(stage) or {})
        if pending_before <= 0 and pending_after <= 0 and not age_row:
            continue
        rows.append(
            {
                "stage": stage,
                "pending_before": pending_before,
                "pending_after": pending_after,
                "oldest_age_seconds": int(age_row.get("oldest_age_seconds") or 0),
                "aged_job_count_soft": int(age_row.get("aged_job_count_soft") or 0),
                "aged_job_count_hard": int(age_row.get("aged_job_count_hard") or 0),
                "priority_counts": dict(priority_stats.get(stage) or {}),
            }
        )
    rows.sort(key=lambda item: (-int(item.get("pending_before") or 0), -int(item.get("oldest_age_seconds") or 0), str(item.get("stage") or "")))
    return rows


def _cleanup_view(*, policy: dict[str, object], summary: dict[str, object]) -> dict[str, object]:
    cleanup_metrics = dict(summary.get("metrics") or {})
    artifact_paths = [str(item).strip() for item in list(summary.get("artifact_paths") or []) if str(item).strip()]
    report_path = str(summary.get("report_path") or "").strip()
    if not report_path:
        report_path = next((path for path in artifact_paths if path.endswith("cleanup_report.json")), "")
    return {
        "policy": {
            "enabled": bool(policy.get("enabled")),
            "cleanup_completed_days": float(policy.get("cleanup_completed_days") or 0.0),
            "cleanup_failed_days": float(policy.get("cleanup_failed_days") or 0.0),
            "cleanup_watch_delta_days": float(policy.get("cleanup_watch_delta_days") or 0.0),
            "workspace_scoped_only": bool(policy.get("workspace_scoped_only", True)),
        },
        "summary": {
            "configured": bool(summary.get("configured")),
            "executed": bool(summary.get("executed")),
            "skipped": bool(summary.get("skipped")),
            "reason": str(summary.get("reason") or ""),
            "removed_count": int(summary.get("removed_count") or cleanup_metrics.get("removed_count") or 0),
            "removed_bytes": int(summary.get("removed_bytes") or cleanup_metrics.get("removed_bytes") or 0),
            "candidate_count": int(cleanup_metrics.get("candidate_count") or 0),
            "candidate_bytes": int(cleanup_metrics.get("candidate_bytes") or 0),
            "warning_count": int(cleanup_metrics.get("warning_count") or 0),
            "error_count": int(cleanup_metrics.get("error_count") or 0),
            "report_path": report_path,
            "artifact_paths": artifact_paths,
            "categories": dict(summary.get("categories") or {}),
            "warnings": [str(item).strip() for item in list(summary.get("warnings") or []) if str(item).strip()],
            "errors": [str(item).strip() for item in list(summary.get("errors") or []) if str(item).strip()],
        },
    }


def _monitor_trend_view(history: list[dict[str, object]]) -> dict[str, object]:
    rows = [dict(item) for item in history if isinstance(item, dict)]
    rows.sort(
        key=lambda item: (
            str(item.get("last_heartbeat_at") or item.get("recorded_at") or ""),
            int(item.get("cycle_count") or 0),
        )
    )
    queue_pressure: list[dict[str, object]] = []
    throughput: list[dict[str, object]] = []
    max_queue_total_before = 0
    max_processed_job_count = 0
    total_processed_job_count = 0
    total_queue_total_before = 0
    for item in rows[-24:]:
        cycle_count = int(item.get("cycle_count") or 0)
        queue_total_before = int(item.get("queue_total_before") or 0)
        queue_total_after = int(item.get("queue_total_after") or 0)
        processed_job_count = int(item.get("processed_job_count") or 0)
        max_queue_total_before = max(max_queue_total_before, queue_total_before)
        max_processed_job_count = max(max_processed_job_count, processed_job_count)
        total_processed_job_count += processed_job_count
        total_queue_total_before += queue_total_before
        label = f"C{cycle_count}"
        queue_pressure.append(
            {
                "label": label,
                "cycle_count": cycle_count,
                "last_heartbeat_at": str(item.get("last_heartbeat_at") or item.get("recorded_at") or ""),
                "queue_total_before": queue_total_before,
                "queue_total_after": queue_total_after,
                "changed_count": int(item.get("changed_count") or 0),
                "hot_source_count": int(item.get("hot_source_count") or 0),
            }
        )
        throughput.append(
            {
                "label": label,
                "cycle_count": cycle_count,
                "last_heartbeat_at": str(item.get("last_heartbeat_at") or item.get("recorded_at") or ""),
                "processed_job_count": processed_job_count,
                "completed_job_count": int(item.get("completed_job_count") or 0),
                "failed_job_count": int(item.get("failed_job_count") or 0),
                "executed_check_count": int(item.get("executed_check_count") or 0),
                "cleanup_removed_count": int(item.get("cleanup_removed_count") or 0),
            }
        )
    count = len(rows[-24:])
    return {
        "summary": {
            "history_count": count,
            "max_queue_total_before": max_queue_total_before,
            "max_processed_job_count": max_processed_job_count,
            "avg_queue_total_before": (float(total_queue_total_before) / count) if count else 0.0,
            "avg_processed_job_count": (float(total_processed_job_count) / count) if count else 0.0,
        },
        "queue_pressure": queue_pressure,
        "throughput": throughput,
    }


def _monitor_result_row(
    *,
    result: dict[str, object],
    watched: dict[str, object],
    watcher: dict[str, object],
    fallback_case_id: str,
) -> dict[str, object]:
    locator = str(result.get("locator") or watcher.get("locator") or watched.get("locator") or "")
    source_type = str(result.get("source_type") or watcher.get("source_type") or watched.get("source_type") or "")
    case_id = str(watched.get("case_id") or watcher.get("case_id") or fallback_case_id or "")
    priority_label = str(result.get("priority_label") or watcher.get("triage_priority") or "low")
    priority_score = int(result.get("priority_score") or watcher.get("triage_score") or 0)
    snooze_until = str(result.get("snooze_until") or watched.get("snooze_until") or "")
    snoozed = bool(result.get("snoozed")) or _timestamp_is_future(snooze_until)
    suppression_until = str(result.get("suppressed_until") or watcher.get("suppression_until") or "")
    poll_adaptation = str(result.get("poll_adaptation") or "")
    next_poll_adaptation = str(result.get("next_poll_adaptation") or "")
    reason = str(result.get("reason") or "")
    if snoozed:
        poll_adaptation = "snoozed"
        next_poll_adaptation = "snoozed"
        reason = "snoozed"
    return {
        "watch_id": str(result.get("watch_id") or watched.get("watch_id") or ""),
        "watcher_id": str(watcher.get("watcher_id") or ""),
        "case_id": case_id,
        "display_name": str(watched.get("display_name") or Path(locator).name or locator or "(source)"),
        "locator": locator,
        "source_type": source_type,
        "enabled": bool(watched.get("enabled", True)),
        "poll_interval_seconds": float(watched.get("poll_interval_seconds") or 0.0),
        "notes": str(watched.get("notes") or ""),
        "tags": list(watched.get("tags") or []),
        "tuning_profile": dict(watched.get("tuning_profile") or {}),
        "priority_label": priority_label,
        "priority_score": priority_score,
        "reason": reason,
        "changed": bool(result.get("changed")),
        "ingested": bool(result.get("ingested")),
        "change_kind": str(result.get("change_kind") or watcher.get("change_kind") or ""),
        "poll_adaptation": poll_adaptation,
        "next_poll_adaptation": next_poll_adaptation,
        "effective_poll_interval_seconds": float(result.get("effective_poll_interval_seconds") or 0.0),
        "cooldown_remaining_seconds": float(result.get("cooldown_remaining_seconds") or 0.0),
        "snooze_until": snooze_until,
        "snooze_remaining_seconds": float(result.get("snooze_remaining_seconds") or _future_timestamp_seconds(snooze_until)),
        "suppressed": bool(result.get("suppressed")),
        "suppressed_until": suppression_until,
        "suppression_remaining_seconds": float(result.get("suppression_remaining_seconds") or _future_timestamp_seconds(suppression_until)),
        "snoozed": snoozed,
        "burst_mode": bool(result.get("burst_mode")),
        "burst_change_streak": int(result.get("burst_change_streak") or watcher.get("burst_change_streak") or 0),
        "backlog_pointer": str(watcher.get("backlog_pointer") or ""),
        "status": str(watcher.get("status") or ""),
    }


def _watcher_monitor_row(watcher: dict[str, object], *, watched: dict[str, object]) -> dict[str, object]:
    locator = str(watcher.get("locator") or "")
    suppression_until = str(watcher.get("suppression_until") or "")
    priority_label = str(watcher.get("triage_priority") or "low")
    return {
        "watch_id": str(watched.get("watch_id") or ""),
        "watcher_id": str(watcher.get("watcher_id") or ""),
        "case_id": str(watcher.get("case_id") or ""),
        "display_name": str(watched.get("display_name") or Path(locator).name or locator or "(source)"),
        "locator": locator,
        "source_type": str(watcher.get("source_type") or ""),
        "enabled": bool(watched.get("enabled", True)),
        "poll_interval_seconds": float(watched.get("poll_interval_seconds") or 0.0),
        "notes": str(watched.get("notes") or ""),
        "tags": list(watched.get("tags") or []),
        "tuning_profile": dict(watched.get("tuning_profile") or {}),
        "priority_label": priority_label,
        "priority_score": int(watcher.get("triage_score") or 0),
        "reason": "backlog" if str(watcher.get("backlog_pointer") or "") else "suppressed",
        "changed": str(watcher.get("status") or "") == "changed",
        "ingested": False,
        "change_kind": str(watcher.get("change_kind") or ""),
        "poll_adaptation": "suppressed" if _timestamp_is_future(suppression_until) else "base",
        "next_poll_adaptation": "",
        "effective_poll_interval_seconds": float(watcher.get("registered_poll_interval_seconds") or 0.0),
        "cooldown_remaining_seconds": 0.0,
        "snooze_until": str(watched.get("snooze_until") or ""),
        "snooze_remaining_seconds": float(_future_timestamp_seconds(str(watched.get("snooze_until") or ""))),
        "suppressed": _timestamp_is_future(suppression_until),
        "suppressed_until": suppression_until,
        "suppression_remaining_seconds": float(_future_timestamp_seconds(suppression_until)),
        "snoozed": _timestamp_is_future(str(watched.get("snooze_until") or "")),
        "burst_mode": int(watcher.get("burst_change_streak") or 0) >= 2,
        "burst_change_streak": int(watcher.get("burst_change_streak") or 0),
        "backlog_pointer": str(watcher.get("backlog_pointer") or ""),
        "status": str(watcher.get("status") or ""),
    }


def _watched_source_monitor_row(watched: dict[str, object]) -> dict[str, object]:
    locator = str(watched.get("locator") or "")
    snooze_until = str(watched.get("snooze_until") or "")
    return {
        "watch_id": str(watched.get("watch_id") or ""),
        "watcher_id": "",
        "case_id": str(watched.get("case_id") or ""),
        "display_name": str(watched.get("display_name") or Path(locator).name or locator or "(source)"),
        "locator": locator,
        "source_type": str(watched.get("source_type") or ""),
        "enabled": bool(watched.get("enabled", True)),
        "poll_interval_seconds": float(watched.get("poll_interval_seconds") or 0.0),
        "notes": str(watched.get("notes") or ""),
        "tags": list(watched.get("tags") or []),
        "tuning_profile": dict(watched.get("tuning_profile") or {}),
        "priority_label": "low",
        "priority_score": 0,
        "reason": "snoozed",
        "changed": False,
        "ingested": False,
        "change_kind": "",
        "poll_adaptation": "snoozed",
        "next_poll_adaptation": "",
        "effective_poll_interval_seconds": max(float(watched.get("poll_interval_seconds") or 0.0), _future_timestamp_seconds(snooze_until)),
        "cooldown_remaining_seconds": float(_future_timestamp_seconds(snooze_until)),
        "snooze_until": snooze_until,
        "snooze_remaining_seconds": float(_future_timestamp_seconds(snooze_until)),
        "suppressed": False,
        "suppressed_until": "",
        "suppression_remaining_seconds": 0.0,
        "snoozed": True,
        "burst_mode": False,
        "burst_change_streak": 0,
        "backlog_pointer": "",
        "status": str(watched.get("status") or ""),
    }


def _monitor_source_key(*, case_id: str, source_type: str, locator: str) -> tuple[str, str, str]:
    return (str(case_id or "").strip(), str(source_type or "").strip(), str(locator or "").strip())


def _monitor_source_sort_key(row: dict[str, object]) -> tuple[int, int, int, str]:
    return (
        -int(row.get("priority_score") or 0),
        -int(bool(row.get("changed"))),
        -int(bool(row.get("backlog_pointer"))),
        str(row.get("display_name") or row.get("locator") or ""),
    )


def _future_timestamp_seconds(value: str) -> float:
    parsed = _parse_utc_timestamp(value)
    if parsed is None:
        return 0.0
    return max(0.0, (parsed - _utc_now()).total_seconds())


def _timestamp_is_future(value: str) -> bool:
    return _future_timestamp_seconds(value) > 0.0


def _parse_utc_timestamp(value: str):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        from datetime import datetime, timezone

        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _utc_now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


def _coerce_bool(value: object) -> bool:
    normalized = str(value or "").strip().lower()
    if normalized in {"1", "true", "yes", "on", "enable", "enabled"}:
        return True
    if normalized in {"0", "false", "no", "off", "disable", "disabled"}:
        return False
    raise ValueError("enabled must be true/false")
