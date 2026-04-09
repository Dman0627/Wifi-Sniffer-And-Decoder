from __future__ import annotations

import json
import html
from pathlib import Path
from urllib.parse import quote

from intel_storage import SQLiteIntelligenceStore


def render_case_index_html(
    store: SQLiteIntelligenceStore,
    *,
    plugin_statuses: tuple[dict[str, object], ...] | list[dict[str, object]] = (),
    plugin_settings: dict[str, object] | None = None,
    monitor_view: dict[str, object] | None = None,
) -> str:
    cases = store.list_cases()
    summary = store.summary()
    plugin_rows = list(plugin_statuses or [])
    plugin_summary = _plugin_summary(plugin_rows)
    plugin_settings_view = dict(plugin_settings or {})
    monitor_summary = dict((monitor_view or {}).get("overview") or {})
    cleanup_view = dict((monitor_view or {}).get("cleanup") or {})
    trend_view = dict((monitor_view or {}).get("trends") or {})
    forecast_view = dict((monitor_view or {}).get("forecast") or {})
    tuning_view = dict((monitor_view or {}).get("tuning") or {})
    automation_view = dict((monitor_view or {}).get("automation") or {})
    monitor_history = list((monitor_view or {}).get("history") or [])
    recent_archives = list((monitor_view or {}).get("recent_archives") or [])
    cleanup_reports = list((monitor_view or {}).get("cleanup_reports") or [])

    case_rows = "".join(
        (
            "<tr>"
            f"<td><a href='/cases/{_url(case['case_id'])}/dashboard'>{_text(case['case_id'])}</a></td>"
            f"<td>{_text(case['source_count'])}</td>"
            f"<td>{_text(case['record_count'])}</td>"
            f"<td>{_text(case['timeline_count'])}</td>"
            f"<td>{_text(case['job_count'])}</td>"
            f"<td><a href='/cases/{_url(case['case_id'])}/summary'>JSON</a></td>"
            "</tr>"
        )
        for case in cases
    ) or "<tr><td colspan='6'>No cases have been stored yet.</td></tr>"

    body = f"""
    <section class="hero">
      <div>
        <p class="eyebrow">Intelligence Platform</p>
        <h1>Case Browser</h1>
      </div>
      <p class="lede">Browse stored cases, jump into analyst dashboards, or use the JSON API directly. This UI is local and read-only.</p>
      <div class="stat-grid">
        <article class="stat-card"><span class="stat-label">Cases</span><strong>{_text(len(cases))}</strong></article>
        <article class="stat-card"><span class="stat-label">Sources</span><strong>{_text(summary.get('source_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Records</span><strong>{_text(summary.get('record_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Graph Edges</span><strong>{_text(summary.get('relationship_edge_count', 0))}</strong></article>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Monitor</p>
          <h2>Passive Runtime Overview</h2>
        </div>
      <div class="link-row">
          <a href="/monitor-view">Monitor Page</a>
          <a href="/monitor">Monitor JSON</a>
          <a href="/monitor-forecast">Forecast JSON</a>
          <a href="/monitor-history">History JSON</a>
          <a href="/archives">Archives JSON</a>
          <a href="/cleanup-reports">Cleanup Reports JSON</a>
      </div>
      </div>
      <div class="stat-grid">
        <article class="stat-card"><span class="stat-label">Cycles</span><strong>{_text(monitor_summary.get('cycle_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Watched</span><strong>{_text(monitor_summary.get('watched_source_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Hot Sources</span><strong>{_text(monitor_summary.get('hot_source_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Suppressed</span><strong>{_text(monitor_summary.get('suppressed_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Snoozed</span><strong>{_text(monitor_summary.get('snoozed_source_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Cleanup Removed</span><strong>{_text(monitor_summary.get('cleanup_removed_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Recent Archives</span><strong>{_text(monitor_summary.get('recent_archive_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Trend Cycles</span><strong>{_text(monitor_summary.get('history_cycle_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Forecast Alerts</span><strong>{_text(monitor_summary.get('forecast_alert_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Automation Recs</span><strong>{_text(monitor_summary.get('automation_recommendation_count', 0))}</strong></article>
      </div>
      <div>
        <p class="eyebrow">Retention</p>
        <h3>Workspace Cleanup</h3>
      </div>
      {_cleanup_summary_block(cleanup_view, empty='No cleanup policy is configured yet.')}
      {_monitor_source_table(
        rows=list((monitor_view or {}).get('hot_sources') or [])[:6],
        empty='No hot sources in the latest cycle.',
        return_to='/',
      )}
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Forecast</p>
          <h2>Backlog Outlook</h2>
        </div>
        <div class="link-row">
          <a href="/monitor-forecast">Forecast JSON</a>
          <a href="/monitor-tuning">Tuning JSON</a>
        </div>
      </div>
      {_forecast_summary_block(forecast_view, empty='No forecast is available yet.')}
      {_forecast_alert_table(rows=list(forecast_view.get('alerts') or []), empty='No forecast alerts are active.')}
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Tuning</p>
          <h2>Forecast Tuning</h2>
        </div>
        <div class="link-row">
          <a href="/monitor-tuning">Tuning JSON</a>
        </div>
      </div>
      {_tuning_summary_block(tuning_view, empty='No monitor tuning is configured yet.')}
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Automation</p>
          <h2>Preset Recommendations</h2>
        </div>
      </div>
      {_automation_summary_block(automation_view, empty='No automation state is available yet.')}
      {_automation_recommendation_table(rows=list(automation_view.get('recommendations') or [])[:5], empty='No preset recommendations are active right now.')}
    </section>

    <section class="grid two-up">
      <article class="panel">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Trends</p>
            <h2>Queue Pressure Trend</h2>
          </div>
          <div class="link-row">
            <a href="/monitor-history">History JSON</a>
          </div>
        </div>
        {_trend_chart(
          rows=list(trend_view.get('queue_pressure') or []),
          primary_key='queue_total_before',
          secondary_key='queue_total_after',
          primary_label='Before',
          secondary_label='After',
          empty='No monitor history has been recorded yet.',
        )}
      </article>
      <article class="panel">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Trends</p>
            <h2>Throughput Trend</h2>
          </div>
        </div>
        {_trend_chart(
          rows=list(trend_view.get('throughput') or []),
          primary_key='processed_job_count',
          secondary_key='completed_job_count',
          primary_label='Processed',
          secondary_label='Completed',
          empty='No throughput history is available yet.',
          detail_keys=('failed_job_count', 'executed_check_count'),
        )}
      </article>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">History</p>
          <h2>Recent Monitor Cycles</h2>
        </div>
        <div class="link-row">
          <a href="/monitor-history">History JSON</a>
        </div>
      </div>
      {_monitor_history_table(rows=monitor_history[:8], empty='No monitor cycles have been recorded yet.')}
    </section>

    <section class="grid two-up">
      <article class="panel">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Archives</p>
            <h2>Recent Queue Archives</h2>
          </div>
          <div class="link-row">
            <a href="/archives">Archives JSON</a>
          </div>
        </div>
        {_archive_table(rows=recent_archives[:8], empty='No archived queue work is available yet.')}
      </article>
      <article class="panel">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Cleanup</p>
            <h2>Cleanup Reports</h2>
          </div>
          <div class="link-row">
            <a href="/cleanup-reports">Cleanup Reports JSON</a>
          </div>
        </div>
        {_cleanup_report_table(rows=cleanup_reports[:6], empty='No cleanup reports have been recorded yet.')}
      </article>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Runtime</p>
          <h2>Plugin Health</h2>
        </div>
        <div class="link-row">
          <a href="/plugins">Plugins JSON</a>
          <a href="/health">Health</a>
        </div>
      </div>
      <div class="stat-grid">
        <article class="stat-card"><span class="stat-label">Plugins</span><strong>{_text(plugin_summary.get('plugin_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Ready</span><strong>{_text(plugin_summary.get('ready_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Missing Tools</span><strong>{_text(plugin_summary.get('optional_tool_missing_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Attention</span><strong>{_text(plugin_summary.get('attention_count', 0))}</strong></article>
      </div>
      {_plugin_settings_block(plugin_settings_view, action_url='/plugins', return_to='/')}
      {_plugin_table(plugin_rows, action_url='/plugins', return_to='/', active_profile=str(plugin_settings_view.get('active_profile') or ''))}
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Stored Cases</p>
          <h2>Analyst Entry Points</h2>
        </div>
        <div class="link-row">
          <a href="/cases">Cases JSON</a>
          <a href="/health">Health</a>
        </div>
      </div>
      <table>
        <thead>
          <tr><th>Case</th><th>Sources</th><th>Records</th><th>Timelines</th><th>Jobs</th><th>API</th></tr>
        </thead>
        <tbody>{case_rows}</tbody>
      </table>
    </section>
    """
    return _page("Intelligence Platform", "Platform Case Browser", body)


def render_case_dashboard_html(
    store: SQLiteIntelligenceStore,
    *,
    case_id: str,
    search_query: str = "",
    record_type: str = "",
    node_id: str = "",
    depth: int = 1,
    timeline_id: str = "",
    plugin_statuses: tuple[dict[str, object], ...] | list[dict[str, object]] = (),
    plugin_settings: dict[str, object] | None = None,
    monitor_view: dict[str, object] | None = None,
) -> str:
    summary = store.case_summary(case_id=case_id)
    search_query = str(search_query or "").strip()
    record_type = str(record_type or "").strip()
    node_id = str(node_id or "").strip()
    timeline_id = str(timeline_id or "").strip()

    search_results = (
        store.search_records(case_id=case_id, query=search_query, record_type=record_type, limit=25)
        if search_query
        else []
    )
    relationships = store.fetch_relationships(case_id=case_id, limit=20)
    jobs = store.fetch_jobs(case_id=case_id, limit=12)
    audit_events = store.fetch_audit_events(case_id=case_id, limit=12)
    timelines = store.fetch_timelines(case_id=case_id, limit=12)
    timeline_detail = store.timeline_detail(case_id=case_id, timeline_id=timeline_id) if timeline_id else None
    plugin_rows = list(plugin_statuses or [])
    plugin_summary = _plugin_summary(plugin_rows)
    plugin_settings_view = dict(plugin_settings or {})
    monitor_payload = dict(monitor_view or {})
    monitor_summary = dict(monitor_payload.get("overview") or {})
    cleanup_view = dict(monitor_payload.get("cleanup") or {})
    trend_view = dict(monitor_payload.get("trends") or {})
    forecast_view = dict(monitor_payload.get("forecast") or {})
    tuning_view = dict(monitor_payload.get("tuning") or {})
    automation_view = dict(monitor_payload.get("automation") or {})
    monitor_history = list(monitor_payload.get("history") or [])
    recent_archives = list(monitor_payload.get("recent_archives") or [])
    cleanup_reports = list(monitor_payload.get("cleanup_reports") or [])
    graph = (
        store.graph_neighbors(case_id=case_id, node_id=node_id, depth=depth, limit=80)
        if node_id
        else store.graph_view(case_id=case_id)
    )

    sources_html = "".join(_source_card(source) for source in summary.get("sources", [])[:6]) or "<p class='muted'>No sources stored for this case.</p>"
    indicators_html = _record_table(
        summary.get("top_indicators", []),
        columns=("record_type", "value", "normalized_value", "created_at"),
        empty="No indicators yet.",
    )
    identities_html = _record_table(
        summary.get("top_identities", []),
        columns=("title", "value", "normalized_value", "created_at"),
        empty="No identities yet.",
    )
    artifacts_html = _record_table(
        summary.get("top_artifacts", []),
        columns=("title", "artifact_type", "media_type", "created_at"),
        empty="No artifacts yet.",
    )
    search_html = _record_table(
        search_results,
        columns=("record_type", "title", "value", "timestamp"),
        empty="Run a search to inspect matching records.",
        link_case_id=case_id,
    )
    relationships_html = _relationship_table(relationships)
    jobs_html = _job_table(jobs)
    audit_html = _audit_table(audit_events)
    timelines_html = _timeline_table(case_id=case_id, rows=timelines)
    timeline_focus_html = _timeline_focus(case_id=case_id, detail=timeline_detail)
    graph_html = _graph_table(case_id=case_id, graph=graph, node_id=node_id)
    hot_sources_html = _monitor_source_table(
        rows=list(monitor_payload.get("hot_sources") or []),
        empty="No hot sources in the latest monitor snapshot.",
        return_to=f"/cases/{_url(case_id)}/dashboard",
    )
    suppressed_sources_html = _monitor_source_table(
        rows=list(monitor_payload.get("suppressed_sources") or []),
        empty="No suppressed sources right now.",
        return_to=f"/cases/{_url(case_id)}/dashboard",
    )
    snoozed_sources_html = _monitor_source_table(
        rows=list(monitor_payload.get("snoozed_sources") or []),
        empty="No sources are currently snoozed.",
        return_to=f"/cases/{_url(case_id)}/dashboard",
    )
    backlog_html = _monitor_backlog_table(
        rows=list(monitor_payload.get("backlog_stages") or []),
        empty="No queued backlog was recorded in the latest snapshot.",
    )

    body = f"""
    <section class="hero">
      <div>
        <p class="eyebrow">Case Dashboard</p>
        <h1>{_text(case_id or 'Unscoped Case')}</h1>
      </div>
      <p class="lede">Review the current intelligence graph, recent activity, timelines, and record search results for this case.</p>
      <div class="stat-grid">
        <article class="stat-card"><span class="stat-label">Sources</span><strong>{_text(summary.get('source_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Records</span><strong>{_text(summary.get('record_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Edges</span><strong>{_text(summary.get('relationship_edge_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Timelines</span><strong>{_text(summary.get('timeline_count', 0))}</strong></article>
      </div>
      <div class="hero-meta">
        <span>First event: {_text(summary.get('first_event_at') or '(none)')}</span>
        <span>Last event: {_text(summary.get('last_event_at') or '(none)')}</span>
        <a href="/">All cases</a>
        <a href="/cases/{_url(case_id)}/summary">Case JSON</a>
        <a href="/plugins">Plugin status</a>
      </div>
    </section>

    <section class="grid two-up">
      <article class="panel">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Source Intake</p>
            <h2>Attached Sources</h2>
          </div>
          <div class="link-row">
            <a href="/cases/{_url(case_id)}/records?record_type=artifact">Artifacts JSON</a>
            <a href="/cases/{_url(case_id)}/export">Case Export</a>
          </div>
        </div>
        <div class="card-grid">{sources_html}</div>
      </article>

      <article class="panel">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Search</p>
            <h2>Record Search</h2>
          </div>
          <div class="link-row">
            <a href="/cases/{_url(case_id)}/search?q={_url(search_query or 'example')}">JSON search</a>
          </div>
        </div>
        <form class="toolbar" method="get" action="/cases/{_url(case_id)}/dashboard">
          <label>Query
            <input type="text" name="q" value="{_attr(search_query)}" placeholder="email, domain, hash, title" />
          </label>
          <label>Record Type
            <input type="text" name="record_type" value="{_attr(record_type)}" placeholder="indicator, identity, event" />
          </label>
          <button type="submit">Search</button>
        </form>
        {search_html}
      </article>
    </section>

    <section class="grid three-up">
      <article class="panel">
        <div class="panel-head"><div><p class="eyebrow">Indicators</p><h2>Top Indicators</h2></div></div>
        {indicators_html}
      </article>
      <article class="panel">
        <div class="panel-head"><div><p class="eyebrow">Identities</p><h2>Top Identities</h2></div></div>
        {identities_html}
      </article>
      <article class="panel">
        <div class="panel-head"><div><p class="eyebrow">Artifacts</p><h2>Top Artifacts</h2></div></div>
        {artifacts_html}
      </article>
    </section>

    <section class="grid two-up">
      <article class="panel">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Graph</p>
            <h2>{"Graph Focus" if node_id else "Graph Overview"}</h2>
          </div>
          <div class="link-row">
            <a href="/cases/{_url(case_id)}/graph">Graph JSON</a>
            <a href="/cases/{_url(case_id)}/graph-view{_query_suffix(node_id=node_id, depth=depth)}">Open graph page</a>
          </div>
        </div>
        <form class="toolbar" method="get" action="/cases/{_url(case_id)}/dashboard">
          <input type="hidden" name="q" value="{_attr(search_query)}" />
          <input type="hidden" name="record_type" value="{_attr(record_type)}" />
          <input type="hidden" name="timeline_id" value="{_attr(timeline_id)}" />
          <label>Node ID
            <input type="text" name="node_id" value="{_attr(node_id)}" placeholder="record-id" />
          </label>
          <label>Depth
            <input type="number" min="1" max="4" name="depth" value="{_attr(depth)}" />
          </label>
          <button type="submit">Focus Graph</button>
        </form>
        {graph_html}
      </article>

      <article class="panel">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Timelines</p>
            <h2>{"Timeline Focus" if timeline_id else "Available Timelines"}</h2>
          </div>
          <div class="link-row">
            <a href="/cases/{_url(case_id)}/timeline">Timeline JSON</a>
            <a href="/cases/{_url(case_id)}/timeline-view{_query_suffix(timeline_id=timeline_id)}">Open timeline page</a>
          </div>
        </div>
        {timelines_html}
        {timeline_focus_html}
      </article>
    </section>

    <section class="grid three-up">
      <article class="panel">
        <div class="panel-head"><div><p class="eyebrow">Relationships</p><h2>Recent Links</h2></div></div>
        {relationships_html}
      </article>
      <article class="panel">
        <div class="panel-head"><div><p class="eyebrow">Jobs</p><h2>Recent Stage Runs</h2></div></div>
        {jobs_html}
      </article>
      <article class="panel">
        <div class="panel-head"><div><p class="eyebrow">Audit</p><h2>Recent Audit Events</h2></div></div>
        {audit_html}
      </article>
    </section>

    <section class="grid three-up">
      <article class="panel">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Monitor</p>
            <h2>Runtime Snapshot</h2>
          </div>
          <div class="link-row">
            <a href="/cases/{_url(case_id)}/monitor">Monitor JSON</a>
            <a href="/cases/{_url(case_id)}/monitor-forecast">Forecast JSON</a>
            <a href="/cases/{_url(case_id)}/monitor-history">History JSON</a>
            <a href="/cases/{_url(case_id)}/monitor-view">Monitor page</a>
            <a href="/cases/{_url(case_id)}/archives">Archives JSON</a>
          </div>
        </div>
        <div class="stat-grid">
          <article class="stat-card"><span class="stat-label">Cycle</span><strong>{_text(monitor_summary.get('cycle_count', 0))}</strong></article>
          <article class="stat-card"><span class="stat-label">Budget Mode</span><strong>{_text(monitor_summary.get('stage_budget_mode', 'idle'))}</strong></article>
          <article class="stat-card"><span class="stat-label">Hot</span><strong>{_text(monitor_summary.get('hot_source_count', 0))}</strong></article>
          <article class="stat-card"><span class="stat-label">Backlogged</span><strong>{_text(monitor_summary.get('backlogged_source_count', 0))}</strong></article>
          <article class="stat-card"><span class="stat-label">Snoozed</span><strong>{_text(monitor_summary.get('snoozed_source_count', 0))}</strong></article>
          <article class="stat-card"><span class="stat-label">Cleanup Removed</span><strong>{_text(monitor_summary.get('cleanup_removed_count', 0))}</strong></article>
          <article class="stat-card"><span class="stat-label">Trend Cycles</span><strong>{_text(monitor_summary.get('history_cycle_count', 0))}</strong></article>
          <article class="stat-card"><span class="stat-label">Forecast Alerts</span><strong>{_text(monitor_summary.get('forecast_alert_count', 0))}</strong></article>
          <article class="stat-card"><span class="stat-label">Automation Recs</span><strong>{_text(monitor_summary.get('automation_recommendation_count', 0))}</strong></article>
        </div>
        <p class="muted">Last heartbeat: {_text(monitor_summary.get('last_heartbeat_at') or '(never)')}</p>
      </article>
      <article class="panel">
        <div class="panel-head"><div><p class="eyebrow">Hot Sources</p><h2>Recent Escalations</h2></div></div>
        {hot_sources_html}
      </article>
      <article class="panel">
        <div class="panel-head"><div><p class="eyebrow">Suppressed</p><h2>Cooling Sources</h2></div></div>
        {suppressed_sources_html}
      </article>
    </section>

    <section class="panel">
      <div class="panel-head"><div><p class="eyebrow">Snoozed</p><h2>Paused Watch Windows</h2></div></div>
      {snoozed_sources_html}
    </section>

    <section class="panel">
      <div class="panel-head"><div><p class="eyebrow">Backlog</p><h2>Queued Stage Pressure</h2></div></div>
      {backlog_html}
    </section>

    <section class="panel">
      <div class="panel-head"><div><p class="eyebrow">Retention</p><h2>Workspace Cleanup</h2></div></div>
      {_cleanup_summary_block(cleanup_view, empty='No cleanup policy is configured for this workspace snapshot.')}
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><p class="eyebrow">Forecast</p><h2>Backlog Outlook</h2></div>
        <div class="link-row">
          <a href="/cases/{_url(case_id)}/monitor-forecast">Forecast JSON</a>
          <a href="/cases/{_url(case_id)}/monitor-tuning">Tuning JSON</a>
        </div>
      </div>
      {_forecast_summary_block(forecast_view, empty='No forecast is available for this case yet.')}
      {_forecast_alert_table(rows=list(forecast_view.get('alerts') or []), empty='No forecast alerts are active for this case.')}
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><p class="eyebrow">Tuning</p><h2>Forecast Tuning</h2></div>
        <div class="link-row"><a href="/cases/{_url(case_id)}/monitor-tuning">Tuning JSON</a></div>
      </div>
      {_tuning_summary_block(tuning_view, empty='No monitor tuning is configured for this case yet.')}
    </section>

    <section class="panel">
      <div class="panel-head"><div><p class="eyebrow">Automation</p><h2>Preset Recommendations</h2></div></div>
      {_automation_summary_block(automation_view, empty='No automation state is available for this case yet.')}
      {_automation_recommendation_table(rows=list(automation_view.get('recommendations') or []), empty='No preset recommendations are active for this case.')}
    </section>

    <section class="grid two-up">
      <article class="panel">
        <div class="panel-head">
          <div><p class="eyebrow">Trends</p><h2>Queue Pressure Trend</h2></div>
          <div class="link-row"><a href="/cases/{_url(case_id)}/monitor-history">History JSON</a></div>
        </div>
        {_trend_chart(
          rows=list(trend_view.get('queue_pressure') or []),
          primary_key='queue_total_before',
          secondary_key='queue_total_after',
          primary_label='Before',
          secondary_label='After',
          empty='No case-scoped monitor history has been recorded yet.',
        )}
      </article>
      <article class="panel">
        <div class="panel-head"><div><p class="eyebrow">Trends</p><h2>Throughput Trend</h2></div></div>
        {_trend_chart(
          rows=list(trend_view.get('throughput') or []),
          primary_key='processed_job_count',
          secondary_key='completed_job_count',
          primary_label='Processed',
          secondary_label='Completed',
          empty='No case-scoped throughput history is available yet.',
          detail_keys=('failed_job_count', 'executed_check_count'),
        )}
      </article>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><p class="eyebrow">History</p><h2>Recent Monitor Cycles</h2></div>
        <div class="link-row"><a href="/cases/{_url(case_id)}/monitor-history">History JSON</a></div>
      </div>
      {_monitor_history_table(rows=monitor_history[:8], empty='No monitor cycles have been recorded for this case.') }
    </section>

    <section class="grid two-up">
      <article class="panel">
        <div class="panel-head">
          <div><p class="eyebrow">Archives</p><h2>Recent Queue Archives</h2></div>
          <div class="link-row"><a href="/cases/{_url(case_id)}/archives">Archives JSON</a></div>
        </div>
        {_archive_table(rows=recent_archives[:8], empty='No archived queue work is available for this case.') }
      </article>
      <article class="panel">
        <div class="panel-head">
          <div><p class="eyebrow">Cleanup</p><h2>Recent Cleanup Reports</h2></div>
          <div class="link-row"><a href="/cases/{_url(case_id)}/cleanup-reports">Cleanup Reports JSON</a></div>
        </div>
        {_cleanup_report_table(rows=cleanup_reports[:6], empty='No cleanup reports have been recorded for this workspace.') }
      </article>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Runtime</p>
          <h2>Plugin Health</h2>
        </div>
        <div class="link-row">
          <span class="muted">Ready {_text(plugin_summary.get('ready_count', 0))} / {_text(plugin_summary.get('plugin_count', 0))}</span>
          <a href="/plugins">Plugins JSON</a>
        </div>
      </div>
      {_plugin_settings_block(plugin_settings_view, action_url='/plugins', return_to=f'/cases/{_url(case_id)}/dashboard')}
      {_plugin_table(
        plugin_rows,
        action_url='/plugins',
        return_to=f'/cases/{_url(case_id)}/dashboard',
        active_profile=str(plugin_settings_view.get('active_profile') or ''),
      )}
    </section>
    """
    return _page(f"Case {case_id}", f"Case {case_id}", body)


def render_timeline_html(store: SQLiteIntelligenceStore, *, case_id: str, timeline_id: str = "") -> str:
    timeline_id = str(timeline_id or "").strip()
    if not timeline_id:
        first = store.fetch_timelines(case_id=case_id, limit=1)
        if first:
            timeline_id = str(first[0].get("timeline", {}).get("id") or "")
    detail = store.timeline_detail(case_id=case_id, timeline_id=timeline_id) if timeline_id else None
    focus_html = _timeline_focus(case_id=case_id, detail=detail)
    body = f"""
    <section class="hero">
      <div>
        <p class="eyebrow">Timeline Drilldown</p>
        <h1>{_text(case_id or 'Unscoped Case')}</h1>
      </div>
      <p class="lede">Follow ordered event flow for a single timeline and jump back into the case dashboard when you need the broader picture.</p>
      <div class="hero-meta">
        <a href="/cases/{_url(case_id)}/dashboard{_query_suffix(timeline_id=timeline_id)}">Back to case dashboard</a>
        <a href="/cases/{_url(case_id)}/timeline?timeline_id={_url(timeline_id)}">Timeline JSON</a>
      </div>
    </section>
    <section class="panel">{focus_html}</section>
    """
    return _page(f"Timeline {timeline_id or case_id}", f"Timeline {timeline_id or '(none)'}", body)


def render_graph_html(
    store: SQLiteIntelligenceStore,
    *,
    case_id: str,
    node_id: str = "",
    depth: int = 1,
) -> str:
    node_id = str(node_id or "").strip()
    graph = (
        store.graph_neighbors(case_id=case_id, node_id=node_id, depth=depth, limit=120)
        if node_id
        else store.graph_view(case_id=case_id)
    )
    body = f"""
    <section class="hero">
      <div>
        <p class="eyebrow">Graph Drilldown</p>
        <h1>{_text(case_id or 'Unscoped Case')}</h1>
      </div>
      <p class="lede">Inspect the broader case graph or focus on a single node and its neighborhood.</p>
      <div class="hero-meta">
        <a href="/cases/{_url(case_id)}/dashboard{_query_suffix(node_id=node_id, depth=depth)}">Back to case dashboard</a>
        <a href="/cases/{_url(case_id)}/graph{_query_suffix(node_id=node_id, depth=depth)}">Graph JSON</a>
      </div>
    </section>
    <section class="panel">
      <form class="toolbar" method="get" action="/cases/{_url(case_id)}/graph-view">
        <label>Node ID
          <input type="text" name="node_id" value="{_attr(node_id)}" placeholder="leave blank for full graph" />
        </label>
        <label>Depth
          <input type="number" min="1" max="4" name="depth" value="{_attr(depth)}" />
        </label>
        <button type="submit">Update Graph</button>
      </form>
      {_graph_table(case_id=case_id, graph=graph, node_id=node_id)}
    </section>
    """
    return _page(f"Graph {case_id}", f"Graph {case_id}", body)


def render_monitor_html(*, case_id: str = "", monitor_view: dict[str, object] | None = None) -> str:
    payload = dict(monitor_view or {})
    overview = dict(payload.get("overview") or {})
    status = dict(payload.get("status") or {})
    cleanup_view = dict(payload.get("cleanup") or {})
    trend_view = dict(payload.get("trends") or {})
    forecast_view = dict(payload.get("forecast") or {})
    tuning_view = dict(payload.get("tuning") or {})
    automation_view = dict(payload.get("automation") or {})
    monitor_history = list(payload.get("history") or [])
    recent_archives = list(payload.get("recent_archives") or [])
    cleanup_reports = list(payload.get("cleanup_reports") or [])
    hot_sources = list(payload.get("hot_sources") or [])
    burst_sources = list(payload.get("burst_sources") or [])
    snoozed_sources = list(payload.get("snoozed_sources") or [])
    suppressed_sources = list(payload.get("suppressed_sources") or [])
    backlogged_sources = list(payload.get("backlogged_sources") or [])
    backlog_stages = list(payload.get("backlog_stages") or [])
    headline = case_id or "All Cases"
    case_prefix = f"/cases/{_url(case_id)}" if case_id else ""

    body = f"""
    <section class="hero">
      <div>
        <p class="eyebrow">Monitor</p>
        <h1>{_text(headline)}</h1>
      </div>
      <p class="lede">Inspect the passive scheduler state, source polling decisions, suppression windows, and queued backlog without opening raw status files.</p>
      <div class="stat-grid">
        <article class="stat-card"><span class="stat-label">Cycle</span><strong>{_text(overview.get('cycle_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Budget Mode</span><strong>{_text(overview.get('stage_budget_mode', 'idle'))}</strong></article>
        <article class="stat-card"><span class="stat-label">Watched Sources</span><strong>{_text(overview.get('watched_source_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Executed Checks</span><strong>{_text(overview.get('executed_check_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Hot Sources</span><strong>{_text(overview.get('hot_source_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Burst Sources</span><strong>{_text(overview.get('burst_source_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Suppressed</span><strong>{_text(overview.get('suppressed_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Snoozed</span><strong>{_text(overview.get('snoozed_source_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Backlogged</span><strong>{_text(overview.get('backlogged_source_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Cleanup Removed</span><strong>{_text(overview.get('cleanup_removed_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Forecast Alerts</span><strong>{_text(overview.get('forecast_alert_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Automation Recs</span><strong>{_text(overview.get('automation_recommendation_count', 0))}</strong></article>
        <article class="stat-card"><span class="stat-label">Auto Applied</span><strong>{_text(overview.get('automation_applied_count', 0))}</strong></article>
      </div>
      <div class="hero-meta">
        <span>Last heartbeat: {_text(overview.get('last_heartbeat_at') or '(never)')}</span>
        <span>Hot streak: {_text(overview.get('hot_cycle_streak', 0))}</span>
        <span>Drain streak: {_text(overview.get('drain_cycle_streak', 0))}</span>
        <a href="{_text(case_prefix + '/monitor' if case_prefix else '/monitor')}">Monitor JSON</a>
        <a href="{_text(case_prefix + '/monitor-forecast' if case_prefix else '/monitor-forecast')}">Forecast JSON</a>
        <a href="{_text(case_prefix + '/monitor-tuning' if case_prefix else '/monitor-tuning')}">Tuning JSON</a>
        <a href="{_text(case_prefix + '/monitor-history' if case_prefix else '/monitor-history')}">History JSON</a>
        <a href="{_text(case_prefix + '/archives' if case_prefix else '/archives')}">Archives JSON</a>
        <a href="{_text(case_prefix + '/cleanup-reports' if case_prefix else '/cleanup-reports')}">Cleanup Reports JSON</a>
        <a href="{_text(case_prefix + '/dashboard' if case_prefix else '/')}">Back to dashboard</a>
      </div>
    </section>

    <section class="grid two-up">
      <article class="panel">
        <div class="panel-head"><div><p class="eyebrow">Hot</p><h2>Recently Active Sources</h2></div></div>
        {_monitor_source_table(rows=hot_sources, empty='No hot sources in the latest snapshot.', return_to=(case_prefix + '/monitor-view' if case_prefix else '/monitor-view'))}
      </article>
      <article class="panel">
        <div class="panel-head"><div><p class="eyebrow">Burst</p><h2>Fast-Poll Sources</h2></div></div>
        {_monitor_source_table(rows=burst_sources, empty='No sources are currently in burst mode.', return_to=(case_prefix + '/monitor-view' if case_prefix else '/monitor-view'))}
      </article>
    </section>

    <section class="grid two-up">
      <article class="panel">
        <div class="panel-head"><div><p class="eyebrow">Suppressed</p><h2>Cooling-Off Windows</h2></div></div>
        {_monitor_source_table(rows=suppressed_sources, empty='No suppression windows are active.', return_to=(case_prefix + '/monitor-view' if case_prefix else '/monitor-view'))}
      </article>
      <article class="panel">
        <div class="panel-head"><div><p class="eyebrow">Snoozed</p><h2>Paused Watch Windows</h2></div></div>
        {_monitor_source_table(rows=snoozed_sources, empty='No sources are currently snoozed.', return_to=(case_prefix + '/monitor-view' if case_prefix else '/monitor-view'))}
      </article>
    </section>

    <section class="grid two-up">
      <article class="panel">
        <div class="panel-head"><div><p class="eyebrow">Backlogged Sources</p><h2>Queued Downstream Work</h2></div></div>
        {_monitor_source_table(rows=backlogged_sources, empty='No watched sources currently point at downstream backlog.', return_to=(case_prefix + '/monitor-view' if case_prefix else '/monitor-view'))}
      </article>
      <article class="panel">
        <div class="panel-head"><div><p class="eyebrow">Source Checks</p><h2>Last Cycle Summary</h2></div></div>
        <pre>{_text(_json_block(status.get('source_checks') or {}))}</pre>
      </article>
    </section>

    <section class="panel">
      <div class="panel-head"><div><p class="eyebrow">Backlog</p><h2>Stage Queue Pressure</h2></div></div>
      {_monitor_backlog_table(rows=backlog_stages, empty='No queue backlog is visible in the latest snapshot.')}
    </section>

    <section class="panel">
      <div class="panel-head"><div><p class="eyebrow">Retention</p><h2>Workspace Cleanup</h2></div></div>
      {_cleanup_summary_block(cleanup_view, empty='No cleanup policy is configured for this monitor snapshot.')}
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><p class="eyebrow">Forecast</p><h2>Backlog Outlook</h2></div>
        <div class="link-row">
          <a href="{_text(case_prefix + '/monitor-forecast' if case_prefix else '/monitor-forecast')}">Forecast JSON</a>
          <a href="{_text(case_prefix + '/monitor-tuning' if case_prefix else '/monitor-tuning')}">Tuning JSON</a>
        </div>
      </div>
      {_forecast_summary_block(forecast_view, empty='No forecast is available for this monitor scope yet.')}
      {_forecast_alert_table(rows=list(forecast_view.get('alerts') or []), empty='No forecast alerts are active for this monitor scope.')}
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><p class="eyebrow">Tuning</p><h2>Forecast Tuning</h2></div>
        <div class="link-row">
          <a href="{_text(case_prefix + '/monitor-tuning' if case_prefix else '/monitor-tuning')}">Tuning JSON</a>
        </div>
      </div>
      {_tuning_summary_block(tuning_view, empty='No monitor tuning is configured for this scope yet.')}
      {_tuning_form(
        action_url=(case_prefix + '/monitor-tuning' if case_prefix else '/monitor-tuning'),
        return_to=(case_prefix + '/monitor-view' if case_prefix else '/monitor-view'),
        tuning_view=tuning_view,
      )}
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><p class="eyebrow">Automation</p><h2>Preset Recommendations</h2></div>
      </div>
      {_automation_summary_block(automation_view, empty='No automation state is available for this monitor scope yet.')}
      {_automation_recommendation_table(rows=list(automation_view.get('recommendations') or []), empty='No preset recommendations are active for this monitor scope.')}
    </section>

    <section class="grid two-up">
      <article class="panel">
        <div class="panel-head">
          <div><p class="eyebrow">Trends</p><h2>Queue Pressure Trend</h2></div>
          <div class="link-row"><a href="{_text(case_prefix + '/monitor-history' if case_prefix else '/monitor-history')}">History JSON</a></div>
        </div>
        {_trend_chart(
          rows=list(trend_view.get('queue_pressure') or []),
          primary_key='queue_total_before',
          secondary_key='queue_total_after',
          primary_label='Before',
          secondary_label='After',
          empty='No monitor queue history is available yet.',
        )}
      </article>
      <article class="panel">
        <div class="panel-head"><div><p class="eyebrow">Trends</p><h2>Throughput Trend</h2></div></div>
        {_trend_chart(
          rows=list(trend_view.get('throughput') or []),
          primary_key='processed_job_count',
          secondary_key='completed_job_count',
          primary_label='Processed',
          secondary_label='Completed',
          empty='No monitor throughput history is available yet.',
          detail_keys=('failed_job_count', 'executed_check_count'),
        )}
      </article>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><p class="eyebrow">History</p><h2>Recent Monitor Cycles</h2></div>
        <div class="link-row"><a href="{_text(case_prefix + '/monitor-history' if case_prefix else '/monitor-history')}">History JSON</a></div>
      </div>
      {_monitor_history_table(rows=monitor_history, empty='No monitor history was found for this scope.')}
    </section>

    <section class="grid two-up">
      <article class="panel">
        <div class="panel-head">
          <div><p class="eyebrow">Archives</p><h2>Recent Queue Archives</h2></div>
          <div class="link-row"><a href="{_text(case_prefix + '/archives' if case_prefix else '/archives')}">Archives JSON</a></div>
        </div>
        {_archive_table(rows=recent_archives, empty='No queue archives were found for this monitor scope.')}
      </article>
      <article class="panel">
        <div class="panel-head">
          <div><p class="eyebrow">Cleanup</p><h2>Cleanup Reports</h2></div>
          <div class="link-row"><a href="{_text(case_prefix + '/cleanup-reports' if case_prefix else '/cleanup-reports')}">Cleanup Reports JSON</a></div>
        </div>
        {_cleanup_report_table(rows=cleanup_reports, empty='No cleanup reports were found for this workspace.') }
      </article>
    </section>
    """
    return _page(f"Monitor {headline}", f"Monitor {headline}", body)


def _page(title: str, heading: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_text(title)}</title>
  <style>
    :root {{
      --bg: #f4efe5;
      --ink: #182128;
      --muted: #5b6770;
      --panel: rgba(255, 251, 244, 0.9);
      --line: rgba(24, 33, 40, 0.12);
      --accent: #0f7b6c;
      --accent-2: #b85c38;
      --accent-soft: rgba(15, 123, 108, 0.08);
      --shadow: 0 22px 60px rgba(38, 26, 12, 0.12);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      font-family: "Segoe UI", "Trebuchet MS", sans-serif;
      background:
        radial-gradient(circle at top right, rgba(184, 92, 56, 0.16), transparent 24%),
        radial-gradient(circle at top left, rgba(15, 123, 108, 0.14), transparent 22%),
        linear-gradient(180deg, #f9f4ec 0%, var(--bg) 100%);
    }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    h1, h2, h3, p {{ margin: 0; }}
    .shell {{
      width: min(1360px, calc(100vw - 32px));
      margin: 24px auto 48px;
      display: grid;
      gap: 18px;
    }}
    .hero, .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 24px;
      box-shadow: var(--shadow);
    }}
    .hero {{
      padding: 28px;
      display: grid;
      gap: 14px;
    }}
    .hero h1 {{
      font-size: clamp(32px, 4vw, 52px);
      letter-spacing: 0.02em;
    }}
    .lede {{
      max-width: 880px;
      color: var(--muted);
      font-size: 16px;
      line-height: 1.6;
    }}
    .eyebrow {{
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-size: 12px;
      color: var(--accent-2);
      font-weight: 700;
    }}
    .hero-meta, .link-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 14px;
      color: var(--muted);
      font-size: 14px;
    }}
    .stat-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
    }}
    .stat-card {{
      padding: 16px;
      border-radius: 18px;
      background: linear-gradient(135deg, rgba(15, 123, 108, 0.08), rgba(184, 92, 56, 0.06));
      border: 1px solid rgba(15, 123, 108, 0.12);
      display: grid;
      gap: 6px;
    }}
    .stat-card strong {{
      font-size: 28px;
      line-height: 1.1;
    }}
    .stat-label {{
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-size: 12px;
    }}
    .grid {{
      display: grid;
      gap: 18px;
    }}
    .two-up {{
      grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
    }}
    .three-up {{
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    }}
    .panel {{
      padding: 22px;
      display: grid;
      gap: 16px;
    }}
    .panel-head {{
      display: flex;
      justify-content: space-between;
      align-items: start;
      gap: 16px;
      flex-wrap: wrap;
    }}
    .card-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
    }}
    .card {{
      padding: 16px;
      border-radius: 18px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.56);
      display: grid;
      gap: 8px;
    }}
    .toolbar {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      align-items: end;
    }}
    label {{
      display: grid;
      gap: 6px;
      color: var(--muted);
      font-size: 13px;
    }}
    input, button {{
      width: 100%;
      border-radius: 14px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.9);
      color: var(--ink);
      font: inherit;
      padding: 11px 12px;
    }}
    button {{
      background: linear-gradient(135deg, rgba(15, 123, 108, 0.15), rgba(184, 92, 56, 0.12));
      cursor: pointer;
      font-weight: 600;
    }}
    .action-stack {{
      display: grid;
      gap: 8px;
    }}
    .action-stack form {{
      margin: 0;
    }}
    .action-stack a, .action-stack button {{
      display: inline-block;
      width: 100%;
      text-align: center;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    th, td {{
      text-align: left;
      padding: 10px 8px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }}
    th {{
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
    }}
    code {{
      display: inline-block;
      font-family: "Cascadia Code", "Consolas", monospace;
      background: var(--accent-soft);
      border-radius: 8px;
      padding: 2px 6px;
    }}
    .muted {{ color: var(--muted); }}
    .timeline-list, .event-list {{
      list-style: none;
      padding: 0;
      margin: 0;
      display: grid;
      gap: 10px;
    }}
    .timeline-item, .event-item {{
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 14px;
      background: rgba(255, 255, 255, 0.56);
      display: grid;
      gap: 6px;
    }}
    .empty {{
      padding: 18px;
      border: 1px dashed var(--line);
      border-radius: 16px;
      color: var(--muted);
      background: rgba(255, 255, 255, 0.35);
    }}
    .trend-list {{
      display: grid;
      gap: 14px;
    }}
    .trend-row {{
      display: grid;
      gap: 10px;
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.56);
    }}
    .trend-head {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      align-items: baseline;
    }}
    .trend-metric {{
      display: grid;
      gap: 6px;
    }}
    .trend-bar-track {{
      width: 100%;
      height: 12px;
      border-radius: 999px;
      overflow: hidden;
      background: rgba(24, 33, 40, 0.08);
      border: 1px solid rgba(24, 33, 40, 0.08);
    }}
    .trend-bar-fill {{
      display: block;
      height: 100%;
      border-radius: 999px;
      background: linear-gradient(90deg, rgba(15, 123, 108, 0.82), rgba(15, 123, 108, 0.48));
    }}
    .trend-bar-fill.secondary {{
      background: linear-gradient(90deg, rgba(184, 92, 56, 0.82), rgba(184, 92, 56, 0.48));
    }}
    .trend-detail {{
      color: var(--muted);
      font-size: 13px;
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }}
    pre {{
      margin: 0;
      padding: 16px;
      border-radius: 16px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.56);
      overflow: auto;
      font-family: "Cascadia Code", "Consolas", monospace;
      font-size: 12px;
      line-height: 1.5;
    }}
  </style>
</head>
<body>
  <main class="shell" aria-label="{_text(heading)}">
    {body}
  </main>
</body>
</html>"""


def _source_card(source: dict[str, object]) -> str:
    return (
        "<article class='card'>"
        f"<strong>{_text(source.get('display_name') or source.get('locator') or source.get('id'))}</strong>"
        f"<span class='muted'>{_text(source.get('source_type') or 'source')}</span>"
        f"<span>{_text(source.get('locator') or '(no locator)')}</span>"
        f"<code>{_text(source.get('id') or '')}</code>"
        "</article>"
    )


def _record_table(
    rows: list[dict[str, object]],
    *,
    columns: tuple[str, ...],
    empty: str,
    link_case_id: str = "",
) -> str:
    if not rows:
        return f"<p class='empty'>{_text(empty)}</p>"
    headers = "".join(f"<th>{_text(column.replace('_', ' '))}</th>" for column in columns)
    body_rows = []
    for row in rows:
        cells = []
        for column in columns:
            value = row.get(column, "")
            if column == "title" and not value:
                value = _record_label(row)
            if column == "value" and not value:
                value = _record_label(row)
            if link_case_id and column == columns[0]:
                cells.append(
                    "<td>"
                    f"<a href='/cases/{_url(link_case_id)}/graph-view?node_id={_url(str(row.get('id') or ''))}&depth=1'>"
                    f"{_text(value)}"
                    "</a></td>"
                )
            else:
                cells.append(f"<td>{_text(value)}</td>")
        body_rows.append(f"<tr>{''.join(cells)}</tr>")
    return f"<table><thead><tr>{headers}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"


def _relationship_table(rows: list[dict[str, object]]) -> str:
    if not rows:
        return "<p class='empty'>No relationships yet.</p>"
    body_rows = "".join(
        (
            "<tr>"
            f"<td>{_text(row.get('relationship_type') or '')}</td>"
            f"<td><code>{_text(row.get('source_ref') or '')}</code></td>"
            f"<td><code>{_text(row.get('target_ref') or '')}</code></td>"
            f"<td>{_text(row.get('reason') or '')}</td>"
            "</tr>"
        )
        for row in rows
    )
    return (
        "<table><thead><tr><th>Type</th><th>Source</th><th>Target</th><th>Reason</th></tr></thead>"
        f"<tbody>{body_rows}</tbody></table>"
    )


def _job_table(rows: list[dict[str, object]]) -> str:
    if not rows:
        return "<p class='empty'>No jobs recorded yet.</p>"
    body_rows = "".join(
        (
            "<tr>"
            f"<td>{_text(row.get('stage') or '')}</td>"
            f"<td>{_text(row.get('status') or '')}</td>"
            f"<td>{_text(row.get('worker') or '')}</td>"
            f"<td>{_text(row.get('finished_at') or row.get('started_at') or '')}</td>"
            "</tr>"
        )
        for row in rows
    )
    return (
        "<table><thead><tr><th>Stage</th><th>Status</th><th>Worker</th><th>When</th></tr></thead>"
        f"<tbody>{body_rows}</tbody></table>"
    )


def _audit_table(rows: list[dict[str, object]]) -> str:
    if not rows:
        return "<p class='empty'>No audit events recorded yet.</p>"
    body_rows = "".join(
        (
            "<tr>"
            f"<td>{_text(row.get('stage') or '')}</td>"
            f"<td>{_text(row.get('status') or '')}</td>"
            f"<td>{_text(row.get('plugin') or '')}</td>"
            f"<td>{_text(row.get('created_at') or '')}</td>"
            "</tr>"
        )
        for row in rows
    )
    return (
        "<table><thead><tr><th>Stage</th><th>Status</th><th>Plugin</th><th>When</th></tr></thead>"
        f"<tbody>{body_rows}</tbody></table>"
    )


def _timeline_table(*, case_id: str, rows: list[dict[str, object]]) -> str:
    if not rows:
        return "<p class='empty'>No timelines recorded yet.</p>"
    items = []
    for row in rows:
        timeline = dict(row.get("timeline") or {})
        timeline_id = str(timeline.get("id") or "")
        items.append(
            "<li class='timeline-item'>"
            f"<strong>{_text(timeline.get('title') or timeline_id or '(untitled)')}</strong>"
            f"<span class='muted'>{_text(timeline.get('start_time') or '')} to {_text(timeline.get('end_time') or '')}</span>"
            f"<span>{_text(len(row.get('events', [])))} events</span>"
            f"<a href='/cases/{_url(case_id)}/dashboard?timeline_id={_url(timeline_id)}'>Open on dashboard</a>"
            f"<a href='/cases/{_url(case_id)}/timeline-view?timeline_id={_url(timeline_id)}'>Timeline page</a>"
            "</li>"
        )
    return f"<ul class='timeline-list'>{''.join(items)}</ul>"


def _timeline_focus(*, case_id: str, detail: dict[str, object] | None) -> str:
    if not detail:
        return "<p class='empty'>Choose a timeline to inspect ordered events.</p>"
    timeline = dict(detail.get("timeline") or {})
    events = list(detail.get("events") or [])
    event_items = "".join(
        (
            "<li class='event-item'>"
            f"<strong>{_text(event.get('title') or event.get('event_type') or event.get('id') or '(event)')}</strong>"
            f"<span class='muted'>{_text(event.get('timestamp') or event.get('created_at') or '')}</span>"
            f"<span>{_text(event.get('event_type') or 'event')}</span>"
            f"<a href='/cases/{_url(case_id)}/graph-view?node_id={_url(str(event.get('id') or ''))}&depth=1'>Graph focus</a>"
            "</li>"
        )
        for event in events
    ) or "<li class='event-item'>No events are attached to this timeline.</li>"
    return (
        "<div class='card'>"
        f"<strong>{_text(timeline.get('title') or timeline.get('id') or '(timeline)')}</strong>"
        f"<span class='muted'>{_text(timeline.get('start_time') or '')} to {_text(timeline.get('end_time') or '')}</span>"
        f"<code>{_text(timeline.get('id') or '')}</code>"
        "</div>"
        f"<ul class='event-list'>{event_items}</ul>"
    )


def _graph_table(*, case_id: str, graph: dict[str, object], node_id: str = "") -> str:
    nodes = list(graph.get("nodes") or [])
    edges = list(graph.get("edges") or [])
    summary = (
        f"<p class='muted'>Showing {_text(len(nodes))} nodes and {_text(len(edges))} edges"
        + (f" around <code>{_text(node_id)}</code>." if node_id else ".")
        + "</p>"
    )
    node_rows = "".join(
        (
            "<tr>"
            f"<td><a href='/cases/{_url(case_id)}/graph-view?node_id={_url(str(node.get('id') or ''))}&depth=1'>{_text(node.get('id') or '')}</a></td>"
            f"<td>{_text(node.get('record_type') or node.get('kind') or '')}</td>"
            f"<td>{_text(node.get('label') or '')}</td>"
            "</tr>"
        )
        for node in nodes[:20]
    ) or "<tr><td colspan='3'>No nodes available.</td></tr>"
    edge_rows = "".join(
        (
            "<tr>"
            f"<td>{_text(edge.get('type') or edge.get('relationship_type') or '')}</td>"
            f"<td><code>{_text(edge.get('source') or edge.get('source_ref') or '')}</code></td>"
            f"<td><code>{_text(edge.get('target') or edge.get('target_ref') or '')}</code></td>"
            "</tr>"
        )
        for edge in edges[:20]
    ) or "<tr><td colspan='3'>No edges available.</td></tr>"
    return (
        summary
        + "<table><thead><tr><th>Node</th><th>Type</th><th>Label</th></tr></thead>"
        + f"<tbody>{node_rows}</tbody></table>"
        + "<table><thead><tr><th>Edge</th><th>Source</th><th>Target</th></tr></thead>"
        + f"<tbody>{edge_rows}</tbody></table>"
    )


def _plugin_settings_block(plugin_settings: dict[str, object], *, action_url: str, return_to: str) -> str:
    payload = dict(plugin_settings or {})
    profiles = list(payload.get("profiles") or [])
    if not payload and not profiles:
        return ""
    active_profile = str(payload.get("active_profile") or "").strip()
    settings_path = str(payload.get("settings_path") or "").strip()
    profile_cards = "".join(
        (
            "<article class='card'>"
            f"<strong>{_text(item.get('name') or '')}</strong>"
            f"<span class='muted'>enabled {_text(item.get('enabled_count', 0))}, disabled {_text(item.get('disabled_count', 0))}</span>"
            f"<span class='muted'>{_text('active' if item.get('active') else 'saved profile')}</span>"
            "</article>"
        )
        for item in profiles
    ) or "<p class='muted'>No plugin profiles are saved yet.</p>"
    return (
        "<div class='card'>"
        f"<span class='muted'>Active profile: {_text(active_profile or 'default')}.</span>"
        f"<span class='muted'>Settings file: {_text(settings_path or '(not written yet)')}.</span>"
        "</div>"
        f"<div class='card-grid'>{profile_cards}</div>"
        f"<form class='toolbar' method='post' action='{_attr(action_url)}'>"
        f"<input type='hidden' name='return_to' value='{_attr(return_to)}' />"
        "<input type='hidden' name='action' value='set-active-profile' />"
        f"<label>Active Profile<input type='text' name='profile_name' value='{_attr(active_profile)}' placeholder='default' /></label>"
        "<button type='submit'>Activate Profile</button>"
        "</form>"
        f"<form class='toolbar' method='post' action='{_attr(action_url)}'>"
        f"<input type='hidden' name='return_to' value='{_attr(return_to)}' />"
        "<input type='hidden' name='action' value='save-profile' />"
        f"<input type='hidden' name='source_profile_name' value='{_attr(active_profile)}' />"
        "<label>Save Profile As<input type='text' name='profile_name' value='' placeholder='triage-only' /></label>"
        "<button type='submit'>Save Profile</button>"
        "</form>"
        f"<form class='toolbar' method='post' action='{_attr(action_url)}'>"
        f"<input type='hidden' name='return_to' value='{_attr(return_to)}' />"
        "<input type='hidden' name='action' value='delete-profile' />"
        "<label>Delete Profile<input type='text' name='profile_name' value='' placeholder='old-profile' /></label>"
        "<button type='submit'>Delete Profile</button>"
        "</form>"
    )


def _plugin_table(
    rows: list[dict[str, object]],
    *,
    action_url: str = "",
    return_to: str = "",
    active_profile: str = "",
) -> str:
    if not rows:
        return "<p class='empty'>No plugin status is available.</p>"
    body_rows = "".join(
        (
            "<tr>"
            + f"<td>{_text(row.get('name') or '')}</td>"
            + f"<td>{_text(row.get('plugin_type') or '')}</td>"
            + f"<td>{_text(row.get('status') or '')}</td>"
            + f"<td>{_text(', '.join(row.get('required_tools') or []) or '-')}</td>"
            + f"<td>{_text(row.get('summary') or '')}</td>"
            + (
                f"<td>{_plugin_control_cell(row, action_url=action_url, return_to=return_to, active_profile=active_profile)}</td>"
                if action_url
                else ""
            )
            + "</tr>"
        )
        for row in rows
    )
    return (
        "<table><thead><tr><th>Name</th><th>Type</th><th>Status</th><th>Tools</th><th>Summary</th>"
        + ("<th>Controls</th>" if action_url else "")
        + "</tr></thead>"
        f"<tbody>{body_rows}</tbody></table>"
    )


def _plugin_summary(rows: list[dict[str, object]]) -> dict[str, int]:
    counts = {
        "plugin_count": len(rows),
        "ready_count": 0,
        "optional_tool_missing_count": 0,
        "attention_count": 0,
        "disabled_count": 0,
    }
    for row in rows:
        status = str(row.get("status") or "")
        if status == "ready":
            counts["ready_count"] += 1
        elif status == "optional_tool_missing":
            counts["optional_tool_missing_count"] += 1
        elif status == "disabled":
            counts["disabled_count"] += 1
        else:
            counts["attention_count"] += 1
    return counts


def _plugin_control_cell(
    row: dict[str, object],
    *,
    action_url: str,
    return_to: str,
    active_profile: str,
) -> str:
    plugin_name = str(row.get("name") or "").strip()
    if not plugin_name:
        return "<span class='muted'>n/a</span>"
    action = "disable" if bool(row.get("enabled", True)) else "enable"
    label = "Disable" if bool(row.get("enabled", True)) else "Enable"
    return (
        "<div class='action-stack'>"
        f"<form method='post' action='{_attr(action_url)}'>"
        f"<input type='hidden' name='return_to' value='{_attr(return_to)}' />"
        f"<input type='hidden' name='action' value='{_attr(action)}' />"
        f"<input type='hidden' name='plugin_name' value='{_attr(plugin_name)}' />"
        f"<input type='hidden' name='profile_name' value='{_attr(active_profile)}' />"
        f"<button type='submit'>{_text(label)}</button>"
        "</form>"
        "</div>"
    )


def _cleanup_summary_block(cleanup_view: dict[str, object], *, empty: str) -> str:
    payload = dict(cleanup_view or {})
    policy = dict(payload.get("policy") or {})
    summary = dict(payload.get("summary") or {})
    if not policy and not summary:
        return f"<p class='empty'>{_text(empty)}</p>"

    configured = bool(policy.get("enabled"))
    state = str(summary.get("reason") or ("configured" if configured else "disabled"))
    report_path = str(summary.get("report_path") or "")
    report_name = Path(report_path).name if report_path else ""
    return (
        "<div class='stat-grid'>"
        f"<article class='stat-card'><span class='stat-label'>Configured</span><strong>{_text('Yes' if configured else 'No')}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Last State</span><strong>{_text(state or 'unknown')}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Removed</span><strong>{_text(summary.get('removed_count', 0))}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Candidates</span><strong>{_text(summary.get('candidate_count', 0))}</strong></article>"
        "</div>"
        "<div class='card'>"
        f"<span class='muted'>Policy: completed {_text(policy.get('cleanup_completed_days', 0.0))}d, failed {_text(policy.get('cleanup_failed_days', 0.0))}d, watch-delta {_text(policy.get('cleanup_watch_delta_days', 0.0))}d.</span>"
        f"<span class='muted'>Last cleanup removed {_text(summary.get('removed_bytes', 0))} bytes, warnings {_text(summary.get('warning_count', 0))}, errors {_text(summary.get('error_count', 0))}.</span>"
        f"{f'<span class=\"muted\">Report: <code>{_text(report_name)}</code></span>' if report_name else ''}"
        "</div>"
    )


def _forecast_summary_block(forecast_view: dict[str, object], *, empty: str) -> str:
    payload = dict(forecast_view or {})
    summary = dict(payload.get("summary") or {})
    if not summary:
        return f"<p class='empty'>{_text(empty)}</p>"
    return (
        "<div class='stat-grid'>"
        f"<article class='stat-card'><span class='stat-label'>Alert Level</span><strong>{_text(summary.get('highest_alert_severity') or 'none')}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Predicted Next Queue</span><strong>{_text(summary.get('predicted_next_queue_total_before', 0))}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Drain Cycles</span><strong>{_text(summary.get('predicted_backlog_drain_cycles', 0))}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Queue State</span><strong>{_text(summary.get('queue_pressure_state') or 'steady')}</strong></article>"
        "</div>"
        "<div class='card'>"
        f"<span class='muted'>History window: {_text(summary.get('history_count', 0))} cycles. Avg queue before {_text(_format_decimal(summary.get('avg_queue_total_before', 0.0)))}, avg processed {_text(_format_decimal(summary.get('avg_processed_job_count', 0.0)))}, avg changed {_text(_format_decimal(summary.get('avg_changed_count', 0.0)))}.</span>"
        f"<span class='muted'>Estimated intake delta {_text(_format_decimal(summary.get('avg_intake_delta', 0.0)))}, throughput state {_text(summary.get('throughput_state') or 'steady')}.</span>"
        "</div>"
    )


def _forecast_alert_table(*, rows: list[dict[str, object]], empty: str) -> str:
    if not rows:
        return f"<p class='empty'>{_text(empty)}</p>"
    body_rows = "".join(
        (
            "<tr>"
            f"<td>{_text(row.get('severity') or '')}</td>"
            f"<td>{_text(row.get('title') or '')}</td>"
            f"<td>{_text(row.get('message') or '')}</td>"
            "</tr>"
        )
        for row in rows
    )
    return (
        "<table><thead><tr><th>Severity</th><th>Alert</th><th>Message</th></tr></thead>"
        f"<tbody>{body_rows}</tbody></table>"
    )


def _tuning_summary_block(tuning_view: dict[str, object], *, empty: str) -> str:
    payload = dict(tuning_view or {})
    if not payload:
        return f"<p class='empty'>{_text(empty)}</p>"
    preset_name = str(payload.get("preset_name") or "").strip()
    suppressed_alert_ids = list(payload.get("suppressed_alert_ids") or [])
    suppressed_stage_alerts = dict(payload.get("suppressed_stage_alerts") or {})
    suppressed_watch_alerts = dict(payload.get("suppressed_watch_alerts") or {})
    alert_severity_overrides = dict(payload.get("alert_severity_overrides") or {})
    stage_threshold_overrides = dict(payload.get("stage_threshold_overrides") or {})
    return (
        "<div class='stat-grid'>"
        f"<article class='stat-card'><span class='stat-label'>Preset</span><strong>{_text(preset_name or 'balanced')}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Automation</span><strong>{_text(payload.get('automation_mode') or 'recommend')}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Min History</span><strong>{_text(payload.get('forecast_min_history', 0))}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Queue Spike</span><strong>{_text(_format_decimal(payload.get('queue_spike_factor', 0.0)))}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Churn Spike</span><strong>{_text(_format_decimal(payload.get('source_churn_spike_factor', 0.0)))}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Throughput Drop</span><strong>{_text(_format_decimal(payload.get('throughput_drop_factor', 0.0)))}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Suppressed Alerts</span><strong>{_text(len(suppressed_alert_ids))}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Suppressed Stages</span><strong>{_text(len(suppressed_stage_alerts))}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Suppressed Watches</span><strong>{_text(len(suppressed_watch_alerts))}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Severity Overrides</span><strong>{_text(len(alert_severity_overrides))}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Stage Thresholds</span><strong>{_text(len(stage_threshold_overrides))}</strong></article>"
        "</div>"
        "<div class='card'>"
        f"<span class='muted'>Global suppressions: {_text(', '.join(suppressed_alert_ids) or 'none')}.</span>"
        f"<span class='muted'>Stage suppressions: {_text(_alert_mapping_text(suppressed_stage_alerts) or 'none')}.</span>"
        f"<span class='muted'>Watch suppressions: {_text(_alert_mapping_text(suppressed_watch_alerts) or 'none')}.</span>"
        f"<span class='muted'>Alert severities: {_text(_severity_mapping_text(alert_severity_overrides) or 'none')}.</span>"
        f"<span class='muted'>Stage thresholds: {_text(_stage_threshold_mapping_text(stage_threshold_overrides) or 'none')}.</span>"
        "</div>"
    )


def _tuning_form(*, action_url: str, return_to: str, tuning_view: dict[str, object]) -> str:
    payload = dict(tuning_view or {})
    return (
        f"<form class='toolbar' method='post' action='{_attr(action_url)}'>"
        f"<input type='hidden' name='return_to' value='{_attr(return_to)}' />"
        f"<label>Preset"
        f"<input type='text' name='preset_name' value='{_attr(payload.get('preset_name') or '')}' placeholder='balanced, collection_first, quiet' />"
        f"</label>"
        f"<label>Automation Mode"
        f"<input type='text' name='automation_mode' value='{_attr(payload.get('automation_mode') or '')}' placeholder='off, recommend, apply' />"
        f"</label>"
        f"<label>Min History"
        f"<input type='number' min='1' name='forecast_min_history' value='{_attr(payload.get('forecast_min_history', 0))}' />"
        f"</label>"
        f"<label>Queue Spike Factor"
        f"<input type='text' name='queue_spike_factor' value='{_attr(_format_decimal(payload.get('queue_spike_factor', 0.0)))}' />"
        f"</label>"
        f"<label>Source Churn Factor"
        f"<input type='text' name='source_churn_spike_factor' value='{_attr(_format_decimal(payload.get('source_churn_spike_factor', 0.0)))}' />"
        f"</label>"
        f"<label>Throughput Drop Factor"
        f"<input type='text' name='throughput_drop_factor' value='{_attr(_format_decimal(payload.get('throughput_drop_factor', 0.0)))}' />"
        f"</label>"
        f"<label>Suppressed Alerts"
        f"<input type='text' name='suppressed_alert_ids' value='{_attr(', '.join(list(payload.get('suppressed_alert_ids') or [])))}' placeholder='failure_burst, queue_pressure_spike' />"
        f"</label>"
        f"<label>Stage Suppressions"
        f"<input type='text' name='suppressed_stage_alerts' value='{_attr(_alert_mapping_text(dict(payload.get('suppressed_stage_alerts') or {})))}' placeholder='recover:failure_burst' />"
        f"</label>"
        f"<label>Watch Suppressions"
        f"<input type='text' name='suppressed_watch_alerts' value='{_attr(_alert_mapping_text(dict(payload.get('suppressed_watch_alerts') or {})))}' placeholder='watch-id:source_churn_spike' />"
        f"</label>"
        f"<label>Alert Severities"
        f"<input type='text' name='alert_severity_overrides' value='{_attr(_severity_mapping_text(dict(payload.get('alert_severity_overrides') or {})))}' placeholder='queue_pressure_spike:critical' />"
        f"</label>"
        f"<label>Stage Thresholds"
        f"<input type='text' name='stage_threshold_overrides' value='{_attr(_stage_threshold_mapping_text(dict(payload.get('stage_threshold_overrides') or {})))}' placeholder='extract:queue_spike_factor=2.5, store:throughput_drop_factor=0.4' />"
        f"</label>"
        "<button type='submit'>Save Tuning</button>"
        "</form>"
        f"<form class='toolbar' method='post' action='{_attr(action_url)}'>"
        f"<input type='hidden' name='return_to' value='{_attr(return_to)}' />"
        "<input type='hidden' name='clear_suppressions' value='true' />"
        "<button type='submit'>Clear Suppressions</button>"
        "</form>"
        f"<form class='toolbar' method='post' action='{_attr(action_url)}'>"
        f"<input type='hidden' name='return_to' value='{_attr(return_to)}' />"
        "<input type='hidden' name='clear_alert_severities' value='true' />"
        "<button type='submit'>Clear Alert Severities</button>"
        "</form>"
        f"<form class='toolbar' method='post' action='{_attr(action_url)}'>"
        f"<input type='hidden' name='return_to' value='{_attr(return_to)}' />"
        "<input type='hidden' name='clear_stage_thresholds' value='true' />"
        "<button type='submit'>Clear Stage Thresholds</button>"
        "</form>"
    )


def _automation_summary_block(automation_view: dict[str, object], *, empty: str) -> str:
    payload = dict(automation_view or {})
    summary = dict(payload.get("summary") or {})
    if not payload:
        return f"<p class='empty'>{_text(empty)}</p>"
    return (
        "<div class='stat-grid'>"
        f"<article class='stat-card'><span class='stat-label'>Mode</span><strong>{_text(payload.get('mode') or 'recommend')}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Recommendations</span><strong>{_text(summary.get('recommendation_count', 0))}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Applied</span><strong>{_text(summary.get('applied_count', 0))}</strong></article>"
        f"<article class='stat-card'><span class='stat-label'>Safe To Apply</span><strong>{_text(summary.get('safe_to_apply_count', 0))}</strong></article>"
        "</div>"
        "<div class='card'>"
        f"<span class='muted'>Case recommendations: {_text(summary.get('case_recommendation_count', 0))}, watch recommendations: {_text(summary.get('watch_recommendation_count', 0))}.</span>"
        f"<span class='muted'>Auto-applied case presets: {_text(summary.get('case_applied_count', 0))}, auto-applied watch presets: {_text(summary.get('watch_applied_count', 0))}.</span>"
        f"<span class='muted'>Last evaluated: {_text(payload.get('evaluated_at') or '(never)')}.</span>"
        "</div>"
    )


def _automation_recommendation_table(*, rows: list[dict[str, object]], empty: str) -> str:
    if not rows:
        return f"<p class='empty'>{_text(empty)}</p>"
    body_rows = "".join(
        (
            "<tr>"
            f"<td>{_text(row.get('scope') or '')}</td>"
            f"<td>{_text(row.get('target_label') or row.get('target_id') or '')}</td>"
            f"<td>{_text(row.get('action') or 'recommend')}</td>"
            f"<td>{_text(row.get('current_preset_name') or '')}</td>"
            f"<td>{_text(row.get('recommended_preset_name') or '')}</td>"
            f"<td>{_text('yes' if row.get('safe_to_apply') else 'no')}</td>"
            f"<td>{_text(row.get('reason') or '')}</td>"
            "</tr>"
        )
        for row in rows
    )
    return (
        "<table><thead><tr><th>Scope</th><th>Target</th><th>Action</th><th>Current</th><th>Recommended</th><th>Safe</th><th>Reason</th></tr></thead>"
        f"<tbody>{body_rows}</tbody></table>"
    )


def _alert_mapping_text(mapping: dict[str, object]) -> str:
    rows: list[str] = []
    for key, values in dict(mapping or {}).items():
        normalized_key = str(key or "").strip()
        if not normalized_key:
            continue
        for value in list(values or []):
            normalized_value = str(value or "").strip()
            if not normalized_value:
                continue
            rows.append(f"{normalized_key}:{normalized_value}")
    return ", ".join(rows)


def _severity_mapping_text(mapping: dict[str, object]) -> str:
    rows: list[str] = []
    for key, value in dict(mapping or {}).items():
        normalized_key = str(key or "").strip()
        normalized_value = str(value or "").strip().lower()
        if not normalized_key or normalized_value not in {"info", "warning", "critical"}:
            continue
        rows.append(f"{normalized_key}:{normalized_value}")
    return ", ".join(rows)


def _stage_threshold_mapping_text(mapping: dict[str, object]) -> str:
    rows: list[str] = []
    for key, values in dict(mapping or {}).items():
        normalized_key = str(key or "").strip()
        if not normalized_key or not isinstance(values, dict):
            continue
        for threshold_key, threshold_value in values.items():
            normalized_threshold_key = str(threshold_key or "").strip()
            if normalized_threshold_key not in {"queue_spike_factor", "throughput_drop_factor"}:
                continue
            rows.append(f"{normalized_key}:{normalized_threshold_key}={_format_decimal(threshold_value)}")
    return ", ".join(rows)


def _monitor_source_table(*, rows: list[dict[str, object]], empty: str, return_to: str = "") -> str:
    if not rows:
        return f"<p class='empty'>{_text(empty)}</p>"
    body_rows = "".join(
        (
            "<tr>"
            f"<td>{_text(row.get('display_name') or row.get('locator') or '')}</td>"
            f"<td>{_text(row.get('source_type') or '')}</td>"
            f"<td>{_text(row.get('priority_label') or '')}</td>"
            f"<td>{_text(row.get('poll_adaptation') or row.get('next_poll_adaptation') or '')}</td>"
            f"<td>{_text(row.get('backlog_pointer') or row.get('reason') or '')}</td>"
            f"<td>{_monitor_source_actions(row, return_to=return_to)}</td>"
            "</tr>"
        )
        for row in rows
    )
    return (
        "<table><thead><tr><th>Source</th><th>Type</th><th>Priority</th><th>Polling</th><th>State</th><th>Actions</th></tr></thead>"
        f"<tbody>{body_rows}</tbody></table>"
    )


def _monitor_backlog_table(*, rows: list[dict[str, object]], empty: str) -> str:
    if not rows:
        return f"<p class='empty'>{_text(empty)}</p>"
    body_rows = "".join(
        (
            "<tr>"
            f"<td>{_text(row.get('stage') or '')}</td>"
            f"<td>{_text(row.get('pending_before') or 0)}</td>"
            f"<td>{_text(row.get('oldest_age_seconds') or 0)}</td>"
            f"<td>{_text(row.get('aged_job_count_soft') or 0)}</td>"
            f"<td>{_text(row.get('aged_job_count_hard') or 0)}</td>"
            "</tr>"
        )
        for row in rows
    )
    return (
        "<table><thead><tr><th>Stage</th><th>Pending</th><th>Oldest Age (s)</th><th>Aged Soft</th><th>Aged Hard</th></tr></thead>"
        f"<tbody>{body_rows}</tbody></table>"
    )


def _archive_table(*, rows: list[dict[str, object]], empty: str) -> str:
    if not rows:
        return f"<p class='empty'>{_text(empty)}</p>"
    body_rows = "".join(
        (
            "<tr>"
            f"<td>{_text(row.get('archived_at') or '')}</td>"
            f"<td>{_text(row.get('archive_state') or '')}</td>"
            f"<td>{_text(row.get('stage') or '')}</td>"
            f"<td>{_text(row.get('display_name') or row.get('locator') or '')}</td>"
            f"<td>{_text(_archive_result_summary(row))}</td>"
            f"<td><code>{_text(row.get('archive_name') or '')}</code></td>"
            "</tr>"
        )
        for row in rows
    )
    return (
        "<table><thead><tr><th>Archived</th><th>State</th><th>Stage</th><th>Source</th><th>Result</th><th>Archive</th></tr></thead>"
        f"<tbody>{body_rows}</tbody></table>"
    )


def _cleanup_report_table(*, rows: list[dict[str, object]], empty: str) -> str:
    if not rows:
        return f"<p class='empty'>{_text(empty)}</p>"
    body_rows = "".join(
        (
            "<tr>"
            f"<td>{_text(row.get('completed_at') or row.get('started_at') or '')}</td>"
            f"<td>{_text('ok' if bool(row.get('ok')) else 'errors')}</td>"
            f"<td>{_text(row.get('removed_count') or 0)}</td>"
            f"<td>{_text(row.get('candidate_count') or 0)}</td>"
            f"<td>{_text(_cleanup_category_summary(row.get('categories') or {}))}</td>"
            f"<td><code>{_text(row.get('report_name') or '')}</code></td>"
            "</tr>"
        )
        for row in rows
    )
    return (
        "<table><thead><tr><th>Completed</th><th>Status</th><th>Removed</th><th>Candidates</th><th>Categories</th><th>Report</th></tr></thead>"
        f"<tbody>{body_rows}</tbody></table>"
    )


def _trend_chart(
    *,
    rows: list[dict[str, object]],
    primary_key: str,
    secondary_key: str,
    primary_label: str,
    secondary_label: str,
    empty: str,
    detail_keys: tuple[str, ...] = (),
) -> str:
    if not rows:
        return f"<p class='empty'>{_text(empty)}</p>"
    recent_rows = list(rows)[-8:]
    max_value = max(
        max(int(row.get(primary_key) or 0), int(row.get(secondary_key) or 0))
        for row in recent_rows
    ) or 1
    body_rows = []
    for row in recent_rows:
        primary_value = int(row.get(primary_key) or 0)
        secondary_value = int(row.get(secondary_key) or 0)
        detail_text = " ".join(
            f"<span>{_text(key.replace('_', ' '))}: {_text(row.get(key) or 0)}</span>"
            for key in detail_keys
        )
        body_rows.append(
            "<article class='trend-row'>"
            "<div class='trend-head'>"
            f"<strong>{_text(row.get('label') or row.get('cycle_count') or '')}</strong>"
            f"<span class='muted'>{_text(row.get('last_heartbeat_at') or '')}</span>"
            "</div>"
            "<div class='trend-metric'>"
            f"<span class='muted'>{_text(primary_label)}: {_text(primary_value)}</span>"
            f"<div class='trend-bar-track'><span class='trend-bar-fill' style='width: {_trend_width(primary_value, max_value)}%'></span></div>"
            "</div>"
            "<div class='trend-metric'>"
            f"<span class='muted'>{_text(secondary_label)}: {_text(secondary_value)}</span>"
            f"<div class='trend-bar-track'><span class='trend-bar-fill secondary' style='width: {_trend_width(secondary_value, max_value)}%'></span></div>"
            "</div>"
            f"{f'<div class=\"trend-detail\">{detail_text}</div>' if detail_text else ''}"
            "</article>"
        )
    return f"<div class='trend-list'>{''.join(body_rows)}</div>"


def _monitor_history_table(*, rows: list[dict[str, object]], empty: str) -> str:
    if not rows:
        return f"<p class='empty'>{_text(empty)}</p>"
    body_rows = "".join(
        (
            "<tr>"
            f"<td>{_text(row.get('cycle_count') or 0)}</td>"
            f"<td>{_text(row.get('last_heartbeat_at') or row.get('recorded_at') or '')}</td>"
            f"<td>{_text(row.get('stage_budget_mode') or '')}</td>"
            f"<td>{_text(row.get('queue_total_before') or 0)} / {_text(row.get('queue_total_after') or 0)}</td>"
            f"<td>{_text(row.get('processed_job_count') or 0)} / {_text(row.get('completed_job_count') or 0)}</td>"
            f"<td>{_text(row.get('executed_check_count') or 0)} / {_text(row.get('changed_count') or 0)}</td>"
            "</tr>"
        )
        for row in rows
    )
    return (
        "<table><thead><tr><th>Cycle</th><th>Heartbeat</th><th>Mode</th><th>Queue B/A</th><th>Processed/Done</th><th>Checks/Changed</th></tr></thead>"
        f"<tbody>{body_rows}</tbody></table>"
    )


def _json_block(value: object) -> str:
    return json.dumps(value, indent=2)


def _archive_result_summary(row: dict[str, object]) -> str:
    parse_error = str(row.get("parse_error") or "").strip()
    if parse_error:
        return "parse-error"
    parts = ["ok" if bool(row.get("ok")) else "errors"]
    warning_count = int(row.get("warning_count") or 0)
    error_count = int(row.get("error_count") or 0)
    artifact_path_count = int(row.get("artifact_path_count") or 0)
    if warning_count > 0:
        parts.append(f"warn {warning_count}")
    if error_count > 0:
        parts.append(f"err {error_count}")
    if artifact_path_count > 0:
        parts.append(f"artifacts {artifact_path_count}")
    return ", ".join(parts)


def _cleanup_category_summary(categories: object) -> str:
    rows = dict(categories or {})
    parts: list[str] = []
    for name, payload in rows.items():
        values = dict(payload or {})
        removed_count = int(values.get("removed_count") or 0)
        candidate_count = int(values.get("candidate_count") or 0)
        if removed_count <= 0 and candidate_count <= 0:
            continue
        parts.append(f"{name}:{removed_count}/{candidate_count}")
    return ", ".join(parts) if parts else "none"


def _trend_width(value: int, max_value: int) -> float:
    normalized_max = max(1, int(max_value or 1))
    normalized_value = max(0, int(value or 0))
    return max(4.0 if normalized_value > 0 else 0.0, min(100.0, (normalized_value / normalized_max) * 100.0))


def _format_decimal(value: object) -> str:
    try:
        return f"{float(value or 0.0):.1f}"
    except (TypeError, ValueError):
        return "0.0"


def _watch_profile_decimal(value: object) -> str:
    try:
        numeric = float(value or 0.0)
    except (TypeError, ValueError):
        numeric = 0.0
    return "" if numeric <= 0.0 else f"{numeric:.1f}"


def _watch_profile_int(value: object) -> str:
    try:
        numeric = int(value or 0)
    except (TypeError, ValueError):
        numeric = 0
    return "" if numeric <= 0 else str(numeric)


def _monitor_source_actions(row: dict[str, object], *, return_to: str) -> str:
    case_id = str(row.get("case_id") or "").strip()
    watch_id = str(row.get("watch_id") or "").strip()
    if not case_id:
        return "<span class='muted'>Case required</span>"

    links = [
        f"<a href='/cases/{_url(case_id)}/watch-sources?watch_id={_url(watch_id)}'>Source JSON</a>" if watch_id else "",
        f"<a href='/cases/{_url(case_id)}/watchers?watch_id={_url(watch_id)}'>Watcher JSON</a>" if watch_id else "",
    ]
    forms: list[str] = []
    if watch_id:
        toggle_action = "disable" if bool(row.get("enabled", True)) else "enable"
        toggle_label = "Disable" if bool(row.get("enabled", True)) else "Enable"
        default_return_to = return_to or f"/cases/{case_id}/monitor-view"
        forms.append(
            "<form method='post' action='/cases/{case}/watch-sources'>"
            "<input type='hidden' name='watch_id' value='{watch_id}' />"
            "<input type='hidden' name='action' value='{action}' />"
            "<input type='hidden' name='return_to' value='{return_to}' />"
            "<button type='submit'>{label}</button>"
            "</form>".format(
                case=_url(case_id),
                watch_id=_attr(watch_id),
                action=_attr(toggle_action),
                return_to=_attr(default_return_to),
                label=_text(toggle_label),
            )
        )
        snooze_action = "resume" if bool(row.get("snoozed")) else "snooze"
        snooze_label = "Resume" if bool(row.get("snoozed")) else "Snooze 10m"
        forms.append(
            "<form method='post' action='/cases/{case}/watch-sources'>"
            "<input type='hidden' name='watch_id' value='{watch_id}' />"
            "<input type='hidden' name='action' value='{action}' />"
            "<input type='hidden' name='seconds' value='600' />"
            "<input type='hidden' name='return_to' value='{return_to}' />"
            "<button type='submit'>{label}</button>"
            "</form>".format(
                case=_url(case_id),
                watch_id=_attr(watch_id),
                action=_attr(snooze_action),
                return_to=_attr(default_return_to),
                label=_text(snooze_label),
            )
        )
        forms.append(
            "<form method='post' action='/cases/{case}/watch-sources'>"
            "<input type='hidden' name='watch_id' value='{watch_id}' />"
            "<input type='hidden' name='action' value='update' />"
            "<input type='hidden' name='return_to' value='{return_to}' />"
            "<label>Poll Seconds<input type='number' min='0' step='1' name='poll_interval_seconds' value='{poll}' /></label>"
            "<button type='submit'>Save Poll</button>"
            "</form>".format(
                case=_url(case_id),
                watch_id=_attr(watch_id),
                return_to=_attr(default_return_to),
                poll=_attr(int(float(row.get("poll_interval_seconds") or 0.0))),
            )
        )
        forms.append(
            "<form method='post' action='/cases/{case}/watch-sources'>"
            "<input type='hidden' name='watch_id' value='{watch_id}' />"
            "<input type='hidden' name='action' value='update' />"
            "<input type='hidden' name='return_to' value='{return_to}' />"
            "<label>Notes<input type='text' name='notes' value='{notes}' placeholder='Analyst note' /></label>"
            "<label>Tags<input type='text' name='tags' value='{tags}' placeholder='tag1, tag2' /></label>"
            "<button type='submit'>Save Meta</button>"
            "</form>".format(
                case=_url(case_id),
                watch_id=_attr(watch_id),
                return_to=_attr(default_return_to),
                notes=_attr(row.get("notes") or ""),
                tags=_attr(", ".join(list(row.get("tags") or []))),
            )
        )
        tuning_profile = dict(row.get("tuning_profile") or {})
        forms.append(
            "<form method='post' action='/cases/{case}/watch-sources'>"
            "<input type='hidden' name='watch_id' value='{watch_id}' />"
            "<input type='hidden' name='action' value='update' />"
            "<input type='hidden' name='return_to' value='{return_to}' />"
            "<label>Preset<input type='text' name='tuning_preset_name' value='{preset_name}' placeholder='source:file, source:log, source:pcap, source:system' /></label>"
            "<label>Churn Factor<input type='number' min='1' step='0.1' name='source_churn_spike_factor' value='{churn_factor}' placeholder='case default' /></label>"
            "<label>Min History<input type='number' min='1' step='1' name='forecast_min_history' value='{min_history}' placeholder='case default' /></label>"
            "<label>Suppress Alerts<input type='text' name='suppressed_alert_ids' value='{suppressed_alerts}' placeholder='source_churn_spike, failure_burst' /></label>"
            "<button type='submit'>Save Source Tuning</button>"
            "</form>".format(
                case=_url(case_id),
                watch_id=_attr(watch_id),
                return_to=_attr(default_return_to),
                preset_name=_attr(tuning_profile.get("preset_name") or ""),
                churn_factor=_attr(_watch_profile_decimal(tuning_profile.get("source_churn_spike_factor"))),
                min_history=_attr(_watch_profile_int(tuning_profile.get("forecast_min_history"))),
                suppressed_alerts=_attr(", ".join(list(tuning_profile.get("suppressed_alert_ids") or []))),
            )
        )
        forms.append(
            "<form method='post' action='/cases/{case}/watch-sources'>"
            "<input type='hidden' name='watch_id' value='{watch_id}' />"
            "<input type='hidden' name='action' value='update' />"
            "<input type='hidden' name='clear_tuning_profile' value='true' />"
            "<input type='hidden' name='return_to' value='{return_to}' />"
            "<button type='submit'>Clear Source Tuning</button>"
            "</form>".format(
                case=_url(case_id),
                watch_id=_attr(watch_id),
                return_to=_attr(default_return_to),
            )
        )
        if bool(row.get("suppressed")):
            forms.append(
                "<form method='post' action='/cases/{case}/watchers'>"
                "<input type='hidden' name='watch_id' value='{watch_id}' />"
                "<input type='hidden' name='action' value='clear_suppression' />"
                "<input type='hidden' name='return_to' value='{return_to}' />"
                "<button type='submit'>Clear Suppression</button>"
                "</form>".format(
                    case=_url(case_id),
                    watch_id=_attr(watch_id),
                    return_to=_attr(default_return_to),
                )
            )
            forms.append(
                "<form method='post' action='/cases/{case}/watchers'>"
                "<input type='hidden' name='watch_id' value='{watch_id}' />"
                "<input type='hidden' name='action' value='shorten_suppression' />"
                "<input type='hidden' name='seconds' value='60' />"
                "<input type='hidden' name='return_to' value='{return_to}' />"
                "<button type='submit'>Shorten To 60s</button>"
                "</form>".format(
                    case=_url(case_id),
                    watch_id=_attr(watch_id),
                    return_to=_attr(default_return_to),
                )
            )
    action_bits = [item for item in [*links, *forms] if item]
    if not action_bits:
        return "<span class='muted'>No actions</span>"
    return "<div class='action-stack'>" + "".join(action_bits) + "</div>"


def _record_label(row: dict[str, object]) -> str:
    for key in ("title", "value", "normalized_value", "locator", "id"):
        value = str(row.get(key) or "").strip()
        if value:
            return value
    return ""


def _query_suffix(**pairs: object) -> str:
    parts = []
    for key, value in pairs.items():
        text = str(value or "").strip()
        if not text:
            continue
        parts.append(f"{quote(key, safe='')}={quote(text, safe='')}")
    return f"?{'&'.join(parts)}" if parts else ""


def _url(value: object) -> str:
    return quote(str(value or ""), safe="")


def _text(value: object) -> str:
    return html.escape(str(value or ""))


def _attr(value: object) -> str:
    return html.escape(str(value or ""), quote=True)
