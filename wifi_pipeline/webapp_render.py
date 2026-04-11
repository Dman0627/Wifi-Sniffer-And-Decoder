from __future__ import annotations

import html
import json
import time
from typing import Dict

from .status_language import status_pill_class
from .wifi_discovery import AUTO_TARGET_VALUE, MANUAL_TARGET_VALUE


def _html_text(value: object) -> str:
    return html.escape(str(value or ""))


def _shorten(value: object, width: int = 96) -> str:
    text = str(value or "")
    if len(text) <= width:
        return text
    return text[: width - 3] + "..."


def _as_list(value: object) -> list:
    if value is None or (isinstance(value, str) and value == ""):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _as_dict(value: object) -> Dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


def _dict_items(value: object) -> list[Dict[str, object]]:
    items: list[Dict[str, object]] = []
    for item in _as_list(value):
        item_dict = _as_dict(item)
        if item_dict:
            items.append(item_dict)
    return items


def _first_text(value: object, default: str = "(none)") -> str:
    for item in _as_list(value):
        text = str(item or "").strip()
        if text:
            return text
    return default


def _log_field(entry: object, name: str, default: object = "") -> object:
    if isinstance(entry, dict):
        return entry.get(name, default)
    return getattr(entry, name, default)


def _render_note_list(items: object, *, empty: str, css_class: str = "muted") -> str:
    values = [str(item or "").strip() for item in _as_list(items) if str(item or "").strip()]
    if not values:
        return f"<p class='{css_class}'>{_html_text(empty)}</p>"
    rows = "".join(f"<li>{_html_text(_shorten(value, 140))}</li>" for value in values)
    return f"<ul class='note-list {css_class}'>{rows}</ul>"


def _render_machine_line(label: str, value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return f"<p class='muted'>{_html_text(label)}: {_html_text(_shorten(text, 140))}</p>"


def _render_requirement_rows(requirements: object) -> str:
    rows = []
    for requirement in _as_list(requirements)[:6]:
        item = _as_dict(requirement)
        status = str(item.get("status") or "blocked")
        rows.append(
            "<div class='requirement'>"
            f"<span class='pill {status_pill_class(status)}'>{_html_text(status)}</span>"
            "<div>"
            f"<strong>{_html_text(item.get('label'))}</strong>"
            f"<code>{_html_text(_shorten(item.get('value'), 72))}</code>"
            f"<p class='muted'>{_html_text(_shorten(item.get('detail'), 110))}</p>"
            "</div>"
            "</div>"
        )
    return "".join(rows) or "<p class='muted'>No requirements listed.</p>"


def _render_tool_cards(tools: object) -> str:
    cards = []
    for tool in _as_list(tools):
        item = _as_dict(tool)
        if not item:
            continue
        status = str(item.get("status") or "blocked")
        action = str(item.get("action") or "").strip()
        action_line = f"<p class='muted'>Action: <code>{_html_text(action)}</code></p>" if action else ""
        cards.append(
            "<article class='tool-card'>"
            "<header>"
            "<div>"
            f"<strong>{_html_text(item.get('label'))}</strong>"
            f"<p class='muted'>{_html_text(item.get('category') or 'Tool')}</p>"
            "</div>"
            f"<span class='pill {status_pill_class(status)}'>{_html_text(status)}</span>"
            "</header>"
            f"<p>{_html_text(_shorten(item.get('summary'), 150))}</p>"
            f"{_render_requirement_rows(item.get('requirements'))}"
            f"{action_line}"
            f"<p class='muted'>Next: {_html_text(_shorten(item.get('next_step'), 140))}</p>"
            "</article>"
        )
    return "".join(cards) or "<p class='muted'>No tool catalog is available yet.</p>"


def _render_device_cards(devices: object) -> str:
    cards = []
    for device in _as_list(devices):
        item = _as_dict(device)
        if not item:
            continue
        status = str(item.get("status") or "blocked")
        details = _render_note_list(item.get("details"), empty="No extra device details are available.")
        cards.append(
            "<article class='device-card'>"
            "<header>"
            "<div>"
            f"<strong>{_html_text(item.get('name'))}</strong>"
            f"<p class='muted'>{_html_text(item.get('scope'))}</p>"
            "</div>"
            f"<span class='pill {status_pill_class(status)}'>{_html_text(status)}</span>"
            "</header>"
            f"<p>{_html_text(item.get('role'))}</p>"
            f"<p class='muted'>{_html_text(_shorten(item.get('summary'), 140))}</p>"
            f"{details}"
            "</article>"
        )
    return "".join(cards) or "<p class='muted'>No devices are available yet.</p>"


def _wifi_target_name(target: Dict[str, object]) -> str:
    return str(target.get("ssid") or "").strip() or "(hidden network)"


def _wifi_target_value(target: Dict[str, object]) -> str:
    payload = {
        "ssid": str(target.get("ssid") or ""),
        "bssid": str(target.get("bssid") or ""),
        "channel": target.get("channel") or "",
        "signal": target.get("signal") or "",
        "signal_label": str(target.get("signal_label") or ""),
        "security": str(target.get("security") or ""),
        "source": str(target.get("source") or ""),
        "connected": bool(target.get("connected")),
    }
    return json.dumps(payload, separators=(",", ":"))


def _same_wifi_target(left: Dict[str, object], right: Dict[str, object]) -> bool:
    left_bssid = str(left.get("bssid") or "").strip().lower()
    right_bssid = str(right.get("bssid") or "").strip().lower()
    if left_bssid and right_bssid:
        return left_bssid == right_bssid
    return (
        str(left.get("ssid") or "").strip().lower(),
        str(left.get("channel") or "").strip(),
    ) == (
        str(right.get("ssid") or "").strip().lower(),
        str(right.get("channel") or "").strip(),
    )


def _wifi_target_label(target: Dict[str, object]) -> str:
    pieces = [_wifi_target_name(target)]
    channel = str(target.get("channel") or "").strip()
    signal = str(target.get("signal_label") or target.get("signal") or "").strip()
    bssid = str(target.get("bssid") or "").strip()
    if channel:
        pieces.append(f"ch {channel}")
    if signal:
        pieces.append(signal)
    if bssid:
        pieces.append(bssid)
    return " | ".join(pieces)


def _render_wifi_target_cards(targets: object, auto_target: Dict[str, object]) -> str:
    cards = []
    for target in _dict_items(targets)[:12]:
        connected = bool(target.get("connected"))
        recommended = _same_wifi_target(target, auto_target) if auto_target else False
        status = "ready" if connected or recommended else "limited"
        badges = []
        if connected:
            badges.append("<span class='pill ready'>connected</span>")
        if recommended:
            badges.append("<span class='pill ok'>auto pick</span>")
        badges.append(f"<span class='pill {status_pill_class(status)}'>{_html_text(status)}</span>")
        detail_parts = [
            f"BSSID: {target.get('bssid') or '(not broadcast)'}",
            f"Channel: {target.get('channel') or '(unknown)'}",
            f"Signal: {target.get('signal_label') or target.get('signal') or '(unknown)'}",
            f"Security: {target.get('security') or 'unknown'}",
            f"Source: {target.get('source') or 'scan'}",
        ]
        details = "".join(f"<li>{_html_text(part)}</li>" for part in detail_parts)
        cards.append(
            "<article class='wifi-target-card'>"
            "<header>"
            "<div>"
            f"<strong>{_html_text(_wifi_target_name(target))}</strong>"
            f"<p class='muted'>{_html_text(_shorten(target.get('bssid') or 'SSID-only discovery', 90))}</p>"
            "</div>"
            f"<div class='mini-badges'>{''.join(badges)}</div>"
            "</header>"
            f"<ul class='note-list muted'>{details}</ul>"
            "</article>"
        )
    if cards:
        return "".join(cards)
    return (
        "<article class='wifi-target-card empty'>"
        "<strong>No SSIDs discovered yet</strong>"
        "<p class='muted'>Auto mode will keep trying when the dashboard refreshes or an auto Wi-Fi action runs. "
        "Manual ESSID/BSSID/channel overrides still work.</p>"
        "</article>"
    )


def render_dashboard_html(snapshot: Dict[str, object], *, capture_path: str) -> str:
    config = _as_dict(snapshot.get("config"))
    bundle = _as_dict(snapshot.get("bundle"))
    detection = _as_dict(bundle.get("detection"))
    analysis = _as_dict(bundle.get("analysis"))
    status_bundle = _as_dict(bundle.get("status_bundle"))
    candidate_rows = _as_list(bundle.get("candidate_rows"))
    corpus_entries = _as_list(bundle.get("corpus_entries"))
    corpus_status = _as_dict(bundle.get("corpus_status"))
    logs = _as_list(snapshot.get("logs"))
    interfaces = _as_list(bundle.get("interfaces"))
    artifacts = _as_list(bundle.get("artifacts"))
    workflow_rows = _as_list(status_bundle.get("workflow"))
    machine_summary = _as_dict(status_bundle.get("machine_summary"))
    machine_items = _as_list(machine_summary.get("items"))
    operator_inventory = _as_dict(bundle.get("operator_inventory"))
    selection_status = _as_dict(status_bundle.get("selection"))
    replay_status = _as_dict(status_bundle.get("replay"))
    wpa_status = _as_dict(status_bundle.get("wpa"))
    busy = bool(snapshot.get("busy"))
    current_action = str(snapshot.get("current_action") or "")
    last_message = str(snapshot.get("last_message") or "")
    last_status = str(snapshot.get("last_status") or "idle")
    selected = _as_dict(detection.get("selected_candidate_stream"))
    selected_analysis = _as_dict(analysis.get("selected_candidate_stream"))
    analysis_corpus = _as_dict(analysis.get("corpus"))
    best_match = _as_dict(analysis_corpus.get("best_match"))
    replay_confidence = _as_dict(replay_status.get("confidence"))

    workflow_cards = []
    for row in _dict_items(workflow_rows):
        status = str(row.get("status") or "blocked")
        reasons = _render_note_list(row.get("reasons"), empty="", css_class="muted") if _as_list(row.get("reasons")) else ""
        next_steps = (
            _render_note_list(row.get("next_steps"), empty="", css_class="muted")
            if _as_list(row.get("next_steps"))
            else ""
        )
        workflow_cards.append(
            "<article class='status-card'>"
            f"<header><strong>{_html_text(row.get('area'))}</strong> "
            f"<span class='pill {status_pill_class(status)}'>{_html_text(status)}</span></header>"
            f"<p>{_html_text(row.get('summary') or row.get('detail') or '')}</p>"
            f"{reasons}"
            f"{next_steps}"
            "</article>"
        )
    workflow_cards_html = "".join(workflow_cards) or "<p class='muted'>No capability rows are available yet.</p>"

    machine_cards = []
    for item in _dict_items(machine_items):
        status = str(item.get("status") or "blocked")
        machine_cards.append(
            "<article class='status-card'>"
            f"<header><strong>{_html_text(item.get('label'))}</strong> "
            f"<span class='pill {status_pill_class(status)}'>{_html_text(status)}</span></header>"
            f"<p>{_html_text(item.get('summary') or '')}</p>"
            f"{_render_machine_line('Note', item.get('reason'))}"
            f"{_render_machine_line('Next', item.get('next_step'))}"
            "</article>"
        )
    machine_cards_html = "".join(machine_cards) or "<p class='muted'>No machine summary is available yet.</p>"

    tool_cards_html = _render_tool_cards(operator_inventory.get("tools"))
    device_cards_html = _render_device_cards(operator_inventory.get("devices"))
    wifi_targets = _dict_items(bundle.get("wifi_targets"))
    wifi_auto_target = _as_dict(bundle.get("wifi_auto_target"))
    wifi_target_mode = str(
        bundle.get("wifi_target_mode")
        or config.get("wifi_target_mode")
        or ("selected" if config.get("ap_essid") or config.get("ap_bssid") else "auto")
    )
    config_wifi_target = {
        "ssid": str(config.get("ap_essid") or ""),
        "bssid": str(config.get("ap_bssid") or ""),
        "channel": str(config.get("ap_channel") or ""),
    }

    log_blocks = []
    for entry in reversed(logs[-6:]):
        if not isinstance(entry, dict) and not any(
            hasattr(entry, name) for name in ("timestamp", "action", "status", "message", "output")
        ):
            continue
        raw_timestamp = _log_field(entry, "timestamp", time.time())
        try:
            timestamp_value = float(raw_timestamp)
        except (TypeError, ValueError):
            timestamp_value = time.time()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_value))
        status = str(_log_field(entry, "status", "unknown") or "unknown")
        action = str(_log_field(entry, "action", "unknown") or "unknown")
        message = str(_log_field(entry, "message", "") or "")
        output = str(_log_field(entry, "output", "") or "")
        log_blocks.append(
            f"<article class='log-card'>"
            f"<header><strong>{_html_text(timestamp)}</strong> <span class='pill {status_pill_class(status)}'>{_html_text(status)}</span> "
            f"<span class='muted'>{_html_text(action)}</span></header>"
            f"<p>{_html_text(message)}</p>"
            f"<pre>{_html_text(output.strip() or '(no terminal output)')}</pre>"
            f"</article>"
        )

    interface_options = []
    for item in interfaces:
        try:
            _number, name, description = item
        except (TypeError, ValueError):
            continue
        interface_options.append(
            f"<option value='{_html_text(name)}'>{_html_text(description or name)}</option>"
        )

    auto_option_label = (
        f"Auto (current/strongest): {_wifi_target_label(wifi_auto_target)}"
        if wifi_auto_target
        else "Auto (scan and choose when available)"
    )
    auto_attrs = ""
    if wifi_auto_target:
        auto_attrs = (
            f" data-ssid='{_html_text(wifi_auto_target.get('ssid'))}'"
            f" data-bssid='{_html_text(wifi_auto_target.get('bssid'))}'"
            f" data-channel='{_html_text(wifi_auto_target.get('channel'))}'"
        )
    wifi_target_options = [
        f"<option value='{AUTO_TARGET_VALUE}' {'selected' if wifi_target_mode == 'auto' else ''}{auto_attrs}>{_html_text(auto_option_label)}</option>",
        f"<option value='{MANUAL_TARGET_VALUE}' {'selected' if wifi_target_mode == 'manual' else ''}>Manual / keep override fields below</option>",
    ]
    wifi_essid_options = []
    wifi_bssid_options = []
    seen_essids = set()
    seen_bssids = set()
    for target in wifi_targets:
        option_value = _wifi_target_value(target)
        selected_attr = "selected" if wifi_target_mode == "selected" and _same_wifi_target(target, config_wifi_target) else ""
        wifi_target_options.append(
            f"<option value='{_html_text(option_value)}' {selected_attr}"
            f" data-ssid='{_html_text(target.get('ssid'))}'"
            f" data-bssid='{_html_text(target.get('bssid'))}'"
            f" data-channel='{_html_text(target.get('channel'))}'>"
            f"{_html_text(_wifi_target_label(target))}</option>"
        )
        ssid = str(target.get("ssid") or "").strip()
        bssid = str(target.get("bssid") or "").strip()
        if ssid and ssid.lower() not in seen_essids:
            seen_essids.add(ssid.lower())
            wifi_essid_options.append(f"<option value='{_html_text(ssid)}'></option>")
        if bssid and bssid.lower() not in seen_bssids:
            seen_bssids.add(bssid.lower())
            wifi_bssid_options.append(f"<option value='{_html_text(bssid)}'></option>")

    artifact_rows = []
    for item in _dict_items(artifacts):
        exists = bool(item.get("exists"))
        artifact_rows.append(
            "<div class='artifact'>"
            f"<strong>{_html_text(item.get('label') or 'Artifact')}</strong>"
            f"<span class='pill {'ok' if exists else 'missing'}'>{'ready' if exists else 'missing'}</span>"
            f"<code>{_html_text(_shorten(item.get('path'), 88))}</code>"
            "</div>"
        )
    artifact_cards = "".join(artifact_rows)

    candidate_rows = _dict_items(candidate_rows)
    candidate_rows_html = "".join(
        (
            "<tr>"
            f"<td>{_html_text(row.get('candidate_class'))}</td>"
            f"<td>{_html_text(row.get('score'))}</td>"
            f"<td>{_html_text(_shorten(row.get('stream_id'), 72))}</td>"
            f"<td>{_html_text(row.get('byte_count'))}</td>"
            f"<td><form method='post' action='/pin'><input type='hidden' name='stream_id' value='{_html_text(row.get('stream_id'))}' /><button type='submit'>Pin</button></form></td>"
            "</tr>"
        )
        for row in candidate_rows[:10]
    ) or "<tr><td colspan='5'>No candidate streams yet.</td></tr>"

    corpus_rows_html = "".join(
        (
            "<tr>"
            f"<td>{_html_text(entry.get('entry_id'))}</td>"
            f"<td>{_html_text(entry.get('candidate_class'))}</td>"
            f"<td>{_html_text(entry.get('dominant_unit_type'))}</td>"
            f"<td>{'yes' if entry.get('candidate_material_available') else 'no'}</td>"
            f"<td>{_html_text(_shorten(entry.get('stream_id'), 60))}</td>"
            "</tr>"
        )
        for entry in _dict_items(corpus_entries)
    ) or "<tr><td colspan='5'>No archived candidates yet.</td></tr>"

    hypotheses = _dict_items(analysis.get("hypotheses"))
    ciphertext_observations = _as_dict(analysis.get("ciphertext_observations"))
    latest_corpus_entry = _as_dict(corpus_status.get("latest_entry"))

    auto_refresh = "<meta http-equiv='refresh' content='4'>" if busy else ""
    return _dashboard_template(
        auto_refresh=auto_refresh,
        busy=busy,
        current_action=current_action,
        last_message=last_message,
        last_status=last_status,
        config_path=str(snapshot.get("config_path") or ""),
        capture_path=capture_path,
        interface_options="".join(interface_options),
        artifact_cards=artifact_cards,
        machine_summary_headline=str(machine_summary.get("headline") or ""),
        machine_cards_html=machine_cards_html,
        operator_headline=str(operator_inventory.get("headline") or "Tool and device inventory will populate as the dashboard gathers context."),
        tool_cards_html=tool_cards_html,
        device_cards_html=device_cards_html,
        wifi_target_cards_html=_render_wifi_target_cards(wifi_targets, wifi_auto_target),
        wifi_target_options="".join(wifi_target_options),
        wifi_essid_options="".join(wifi_essid_options),
        wifi_bssid_options="".join(wifi_bssid_options),
        wifi_target_mode=wifi_target_mode,
        candidate_rows_html=candidate_rows_html,
        corpus_rows_html=corpus_rows_html,
        log_blocks="".join(log_blocks) or "<p class='muted'>No actions have been run from the dashboard yet.</p>",
        interface=str(config.get("interface") or ""),
        protocol=str(config.get("protocol") or "udp"),
        video_port=str(config.get("video_port") or ""),
        capture_duration=str(config.get("capture_duration") or ""),
        output_dir=str(config.get("output_dir") or ""),
        target_macs=",".join(str(item) for item in _as_list(config.get("target_macs"))),
        ap_essid=str(config.get("ap_essid") or ""),
        ap_bssid=str(config.get("ap_bssid") or ""),
        ap_channel=str(config.get("ap_channel") or "6"),
        monitor_method=str(config.get("monitor_method") or "airodump"),
        wordlist_path=str(config.get("wordlist_path") or ""),
        deauth_count=str(config.get("deauth_count") or "10"),
        wpa_password_env=str(config.get("wpa_password_env") or ""),
        remote_host=str(config.get("remote_host") or ""),
        remote_path=str(config.get("remote_path") or ""),
        remote_port=str(config.get("remote_port") or "22"),
        remote_identity=str(config.get("remote_identity") or ""),
        remote_interface=str(config.get("remote_interface") or ""),
        remote_install_mode=str(config.get("remote_install_mode") or "auto"),
        remote_install_profile=str(config.get("remote_install_profile") or "appliance"),
        remote_health_port=str(config.get("remote_health_port") or "8741"),
        remote_dest_dir=str(config.get("remote_dest_dir") or ""),
        remote_poll_interval=str(config.get("remote_poll_interval") or "8"),
        custom_header_size=str(config.get("custom_header_size") or ""),
        custom_magic_hex=str(config.get("custom_magic_hex") or ""),
        preferred_stream_id=str(config.get("preferred_stream_id") or ""),
        min_candidate_bytes=str(config.get("min_candidate_bytes") or ""),
        replay_format_hint=str(config.get("replay_format_hint") or ""),
        playback_mode=str(config.get("playback_mode") or "both"),
        jitter_buffer_packets=str(config.get("jitter_buffer_packets") or ""),
        corpus_review_threshold=str(config.get("corpus_review_threshold") or ""),
        corpus_auto_reuse_threshold=str(config.get("corpus_auto_reuse_threshold") or ""),
        detection_stream=_shorten(selected.get("stream_id") or "(none)", 88),
        detection_class=str(selected.get("candidate_class") or "(none)"),
        detection_score=str(selected.get("score") or "?"),
        analysis_stream=_shorten(selected_analysis.get("stream_id") or "(none)", 88),
        top_hypothesis=str(hypotheses[0].get("name") if hypotheses else "(none)"),
        best_match_id=str(best_match.get("entry_id") or "(none)"),
        best_match_similarity=str(best_match.get("similarity") or ""),
        corpus_entry_count=str(corpus_status.get("entry_count") or 0),
        corpus_material_count=str(corpus_status.get("candidate_material_count") or 0),
        corpus_latest=str(latest_corpus_entry.get("entry_id") or "(none)"),
        corpus_reused="yes" if analysis_corpus.get("reused_candidate_material") else "no",
        average_entropy=str(detection.get("average_entropy") or "?"),
        chi_squared=str(ciphertext_observations.get("chi_squared") or "?"),
        total_units=str(analysis.get("total_units") or 0),
        recommendation=_shorten(_first_text(analysis.get("recommendations")), 90),
        selection_status=str(selection_status.get("status") or "blocked"),
        selection_status_class=status_pill_class(str(selection_status.get("status") or "blocked")),
        selection_summary=_shorten(selection_status.get("summary") or "Run analyze to evaluate replay readiness.", 120),
        selection_decode_level=str(selection_status.get("decode_level") or "heuristic"),
        selection_replay_level=str(selection_status.get("replay_level") or "unsupported"),
        selection_unit_type=str(selection_status.get("dominant_unit_type") or "opaque_chunk"),
        selection_signal_strength=str(selection_status.get("signal_strength") or "unknown"),
        selection_notes_html=_render_note_list(
            selection_status.get("notes"),
            empty="No blockers or caveats are recorded for the current selection.",
        ),
        selection_next_step=_shorten(_first_text(selection_status.get("next_steps")), 120),
        replay_status=str(replay_status.get("status") or "blocked"),
        replay_status_class=status_pill_class(str(replay_status.get("status") or "blocked")),
        replay_summary=_shorten(replay_status.get("summary") or "Run analyze to evaluate replay readiness.", 120),
        replay_decode_level=str(replay_status.get("decode_level") or "heuristic"),
        replay_replay_level=str(replay_status.get("replay_level") or "unsupported"),
        replay_unit_type=str(replay_status.get("dominant_unit_type") or "opaque_chunk"),
        replay_confidence_band=str(replay_confidence.get("confidence_band") or "low"),
        replay_confidence_label=str(replay_confidence.get("confidence_label") or "unknown"),
        replay_confidence_score=str(replay_confidence.get("confidence_score") or "?"),
        replay_delivery_mode=str(replay_confidence.get("delivery_mode") or "unknown"),
        replay_reasons_html=_render_note_list(
            replay_status.get("reasons"),
            empty="No replay blockers or caveats are recorded yet.",
        ),
        replay_next_steps_html=_render_note_list(
            replay_status.get("next_steps"),
            empty="No replay next step is recorded yet.",
        ),
        wpa_status=str(wpa_status.get("status") or "ready"),
        wpa_status_class=status_pill_class(str(wpa_status.get("status") or "ready")),
        wpa_summary=_shorten(wpa_status.get("summary") or "WPA feasibility is not relevant to the current workflow.", 120),
        wpa_state=str(wpa_status.get("state") or "not_applicable"),
        wpa_artifact=str(wpa_status.get("handshake_artifact") or "(none)"),
        wpa_reasons_html=_render_note_list(
            wpa_status.get("reasons"),
            empty="No WPA blockers or caveats are recorded yet.",
        ),
        wpa_next_steps_html=_render_note_list(
            wpa_status.get("next_steps"),
            empty="No WPA next step is recorded yet.",
        ),
        workflow_cards_html=workflow_cards_html,
    )


def _dashboard_template(**values: object) -> str:
    def val(key: str) -> str:
        return _html_text(values.get(key, ""))

    auto_refresh = str(values.get("auto_refresh", ""))
    last_status_class = status_pill_class(str(values.get("last_status") or "idle"))
    current_action_markup = (
        f"<span class='muted'>Current action: {val('current_action')}</span>"
        if values.get("busy")
        else ""
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {auto_refresh}
  <title>WiFi Stream Dashboard</title>
  <style>
    :root {{
      --bg: #0f1720;
      --panel: #16212d;
      --panel-2: #1d2a38;
      --line: #284052;
      --text: #eef4f7;
      --muted: #9cb2bf;
      --accent: #69d2b0;
      --accent-2: #9ad7ff;
      --warn: #f3c969;
      --bad: #ff8f7d;
      --good: #69d2b0;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", "Trebuchet MS", sans-serif;
      background:
        radial-gradient(circle at top right, rgba(105, 210, 176, 0.14), transparent 32%),
        radial-gradient(circle at top left, rgba(154, 215, 255, 0.12), transparent 28%),
        linear-gradient(180deg, #0b1118 0%, var(--bg) 100%);
      color: var(--text);
    }}
    .shell {{
      width: min(1300px, calc(100vw - 32px));
      margin: 24px auto 40px;
    }}
    .hero {{
      display: grid;
      gap: 12px;
      padding: 22px 24px;
      background: linear-gradient(135deg, rgba(22,33,45,0.96), rgba(17,25,34,0.96));
      border: 1px solid var(--line);
      border-radius: 20px;
      box-shadow: 0 24px 70px rgba(0, 0, 0, 0.28);
    }}
    h1, h2, h3, p {{ margin: 0; }}
    h1 {{
      font-size: clamp(28px, 3vw, 40px);
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }}
    .hero p {{ color: var(--muted); max-width: 920px; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 18px;
      margin-top: 18px;
    }}
    .panel {{
      background: linear-gradient(180deg, rgba(29,42,56,0.98), rgba(18,27,36,0.98));
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 18px;
      box-shadow: 0 16px 40px rgba(0, 0, 0, 0.18);
    }}
    .panel.wide {{ grid-column: 1 / -1; }}
    .status-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      margin-top: 10px;
    }}
    .status-stack {{
      display: grid;
      gap: 12px;
      margin-top: 12px;
    }}
    .status-card {{
      display: grid;
      gap: 10px;
      padding: 14px;
      border-radius: 14px;
      background: rgba(8, 12, 17, 0.52);
      border: 1px solid rgba(255,255,255,0.06);
    }}
    .status-card header {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }}
    .operator-layout {{
      display: grid;
      grid-template-columns: minmax(0, 2fr) minmax(280px, 1fr);
      gap: 16px;
      margin-top: 14px;
    }}
    .tool-grid, .device-grid {{
      display: grid;
      gap: 12px;
      margin-top: 10px;
      max-height: 640px;
      overflow: auto;
      padding-right: 4px;
    }}
    .tool-grid {{
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    }}
    .tool-card, .device-card {{
      display: grid;
      gap: 10px;
      padding: 14px;
      border-radius: 16px;
      background:
        linear-gradient(160deg, rgba(105,210,176,0.08), transparent 42%),
        rgba(8, 12, 17, 0.52);
      border: 1px solid rgba(255,255,255,0.07);
    }}
    .tool-card header, .device-card header, .requirement {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: flex-start;
      justify-content: space-between;
    }}
    .requirement {{
      justify-content: flex-start;
      padding: 9px;
      border-radius: 12px;
      background: rgba(255,255,255,0.035);
    }}
    .requirement > div {{
      min-width: 0;
      flex: 1 1 180px;
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      background: rgba(255,255,255,0.08);
      border: 1px solid rgba(255,255,255,0.08);
    }}
    .pill.ok {{ color: var(--good); border-color: rgba(105,210,176,0.45); }}
    .pill.running {{ color: var(--accent-2); border-color: rgba(154,215,255,0.45); }}
    .pill.warning {{ color: var(--warn); border-color: rgba(243,201,105,0.45); }}
    .pill.error, .pill.missing {{ color: var(--bad); border-color: rgba(255,143,125,0.45); }}
    .muted {{ color: var(--muted); }}
    .note-list {{
      margin: 0;
      padding-left: 18px;
      display: grid;
      gap: 6px;
    }}
    .artifact-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      margin-top: 12px;
    }}
    .artifact {{
      display: grid;
      gap: 8px;
      padding: 12px;
      border-radius: 14px;
      background: rgba(10, 15, 21, 0.28);
      border: 1px solid rgba(255,255,255,0.06);
    }}
    form {{
      display: grid;
      gap: 12px;
    }}
    .field-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
    }}
    label {{
      display: grid;
      gap: 6px;
      font-size: 13px;
      color: var(--muted);
    }}
    input, select, textarea, button {{
      width: 100%;
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 12px;
      padding: 10px 12px;
      background: rgba(8, 12, 17, 0.62);
      color: var(--text);
      font: inherit;
    }}
    textarea {{ min-height: 88px; resize: vertical; }}
    button {{
      cursor: pointer;
      font-weight: 600;
      background: linear-gradient(135deg, rgba(105,210,176,0.22), rgba(154,215,255,0.18));
      border-color: rgba(105,210,176,0.35);
    }}
    button:hover {{ filter: brightness(1.06); }}
    .button-row {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 10px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
      font-size: 14px;
    }}
    th, td {{
      text-align: left;
      padding: 10px 8px;
      border-bottom: 1px solid rgba(255,255,255,0.08);
      vertical-align: top;
    }}
    code, pre {{
      font-family: "Cascadia Code", "Consolas", monospace;
    }}
    code {{ display: block; color: var(--muted); }}
    pre {{
      margin: 0;
      padding: 12px;
      border-radius: 12px;
      background: rgba(3, 6, 10, 0.72);
      overflow: auto;
      max-height: 240px;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .links {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 12px;
    }}
    .links a {{
      color: var(--accent-2);
      text-decoration: none;
    }}
    .log-stack {{
      display: grid;
      gap: 12px;
      margin-top: 12px;
    }}
    .log-card {{
      display: grid;
      gap: 10px;
      padding: 14px;
      border-radius: 14px;
      background: rgba(8, 12, 17, 0.52);
      border: 1px solid rgba(255,255,255,0.06);
    }}
    .log-card header {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }}
    @media (max-width: 860px) {{
      .operator-layout {{ grid-template-columns: 1fr; }}
    }}

    :root {{
      --canvas: #081014;
      --canvas-2: #101b1f;
      --card: rgba(18, 28, 31, 0.82);
      --card-strong: rgba(25, 38, 41, 0.94);
      --stroke: rgba(178, 226, 209, 0.14);
      --stroke-strong: rgba(178, 226, 209, 0.26);
      --text: #f2f0e8;
      --muted: #9daea6;
      --accent: #b7f36b;
      --accent-2: #65d5c6;
      --amber: #f0bf55;
      --danger: #ff7868;
      --shadow: 0 24px 90px rgba(0, 0, 0, 0.38);
    }}
    html {{
      scroll-behavior: smooth;
    }}
    body {{
      min-height: 100vh;
      font-family: "Bahnschrift", "Aptos Display", "Segoe UI Variable", sans-serif;
      background:
        radial-gradient(circle at 12% -10%, rgba(183, 243, 107, 0.22), transparent 30%),
        radial-gradient(circle at 92% 0%, rgba(101, 213, 198, 0.18), transparent 34%),
        linear-gradient(90deg, rgba(255,255,255,0.035) 1px, transparent 1px),
        linear-gradient(180deg, rgba(255,255,255,0.026) 1px, transparent 1px),
        linear-gradient(155deg, #070b0e 0%, var(--canvas) 42%, #11150f 100%);
      background-size: auto, auto, 44px 44px, 44px 44px, auto;
      color: var(--text);
    }}
    body::before {{
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background:
        linear-gradient(120deg, transparent 0 42%, rgba(183, 243, 107, 0.05) 42% 43%, transparent 43% 100%),
        radial-gradient(circle at 50% 120%, rgba(240, 191, 85, 0.1), transparent 38%);
      mix-blend-mode: screen;
    }}
    .shell {{
      width: min(1480px, calc(100vw - 28px));
      margin: 18px auto 42px;
      position: relative;
      z-index: 1;
    }}
    .hero {{
      grid-template-columns: minmax(0, 1.35fr) minmax(280px, 0.65fr);
      gap: 22px;
      padding: clamp(22px, 3vw, 36px);
      overflow: hidden;
      position: relative;
      background:
        linear-gradient(135deg, rgba(22, 34, 31, 0.96), rgba(9, 14, 17, 0.96)),
        radial-gradient(circle at top right, rgba(183, 243, 107, 0.24), transparent 38%);
      border-color: var(--stroke-strong);
      border-radius: 28px;
      box-shadow: var(--shadow);
    }}
    .hero::after {{
      content: "";
      position: absolute;
      width: 280px;
      height: 280px;
      right: -84px;
      top: -96px;
      border-radius: 999px;
      border: 1px solid rgba(183, 243, 107, 0.24);
      background: radial-gradient(circle, rgba(183, 243, 107, 0.12), transparent 62%);
    }}
    .hero-main, .hero-card {{
      position: relative;
      z-index: 1;
    }}
    .eyebrow {{
      display: inline-flex;
      width: fit-content;
      margin-bottom: 12px;
      padding: 6px 10px;
      border-radius: 999px;
      color: var(--accent);
      background: rgba(183, 243, 107, 0.08);
      border: 1px solid rgba(183, 243, 107, 0.22);
      font-size: 12px;
      letter-spacing: 0.16em;
      text-transform: uppercase;
    }}
    h1 {{
      max-width: 880px;
      font-size: clamp(38px, 5vw, 72px);
      line-height: 0.92;
      letter-spacing: -0.055em;
      text-transform: none;
    }}
    h2 {{
      font-size: clamp(20px, 2vw, 30px);
      letter-spacing: -0.03em;
    }}
    h3 {{
      font-size: 15px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--accent-2);
    }}
    .hero p {{
      max-width: 760px;
      margin-top: 14px;
      color: #bac9c0;
      font-size: clamp(15px, 1.4vw, 18px);
      line-height: 1.55;
    }}
    .hero-card {{
      display: grid;
      align-content: start;
      gap: 14px;
      padding: 18px;
      border-radius: 22px;
      background: rgba(5, 9, 11, 0.5);
      border: 1px solid rgba(255,255,255,0.1);
      backdrop-filter: blur(14px);
    }}
    .hero-card strong {{
      font-size: 13px;
      color: var(--muted);
      letter-spacing: 0.12em;
      text-transform: uppercase;
    }}
    .hero-metric {{
      display: grid;
      gap: 4px;
      padding: 12px;
      border-radius: 16px;
      background: rgba(255,255,255,0.045);
      border: 1px solid rgba(255,255,255,0.06);
    }}
    .hero-metric span {{
      color: var(--muted);
      font-size: 12px;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }}
    .hero-metric b {{
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-size: 15px;
    }}
    .status-row {{
      gap: 12px;
      margin-top: 18px;
    }}
    .nav-rail {{
      position: sticky;
      top: 10px;
      z-index: 5;
      display: flex;
      gap: 8px;
      overflow-x: auto;
      margin: 14px 0 18px;
      padding: 8px;
      border-radius: 18px;
      background: rgba(8, 14, 16, 0.78);
      border: 1px solid var(--stroke);
      backdrop-filter: blur(16px);
      box-shadow: 0 12px 36px rgba(0,0,0,0.22);
    }}
    .nav-rail a {{
      flex: 0 0 auto;
      padding: 9px 12px;
      color: var(--text);
      text-decoration: none;
      border-radius: 999px;
      border: 1px solid transparent;
      font-size: 13px;
    }}
    .nav-rail a:hover {{
      color: var(--accent);
      background: rgba(183, 243, 107, 0.08);
      border-color: rgba(183, 243, 107, 0.18);
    }}
    .grid {{
      grid-template-columns: repeat(12, minmax(0, 1fr));
      gap: 16px;
      margin-top: 0;
    }}
    .panel {{
      grid-column: span 4;
      position: relative;
      scroll-margin-top: 86px;
      overflow: hidden;
      padding: clamp(16px, 2vw, 22px);
      border-radius: 24px;
      background:
        linear-gradient(180deg, rgba(255,255,255,0.05), transparent 42%),
        var(--card);
      border: 1px solid var(--stroke);
      box-shadow: 0 16px 48px rgba(0,0,0,0.24);
    }}
    .panel::before {{
      content: "";
      position: absolute;
      inset: 0 0 auto;
      height: 3px;
      background: linear-gradient(90deg, var(--accent), var(--accent-2), transparent);
      opacity: 0.55;
    }}
    .panel.wide {{
      grid-column: 1 / -1;
    }}
    .panel.actions {{
      grid-column: span 8;
    }}
    .panel.artifacts, .panel.corpus, .panel.analysis {{
      grid-column: span 4;
    }}
    .panel.selection, .panel.readiness {{
      grid-column: span 6;
    }}
    .panel.config-panel {{
      background:
        linear-gradient(120deg, rgba(240, 191, 85, 0.09), transparent 38%),
        var(--card);
    }}
    .panel > h2 + .muted {{
      margin-top: 8px;
      line-height: 1.5;
    }}
    .status-stack, .log-stack {{
      gap: 10px;
    }}
    .status-card, .log-card, .tool-card, .device-card, .wifi-target-card, .artifact {{
      background: rgba(5, 9, 11, 0.48);
      border: 1px solid rgba(255,255,255,0.08);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.04);
    }}
    .tool-card, .device-card, .wifi-target-card {{
      transition: transform 160ms ease, border-color 160ms ease, background 160ms ease;
    }}
    .tool-card:hover, .device-card:hover, .wifi-target-card:hover {{
      transform: translateY(-2px);
      border-color: rgba(183, 243, 107, 0.28);
      background: rgba(8, 14, 16, 0.68);
    }}
    .operator-layout {{
      grid-template-columns: minmax(0, 1.55fr) minmax(300px, 0.85fr);
      gap: 18px;
    }}
    .tool-grid, .device-grid {{
      max-height: none;
      overflow: visible;
      scrollbar-color: rgba(183, 243, 107, 0.42) rgba(255,255,255,0.04);
    }}
    .tool-grid {{
      grid-template-columns: repeat(auto-fit, minmax(min(100%, 360px), 1fr));
      align-items: start;
    }}
    .device-grid {{
      grid-template-columns: 1fr;
      align-items: start;
    }}
    .tool-card, .device-card, .wifi-target-card, .status-card, .artifact {{
      min-width: 0;
      align-content: start;
    }}
    .tool-card p, .device-card p, .wifi-target-card p, .status-card p, .requirement strong, .requirement code {{
      overflow-wrap: anywhere;
    }}
    .wifi-panel {{
      grid-column: span 5;
    }}
    .wifi-target-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(min(100%, 250px), 1fr));
      gap: 12px;
      margin-top: 14px;
    }}
    .wifi-target-card {{
      display: grid;
      gap: 10px;
      padding: 14px;
      border-radius: 18px;
      background:
        radial-gradient(circle at top left, rgba(183, 243, 107, 0.11), transparent 45%),
        rgba(5, 9, 11, 0.48);
    }}
    .wifi-target-card header {{
      display: flex;
      gap: 10px;
      align-items: flex-start;
      justify-content: space-between;
    }}
    .mini-badges {{
      display: flex;
      flex-wrap: wrap;
      justify-content: flex-end;
      gap: 6px;
    }}
    .primary-choice {{
      grid-column: 1 / -1;
      background: linear-gradient(135deg, rgba(183, 243, 107, 0.08), rgba(101, 213, 198, 0.06));
      border-color: rgba(183, 243, 107, 0.18);
    }}
    .field-hint {{
      color: var(--muted);
      font-size: 12px;
      line-height: 1.45;
    }}
    .pill {{
      gap: 6px;
      padding: 5px 10px;
      color: #d8e1dc;
      background: rgba(255,255,255,0.06);
      border-color: rgba(255,255,255,0.11);
      font-size: 11px;
      font-weight: 700;
    }}
    .pill::before {{
      content: "";
      width: 7px;
      height: 7px;
      border-radius: 99px;
      background: currentColor;
      box-shadow: 0 0 16px currentColor;
    }}
    .pill.ok, .pill.ready, .pill.supported {{
      color: var(--accent);
    }}
    .pill.running, .pill.limited, .pill.heuristic {{
      color: var(--accent-2);
    }}
    .pill.warning, .pill.supported_with_limits {{
      color: var(--amber);
    }}
    .pill.error, .pill.missing, .pill.blocked, .pill.unsupported {{
      color: var(--danger);
    }}
    .field-grid {{
      grid-template-columns: repeat(auto-fit, minmax(245px, 1fr));
    }}
    label {{
      padding: 10px;
      border-radius: 15px;
      background: rgba(255,255,255,0.035);
      border: 1px solid rgba(255,255,255,0.05);
    }}
    input, select, textarea {{
      min-height: 42px;
      background: rgba(3, 8, 10, 0.72);
      border-color: rgba(178, 226, 209, 0.16);
      outline: none;
    }}
    input:focus, select:focus, textarea:focus {{
      border-color: rgba(183, 243, 107, 0.58);
      box-shadow: 0 0 0 3px rgba(183, 243, 107, 0.1);
    }}
    .button-row {{
      grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
    }}
    button {{
      min-height: 42px;
      border-radius: 14px;
      color: #07100f;
      background: linear-gradient(135deg, var(--accent), #72decd);
      border: 0;
      box-shadow: 0 12px 26px rgba(101, 213, 198, 0.14);
      transition: transform 140ms ease, filter 140ms ease, box-shadow 140ms ease;
    }}
    button:hover {{
      transform: translateY(-1px);
      filter: brightness(1.05);
      box-shadow: 0 16px 32px rgba(101, 213, 198, 0.2);
    }}
    button[value="all"], button[value="start_remote"], button[value="remote_doctor"], button[type="submit"]:last-child {{
      background: linear-gradient(135deg, #ffe38e, var(--accent));
    }}
    details {{
      padding: 12px;
      border-radius: 18px;
      background: rgba(255,255,255,0.035);
      border: 1px solid rgba(255,255,255,0.06);
    }}
    summary {{
      cursor: pointer;
      color: var(--accent);
      font-weight: 700;
      letter-spacing: 0.02em;
    }}
    .config-panel form {{
      margin-top: 14px;
    }}
    .config-panel .field-grid {{
      max-height: none;
      overflow: visible;
      padding-right: 6px;
      scrollbar-color: rgba(183, 243, 107, 0.42) rgba(255,255,255,0.04);
    }}
    table {{
      min-width: 680px;
      border-collapse: separate;
      border-spacing: 0;
      overflow: hidden;
    }}
    th {{
      color: var(--accent-2);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      background: rgba(255,255,255,0.04);
    }}
    td, th {{
      padding: 12px 10px;
    }}
    .panel:has(table) {{
      overflow-x: auto;
    }}
    code, pre {{
      font-family: "Cascadia Code", "IBM Plex Mono", "Consolas", monospace;
    }}
    code {{
      color: #bed3cc;
      white-space: normal;
      overflow-wrap: anywhere;
    }}
    pre {{
      background: #040708;
      border: 1px solid rgba(255,255,255,0.06);
    }}
    .links a {{
      display: inline-flex;
      padding: 8px 10px;
      border-radius: 999px;
      color: var(--accent-2);
      background: rgba(101, 213, 198, 0.08);
      border: 1px solid rgba(101, 213, 198, 0.14);
    }}
    @media (max-width: 1100px) {{
      .hero {{
        grid-template-columns: 1fr;
      }}
      .panel, .panel.actions, .panel.artifacts, .panel.selection, .panel.readiness, .panel.corpus, .panel.analysis {{
        grid-column: 1 / -1;
      }}
    }}
    @media (max-width: 720px) {{
      .shell {{
        width: min(100% - 18px, 1480px);
        margin-top: 9px;
      }}
      .hero {{
        border-radius: 22px;
      }}
      .nav-rail {{
        top: 6px;
      }}
      .field-grid, .button-row {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <div class="hero-main">
        <span class="eyebrow">Local operator console</span>
        <h1>WiFi Stream Dashboard</h1>
        <p>Capture on the machine or Raspberry Pi, pull artifacts back, inspect decoded streams, and keep replay/WPA readiness visible before you spend time on a long run.</p>
        <div class="status-row">
          <span class="pill {last_status_class}">{val('last_status')}</span>
          <strong>{val('last_message')}</strong>
          {current_action_markup}
        </div>
      </div>
      <aside class="hero-card">
        <strong>Live context</strong>
        <div class="hero-metric">
          <span>Config</span>
          <b>{val('config_path')}</b>
        </div>
        <div class="hero-metric">
          <span>Capture</span>
          <b>{val('capture_path')}</b>
        </div>
        <div class="hero-metric">
          <span>Remote</span>
          <b>{val('remote_host')}</b>
        </div>
      </aside>
    </section>

    <nav class="nav-rail" aria-label="Dashboard sections">
      <a href="#operator">Operator</a>
      <a href="#wifi">Wi-Fi</a>
      <a href="#actions">Actions</a>
      <a href="#selection">Selection</a>
      <a href="#artifacts">Artifacts</a>
      <a href="#config">Config</a>
      <a href="#logs">Logs</a>
    </nav>

    <section class="grid">
      <div class="panel wide" id="machine">
        <h2>What This Machine Can Do</h2>
        <p class="muted">{val('machine_summary_headline')}</p>
        <div class="status-stack">{values.get('machine_cards_html', '')}</div>
      </div>

      <div class="panel wide" id="operator">
        <h2>Operator Console</h2>
        <p class="muted">{val('operator_headline')}</p>
        <div class="operator-layout">
          <div>
            <h3>Tool Requirements</h3>
            <div class="tool-grid">{values.get('tool_cards_html', '')}</div>
          </div>
          <div>
            <h3>Detected Devices</h3>
            <div class="device-grid">{values.get('device_cards_html', '')}</div>
          </div>
        </div>
      </div>

      <div class="panel actions" id="actions">
        <h2>Pipeline Actions</h2>
        <p class="muted">Use the quick actions for the usual flow, or fill in a pcap / decrypted-reference path for one-off runs. While an action is running, this page refreshes every few seconds.</p>
        <form method="post" action="/action">
          <div class="field-grid">
            <label>PCAP Path Override
              <input type="text" name="pcap_path" value="{val('capture_path')}" />
            </label>
            <label>Decrypted Reference Directory
              <input type="text" name="decrypted_dir" value="" />
            </label>
            <label>Wi-Fi Strip After Capture
              <select name="strip_wifi_flag">
                <option value="no">No</option>
                <option value="yes">Yes</option>
              </select>
            </label>
            <label>Monitor Method
              <select name="monitor_method">
                <option value="airodump" {"selected" if values.get("monitor_method") == "airodump" else ""}>airodump (targeted)</option>
                <option value="besside" {"selected" if values.get("monitor_method") == "besside" else ""}>besside (auto)</option>
                <option value="tcpdump" {"selected" if values.get("monitor_method") == "tcpdump" else ""}>tcpdump (generic; uses dumpcap on Windows)</option>
              </select>
            </label>
            <label>Handshake .cap Path (crack only)
              <input type="text" name="cap_path" value="" placeholder="auto-detected if blank" />
            </label>
          </div>
          <div class="button-row">
            <button type="submit" name="action" value="deps">Check Env</button>
            <button type="submit" name="action" value="capture">Capture</button>
            <button type="submit" name="action" value="stripwifi">Strip Wi-Fi</button>
            <button type="submit" name="action" value="extract">Extract</button>
            <button type="submit" name="action" value="detect">Detect</button>
            <button type="submit" name="action" value="analyze">Analyze</button>
            <button type="submit" name="action" value="enrich">Enrich</button>
            <button type="submit" name="action" value="play">Reconstruct</button>
            <button type="submit" name="action" value="all">Run Full Flow</button>
          </div>
          <details>
            <summary>Wi-Fi Lab Pipeline</summary>
            <p class="muted" style="margin:8px 0 12px">Monitor mode, WPA2 crack, and airdecap-ng strip. Most reliable on Linux; Windows requires Npcap monitor mode + aircrack-ng and is adapter-dependent.</p>
            <div class="button-row">
              <button type="submit" name="action" value="monitor">Monitor Capture</button>
              <button type="submit" name="action" value="crack">Crack + Decrypt</button>
              <button type="submit" name="action" value="wifi">Full Wi-Fi Lab Flow</button>
            </div>
          </details>
          <details open>
            <summary>Raspberry Pi / Remote Appliance</summary>
            <p class="muted" style="margin:8px 0 12px">Use the Pi for capture-heavy work, then pull the PCAP back here for extraction and analysis. These actions use SSH keys and saved remote config, not stored passwords.</p>
            <div class="field-grid">
              <label>Remote Output Override
                <input type="text" name="remote_output" value="" placeholder="/home/david/wifi-pipeline/captures/manual.pcap" />
              </label>
            </div>
            <div class="button-row">
              <button type="submit" name="action" value="discover_remote">Discover Pi</button>
              <button type="submit" name="action" value="remote_doctor">Remote Doctor</button>
              <button type="submit" name="action" value="bootstrap_remote">Bootstrap Pi</button>
              <button type="submit" name="action" value="remote_status">Service Status</button>
              <button type="submit" name="action" value="remote_service_start">Start Service</button>
              <button type="submit" name="action" value="remote_stop">Stop Service</button>
              <button type="submit" name="action" value="remote_last_capture">Last Capture</button>
              <button type="submit" name="action" value="start_remote">Capture + Pull</button>
              <button type="submit" name="action" value="pull_remote">Pull Existing</button>
            </div>
          </details>
        </form>
      </div>

      <div class="panel wifi-panel" id="wifi">
        <h2>Auto Wi-Fi Targeting</h2>
        <p class="muted">The dashboard scans for nearby APs and prefers the connected network, then the strongest secured target. Use Auto for plug-and-play, or switch to Manual in Saved Configuration when you want exact ESSID/BSSID/channel control.</p>
        <div class="wifi-target-grid">{values.get('wifi_target_cards_html', '')}</div>
      </div>

      <div class="panel artifacts" id="artifacts">
        <h2>Artifacts</h2>
        <div class="artifact-grid">{values.get('artifact_cards', '')}</div>
        <div class="links">
          <a href="/reports/manifest" target="_blank">Manifest JSON</a>
          <a href="/reports/detection" target="_blank">Detection JSON</a>
          <a href="/reports/analysis" target="_blank">Analysis JSON</a>
          <a href="/reports/enrichment" target="_blank">Enrichment JSON</a>
          <a href="/reports/corpus" target="_blank">Corpus JSON</a>
        </div>
      </div>

      <div class="panel selection" id="selection">
        <h2>Current Selection</h2>
        <p><strong>Detection stream:</strong> {val('detection_stream')}</p>
        <p class="muted">Class / score: {val('detection_class')} / {val('detection_score')}</p>
        <p><strong>Analysis stream:</strong> {val('analysis_stream')}</p>
        <p class="muted">Top hypothesis: {val('top_hypothesis')}</p>
        <p class="muted">Corpus best match: {val('best_match_id')} {val('best_match_similarity')}</p>
        <div class="status-row">
          <span class="pill {val('selection_status_class')}">{val('selection_status')}</span>
          <span class="muted">{val('selection_summary')}</span>
        </div>
        <p class="muted">Decode / replay: {val('selection_decode_level')} / {val('selection_replay_level')} ({val('selection_unit_type')})</p>
        <p class="muted">Signal strength: {val('selection_signal_strength')}</p>
        {values.get('selection_notes_html', '')}
        <p class="muted">Next step: {val('selection_next_step')}</p>
      </div>

      <div class="panel readiness" id="readiness">
        <h2>Replay + WPA Readiness</h2>
        <div class="status-row">
          <span class="pill {val('replay_status_class')}">{val('replay_status')}</span>
          <strong>Replay path</strong>
        </div>
        <p class="muted">{val('replay_summary')}</p>
        <p class="muted">Decode / replay: {val('replay_decode_level')} / {val('replay_replay_level')} ({val('replay_unit_type')})</p>
        <p class="muted">Confidence: {val('replay_confidence_band')} [{val('replay_confidence_label')}, score={val('replay_confidence_score')}] via {val('replay_delivery_mode')}</p>
        {values.get('replay_reasons_html', '')}
        {values.get('replay_next_steps_html', '')}
        <div class="status-row" style="margin-top:16px">
          <span class="pill {val('wpa_status_class')}">{val('wpa_status')}</span>
          <strong>WPA path</strong>
        </div>
        <p class="muted">{val('wpa_summary')}</p>
        <p class="muted">State / artifact: {val('wpa_state')} / {val('wpa_artifact')}</p>
        {values.get('wpa_reasons_html', '')}
        {values.get('wpa_next_steps_html', '')}
      </div>

      <div class="panel wide config-panel" id="config">
        <h2>Saved Configuration</h2>
        <form method="post" action="/config">
          <div class="field-grid">
            <label class="primary-choice">Wi-Fi Target
              <select name="ap_target" data-ap-target-select>
                {values.get('wifi_target_options', '')}
              </select>
              <span class="field-hint">Auto updates ESSID/BSSID/channel from discovery when possible. Manual keeps the override fields below exactly as typed.</span>
            </label>
            <label>Interface
              <input list="interfaces" type="text" name="interface" value="{val('interface')}" />
              <datalist id="interfaces">
                {values.get('interface_options', '')}
              </datalist>
            </label>
            <label>Protocol
              <select name="protocol">
                <option value="udp" {"selected" if values.get("protocol") == "udp" else ""}>udp</option>
                <option value="tcp" {"selected" if values.get("protocol") == "tcp" else ""}>tcp</option>
              </select>
            </label>
            <label>Target Port
              <input type="number" name="video_port" value="{val('video_port')}" />
            </label>
            <label>Capture Duration
              <input type="number" name="capture_duration" value="{val('capture_duration')}" />
            </label>
            <label>Output Directory
              <input type="text" name="output_dir" value="{val('output_dir')}" />
            </label>
            <label>Target MACs
              <input type="text" name="target_macs" value="{val('target_macs')}" />
            </label>
            <label>AP ESSID
              <input list="wifi-essids" type="text" name="ap_essid" value="{val('ap_essid')}" data-ap-essid />
              <datalist id="wifi-essids">
                {values.get('wifi_essid_options', '')}
              </datalist>
            </label>
            <label>AP BSSID
              <input list="wifi-bssids" type="text" name="ap_bssid" value="{val('ap_bssid')}" placeholder="00:11:22:33:44:55" data-ap-bssid />
              <datalist id="wifi-bssids">
                {values.get('wifi_bssid_options', '')}
              </datalist>
            </label>
            <label>AP Channel
              <input type="number" name="ap_channel" value="{val('ap_channel')}" data-ap-channel />
            </label>
            <label>Monitor Method
              <select name="monitor_method">
                <option value="airodump" {"selected" if values.get("monitor_method") == "airodump" else ""}>airodump</option>
                <option value="besside" {"selected" if values.get("monitor_method") == "besside" else ""}>besside</option>
                <option value="tcpdump" {"selected" if values.get("monitor_method") == "tcpdump" else ""}>tcpdump</option>
              </select>
            </label>
            <label>Wordlist Path
              <input type="text" name="wordlist_path" value="{val('wordlist_path')}" />
            </label>
            <label>Deauth Count (0 = passive)
              <input type="number" name="deauth_count" value="{val('deauth_count')}" />
            </label>
            <label>WPA Password Env
              <input type="text" name="wpa_password_env" value="{val('wpa_password_env')}" />
            </label>
            <label>Remote Host
              <input type="text" name="remote_host" value="{val('remote_host')}" placeholder="david@raspi-sniffer" />
            </label>
            <label>Remote SSH Port
              <input type="number" name="remote_port" value="{val('remote_port')}" />
            </label>
            <label>Remote Identity File
              <input type="text" name="remote_identity" value="{val('remote_identity')}" placeholder="optional ~/.ssh/id_ed25519" />
            </label>
            <label>Remote Interface
              <input type="text" name="remote_interface" value="{val('remote_interface')}" placeholder="wlan0" />
            </label>
            <label>Remote Path / Pattern
              <input type="text" name="remote_path" value="{val('remote_path')}" placeholder="/home/david/wifi-pipeline/captures/" />
            </label>
            <label>Remote Import Directory
              <input type="text" name="remote_dest_dir" value="{val('remote_dest_dir')}" />
            </label>
            <label>Remote Health Port
              <input type="number" name="remote_health_port" value="{val('remote_health_port')}" />
            </label>
            <label>Remote Poll Interval
              <input type="number" name="remote_poll_interval" value="{val('remote_poll_interval')}" />
            </label>
            <label>Remote Install Mode
              <select name="remote_install_mode">
                <option value="auto" {"selected" if values.get("remote_install_mode") == "auto" else ""}>auto</option>
                <option value="native" {"selected" if values.get("remote_install_mode") == "native" else ""}>native</option>
                <option value="bundle" {"selected" if values.get("remote_install_mode") == "bundle" else ""}>bundle</option>
              </select>
            </label>
            <label>Remote Install Profile
              <select name="remote_install_profile">
                <option value="appliance" {"selected" if values.get("remote_install_profile") == "appliance" else ""}>appliance</option>
                <option value="standard" {"selected" if values.get("remote_install_profile") == "standard" else ""}>standard</option>
              </select>
            </label>
            <label>Header Strip Bytes
              <input type="number" name="custom_header_size" value="{val('custom_header_size')}" />
            </label>
            <label>Custom Magic Hex
              <input type="text" name="custom_magic_hex" value="{val('custom_magic_hex')}" />
            </label>
            <label>Preferred Stream
              <input type="text" name="preferred_stream_id" value="{val('preferred_stream_id')}" />
            </label>
            <label>Minimum Candidate Bytes
              <input type="number" name="min_candidate_bytes" value="{val('min_candidate_bytes')}" />
            </label>
            <label>Replay Format Hint
              <input type="text" name="replay_format_hint" value="{val('replay_format_hint')}" />
            </label>
            <label>Playback Mode
              <select name="playback_mode">
                <option value="file" {"selected" if values.get("playback_mode") == "file" else ""}>file</option>
                <option value="ffplay" {"selected" if values.get("playback_mode") == "ffplay" else ""}>ffplay</option>
                <option value="both" {"selected" if values.get("playback_mode") == "both" else ""}>both</option>
              </select>
            </label>
            <label>Jitter Buffer Packets
              <input type="number" name="jitter_buffer_packets" value="{val('jitter_buffer_packets')}" />
            </label>
            <label>Corpus Review Threshold
              <input type="number" step="0.01" name="corpus_review_threshold" value="{val('corpus_review_threshold')}" />
            </label>
            <label>Corpus Auto-Reuse Threshold
              <input type="number" step="0.01" name="corpus_auto_reuse_threshold" value="{val('corpus_auto_reuse_threshold')}" />
            </label>
          </div>
          <button type="submit">Save Configuration</button>
        </form>
      </div>

      <div class="panel wide" id="workflow">
        <h2>Workflow Capabilities</h2>
        <div class="status-stack">{values.get('workflow_cards_html', '')}</div>
      </div>

      <div class="panel wide" id="candidates">
        <h2>Top Candidate Streams</h2>
        <table>
          <thead>
            <tr><th>Class</th><th>Score</th><th>Stream</th><th>Bytes</th><th>Action</th></tr>
          </thead>
          <tbody>{values.get('candidate_rows_html', '')}</tbody>
        </table>
      </div>

      <div class="panel corpus" id="corpus">
        <h2>Corpus Archive</h2>
        <p><strong>Archived streams:</strong> {val('corpus_entry_count')}</p>
        <p><strong>Reusable material:</strong> {val('corpus_material_count')}</p>
        <p class="muted">Latest entry: {val('corpus_latest')}</p>
        <p class="muted">Analysis reused material: {val('corpus_reused')}</p>
      </div>

      <div class="panel analysis" id="analysis">
        <h2>Detection + Analysis</h2>
        <p><strong>Average entropy:</strong> {val('average_entropy')}</p>
        <p><strong>Chi-squared:</strong> {val('chi_squared')}</p>
        <p><strong>Units analyzed:</strong> {val('total_units')}</p>
        <p class="muted">Recommendation: {val('recommendation')}</p>
      </div>

      <div class="panel wide" id="recent-corpus">
        <h2>Recent Corpus Entries</h2>
        <table>
          <thead>
            <tr><th>Entry ID</th><th>Class</th><th>Type</th><th>Material</th><th>Stream</th></tr>
          </thead>
          <tbody>{values.get('corpus_rows_html', '')}</tbody>
        </table>
      </div>

      <div class="panel wide" id="logs">
        <h2>Action Logs</h2>
        <div class="log-stack">{values.get('log_blocks', '')}</div>
      </div>
    </section>
  </main>
  <script>
    const form = document.querySelector("form[action='/action']");
    if (form) {{
      form.addEventListener("submit", () => {{
        const select = form.querySelector("select[name='strip_wifi_flag']");
        if (!select) return;
        let hidden = form.querySelector("input[name='strip_wifi']");
        if (select.value === "yes") {{
          if (!hidden) {{
            hidden = document.createElement("input");
            hidden.type = "hidden";
            hidden.name = "strip_wifi";
            hidden.value = "1";
            form.appendChild(hidden);
          }}
        }} else if (hidden) {{
          hidden.remove();
        }}
      }});
    }}
    const targetSelect = document.querySelector("[data-ap-target-select]");
    if (targetSelect) {{
      const essid = document.querySelector("[data-ap-essid]");
      const bssid = document.querySelector("[data-ap-bssid]");
      const channel = document.querySelector("[data-ap-channel]");
      const fillTargetFields = (force) => {{
        const option = targetSelect.selectedOptions && targetSelect.selectedOptions[0];
        if (!option || targetSelect.value === "{MANUAL_TARGET_VALUE}") return;
        const apply = (field, value) => {{
          if (!field || !value) return;
          if (force || !String(field.value || "").trim()) {{
            field.value = value;
          }}
        }};
        apply(essid, option.dataset.ssid || "");
        apply(bssid, option.dataset.bssid || "");
        apply(channel, option.dataset.channel || "");
      }};
      targetSelect.addEventListener("change", () => fillTargetFields(true));
      fillTargetFields(false);
    }}
  </script>
</body>
</html>"""
