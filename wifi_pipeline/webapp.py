from __future__ import annotations

import contextlib
import html
import io
import json
import threading
import time
import traceback
import webbrowser
from dataclasses import asdict, dataclass, field, is_dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from .analysis import CryptoAnalyzer, FormatDetector, _rank_candidate_streams
from .capture import Capture
from .config import DEFAULT_CONFIG
from .corpus import CorpusStore
from .environment import check_environment, list_interfaces
from .extract import StreamExtractor
from .playback import infer_replay_hint, reconstruct_from_capture

DEFAULT_WEB_HOST = "127.0.0.1"
DEFAULT_WEB_PORT = 8765


def _json_default(value: object) -> object:
    if is_dataclass(value):
        return asdict(value)
    return str(value)


def _config_path(config_path: Optional[str] = None) -> Path:
    return Path(config_path or "lab.json").resolve()


def _capture_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "raw_capture.pcapng"


def _manifest_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "manifest.json"


def _detection_report_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "detection_report.json"


def _analysis_report_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "analysis_report.json"


def _quiet_load_json(path: Path) -> Optional[Dict[str, object]]:
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def _quiet_load_config(path: Optional[str] = None) -> Dict[str, object]:
    config = dict(DEFAULT_CONFIG)
    selected_path = _config_path(path)
    if selected_path.exists():
        try:
            with open(selected_path, "r", encoding="utf-8") as handle:
                config.update(json.load(handle))
        except (OSError, json.JSONDecodeError):
            pass
    config["environment_model"] = "native_windows"
    config.setdefault("wpa_password_env", "WIFI_PIPELINE_WPA_PASSWORD")
    config.setdefault("wpa_password", "")
    if not config.get("replay_format_hint"):
        config["replay_format_hint"] = config.get("video_codec") or "raw"
    config.setdefault("corpus_review_threshold", 0.62)
    config.setdefault("corpus_auto_reuse_threshold", 0.88)
    return config


def _quiet_save_config(config: Dict[str, object], path: Optional[str] = None) -> None:
    selected_path = _config_path(path)
    sanitized = dict(config)
    sanitized["environment_model"] = "native_windows"
    sanitized["wpa_password"] = ""
    selected_path.write_text(json.dumps(sanitized, indent=2), encoding="utf-8")


def _safe_int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: str, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _form_value(payload: Dict[str, List[str]], key: str, default: str = "") -> str:
    values = payload.get(key, [])
    if not values:
        return default
    return values[0].strip()


def _checked(payload: Dict[str, List[str]], key: str) -> bool:
    return key in payload


def _html_text(value: object) -> str:
    return html.escape(str(value or ""))


def _shorten(value: object, width: int = 96) -> str:
    text = str(value or "")
    if len(text) <= width:
        return text
    return text[: width - 3] + "..."


def _artifact_status(config: Dict[str, object]) -> List[Dict[str, object]]:
    paths = [
        ("Capture", _capture_path(config)),
        ("Manifest", _manifest_path(config)),
        ("Detection Report", _detection_report_path(config)),
        ("Analysis Report", _analysis_report_path(config)),
    ]
    return [
        {
            "label": label,
            "path": str(path),
            "exists": path.exists(),
        }
        for label, path in paths
    ]


def _report_bundle(config: Dict[str, object]) -> Dict[str, object]:
    manifest = _quiet_load_json(_manifest_path(config)) or {}
    detection = _quiet_load_json(_detection_report_path(config)) or {}
    analysis = _quiet_load_json(_analysis_report_path(config)) or {}
    candidate_rows = _rank_candidate_streams(manifest, config) if manifest else []
    corpus = CorpusStore(config)
    return {
        "manifest": manifest,
        "detection": detection,
        "analysis": analysis,
        "candidate_rows": candidate_rows,
        "corpus_status": corpus.status(),
        "corpus_entries": corpus.recent_entries(limit=8),
        "artifacts": _artifact_status(config),
        "interfaces": list_interfaces(),
    }


@dataclass
class ActionLog:
    timestamp: float
    action: str
    status: str
    message: str
    output: str


@dataclass
class DashboardState:
    config_path: Path
    lock: threading.Lock = field(default_factory=threading.Lock)
    busy: bool = False
    current_action: str = ""
    last_started_at: float = 0.0
    last_finished_at: float = 0.0
    last_status: str = "idle"
    last_message: str = "Dashboard ready."
    logs: List[ActionLog] = field(default_factory=list)

    def add_log(self, action: str, status: str, message: str, output: str) -> None:
        with self.lock:
            self.logs.append(ActionLog(time.time(), action, status, message, output))
            self.logs = self.logs[-24:]
            self.last_status = status
            self.last_message = message
            self.last_finished_at = time.time()

    def snapshot(self) -> Dict[str, object]:
        with self.lock:
            logs = list(self.logs)
            current_action = self.current_action
            busy = self.busy
            last_started_at = self.last_started_at
            last_finished_at = self.last_finished_at
            last_status = self.last_status
            last_message = self.last_message

        config = _quiet_load_config(str(self.config_path))
        bundle = _report_bundle(config)
        return {
            "config": config,
            "bundle": bundle,
            "busy": busy,
            "current_action": current_action,
            "last_started_at": last_started_at,
            "last_finished_at": last_finished_at,
            "last_status": last_status,
            "last_message": last_message,
            "logs": logs,
            "config_path": str(self.config_path),
        }

    def update_config(self, form: Dict[str, List[str]]) -> str:
        config = _quiet_load_config(str(self.config_path))
        current_target_macs = list(config.get("target_macs", []))
        macs_text = _form_value(form, "target_macs", ",".join(current_target_macs))

        config["interface"] = _form_value(form, "interface", str(config.get("interface") or ""))
        config["protocol"] = "tcp" if _form_value(form, "protocol", str(config.get("protocol") or "udp")).lower() == "tcp" else "udp"
        config["video_port"] = _safe_int(_form_value(form, "video_port", str(config.get("video_port", 5004))), int(config.get("video_port", 5004) or 5004))
        config["capture_duration"] = _safe_int(
            _form_value(form, "capture_duration", str(config.get("capture_duration", 60))),
            int(config.get("capture_duration", 60) or 60),
        )
        config["output_dir"] = _form_value(form, "output_dir", str(config.get("output_dir") or "./pipeline_output"))
        config["target_macs"] = [item.strip() for item in macs_text.split(",") if item.strip()]
        config["ap_essid"] = _form_value(form, "ap_essid", str(config.get("ap_essid") or ""))
        config["custom_header_size"] = _safe_int(
            _form_value(form, "custom_header_size", str(config.get("custom_header_size", 0))),
            int(config.get("custom_header_size", 0) or 0),
        )
        config["custom_magic_hex"] = _form_value(form, "custom_magic_hex", str(config.get("custom_magic_hex") or "")).replace(" ", "")
        config["preferred_stream_id"] = _form_value(form, "preferred_stream_id", str(config.get("preferred_stream_id") or ""))
        config["min_candidate_bytes"] = _safe_int(
            _form_value(form, "min_candidate_bytes", str(config.get("min_candidate_bytes", 4096))),
            int(config.get("min_candidate_bytes", 4096) or 4096),
        )
        config["replay_format_hint"] = _form_value(
            form,
            "replay_format_hint",
            str(config.get("replay_format_hint") or config.get("video_codec") or "raw"),
        )
        config["video_codec"] = str(config.get("replay_format_hint") or "raw")
        config["playback_mode"] = _form_value(form, "playback_mode", str(config.get("playback_mode") or "both")).lower()
        config["jitter_buffer_packets"] = _safe_int(
            _form_value(form, "jitter_buffer_packets", str(config.get("jitter_buffer_packets", 24))),
            int(config.get("jitter_buffer_packets", 24) or 24),
        )
        config["corpus_review_threshold"] = _safe_float(
            _form_value(form, "corpus_review_threshold", str(config.get("corpus_review_threshold", 0.62))),
            float(config.get("corpus_review_threshold", 0.62) or 0.62),
        )
        config["corpus_auto_reuse_threshold"] = _safe_float(
            _form_value(form, "corpus_auto_reuse_threshold", str(config.get("corpus_auto_reuse_threshold", 0.88))),
            float(config.get("corpus_auto_reuse_threshold", 0.88) or 0.88),
        )
        config["wpa_password_env"] = _form_value(
            form,
            "wpa_password_env",
            str(config.get("wpa_password_env") or "WIFI_PIPELINE_WPA_PASSWORD"),
        )
        _quiet_save_config(config, str(self.config_path))
        self.add_log("config", "ok", "Saved configuration.", "")
        return "Saved configuration."

    def start_action(self, action: str, form: Dict[str, List[str]]) -> bool:
        with self.lock:
            if self.busy:
                return False
            self.busy = True
            self.current_action = action
            self.last_started_at = time.time()
            self.last_status = "running"
            self.last_message = f"Running {action}..."

        thread = threading.Thread(target=self._run_action, args=(action, form), daemon=True)
        thread.start()
        return True

    def _run_action(self, action: str, form: Dict[str, List[str]]) -> None:
        output = io.StringIO()
        message = ""
        status = "ok"
        try:
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                message = self._execute_action(action, form)
        except Exception as exc:  # pragma: no cover - defensive path
            status = "error"
            message = str(exc) or f"{action} failed."
            traceback.print_exc(file=output)
        finally:
            with self.lock:
                self.busy = False
                self.current_action = ""
            self.add_log(action, status, message, output.getvalue())

    def _execute_action(self, action: str, form: Dict[str, List[str]]) -> str:
        config = _quiet_load_config(str(self.config_path))
        pcap_path = _form_value(form, "pcap_path", "")
        decrypted_dir = _form_value(form, "decrypted_dir", "")
        strip_wifi = _checked(form, "strip_wifi") or _form_value(form, "strip_wifi_flag", "no").lower() == "yes"

        if action == "deps":
            ready = check_environment()
            return "Environment looks ready." if ready else "Environment check found missing requirements."

        if action == "capture":
            capture = Capture(config)
            source = capture.run(interactive=False)
            if source and strip_wifi:
                source = capture.strip_wifi_layer(source)
            return source or "Capture did not produce a pcap."

        if action == "stripwifi":
            source = pcap_path or str(_capture_path(config))
            result = Capture(config).strip_wifi_layer(source)
            return result or "Wi-Fi strip did not produce a decrypted pcap."

        if action == "extract":
            source = pcap_path or str(_capture_path(config))
            result = StreamExtractor(config).extract(source)
            if not result:
                return "Extraction did not produce a manifest."
            return str(_manifest_path(config))

        if action == "detect":
            result = FormatDetector(config).detect()
            if not result:
                return "Detection did not produce a report."
            return str(_detection_report_path(config))

        if action == "analyze":
            result = CryptoAnalyzer(config).analyze(decrypted_dir or None)
            if not result:
                return "Analysis did not produce a report."
            return str(_analysis_report_path(config))

        if action == "play":
            report = _quiet_load_json(_analysis_report_path(config)) or {}
            if not report:
                return "Run analyze first."
            config_for_play = dict(config)
            config_for_play["replay_format_hint"] = infer_replay_hint(config, report)
            reconstructed = reconstruct_from_capture(config_for_play, report)
            return reconstructed or "No offline reconstruction was available in the last analysis report."

        if action == "all":
            source = pcap_path
            if not source:
                capture = Capture(config)
                source = capture.run(interactive=False)
                if source and strip_wifi:
                    source = capture.strip_wifi_layer(source)
            if not source:
                return "Full pipeline stopped before extraction."
            StreamExtractor(config).extract(source)
            FormatDetector(config).detect()
            report = CryptoAnalyzer(config).analyze(decrypted_dir or None)
            if report and report.get("candidate_material"):
                config_for_play = dict(config)
                config_for_play["replay_format_hint"] = infer_replay_hint(config, report)
                reconstructed = reconstruct_from_capture(config_for_play, report)
                if reconstructed:
                    return f"Full pipeline finished and wrote reconstructed output to {reconstructed}"
            return "Full pipeline finished."

        raise RuntimeError(f"Unknown action: {action}")


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "WifiPipelineWeb/1.0"

    @property
    def app(self) -> DashboardState:
        return self.server.app_state  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._render_dashboard()
            return
        if parsed.path.startswith("/reports/"):
            name = parsed.path.rsplit("/", 1)[-1]
            self._serve_report(name)
            return
        if parsed.path == "/api/state":
            self._serve_json(self.app.snapshot())
            return
        self.send_error(404, "Not Found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        payload = self._parse_form()
        if parsed.path == "/config":
            self.app.update_config(payload)
            self._redirect("/")
            return
        if parsed.path == "/pin":
            stream_id = _form_value(payload, "stream_id", "")
            config = _quiet_load_config(str(self.app.config_path))
            config["preferred_stream_id"] = stream_id
            _quiet_save_config(config, str(self.app.config_path))
            self.app.add_log("pin", "ok", f"Pinned preferred stream to {stream_id or '(auto)'}", "")
            self._redirect("/")
            return
        if parsed.path == "/action":
            action = _form_value(payload, "action", "")
            if not action:
                self.app.add_log("action", "error", "No action was selected.", "")
            elif not self.app.start_action(action, payload):
                self.app.add_log(action, "warning", "Another action is still running.", "")
            self._redirect("/")
            return
        self.send_error(404, "Not Found")

    def _parse_form(self) -> Dict[str, List[str]]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        return parse_qs(raw, keep_blank_values=True)

    def _redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.end_headers()

    def _serve_json(self, payload: object) -> None:
        body = json.dumps(payload, indent=2, default=_json_default).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_report(self, name: str) -> None:
        config = _quiet_load_config(str(self.app.config_path))
        report_map = {
            "manifest": _manifest_path(config),
            "detection": _detection_report_path(config),
            "analysis": _analysis_report_path(config),
            "corpus": Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "corpus" / "index.json",
        }
        target = report_map.get(name)
        if not target or not target.exists():
            self.send_error(404, "Report not found")
            return
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _render_dashboard(self) -> None:
        snapshot = self.app.snapshot()
        body = _render_dashboard_html(snapshot).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # pragma: no cover - quiet server logs
        return


def _render_dashboard_html(snapshot: Dict[str, object]) -> str:
    config = dict(snapshot.get("config") or {})
    bundle = dict(snapshot.get("bundle") or {})
    detection = dict(bundle.get("detection") or {})
    analysis = dict(bundle.get("analysis") or {})
    candidate_rows = list(bundle.get("candidate_rows") or [])
    corpus_entries = list(bundle.get("corpus_entries") or [])
    corpus_status = dict(bundle.get("corpus_status") or {})
    logs = list(snapshot.get("logs") or [])
    interfaces = list(bundle.get("interfaces") or [])
    artifacts = list(bundle.get("artifacts") or [])
    busy = bool(snapshot.get("busy"))
    current_action = str(snapshot.get("current_action") or "")
    last_message = str(snapshot.get("last_message") or "")
    last_status = str(snapshot.get("last_status") or "idle")
    selected = dict(detection.get("selected_candidate_stream") or {})
    selected_analysis = dict(analysis.get("selected_candidate_stream") or {})
    analysis_corpus = dict(analysis.get("corpus") or {})
    best_match = dict(analysis_corpus.get("best_match") or {})

    log_blocks = []
    for entry in reversed(logs[-6:]):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry.timestamp))
        log_blocks.append(
            f"<article class='log-card'>"
            f"<header><strong>{_html_text(timestamp)}</strong> <span class='pill {entry.status}'>{_html_text(entry.status)}</span> "
            f"<span class='muted'>{_html_text(entry.action)}</span></header>"
            f"<p>{_html_text(entry.message)}</p>"
            f"<pre>{_html_text(entry.output.strip() or '(no terminal output)')}</pre>"
            f"</article>"
        )

    interface_options = [
        f"<option value='{_html_text(name)}'>{_html_text(description or name)}</option>"
        for _number, name, description in interfaces
    ]

    artifact_cards = "".join(
        (
            "<div class='artifact'>"
            f"<strong>{_html_text(item['label'])}</strong>"
            f"<span class='pill {'ok' if item['exists'] else 'missing'}'>{'ready' if item['exists'] else 'missing'}</span>"
            f"<code>{_html_text(_shorten(item['path'], 88))}</code>"
            "</div>"
        )
        for item in artifacts
    )

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
        for entry in corpus_entries
    ) or "<tr><td colspan='5'>No archived candidates yet.</td></tr>"

    auto_refresh = "<meta http-equiv='refresh' content='4'>" if busy else ""
    return _dashboard_template(
        auto_refresh=auto_refresh,
        busy=busy,
        current_action=current_action,
        last_message=last_message,
        last_status=last_status,
        config_path=str(snapshot.get("config_path") or ""),
        capture_path=str(_capture_path(config)),
        interface_options="".join(interface_options),
        artifact_cards=artifact_cards,
        candidate_rows_html=candidate_rows_html,
        corpus_rows_html=corpus_rows_html,
        log_blocks="".join(log_blocks) or "<p class='muted'>No actions have been run from the dashboard yet.</p>",
        interface=str(config.get("interface") or ""),
        protocol=str(config.get("protocol") or "udp"),
        video_port=str(config.get("video_port") or ""),
        capture_duration=str(config.get("capture_duration") or ""),
        output_dir=str(config.get("output_dir") or ""),
        target_macs=",".join(config.get("target_macs", [])),
        ap_essid=str(config.get("ap_essid") or ""),
        wpa_password_env=str(config.get("wpa_password_env") or ""),
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
        top_hypothesis=str((analysis.get("hypotheses") or [{}])[0].get("name") if analysis.get("hypotheses") else "(none)"),
        best_match_id=str(best_match.get("entry_id") or "(none)"),
        best_match_similarity=str(best_match.get("similarity") or ""),
        corpus_entry_count=str(corpus_status.get("entry_count") or 0),
        corpus_material_count=str(corpus_status.get("candidate_material_count") or 0),
        corpus_latest=str((corpus_status.get("latest_entry") or {}).get("entry_id") or "(none)"),
        corpus_reused="yes" if analysis_corpus.get("reused_candidate_material") else "no",
        average_entropy=str(detection.get("average_entropy") or "?"),
        chi_squared=str((analysis.get("ciphertext_observations") or {}).get("chi_squared") or "?"),
        total_units=str(analysis.get("total_units") or 0),
        recommendation=_shorten((analysis.get("recommendations") or ["(none)"])[0], 90),
    )


def _dashboard_template(**values: str) -> str:
    def val(key: str) -> str:
        return _html_text(values.get(key, ""))

    auto_refresh = values.get("auto_refresh", "")
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
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <h1>WiFi Stream Dashboard</h1>
      <p>Local browser control for capture, extraction, detection, analysis, corpus matching, and offline reconstruction. This dashboard stays on your machine and wraps the existing pipeline instead of replacing it.</p>
      <div class="status-row">
        <span class="pill {val('last_status')}">{val('last_status')}</span>
        <strong>{val('last_message')}</strong>
        {current_action_markup}
        <span class="muted">Config: {val('config_path')}</span>
      </div>
    </section>

    <section class="grid">
      <div class="panel wide">
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
          </div>
          <div class="button-row">
            <button type="submit" name="action" value="deps">Check Env</button>
            <button type="submit" name="action" value="capture">Capture</button>
            <button type="submit" name="action" value="stripwifi">Strip Wi-Fi</button>
            <button type="submit" name="action" value="extract">Extract</button>
            <button type="submit" name="action" value="detect">Detect</button>
            <button type="submit" name="action" value="analyze">Analyze</button>
            <button type="submit" name="action" value="play">Reconstruct</button>
            <button type="submit" name="action" value="all">Run Full Flow</button>
          </div>
        </form>
      </div>

      <div class="panel">
        <h2>Artifacts</h2>
        <div class="artifact-grid">{values.get('artifact_cards', '')}</div>
        <div class="links">
          <a href="/reports/manifest" target="_blank">Manifest JSON</a>
          <a href="/reports/detection" target="_blank">Detection JSON</a>
          <a href="/reports/analysis" target="_blank">Analysis JSON</a>
          <a href="/reports/corpus" target="_blank">Corpus JSON</a>
        </div>
      </div>

      <div class="panel">
        <h2>Current Selection</h2>
        <p><strong>Detection stream:</strong> {val('detection_stream')}</p>
        <p class="muted">Class / score: {val('detection_class')} / {val('detection_score')}</p>
        <p><strong>Analysis stream:</strong> {val('analysis_stream')}</p>
        <p class="muted">Top hypothesis: {val('top_hypothesis')}</p>
        <p class="muted">Corpus best match: {val('best_match_id')} {val('best_match_similarity')}</p>
      </div>

      <div class="panel wide">
        <h2>Saved Configuration</h2>
        <form method="post" action="/config">
          <div class="field-grid">
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
              <input type="text" name="ap_essid" value="{val('ap_essid')}" />
            </label>
            <label>WPA Password Env
              <input type="text" name="wpa_password_env" value="{val('wpa_password_env')}" />
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

      <div class="panel wide">
        <h2>Top Candidate Streams</h2>
        <table>
          <thead>
            <tr><th>Class</th><th>Score</th><th>Stream</th><th>Bytes</th><th>Action</th></tr>
          </thead>
          <tbody>{values.get('candidate_rows_html', '')}</tbody>
        </table>
      </div>

      <div class="panel">
        <h2>Corpus Archive</h2>
        <p><strong>Archived streams:</strong> {val('corpus_entry_count')}</p>
        <p><strong>Reusable material:</strong> {val('corpus_material_count')}</p>
        <p class="muted">Latest entry: {val('corpus_latest')}</p>
        <p class="muted">Analysis reused material: {val('corpus_reused')}</p>
      </div>

      <div class="panel">
        <h2>Detection + Analysis</h2>
        <p><strong>Average entropy:</strong> {val('average_entropy')}</p>
        <p><strong>Chi-squared:</strong> {val('chi_squared')}</p>
        <p><strong>Units analyzed:</strong> {val('total_units')}</p>
        <p class="muted">Recommendation: {val('recommendation')}</p>
      </div>

      <div class="panel wide">
        <h2>Recent Corpus Entries</h2>
        <table>
          <thead>
            <tr><th>Entry ID</th><th>Class</th><th>Type</th><th>Material</th><th>Stream</th></tr>
          </thead>
          <tbody>{values.get('corpus_rows_html', '')}</tbody>
        </table>
      </div>

      <div class="panel wide">
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
  </script>
</body>
</html>"""


def serve_dashboard(
    config_path: Optional[str] = None,
    host: str = DEFAULT_WEB_HOST,
    port: int = DEFAULT_WEB_PORT,
    open_browser: bool = True,
) -> None:
    state = DashboardState(config_path=_config_path(config_path))
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    server.app_state = state  # type: ignore[attr-defined]
    url = f"http://{host}:{port}/"
    print(f"Web dashboard running at {url}")
    print("Press Ctrl+C to stop the server.")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    finally:
        server.server_close()
