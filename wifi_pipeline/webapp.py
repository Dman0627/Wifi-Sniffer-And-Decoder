from __future__ import annotations

import contextlib
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
from .config import load_config, save_config
from .corpus import CorpusStore
from .environment import check_environment, list_interfaces
from .extract import StreamExtractor
from .playback import infer_replay_hint, reconstruct_from_capture
from .status_language import build_surface_status_bundle
from .webapp_render import render_dashboard_html

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


def _load_dashboard_config(path: Optional[str] = None) -> Dict[str, object]:
    return load_config(path, quiet=True, ignore_errors=True)


def _save_dashboard_config(config: Dict[str, object], path: Optional[str] = None) -> None:
    save_config(config, path or "lab.json", quiet=True)


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
    status_bundle = build_surface_status_bundle(config, detection, analysis)
    return {
        "manifest": manifest,
        "detection": detection,
        "analysis": analysis,
        "status_bundle": status_bundle,
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

        config = _load_dashboard_config(str(self.config_path))
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
        config = _load_dashboard_config(str(self.config_path))
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
        config["monitor_method"] = _form_value(
            form, "monitor_method", str(config.get("monitor_method") or "airodump")
        ).lower()
        config["ap_bssid"] = _form_value(form, "ap_bssid", str(config.get("ap_bssid") or ""))
        config["ap_channel"] = _safe_int(
            _form_value(form, "ap_channel", str(config.get("ap_channel", 6))),
            int(config.get("ap_channel", 6) or 6),
        )
        config["wordlist_path"] = _form_value(
            form, "wordlist_path", str(config.get("wordlist_path") or "/usr/share/wordlists/rockyou.txt")
        )
        config["deauth_count"] = _safe_int(
            _form_value(form, "deauth_count", str(config.get("deauth_count", 10))),
            int(config.get("deauth_count", 10) or 10),
        )
        _save_dashboard_config(config, str(self.config_path))
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
        config = _load_dashboard_config(str(self.config_path))
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

        if action == "monitor":
            monitor_method = _form_value(form, "monitor_method",
                                         str(config.get("monitor_method") or "airodump"))
            capture = Capture(config)
            result = capture.run_monitor(method=monitor_method, interactive=False)
            return result or "Monitor capture did not produce a pcap. Check that the interface supports monitor mode and you are running as root/Administrator."

        if action == "crack":
            cap = _form_value(form, "cap_path", "").strip() or None
            capture = Capture(config)
            result = capture.crack_and_decrypt(handshake_cap=cap)
            return result or "Crack/decrypt step did not produce a decrypted pcap. Check that a handshake capture exists and your wordlist is configured."

        if action == "wifi":
            monitor_method = _form_value(form, "monitor_method",
                                         str(config.get("monitor_method") or "airodump"))
            capture = Capture(config)
            decrypted_pcap = capture.run_full_wifi_pipeline(method=monitor_method, interactive=False)
            source = decrypted_pcap or str(_capture_path(config))
            if not Path(source).exists():
                return "Wi-Fi lab pipeline did not produce a capture to extract from."
            StreamExtractor(config).extract(source)
            FormatDetector(config).detect()
            report = CryptoAnalyzer(config).analyze(decrypted_dir or None)
            if report and report.get("candidate_material"):
                config_for_play = dict(config)
                config_for_play["replay_format_hint"] = infer_replay_hint(config, report)
                reconstructed = reconstruct_from_capture(config_for_play, report)
                if reconstructed:
                    return f"Full Wi-Fi lab pipeline finished. Reconstructed output: {reconstructed}"
            return "Full Wi-Fi lab pipeline finished."

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
            config = _load_dashboard_config(str(self.app.config_path))
            config["preferred_stream_id"] = stream_id
            _save_dashboard_config(config, str(self.app.config_path))
            if stream_id:
                StreamExtractor(config).remember_candidate_feedback_by_stream_id(
                    stream_id,
                    "pin",
                    note="Pinned from the dashboard.",
                )
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
        config = _load_dashboard_config(str(self.app.config_path))
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
    return render_dashboard_html(snapshot, capture_path=str(_capture_path(config)))


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
