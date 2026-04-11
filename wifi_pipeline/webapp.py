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
from .enrich import ArtifactEnricher
from .extract import StreamExtractor
from .playback import infer_replay_hint, reconstruct_from_capture
from .remote import (
    bootstrap_remote_host,
    discover_remote_appliances,
    doctor_remote_host,
    pull_remote_capture,
    remote_service_host,
    start_remote_capture,
)
from .status_language import build_surface_status_bundle
from .webapp_render import render_dashboard_html
from .wifi_discovery import (
    AUTO_TARGET_VALUE,
    MANUAL_TARGET_VALUE,
    discover_wifi_targets,
    select_preferred_wifi_target,
)

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


def _enrichment_report_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "enrichment_report.json"


def _validation_report_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "validation_report.json"


def _remote_discovery_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "remote_discovery.json"


def _remote_doctor_report_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "remote_doctor_report.json"


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


def _config_int(config: Dict[str, object], key: str, default: int) -> int:
    return _safe_int(str(config.get(key, default)), default)


def _safe_float(value: str, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _config_float(config: Dict[str, object], key: str, default: float) -> float:
    return _safe_float(str(config.get(key, default)), default)


def _config_list(config: Dict[str, object], key: str) -> List[str]:
    value = config.get(key, [])
    if value is None or (isinstance(value, str) and value == ""):
        return []
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()]


def _form_value(payload: Dict[str, List[str]], key: str, default: str = "") -> str:
    values = payload.get(key, [])
    if not values:
        return default
    return values[0].strip()


def _checked(payload: Dict[str, List[str]], key: str) -> bool:
    return key in payload


def _wifi_target_mode(config: Dict[str, object]) -> str:
    mode = str(config.get("wifi_target_mode") or "").strip().lower()
    if mode in ("auto", "selected", "manual"):
        return mode
    if str(config.get("ap_essid") or "").strip() or str(config.get("ap_bssid") or "").strip():
        return "selected"
    return "auto"


def _decode_wifi_target_value(value: str) -> Optional[Dict[str, object]]:
    text = str(value or "").strip()
    if not text or text in (AUTO_TARGET_VALUE, MANUAL_TARGET_VALUE):
        return None
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, dict):
        return None
    return {
        "ssid": str(raw.get("ssid") or "").strip(),
        "bssid": str(raw.get("bssid") or "").strip(),
        "channel": raw.get("channel") or "",
        "signal": raw.get("signal") or "",
        "signal_label": str(raw.get("signal_label") or "").strip(),
        "security": str(raw.get("security") or "").strip(),
        "source": str(raw.get("source") or "dashboard").strip(),
        "connected": bool(raw.get("connected")),
    }


def _discover_wifi_targets_for_config(
    config: Dict[str, object],
    *,
    force: bool = False,
) -> List[Dict[str, object]]:
    interface = str(config.get("interface") or config.get("remote_interface") or "").strip()
    try:
        return discover_wifi_targets(interface, timeout=1.2, ttl_seconds=20.0, force=force)
    except Exception:
        return []


def _preferred_wifi_target(
    config: Dict[str, object],
    targets: List[Dict[str, object]],
) -> Optional[Dict[str, object]]:
    if _wifi_target_mode(config) == "auto":
        return select_preferred_wifi_target(targets)
    return select_preferred_wifi_target(
        targets,
        configured_essid=str(config.get("ap_essid") or ""),
        configured_bssid=str(config.get("ap_bssid") or ""),
    )


def _apply_wifi_target(
    config: Dict[str, object],
    target: Optional[Dict[str, object]],
    *,
    mode: str,
) -> bool:
    if not target:
        config["wifi_target_mode"] = mode
        return False

    changed = False
    ssid = str(target.get("ssid") or "").strip()
    bssid = str(target.get("bssid") or "").strip()
    channel_text = str(target.get("channel") or "").strip()
    if ssid and config.get("ap_essid") != ssid:
        config["ap_essid"] = ssid
        changed = True
    if bssid and config.get("ap_bssid") != bssid:
        config["ap_bssid"] = bssid
        changed = True
    if channel_text:
        channel = _safe_int(channel_text, _config_int(config, "ap_channel", 6))
        if config.get("ap_channel") != channel:
            config["ap_channel"] = channel
            changed = True

    config["wifi_target_mode"] = mode
    config["wifi_target_source"] = str(target.get("source") or "auto")
    config["wifi_target_last_selected"] = _utc_stamp()
    return changed


def _resolve_auto_wifi_target(config: Dict[str, object], *, force: bool = False) -> Optional[Dict[str, object]]:
    mode = _wifi_target_mode(config)
    if mode == "manual":
        return None
    if mode == "selected" and (str(config.get("ap_essid") or "").strip() or str(config.get("ap_bssid") or "").strip()):
        return None
    targets = _discover_wifi_targets_for_config(config, force=force)
    target = _preferred_wifi_target({**config, "wifi_target_mode": "auto"}, targets)
    if target:
        _apply_wifi_target(config, target, mode="auto")
        return target
    config["wifi_target_mode"] = mode
    return None


def _artifact_status(config: Dict[str, object]) -> List[Dict[str, object]]:
    paths = [
        ("Capture", _capture_path(config)),
        ("Manifest", _manifest_path(config)),
        ("Detection Report", _detection_report_path(config)),
        ("Analysis Report", _analysis_report_path(config)),
        ("Enrichment Report", _enrichment_report_path(config)),
        ("Validation Report", _validation_report_path(config)),
        ("Remote Discovery", _remote_discovery_path(config)),
        ("Remote Doctor", _remote_doctor_report_path(config)),
    ]
    return [
        {
            "label": label,
            "path": str(path),
            "exists": path.exists(),
        }
        for label, path in paths
    ]


def _write_dashboard_json(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, default=_json_default)


def _utc_stamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _first_artifact(artifacts: List[Dict[str, object]], label: str) -> Dict[str, object]:
    for artifact in artifacts:
        if str(artifact.get("label") or "") == label:
            return artifact
    return {"label": label, "path": "", "exists": False}


def _requirement(
    label: str,
    value: object,
    status: str,
    detail: str,
    *,
    required: bool = True,
) -> Dict[str, object]:
    return {
        "label": label,
        "value": str(value or ""),
        "status": status,
        "detail": detail,
        "required": required,
    }


def _configured_requirement(
    label: str,
    value: object,
    missing_detail: str,
    *,
    present_detail: str = "",
    required: bool = True,
) -> Dict[str, object]:
    text = str(value or "").strip()
    if text:
        return _requirement(label, text, "ready", present_detail or "Configured.", required=required)
    return _requirement(
        label,
        "(not set)",
        "blocked" if required else "limited",
        missing_detail,
        required=required,
    )


def _artifact_requirement(
    artifacts: List[Dict[str, object]],
    label: str,
    missing_detail: str,
    *,
    required: bool = True,
) -> Dict[str, object]:
    artifact = _first_artifact(artifacts, label)
    exists = bool(artifact.get("exists"))
    path = str(artifact.get("path") or "")
    if exists:
        return _requirement(label, path, "ready", "Artifact exists.", required=required)
    return _requirement(
        label,
        path or "(not created yet)",
        "blocked" if required else "limited",
        missing_detail,
        required=required,
    )


def _path_requirement(
    label: str,
    value: object,
    missing_detail: str,
    *,
    required: bool = True,
    must_exist: bool = False,
) -> Dict[str, object]:
    text = str(value or "").strip()
    if not text:
        return _requirement(
            label,
            "(not set)",
            "blocked" if required else "limited",
            missing_detail,
            required=required,
        )
    if must_exist and not Path(text).expanduser().exists():
        return _requirement(label, text, "limited", "Path is configured, but it does not exist on this controller.", required=required)
    return _requirement(label, text, "ready", "Configured.", required=required)


def _duration_requirement(config: Dict[str, object]) -> Dict[str, object]:
    duration = _config_int(config, "capture_duration", 60)
    if duration <= 0:
        return _requirement("Duration", str(duration), "blocked", "Capture duration must be positive.")
    return _requirement("Duration", f"{duration}s", "ready", "Configured.")


def _tool_status(requirements: List[Dict[str, object]]) -> str:
    required = [item for item in requirements if bool(item.get("required", True))]
    if any(str(item.get("status") or "") == "blocked" for item in required):
        return "blocked"
    if any(str(item.get("status") or "") in ("limited", "warning") for item in requirements):
        return "limited"
    return "ready"


def _tool_entry(
    tool_id: str,
    label: str,
    summary: str,
    requirements: List[Dict[str, object]],
    *,
    action: str = "",
    category: str = "Pipeline",
    next_step: str = "",
) -> Dict[str, object]:
    status = _tool_status(requirements)
    if not next_step:
        next_step = "Ready to run from Pipeline Actions." if status == "ready" else "Fill the blocked requirements, then retry."
    return {
        "id": tool_id,
        "label": label,
        "summary": summary,
        "requirements": requirements,
        "status": status,
        "action": action,
        "category": category,
        "next_step": next_step,
    }


def _remote_doctor_from_reports(
    validation: Dict[str, object],
    remote_doctor: Dict[str, object],
) -> Dict[str, object]:
    validation_doctor = validation.get("doctor")
    if isinstance(validation_doctor, dict):
        return validation_doctor
    doctor = remote_doctor.get("doctor")
    if isinstance(doctor, dict):
        return doctor
    if remote_doctor.get("remote"):
        return remote_doctor
    return {}


def _operator_tools(
    config: Dict[str, object],
    artifacts: List[Dict[str, object]],
) -> List[Dict[str, object]]:
    interface = str(config.get("interface") or "").strip()
    remote_host = str(config.get("remote_host") or "").strip()
    remote_interface = str(config.get("remote_interface") or "").strip()
    output_dir = str(config.get("output_dir") or "./pipeline_output")
    remote_dest_dir = str(config.get("remote_dest_dir") or "./pipeline_output/remote_imports")
    remote_path = str(config.get("remote_path") or "").strip()
    remote_health_port = _config_int(config, "remote_health_port", 8741)
    monitor_method = str(config.get("monitor_method") or "airodump")
    wordlist_path = str(config.get("wordlist_path") or "")
    ap_essid = str(config.get("ap_essid") or "")
    ap_bssid = str(config.get("ap_bssid") or "")
    ap_channel = str(config.get("ap_channel") or "")

    return [
        _tool_entry(
            "deps",
            "Environment doctor",
            "Checks local Python/runtime/network tooling before a run.",
            [_requirement("Local shell", "current controller", "ready", "Uses the same environment as the CLI.")],
            action="deps",
            category="Readiness",
        ),
        _tool_entry(
            "capture",
            "Local packet capture",
            "Captures traffic on a controller interface and writes the raw PCAP artifact.",
            [
                _configured_requirement("Interface", interface, "Choose a local adapter from Detected Devices."),
                _duration_requirement(config),
                _path_requirement("Output directory", output_dir, "Set an output directory."),
            ],
            action="capture",
            category="Capture",
        ),
        _tool_entry(
            "stripwifi",
            "Strip Wi-Fi layer",
            "Removes link-layer Wi-Fi framing from a capture before extraction.",
            [_artifact_requirement(artifacts, "Capture", "Capture or pull a PCAP first.")],
            action="stripwifi",
            category="Decode",
        ),
        _tool_entry(
            "extract",
            "Stream extraction",
            "Builds a manifest of conversations and payload streams from a PCAP.",
            [_artifact_requirement(artifacts, "Capture", "Capture or pull a PCAP first.")],
            action="extract",
            category="Decode",
        ),
        _tool_entry(
            "detect",
            "Format detection",
            "Ranks candidate streams and guesses image/video/text/archive formats.",
            [_artifact_requirement(artifacts, "Manifest", "Run extraction first.")],
            action="detect",
            category="Analysis",
        ),
        _tool_entry(
            "analyze",
            "Crypto and replay analysis",
            "Evaluates entropy, protocol support, corpus reuse, and replay feasibility.",
            [_artifact_requirement(artifacts, "Manifest", "Run extraction first.")],
            action="analyze",
            category="Analysis",
        ),
        _tool_entry(
            "enrich",
            "Artifact enrichment",
            "Adds file metadata and richer artifact summaries after detection/analysis.",
            [
                _artifact_requirement(artifacts, "Detection Report", "Run detection first."),
                _artifact_requirement(artifacts, "Analysis Report", "Run analysis first.", required=False),
            ],
            action="enrich",
            category="Analysis",
        ),
        _tool_entry(
            "play",
            "Replay / reconstruct",
            "Exports or reconstructs supported candidate media from the latest analysis.",
            [_artifact_requirement(artifacts, "Analysis Report", "Run analysis first.")],
            action="play",
            category="Output",
        ),
        _tool_entry(
            "all",
            "Full local flow",
            "Runs capture or uses a PCAP override, then extract, detect, analyze, enrich, and reconstruct.",
            [
                _path_requirement("Output directory", output_dir, "Set an output directory."),
                _duration_requirement(config),
            ],
            action="all",
            category="Workflow",
        ),
        _tool_entry(
            "monitor",
            "Wi-Fi monitor capture",
            "Runs monitor-mode capture for AP/handshake workflows.",
            [
                _configured_requirement("Interface", interface, "Choose a monitor-capable adapter."),
                _configured_requirement("Monitor method", monitor_method, "Choose a monitor method."),
                _configured_requirement("AP BSSID", ap_bssid, "Optional until you want targeted capture.", required=False),
                _configured_requirement("AP channel", ap_channel, "Optional until you want targeted capture.", required=False),
            ],
            action="monitor",
            category="Wi-Fi Lab",
            next_step="Use the Pi remote path if local monitor mode is flaky.",
        ),
        _tool_entry(
            "crack",
            "WPA crack + decrypt",
            "Uses a handshake/PMKID capture, ESSID, and wordlist to produce decrypted traffic.",
            [
                _configured_requirement("AP ESSID", ap_essid, "Set the Wi-Fi network name."),
                _path_requirement("Wordlist", wordlist_path, "Set a wordlist path.", must_exist=True),
                _artifact_requirement(artifacts, "Capture", "Collect or provide a handshake capture.", required=False),
            ],
            action="crack",
            category="Wi-Fi Lab",
        ),
        _tool_entry(
            "wifi",
            "Full Wi-Fi lab flow",
            "Runs monitor capture, WPA decrypt, extraction, detection, analysis, and reconstruction.",
            [
                _configured_requirement("Interface", interface, "Choose a monitor-capable adapter."),
                _configured_requirement("AP ESSID", ap_essid, "Set the Wi-Fi network name."),
                _path_requirement("Wordlist", wordlist_path, "Set a wordlist path.", must_exist=True),
            ],
            action="wifi",
            category="Wi-Fi Lab",
        ),
        _tool_entry(
            "discover_remote",
            "Discover Pi appliances",
            "Scans for capture appliances exposing the health endpoint.",
            [
                _requirement("Health port", str(remote_health_port), "ready", "Configured."),
                _requirement("Network scope", "auto-detected LAN", "ready", "Uses local network hints and common hostnames."),
            ],
            action="discover_remote",
            category="Raspberry Pi",
        ),
        _tool_entry(
            "remote_doctor",
            "Remote doctor",
            "Checks SSH, the Pi capture agent, tcpdump/iw, service status, and health endpoint.",
            [
                _configured_requirement("Remote host", remote_host, "Set remote_host, for example david@raspi-sniffer."),
                _configured_requirement("Remote interface", remote_interface, "Set the Pi capture interface, usually wlan0.", required=False),
            ],
            action="remote_doctor",
            category="Raspberry Pi",
        ),
        _tool_entry(
            "bootstrap_remote",
            "Bootstrap Pi appliance",
            "Installs/updates the remote capture helper, service, privileged runner, and health endpoint.",
            [
                _configured_requirement("Remote host", remote_host, "Set remote_host before bootstrapping."),
                _requirement("Install mode", str(config.get("remote_install_mode") or "auto"), "ready", "Configured."),
                _requirement("Install profile", str(config.get("remote_install_profile") or "appliance"), "ready", "Configured."),
                _requirement("Health port", str(remote_health_port), "ready", "Configured."),
            ],
            action="bootstrap_remote",
            category="Raspberry Pi",
        ),
        _tool_entry(
            "remote_status",
            "Remote service status",
            "Reads the Pi service state without starting a new capture.",
            [_configured_requirement("Remote host", remote_host, "Set remote_host first.")],
            action="remote_status",
            category="Raspberry Pi",
        ),
        _tool_entry(
            "start_remote",
            "Remote capture + pull",
            "Starts a managed Pi capture, waits for completion, and imports the PCAP locally.",
            [
                _configured_requirement("Remote host", remote_host, "Set remote_host first."),
                _configured_requirement("Remote interface", remote_interface, "Set the Pi capture interface, usually wlan0."),
                _duration_requirement(config),
                _path_requirement("Local import directory", remote_dest_dir, "Set remote_dest_dir."),
            ],
            action="start_remote",
            category="Raspberry Pi",
        ),
        _tool_entry(
            "pull_remote",
            "Pull existing remote capture",
            "Copies the configured remote PCAP/file pattern into the local import directory.",
            [
                _configured_requirement("Remote host", remote_host, "Set remote_host first."),
                _configured_requirement("Remote path", remote_path, "Set a remote file, directory, or pattern."),
                _path_requirement("Local import directory", remote_dest_dir, "Set remote_dest_dir."),
            ],
            action="pull_remote",
            category="Raspberry Pi",
        ),
    ]


def _operator_devices(
    config: Dict[str, object],
    interfaces: List[object],
    validation: Dict[str, object],
    remote_doctor: Dict[str, object],
    discovery: Dict[str, object],
) -> List[Dict[str, object]]:
    devices: List[Dict[str, object]] = []
    selected_interface = str(config.get("interface") or "").strip()
    remote_host = str(config.get("remote_host") or "").strip()
    remote_interface = str(config.get("remote_interface") or "").strip()
    doctor = _remote_doctor_from_reports(validation, remote_doctor)
    remote = dict(doctor.get("remote") or {})

    for _number, name, description in interfaces:
        interface_name = str(name or "").strip()
        if not interface_name:
            continue
        selected = interface_name == selected_interface
        devices.append(
            {
                "id": f"local:{interface_name}",
                "name": interface_name,
                "scope": "Local controller",
                "status": "ready" if selected else "limited",
                "role": "Configured capture interface" if selected else "Detected adapter",
                "summary": str(description or interface_name),
                "details": [
                    "Selected in config." if selected else "Available to select in Saved Configuration.",
                ],
            }
        )

    if remote_host:
        reachable = remote.get("reachable")
        service_status = str(remote.get("service_status") or "unknown")
        health_ok = remote.get("health_probe_ok")
        if doctor.get("ok"):
            status = "ready"
        elif reachable is False:
            status = "blocked"
        else:
            status = "limited"
        details = [
            f"Interface: {remote_interface or remote.get('interface') or '(not set)'}",
            f"Service: {service_status}",
            f"tcpdump: {'yes' if remote.get('tcpdump') else 'unknown'}",
            f"iw: {'yes' if remote.get('iw') else 'unknown'}",
        ]
        endpoint = str(remote.get("health_endpoint") or "").strip()
        if endpoint:
            details.append(f"Health: {endpoint} ({'ok' if health_ok is True else 'not confirmed'})")
        devices.append(
            {
                "id": f"remote:{remote_host}",
                "name": remote_host,
                "scope": "Raspberry Pi appliance",
                "status": status,
                "role": "Configured remote capture node",
                "summary": str(remote.get("health_device_name") or remote.get("home") or "Configured SSH target"),
                "details": details,
            }
        )

    discovered_nodes = list(discovery.get("nodes") or [])
    seen_remote_hosts = {remote_host.split("@", 1)[-1] if remote_host else ""}
    for node in discovered_nodes:
        if not isinstance(node, dict):
            continue
        host = str(node.get("host") or "").strip()
        ssh_target = str(node.get("ssh_target") or host).strip()
        if not host or host in seen_remote_hosts or ssh_target == remote_host:
            continue
        seen_remote_hosts.add(host)
        devices.append(
            {
                "id": f"discovered:{host}",
                "name": ssh_target,
                "scope": "Discovered appliance",
                "status": "ready",
                "role": str(node.get("device_name") or "Capture appliance"),
                "summary": str(node.get("health_endpoint") or host),
                "details": [
                    f"Service: {node.get('service_status') or 'unknown'}",
                    f"Profile: {node.get('install_profile') or 'unknown'}",
                    "Save this host in Remote Host to control it.",
                ],
            }
        )

    if not devices:
        devices.append(
            {
                "id": "none",
                "name": "No devices discovered yet",
                "scope": "Inventory",
                "status": "blocked",
                "role": "Run discovery or save an interface",
                "summary": "No local adapters or remote appliances are currently listed.",
                "details": ["Run Check Env, Discover Pi, or save an interface/remote host."],
            }
        )
    return devices


def _operator_inventory(
    config: Dict[str, object],
    artifacts: List[Dict[str, object]],
    interfaces: List[object],
    validation: Dict[str, object],
    remote_doctor: Dict[str, object],
    discovery: Dict[str, object],
) -> Dict[str, object]:
    tools = _operator_tools(config, artifacts)
    devices = _operator_devices(config, interfaces, validation, remote_doctor, discovery)
    blocked_tools = [tool for tool in tools if tool.get("status") == "blocked"]
    ready_tools = [tool for tool in tools if tool.get("status") == "ready"]
    headline = (
        f"{len(ready_tools)} ready tool(s), {len(blocked_tools)} needing inputs, {len(devices)} device entry/entries."
    )
    return {
        "headline": headline,
        "tools": tools,
        "devices": devices,
        "blocked_tool_count": len(blocked_tools),
        "ready_tool_count": len(ready_tools),
    }


def _remote_host(config: Dict[str, object]) -> Optional[str]:
    return str(config.get("remote_host") or "").strip() or None


def _remote_port(config: Dict[str, object]) -> int:
    return _config_int(config, "remote_port", 22)


def _remote_identity(config: Dict[str, object]) -> Optional[str]:
    return str(config.get("remote_identity") or "").strip() or None


def _remote_interface(config: Dict[str, object]) -> Optional[str]:
    return str(config.get("remote_interface") or "").strip() or None


def _remote_dest_dir(config: Dict[str, object]) -> Optional[str]:
    return str(config.get("remote_dest_dir") or "").strip() or None


def _report_bundle(config: Dict[str, object]) -> Dict[str, object]:
    manifest = _quiet_load_json(_manifest_path(config)) or {}
    detection = _quiet_load_json(_detection_report_path(config)) or {}
    analysis = _quiet_load_json(_analysis_report_path(config)) or {}
    enrichment = _quiet_load_json(_enrichment_report_path(config)) or {}
    validation = _quiet_load_json(_validation_report_path(config)) or {}
    remote_discovery = _quiet_load_json(_remote_discovery_path(config)) or {}
    remote_doctor = _quiet_load_json(_remote_doctor_report_path(config)) or {}
    candidate_rows = _rank_candidate_streams(manifest, config) if manifest else []
    corpus = CorpusStore(config)
    status_bundle = build_surface_status_bundle(config, detection, analysis)
    artifacts = _artifact_status(config)
    interfaces = list_interfaces()
    wifi_targets = _discover_wifi_targets_for_config(config)
    wifi_auto_target = _preferred_wifi_target(config, wifi_targets)
    return {
        "manifest": manifest,
        "detection": detection,
        "analysis": analysis,
        "enrichment": enrichment,
        "validation": validation,
        "remote_discovery": remote_discovery,
        "remote_doctor": remote_doctor,
        "status_bundle": status_bundle,
        "candidate_rows": candidate_rows,
        "corpus_status": corpus.status(),
        "corpus_entries": corpus.recent_entries(limit=8),
        "artifacts": artifacts,
        "interfaces": interfaces,
        "wifi_targets": wifi_targets,
        "wifi_auto_target": wifi_auto_target or {},
        "wifi_target_mode": _wifi_target_mode(config),
        "operator_inventory": _operator_inventory(config, artifacts, interfaces, validation, remote_doctor, remote_discovery),
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
        current_target_macs = _config_list(config, "target_macs")
        macs_text = _form_value(form, "target_macs", ",".join(current_target_macs))

        config["interface"] = _form_value(form, "interface", str(config.get("interface") or ""))
        config["protocol"] = "tcp" if _form_value(form, "protocol", str(config.get("protocol") or "udp")).lower() == "tcp" else "udp"
        config["video_port"] = _safe_int(_form_value(form, "video_port", str(config.get("video_port", 5004))), _config_int(config, "video_port", 5004))
        config["capture_duration"] = _safe_int(
            _form_value(form, "capture_duration", str(config.get("capture_duration", 60))),
            _config_int(config, "capture_duration", 60),
        )
        config["output_dir"] = _form_value(form, "output_dir", str(config.get("output_dir") or "./pipeline_output"))
        config["target_macs"] = [item.strip() for item in macs_text.split(",") if item.strip()]
        config["custom_header_size"] = _safe_int(
            _form_value(form, "custom_header_size", str(config.get("custom_header_size", 0))),
            _config_int(config, "custom_header_size", 0),
        )
        config["custom_magic_hex"] = _form_value(form, "custom_magic_hex", str(config.get("custom_magic_hex") or "")).replace(" ", "")
        config["preferred_stream_id"] = _form_value(form, "preferred_stream_id", str(config.get("preferred_stream_id") or ""))
        config["min_candidate_bytes"] = _safe_int(
            _form_value(form, "min_candidate_bytes", str(config.get("min_candidate_bytes", 4096))),
            _config_int(config, "min_candidate_bytes", 4096),
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
            _config_int(config, "jitter_buffer_packets", 24),
        )
        config["corpus_review_threshold"] = _safe_float(
            _form_value(form, "corpus_review_threshold", str(config.get("corpus_review_threshold", 0.62))),
            _config_float(config, "corpus_review_threshold", 0.62),
        )
        config["corpus_auto_reuse_threshold"] = _safe_float(
            _form_value(form, "corpus_auto_reuse_threshold", str(config.get("corpus_auto_reuse_threshold", 0.88))),
            _config_float(config, "corpus_auto_reuse_threshold", 0.88),
        )
        config["wpa_password_env"] = _form_value(
            form,
            "wpa_password_env",
            str(config.get("wpa_password_env") or "WIFI_PIPELINE_WPA_PASSWORD"),
        )
        config["monitor_method"] = _form_value(
            form, "monitor_method", str(config.get("monitor_method") or "airodump")
        ).lower()
        config["ap_essid"] = _form_value(form, "ap_essid", str(config.get("ap_essid") or ""))
        config["ap_bssid"] = _form_value(form, "ap_bssid", str(config.get("ap_bssid") or ""))
        config["ap_channel"] = _safe_int(
            _form_value(form, "ap_channel", str(config.get("ap_channel", 6))),
            _config_int(config, "ap_channel", 6),
        )
        target_value = _form_value(form, "ap_target", "")
        if target_value == MANUAL_TARGET_VALUE:
            config["wifi_target_mode"] = "manual"
        elif target_value == AUTO_TARGET_VALUE:
            config["wifi_target_mode"] = "auto"
            targets = _discover_wifi_targets_for_config(config, force=True)
            _apply_wifi_target(config, _preferred_wifi_target({**config, "wifi_target_mode": "auto"}, targets), mode="auto")
        elif target_value:
            selected_target = _decode_wifi_target_value(target_value)
            if selected_target:
                _apply_wifi_target(config, selected_target, mode="selected")
            else:
                config["wifi_target_mode"] = "manual"
        elif "ap_target" not in form:
            config["wifi_target_mode"] = "manual"
        config["wordlist_path"] = _form_value(
            form, "wordlist_path", str(config.get("wordlist_path") or "/usr/share/wordlists/rockyou.txt")
        )
        config["deauth_count"] = _safe_int(
            _form_value(form, "deauth_count", str(config.get("deauth_count", 10))),
            _config_int(config, "deauth_count", 10),
        )
        config["remote_host"] = _form_value(form, "remote_host", str(config.get("remote_host") or ""))
        config["remote_path"] = _form_value(form, "remote_path", str(config.get("remote_path") or ""))
        config["remote_port"] = _safe_int(
            _form_value(form, "remote_port", str(config.get("remote_port", 22))),
            _config_int(config, "remote_port", 22),
        )
        config["remote_identity"] = _form_value(form, "remote_identity", str(config.get("remote_identity") or ""))
        config["remote_interface"] = _form_value(form, "remote_interface", str(config.get("remote_interface") or ""))
        install_mode = _form_value(form, "remote_install_mode", str(config.get("remote_install_mode") or "auto")).lower()
        config["remote_install_mode"] = install_mode if install_mode in ("auto", "native", "bundle") else "auto"
        install_profile = _form_value(
            form,
            "remote_install_profile",
            str(config.get("remote_install_profile") or "appliance"),
        ).lower()
        config["remote_install_profile"] = install_profile if install_profile in ("standard", "appliance") else "appliance"
        config["remote_health_port"] = _safe_int(
            _form_value(form, "remote_health_port", str(config.get("remote_health_port", 8741))),
            _config_int(config, "remote_health_port", 8741),
        )
        config["remote_dest_dir"] = _form_value(
            form,
            "remote_dest_dir",
            str(config.get("remote_dest_dir") or "./pipeline_output/remote_imports"),
        )
        config["remote_poll_interval"] = _safe_int(
            _form_value(form, "remote_poll_interval", str(config.get("remote_poll_interval", 8))),
            _config_int(config, "remote_poll_interval", 8),
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
        if action in ("monitor", "crack", "wifi") and _resolve_auto_wifi_target(config):
            _save_dashboard_config(config, str(self.config_path))
        pcap_path = _form_value(form, "pcap_path", "")
        decrypted_dir = _form_value(form, "decrypted_dir", "")
        strip_wifi = _checked(form, "strip_wifi") or _form_value(form, "strip_wifi_flag", "no").lower() == "yes"
        remote_output = _form_value(form, "remote_output", "").strip() or None

        if action == "deps":
            ready = check_environment()
            return "Environment looks ready." if ready else "Environment check found missing requirements."

        if action == "discover_remote":
            nodes = discover_remote_appliances(config)
            _write_dashboard_json(
                _remote_discovery_path(config),
                {
                    "schema_version": 1,
                    "discovered_at_utc": _utc_stamp(),
                    "nodes": nodes,
                },
            )
            if len(nodes) == 1 and not _remote_host(config):
                node = nodes[0]
                config["remote_host"] = str(node.get("ssh_target") or node.get("host") or "")
                if node.get("health_port"):
                    config["remote_health_port"] = _safe_int(str(node.get("health_port")), _config_int(config, "remote_health_port", 8741))
                if node.get("capture_dir") and not str(config.get("remote_path") or "").strip():
                    config["remote_path"] = str(node.get("capture_dir")).rstrip("/") + "/"
                _save_dashboard_config(config, str(self.config_path))
            if not nodes:
                return "No Pi/appliance health endpoints were discovered. Check that the remote service is bootstrapped and on the same LAN."
            targets = ", ".join(str(node.get("ssh_target") or node.get("host") or "") for node in nodes[:4])
            suffix = "" if len(nodes) <= 4 else f" (+{len(nodes) - 4} more)"
            return f"Discovered {len(nodes)} remote appliance(s): {targets}{suffix}"

        if action == "remote_doctor":
            report = doctor_remote_host(
                config,
                host=_remote_host(config),
                port=_remote_port(config),
                identity=_remote_identity(config),
                interface=_remote_interface(config),
            )
            _write_dashboard_json(
                _remote_doctor_report_path(config),
                {
                    "schema_version": 1,
                    "checked_at_utc": _utc_stamp(),
                    "doctor": report,
                },
            )
            return "Remote doctor passed." if report.get("ok") else "Remote doctor found issues. See the action log and Remote Doctor artifact."

        if action == "bootstrap_remote":
            result = bootstrap_remote_host(
                config,
                host=_remote_host(config),
                port=_remote_port(config),
                identity=_remote_identity(config),
                install_packages=True,
                install_mode=str(config.get("remote_install_mode") or "auto"),
                install_profile=str(config.get("remote_install_profile") or "appliance"),
                health_port=_config_int(config, "remote_health_port", 8741),
                pair=False,
            )
            if not result:
                return "Remote bootstrap failed. If this is first pairing, run pair/setup from the CLI once so no password is needed in the browser."
            _write_dashboard_json(
                _remote_doctor_report_path(config),
                {
                    "schema_version": 1,
                    "checked_at_utc": _utc_stamp(),
                    "bootstrap": result,
                    "doctor": doctor_remote_host(
                        config,
                        host=_remote_host(config),
                        port=_remote_port(config),
                        identity=_remote_identity(config),
                        interface=_remote_interface(config),
                    ),
                },
            )
            return f"Remote bootstrap complete. Capture directory: {result.get('capture_dir') or '(unknown)'}"

        if action in ("remote_status", "remote_stop", "remote_last_capture", "remote_service_start"):
            service_action = {
                "remote_status": "status",
                "remote_stop": "stop",
                "remote_last_capture": "last-capture",
                "remote_service_start": "start",
            }[action]
            result = remote_service_host(
                config,
                service_action,
                host=_remote_host(config),
                port=_remote_port(config),
                identity=_remote_identity(config),
                interface=_remote_interface(config),
                duration=_config_int(config, "capture_duration", 60),
                output=remote_output,
            )
            if not result:
                return f"Remote service {service_action} did not complete."
            if service_action == "status":
                return f"Remote service status: {result.get('service_status') or 'unknown'}"
            if service_action == "last-capture":
                return f"Last remote capture: {result.get('last_capture') or '(none yet)'}"
            if service_action == "start":
                return f"Remote service started: {result.get('output') or '(no output path returned)'}"
            return "Remote service stop requested."

        if action == "start_remote":
            pulled = start_remote_capture(
                config,
                host=_remote_host(config),
                port=_remote_port(config),
                identity=_remote_identity(config),
                interface=_remote_interface(config),
                duration=_config_int(config, "capture_duration", 60),
                output=remote_output,
                dest_dir=_remote_dest_dir(config),
            )
            return f"Remote capture imported: {pulled}" if pulled else "Remote capture did not produce a local PCAP."

        if action == "pull_remote":
            pulled = pull_remote_capture(
                config,
                host=_remote_host(config),
                path=str(config.get("remote_path") or "").strip() or None,
                port=_remote_port(config),
                identity=_remote_identity(config),
                dest_dir=_remote_dest_dir(config),
                latest_only=True,
                require_complete=False,
            )
            return f"Remote capture pulled: {pulled}" if pulled else "Remote pull did not produce a local PCAP."

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

        if action == "enrich":
            result = ArtifactEnricher(config).enrich()
            if not result:
                return "Enrichment did not produce a report."
            return str(_enrichment_report_path(config))

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
            ArtifactEnricher(config).enrich()
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
            "enrichment": _enrichment_report_path(config),
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
