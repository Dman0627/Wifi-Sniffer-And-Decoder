from __future__ import annotations

import json
import os
from typing import Dict, Optional

from .environment import pick_interface
from .ui import ask, ask_int, confirm, ok, section, warn

DEFAULT_CONFIG = {
    "environment_model": "native_windows",
    "interface": "",
    "target_macs": [],
    "ap_essid": "",
    "ap_bssid": "",
    "ap_channel": 6,
    "wpa_password": "",
    "wpa_password_env": "WIFI_PIPELINE_WPA_PASSWORD",
    "video_port": 5004,
    "protocol": "udp",
    "output_dir": "./pipeline_output",
    "capture_duration": 60,
    "custom_header_size": 0,
    "custom_magic_hex": "",
    "preferred_stream_id": "",
    "min_candidate_bytes": 4096,
    "replay_format_hint": "raw",
    "corpus_review_threshold": 0.62,
    "corpus_auto_reuse_threshold": 0.88,
    "video_codec": "mpegts",
    "live_output_port": 5005,
    "playback_mode": "both",
    "jitter_buffer_packets": 24,
}


def load_config(path: Optional[str] = None) -> Dict[str, object]:
    config = DEFAULT_CONFIG.copy()
    selected_path = path or "lab.json"
    if selected_path and os.path.exists(selected_path):
        with open(selected_path, "r", encoding="utf-8") as handle:
            config.update(json.load(handle))
        ok(f"Config loaded from {selected_path}")
    if config.get("environment_model") != "native_windows":
        warn("Overriding legacy environment_model with native_windows.")
        config["environment_model"] = "native_windows"
    config.setdefault("wpa_password_env", "WIFI_PIPELINE_WPA_PASSWORD")
    config.setdefault("wpa_password", "")
    if not config.get("replay_format_hint"):
        config["replay_format_hint"] = config.get("video_codec") or "raw"
    config.setdefault("corpus_review_threshold", 0.62)
    config.setdefault("corpus_auto_reuse_threshold", 0.88)
    return config


def save_config(config: Dict[str, object], path: str = "lab.json") -> None:
    sanitized = dict(config)
    sanitized["environment_model"] = "native_windows"
    sanitized["wpa_password"] = ""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(sanitized, handle, indent=2)
    ok(f"Config saved to {path}")


def resolve_wpa_password(config: Dict[str, object]) -> str:
    env_name = str(config.get("wpa_password_env") or "").strip()
    if env_name and os.getenv(env_name):
        return os.getenv(env_name, "")
    return str(config.get("wpa_password") or "")


def interactive_config(config: Dict[str, object]) -> Dict[str, object]:
    section("Configuration")
    if confirm("Pick the capture interface from a discovered list?", default=True):
        config["interface"] = pick_interface(str(config.get("interface") or ""))
    else:
        config["interface"] = ask("Capture interface", str(config.get("interface") or ""))

    macs = ask(
        "Target MACs (comma-separated, blank keeps all traffic)",
        ",".join(config.get("target_macs", [])),
    )
    config["target_macs"] = [item.strip() for item in macs.split(",") if item.strip()]
    config["ap_essid"] = ask("AP ESSID for optional Wi-Fi strip", str(config.get("ap_essid") or ""))
    config["video_port"] = ask_int("Target payload port", int(config.get("video_port", 5004)))
    protocol = ask("Transport protocol (udp/tcp)", str(config.get("protocol") or "udp")).lower()
    config["protocol"] = "tcp" if protocol == "tcp" else "udp"
    config["capture_duration"] = ask_int(
        "Capture duration in seconds (0 means manual stop)",
        int(config.get("capture_duration", 60)),
    )
    config["output_dir"] = ask("Output directory", str(config.get("output_dir") or "./pipeline_output"))
    config["custom_header_size"] = ask_int(
        "Bytes to strip after the transport header",
        int(config.get("custom_header_size", 0)),
    )
    config["custom_magic_hex"] = ask(
        "Optional custom magic/header bytes in hex",
        str(config.get("custom_magic_hex") or ""),
    ).replace(" ", "")
    config["preferred_stream_id"] = ask(
        "Preferred stream ID to analyze first (optional)",
        str(config.get("preferred_stream_id") or ""),
    )
    config["min_candidate_bytes"] = ask_int(
        "Minimum bytes for a stream to count as a serious candidate",
        int(config.get("min_candidate_bytes", 4096)),
    )
    config["replay_format_hint"] = ask(
        "Replay format hint (raw/txt/json/xml/jpeg/png/webp/wav/mp3/ogg/flac/aac/mpegts/h264/h265)",
        str(config.get("replay_format_hint") or config.get("video_codec") or "raw"),
    )
    review_threshold = ask(
        "Corpus similarity score to surface an archived match",
        str(config.get("corpus_review_threshold", 0.62)),
    )
    try:
        config["corpus_review_threshold"] = float(review_threshold)
    except ValueError:
        warn(f"Invalid corpus review threshold {review_threshold!r}; keeping {config.get('corpus_review_threshold', 0.62)}.")
    auto_reuse_threshold = ask(
        "Corpus similarity score to auto-reuse archived candidate material",
        str(config.get("corpus_auto_reuse_threshold", 0.88)),
    )
    try:
        config["corpus_auto_reuse_threshold"] = float(auto_reuse_threshold)
    except ValueError:
        warn(
            f"Invalid corpus auto-reuse threshold {auto_reuse_threshold!r}; "
            f"keeping {config.get('corpus_auto_reuse_threshold', 0.88)}."
        )
    config["video_codec"] = str(config.get("replay_format_hint") or "raw")
    config["playback_mode"] = ask(
        "Playback mode (file/ffplay/both)",
        str(config.get("playback_mode") or "both"),
    ).lower()
    config["jitter_buffer_packets"] = ask_int(
        "UDP jitter buffer size in packets",
        int(config.get("jitter_buffer_packets", 24)),
    )

    env_name = ask(
        "Environment variable name for WPA password",
        str(config.get("wpa_password_env") or "WIFI_PIPELINE_WPA_PASSWORD"),
    )
    config["wpa_password_env"] = env_name
    config["wpa_password"] = ""

    if os.getenv(env_name):
        ok(f"Using WPA password from environment variable {env_name}.")
    elif confirm("Provide a session-only WPA password now? It will not be saved to disk.", default=False):
        config["wpa_password"] = ask("WPA password", secret=True)

    if confirm("Save config to lab.json?", default=True):
        save_config(config)
    return config
