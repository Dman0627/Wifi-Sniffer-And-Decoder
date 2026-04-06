from __future__ import annotations

import json
import os
import sys
from typing import Dict, Optional

from .environment import IS_MACOS, IS_WINDOWS, pick_interface
from .ui import ask, ask_int, confirm, ok, section, warn

DEFAULT_CONFIG = {
    # ── environment ───────────────────────────────────────────────────────────
    "environment_model": (
        "native_windows" if sys.platform.startswith("win")
        else "macos" if sys.platform == "darwin"
        else "linux"
    ),
    # ── capture ───────────────────────────────────────────────────────────────
    "interface": "",
    "target_macs": [],
    "capture_duration": 60,
    "output_dir": "./pipeline_output",
    # ── Wi-Fi / WPA ───────────────────────────────────────────────────────────
    "ap_essid": "",
    "ap_bssid": "",
    "ap_channel": 6,
    "wpa_password": "",
    "wpa_password_env": "WIFI_PIPELINE_WPA_PASSWORD",
    # ── wi-fi lab pipeline (monitor mode + cracking) ─────────────────────────────
    "wordlist_path": "/usr/share/wordlists/rockyou.txt",
    "handshake_timeout": 120,
    "crack_timeout": 600,
    "deauth_count": 10,
    "hashcat_rules": "",
    "monitor_method": "airodump",   # airodump | besside | tcpdump
    # ── remote capture (optional) ──────────────────────────────────────────
    "remote_host": "",
    "remote_path": "",
    "remote_port": 22,
    "remote_identity": "",
    "remote_interface": "",
    "remote_dest_dir": "./pipeline_output/remote_imports",
    "remote_poll_interval": 8,
    # ── extraction ────────────────────────────────────────────────────────────
    "video_port": 5004,
    "protocol": "udp",
    "custom_header_size": 0,
    "custom_magic_hex": "",
    # ── analysis / corpus ─────────────────────────────────────────────────────
    "preferred_stream_id": "",
    "min_candidate_bytes": 4096,
    "replay_format_hint": "raw",
    "corpus_review_threshold": 0.62,
    "corpus_auto_reuse_threshold": 0.88,
    # ── playback ──────────────────────────────────────────────────────────────
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

    # Correct environment_model for the actual running platform so that
    # platform-specific tool lists and capture paths are always consistent.
    if IS_WINDOWS and config.get("environment_model") != "native_windows":
        warn("Overriding environment_model with native_windows on this platform.")
        config["environment_model"] = "native_windows"
    elif IS_MACOS and config.get("environment_model") not in ("macos", "linux"):
        warn("Overriding environment_model with macos on this platform.")
        config["environment_model"] = "macos"
    elif not IS_WINDOWS and not IS_MACOS and config.get("environment_model") == "native_windows":
        warn("Overriding environment_model with linux on this platform.")
        config["environment_model"] = "linux"

    # Back-fill any keys that may be absent in older lab.json files
    config.setdefault("wpa_password_env", "WIFI_PIPELINE_WPA_PASSWORD")
    config.setdefault("wpa_password", "")
    config.setdefault("wordlist_path", "/usr/share/wordlists/rockyou.txt")
    config.setdefault("handshake_timeout", 120)
    config.setdefault("crack_timeout", 600)
    config.setdefault("deauth_count", 10)
    config.setdefault("hashcat_rules", "")
    config.setdefault("monitor_method", "airodump")
    config.setdefault("remote_interface", "")
    if not config.get("replay_format_hint"):
        config["replay_format_hint"] = config.get("video_codec") or "raw"
    config.setdefault("corpus_review_threshold", 0.62)
    config.setdefault("corpus_auto_reuse_threshold", 0.88)
    return config


def save_config(config: Dict[str, object], path: str = "lab.json") -> None:
    sanitized = dict(config)
    # Never persist the raw password to disk
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

    # ── interface ────────────────────────────────────────────────────────────
    if confirm("Pick the capture interface from a discovered list?", default=True):
        config["interface"] = pick_interface(str(config.get("interface") or ""))
    else:
        config["interface"] = ask("Capture interface", str(config.get("interface") or ""))

    macs = ask(
        "Target MACs (comma-separated, blank keeps all traffic)",
        ",".join(config.get("target_macs", [])),
    )
    config["target_macs"] = [item.strip() for item in macs.split(",") if item.strip()]

    # ── Wi-Fi / WPA ──────────────────────────────────────────────────────────
    config["ap_essid"] = ask("AP ESSID for Wi-Fi strip / crack", str(config.get("ap_essid") or ""))
    config["ap_bssid"] = ask("AP BSSID (MAC of access point)", str(config.get("ap_bssid") or ""))
    config["ap_channel"] = ask_int("AP channel", int(config.get("ap_channel", 6)))

    # ── wi-fi lab pipeline ───────────────────────────────────────────────────
    section("Monitor Mode / WPA2 Cracking (wi-fi lab pipeline)")
    config["monitor_method"] = ask(
        "Handshake capture method (airodump/besside/tcpdump)",
        str(config.get("monitor_method") or "airodump"),
    ).lower()
    config["handshake_timeout"] = ask_int(
        "Handshake capture timeout in seconds",
        int(config.get("handshake_timeout", 120)),
    )
    config["deauth_count"] = ask_int(
        "Deauth frames to send (0 = passive capture only)",
        int(config.get("deauth_count", 10)),
    )
    config["wordlist_path"] = ask(
        "Wordlist path for aircrack-ng / hashcat",
        str(config.get("wordlist_path") or "/usr/share/wordlists/rockyou.txt"),
    )
    config["crack_timeout"] = ask_int(
        "Crack timeout in seconds",
        int(config.get("crack_timeout", 600)),
    )
    config["hashcat_rules"] = ask(
        "Hashcat rules file path (optional)",
        str(config.get("hashcat_rules") or ""),
    )

    # ── extraction ───────────────────────────────────────────────────────────
    section("Extraction")
    config["video_port"] = ask_int("Target payload port", int(config.get("video_port", 5004)))
    protocol = ask("Transport protocol (udp/tcp)", str(config.get("protocol") or "udp")).lower()
    config["protocol"] = "tcp" if protocol == "tcp" else "udp"
    config["capture_duration"] = ask_int(
        "Capture duration in seconds (0 = manual stop)",
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

    # ── corpus ───────────────────────────────────────────────────────────────
    review_threshold = ask(
        "Corpus similarity score to surface an archived match",
        str(config.get("corpus_review_threshold", 0.62)),
    )
    try:
        config["corpus_review_threshold"] = float(review_threshold)
    except ValueError:
        warn(f"Invalid value {review_threshold!r}; keeping {config.get('corpus_review_threshold', 0.62)}.")

    auto_reuse_threshold = ask(
        "Corpus similarity score to auto-reuse archived candidate material",
        str(config.get("corpus_auto_reuse_threshold", 0.88)),
    )
    try:
        config["corpus_auto_reuse_threshold"] = float(auto_reuse_threshold)
    except ValueError:
        warn(f"Invalid value {auto_reuse_threshold!r}; keeping {config.get('corpus_auto_reuse_threshold', 0.88)}.")

    config["video_codec"] = str(config.get("replay_format_hint") or "raw")
    config["playback_mode"] = ask(
        "Playback mode (file/ffplay/both)",
        str(config.get("playback_mode") or "both"),
    ).lower()
    config["jitter_buffer_packets"] = ask_int(
        "UDP jitter buffer size in packets",
        int(config.get("jitter_buffer_packets", 24)),
    )

    # ── WPA password (session only, never saved) ──────────────────────────────
    section("WPA Password")
    env_name = ask(
        "Environment variable name for WPA password",
        str(config.get("wpa_password_env") or "WIFI_PIPELINE_WPA_PASSWORD"),
    )
    config["wpa_password_env"] = env_name
    config["wpa_password"] = ""

    if os.getenv(env_name):
        ok(f"Using WPA password from environment variable {env_name}.")
    elif confirm("Provide a session-only WPA password now? (will NOT be saved to disk)", default=False):
        config["wpa_password"] = ask("WPA password", secret=True)

    section("Remote Capture (optional)")
    if confirm("Configure a remote capture source (SSH/SCP)?", default=False):
        config["remote_host"] = ask(
            "Remote host (user@host)",
            str(config.get("remote_host") or ""),
        )
        config["remote_path"] = ask(
            "Remote capture path (file or directory)",
            str(config.get("remote_path") or ""),
        )
        config["remote_port"] = ask_int(
            "Remote SSH port",
            int(config.get("remote_port", 22)),
        )
        config["remote_identity"] = ask(
            "SSH identity file (optional)",
            str(config.get("remote_identity") or ""),
        )
        config["remote_interface"] = ask(
            "Remote capture interface (optional, for start-remote)",
            str(config.get("remote_interface") or "wlan0"),
        )
        config["remote_dest_dir"] = ask(
            "Local import directory",
            str(config.get("remote_dest_dir") or "./pipeline_output/remote_imports"),
        )
        config["remote_poll_interval"] = ask_int(
            "Remote poll interval in seconds",
            int(config.get("remote_poll_interval", 8)),
        )

    if confirm("Save config to lab.json?", default=True):
        save_config(config)
    return config
