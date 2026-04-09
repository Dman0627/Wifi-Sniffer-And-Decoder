from __future__ import annotations

import argparse

from .environment import SUPPORTED_PRODUCT_SUMMARY
from .webapp import DEFAULT_WEB_HOST, DEFAULT_WEB_PORT


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"WiFi payload pipeline - official product modes: {SUPPORTED_PRODUCT_SUMMARY}."
    )
    parser.add_argument("--config", default=None, help="Path to a JSON config file")
    parser.add_argument("--stage", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--pcap", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--decrypted", default=None, help=argparse.SUPPRESS)

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("menu", help="Open the guided dashboard interface (recommended: Linux standalone or Windows + Linux remote capture)")
    subparsers.add_parser("config", help="Launch interactive configuration")

    capture_p = subparsers.add_parser("capture", help="Local capture into a pcap (officially supported on Ubuntu and Raspberry Pi OS; experimental for Windows Wi-Fi and macOS)")
    capture_p.add_argument("--strip-wifi", action="store_true", help="Run airdecap-ng after capture")

    monitor_p = subparsers.add_parser("monitor", help="Local monitor-mode capture (Linux-first; experimental on Windows and macOS)")
    monitor_p.add_argument(
        "--method",
        default=None,
        choices=["airodump", "besside", "tcpdump"],
        help="Handshake capture method (default: value from config / airodump)",
    )

    crack_p = subparsers.add_parser("crack", help="Crack WPA2 PSK from a handshake capture then decrypt with airdecap-ng")
    crack_p.add_argument("--cap", default=None, help="Path to handshake .cap file (auto-detected if omitted)")
    crack_status_p = subparsers.add_parser("crack-status", help="Inspect whether the current WPA crack/decrypt path is actually ready")
    crack_status_p.add_argument("--cap", default=None, help="Path to handshake .cap file (auto-detected if omitted)")

    remote_p = subparsers.add_parser("remote", help="Pull a capture from an Ubuntu or Raspberry Pi OS capture device over SSH/SCP")
    remote_p.add_argument("--host", default=None, help="Remote host in user@host form")
    remote_p.add_argument("--path", default=None, help="Remote file path or directory")
    remote_p.add_argument("--port", default=None, type=int, help="SSH port (default: 22)")
    remote_p.add_argument("--identity", default=None, help="SSH identity file (optional)")
    remote_p.add_argument("--dest", default=None, help="Local destination directory")
    remote_p.add_argument("--no-latest", action="store_true", help="Do not resolve latest file for directory/pattern paths")
    remote_p.add_argument("--watch", action="store_true", help="Keep pulling on an interval")
    remote_p.add_argument("--interval", default=None, type=int, help="Watch interval in seconds")
    remote_p.add_argument("--run", default="none", choices=["none", "extract", "detect", "analyze", "play", "all"], help="Run stages after pull")

    pair_p = subparsers.add_parser("pair-remote", help="Install your SSH public key on an Ubuntu or Raspberry Pi OS remote capture device")
    pair_p.add_argument("--host", default=None, help="Remote host in user@host form")
    pair_p.add_argument("--port", default=None, type=int, help="SSH port (default: 22)")
    pair_p.add_argument("--identity", default=None, help="SSH identity file (private key or .pub)")

    discover_p = subparsers.add_parser("discover-remote", help="Discover appliance-style capture nodes on the local network")
    discover_p.add_argument("--network", action="append", default=None, help="CIDR block to scan, for example 192.168.1.0/24 (repeatable)")
    discover_p.add_argument("--health-port", default=None, type=int, help="Health endpoint port (default: 8741)")
    discover_p.add_argument("--timeout", default=0.35, type=float, help="Per-host HTTP timeout in seconds")
    discover_p.add_argument("--max-hosts", default=64, type=int, help="Maximum IPs to probe across discovered networks")

    bootstrap_p = subparsers.add_parser("bootstrap-remote", help="Prepare an Ubuntu or Raspberry Pi OS remote capture device over SSH")
    bootstrap_p.add_argument("--host", default=None, help="Remote host in user@host form")
    bootstrap_p.add_argument("--port", default=None, type=int, help="SSH port (default: 22)")
    bootstrap_p.add_argument("--identity", default=None, help="SSH identity file (private key or .pub)")
    bootstrap_p.add_argument("--remote-root", default=None, help="Remote install root (default: $HOME/wifi-pipeline)")
    bootstrap_p.add_argument("--capture-dir", default=None, help="Remote capture directory (default: <remote-root>/captures)")
    bootstrap_p.add_argument("--install-mode", default=None, choices=["auto", "native", "bundle"], help="Remote install mode (default: auto)")
    bootstrap_p.add_argument("--install-profile", default=None, choices=["standard", "appliance"], help="Remote install profile (default: appliance)")
    bootstrap_p.add_argument("--health-port", default=None, type=int, help="Health endpoint port for appliance installs (default: 8741)")
    bootstrap_p.add_argument("--skip-packages", action="store_true", help="Do not install capture-side packages")
    bootstrap_p.add_argument("--skip-pair", action="store_true", help="Skip SSH key pairing before bootstrap")

    setup_remote_p = subparsers.add_parser("setup-remote", help="Run the guided first-run Windows setup flow for the official remote-capture mode")
    setup_remote_p.add_argument("--host", default=None, help="Remote host in user@host form")
    setup_remote_p.add_argument("--port", default=None, type=int, help="SSH port (default: 22)")
    setup_remote_p.add_argument("--identity", default=None, help="SSH identity file (private key or .pub)")
    setup_remote_p.add_argument("--interface", default=None, help="Remote capture interface, for example wlan0")
    setup_remote_p.add_argument("--duration", default=None, type=int, help="Default capture duration in seconds")
    setup_remote_p.add_argument("--install-mode", default=None, choices=["auto", "native", "bundle"], help="Bootstrap install mode for the remote device")
    setup_remote_p.add_argument("--install-profile", default=None, choices=["standard", "appliance"], help="Bootstrap install profile for the remote device")
    setup_remote_p.add_argument("--health-port", default=None, type=int, help="Health endpoint port for appliance installs")
    setup_remote_p.add_argument("--dest", default=None, help="Local destination directory")
    setup_remote_p.add_argument("--smoke-test", action="store_true", help="Run a short remote smoke capture after setup")

    start_remote_p = subparsers.add_parser("start-remote", help="Run the official Windows remote-capture flow, pull it back, and optionally process it")
    start_remote_p.add_argument("--host", default=None, help="Remote host in user@host form")
    start_remote_p.add_argument("--port", default=None, type=int, help="SSH port (default: 22)")
    start_remote_p.add_argument("--identity", default=None, help="SSH identity file (private key or .pub)")
    start_remote_p.add_argument("--interface", default=None, help="Remote capture interface, for example wlan0")
    start_remote_p.add_argument("--duration", default=None, type=int, help="Capture duration in seconds")
    start_remote_p.add_argument("--output", default=None, help="Remote output path (optional)")
    start_remote_p.add_argument("--dest", default=None, help="Local destination directory")
    start_remote_p.add_argument("--run", default="all", choices=["none", "extract", "detect", "analyze", "play", "all"], help="Run stages after pull")

    service_remote_p = subparsers.add_parser("remote-service", help="Control the managed remote capture appliance helper")
    service_remote_p.add_argument("action", choices=["start", "stop", "status", "last-capture"])
    service_remote_p.add_argument("--host", default=None, help="Remote host in user@host form")
    service_remote_p.add_argument("--port", default=None, type=int, help="SSH port (default: 22)")
    service_remote_p.add_argument("--identity", default=None, help="SSH identity file (private key or .pub)")
    service_remote_p.add_argument("--interface", default=None, help="Remote capture interface for start")
    service_remote_p.add_argument("--duration", default=None, type=int, help="Capture duration in seconds for start")
    service_remote_p.add_argument("--output", default=None, help="Remote output path for start")

    validate_remote_p = subparsers.add_parser("validate-remote", help="Run the official Windows remote-capture validation flow and write a validation report")
    validate_remote_p.add_argument("--host", default=None, help="Remote host in user@host form")
    validate_remote_p.add_argument("--port", default=None, type=int, help="SSH port (default: 22)")
    validate_remote_p.add_argument("--identity", default=None, help="SSH identity file (private key or .pub)")
    validate_remote_p.add_argument("--interface", default=None, help="Remote capture interface, for example wlan0")
    validate_remote_p.add_argument("--duration", default=None, type=int, help="Smoke-capture duration in seconds")
    validate_remote_p.add_argument("--dest", default=None, help="Local destination directory for the smoke capture")
    validate_remote_p.add_argument("--report", default=None, help="Path to save the JSON validation report")
    validate_remote_p.add_argument("--skip-smoke", action="store_true", help="Run readiness checks only and skip the smoke capture")

    validate_local_p = subparsers.add_parser("validate-local", help="Run the standalone Linux/local validation flow and write a JSON report")
    validate_local_p.add_argument("--interface", default=None, help="Local capture interface, for example wlan0")
    validate_local_p.add_argument("--duration", default=None, type=int, help="Smoke-capture duration in seconds")
    validate_local_p.add_argument("--report", default=None, help="Path to save the JSON validation report")
    validate_local_p.add_argument("--skip-smoke", action="store_true", help="Run readiness checks only and skip the smoke capture")

    wifi_p = subparsers.add_parser(
        "wifi",
        help="Full Wi-Fi pipeline: monitor mode -> handshake capture -> WPA2 crack -> airdecap-ng",
    )
    wifi_p.add_argument("--method", default=None, choices=["airodump", "besside", "tcpdump"])
    wifi_p.add_argument("--decrypted", default=None, help="Directory of decrypted reference units")

    extract_p = subparsers.add_parser("extract", help="Extract payload streams from a pcap")
    extract_p.add_argument("--pcap", required=False, help="Path to an existing pcap/pcapng file")

    detect_p = subparsers.add_parser("detect", help="Run payload detection from the manifest")
    detect_p.add_argument("--manifest", required=False, help="Path to an existing manifest.json")

    analyze_p = subparsers.add_parser("analyze", help="Run cipher heuristics")
    analyze_p.add_argument("--decrypted", required=False, help="Directory containing decrypted reference units")

    enrich_p = subparsers.add_parser("enrich", help="Build artifact metadata and passive triage summaries from extracted units")
    enrich_p.add_argument("--manifest", required=False, help="Path to an existing manifest.json")

    subparsers.add_parser("play", help="Start experimental replay/reconstruction using the last analysis report")
    subparsers.add_parser("corpus", help="Show archived candidate streams and reusable material")

    web_p = subparsers.add_parser("web", help="Open the local browser dashboard")
    web_p.add_argument("--host", default=DEFAULT_WEB_HOST)
    web_p.add_argument("--port", default=DEFAULT_WEB_PORT, type=int)
    web_p.add_argument("--no-browser", action="store_true")

    subparsers.add_parser("deps", help="Check the environment, workflow support tiers, hardware qualification, official modes, and product limits")
    subparsers.add_parser("hardware", help="Show the supported hardware qualification report for this machine")
    subparsers.add_parser("preflight", help="Fail early with exact replay/WPA reasons before long-running decode or replay work")
    release_gate_p = subparsers.add_parser("release-gate", help="Require the real validation matrix and sample analysis reports before calling a release fully validated")
    release_gate_p.add_argument("--ubuntu-report", default=None, help="Path to the Ubuntu standalone validation report")
    release_gate_p.add_argument("--pi-report", default=None, help="Path to the Raspberry Pi OS standalone validation report")
    release_gate_p.add_argument("--windows-report", default=None, help="Path to the Windows remote validation report")
    release_gate_p.add_argument("--sample-report", action="append", default=None, help="Path to an analysis report from a supported decode/replay sample set (repeatable)")
    release_gate_p.add_argument("--write-summary", default=None, help="Optional path to write the computed release-gate summary JSON")

    doctor_p = subparsers.add_parser("doctor", help="Check local tools and optional remote capture setup")
    doctor_p.add_argument("--host", default=None, help="Remote host in user@host form")
    doctor_p.add_argument("--port", default=None, type=int, help="SSH port (default: 22)")
    doctor_p.add_argument("--identity", default=None, help="SSH identity file (private key or .pub)")
    doctor_p.add_argument("--interface", default=None, help="Remote capture interface to verify")

    all_p = subparsers.add_parser("all", help="Run capture/extract/detect/analyze in sequence (all platforms)")
    all_p.add_argument("--pcap", required=False, help="Skip capture and use an existing pcap/pcapng file")
    all_p.add_argument("--decrypted", required=False, help="Directory containing decrypted reference units")
    all_p.add_argument("--strip-wifi", action="store_true", help="Run airdecap-ng before extraction")

    return parser


def map_legacy_stage(args: argparse.Namespace) -> argparse.Namespace:
    stage = str(args.stage or "").lower()
    if not stage:
        return args
    mapping = {
        "capture": "capture",
        "extract": "extract",
        "detect": "detect",
        "analyze": "analyze",
        "live": "play",
        "all": "all",
    }
    args.command = mapping.get(stage)
    return args
