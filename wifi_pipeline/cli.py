from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, Optional

from .analysis import CryptoAnalyzer, FormatDetector, _load_manifest, _rank_candidate_streams
from .capture import Capture
from .config import interactive_config, load_config, resolve_wpa_password, save_config
from .corpus import CorpusStore
from .environment import IS_MACOS, IS_WINDOWS, check_environment
from .extract import StreamExtractor
from .playback import ExperimentalPlayback, infer_replay_hint, reconstruct_from_capture
from .ui import (
    BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW,
    ask, banner, choose, confirm, done, err, info, section, warn,
)
from .webapp import DEFAULT_WEB_HOST, DEFAULT_WEB_PORT, serve_dashboard


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _analysis_report_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "analysis_report.json"


def _manifest_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "manifest.json"


def _detection_report_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "detection_report.json"


def _capture_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "raw_capture.pcapng"


def _handshake_path(config: Dict[str, object]) -> Optional[Path]:
    out = Path(str(config.get("output_dir") or "./pipeline_output")).resolve()
    for name in ("airodump_hs-01.cap", "besside_handshakes.cap", "monitor_raw.pcap"):
        p = out / name
        if p.exists():
            return p
    return None


def _decrypted_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "decrypted_wifi.pcapng"


def _load_json(path: Path) -> Optional[Dict[str, object]]:
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_report(config: Dict[str, object]) -> Optional[Dict[str, object]]:
    path = _analysis_report_path(config)
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _shorten(value: str, width: int = 76) -> str:
    if len(value) <= width:
        return value
    return value[: width - 3] + "..."


def _status_label(condition: bool, when_true: str, when_false: str = "missing") -> str:
    if condition:
        return f"{GREEN}{when_true}{RESET}"
    return f"{RED}{when_false}{RESET}"


def _candidate_rows(config: Dict[str, object]) -> list[Dict[str, object]]:
    manifest = _load_json(_manifest_path(config))
    if not manifest:
        return []
    return _rank_candidate_streams(manifest, config)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

def _print_dashboard(config: Dict[str, object]) -> None:
    section("Dashboard")
    capture_path = _capture_path(config)
    manifest_path = _manifest_path(config)
    detection_path = _detection_report_path(config)
    analysis_path = _analysis_report_path(config)
    decrypted = _decrypted_path(config)
    handshake = _handshake_path(config)

    detection = _load_json(detection_path)
    analysis = _load_json(analysis_path)
    corpus_status = CorpusStore(config).status()
    candidate = detection.get("selected_candidate_stream") if detection else None

    interface = str(config.get("interface") or "").strip() or f"{RED}unset{RESET}"
    magic = str(config.get("custom_magic_hex") or "").strip() or f"{DIM}(none){RESET}"
    preferred = str(config.get("preferred_stream_id") or "").strip() or f"{DIM}(auto-pick){RESET}"
    env_model = str(config.get("environment_model") or ("native_windows" if IS_WINDOWS else "macos" if IS_MACOS else "linux"))

    print(f"  {BOLD}Saved Config{RESET}")
    print(f"    Platform         : {env_model}")
    print(f"    Interface        : {interface}")
    print(f"    Target           : {config.get('protocol', 'udp')}/{config.get('video_port', 5004)}")
    print(f"    Output           : {config.get('output_dir', './pipeline_output')}")
    print(f"    Header Strip     : {config.get('custom_header_size', 0)} bytes")
    print(f"    Custom Magic     : {magic}")
    print(f"    Preferred Stream : {_shorten(str(preferred), 84)}")
    print(f"    Replay Hint      : {config.get('replay_format_hint') or config.get('video_codec') or 'raw'}")
    print(f"    Corpus Reuse     : review {config.get('corpus_review_threshold', 0.62)} / auto {config.get('corpus_auto_reuse_threshold', 0.88)}")

    print(f"\n  {BOLD}Wi-Fi / Piracy Pipeline{RESET}")
    print(f"    AP ESSID         : {config.get('ap_essid') or f'{DIM}(unset){RESET}'}")
    print(f"    AP BSSID         : {config.get('ap_bssid') or f'{DIM}(unset){RESET}'}")
    print(f"    AP Channel       : {config.get('ap_channel', 6)}")
    print(f"    Monitor Method   : {config.get('monitor_method', 'airodump')}")
    print(f"    Wordlist         : {config.get('wordlist_path') or f'{DIM}(unset){RESET}'}")
    wpa_available = bool(resolve_wpa_password(config))
    print(f"    WPA Password     : {_status_label(wpa_available, 'set (env/session)', 'not set')}")

    print(f"\n  {BOLD}Artifacts{RESET}")
    print(f"    Capture          : {_status_label(capture_path.exists(), 'ready')}")
    print(f"    Handshake        : {_status_label(bool(handshake), 'ready')}")
    print(f"    Decrypted Pcap   : {_status_label(decrypted.exists(), 'ready')}")
    print(f"    Manifest         : {_status_label(manifest_path.exists(), 'ready')}")
    print(f"    Detection Report : {_status_label(detection_path.exists(), 'ready')}")
    print(f"    Analysis Report  : {_status_label(analysis_path.exists(), 'ready')}")

    if detection:
        top_count = len(detection.get("top_streams", []))
        print(f"\n  {BOLD}Candidate Payloads{RESET}")
        print(f"    Ranked Streams   : {top_count}")
        if candidate:
            print(f"    Selected         : {_shorten(str(candidate.get('stream_id') or ''), 84)}")
            print(f"    Class / Score    : {candidate.get('candidate_class', 'unknown')} / {candidate.get('score', '?')}")
    else:
        print(f"\n  {BOLD}Candidate Payloads{RESET}")
        print(f"    Ranked Streams   : {DIM}run detect first{RESET}")

    print(f"\n  {BOLD}Corpus Archive{RESET}")
    print(f"    Archived Streams : {corpus_status.get('entry_count', 0)}")
    print(f"    Reusable Material: {corpus_status.get('candidate_material_count', 0)}")
    latest_entry = corpus_status.get("latest_entry") or {}
    if latest_entry:
        print(f"    Latest Entry     : {_shorten(str(latest_entry.get('entry_id') or ''), 84)}")

    if analysis:
        hypotheses = analysis.get("hypotheses", [])
        hypothesis = str(hypotheses[0].get("name") or "") if hypotheses else ""
        print(f"\n  {BOLD}Latest Analysis{RESET}")
        print(f"    Units Analyzed   : {analysis.get('total_units', 0)}")
        print(f"    Entropy          : {analysis.get('ciphertext_observations', {}).get('average_entropy', '?')}")
        print(f"    Lead Hypothesis  : {hypothesis or f'{DIM}(none){RESET}'}")
        corpus = analysis.get("corpus") or {}
        best_match = corpus.get("best_match") or {}
        if best_match:
            print(
                f"    Best Corpus Match: {_shorten(str(best_match.get('entry_id') or ''), 40)} "
                f"({best_match.get('similarity', '?')})"
            )
        if corpus.get("reused_candidate_material"):
            print(f"    Corpus Reuse     : {GREEN}yes{RESET}")


# ---------------------------------------------------------------------------
# Report / candidate helpers
# ---------------------------------------------------------------------------

def _show_corpus_summary(config: Dict[str, object], limit: int = 8) -> None:
    section("Corpus Archive")
    corpus = CorpusStore(config)
    status = corpus.status()
    print(f"  {BOLD}Stored Candidates{RESET}")
    print(f"    Archived Streams : {status.get('entry_count', 0)}")
    print(f"    Reusable Material: {status.get('candidate_material_count', 0)}")

    entries = corpus.recent_entries(limit=limit)
    if not entries:
        warn("No corpus entries yet. Run analyze on a capture first.")
        return

    print(f"\n  {BOLD}Recent Entries{RESET}")
    for entry in entries:
        similarity_hint = " material" if entry.get("candidate_material_available") else ""
        print(
            f"    {entry.get('entry_id')} "
            f"[{entry.get('candidate_class', 'unknown')}, {entry.get('dominant_unit_type', 'opaque_chunk')}{similarity_hint}]"
        )
        print(f"      {_shorten(str(entry.get('stream_id') or ''), 88)}")


def _show_report_summary(config: Dict[str, object]) -> None:
    section("Latest Reports")
    detection = _load_json(_detection_report_path(config))
    analysis = _load_json(_analysis_report_path(config))

    if detection:
        selected = detection.get("selected_candidate_stream") or {}
        print(f"  {BOLD}Detection{RESET}")
        print(f"    Average Entropy  : {detection.get('average_entropy', '?')}")
        print(f"    Opaque Hits      : {detection.get('protocol_hits', {}).get('opaque', 0)}")
        print(f"    Selected Stream  : {_shorten(str(selected.get('stream_id') or '(none)'), 84)}")
        print(f"    Candidate Class  : {selected.get('candidate_class', '(none)')}")
    else:
        warn("No detection report found yet.")

    if analysis:
        selected = analysis.get("selected_candidate_stream") or {}
        hypotheses = analysis.get("hypotheses", [])
        recommendations = analysis.get("recommendations", [])
        print(f"\n  {BOLD}Analysis{RESET}")
        print(f"    Units Analyzed   : {analysis.get('total_units', 0)}")
        print(f"    Chi-Squared      : {analysis.get('ciphertext_observations', {}).get('chi_squared', '?')}")
        print(f"    Selected Stream  : {_shorten(str(selected.get('stream_id') or '(none)'), 84)}")
        if hypotheses:
            print(f"    Top Hypothesis   : {hypotheses[0].get('name', '(none)')}")
        if recommendations:
            print(f"    Recommendation   : {_shorten(str(recommendations[0]), 84)}")
        corpus = analysis.get("corpus") or {}
        best_match = corpus.get("best_match") or {}
        if best_match:
            print(
                f"    Corpus Match     : {_shorten(str(best_match.get('entry_id') or '(none)'), 32)} "
                f"({best_match.get('similarity', '?')})"
            )
        if corpus.get("reused_candidate_material"):
            print(f"    Reused Material  : yes")
    else:
        warn("No analysis report found yet.")


def _show_candidate_streams(config: Dict[str, object], limit: int = 10) -> list[Dict[str, object]]:
    section("Candidate Payloads")
    rows = _candidate_rows(config)
    if not rows:
        warn("No ranked streams yet. Run extract and detect first.")
        return []

    for index, row in enumerate(rows[:limit], start=1):
        label = f"[{index}] {row['candidate_class']} score={row['score']} bytes={row['byte_count']}"
        print(f"  {CYAN}{label}{RESET}")
        print(f"      {_shorten(str(row['stream_id']), 88)}")
        if row.get("reasons"):
            print(f"      {DIM}{_shorten('; '.join(row['reasons']), 88)}{RESET}")
    return rows


def _pick_preferred_stream(config: Dict[str, object]) -> Dict[str, object]:
    rows = _show_candidate_streams(config)
    if not rows:
        return config

    options = ["Clear preferred stream"]
    for row in rows[:10]:
        options.append(_shorten(f"{row['candidate_class']} | {row['score']} | {row['stream_id']}", 88))
    current = str(config.get("preferred_stream_id") or "").strip()
    default = 0
    for index, row in enumerate(rows[:10], start=1):
        if row.get("stream_id") == current:
            default = index
            break

    selection = choose("Choose a stream to pin for analysis", options, default=default)
    if selection == 0:
        config["preferred_stream_id"] = ""
        save_config(config)
        ok("Preferred stream cleared.")
        return config

    selected = rows[selection - 1]
    config["preferred_stream_id"] = selected["stream_id"]
    save_config(config)
    ok(f"Pinned preferred stream: {selected['stream_id']}")
    return config


def _edit_device_hints(config: Dict[str, object]) -> Dict[str, object]:
    section("Device Hints")
    magic = ask(
        "Custom magic/header bytes in hex (blank clears it)",
        str(config.get("custom_magic_hex") or ""),
    ).replace(" ", "")
    config["custom_magic_hex"] = magic
    header_size = ask(
        "Bytes to strip after the transport header",
        str(config.get("custom_header_size") or 0),
    )
    try:
        config["custom_header_size"] = max(0, int(header_size))
    except ValueError:
        warn(f"Invalid header size {header_size!r}; keeping {config.get('custom_header_size', 0)}.")
    min_bytes = ask(
        "Minimum stream bytes to count as a serious candidate",
        str(config.get("min_candidate_bytes") or 4096),
    )
    try:
        config["min_candidate_bytes"] = max(1, int(min_bytes))
    except ValueError:
        warn(f"Invalid value {min_bytes!r}; keeping {config.get('min_candidate_bytes', 4096)}.")
    replay_hint = ask(
        "Replay/output format hint",
        str(config.get("replay_format_hint") or config.get("video_codec") or "raw"),
    )
    config["replay_format_hint"] = replay_hint
    config["video_codec"] = replay_hint
    review_threshold = ask(
        "Corpus similarity threshold (surface match)",
        str(config.get("corpus_review_threshold") or 0.62),
    )
    try:
        config["corpus_review_threshold"] = float(review_threshold)
    except ValueError:
        warn(f"Invalid value {review_threshold!r}; keeping {config.get('corpus_review_threshold', 0.62)}.")
    auto_reuse_threshold = ask(
        "Corpus similarity threshold (auto-reuse material)",
        str(config.get("corpus_auto_reuse_threshold") or 0.88),
    )
    try:
        config["corpus_auto_reuse_threshold"] = float(auto_reuse_threshold)
    except ValueError:
        warn(f"Invalid value {auto_reuse_threshold!r}; keeping {config.get('corpus_auto_reuse_threshold', 0.88)}.")
    save_config(config)
    ok("Device hints saved.")
    return config


# ---------------------------------------------------------------------------
# Stage runners
# ---------------------------------------------------------------------------

def run_capture(config: Dict[str, object], strip_wifi: bool = False) -> Optional[str]:
    capture = Capture(config)
    pcap_path = capture.run()
    if not pcap_path:
        return None
    if strip_wifi:
        return capture.strip_wifi_layer(pcap_path)
    return pcap_path


def run_monitor(config: Dict[str, object], method: Optional[str] = None) -> Optional[str]:
    """Enable monitor mode and capture raw 802.11 frames (Linux/Kali and macOS)."""
    capture = Capture(config)
    chosen_method = method or str(config.get("monitor_method") or "airodump")
    return capture.run_monitor(method=chosen_method)


def run_crack_decrypt(config: Dict[str, object], handshake_cap: Optional[str] = None) -> Optional[str]:
    """Crack WPA2 PSK from a handshake capture then run airdecap-ng."""
    capture = Capture(config)
    return capture.crack_and_decrypt(handshake_cap=handshake_cap)


def run_wifi_pipeline(config: Dict[str, object], method: Optional[str] = None) -> Optional[str]:
    """Full wi-fi lab pipeline: monitor → handshake → crack → airdecap-ng → returns decrypted pcap."""
    capture = Capture(config)
    chosen_method = method or str(config.get("monitor_method") or "airodump")
    return capture.run_full_wifi_pipeline(method=chosen_method)


def run_extract(config: Dict[str, object], pcap_path: Optional[str]) -> Optional[Dict[str, object]]:
    if not pcap_path:
        # Prefer decrypted pcap if it exists
        dec = _decrypted_path(config)
        default_path = dec if dec.exists() else _capture_path(config)
        if default_path.exists():
            pcap_path = str(default_path)
        else:
            err("No pcap path supplied and no default capture exists.")
            return None
    return StreamExtractor(config).extract(pcap_path)


def run_detect(config: Dict[str, object], manifest_path: Optional[str] = None) -> Optional[Dict[str, object]]:
    return FormatDetector(config).detect(manifest_path)


def run_analyze(config: Dict[str, object], decrypted_dir: Optional[str]) -> Optional[Dict[str, object]]:
    return CryptoAnalyzer(config).analyze(decrypted_dir)


def run_play(config: Dict[str, object]) -> Optional[str]:
    report = _load_report(config)
    if not report:
        err("No analysis report found. Run analyze first.")
        return None
    candidate = dict(report.get("candidate_material") or {})
    if not candidate:
        err("The last analysis report did not produce any experimental replay material.")
        return None
    config_for_play = dict(config)
    config_for_play["replay_format_hint"] = infer_replay_hint(config, report)
    reconstructed = reconstruct_from_capture(config_for_play, report)
    if reconstructed:
        return reconstructed
    return ExperimentalPlayback(config_for_play, candidate).start()


def run_all(
    config: Dict[str, object],
    pcap_path: Optional[str],
    decrypted_dir: Optional[str],
    strip_wifi: bool,
) -> None:
    source = pcap_path or run_capture(config, strip_wifi=strip_wifi)
    if not source:
        return
    run_extract(config, source)
    run_detect(config)
    report = run_analyze(config, decrypted_dir)
    if report and report.get("candidate_material"):
        run_play(config)


def run_all_wifi(
    config: Dict[str, object],
    decrypted_dir: Optional[str],
    method: Optional[str],
) -> None:
    """Full end-to-end pipeline including monitor mode + WPA2 crack."""
    decrypted_pcap = run_wifi_pipeline(config, method=method)
    source = decrypted_pcap or str(_capture_path(config))
    run_extract(config, source)
    run_detect(config)
    report = run_analyze(config, decrypted_dir)
    if report and report.get("candidate_material"):
        run_play(config)


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

def interactive_menu(config: Dict[str, object]) -> int:
    while True:
        _print_dashboard(config)
        report = _load_report(config)
        has_candidate = bool(report and report.get("candidate_material"))
        options = [
            "Guided setup / configure device",                    # 0
            "Capture traffic (dumpcap / tcpdump fallback)",       # 1
            "Monitor mode capture (Linux / macOS)",               # 2
            "Crack WPA2 + decrypt pcap",                          # 3
            "Strip Wi-Fi layer on an existing pcap",              # 4
            "Extract payload streams from a pcap",                # 5
            "Run payload detection",                              # 6
            "Review candidate payloads",                          # 7
            "Pin a preferred candidate stream",                   # 8
            "Edit custom stream hints",                           # 9
            "Run cipher heuristics",                              # 10
            "Start experimental replay / reconstruction",         # 11
            "Run full pipeline (dumpcap / tcpdump capture)",      # 12
            "Run full Wi-Fi pipeline (Linux/macOS monitor+crack)",# 13
            "Show latest report summary",                         # 14
            "Show corpus archive",                                # 15
            "Launch web dashboard",                               # 16
            "Check environment",                                  # 17
            "Exit",                                               # 18
        ]
        default = 11 if has_candidate else (1 if IS_WINDOWS else 2)
        selection = choose("Select an action", options, default=default)

        if selection == 0:
            config = interactive_config(config)
        elif selection == 1:
            strip_wifi = confirm("Run Wi-Fi layer strip after capture?", default=bool(resolve_wpa_password(config)))
            run_capture(config, strip_wifi=strip_wifi)
        elif selection == 2:
            method = ask("Capture method (airodump/besside/tcpdump)", str(config.get("monitor_method") or "airodump"))
            run_monitor(config, method=method)
        elif selection == 3:
            cap = ask("Path to handshake .cap (blank = auto-detect)", "").strip() or None
            run_crack_decrypt(config, handshake_cap=cap)
        elif selection == 4:
            source = input("  > Path to existing pcap: ").strip()
            if source:
                Capture(config).strip_wifi_layer(source)
        elif selection == 5:
            source = ask("Path to pcap (blank = auto)", "").strip() or None
            run_extract(config, source)
        elif selection == 6:
            run_detect(config)
        elif selection == 7:
            _show_candidate_streams(config)
        elif selection == 8:
            config = _pick_preferred_stream(config)
        elif selection == 9:
            config = _edit_device_hints(config)
        elif selection == 10:
            decrypted = input("  > Directory of decrypted reference units (optional): ").strip() or None
            run_analyze(config, decrypted)
        elif selection == 11:
            run_play(config)
        elif selection == 12:
            decrypted = input("  > Directory of decrypted reference units (optional): ").strip() or None
            strip_wifi = confirm("Strip the Wi-Fi layer when possible?", default=bool(resolve_wpa_password(config)))
            run_all(config, None, decrypted, strip_wifi)
        elif selection == 13:
            decrypted = input("  > Directory of decrypted reference units (optional): ").strip() or None
            method = ask("Capture method (airodump/besside/tcpdump)", str(config.get("monitor_method") or "airodump"))
            run_all_wifi(config, decrypted_dir=decrypted, method=method)
        elif selection == 14:
            _show_report_summary(config)
        elif selection == 15:
            _show_corpus_summary(config)
        elif selection == 16:
            serve_dashboard()
        elif selection == 17:
            check_environment()
        else:
            info("Goodbye.")
            return 0

        input("\n  Press Enter to continue...")


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="WiFi payload pipeline — Windows capture + Linux monitor/crack + flow extraction."
    )
    parser.add_argument("--config", default=None, help="Path to a JSON config file")
    parser.add_argument("--stage", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--pcap", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--decrypted", default=None, help=argparse.SUPPRESS)

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("menu", help="Open the guided dashboard interface")
    subparsers.add_parser("config", help="Launch interactive configuration")

    # ── Standard capture (all platforms) ─────────────────────────────────────
    capture_p = subparsers.add_parser("capture", help="Capture traffic into a pcap (dumpcap, or tcpdump fallback)")
    capture_p.add_argument("--strip-wifi", action="store_true", help="Run airdecap-ng after capture")

    # ── Linux / macOS monitor mode ────────────────────────────────────────────
    monitor_p = subparsers.add_parser("monitor", help="Enable monitor mode and capture raw 802.11 frames (Linux/Kali and macOS)")
    monitor_p.add_argument(
        "--method",
        default=None,
        choices=["airodump", "besside", "tcpdump"],
        help="Handshake capture method (default: value from config / airodump)",
    )

    # ── WPA2 crack + decrypt ─────────────────────────────────────────────────
    crack_p = subparsers.add_parser("crack", help="Crack WPA2 PSK from a handshake capture then decrypt with airdecap-ng")
    crack_p.add_argument("--cap", default=None, help="Path to handshake .cap file (auto-detected if omitted)")

    # ── Full Linux Wi-Fi pipeline ────────────────────────────────────────────
    wifi_p = subparsers.add_parser(
        "wifi",
        help="Full Linux pipeline: monitor mode → handshake capture → WPA2 crack → airdecap-ng",
    )
    wifi_p.add_argument("--method", default=None, choices=["airodump", "besside", "tcpdump"])
    wifi_p.add_argument("--decrypted", default=None, help="Directory of decrypted reference units")

    # ── Extract / detect / analyze / play ────────────────────────────────────
    extract_p = subparsers.add_parser("extract", help="Extract payload streams from a pcap")
    extract_p.add_argument("--pcap", required=False, help="Path to an existing pcap/pcapng file")

    detect_p = subparsers.add_parser("detect", help="Run payload detection from the manifest")
    detect_p.add_argument("--manifest", required=False, help="Path to an existing manifest.json")

    analyze_p = subparsers.add_parser("analyze", help="Run cipher heuristics")
    analyze_p.add_argument("--decrypted", required=False, help="Directory containing decrypted reference units")

    subparsers.add_parser("play", help="Start experimental replay/reconstruction using the last analysis report")
    subparsers.add_parser("corpus", help="Show archived candidate streams and reusable material")

    web_p = subparsers.add_parser("web", help="Open the local browser dashboard")
    web_p.add_argument("--host", default=DEFAULT_WEB_HOST)
    web_p.add_argument("--port", default=DEFAULT_WEB_PORT, type=int)
    web_p.add_argument("--no-browser", action="store_true")

    subparsers.add_parser("deps", help="Check the native environment (Windows, Linux, or macOS)")

    all_p = subparsers.add_parser("all", help="Run capture/extract/detect/analyze in sequence (all platforms)")
    all_p.add_argument("--pcap", required=False, help="Skip capture and use an existing pcap/pcapng file")
    all_p.add_argument("--decrypted", required=False, help="Directory containing decrypted reference units")
    all_p.add_argument("--strip-wifi", action="store_true", help="Run airdecap-ng before extraction")

    return parser


def _map_legacy_stage(args: argparse.Namespace) -> argparse.Namespace:
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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args = _map_legacy_stage(args)

    banner()
    config = load_config(args.config)

    if args.command == "deps":
        return 0 if check_environment() else 1

    if args.command == "menu":
        return interactive_menu(config)

    if args.command == "config":
        interactive_config(config)
        return 0

    if args.command == "capture":
        run_capture(config, strip_wifi=bool(getattr(args, "strip_wifi", False)))
        return 0

    if args.command == "monitor":
        method = getattr(args, "method", None) or str(config.get("monitor_method") or "airodump")
        result = run_monitor(config, method=method)
        if result:
            done(f"Monitor capture: {result}")
        return 0 if result else 1

    if args.command == "crack":
        cap = getattr(args, "cap", None)
        result = run_crack_decrypt(config, handshake_cap=cap)
        if result:
            done(f"Decrypted pcap: {result}")
        return 0 if result else 1

    if args.command == "wifi":
        method = getattr(args, "method", None) or str(config.get("monitor_method") or "airodump")
        decrypted_dir = getattr(args, "decrypted", None)
        run_all_wifi(config, decrypted_dir=decrypted_dir, method=method)
        return 0

    if args.command == "extract":
        run_extract(config, getattr(args, "pcap", None))
        return 0

    if args.command == "detect":
        run_detect(config, getattr(args, "manifest", None))
        return 0

    if args.command == "analyze":
        run_analyze(config, getattr(args, "decrypted", None))
        return 0

    if args.command == "play":
        run_play(config)
        return 0

    if args.command == "corpus":
        _show_corpus_summary(config)
        return 0

    if args.command == "web":
        serve_dashboard(
            config_path=args.config,
            host=str(getattr(args, "host", DEFAULT_WEB_HOST)),
            port=int(getattr(args, "port", DEFAULT_WEB_PORT)),
            open_browser=not bool(getattr(args, "no_browser", False)),
        )
        return 0

    if args.command == "all":
        run_all(
            config,
            getattr(args, "pcap", None),
            getattr(args, "decrypted", None),
            bool(getattr(args, "strip_wifi", False)),
        )
        return 0

    return interactive_menu(config)


if __name__ == "__main__":
    raise SystemExit(main())