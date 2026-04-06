from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, Optional

from .analysis import CryptoAnalyzer, FormatDetector, _load_manifest, _rank_candidate_streams
from .capture import Capture
from .config import interactive_config, load_config, resolve_wpa_password, save_config
from .corpus import CorpusStore
from .environment import IS_MACOS, IS_WINDOWS, check_environment
from .extract import StreamExtractor
from .playback import ExperimentalPlayback, infer_replay_hint, reconstruct_from_capture
from .remote import (
    bootstrap_remote_host,
    doctor_remote_host,
    pair_remote_host,
    pull_remote_capture,
    remote_service_host,
    start_remote_capture,
    watch_remote_capture,
)
from .ui import (
    BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW,
    ask, ask_int, banner, choose, confirm, done, err, info, section, warn,
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


def _validation_report_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "validation_report.json"


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


def _run_after_pull(config: Dict[str, object], pcap_path: str, mode: str) -> None:
    run_extract(config, pcap_path)
    if mode in ("detect", "analyze", "play", "all"):
        run_detect(config)
    if mode in ("analyze", "play", "all"):
        run_analyze(config, None)
    if mode in ("play", "all"):
        run_play(config)


def run_pair_remote(
    config: Dict[str, object],
    host: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
) -> bool:
    return pair_remote_host(config, host=host, port=port, identity=identity)


def run_bootstrap_remote(
    config: Dict[str, object],
    host: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    remote_root: Optional[str] = None,
    capture_dir: Optional[str] = None,
    install_packages: bool = True,
    pair: bool = True,
) -> Optional[Dict[str, str]]:
    return bootstrap_remote_host(
        config,
        host=host,
        port=port,
        identity=identity,
        remote_root=remote_root,
        capture_dir=capture_dir,
        install_packages=install_packages,
        pair=pair,
    )


def run_start_remote(
    config: Dict[str, object],
    host: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    interface: Optional[str] = None,
    duration: Optional[int] = None,
    output: Optional[str] = None,
    dest_dir: Optional[str] = None,
    run_mode: str = "none",
) -> Optional[str]:
    pulled = start_remote_capture(
        config,
        host=host,
        port=port,
        identity=identity,
        interface=interface,
        duration=duration,
        output=output,
        dest_dir=dest_dir,
    )
    if pulled and run_mode != "none":
        _run_after_pull(config, str(pulled), run_mode)
    return str(pulled) if pulled else None


def run_remote_service(
    config: Dict[str, object],
    action: str,
    host: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    interface: Optional[str] = None,
    duration: Optional[int] = None,
    output: Optional[str] = None,
) -> bool:
    result = remote_service_host(
        config,
        action,
        host=host,
        port=port,
        identity=identity,
        interface=interface,
        duration=duration,
        output=output,
    )
    return bool(result)


def run_setup_remote(
    config: Dict[str, object],
    *,
    config_path: Optional[str] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    interface: Optional[str] = None,
    dest_dir: Optional[str] = None,
    duration: Optional[int] = None,
    smoke_test: bool = False,
) -> bool:
    section("Windows Remote Setup")
    if IS_WINDOWS:
        info("This guided setup is optimized for the supported Windows controller workflow.")
    else:
        warn("This guided setup is Windows-first, but it can still prepare the supported remote capture path.")

    resolved_host = (host if host is not None else ask("Remote host (user@host)", str(config.get("remote_host") or "pi@raspberrypi"))).strip()
    if not resolved_host:
        err("Remote host is required for setup.")
        return False

    resolved_port = int(port if port is not None else ask_int("Remote SSH port", int(config.get("remote_port", 22) or 22)))
    resolved_identity = (
        str(identity).strip()
        if identity is not None
        else ask("SSH identity file (optional)", str(config.get("remote_identity") or "")).strip()
    )
    resolved_interface = (
        str(interface).strip()
        if interface is not None
        else ask("Remote capture interface", str(config.get("remote_interface") or "wlan0")).strip()
    )
    if not resolved_interface:
        err("Remote capture interface is required for setup.")
        return False

    resolved_dest = (
        str(dest_dir).strip()
        if dest_dir is not None
        else ask("Local import directory", str(config.get("remote_dest_dir") or "./pipeline_output/remote_imports")).strip()
    )
    resolved_duration = int(
        duration if duration is not None else ask_int("Default remote capture duration in seconds", int(config.get("capture_duration", 60) or 60))
    )
    if resolved_duration <= 0:
        warn("Default capture duration must be positive; using 60 seconds.")
        resolved_duration = 60

    config["remote_host"] = resolved_host
    config["remote_port"] = resolved_port
    config["remote_identity"] = resolved_identity
    config["remote_interface"] = resolved_interface
    config["remote_dest_dir"] = resolved_dest
    config["capture_duration"] = resolved_duration

    save_target = config_path or "lab.json"
    save_config(config, save_target)
    info("Running the supported first-run flow: pair -> bootstrap -> doctor.")
    if not run_pair_remote(config, host=resolved_host, port=resolved_port, identity=resolved_identity or None):
        return False

    bootstrap_result = run_bootstrap_remote(
        config,
        host=resolved_host,
        port=resolved_port,
        identity=resolved_identity or None,
        install_packages=True,
        pair=False,
    )
    if not bootstrap_result:
        return False

    capture_dir = str(bootstrap_result.get("capture_dir") or "").strip()
    if capture_dir:
        config["remote_path"] = capture_dir.rstrip("/") + "/"
    save_config(config, save_target)

    doctor_ok = run_doctor(
        config,
        host=resolved_host,
        port=resolved_port,
        identity=resolved_identity or None,
        interface=resolved_interface,
    )
    if not doctor_ok:
        warn("Setup saved your config, but doctor still found issues.")
        return False

    if smoke_test:
        smoke_duration = min(max(5, resolved_duration), 15)
        info(f"Running a short smoke capture ({smoke_duration}s) to validate the full remote path.")
        if not run_start_remote(
            config,
            host=resolved_host,
            port=resolved_port,
            identity=resolved_identity or None,
            interface=resolved_interface,
            duration=smoke_duration,
            run_mode="none",
        ):
            warn("Setup completed, but the smoke capture did not finish cleanly.")
            return False

    done("Windows remote setup complete.")
    info(r"Next run: .\run_remote.ps1 -Host %s -Interface %s -DoctorFirst" % (resolved_host, resolved_interface))
    return True


def _print_remote_doctor(report: Dict[str, object]) -> None:
    section("Remote Doctor")
    local = dict(report.get("local") or {})
    remote = dict(report.get("remote") or {})
    host = str(report.get("host") or "(unset)")

    print(f"  {BOLD}Target{RESET}")
    print(f"    Host             : {host}")

    print(f"\n  {BOLD}Local SSH Prereqs{RESET}")
    print(f"    ssh              : {_status_label(bool(local.get('ssh')), 'ready')}")
    if local.get("ssh_path"):
        print(f"    ssh path         : {local.get('ssh_path')}")
    print(f"    scp              : {_status_label(bool(local.get('scp')), 'ready')}")
    if local.get("scp_path"):
        print(f"    scp path         : {local.get('scp_path')}")
    public_key_ok = bool(local.get("public_key"))
    print(f"    Public key       : {_status_label(public_key_ok, 'present', 'not found')}")
    if local.get("public_key_path"):
        print(f"    Public key path  : {local.get('public_key_path')}")

    print(f"\n  {BOLD}Remote Setup{RESET}")
    print(f"    Reachable        : {_status_label(bool(remote.get('reachable')), 'yes', 'no')}")
    if remote.get("home"):
        print(f"    Home             : {remote.get('home')}")
    print(f"    tcpdump          : {_status_label(bool(remote.get('tcpdump')), 'present', 'missing')}")
    print(f"    Helper           : {_status_label(bool(remote.get('helper')), 'present', 'missing')}")
    if remote.get("helper_path"):
        print(f"    Helper path      : {remote.get('helper_path')}")
    service_state = str(remote.get("service_status") or "missing")
    if service_state == "running":
        service_label = f"{YELLOW}running{RESET}"
    elif service_state == "idle":
        service_label = _status_label(True, "ready")
    elif service_state == "failed":
        service_label = _status_label(False, "ready", "failed")
    else:
        service_label = _status_label(False, "ready", "missing")
    print(f"    Service          : {_status_label(bool(remote.get('service')), 'present', 'missing')}")
    print(f"    Service status   : {service_label}")
    if remote.get("service_path"):
        print(f"    Service path     : {remote.get('service_path')}")
    state_dir = str(remote.get("state_dir") or "")
    print(f"    State dir        : {_status_label(bool(remote.get('state_dir_exists')), 'present', 'missing')}")
    if state_dir:
        print(f"    State dir path   : {state_dir}")
    print(f"    State writable   : {_status_label(bool(remote.get('state_dir_writable')), 'yes', 'no')}")
    privilege_mode = str(remote.get("privilege_mode") or "fallback")
    privilege_ready = privilege_mode in ("sudoers_runner", "root_session")
    if privilege_mode == "sudoers_runner":
        privilege_label = _status_label(True, "hardened")
    elif privilege_mode == "root_session":
        privilege_label = f"{YELLOW}root session only{RESET}"
    else:
        privilege_label = _status_label(False, "hardened", "fallback")
    print(f"    Privilege mode   : {privilege_label}")
    print(f"    Privileged runner: {_status_label(bool(remote.get('privileged_runner')), 'present', 'missing')}")
    if remote.get("privileged_runner_path"):
        print(f"    Runner path      : {remote.get('privileged_runner_path')}")
    capture_dir = str(remote.get("capture_dir") or "")
    print(f"    Capture dir      : {_status_label(bool(remote.get('capture_dir_exists')), 'present', 'missing')}")
    if capture_dir:
        print(f"    Capture dir path : {capture_dir}")
    print(f"    Capture writable : {_status_label(bool(remote.get('capture_dir_writable')), 'yes', 'no')}")
    has_last_capture = bool(remote.get("remote_size_bytes")) or bool(remote.get("checksum_value"))
    if has_last_capture:
        print(f"    Last marker      : {_status_label(bool(remote.get('complete_marker')), 'present', 'missing')}")
        print(f"    Last checksum    : {_status_label(bool(remote.get('checksum_file')), 'present', 'missing')}")
        if remote.get("remote_size_bytes"):
            print(f"    Last size        : {remote.get('remote_size_bytes')} bytes")
    interface_name = str(remote.get("interface") or "").strip()
    if interface_name:
        interface_exists = remote.get("interface_exists")
        if interface_exists is True:
            label = _status_label(True, "present")
        elif interface_exists is False:
            label = _status_label(False, "present", "missing")
        else:
            label = f"{YELLOW}unknown{RESET}"
        print(f"    Interface        : {interface_name} ({label})")
    if not privilege_ready:
        print(f"    Next step        : re-run bootstrap-remote with a remote user that has sudo access")


def run_doctor(
    config: Dict[str, object],
    host: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    interface: Optional[str] = None,
) -> bool:
    section("Doctor")
    local_ok = check_environment()
    remote_host = host or str(config.get("remote_host") or "").strip() or None
    if not remote_host:
        info("No remote host configured. Skipping remote doctor checks.")
        return local_ok

    report = doctor_remote_host(
        config,
        host=remote_host,
        port=port,
        identity=identity,
        interface=interface,
    )
    _print_remote_doctor(report)
    if report.get("ok"):
        done("Doctor checks passed.")
    else:
        warn("Doctor found issues. Fix the missing items above and re-run.")
    return bool(local_ok and report.get("ok"))


def run_validate_remote(
    config: Dict[str, object],
    host: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    interface: Optional[str] = None,
    duration: Optional[int] = None,
    dest_dir: Optional[str] = None,
    report_path: Optional[str] = None,
    skip_smoke: bool = False,
) -> bool:
    section("Supported Validation")
    target_host = host or str(config.get("remote_host") or "").strip() or None
    target_interface = interface or str(config.get("remote_interface") or "").strip() or None
    target_duration = int(duration if duration is not None else min(max(int(config.get("capture_duration", 60) or 60), 10), 30))
    report_file = Path(report_path).resolve() if report_path else _validation_report_path(config)
    report_file.parent.mkdir(parents=True, exist_ok=True)

    validation: Dict[str, object] = {
        "schema_version": 1,
        "validated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "supported_target": "Windows controller/analyzer + Raspberry Pi OS or Ubuntu capture device",
        "inputs": {
            "host": target_host or "",
            "port": int(port if port is not None else config.get("remote_port", 22) or 22),
            "interface": target_interface or "",
            "duration": target_duration,
            "dest_dir": str(dest_dir or config.get("remote_dest_dir") or "./pipeline_output/remote_imports"),
            "skip_smoke": bool(skip_smoke),
        },
        "environment_ok": False,
        "doctor": {},
        "service_status_before": {},
        "smoke_capture": {
            "requested": not skip_smoke,
            "success": False,
            "local_capture_path": "",
            "size_bytes": 0,
        },
        "service_status_after": {},
        "last_capture_after": {},
        "overall_ok": False,
    }

    env_ok = check_environment()
    validation["environment_ok"] = env_ok

    doctor_report = doctor_remote_host(
        config,
        host=target_host,
        port=port,
        identity=identity,
        interface=target_interface,
    )
    validation["doctor"] = doctor_report
    if target_host:
        _print_remote_doctor(doctor_report)

    before_status = remote_service_host(
        config,
        "status",
        host=target_host,
        port=port,
        identity=identity,
    )
    validation["service_status_before"] = before_status or {}

    smoke_success = True
    if not skip_smoke:
        if not target_host or not target_interface:
            warn("Skipping smoke validation because remote host or interface is not configured.")
            smoke_success = False
        else:
            pulled = start_remote_capture(
                config,
                host=target_host,
                port=port,
                identity=identity,
                interface=target_interface,
                duration=target_duration,
                dest_dir=dest_dir,
            )
            if pulled:
                pulled_path = Path(pulled)
                validation["smoke_capture"] = {
                    "requested": True,
                    "success": True,
                    "local_capture_path": str(pulled_path),
                    "size_bytes": pulled_path.stat().st_size if pulled_path.exists() else 0,
                }
            else:
                smoke_success = False
                validation["smoke_capture"] = {
                    "requested": True,
                    "success": False,
                    "local_capture_path": "",
                    "size_bytes": 0,
                }

    after_status = remote_service_host(
        config,
        "status",
        host=target_host,
        port=port,
        identity=identity,
    )
    validation["service_status_after"] = after_status or {}

    last_capture = remote_service_host(
        config,
        "last-capture",
        host=target_host,
        port=port,
        identity=identity,
    )
    validation["last_capture_after"] = last_capture or {}

    overall_ok = bool(env_ok and doctor_report.get("ok") and smoke_success)
    validation["overall_ok"] = overall_ok

    with open(report_file, "w", encoding="utf-8") as handle:
        json.dump(validation, handle, indent=2)

    if overall_ok:
        done(f"Supported validation passed. Report saved to {report_file}")
    else:
        warn(f"Supported validation found issues. Report saved to {report_file}")
    return overall_ok


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
    """Enable monitor mode and capture raw 802.11 frames (Linux/macOS, Windows when supported)."""
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
            "Windows remote setup wizard",                        # 1
            "Capture traffic (dumpcap / tcpdump fallback)",       # 2
            "Pair remote capture device (SSH key install)",       # 3
            "Bootstrap remote capture device",                    # 4
            "Start remote capture, pull, and process",            # 5
            "Pull remote capture (SSH/SCP)",                      # 6
            "Monitor mode capture (airodump/besside/tcpdump)",   # 7
            "Crack WPA2 + decrypt pcap",                          # 8
            "Strip Wi-Fi layer on an existing pcap",              # 9
            "Extract payload streams from a pcap",                # 10
            "Run payload detection",                              # 11
            "Review candidate payloads",                          # 12
            "Pin a preferred candidate stream",                   # 13
            "Edit custom stream hints",                           # 14
            "Run cipher heuristics",                              # 15
            "Start experimental replay / reconstruction",         # 16
            "Run full pipeline (dumpcap / tcpdump capture)",      # 17
            "Run full Wi-Fi pipeline (monitor + crack + decrypt)",# 18
            "Show latest report summary",                         # 19
            "Show corpus archive",                                # 20
            "Launch web dashboard",                               # 21
            "Run doctor",                                         # 22
            "Run supported validation",                           # 23
            "Exit",                                               # 24
        ]
        default = 1 if IS_WINDOWS and not str(config.get("remote_host") or "").strip() else (16 if has_candidate else (2 if IS_WINDOWS else 7))
        selection = choose("Select an action", options, default=default)

        if selection == 0:
            config = interactive_config(config)
        elif selection == 1:
            run_setup_remote(config)
        elif selection == 2:
            strip_wifi = confirm("Run Wi-Fi layer strip after capture?", default=bool(resolve_wpa_password(config)))
            run_capture(config, strip_wifi=strip_wifi)
        elif selection == 3:
            host = ask("Remote host (user@host)", str(config.get("remote_host") or ""))
            identity = ask("SSH identity file (blank = auto)", str(config.get("remote_identity") or "")).strip() or None
            run_pair_remote(config, host=host, identity=identity)
        elif selection == 4:
            host = ask("Remote host (user@host)", str(config.get("remote_host") or ""))
            identity = ask("SSH identity file (blank = auto)", str(config.get("remote_identity") or "")).strip() or None
            install_packages = confirm("Install capture-side packages when possible?", default=True)
            run_bootstrap_remote(config, host=host, identity=identity, install_packages=install_packages)
        elif selection == 5:
            host = ask("Remote host (user@host)", str(config.get("remote_host") or ""))
            interface = ask("Remote interface", str(config.get("remote_interface") or "wlan0"))
            duration_text = ask("Capture duration in seconds", str(config.get("capture_duration") or 60))
            try:
                duration = max(1, int(duration_text))
            except ValueError:
                warn(f"Invalid duration {duration_text!r}; using 60.")
                duration = 60
            run_mode = ask("Run stage after pull? (none/extract/detect/analyze/play/all)", "all").strip().lower()
            if run_mode not in ("none", "extract", "detect", "analyze", "play", "all"):
                run_mode = "none"
            run_start_remote(config, host=host, interface=interface, duration=duration, run_mode=run_mode)
        elif selection == 6:
            host = ask("Remote host (user@host)", str(config.get("remote_host") or ""))
            path = ask("Remote path (file or directory)", str(config.get("remote_path") or ""))
            latest_only = confirm("Pull latest file from a directory/pattern?", default=True)
            run_mode = ask("Run stage after pull? (none/extract/detect/analyze/play/all)", "all").strip().lower()
            if run_mode not in ("none", "extract", "detect", "analyze", "play", "all"):
                run_mode = "none"
            pulled = pull_remote_capture(config, host=host, path=path, latest_only=latest_only)
            if pulled and run_mode != "none":
                _run_after_pull(config, str(pulled), run_mode)
        elif selection == 7:
            method = ask("Capture method (airodump/besside/tcpdump)", str(config.get("monitor_method") or "airodump"))
            run_monitor(config, method=method)
        elif selection == 8:
            cap = ask("Path to handshake .cap (blank = auto-detect)", "").strip() or None
            run_crack_decrypt(config, handshake_cap=cap)
        elif selection == 9:
            source = input("  > Path to existing pcap: ").strip()
            if source:
                Capture(config).strip_wifi_layer(source)
        elif selection == 10:
            source = ask("Path to pcap (blank = auto)", "").strip() or None
            run_extract(config, source)
        elif selection == 11:
            run_detect(config)
        elif selection == 12:
            _show_candidate_streams(config)
        elif selection == 13:
            config = _pick_preferred_stream(config)
        elif selection == 14:
            config = _edit_device_hints(config)
        elif selection == 15:
            decrypted = input("  > Directory of decrypted reference units (optional): ").strip() or None
            run_analyze(config, decrypted)
        elif selection == 16:
            run_play(config)
        elif selection == 17:
            decrypted = input("  > Directory of decrypted reference units (optional): ").strip() or None
            strip_wifi = confirm("Strip the Wi-Fi layer when possible?", default=bool(resolve_wpa_password(config)))
            run_all(config, None, decrypted, strip_wifi)
        elif selection == 18:
            decrypted = input("  > Directory of decrypted reference units (optional): ").strip() or None
            method = ask("Capture method (airodump/besside/tcpdump)", str(config.get("monitor_method") or "airodump"))
            run_all_wifi(config, decrypted_dir=decrypted, method=method)
        elif selection == 19:
            _show_report_summary(config)
        elif selection == 20:
            _show_corpus_summary(config)
        elif selection == 21:
            serve_dashboard()
        elif selection == 22:
            run_doctor(
                config,
                host=str(config.get("remote_host") or "").strip() or None,
                interface=str(config.get("remote_interface") or "").strip() or None,
            )
        elif selection == 23:
            run_validate_remote(
                config,
                host=str(config.get("remote_host") or "").strip() or None,
                interface=str(config.get("remote_interface") or "").strip() or None,
            )
        else:
            info("Goodbye.")
            return 0

        input("\n  Press Enter to continue...")


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="WiFi payload pipeline — supported path: Windows controller/analyzer plus Raspberry Pi OS or Ubuntu remote capture."
    )
    parser.add_argument("--config", default=None, help="Path to a JSON config file")
    parser.add_argument("--stage", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--pcap", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--decrypted", default=None, help=argparse.SUPPRESS)

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("menu", help="Open the guided dashboard interface (recommended: Windows controller + remote capture)")
    subparsers.add_parser("config", help="Launch interactive configuration")

    # ── Standard capture (all platforms) ─────────────────────────────────────
    capture_p = subparsers.add_parser("capture", help="Local capture into a pcap (supported mainly for Linux/macOS or imported pcaps; experimental for Windows Wi-Fi)")
    capture_p.add_argument("--strip-wifi", action="store_true", help="Run airdecap-ng after capture")

    # ── Monitor mode (Linux/macOS, Windows when supported) ────────────────────
    monitor_p = subparsers.add_parser("monitor", help="Experimental local monitor-mode capture (preferred product path is remote Raspberry Pi OS/Ubuntu capture)")
    monitor_p.add_argument(
        "--method",
        default=None,
        choices=["airodump", "besside", "tcpdump"],
        help="Handshake capture method (default: value from config / airodump)",
    )

    # ── WPA2 crack + decrypt ─────────────────────────────────────────────────
    crack_p = subparsers.add_parser("crack", help="Crack WPA2 PSK from a handshake capture then decrypt with airdecap-ng")
    crack_p.add_argument("--cap", default=None, help="Path to handshake .cap file (auto-detected if omitted)")

    # ── Remote capture pull (SSH/SCP) ────────────────────────────────────────
    remote_p = subparsers.add_parser("remote", help="Pull a capture from a supported remote capture device over SSH/SCP")
    remote_p.add_argument("--host", default=None, help="Remote host in user@host form")
    remote_p.add_argument("--path", default=None, help="Remote file path or directory")
    remote_p.add_argument("--port", default=None, type=int, help="SSH port (default: 22)")
    remote_p.add_argument("--identity", default=None, help="SSH identity file (optional)")
    remote_p.add_argument("--dest", default=None, help="Local destination directory")
    remote_p.add_argument("--no-latest", action="store_true", help="Do not resolve latest file for directory/pattern paths")
    remote_p.add_argument("--watch", action="store_true", help="Keep pulling on an interval")
    remote_p.add_argument("--interval", default=None, type=int, help="Watch interval in seconds")
    remote_p.add_argument("--run", default="none", choices=["none", "extract", "detect", "analyze", "play", "all"], help="Run stages after pull")

    pair_p = subparsers.add_parser("pair-remote", help="Install your SSH public key on a supported remote Raspberry Pi OS/Ubuntu capture device")
    pair_p.add_argument("--host", default=None, help="Remote host in user@host form")
    pair_p.add_argument("--port", default=None, type=int, help="SSH port (default: 22)")
    pair_p.add_argument("--identity", default=None, help="SSH identity file (private key or .pub)")

    bootstrap_p = subparsers.add_parser("bootstrap-remote", help="Prepare a supported Raspberry Pi OS/Ubuntu capture device over SSH")
    bootstrap_p.add_argument("--host", default=None, help="Remote host in user@host form")
    bootstrap_p.add_argument("--port", default=None, type=int, help="SSH port (default: 22)")
    bootstrap_p.add_argument("--identity", default=None, help="SSH identity file (private key or .pub)")
    bootstrap_p.add_argument("--remote-root", default=None, help="Remote install root (default: $HOME/wifi-pipeline)")
    bootstrap_p.add_argument("--capture-dir", default=None, help="Remote capture directory (default: <remote-root>/captures)")
    bootstrap_p.add_argument("--skip-packages", action="store_true", help="Do not install capture-side packages")
    bootstrap_p.add_argument("--skip-pair", action="store_true", help="Skip SSH key pairing before bootstrap")

    setup_remote_p = subparsers.add_parser("setup-remote", help="Run the guided first-run Windows setup flow for the supported remote capture path")
    setup_remote_p.add_argument("--host", default=None, help="Remote host in user@host form")
    setup_remote_p.add_argument("--port", default=None, type=int, help="SSH port (default: 22)")
    setup_remote_p.add_argument("--identity", default=None, help="SSH identity file (private key or .pub)")
    setup_remote_p.add_argument("--interface", default=None, help="Remote capture interface, for example wlan0")
    setup_remote_p.add_argument("--duration", default=None, type=int, help="Default capture duration in seconds")
    setup_remote_p.add_argument("--dest", default=None, help="Local destination directory")
    setup_remote_p.add_argument("--smoke-test", action="store_true", help="Run a short remote smoke capture after setup")

    start_remote_p = subparsers.add_parser("start-remote", help="Run the supported timed remote capture flow, pull it back, and optionally process it")
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

    validate_remote_p = subparsers.add_parser("validate-remote", help="Run the supported hardware-validation flow and write a validation report")
    validate_remote_p.add_argument("--host", default=None, help="Remote host in user@host form")
    validate_remote_p.add_argument("--port", default=None, type=int, help="SSH port (default: 22)")
    validate_remote_p.add_argument("--identity", default=None, help="SSH identity file (private key or .pub)")
    validate_remote_p.add_argument("--interface", default=None, help="Remote capture interface, for example wlan0")
    validate_remote_p.add_argument("--duration", default=None, type=int, help="Smoke-capture duration in seconds")
    validate_remote_p.add_argument("--dest", default=None, help="Local destination directory for the smoke capture")
    validate_remote_p.add_argument("--report", default=None, help="Path to save the JSON validation report")
    validate_remote_p.add_argument("--skip-smoke", action="store_true", help="Run readiness checks only and skip the smoke capture")

    # ── Full Wi-Fi pipeline ──────────────────────────────────────────────────
    wifi_p = subparsers.add_parser(
        "wifi",
        help="Full Wi-Fi pipeline: monitor mode → handshake capture → WPA2 crack → airdecap-ng",
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

    subparsers.add_parser("deps", help="Check the environment, supported workflow target, and explicit product limits")

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

    if args.command == "doctor":
        return 0 if run_doctor(
            config,
            host=getattr(args, "host", None),
            port=getattr(args, "port", None),
            identity=getattr(args, "identity", None),
            interface=getattr(args, "interface", None),
        ) else 1

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

    if args.command == "remote":
        latest_only = not bool(getattr(args, "no_latest", False))
        if getattr(args, "watch", False):
            watch_remote_capture(
                config,
                host=getattr(args, "host", None),
                path=getattr(args, "path", None),
                port=getattr(args, "port", None),
                identity=getattr(args, "identity", None),
                dest_dir=getattr(args, "dest", None),
                interval=getattr(args, "interval", None),
                latest_only=latest_only,
            )
            return 0
        pulled = pull_remote_capture(
            config,
            host=getattr(args, "host", None),
            path=getattr(args, "path", None),
            port=getattr(args, "port", None),
            identity=getattr(args, "identity", None),
            dest_dir=getattr(args, "dest", None),
            latest_only=latest_only,
        )
        if pulled and getattr(args, "run", "none") != "none":
            _run_after_pull(config, str(pulled), str(getattr(args, "run", "none")))
        return 0 if pulled else 1

    if args.command == "pair-remote":
        paired = run_pair_remote(
            config,
            host=getattr(args, "host", None),
            port=getattr(args, "port", None),
            identity=getattr(args, "identity", None),
        )
        return 0 if paired else 1

    if args.command == "bootstrap-remote":
        result = run_bootstrap_remote(
            config,
            host=getattr(args, "host", None),
            port=getattr(args, "port", None),
            identity=getattr(args, "identity", None),
            remote_root=getattr(args, "remote_root", None),
            capture_dir=getattr(args, "capture_dir", None),
            install_packages=not bool(getattr(args, "skip_packages", False)),
            pair=not bool(getattr(args, "skip_pair", False)),
        )
        return 0 if result else 1

    if args.command == "setup-remote":
        result = run_setup_remote(
            config,
            config_path=getattr(args, "config", None),
            host=getattr(args, "host", None),
            port=getattr(args, "port", None),
            identity=getattr(args, "identity", None),
            interface=getattr(args, "interface", None),
            dest_dir=getattr(args, "dest", None),
            duration=getattr(args, "duration", None),
            smoke_test=bool(getattr(args, "smoke_test", False)),
        )
        return 0 if result else 1

    if args.command == "start-remote":
        result = run_start_remote(
            config,
            host=getattr(args, "host", None),
            port=getattr(args, "port", None),
            identity=getattr(args, "identity", None),
            interface=getattr(args, "interface", None),
            duration=getattr(args, "duration", None),
            output=getattr(args, "output", None),
            dest_dir=getattr(args, "dest", None),
            run_mode=str(getattr(args, "run", "all")),
        )
        return 0 if result else 1

    if args.command == "remote-service":
        result = run_remote_service(
            config,
            action=str(getattr(args, "action", "status")),
            host=getattr(args, "host", None),
            port=getattr(args, "port", None),
            identity=getattr(args, "identity", None),
            interface=getattr(args, "interface", None),
            duration=getattr(args, "duration", None),
            output=getattr(args, "output", None),
        )
        return 0 if result else 1

    if args.command == "validate-remote":
        result = run_validate_remote(
            config,
            host=getattr(args, "host", None),
            port=getattr(args, "port", None),
            identity=getattr(args, "identity", None),
            interface=getattr(args, "interface", None),
            duration=getattr(args, "duration", None),
            dest_dir=getattr(args, "dest", None),
            report_path=getattr(args, "report", None),
            skip_smoke=bool(getattr(args, "skip_smoke", False)),
        )
        return 0 if result else 1

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
