from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, Optional

from .analysis import CryptoAnalyzer, FormatDetector, _load_manifest, _rank_candidate_streams
from .capture import Capture
from .cli_parser import build_parser, map_legacy_stage as _map_legacy_stage
from .config import interactive_config, load_config, resolve_wpa_password, save_config
from .corpus import CorpusStore
from .environment import (
    IS_LINUX,
    IS_MACOS,
    IS_WINDOWS,
    build_capability_report,
    command_support,
    check_environment,
    hardware_qualification_report,
    list_interfaces,
    print_capability_hardware,
    print_hardware_qualification,
    resolve_product_profile,
)
from .enrich import ArtifactEnricher
from .extract import StreamExtractor
from .feasibility import (
    attach_feasibility_to_report,
    evaluate_pipeline_feasibility,
    print_pipeline_feasibility,
)
from .playback import ExperimentalPlayback, infer_replay_hint, reconstruct_from_capture, replay_support_summary
from .release_gate import evaluate_release_gate, print_release_gate
from .remote import (
    bootstrap_remote_host,
    discover_remote_appliances,
    doctor_remote_host,
    pair_remote_host,
    pull_remote_capture,
    remote_service_host,
    start_remote_capture,
    watch_remote_capture,
)
from .status_language import build_surface_status_bundle
from .ui import (
    BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW,
    ask, ask_int, banner, choose, confirm, done, err, info, ok, section, warn,
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


def _enrichment_report_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "enrichment_report.json"


def _capture_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "raw_capture.pcapng"


def _validation_report_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "validation_report.json"


def _standalone_validation_report_path(config: Dict[str, object]) -> Path:
    return Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "standalone_validation_report.json"


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


def _status_badge(status: str) -> str:
    value = str(status or "").strip().lower()
    if value in ("supported", "ready"):
        return f"{GREEN}{value}{RESET}"
    if value in ("limited", "warning", "heuristic"):
        return f"{YELLOW}{value}{RESET}"
    if value == "running":
        return f"{CYAN}running{RESET}"
    return f"{RED}{value or 'blocked'}{RESET}"


def _command_support_suffix(config: Dict[str, object], command: str, *, has_input_pcap: bool = False) -> str:
    support = command_support(command, config, has_input_pcap=has_input_pcap)
    if support.status == "experimental":
        return " [experimental]"
    if support.status == "best_effort":
        return " [best effort]"
    return ""


def _enforce_command_support(config: Dict[str, object], command: str, *, has_input_pcap: bool = False) -> bool:
    support = command_support(command, config, has_input_pcap=has_input_pcap)
    if support.status == "official":
        return True
    if support.status == "best_effort":
        warn(f"`{command}` is outside the official support matrix for {support.profile.label}. Continuing in best-effort mode.")
        if support.message:
            info(support.message)
        return True
    if support.status == "experimental":
        warn(f"`{command}` uses an experimental path on this machine.")
        if support.message:
            info(support.message)
        return True

    err(f"`{command}` is not supported for {support.profile.label}.")
    if support.message:
        err(support.message)
    return False


def _candidate_rows(config: Dict[str, object]) -> list[Dict[str, object]]:
    manifest = _load_json(_manifest_path(config))
    if not manifest:
        return []
    return _rank_candidate_streams(manifest, config)


def _recommended_next_command(config: Dict[str, object], has_candidate: bool = False) -> str:
    profile = resolve_product_profile(config)
    if profile.key == "windows_remote":
        if not str(config.get("remote_host") or "").strip():
            return r".\setup_remote.ps1"
        return r".\run_remote.ps1 -Host <user@host> -Interface <wlan0> -DoctorFirst"
    if profile.key in ("ubuntu_standalone", "pi_standalone"):
        if not str(config.get("interface") or "").strip():
            return "bash ./setup_local.sh"
        if has_candidate:
            return "python3 videopipeline.py play"
        return "bash ./run_local.sh"
    if profile.key == "linux_best_effort":
        return "bash ./run_local.sh"
    return "python videopipeline.py deps"


def _active_validation_command(config: Dict[str, object]) -> str:
    profile = resolve_product_profile(config)
    if profile.key in ("ubuntu_standalone", "pi_standalone", "linux_best_effort"):
        return "validate-local"
    return "validate-remote"


def _active_validation_label(config: Dict[str, object]) -> str:
    command = _active_validation_command(config)
    if command == "validate-local":
        return "Run standalone validation"
    return "Run supported validation"


def run_hardware(config: Dict[str, object]) -> bool:
    print_capability_hardware(build_capability_report(config))
    return True


def run_crack_status(config: Dict[str, object], handshake_cap: Optional[str] = None) -> bool:
    capture = Capture(config)
    readiness = capture.print_wpa_crack_status(handshake_cap=handshake_cap)
    return readiness.status != "unsupported"


def run_preflight(config: Dict[str, object]) -> bool:
    report = _load_report(config)
    feasibility = print_pipeline_feasibility(config, report)
    return feasibility.get("status") != "blocked"


def run_release_gate(
    config: Dict[str, object],
    *,
    ubuntu_report: Optional[str] = None,
    pi_report: Optional[str] = None,
    windows_report: Optional[str] = None,
    sample_reports: Optional[list[str]] = None,
    write_summary: Optional[str] = None,
) -> bool:
    result = evaluate_release_gate(
        ubuntu_report=Path(ubuntu_report).resolve() if ubuntu_report else Path("validation_matrix/ubuntu_standalone_validation.json"),
        pi_report=Path(pi_report).resolve() if pi_report else Path("validation_matrix/pi_standalone_validation.json"),
        windows_report=Path(windows_report).resolve() if windows_report else Path("validation_matrix/windows_remote_validation.json"),
        sample_reports=[Path(path).resolve() for path in (sample_reports or [])],
    )
    print_release_gate(result)
    if write_summary:
        from .release_gate import write_release_gate_summary

        summary_path = write_release_gate_summary(result, Path(write_summary).resolve())
        info(f"Release-gate summary written to {summary_path}")
    return bool(result.get("fully_validated"))


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


def run_discover_remote(
    config: Dict[str, object],
    *,
    networks: Optional[list[str]] = None,
    health_port: Optional[int] = None,
    timeout: float = 0.35,
    max_hosts: int = 64,
) -> list[Dict[str, str]]:
    section("Remote Appliance Discovery")
    results = discover_remote_appliances(
        config,
        networks=networks,
        health_port=health_port,
        timeout=timeout,
        max_hosts=max_hosts,
    )
    if not results:
        warn("No appliance-style capture nodes responded on the local network.")
        return []

    for record in results:
        label = str(record.get("device_name") or record.get("host") or "appliance")
        ssh_target = str(record.get("ssh_target") or record.get("host") or "")
        health_endpoint = str(record.get("health_endpoint") or "")
        install_profile = str(record.get("install_profile") or "standard")
        info(f"{label}: {ssh_target} ({install_profile})")
        if health_endpoint:
            info(f"  health: {health_endpoint}")
    done(f"Discovered {len(results)} appliance node(s).")
    return results


def run_bootstrap_remote(
    config: Dict[str, object],
    host: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    remote_root: Optional[str] = None,
    capture_dir: Optional[str] = None,
    install_packages: bool = True,
    install_mode: Optional[str] = None,
    install_profile: Optional[str] = None,
    health_port: Optional[int] = None,
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
        install_mode=install_mode,
        install_profile=install_profile,
        health_port=health_port,
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
    install_mode: Optional[str] = None,
    install_profile: Optional[str] = None,
    health_port: Optional[int] = None,
    smoke_test: bool = False,
) -> bool:
    section("Windows Remote Setup")
    if IS_WINDOWS:
        info("This guided setup is optimized for the official Windows remote-capture mode.")
    else:
        warn("This guided setup is Windows-first, but it can still prepare the official Windows remote-capture mode.")

    existing_host = str(config.get("remote_host") or "").strip()
    discovered_nodes: list[Dict[str, str]] = []
    default_health_port = int(health_port if health_port is not None else int(config.get("remote_health_port", 8741) or 8741))
    if host is None and not existing_host:
        info("No remote host is configured yet. Looking for appliance capture nodes on the local network...")
        discovered_nodes = discover_remote_appliances(config, health_port=default_health_port)
        if len(discovered_nodes) == 1:
            node = discovered_nodes[0]
            existing_host = str(node.get("ssh_target") or node.get("host") or "").strip()
            if existing_host:
                ok(f"Discovered appliance: {existing_host}")
        elif len(discovered_nodes) > 1:
            labels = [
                f"{node.get('device_name') or node.get('host')} -> {node.get('ssh_target') or node.get('host')}"
                for node in discovered_nodes
            ]
            selected = choose("Select a discovered appliance", labels, default=0)
            node = discovered_nodes[selected]
            existing_host = str(node.get("ssh_target") or node.get("host") or "").strip()
            if existing_host:
                ok(f"Selected appliance: {existing_host}")

    if host is not None:
        resolved_host = str(host).strip()
    elif discovered_nodes and existing_host:
        resolved_host = existing_host
    else:
        resolved_host = ask("Remote host (user@host)", existing_host or "pi@raspberrypi").strip()
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
    resolved_install_mode = (
        str(install_mode).strip().lower()
        if install_mode is not None
        else str(config.get("remote_install_mode") or "auto").strip().lower()
    )
    resolved_install_profile = (
        str(install_profile).strip().lower()
        if install_profile is not None
        else str(config.get("remote_install_profile") or "appliance").strip().lower()
    )
    resolved_health_port = int(
        health_port if health_port is not None else int(config.get("remote_health_port", 8741) or 8741)
    )
    if resolved_install_mode not in ("auto", "native", "bundle"):
        warn(f"Unknown remote install mode {resolved_install_mode!r}; using auto.")
        resolved_install_mode = "auto"
    if resolved_install_profile not in ("standard", "appliance"):
        warn(f"Unknown remote install profile {resolved_install_profile!r}; using appliance.")
        resolved_install_profile = "appliance"
    if resolved_duration <= 0:
        warn("Default capture duration must be positive; using 60 seconds.")
        resolved_duration = 60

    config["remote_host"] = resolved_host
    config["remote_port"] = resolved_port
    config["remote_identity"] = resolved_identity
    config["remote_interface"] = resolved_interface
    config["remote_dest_dir"] = resolved_dest
    config["remote_install_mode"] = resolved_install_mode
    config["remote_install_profile"] = resolved_install_profile
    config["remote_health_port"] = resolved_health_port
    config["capture_duration"] = resolved_duration

    save_target = config_path or "lab.json"
    save_config(config, save_target)
    info("Running the official Windows first-run flow: pair -> bootstrap -> doctor.")
    if not run_pair_remote(config, host=resolved_host, port=resolved_port, identity=resolved_identity or None):
        return False

    bootstrap_result = run_bootstrap_remote(
        config,
        host=resolved_host,
        port=resolved_port,
        identity=resolved_identity or None,
        install_packages=True,
        install_mode=resolved_install_mode,
        install_profile=resolved_install_profile,
        health_port=resolved_health_port,
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
    print(f"    Control mode     : {_status_label(bool(remote.get('agent')), 'agent', str(remote.get('control_mode') or 'legacy shell'))}")
    if remote.get("agent_path"):
        print(f"    Agent path       : {remote.get('agent_path')}")
    if remote.get("agent_protocol"):
        print(f"    Agent protocol   : {remote.get('agent_protocol')}")
    print(f"    Install profile  : {remote.get('install_profile') or 'standard'}")
    if remote.get("health_endpoint"):
        print(f"    Health endpoint  : {remote.get('health_endpoint')}")
    health_socket_enabled = remote.get("health_socket_enabled")
    if health_socket_enabled is not None:
        print(f"    Health socket    : {_status_label(bool(health_socket_enabled), 'enabled', 'disabled')}")
    appliance_service_enabled = remote.get("appliance_service_enabled")
    if appliance_service_enabled is not None:
        print(f"    Appliance svc    : {_status_label(bool(appliance_service_enabled), 'enabled', 'disabled')}")
    print(f"    tcpdump          : {_status_label(bool(remote.get('tcpdump')), 'present', 'missing')}")
    print(f"    Helper           : {_status_label(bool(remote.get('helper')), 'present', 'missing')}")
    if remote.get("helper_path"):
        print(f"    Helper path      : {remote.get('helper_path')}")
    service_state = str(remote.get("service_status") or "missing")
    if service_state == "running":
        service_label = f"{YELLOW}running{RESET}"
    elif service_state == "idle":
        service_label = _status_label(True, "ready")
    elif service_state == "stopped":
        service_label = f"{YELLOW}stopped{RESET}"
    elif service_state == "interrupted":
        service_label = f"{YELLOW}interrupted{RESET}"
    elif service_state == "failed":
        service_label = _status_label(False, "ready", "failed")
    else:
        service_label = _status_label(False, "ready", "missing")
    print(f"    Service          : {_status_label(bool(remote.get('service')), 'present', 'missing')}")
    print(f"    Service status   : {service_label}")
    if remote.get("recovery_reason"):
        print(f"    Recovery reason  : {remote.get('recovery_reason')}")
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
    if str(remote.get("install_profile") or "") == "appliance" and not remote.get("health_endpoint"):
        print(f"    Next step        : re-run bootstrap-remote with --install-profile appliance")
    elif not bool(remote.get("agent")):
        print(f"    Next step        : re-run bootstrap-remote to install the managed capture agent")
    elif not privilege_ready:
        print(f"    Next step        : re-run bootstrap-remote with a remote user that has sudo access")


def run_doctor(
    config: Dict[str, object],
    host: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    interface: Optional[str] = None,
) -> bool:
    section("Doctor")
    local_ok = check_environment(config)
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


def _validation_reporting_artifacts(
    config: Dict[str, object],
    *,
    detection_report: Optional[Dict[str, object]] = None,
    analysis_report: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    return {
        "capability_report": build_capability_report(config).to_dict(),
        "status_bundle": build_surface_status_bundle(config, detection_report, analysis_report),
    }


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
    validation_config = dict(config)
    if target_host:
        validation_config["remote_host"] = target_host
    if target_interface:
        validation_config["remote_interface"] = target_interface
    if port is not None:
        validation_config["remote_port"] = int(port)

    validation: Dict[str, object] = {
        "schema_version": 1,
        "validated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "supported_target": "Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture",
        "inputs": {
            "host": target_host or "",
            "port": int(port if port is not None else config.get("remote_port", 22) or 22),
            "interface": target_interface or "",
            "duration": target_duration,
            "dest_dir": str(dest_dir or config.get("remote_dest_dir") or "./pipeline_output/remote_imports"),
            "skip_smoke": bool(skip_smoke),
        },
        "environment_ok": False,
        "hardware_qualification": [],
        "capability_report": {},
        "status_bundle": {},
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

    env_ok = check_environment(config)
    validation["environment_ok"] = env_ok
    validation["hardware_qualification"] = [
        {
            "area": row.area,
            "label": row.label,
            "status": row.status,
            "summary": row.summary,
            "detail": row.detail,
            "monitor_mode": row.monitor_mode,
            "injection": row.injection,
            "channels": row.channels,
        }
        for row in hardware_qualification_report(config)
    ]
    validation.update(_validation_reporting_artifacts(validation_config))

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


def run_validate_local(
    config: Dict[str, object],
    interface: Optional[str] = None,
    duration: Optional[int] = None,
    report_path: Optional[str] = None,
    skip_smoke: bool = False,
) -> bool:
    section("Standalone Validation")
    profile = resolve_product_profile(config)
    target_interface = interface or str(config.get("interface") or "").strip()
    target_duration = int(duration if duration is not None else min(max(int(config.get("capture_duration", 60) or 60), 10), 30))
    report_file = Path(report_path).resolve() if report_path else _standalone_validation_report_path(config)
    report_file.parent.mkdir(parents=True, exist_ok=True)

    discovered = list_interfaces()
    discovered_names = [name for _index, name, _desc in discovered]
    interface_present = bool(target_interface and target_interface in discovered_names)
    smoke_config = dict(config)
    if target_interface:
        smoke_config["interface"] = target_interface
    smoke_config["capture_duration"] = target_duration

    validation: Dict[str, object] = {
        "schema_version": 1,
        "validated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "supported_target": profile.label,
        "inputs": {
            "interface": target_interface,
            "duration": target_duration,
            "skip_smoke": bool(skip_smoke),
        },
        "environment_ok": False,
        "hardware_qualification": [],
        "product_profile": {
            "key": profile.key,
            "label": profile.label,
            "official": bool(profile.official),
            "standalone": bool(profile.standalone),
        },
        "interface_check": {
            "requested": target_interface,
            "present": interface_present,
            "discovered_count": len(discovered),
            "discovered_names": discovered_names,
        },
        "smoke_capture": {
            "requested": not skip_smoke,
            "success": False,
            "local_capture_path": "",
            "size_bytes": 0,
        },
        "processing_smoke": {
            "requested": not skip_smoke,
            "success": False,
            "manifest_path": str(_manifest_path(config)),
            "detection_report_path": str(_detection_report_path(config)),
            "analysis_report_path": str(_analysis_report_path(config)),
            "selected_protocol_support": {},
            "selected_replay_confidence": {},
            "analysis_preflight": {},
        },
        "capability_report": {},
        "status_bundle": {},
        "overall_ok": False,
    }

    env_ok = check_environment(config)
    validation["environment_ok"] = env_ok
    validation["hardware_qualification"] = [
        {
            "area": row.area,
            "label": row.label,
            "status": row.status,
            "summary": row.summary,
            "detail": row.detail,
            "monitor_mode": row.monitor_mode,
            "injection": row.injection,
            "channels": row.channels,
        }
        for row in hardware_qualification_report(smoke_config)
    ]
    validation.update(_validation_reporting_artifacts(smoke_config))

    if not target_interface:
        warn("No local capture interface is configured for standalone validation.")
    elif interface_present:
        info(f"Validation interface: {target_interface}")
    else:
        warn(f"Configured interface `{target_interface}` was not found in the discovered interface list.")

    smoke_ok = True
    processing_ok = True
    if not skip_smoke:
        smoke_ok = False
        processing_ok = False
        capture_path = run_capture(smoke_config)
        if capture_path:
            capture_file = Path(str(capture_path)).resolve()
            validation["smoke_capture"]["local_capture_path"] = str(capture_file)
            if capture_file.exists():
                validation["smoke_capture"]["size_bytes"] = capture_file.stat().st_size
            smoke_ok = capture_file.exists() and capture_file.stat().st_size > 0
            validation["smoke_capture"]["success"] = smoke_ok
            if smoke_ok:
                manifest = run_extract(smoke_config, str(capture_file))
                detection = run_detect(smoke_config)
                analysis = run_analyze(smoke_config, None)
                processing_ok = bool(manifest) and bool(detection) and bool(analysis)
                validation["processing_smoke"]["success"] = processing_ok
                if analysis:
                    validation["processing_smoke"]["selected_protocol_support"] = dict(
                        analysis.get("selected_protocol_support") or {}
                    )
                    validation["processing_smoke"]["selected_replay_confidence"] = dict(
                        analysis.get("selected_replay_confidence") or {}
                    )
                    validation["processing_smoke"]["analysis_preflight"] = dict(
                        analysis.get("feasibility") or {}
                    )
                validation.update(_validation_reporting_artifacts(smoke_config, detection_report=detection, analysis_report=analysis))
            else:
                warn("Standalone smoke capture did not produce a readable pcap.")
        else:
            warn("Standalone smoke capture did not return a capture path.")
    else:
        validation["smoke_capture"]["success"] = True
        validation["processing_smoke"]["success"] = True

    interface_ok = bool(target_interface) and interface_present
    overall_ok = bool(env_ok and interface_ok and smoke_ok and processing_ok)
    validation["overall_ok"] = overall_ok
    report_file.write_text(json.dumps(validation, indent=2), encoding="utf-8")

    if overall_ok:
        done(f"Standalone validation passed. Report saved to {report_file}")
    else:
        warn(f"Standalone validation found issues. Report saved to {report_file}")
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
    status_bundle = build_surface_status_bundle(config, detection, analysis)
    machine_summary = dict(status_bundle.get("machine_summary") or {})
    machine_items = list(machine_summary.get("items") or [])
    workflow_rows = list(status_bundle.get("workflow") or [])
    replay_status = dict(status_bundle.get("replay") or {})
    wpa_status = dict(status_bundle.get("wpa") or {})

    interface = str(config.get("interface") or "").strip() or f"{RED}unset{RESET}"
    magic = str(config.get("custom_magic_hex") or "").strip() or f"{DIM}(none){RESET}"
    preferred = str(config.get("preferred_stream_id") or "").strip() or f"{DIM}(auto-pick){RESET}"
    env_model = str(config.get("environment_model") or ("native_windows" if IS_WINDOWS else "macos" if IS_MACOS else "linux"))
    profile = resolve_product_profile(config)
    profile_status = "official" if profile.official else "non-official"

    print(f"  {BOLD}Saved Config{RESET}")
    print(f"    Platform         : {env_model}")
    print(f"    Product Mode     : {profile.label} ({profile_status})")
    print(f"    Interface        : {interface}")
    print(f"    Target           : {config.get('protocol', 'udp')}/{config.get('video_port', 5004)}")
    print(f"    Output           : {config.get('output_dir', './pipeline_output')}")
    print(f"    Header Strip     : {config.get('custom_header_size', 0)} bytes")
    print(f"    Custom Magic     : {magic}")
    print(f"    Preferred Stream : {_shorten(str(preferred), 84)}")
    print(f"    Replay Hint      : {config.get('replay_format_hint') or config.get('video_codec') or 'raw'}")
    print(f"    Corpus Reuse     : review {config.get('corpus_review_threshold', 0.62)} / auto {config.get('corpus_auto_reuse_threshold', 0.88)}")

    print(f"\n  {BOLD}What This Machine Can Do{RESET}")
    if machine_summary.get("headline"):
        print(f"    Profile          : {_shorten(str(machine_summary.get('headline')), 84)}")
    for item in machine_items:
        print(f"    {str(item.get('label') or ''):<16} {_status_badge(str(item.get('status') or 'blocked'))}")
        print(f"      {_shorten(str(item.get('summary') or ''), 88)}")
        reason = str(item.get("reason") or "").strip()
        next_step = str(item.get("next_step") or "").strip()
        if reason:
            print(f"      note : {_shorten(reason, 88)}")
        if next_step:
            print(f"      next : {_shorten(next_step, 88)}")

    print(f"\n  {BOLD}Wi-Fi / Piracy Pipeline{RESET}")
    print(f"    AP ESSID         : {config.get('ap_essid') or f'{DIM}(unset){RESET}'}")
    print(f"    AP BSSID         : {config.get('ap_bssid') or f'{DIM}(unset){RESET}'}")
    print(f"    AP Channel       : {config.get('ap_channel', 6)}")
    print(f"    Monitor Method   : {config.get('monitor_method', 'airodump')}")
    print(f"    Wordlist         : {config.get('wordlist_path') or f'{DIM}(unset){RESET}'}")
    wpa_available = bool(resolve_wpa_password(config))
    print(f"    WPA Password     : {_status_label(wpa_available, 'set (env/session)', 'not set')}")
    print(f"    WPA Path         : {_status_badge(str(wpa_status.get('status') or 'blocked'))}")
    print(f"    WPA Summary      : {_shorten(str(wpa_status.get('summary') or 'WPA readiness has not been evaluated yet.'), 84)}")
    if wpa_status.get("next_steps"):
        print(f"    WPA Next         : {_shorten(str(wpa_status['next_steps'][0]), 84)}")

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

    print(f"\n  {BOLD}Workflow Capabilities{RESET}")
    for row in workflow_rows:
        print(f"    {str(row.get('area') or ''):<30} {_status_badge(str(row.get('status') or 'blocked'))}")
        print(f"      {_shorten(str(row.get('summary') or row.get('detail') or ''), 88)}")
        reasons = list(row.get("reasons") or [])
        next_steps = list(row.get("next_steps") or [])
        if reasons:
            print(f"      reason: {_shorten(str(reasons[0]), 88)}")
        if next_steps:
            print(f"      next  : {_shorten(str(next_steps[0]), 88)}")

    if analysis:
        hypotheses = analysis.get("hypotheses", [])
        hypothesis = str(hypotheses[0].get("name") or "") if hypotheses else ""
        replay_support = dict(analysis.get("selected_protocol_support") or {})
        replay_confidence = dict(replay_status.get("confidence") or {})
        print(f"\n  {BOLD}Latest Analysis{RESET}")
        print(f"    Units Analyzed   : {analysis.get('total_units', 0)}")
        print(f"    Entropy          : {analysis.get('ciphertext_observations', {}).get('average_entropy', '?')}")
        print(f"    Lead Hypothesis  : {hypothesis or f'{DIM}(none){RESET}'}")
        if replay_support:
            print(
                f"    Decode / Replay  : "
                f"{replay_support.get('decode_level', 'heuristic')} / "
                f"{replay_support.get('replay_level', 'unsupported')} "
                f"({replay_support.get('dominant_unit_type', 'opaque_chunk')})"
            )
        print(f"    Replay Path      : {_status_badge(str(replay_status.get('status') or 'blocked'))}")
        print(f"    Replay Summary   : {_shorten(str(replay_status.get('summary') or 'Run analyze to evaluate replay readiness.'), 84)}")
        if replay_confidence:
            print(
                f"    Replay Confidence: "
                f"{replay_confidence.get('confidence_band', 'low')} "
                f"[{replay_confidence.get('confidence_label', 'unknown')}, score={replay_confidence.get('confidence_score', '?')}]"
            )
        blockers = list(replay_status.get("blockers") or [])
        warnings = list(replay_status.get("warnings") or [])
        next_steps = list(replay_status.get("next_steps") or [])
        if blockers:
            print(f"    Top Blocker      : {_shorten(str(blockers[0]), 84)}")
        elif warnings:
            print(f"    Top Caveat       : {_shorten(str(warnings[0]), 84)}")
        if next_steps:
            print(f"    Next Step        : {_shorten(str(next_steps[0]), 84)}")
        corpus = analysis.get("corpus") or {}
        best_match = corpus.get("best_match") or {}
        if best_match:
            print(
                f"    Best Corpus Match: {_shorten(str(best_match.get('entry_id') or ''), 40)} "
                f"({best_match.get('similarity', '?')})"
            )
        if corpus.get("reused_candidate_material"):
            print(f"    Corpus Reuse     : {GREEN}yes{RESET}")

    print(f"\n  {BOLD}Recommended Next Step{RESET}")
    print(f"    Command          : {_recommended_next_command(config, has_candidate=bool(candidate or analysis))}")


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
    status_bundle = build_surface_status_bundle(config, detection, analysis)
    machine_summary = dict(status_bundle.get("machine_summary") or {})
    replay_status = dict(status_bundle.get("replay") or {})
    wpa_status = dict(status_bundle.get("wpa") or {})

    if detection:
        selected = detection.get("selected_candidate_stream") or {}
        support = detection.get("selected_protocol_support") or {}
        print(f"  {BOLD}Detection{RESET}")
        print(f"    Average Entropy  : {detection.get('average_entropy', '?')}")
        print(f"    Opaque Hits      : {detection.get('protocol_hits', {}).get('opaque', 0)}")
        print(f"    Selected Stream  : {_shorten(str(selected.get('stream_id') or '(none)'), 84)}")
        print(f"    Candidate Class  : {selected.get('candidate_class', '(none)')}")
        if support:
            print(
                f"    Decode / Replay  : "
                f"{support.get('decode_level', 'heuristic')} / {support.get('replay_level', 'unsupported')}"
            )
    else:
        warn("No detection report found yet.")

    if analysis:
        selected = analysis.get("selected_candidate_stream") or {}
        hypotheses = analysis.get("hypotheses", [])
        recommendations = analysis.get("recommendations", [])
        replay_confidence = dict(replay_status.get("confidence") or {})
        print(f"\n  {BOLD}Analysis{RESET}")
        print(f"    Units Analyzed   : {analysis.get('total_units', 0)}")
        print(f"    Chi-Squared      : {analysis.get('ciphertext_observations', {}).get('chi_squared', '?')}")
        print(f"    Selected Stream  : {_shorten(str(selected.get('stream_id') or '(none)'), 84)}")
        if hypotheses:
            print(f"    Top Hypothesis   : {hypotheses[0].get('name', '(none)')}")
        print(f"    Replay Path      : {_status_badge(str(replay_status.get('status') or 'blocked'))}")
        print(f"    Replay Summary   : {_shorten(str(replay_status.get('summary') or 'Run analyze to evaluate replay readiness.'), 84)}")
        if replay_confidence:
            print(
                f"    Replay Confidence: "
                f"{replay_confidence.get('confidence_band', 'low')} "
                f"[{replay_confidence.get('confidence_label', 'unknown')}, score={replay_confidence.get('confidence_score', '?')}]"
            )
        blockers = list(replay_status.get("blockers") or [])
        warnings = list(replay_status.get("warnings") or [])
        next_steps = list(replay_status.get("next_steps") or [])
        if blockers:
            print(f"    Top Blocker      : {_shorten(str(blockers[0]), 84)}")
        elif warnings:
            print(f"    Top Caveat       : {_shorten(str(warnings[0]), 84)}")
        if next_steps:
            print(f"    Next Step        : {_shorten(str(next_steps[0]), 84)}")
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

    print(f"\n  {BOLD}WPA Path{RESET}")
    print(f"    Status           : {_status_badge(str(wpa_status.get('status') or 'ready'))}")
    print(f"    Summary          : {_shorten(str(wpa_status.get('summary') or 'WPA feasibility is not relevant to the current workflow.'), 84)}")
    reasons = list(wpa_status.get("reasons") or [])
    next_steps = list(wpa_status.get("next_steps") or [])
    if reasons:
        print(f"    Detail           : {_shorten(str(reasons[0]), 84)}")
    if next_steps:
        print(f"    Next Step        : {_shorten(str(next_steps[0]), 84)}")

    print(f"\n  {BOLD}What This Machine Can Do{RESET}")
    if machine_summary.get("headline"):
        print(f"    Profile          : {_shorten(str(machine_summary.get('headline')), 84)}")
    for item in list(machine_summary.get("items") or []):
        print(f"    {str(item.get('label') or ''):<16} {_status_badge(str(item.get('status') or 'blocked'))}")
        print(f"      {_shorten(str(item.get('summary') or ''), 88)}")
        reason = str(item.get("reason") or "").strip()
        next_step = str(item.get("next_step") or "").strip()
        if reason:
            print(f"      note : {_shorten(reason, 88)}")
        if next_step:
            print(f"      next : {_shorten(next_step, 88)}")


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
        support = dict(row.get("protocol_support") or {})
        if support:
            print(
                f"      support: decode={support.get('decode_level', 'heuristic')} "
                f"replay={support.get('replay_level', 'unsupported')} "
                f"type={support.get('dominant_unit_type', 'opaque_chunk')}"
            )
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
    report = CryptoAnalyzer(config).analyze(decrypted_dir)
    if not report:
        return report
    return attach_feasibility_to_report(config, report, _analysis_report_path(config))


def run_enrich(config: Dict[str, object], manifest_path: Optional[str] = None) -> Optional[Dict[str, object]]:
    return ArtifactEnricher(config).enrich(manifest_path)


def run_play(config: Dict[str, object]) -> Optional[str]:
    report = _load_report(config)
    if not report:
        err("No analysis report found. Run analyze first.")
        return None
    feasibility = dict(report.get("feasibility") or evaluate_pipeline_feasibility(config, report))
    replay_feasibility = dict(feasibility.get("replay") or {})
    if replay_feasibility.get("status") == "blocked":
        err(str(replay_feasibility.get("summary") or "Replay is blocked."))
        for blocker in replay_feasibility.get("blockers", []):
            err(str(blocker))
        for step in replay_feasibility.get("next_steps", []):
            info(f"Next: {step}")
        return None
    for warning in replay_feasibility.get("warnings", []):
        warn(str(warning))
    candidate = dict(report.get("candidate_material") or {})
    if not candidate:
        err("The last analysis report did not produce any experimental replay material.")
        return None
    support = replay_support_summary(report)
    replay_level = str(support.get("replay_level") or "unsupported")
    info(
        f"Replay family support: {replay_level.replace('_', ' ')} "
        f"for {support.get('dominant_unit_type') or 'selected stream'}."
    )
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
    run_enrich(config)
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
    run_enrich(config)
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
        profile = resolve_product_profile(config)
        options = [
            "Guided setup / configure device",                    # 0
            "Windows remote setup wizard" + _command_support_suffix(config, "setup-remote"),                        # 1
            "Capture traffic (dumpcap / tcpdump fallback)" + _command_support_suffix(config, "capture"),       # 2
            "Pair remote capture device (SSH key install)" + _command_support_suffix(config, "pair-remote"),       # 3
            "Bootstrap remote capture device" + _command_support_suffix(config, "bootstrap-remote"),                    # 4
            "Start remote capture, pull, and process" + _command_support_suffix(config, "start-remote"),            # 5
            "Pull remote capture (SSH/SCP)" + _command_support_suffix(config, "remote"),                      # 6
            "Monitor mode capture (airodump/besside/tcpdump)" + _command_support_suffix(config, "monitor"),   # 7
            "Crack WPA2 + decrypt pcap" + _command_support_suffix(config, "crack"),                          # 8
            "Strip Wi-Fi layer on an existing pcap",              # 9
            "Extract payload streams from a pcap",                # 10
            "Run payload detection",                              # 11
            "Review candidate payloads",                          # 12
            "Pin a preferred candidate stream",                   # 13
            "Edit custom stream hints",                           # 14
            "Run cipher heuristics",                              # 15
            "Start experimental replay / reconstruction",         # 16
            "Run full pipeline (dumpcap / tcpdump capture)" + _command_support_suffix(config, "all"),      # 17
            "Run full Wi-Fi pipeline (monitor + crack + decrypt)" + _command_support_suffix(config, "wifi"),# 18
            "Show latest report summary",                         # 19
            "Show corpus archive",                                # 20
            "Launch web dashboard",                               # 21
            "Run doctor" + _command_support_suffix(config, "doctor"),                                         # 22
            _active_validation_label(config) + _command_support_suffix(config, _active_validation_command(config)),    # 23
            "Show hardware qualification" + _command_support_suffix(config, "hardware"),                    # 24
            "Run pipeline preflight" + _command_support_suffix(config, "preflight"),                       # 25
            "Run release gate" + _command_support_suffix(config, "release-gate"),                         # 26
            "Exit",                                               # 27
        ]
        if profile.key == "windows_remote" and not str(config.get("remote_host") or "").strip():
            default = 1
        elif has_candidate:
            default = 16
        elif profile.key in ("ubuntu_standalone", "pi_standalone", "linux_best_effort"):
            default = 17
        else:
            default = 2 if IS_WINDOWS else 7
        selection = choose("Select an action", options, default=default)

        if selection == 0:
            config = interactive_config(config)
        elif selection == 1:
            if _enforce_command_support(config, "setup-remote"):
                run_setup_remote(config)
        elif selection == 2:
            if _enforce_command_support(config, "capture"):
                strip_wifi = confirm("Run Wi-Fi layer strip after capture?", default=bool(resolve_wpa_password(config)))
                run_capture(config, strip_wifi=strip_wifi)
        elif selection == 3:
            if _enforce_command_support(config, "pair-remote"):
                host = ask("Remote host (user@host)", str(config.get("remote_host") or ""))
                identity = ask("SSH identity file (blank = auto)", str(config.get("remote_identity") or "")).strip() or None
                run_pair_remote(config, host=host, identity=identity)
        elif selection == 4:
            if _enforce_command_support(config, "bootstrap-remote"):
                host = ask("Remote host (user@host)", str(config.get("remote_host") or ""))
                identity = ask("SSH identity file (blank = auto)", str(config.get("remote_identity") or "")).strip() or None
                install_packages = confirm("Install capture-side packages when possible?", default=True)
                install_mode = ask(
                    "Remote install mode (auto/native/bundle)",
                    str(config.get("remote_install_mode") or "auto"),
                ).strip().lower()
                install_profile = ask(
                    "Remote install profile (standard/appliance)",
                    str(config.get("remote_install_profile") or "appliance"),
                ).strip().lower()
                health_port = None
                if install_profile == "appliance":
                    health_port = ask_int(
                        "Appliance health port",
                        int(config.get("remote_health_port", 8741) or 8741),
                    )
                run_bootstrap_remote(
                    config,
                    host=host,
                    identity=identity,
                    install_packages=install_packages,
                    install_mode=install_mode,
                    install_profile=install_profile,
                    health_port=health_port,
                )
        elif selection == 5:
            if _enforce_command_support(config, "start-remote"):
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
            if _enforce_command_support(config, "remote"):
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
            if _enforce_command_support(config, "monitor"):
                method = ask("Capture method (airodump/besside/tcpdump)", str(config.get("monitor_method") or "airodump"))
                run_monitor(config, method=method)
        elif selection == 8:
            if _enforce_command_support(config, "crack"):
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
            if _enforce_command_support(config, "all"):
                decrypted = input("  > Directory of decrypted reference units (optional): ").strip() or None
                strip_wifi = confirm("Strip the Wi-Fi layer when possible?", default=bool(resolve_wpa_password(config)))
                run_all(config, None, decrypted, strip_wifi)
        elif selection == 18:
            if _enforce_command_support(config, "wifi"):
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
            if _enforce_command_support(config, "doctor"):
                run_doctor(
                    config,
                    host=str(config.get("remote_host") or "").strip() or None,
                    interface=str(config.get("remote_interface") or "").strip() or None,
                )
        elif selection == 23:
            validation_command = _active_validation_command(config)
            if _enforce_command_support(config, validation_command):
                if validation_command == "validate-local":
                    run_validate_local(
                        config,
                        interface=str(config.get("interface") or "").strip() or None,
                    )
                else:
                    run_validate_remote(
                        config,
                        host=str(config.get("remote_host") or "").strip() or None,
                        interface=str(config.get("remote_interface") or "").strip() or None,
                    )
        elif selection == 24:
            if _enforce_command_support(config, "hardware"):
                run_hardware(config)
        elif selection == 25:
            if _enforce_command_support(config, "preflight"):
                run_preflight(config)
        elif selection == 26:
            if _enforce_command_support(config, "release-gate"):
                run_release_gate(config)
        else:
            info("Goodbye.")
            return 0

        input("\n  Press Enter to continue...")


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args = _map_legacy_stage(args)

    banner()
    config = load_config(args.config)
    has_input_pcap = bool(getattr(args, "pcap", None)) if getattr(args, "command", None) == "all" else False

    if args.command and not _enforce_command_support(config, str(args.command), has_input_pcap=has_input_pcap):
        return 1

    if args.command == "deps":
        return 0 if check_environment(config) else 1

    if args.command == "hardware":
        return 0 if run_hardware(config) else 1

    if args.command == "preflight":
        return 0 if run_preflight(config) else 1

    if args.command == "release-gate":
        return 0 if run_release_gate(
            config,
            ubuntu_report=getattr(args, "ubuntu_report", None),
            pi_report=getattr(args, "pi_report", None),
            windows_report=getattr(args, "windows_report", None),
            sample_reports=list(getattr(args, "sample_report", None) or []),
            write_summary=getattr(args, "write_summary", None),
        ) else 1

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

    if args.command == "crack-status":
        return 0 if run_crack_status(config, handshake_cap=getattr(args, "cap", None)) else 1

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

    if args.command == "discover-remote":
        results = run_discover_remote(
            config,
            networks=list(getattr(args, "network", None) or []),
            health_port=getattr(args, "health_port", None),
            timeout=float(getattr(args, "timeout", 0.35) or 0.35),
            max_hosts=int(getattr(args, "max_hosts", 64) or 64),
        )
        return 0 if results else 1

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
            install_mode=getattr(args, "install_mode", None),
            install_profile=getattr(args, "install_profile", None),
            health_port=getattr(args, "health_port", None),
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
            install_mode=getattr(args, "install_mode", None),
            install_profile=getattr(args, "install_profile", None),
            health_port=getattr(args, "health_port", None),
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

    if args.command == "validate-local":
        result = run_validate_local(
            config,
            interface=getattr(args, "interface", None),
            duration=getattr(args, "duration", None),
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

    if args.command == "enrich":
        run_enrich(config, getattr(args, "manifest", None))
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
