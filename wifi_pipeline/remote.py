from __future__ import annotations

import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from . import __version__
from .remote_discovery import (
    DEFAULT_APPLIANCE_HEALTH_PORT,
    DEFAULT_DISCOVERY_HOST_LIMIT,
    DEFAULT_DISCOVERY_TIMEOUT,
    _candidate_discovery_hosts,
    _preferred_discovery_user,
    _probe_remote_appliance,
    discover_remote_appliances as _discover_remote_appliances_impl,
)
from .ui import done, err, info, ok, section, warn


@dataclass
class RemoteSource:
    host: str
    path: str
    port: int
    identity: str
    dest_dir: Path
    poll_interval: int


REMOTE_INSTALL_MODES = ("auto", "native", "bundle")
REMOTE_INSTALL_PROFILES = ("standard", "appliance")
REMOTE_AGENT_PROTOCOL = "capture-agent/v1"
REMOTE_RETRY_ATTEMPTS = 3
REMOTE_RETRY_BACKOFF_SECONDS = 0.5


def _run_remote(
    source: RemoteSource,
    args: List[str],
    *,
    capture_output: bool = True,
    text: bool = True,
    input: Optional[str] = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        _ssh_args(source) + args,
        capture_output=capture_output,
        text=text,
        input=input,
        check=False,
    )


def _retry_delay_seconds(attempt: int) -> float:
    return float(REMOTE_RETRY_BACKOFF_SECONDS) * max(1, int(attempt))


def _retry_remote_call(action, *, should_retry, attempts: int = REMOTE_RETRY_ATTEMPTS):
    max_attempts = max(1, int(attempts))
    result = None
    for attempt in range(1, max_attempts + 1):
        result = action()
        if not should_retry(result):
            return result
        if attempt < max_attempts:
            time.sleep(_retry_delay_seconds(attempt))
    return result


def _process_retryable(result: subprocess.CompletedProcess, *, stop_markers: tuple[str, ...] = ()) -> bool:
    if result.returncode == 0:
        return False
    message = f"{result.stderr or ''} {result.stdout or ''}".lower()
    return not any(marker in message for marker in stop_markers)


def _has_ssh_tools() -> bool:
    return bool(shutil.which("ssh")) and bool(shutil.which("scp"))


def discover_remote_appliances(
    config: Dict[str, object],
    *,
    networks: Optional[List[str]] = None,
    health_port: Optional[int] = None,
    timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
    max_hosts: int = DEFAULT_DISCOVERY_HOST_LIMIT,
) -> List[Dict[str, str]]:
    return _discover_remote_appliances_impl(
        config,
        networks=networks,
        health_port=health_port,
        timeout=timeout,
        max_hosts=max_hosts,
        candidate_hosts_fn=_candidate_discovery_hosts,
        probe_fn=_probe_remote_appliance,
        preferred_user_fn=_preferred_discovery_user,
    )


def _is_pattern(path: str) -> bool:
    return any(char in path for char in ("*", "?", "[", "]"))


def _escape_remote(pattern: str) -> str:
    return pattern.replace(" ", "\\ ")


def _latest_patterns(path: str) -> List[str]:
    if path.endswith("/"):
        base = path.rstrip("/")
        return [f"{base}/*.pcap*", f"{base}/*.cap*"]
    if _is_pattern(path):
        return [path]
    return []


def _ssh_args(source: RemoteSource) -> List[str]:
    args = ["ssh", "-o", "StrictHostKeyChecking=accept-new"]
    if source.port:
        args.extend(["-p", str(source.port)])
    if source.identity:
        args.extend(["-i", source.identity])
    args.append(source.host)
    return args


def _scp_args(source: RemoteSource) -> List[str]:
    args = ["scp", "-o", "StrictHostKeyChecking=accept-new"]
    if source.port:
        args.extend(["-P", str(source.port)])
    if source.identity:
        args.extend(["-i", source.identity])
    return args


def _private_key_path(identity: Optional[str] = None) -> Path:
    if identity:
        expanded = Path(os.path.expanduser(str(identity)))
        if expanded.suffix == ".pub":
            return Path(str(expanded)[:-4])
        return expanded
    return Path.home() / ".ssh" / "id_ed25519"


def _public_key_candidates(identity: Optional[str] = None) -> List[Path]:
    if identity:
        expanded = Path(os.path.expanduser(str(identity)))
        if expanded.suffix == ".pub":
            return [expanded]
        return [Path(str(expanded) + ".pub")]
    home = Path.home() / ".ssh"
    return [home / "id_ed25519.pub", home / "id_rsa.pub"]


def _ensure_public_key(identity: Optional[str] = None, generate_if_missing: bool = True) -> Optional[Path]:
    for candidate in _public_key_candidates(identity):
        if candidate.exists():
            return candidate

    if not generate_if_missing:
        return None

    ssh_keygen = shutil.which("ssh-keygen")
    if not ssh_keygen:
        return None

    private_key = _private_key_path(identity)
    private_key.parent.mkdir(parents=True, exist_ok=True)
    cmd = [ssh_keygen, "-t", "ed25519", "-f", str(private_key), "-N", ""]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return None

    public_key = Path(str(private_key) + ".pub")
    if public_key.exists():
        return public_key
    return None


def _authorized_keys_script(public_key: str) -> str:
    quoted_key = shlex.quote(public_key)
    return (
        "set -eu; "
        "umask 077; "
        "mkdir -p ~/.ssh; "
        "touch ~/.ssh/authorized_keys; "
        f"grep -qxF {quoted_key} ~/.ssh/authorized_keys || printf '%s\\n' {quoted_key} >> ~/.ssh/authorized_keys; "
        "chmod 700 ~/.ssh; "
        "chmod 600 ~/.ssh/authorized_keys"
    )


def _resolve_latest_remote_path(source: RemoteSource) -> Optional[str]:
    patterns = _latest_patterns(source.path)
    if not patterns:
        return None
    escaped = " ".join(_escape_remote(pattern) for pattern in patterns)
    result = _retry_remote_call(
        lambda: _run_remote(source, ["--", "sh", "-lc", f"ls -t {escaped} 2>/dev/null | head -n 1"]),
        should_retry=lambda outcome: outcome.returncode != 0 or not (outcome.stdout or "").strip(),
    )
    if result.returncode != 0:
        return None
    latest = (result.stdout or "").strip()
    return latest or None


def _resolve_remote_home(source: RemoteSource) -> Optional[str]:
    result = _retry_remote_call(
        lambda: _run_remote(source, ["--", "sh", "-lc", 'printf "%s" "$HOME"']),
        should_retry=lambda outcome: outcome.returncode != 0 or not (outcome.stdout or "").strip(),
    )
    if result.returncode != 0:
        return None
    value = (result.stdout or "").strip()
    return value or None


def _capture_helper_script(capture_dir: str) -> str:
    quoted_capture_dir = shlex.quote(capture_dir)
    return f"""#!/usr/bin/env bash
set -euo pipefail

CAPTURE_DIR={quoted_capture_dir}
PRIVILEGED_RUNNER="/usr/local/bin/wifi-pipeline-capture-privileged"
INTERFACE=""
DURATION="60"
OUTPUT=""
EXTRA_ARGS=()

usage() {{
    echo "Usage: wifi-pipeline-capture --interface <iface> [--duration seconds] [--output path] [--] [extra tcpdump args...]" >&2
}}

fail_privileges() {{
    echo "capture_privileges_unavailable: re-run bootstrap-remote with a user that has sudo access, or configure passwordless capture for tcpdump." >&2
    exit 3
}}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface|-i)
            INTERFACE="${{2:-}}"
            shift 2
            ;;
        --duration|-d)
            DURATION="${{2:-}}"
            shift 2
            ;;
        --output|-o)
            OUTPUT="${{2:-}}"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        --)
            shift
            EXTRA_ARGS+=("$@")
            break
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

if [[ -z "$INTERFACE" ]]; then
    usage
    exit 1
fi
if [[ ! "$INTERFACE" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
    echo "invalid interface name: $INTERFACE" >&2
    exit 1
fi
if [[ ! "$DURATION" =~ ^[0-9]+$ ]]; then
    echo "duration must be a non-negative integer" >&2
    exit 1
fi

mkdir -p "$CAPTURE_DIR"
if [[ -z "$OUTPUT" ]]; then
    stamp=$(date +%Y%m%d_%H%M%S)
    OUTPUT="$CAPTURE_DIR/capture_${{stamp}}.pcap"
fi
mkdir -p "$(dirname "$OUTPUT")"

echo "[*] Saving capture to $OUTPUT"
if [[ -x "$PRIVILEGED_RUNNER" ]]; then
    if command -v sudo >/dev/null 2>&1 && sudo -n "$PRIVILEGED_RUNNER" --help >/dev/null 2>&1; then
        if [[ "${{#EXTRA_ARGS[@]}}" -gt 0 ]]; then
            echo "extra tcpdump args are not supported with the privileged runner" >&2
            exit 1
        fi
        sudo -n "$PRIVILEGED_RUNNER" --interface "$INTERFACE" --duration "$DURATION" --output "$OUTPUT"
    else
        echo "capture_privileges_unavailable: privileged runner exists but passwordless sudo access is not configured." >&2
        exit 3
    fi
else
    TCPDUMP_CMD=(tcpdump -i "$INTERFACE" -w "$OUTPUT")
    if [[ "${{#EXTRA_ARGS[@]}}" -gt 0 ]]; then
        TCPDUMP_CMD+=("${{EXTRA_ARGS[@]}}")
    fi

    RUN_CMD=("${{TCPDUMP_CMD[@]}}")
    if [[ "${{EUID}}" -ne 0 ]]; then
        if ! command -v sudo >/dev/null 2>&1; then
            fail_privileges
        fi
        if ! sudo -n true >/dev/null 2>&1; then
            fail_privileges
        fi
        RUN_CMD=(sudo -n "${{RUN_CMD[@]}}")
    fi

    if [[ "$DURATION" != "0" ]]; then
        "${{RUN_CMD[@]}}" &
        CAPTURE_PID=$!
        sleep 1
        if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
            wait "$CAPTURE_PID"
            exit $?
        fi
        if [[ "$DURATION" -gt 1 ]]; then
            sleep "$((DURATION - 1))"
        fi
        kill -INT "$CAPTURE_PID" 2>/dev/null || true
        wait "$CAPTURE_PID" || true
    else
        "${{RUN_CMD[@]}}"
    fi
fi
printf '%s\\n' "$OUTPUT"
"""


def _privileged_capture_runner_script(capture_dir: str) -> str:
    quoted_capture_dir = shlex.quote(capture_dir)
    return f"""#!/usr/bin/env bash
set -euo pipefail

CAPTURE_DIR={quoted_capture_dir}
INTERFACE=""
DURATION="60"
OUTPUT=""

usage() {{
    echo "Usage: wifi-pipeline-capture-privileged --interface <iface> [--duration seconds] --output <path>" >&2
}}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface|-i)
            INTERFACE="${{2:-}}"
            shift 2
            ;;
        --duration|-d)
            DURATION="${{2:-}}"
            shift 2
            ;;
        --output|-o)
            OUTPUT="${{2:-}}"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [[ -z "$INTERFACE" || -z "$OUTPUT" ]]; then
    usage
    exit 1
fi
if [[ ! "$INTERFACE" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
    echo "invalid interface name: $INTERFACE" >&2
    exit 1
fi
if [[ ! "$DURATION" =~ ^[0-9]+$ ]]; then
    echo "duration must be a non-negative integer" >&2
    exit 1
fi

mkdir -p "$CAPTURE_DIR"
CAPTURE_DIR_REAL="$(cd "$CAPTURE_DIR" && pwd -P)"
OUTPUT_PARENT="$(dirname "$OUTPUT")"
mkdir -p "$OUTPUT_PARENT"
OUTPUT_REAL="$(cd "$OUTPUT_PARENT" && pwd -P)/$(basename "$OUTPUT")"
case "$OUTPUT_REAL" in
    "$CAPTURE_DIR_REAL"/*) ;;
    *)
        echo "output path must stay under $CAPTURE_DIR_REAL" >&2
        exit 2
        ;;
esac
OUTPUT="$OUTPUT_REAL"
TCPDUMP_CMD=(tcpdump -i "$INTERFACE" -w "$OUTPUT")

if [[ "$DURATION" != "0" ]]; then
    "${{TCPDUMP_CMD[@]}}" &
    CAPTURE_PID=$!
    sleep "$DURATION"
    kill -INT "$CAPTURE_PID" 2>/dev/null || true
    wait "$CAPTURE_PID" || true
else
    exec "${{TCPDUMP_CMD[@]}}"
    fi
"""


def _capture_service_script(remote_root: str, capture_dir: str) -> str:
    quoted_remote_root = shlex.quote(remote_root)
    quoted_capture_dir = shlex.quote(capture_dir)
    return f"""#!/usr/bin/env bash
set -euo pipefail

REMOTE_ROOT={quoted_remote_root}
CAPTURE_DIR={quoted_capture_dir}
STATE_DIR="$REMOTE_ROOT/state"
PID_FILE="$STATE_DIR/capture-service.pid"
META_FILE="$STATE_DIR/capture-service.env"
LAST_FILE="$STATE_DIR/last-capture.txt"
LOG_FILE="$STATE_DIR/capture-service.log"
LOCAL_HELPER="$HOME/.local/bin/wifi-pipeline-capture"
HELPER="$REMOTE_ROOT/bin/wifi-pipeline-capture"
ACTION="${{1:-status}}"
if [[ $# -gt 0 ]]; then
    shift
fi
INTERFACE=""
DURATION="60"
OUTPUT=""
STALE_PID_CLEANED="no"
STALE_PID_VALUE=""

usage() {{
    echo "Usage: wifi-pipeline-service <start|stop|status|last-capture> [--interface <iface>] [--duration <seconds>] [--output <path>]" >&2
}}

resolve_helper() {{
    if [[ -x "$LOCAL_HELPER" ]]; then
        HELPER="$LOCAL_HELPER"
    fi
}}

current_boot_id() {{
    if [[ -r "/proc/sys/kernel/random/boot_id" ]]; then
        tr -d '[:space:]' < "/proc/sys/kernel/random/boot_id"
    else
        printf 'unknown'
    fi
}}

meta_value() {{
    local key="$1"
    if [[ ! -f "$META_FILE" ]]; then
        return 0
    fi
    grep -E "^${{key}}=" "$META_FILE" | tail -n 1 | cut -d= -f2- || true
}}

meta_set() {{
    local key="$1"
    local value="${{2-}}"
    local temp_file=""
    mkdir -p "$STATE_DIR"
    touch "$META_FILE"
    temp_file="$(mktemp "$STATE_DIR/meta.XXXXXX")"
    awk -F= -v key="$key" -v value="$value" '
        BEGIN {{ updated=0 }}
        $1 == key {{ print key "=" value; updated=1; next }}
        {{ print }}
        END {{ if (!updated) print key "=" value }}
    ' "$META_FILE" > "$temp_file"
    mv "$temp_file" "$META_FILE"
}}

finalize_lifecycle_state() {{
    local result_name="$1"
    local exit_code="$2"
    local reason="$3"
    [[ -f "$META_FILE" ]] || return 0
    meta_set finished_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    meta_set last_result "$result_name"
    meta_set last_exit_code "$exit_code"
    meta_set recovery_reason "$reason"
}}

reset_service_flags() {{
    STALE_PID_CLEANED="no"
    STALE_PID_VALUE=""
}}

running_pid() {{
    if [[ ! -f "$PID_FILE" ]]; then
        return 1
    fi
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [[ -z "$pid" ]]; then
        rm -f "$PID_FILE"
        return 1
    fi
    if kill -0 "$pid" 2>/dev/null; then
        printf '%s\\n' "$pid"
        return 0
    fi
    STALE_PID_CLEANED="yes"
    STALE_PID_VALUE="$pid"
    rm -f "$PID_FILE"
    return 1
}}

emit_status() {{
    local service_status="idle"
    local pid=""
    local current_output=""
    local marker_file=""
    local checksum_file=""
    local last_result=""
    local finished_at=""
    local meta_boot_id=""
    local observed_boot_id=""
    local recovery_reason=""
    reset_service_flags
    if pid="$(running_pid)"; then
        service_status="running"
    elif [[ -f "$META_FILE" ]]; then
        last_result="$(meta_value last_result)"
        current_output="$(meta_value output)"
        finished_at="$(meta_value finished_at)"
        meta_boot_id="$(meta_value boot_id)"
        recovery_reason="$(meta_value recovery_reason)"
        observed_boot_id="$(current_boot_id)"
        if [[ "$last_result" == "starting" && -z "$finished_at" ]]; then
            if [[ -n "$meta_boot_id" && -n "$observed_boot_id" && "$meta_boot_id" != "$observed_boot_id" ]]; then
                finalize_lifecycle_state "interrupted_reboot" "130" "reboot"
                last_result="interrupted_reboot"
                recovery_reason="reboot"
            elif [[ "$STALE_PID_CLEANED" == "yes" ]]; then
                finalize_lifecycle_state "interrupted" "130" "stale_pid"
                last_result="interrupted"
                recovery_reason="stale_pid"
            fi
        fi
        case "$last_result" in
            failed)
                service_status="failed"
                ;;
            stopped)
                service_status="stopped"
                ;;
            interrupted|interrupted_reboot)
                service_status="interrupted"
                ;;
            complete|"")
                service_status="idle"
                ;;
        esac
    fi
    printf 'service_status=%s\\n' "$service_status"
    if [[ -n "$pid" ]]; then
        printf 'pid=%s\\n' "$pid"
    fi
    if [[ "$STALE_PID_CLEANED" == "yes" ]]; then
        echo "stale_pid_cleaned=yes"
        printf 'stale_pid=%s\\n' "$STALE_PID_VALUE"
    else
        echo "stale_pid_cleaned=no"
    fi
    if [[ -n "$recovery_reason" ]]; then
        printf 'recovery_reason=%s\\n' "$recovery_reason"
    fi
    printf 'capture_dir=%s\\n' "$CAPTURE_DIR"
    printf 'log_file=%s\\n' "$LOG_FILE"
    if [[ -f "$META_FILE" ]]; then
        cat "$META_FILE"
    fi
    if [[ -n "$current_output" ]]; then
        marker_file="${{current_output}}.complete"
        checksum_file="${{current_output}}.sha256"
        if [[ -f "$marker_file" ]]; then
            echo "complete_marker=yes"
            cat "$marker_file"
        else
            echo "complete_marker=no"
        fi
        if [[ -f "$checksum_file" ]]; then
            echo "checksum_file=yes"
            printf 'checksum_value=%s\\n' "$(tr -d '[:space:]' < "$checksum_file")"
        else
            echo "checksum_file=no"
        fi
        if [[ -f "$current_output" ]]; then
            printf 'remote_size_bytes=%s\\n' "$(wc -c < "$current_output" | tr -d ' ')"
        fi
    fi
    if [[ -f "$LAST_FILE" ]]; then
        printf 'last_capture=%s\\n' "$(cat "$LAST_FILE")"
    fi
}}

validate_start() {{
    if [[ -z "$INTERFACE" ]]; then
        usage
        exit 1
    fi
    if [[ ! "$INTERFACE" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
        echo "invalid interface name: $INTERFACE" >&2
        exit 1
    fi
    if [[ ! "$DURATION" =~ ^[0-9]+$ ]]; then
        echo "duration must be a non-negative integer" >&2
        exit 1
    fi
}}

start_capture() {{
    local pid=""
    resolve_helper
    mkdir -p "$STATE_DIR" "$CAPTURE_DIR"
    if [[ ! -x "$HELPER" ]]; then
        echo "missing_helper" >&2
        exit 1
    fi
    if pid="$(running_pid)"; then
        printf 'service_status=running\\n'
        printf 'pid=%s\\n' "$pid"
        if [[ -f "$META_FILE" ]]; then
            cat "$META_FILE"
        fi
        exit 0
    fi

    validate_start
    if [[ -z "$OUTPUT" ]]; then
        local stamp
        stamp="$(date +%Y%m%d_%H%M%S)"
        OUTPUT="$CAPTURE_DIR/capture_${{stamp}}.pcap"
    fi
    mkdir -p "$(dirname "$OUTPUT")"
    local started_at
    local start_boot_id
    started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    start_boot_id="$(current_boot_id)"
    local checksum_file="${{OUTPUT}}.sha256"
    local marker_file="${{OUTPUT}}.complete"
    rm -f "$checksum_file" "$marker_file"
    {{
        printf 'interface=%s\\n' "$INTERFACE"
        printf 'duration=%s\\n' "$DURATION"
        printf 'output=%s\\n' "$OUTPUT"
        printf 'checksum_file=%s\\n' "$checksum_file"
        printf 'complete_marker=%s\\n' "$marker_file"
        printf 'started_at=%s\\n' "$started_at"
        printf 'finished_at=\\n'
        printf 'last_result=starting\\n'
        printf 'last_exit_code=\\n'
        printf 'boot_id=%s\\n' "$start_boot_id"
        printf 'recovery_reason=\\n'
    }} > "$META_FILE"

    export HELPER INTERFACE DURATION OUTPUT LOG_FILE META_FILE LAST_FILE PID_FILE started_at start_boot_id checksum_file marker_file
    nohup bash -lc '
set -euo pipefail
rc=0
"$HELPER" --interface "$INTERFACE" --duration "$DURATION" --output "$OUTPUT" > "$LOG_FILE" 2>&1 || rc=$?
printf "%s\\n" "$OUTPUT" > "$LAST_FILE"
result="complete"
checksum=""
if [[ "$rc" -ne 0 ]]; then
    result="failed"
    rm -f "$checksum_file" "$marker_file"
else
    if command -v sha256sum >/dev/null 2>&1; then
        checksum="$(sha256sum "$OUTPUT" | awk "{{print \\$1}}")"
    elif command -v shasum >/dev/null 2>&1; then
        checksum="$(shasum -a 256 "$OUTPUT" | awk "{{print \\$1}}")"
    elif command -v python3 >/dev/null 2>&1; then
        checksum="$(python3 -c "import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())" "$OUTPUT")"
    fi
    if [[ -n "$checksum" ]]; then
        printf "%s\\n" "$checksum" > "$checksum_file"
    fi
    {{
        printf "output=%s\\n" "$OUTPUT"
        printf "checksum=%s\\n" "$checksum"
        printf "remote_size_bytes=%s\\n" "$(wc -c < "$OUTPUT" | tr -d " ")"
        printf "finished_at=%s\\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    }} > "$marker_file"
fi
{{
    printf "interface=%s\\n" "$INTERFACE"
    printf "duration=%s\\n" "$DURATION"
    printf "output=%s\\n" "$OUTPUT"
    printf "checksum_file=%s\\n" "$checksum_file"
    printf "complete_marker=%s\\n" "$marker_file"
    printf "started_at=%s\\n" "$started_at"
    printf "finished_at=%s\\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf "last_result=%s\\n" "$result"
    printf "last_exit_code=%s\\n" "$rc"
    printf "boot_id=%s\\n" "$start_boot_id"
    printf "recovery_reason=\\n"
}} > "$META_FILE"
rm -f "$PID_FILE"
exit "$rc"
' >/dev/null 2>&1 </dev/null &
    local service_pid=$!
    printf '%s\\n' "$service_pid" > "$PID_FILE"
    printf 'service_status=running\\n'
    printf 'pid=%s\\n' "$service_pid"
    printf 'output=%s\\n' "$OUTPUT"
    printf 'capture_dir=%s\\n' "$CAPTURE_DIR"
    printf 'log_file=%s\\n' "$LOG_FILE"
}}

stop_capture() {{
    local pid=""
    if ! pid="$(running_pid)"; then
        emit_status
        return 0
    fi
    kill -INT "$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
    fi
    finalize_lifecycle_state "stopped" "130" "manual_stop"
    rm -f "$PID_FILE"
    printf 'service_status=stopped\\n'
    printf 'pid=%s\\n' "$pid"
    printf 'log_file=%s\\n' "$LOG_FILE"
    printf 'recovery_reason=%s\\n' "manual_stop"
    if [[ -f "$LAST_FILE" ]]; then
        printf 'last_capture=%s\\n' "$(cat "$LAST_FILE")"
    fi
}}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface|-i)
            INTERFACE="${{2:-}}"
            shift 2
            ;;
        --duration|-d)
            DURATION="${{2:-}}"
            shift 2
            ;;
        --output|-o)
            OUTPUT="${{2:-}}"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

case "$ACTION" in
    start)
        start_capture
        ;;
    stop)
        stop_capture
        ;;
    status)
        emit_status
        ;;
    last-capture)
        emit_status
        ;;
    *)
        usage
        exit 1
        ;;
esac
"""


def _capture_agent_script(remote_root: str, capture_dir: str) -> str:
    quoted_remote_root = shlex.quote(remote_root)
    quoted_capture_dir = shlex.quote(capture_dir)
    return f"""#!/usr/bin/env bash
set -euo pipefail

PROTOCOL="{REMOTE_AGENT_PROTOCOL}"
VERSION="{__version__}"
REMOTE_ROOT={quoted_remote_root}
CAPTURE_DIR={quoted_capture_dir}
STATE_DIR="$REMOTE_ROOT/state"
LOCAL_BIN="$HOME/.local/bin"
LOCAL_HELPER="$LOCAL_BIN/wifi-pipeline-capture"
HELPER="$REMOTE_ROOT/bin/wifi-pipeline-capture"
LOCAL_SERVICE="$LOCAL_BIN/wifi-pipeline-service"
SERVICE="$REMOTE_ROOT/bin/wifi-pipeline-service"
PRIVILEGED_RUNNER="/usr/local/bin/wifi-pipeline-capture-privileged"

json_escape() {{
    printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/"/\\"/g;s/\t/\\\\t/g;s/\r/\\\\r/g;s/\n/\\\\n/g'
}}

yes_no() {{
    if [[ "$1" == "0" ]]; then
        printf 'yes'
    else
        printf 'no'
    fi
}}

preferred_path() {{
    local local_path="$1"
    local fallback_path="$2"
    if [[ -x "$local_path" ]]; then
        printf '%s\\n' "$local_path"
    else
        printf '%s\\n' "$fallback_path"
    fi
}}

kv_to_json() {{
    local input_file="$1"
    local first=1
    printf '{{'
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" == *=* ]] || continue
        local key="${{line%%=*}}"
        local value="${{line#*=}}"
        if [[ $first -eq 0 ]]; then
            printf ','
        fi
        first=0
        printf '"%s":"%s"' "$(json_escape "$key")" "$(json_escape "$value")"
    done < "$input_file"
    printf '}}'
}}

emit_json() {{
    local ok="$1"
    local returncode="$2"
    local data_file="$3"
    local error_message="${{4:-}}"
    local stdout_value="${{5:-}}"
    local stderr_value="${{6:-}}"
    printf '{{"ok":%s,"protocol":"%s","returncode":%s,"data":' "$ok" "$PROTOCOL" "$returncode"
    kv_to_json "$data_file"
    if [[ -n "$error_message" ]]; then
        printf ',"error":"%s"' "$(json_escape "$error_message")"
    fi
    if [[ -n "$stdout_value" ]]; then
        printf ',"stdout":"%s"' "$(json_escape "$stdout_value")"
    fi
    if [[ -n "$stderr_value" ]]; then
        printf ',"stderr":"%s"' "$(json_escape "$stderr_value")"
    fi
    printf '}}\\n'
}}

artifact_info() {{
    local path="$1"
    local marker_path="${{path}}.complete"
    local checksum_path="${{path}}.sha256"
    if [[ -f "$path" ]]; then
        echo "file_exists=yes"
    else
        echo "file_exists=no"
        return 0
    fi
    if [[ -f "$marker_path" ]]; then
        echo "complete_marker=yes"
    else
        echo "complete_marker=no"
    fi
    if [[ -f "$checksum_path" ]]; then
        echo "checksum_file=yes"
        printf 'checksum_value=%s\\n' "$(tr -d '[:space:]' < "$checksum_path")"
    else
        echo "checksum_file=no"
    fi
    printf 'remote_size_bytes=%s\\n' "$(wc -c < "$path" | tr -d ' ')"
}}

detect_privilege_mode() {{
    if [[ "$(id -u)" -eq 0 ]]; then
        printf 'root_session\\n'
    elif command -v sudo >/dev/null 2>&1 && [[ -x "$PRIVILEGED_RUNNER" ]] && sudo -n "$PRIVILEGED_RUNNER" --help >/dev/null 2>&1; then
        printf 'sudoers_runner\\n'
    else
        printf 'fallback\\n'
    fi
}}

detect_interface() {{
    local interface_name="$1"
    if [[ -e "/sys/class/net/$interface_name" ]]; then
        printf 'yes\\n'
    elif command -v ip >/dev/null 2>&1; then
        if ip link show "$interface_name" >/dev/null 2>&1; then
            printf 'yes\\n'
        else
            printf 'no\\n'
        fi
    elif command -v ifconfig >/dev/null 2>&1; then
        if ifconfig "$interface_name" >/dev/null 2>&1; then
            printf 'yes\\n'
        else
            printf 'no\\n'
        fi
    else
        printf 'unknown\\n'
    fi
}}

run_service() {{
    local action="$1"
    shift
    local service_path
    service_path="$(preferred_path "$LOCAL_SERVICE" "$SERVICE")"
    local data_file stdout_file stderr_file
    data_file="$(mktemp)"
    stdout_file="$(mktemp)"
    stderr_file="$(mktemp)"
    if [[ ! -x "$service_path" ]]; then
        emit_json false 1 "$data_file" "missing_service" "" "Remote capture service not found."
        rm -f "$data_file" "$stdout_file" "$stderr_file"
        return 1
    fi
    set +e
    "$service_path" "$action" "$@" >"$stdout_file" 2>"$stderr_file"
    local rc=$?
    set -e
    cp "$stdout_file" "$data_file"
    emit_json "$([[ $rc -eq 0 ]] && printf true || printf false)" "$rc" "$data_file" "$([[ $rc -eq 0 ]] && printf '' || printf 'service_failed')" "$(cat "$stdout_file")" "$(cat "$stderr_file")"
    rm -f "$data_file" "$stdout_file" "$stderr_file"
    return "$rc"
}}

run_doctor() {{
    local interface_name="${{1:-}}"
    local helper_path service_path data_file status_file appliance_env
    helper_path="$(preferred_path "$LOCAL_HELPER" "$HELPER")"
    service_path="$(preferred_path "$LOCAL_SERVICE" "$SERVICE")"
    appliance_env="$STATE_DIR/appliance.env"
    data_file="$(mktemp)"
    status_file="$(mktemp)"
    printf 'tcpdump=%s\\n' "$(yes_no "$([[ -n "$(command -v tcpdump 2>/dev/null)" ]] && printf 0 || printf 1)")" > "$data_file"
    printf 'helper=%s\\n' "$(yes_no "$([[ -x "$helper_path" ]] && printf 0 || printf 1)")" >> "$data_file"
    printf 'helper_path=%s\\n' "$helper_path" >> "$data_file"
    printf 'service=%s\\n' "$(yes_no "$([[ -x "$service_path" ]] && printf 0 || printf 1)")" >> "$data_file"
    printf 'service_path=%s\\n' "$service_path" >> "$data_file"
    printf 'privileged_runner=%s\\n' "$(yes_no "$([[ -x "$PRIVILEGED_RUNNER" ]] && printf 0 || printf 1)")" >> "$data_file"
    printf 'privileged_runner_path=%s\\n' "$PRIVILEGED_RUNNER" >> "$data_file"
    printf 'privilege_mode=%s\\n' "$(detect_privilege_mode)" >> "$data_file"
    printf 'state_dir=%s\\n' "$STATE_DIR" >> "$data_file"
    printf 'state_dir_exists=%s\\n' "$(yes_no "$([[ -d "$STATE_DIR" ]] && printf 0 || printf 1)")" >> "$data_file"
    printf 'state_dir_writable=%s\\n' "$(yes_no "$([[ -w "$STATE_DIR" ]] && printf 0 || printf 1)")" >> "$data_file"
    printf 'capture_dir=%s\\n' "$CAPTURE_DIR" >> "$data_file"
    printf 'capture_dir_exists=%s\\n' "$(yes_no "$([[ -d "$CAPTURE_DIR" ]] && printf 0 || printf 1)")" >> "$data_file"
    printf 'capture_dir_writable=%s\\n' "$(yes_no "$([[ -w "$CAPTURE_DIR" ]] && printf 0 || printf 1)")" >> "$data_file"
    printf 'agent=yes\\n' >> "$data_file"
    printf 'agent_path=%s\\n' "$0" >> "$data_file"
    printf 'agent_protocol=%s\\n' "$PROTOCOL" >> "$data_file"
    printf 'agent_version=%s\\n' "$VERSION" >> "$data_file"
    printf 'control_mode=agent\\n' >> "$data_file"
    printf 'remote_root=%s\\n' "$REMOTE_ROOT" >> "$data_file"
    printf 'helper_version=%s\\n' "$VERSION" >> "$data_file"
    printf 'service_version=%s\\n' "$VERSION" >> "$data_file"
    if [[ -f "$appliance_env" ]]; then
        cat "$appliance_env" >> "$data_file"
    else
        printf 'install_profile=standard\\n' >> "$data_file"
    fi
    if [[ -x "$service_path" ]]; then
        set +e
        "$service_path" status >"$status_file" 2>/dev/null
        set -e
        cat "$status_file" >> "$data_file"
    else
        printf 'service_status=missing\\n' >> "$data_file"
    fi
    local last_capture=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" == last_capture=* ]]; then
            last_capture="${{line#*=}}"
        elif [[ -z "$last_capture" && "$line" == output=* ]]; then
            last_capture="${{line#*=}}"
        fi
    done < "$data_file"
    if [[ -n "$last_capture" ]]; then
        artifact_info "$last_capture" >> "$data_file"
    fi
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-enabled wifi-pipeline-appliance.service >/dev/null 2>&1; then
            printf 'appliance_service_enabled=yes\\n' >> "$data_file"
        else
            printf 'appliance_service_enabled=no\\n' >> "$data_file"
        fi
        if systemctl is-active wifi-pipeline-appliance.service >/dev/null 2>&1; then
            printf 'appliance_service_active=yes\\n' >> "$data_file"
        else
            printf 'appliance_service_active=no\\n' >> "$data_file"
        fi
        if systemctl is-enabled wifi-pipeline-health.socket >/dev/null 2>&1; then
            printf 'health_socket_enabled=yes\\n' >> "$data_file"
        else
            printf 'health_socket_enabled=no\\n' >> "$data_file"
        fi
        if systemctl is-active wifi-pipeline-health.socket >/dev/null 2>&1; then
            printf 'health_socket_active=yes\\n' >> "$data_file"
        else
            printf 'health_socket_active=no\\n' >> "$data_file"
        fi
    else
        printf 'appliance_service_enabled=unknown\\n' >> "$data_file"
        printf 'appliance_service_active=unknown\\n' >> "$data_file"
        printf 'health_socket_enabled=unknown\\n' >> "$data_file"
        printf 'health_socket_active=unknown\\n' >> "$data_file"
    fi
    if [[ -n "$interface_name" ]]; then
        printf 'interface_exists=%s\\n' "$(detect_interface "$interface_name")" >> "$data_file"
    fi
    emit_json true 0 "$data_file"
    rm -f "$data_file" "$status_file"
}}

run_artifact_info() {{
    local path="$1"
    local data_file
    data_file="$(mktemp)"
    artifact_info "$path" > "$data_file"
    emit_json true 0 "$data_file"
    rm -f "$data_file"
}}

COMMAND="${{1:-}}"
if [[ $# -gt 0 ]]; then
    shift
fi

case "$COMMAND" in
    service)
        ACTION="${{1:-status}}"
        if [[ $# -gt 0 ]]; then
            shift
        fi
        run_service "$ACTION" "$@"
        ;;
    doctor)
        INTERFACE=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --interface)
                    INTERFACE="${{2:-}}"
                    shift 2
                    ;;
                *)
                    echo "unknown argument: $1" >&2
                    exit 1
                    ;;
            esac
        done
        run_doctor "$INTERFACE"
        ;;
    artifact-info)
        PATH_VALUE=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --path)
                    PATH_VALUE="${{2:-}}"
                    shift 2
                    ;;
                *)
                    echo "unknown argument: $1" >&2
                    exit 1
                    ;;
            esac
        done
        if [[ -z "$PATH_VALUE" ]]; then
            echo "artifact-info requires --path" >&2
            exit 1
        fi
        run_artifact_info "$PATH_VALUE"
        ;;
    *)
        echo "Usage: wifi-pipeline-agent <service|doctor|artifact-info> [...]" >&2
        exit 1
        ;;
esac
"""


def build_capture_agent_bundle(
    output_dir: Optional[Path | str] = None,
    *,
    remote_root: str = "/opt/wifi-pipeline",
    capture_dir: Optional[str] = None,
) -> Path:
    bundle_capture_dir = capture_dir or f"{remote_root.rstrip('/')}/captures"
    destination_dir = Path(output_dir).resolve() if output_dir else (Path.cwd() / "dist").resolve()
    destination_dir.mkdir(parents=True, exist_ok=True)
    bundle_name = f"wifi-pipeline-agent-{__version__}-bundle.tar.gz"
    bundle_path = destination_dir / bundle_name

    members = {
        "manifest.json": json.dumps(
            {
                "version": __version__,
                "kind": "wifi-pipeline-agent-bundle",
                "remote_root": remote_root,
                "capture_dir": bundle_capture_dir,
                "files": [
                    "install.sh",
                    "bin/wifi-pipeline-agent",
                    "bin/wifi-pipeline-capture",
                    "bin/wifi-pipeline-service",
                ],
            },
            indent=2,
        )
        + "\n",
        "bin/wifi-pipeline-agent": _capture_agent_script(remote_root, bundle_capture_dir),
        "bin/wifi-pipeline-capture": _capture_helper_script(bundle_capture_dir),
        "bin/wifi-pipeline-service": _capture_service_script(remote_root, bundle_capture_dir),
        "install.sh": (
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            f"REMOTE_ROOT={shlex.quote(remote_root)}\n"
            'BIN_DIR="$REMOTE_ROOT/bin"\n'
            'STATE_DIR="$REMOTE_ROOT/state"\n'
            'LOCAL_BIN="$HOME/.local/bin"\n'
            'mkdir -p "$BIN_DIR" "$STATE_DIR" "$LOCAL_BIN"\n'
            'install -m 755 bin/wifi-pipeline-agent "$BIN_DIR/wifi-pipeline-agent"\n'
            'install -m 755 bin/wifi-pipeline-capture "$BIN_DIR/wifi-pipeline-capture"\n'
            'install -m 755 bin/wifi-pipeline-service "$BIN_DIR/wifi-pipeline-service"\n'
            'ln -sf "$BIN_DIR/wifi-pipeline-agent" "$LOCAL_BIN/wifi-pipeline-agent"\n'
            'ln -sf "$BIN_DIR/wifi-pipeline-capture" "$LOCAL_BIN/wifi-pipeline-capture"\n'
            'ln -sf "$BIN_DIR/wifi-pipeline-service" "$LOCAL_BIN/wifi-pipeline-service"\n'
            'printf "remote_root=%s\\n" "$REMOTE_ROOT"\n'
            f'printf "capture_dir=%s\\n" {shlex.quote(bundle_capture_dir)}\n'
            'printf "agent_cmd=%s\\n" "$BIN_DIR/wifi-pipeline-agent"\n'
            'printf "capture_cmd=%s\\n" "$BIN_DIR/wifi-pipeline-capture"\n'
            'printf "service_cmd=%s\\n" "$BIN_DIR/wifi-pipeline-service"\n'
        ),
    }

    with tarfile.open(bundle_path, "w:gz") as archive:
        for name, content in members.items():
            data = content.encode("utf-8")
            info_obj = tarfile.TarInfo(name)
            info_obj.size = len(data)
            info_obj.mode = 0o755 if name.startswith("bin/") or name == "install.sh" else 0o644
            archive.addfile(info_obj, io.BytesIO(data))

    return bundle_path


def _package_install_block() -> str:
    return """
install_packages() {
    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
    elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
        SUDO="sudo -n"
    else
        echo "[!] passwordless sudo not available; skipping package installation."
        return 0
    fi

    if command -v apt-get >/dev/null 2>&1; then
        $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -qq
        $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y tcpdump >/dev/null
    elif command -v dnf >/dev/null 2>&1; then
        $SUDO dnf install -y tcpdump >/dev/null
    elif command -v yum >/dev/null 2>&1; then
        $SUDO yum install -y tcpdump >/dev/null
    elif command -v pacman >/dev/null 2>&1; then
        $SUDO pacman -Sy --noconfirm tcpdump >/dev/null
    elif command -v zypper >/dev/null 2>&1; then
        $SUDO zypper --non-interactive install tcpdump >/dev/null
    elif command -v apk >/dev/null 2>&1; then
        $SUDO apk add tcpdump >/dev/null
    elif command -v brew >/dev/null 2>&1; then
        brew install tcpdump >/dev/null
    else
        echo "[!] No supported package manager found; skipping package installation."
    fi
}
install_packages
"""


def _post_install_setup_script(remote_root: str, capture_dir: str, install_packages: bool = True) -> str:
    quoted_remote_root = shlex.quote(remote_root)
    quoted_capture_dir = shlex.quote(capture_dir)
    runner_script = _privileged_capture_runner_script(capture_dir)
    install_block = _package_install_block() if install_packages else ""
    return f"""set -eu

REMOTE_ROOT={quoted_remote_root}
CAPTURE_DIR={quoted_capture_dir}
BIN_DIR="$REMOTE_ROOT/bin"
STATE_DIR="$REMOTE_ROOT/state"
HELPER="$BIN_DIR/wifi-pipeline-capture"
SERVICE="$BIN_DIR/wifi-pipeline-service"
AGENT="$BIN_DIR/wifi-pipeline-agent"
PRIVILEGED_RUNNER="/usr/local/bin/wifi-pipeline-capture-privileged"
SUDOERS_FILE="/etc/sudoers.d/wifi-pipeline-capture"
LOCAL_BIN="$HOME/.local/bin"
PRIVILEGE_MODE="fallback"

{install_block}

setup_privileged_runner() {{
    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
    elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
        SUDO="sudo -n"
    else
        echo "[!] passwordless sudo not available; leaving capture privileges in fallback mode."
        return 0
    fi

    CURRENT_USER="$(id -un)"
    $SUDO mkdir -p /usr/local/bin /etc/sudoers.d
    cat <<'EOF_RUNNER' | $SUDO tee "$PRIVILEGED_RUNNER" >/dev/null
{runner_script}EOF_RUNNER
    $SUDO chmod 755 "$PRIVILEGED_RUNNER"
    $SUDO chown root:root "$PRIVILEGED_RUNNER" >/dev/null 2>&1 || true
    printf '%s ALL=(root) NOPASSWD: %s\\n' "$CURRENT_USER" "$PRIVILEGED_RUNNER" | $SUDO tee "$SUDOERS_FILE" >/dev/null
    $SUDO chmod 440 "$SUDOERS_FILE"
    if command -v visudo >/dev/null 2>&1; then
        if ! $SUDO visudo -cf "$SUDOERS_FILE" >/dev/null; then
            echo "[!] sudoers validation failed; removing privileged runner access."
            $SUDO rm -f "$SUDOERS_FILE"
            return 0
        fi
    fi
    if $SUDO "$PRIVILEGED_RUNNER" --help >/dev/null 2>&1; then
        PRIVILEGE_MODE="sudoers_runner"
    fi
}}

mkdir -p "$REMOTE_ROOT" "$CAPTURE_DIR" "$BIN_DIR" "$LOCAL_BIN" "$STATE_DIR"
ln -sf "$AGENT" "$LOCAL_BIN/wifi-pipeline-agent"
ln -sf "$HELPER" "$LOCAL_BIN/wifi-pipeline-capture"
ln -sf "$SERVICE" "$LOCAL_BIN/wifi-pipeline-service"
setup_privileged_runner

printf 'remote_root=%s\\n' "$REMOTE_ROOT"
printf 'capture_dir=%s\\n' "$CAPTURE_DIR"
printf 'state_dir=%s\\n' "$STATE_DIR"
printf 'agent_cmd=%s\\n' "$AGENT"
printf 'capture_cmd=%s\\n' "$HELPER"
printf 'service_cmd=%s\\n' "$SERVICE"
printf 'privilege_mode=%s\\n' "$PRIVILEGE_MODE"
printf 'privileged_runner=%s\\n' "$PRIVILEGED_RUNNER"
"""


def _appliance_profile_script(remote_root: str, capture_dir: str, health_port: int = DEFAULT_APPLIANCE_HEALTH_PORT) -> str:
    quoted_remote_root = shlex.quote(remote_root)
    quoted_capture_dir = shlex.quote(capture_dir)
    quoted_health_port = int(health_port)
    return f"""set -eu

REMOTE_ROOT={quoted_remote_root}
CAPTURE_DIR={quoted_capture_dir}
STATE_DIR="$REMOTE_ROOT/state"
BIN_DIR="$REMOTE_ROOT/bin"
LOCAL_BIN="$HOME/.local/bin"
AGENT="$BIN_DIR/wifi-pipeline-agent"
HEALTH_SCRIPT="$BIN_DIR/wifi-pipeline-health-http"
APPLIANCE_ENV="$STATE_DIR/appliance.env"
HEALTH_PORT={quoted_health_port}
HEALTH_SERVICE_NAME="wifi-pipeline-health.service"
HEALTH_SOCKET_NAME="wifi-pipeline-health.socket"
APPLIANCE_SERVICE_NAME="wifi-pipeline-appliance.service"
SYSTEMD_DIR="/etc/systemd/system"
HEALTH_SERVICE_PATH="$SYSTEMD_DIR/$HEALTH_SERVICE_NAME"
HEALTH_SOCKET_PATH="$SYSTEMD_DIR/$HEALTH_SOCKET_NAME"
APPLIANCE_SERVICE_PATH="$SYSTEMD_DIR/$APPLIANCE_SERVICE_NAME"

if [ ! -x "$AGENT" ]; then
    echo "missing_agent" >&2
    exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemd_required_for_appliance_profile" >&2
    exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    SUDO="sudo -n"
else
    echo "sudo_required_for_appliance_profile" >&2
    exit 1
fi

$SUDO mkdir -p "$SYSTEMD_DIR"
mkdir -p "$STATE_DIR" "$BIN_DIR" "$LOCAL_BIN"

cat > "$HEALTH_SCRIPT" <<'EOF_HEALTH'
#!/usr/bin/env bash
set -euo pipefail
REMOTE_ROOT={quoted_remote_root}
AGENT="$REMOTE_ROOT/bin/wifi-pipeline-agent"
read -r _REQUEST_LINE || true
while IFS= read -r header; do
    header="${{header%$'\\r'}}"
    [[ -z "$header" ]] && break
done
BODY="$("$AGENT" doctor)"
printf 'HTTP/1.1 200 OK\\r\\n'
printf 'Content-Type: application/json\\r\\n'
printf 'Cache-Control: no-store\\r\\n'
printf 'Content-Length: %s\\r\\n' "${{#BODY}}"
printf '\\r\\n'
printf '%s' "$BODY"
EOF_HEALTH
chmod 755 "$HEALTH_SCRIPT"

cat <<EOF_ENV > "$APPLIANCE_ENV"
install_profile=appliance
health_port=$HEALTH_PORT
health_bind=0.0.0.0
health_path=/health
health_endpoint=http://0.0.0.0:$HEALTH_PORT/health
health_service=$HEALTH_SERVICE_NAME
health_socket=$HEALTH_SOCKET_NAME
appliance_service=$APPLIANCE_SERVICE_NAME
capture_dir=$CAPTURE_DIR
remote_root=$REMOTE_ROOT
ssh_user=$(id -un)
device_name=$(hostname)
EOF_ENV

cat <<EOF_SERVICE | $SUDO tee "$HEALTH_SERVICE_PATH" >/dev/null
[Unit]
Description=WiFi Pipeline Health Endpoint
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/bin/sh $HEALTH_SCRIPT
StandardInput=socket
StandardOutput=socket
Restart=no

[Install]
WantedBy=multi-user.target
EOF_SERVICE

cat <<EOF_SOCKET | $SUDO tee "$HEALTH_SOCKET_PATH" >/dev/null
[Unit]
Description=WiFi Pipeline Health Endpoint Socket

[Socket]
ListenStream=$HEALTH_PORT
Accept=no
NoDelay=true

[Install]
WantedBy=sockets.target
EOF_SOCKET

cat <<EOF_APPLIANCE | $SUDO tee "$APPLIANCE_SERVICE_PATH" >/dev/null
[Unit]
Description=WiFi Pipeline Appliance Bootstrap
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh -lc 'mkdir -p {shlex.quote(remote_root)}/captures {shlex.quote(remote_root)}/state && {shlex.quote(remote_root)}/bin/wifi-pipeline-agent doctor >/dev/null'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_APPLIANCE

$SUDO systemctl daemon-reload
$SUDO systemctl enable --now "$APPLIANCE_SERVICE_NAME" >/dev/null
$SUDO systemctl enable --now "$HEALTH_SOCKET_NAME" >/dev/null

printf 'install_profile=%s\\n' "appliance"
printf 'health_port=%s\\n' "$HEALTH_PORT"
printf 'health_bind=%s\\n' "0.0.0.0"
printf 'health_path=%s\\n' "/health"
printf 'health_endpoint=%s\\n' "http://0.0.0.0:$HEALTH_PORT/health"
printf 'health_service=%s\\n' "$HEALTH_SERVICE_NAME"
printf 'health_socket=%s\\n' "$HEALTH_SOCKET_NAME"
printf 'appliance_service=%s\\n' "$APPLIANCE_SERVICE_NAME"
"""


def _install_remote_appliance_profile(
    source: RemoteSource,
    *,
    remote_root: str,
    capture_dir: str,
    health_port: int,
) -> Optional[Dict[str, str]]:
    result = _run_remote(
        source,
        ["--", "sh", "-s"],
        input=_appliance_profile_script(remote_root, capture_dir, health_port=health_port),
    )
    if result.returncode != 0:
        err((result.stderr or result.stdout or "remote appliance install failed").strip())
        return None

    info_map: Dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            info_map[key.strip()] = value.strip()
    return info_map


def _resolve_remote_install_mode(requested: Optional[str], *, prefer_bundle: bool) -> str:
    mode = str(requested or "auto").strip().lower() or "auto"
    if mode not in REMOTE_INSTALL_MODES:
        return "auto"
    if mode == "auto":
        return "bundle" if prefer_bundle else "native"
    return mode


def _resolve_remote_install_profile(requested: Optional[str]) -> str:
    profile = str(requested or "appliance").strip().lower() or "appliance"
    if profile not in REMOTE_INSTALL_PROFILES:
        return "appliance"
    return profile


def _install_remote_bundle(
    source: RemoteSource,
    *,
    remote_home: str,
    remote_root: str,
    capture_dir: str,
    install_packages: bool,
) -> Optional[Dict[str, str]]:
    if not shutil.which("scp"):
        err("scp not found on PATH. Install OpenSSH client and re-run, or use --install-mode native.")
        return None

    with tempfile.TemporaryDirectory(prefix="wifi-pipeline-agent-") as temp_dir:
        bundle_path = build_capture_agent_bundle(
            output_dir=Path(temp_dir),
            remote_root=remote_root,
            capture_dir=capture_dir,
        )
        remote_bundle_path = f"{remote_home}/.wifi-pipeline-agent-{__version__}-bundle.tar.gz"
        copy_result = subprocess.run(
            _scp_args(source) + [str(bundle_path), f"{source.host}:{remote_bundle_path}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if copy_result.returncode != 0:
            err(copy_result.stderr.strip() or copy_result.stdout.strip() or "failed to upload the capture-agent bundle")
            return None

    extract_script = (
        "set -eu; "
        f'ARCHIVE={shlex.quote(remote_bundle_path)}; '
        'TMP_DIR="$(mktemp -d)"; '
        'cleanup() { rm -rf "$TMP_DIR"; rm -f "$ARCHIVE"; }; '
        'trap cleanup EXIT; '
        'tar -xzf "$ARCHIVE" -C "$TMP_DIR"; '
        'cd "$TMP_DIR"; '
        './install.sh'
    )
    extract_result = _run_remote(source, ["--", "sh", "-lc", extract_script])
    if extract_result.returncode != 0:
        err((extract_result.stderr or extract_result.stdout or "remote bundle install failed").strip())
        return None

    post_result = _run_remote(
        source,
        ["--", "sh", "-s"],
        input=_post_install_setup_script(remote_root, capture_dir, install_packages=install_packages),
    )
    if post_result.returncode != 0:
        err((post_result.stderr or post_result.stdout or "remote post-install setup failed").strip())
        return None

    info_map: Dict[str, str] = {}
    for line in (post_result.stdout or "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            info_map[key.strip()] = value.strip()
    return info_map


def _bootstrap_remote_script(remote_root: str, capture_dir: str, install_packages: bool = True) -> str:
    quoted_remote_root = shlex.quote(remote_root)
    quoted_capture_dir = shlex.quote(capture_dir)
    helper_script = _capture_helper_script(capture_dir)
    runner_script = _privileged_capture_runner_script(capture_dir)
    service_script = _capture_service_script(remote_root, capture_dir)
    agent_script = _capture_agent_script(remote_root, capture_dir)
    install_block = _package_install_block() if install_packages else ""
    return f"""set -eu

REMOTE_ROOT={quoted_remote_root}
CAPTURE_DIR={quoted_capture_dir}
BIN_DIR="$REMOTE_ROOT/bin"
STATE_DIR="$REMOTE_ROOT/state"
HELPER="$BIN_DIR/wifi-pipeline-capture"
SERVICE="$BIN_DIR/wifi-pipeline-service"
AGENT="$BIN_DIR/wifi-pipeline-agent"
PRIVILEGED_RUNNER="/usr/local/bin/wifi-pipeline-capture-privileged"
SUDOERS_FILE="/etc/sudoers.d/wifi-pipeline-capture"
LOCAL_BIN="$HOME/.local/bin"
PRIVILEGE_MODE="fallback"

{install_block}

setup_privileged_runner() {{
    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
    elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
        SUDO="sudo -n"
    else
        echo "[!] passwordless sudo not available; leaving capture privileges in fallback mode."
        return 0
    fi

    CURRENT_USER="$(id -un)"
    $SUDO mkdir -p /usr/local/bin /etc/sudoers.d
    cat <<'EOF_RUNNER' | $SUDO tee "$PRIVILEGED_RUNNER" >/dev/null
{runner_script}EOF_RUNNER
    $SUDO chmod 755 "$PRIVILEGED_RUNNER"
    $SUDO chown root:root "$PRIVILEGED_RUNNER" >/dev/null 2>&1 || true
    printf '%s ALL=(root) NOPASSWD: %s\\n' "$CURRENT_USER" "$PRIVILEGED_RUNNER" | $SUDO tee "$SUDOERS_FILE" >/dev/null
    $SUDO chmod 440 "$SUDOERS_FILE"
    if command -v visudo >/dev/null 2>&1; then
        if ! $SUDO visudo -cf "$SUDOERS_FILE" >/dev/null; then
            echo "[!] sudoers validation failed; removing privileged runner access."
            $SUDO rm -f "$SUDOERS_FILE"
            return 0
        fi
    fi
    if $SUDO "$PRIVILEGED_RUNNER" --help >/dev/null 2>&1; then
        PRIVILEGE_MODE="sudoers_runner"
    fi
}}

mkdir -p "$REMOTE_ROOT" "$CAPTURE_DIR" "$BIN_DIR" "$LOCAL_BIN" "$STATE_DIR"
cat > "$HELPER" <<'EOF_CAPTURE'
{helper_script}EOF_CAPTURE
chmod +x "$HELPER"
cat > "$SERVICE" <<'EOF_SERVICE'
{service_script}EOF_SERVICE
chmod +x "$SERVICE"
cat > "$AGENT" <<'EOF_AGENT'
{agent_script}EOF_AGENT
chmod +x "$AGENT"

ln -sf "$HELPER" "$LOCAL_BIN/wifi-pipeline-capture"
ln -sf "$SERVICE" "$LOCAL_BIN/wifi-pipeline-service"
ln -sf "$AGENT" "$LOCAL_BIN/wifi-pipeline-agent"
setup_privileged_runner

printf 'remote_root=%s\\n' "$REMOTE_ROOT"
printf 'capture_dir=%s\\n' "$CAPTURE_DIR"
printf 'state_dir=%s\\n' "$STATE_DIR"
printf 'capture_cmd=%s\\n' "$HELPER"
printf 'service_cmd=%s\\n' "$SERVICE"
printf 'agent_cmd=%s\\n' "$AGENT"
printf 'privilege_mode=%s\\n' "$PRIVILEGE_MODE"
printf 'privileged_runner=%s\\n' "$PRIVILEGED_RUNNER"
"""


def _remote_capture_helper_path(remote_home: str) -> str:
    return f"{remote_home}/wifi-pipeline/bin/wifi-pipeline-capture"


def _remote_capture_service_path(remote_home: str) -> str:
    return f"{remote_home}/wifi-pipeline/bin/wifi-pipeline-service"


def _remote_capture_agent_path(remote_home: str) -> str:
    return f"{remote_home}/wifi-pipeline/bin/wifi-pipeline-agent"


def _remote_capture_command(
    remote_home: str,
    interface: str,
    duration: int,
    output: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> str:
    helper = _remote_capture_helper_path(remote_home)
    local_bin_helper = f"{remote_home}/.local/bin/wifi-pipeline-capture"
    command = (
        f'HELPER="{local_bin_helper}"; '
        f'[ -x "$HELPER" ] || HELPER="{helper}"; '
        'if [ ! -x "$HELPER" ]; then echo "missing_helper" >&2; exit 1; fi; '
        f'"$HELPER" --interface {shlex.quote(interface)} --duration {int(duration)}'
    )
    if output:
        command += f" --output {shlex.quote(output)}"
    for item in extra_args or []:
        command += f" {shlex.quote(str(item))}"
    return command


def _remote_service_command(
    remote_home: str,
    action: str,
    interface: Optional[str] = None,
    duration: Optional[int] = None,
    output: Optional[str] = None,
) -> str:
    service = _remote_capture_service_path(remote_home)
    local_bin_service = f"{remote_home}/.local/bin/wifi-pipeline-service"
    command = (
        f'SERVICE="{local_bin_service}"; '
        f'[ -x "$SERVICE" ] || SERVICE="{service}"; '
        'if [ ! -x "$SERVICE" ]; then echo "missing_service" >&2; exit 1; fi; '
        f'"$SERVICE" {shlex.quote(action)}'
    )
    if action == "start":
        if interface:
            command += f" --interface {shlex.quote(interface)}"
        if duration is not None:
            command += f" --duration {int(duration)}"
        if output:
            command += f" --output {shlex.quote(output)}"
    return command


def _extract_capture_path(output: str) -> Optional[str]:
    lines = [line.strip() for line in (output or "").splitlines() if line.strip()]
    if not lines:
        return None
    candidate = lines[-1]
    if "/" in candidate or "\\" in candidate:
        return candidate
    return None


def _parse_key_value_output(output: str) -> Dict[str, str]:
    rows: Dict[str, str] = {}
    for line in (output or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        rows[key.strip()] = value.strip()
    return rows


def _build_remote_agent_command(remote_home: str, *args: object) -> str:
    command = [_remote_capture_agent_path(remote_home)]
    command.extend(str(arg) for arg in args)
    return " ".join(shlex.quote(part) for part in command)


def _run_remote_agent(
    source: RemoteSource,
    remote_home: str,
    *args: object,
) -> Dict[str, object]:
    result = _run_remote(source, ["--", "sh", "-lc", _build_remote_agent_command(remote_home, *args)])
    stdout = (result.stdout or "").strip()
    payload: Dict[str, object]
    if stdout:
        try:
            raw = json.loads(stdout)
            if isinstance(raw, dict):
                payload = raw
            else:
                payload = {"ok": result.returncode == 0, "returncode": result.returncode, "data": {}, "stdout": stdout}
        except json.JSONDecodeError:
            payload = {
                "ok": result.returncode == 0,
                "returncode": result.returncode,
                "data": _parse_key_value_output(stdout),
                "stdout": stdout,
            }
    else:
        payload = {"ok": result.returncode == 0, "returncode": result.returncode, "data": {}}

    payload.setdefault("returncode", result.returncode)
    payload.setdefault("ok", result.returncode == 0)
    if result.stderr and "stderr" not in payload:
        payload["stderr"] = result.stderr.strip()
    return payload


def _agent_payload_retryable(payload: Dict[str, object]) -> bool:
    if payload.get("ok"):
        return False
    message = " ".join(
        str(payload.get(key) or "")
        for key in ("error", "stderr", "stdout")
    ).lower()
    return not any(marker in message for marker in ("missing_service", "missing_helper", "not found", "unknown argument"))


def _run_remote_agent_with_retry(
    source: RemoteSource,
    remote_home: str,
    *args: object,
    attempts: int = REMOTE_RETRY_ATTEMPTS,
) -> Dict[str, object]:
    payload = _retry_remote_call(
        lambda: _run_remote_agent(source, remote_home, *args),
        should_retry=_agent_payload_retryable,
        attempts=attempts,
    )
    return dict(payload or {})


def _agent_data_map(payload: Dict[str, object]) -> Dict[str, str]:
    raw = payload.get("data")
    if not isinstance(raw, dict):
        return {}
    return {str(key): "" if value is None else str(value) for key, value in raw.items()}


def _probe_health_host(source_host: str) -> str:
    value = str(source_host or "").strip()
    if "@" in value:
        return value.split("@", 1)[1].strip()
    return value


def _probe_remote_health(
    source: RemoteSource,
    *,
    health_port: int,
    user_hint: str,
    timeout: float = 0.75,
    attempts: int = 3,
) -> Optional[Dict[str, str]]:
    host = _probe_health_host(source.host)
    for attempt in range(max(1, int(attempts))):
        record = _probe_remote_appliance(host, health_port=health_port, timeout=timeout, user_hint=user_hint)
        if record:
            return record
        if attempt + 1 < max(1, int(attempts)):
            time.sleep(0.5)
    return None


def _bootstrap_validation_errors(
    report: Dict[str, object],
    *,
    expected_profile: str,
    expected_health_port: int,
    expected_remote_root: str,
    expected_capture_dir: str,
) -> List[str]:
    remote = dict(report.get("remote") or {})
    errors: List[str] = []

    if not remote.get("reachable"):
        errors.append("Remote host is reachable over SSH, but post-bootstrap diagnostics did not complete.")
        return errors

    if not remote.get("agent"):
        errors.append("Managed capture agent is missing after bootstrap.")
    if not remote.get("agent_path"):
        errors.append("Managed capture agent path was not reported after bootstrap.")
    if str(remote.get("agent_protocol") or "") != REMOTE_AGENT_PROTOCOL:
        errors.append(f"Managed capture agent protocol is incompatible: expected {REMOTE_AGENT_PROTOCOL}.")
    agent_version = str(remote.get("agent_version") or "").strip()
    if not agent_version:
        errors.append("Managed capture agent version was not reported after bootstrap.")
    elif agent_version != __version__:
        errors.append(f"Managed capture agent version mismatch: expected {__version__}, got {agent_version}.")

    if not remote.get("helper"):
        errors.append("Remote capture helper is missing after bootstrap.")
    if not remote.get("helper_path"):
        errors.append("Remote capture helper path was not reported after bootstrap.")
    if not remote.get("service"):
        errors.append("Remote capture service is missing after bootstrap.")
    if not remote.get("service_path"):
        errors.append("Remote capture service path was not reported after bootstrap.")
    if str(remote.get("service_status") or "missing") in ("missing", "failed"):
        errors.append(f"Remote capture service is not healthy yet: {remote.get('service_status') or 'missing'}.")

    if str(remote.get("privilege_mode") or "") not in ("sudoers_runner", "root_session"):
        errors.append("Remote capture privileges are still not hardened; bootstrap needs a sudo-capable remote account.")

    if not remote.get("state_dir_exists"):
        errors.append("Remote state directory is missing after bootstrap.")
    if not remote.get("state_dir_writable"):
        errors.append("Remote state directory is not writable after bootstrap.")

    if str(remote.get("remote_root") or expected_remote_root) != expected_remote_root:
        errors.append(f"Remote root mismatch: expected {expected_remote_root}.")
    if str(remote.get("capture_dir") or "") != expected_capture_dir:
        errors.append(f"Remote capture directory mismatch: expected {expected_capture_dir}.")
    if not remote.get("capture_dir_exists"):
        errors.append("Remote capture directory is missing after bootstrap.")
    if not remote.get("capture_dir_writable"):
        errors.append("Remote capture directory is not writable after bootstrap.")

    if expected_profile == "appliance":
        if str(remote.get("install_profile") or "") != "appliance":
            errors.append("Appliance profile was requested, but the remote node did not report appliance mode.")
        if str(remote.get("health_port") or "") != str(expected_health_port):
            errors.append(f"Remote health port mismatch: expected {expected_health_port}.")
        if str(remote.get("health_path") or "") != "/health":
            errors.append("Remote health path mismatch: expected /health.")
        if not remote.get("health_endpoint"):
            errors.append("Remote health endpoint was not reported after bootstrap.")
        if remote.get("health_probe_ok") is not True:
            errors.append("Remote health endpoint did not answer with a valid appliance payload.")
        if str(remote.get("health_protocol") or "") != REMOTE_AGENT_PROTOCOL:
            errors.append(f"Remote health endpoint protocol is incompatible: expected {REMOTE_AGENT_PROTOCOL}.")
        health_agent_version = str(remote.get("health_agent_version") or "").strip()
        if not health_agent_version:
            errors.append("Remote health endpoint did not report an agent version.")
        elif health_agent_version != __version__:
            errors.append(f"Remote health endpoint version mismatch: expected {__version__}, got {health_agent_version}.")
        if remote.get("health_socket_enabled") is not True:
            errors.append("Remote health socket is not enabled after bootstrap.")
        if remote.get("health_socket_active") is not True:
            errors.append("Remote health socket is not active after bootstrap.")
        if remote.get("appliance_service_enabled") is not True:
            errors.append("Remote appliance service is not enabled after bootstrap.")
        if remote.get("appliance_service_active") is not True:
            errors.append("Remote appliance service is not active after bootstrap.")

    return errors


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _remote_artifact_info(
    source: RemoteSource,
    remote_path: str,
    remote_home: Optional[str] = None,
) -> Optional[Dict[str, str]]:
    if remote_home:
        payload = _run_remote_agent_with_retry(source, remote_home, "artifact-info", "--path", remote_path)
        info_map = _agent_data_map(payload)
        if payload.get("ok") and info_map:
            return info_map

    quoted_file = shlex.quote(remote_path)
    quoted_marker = shlex.quote(f"{remote_path}.complete")
    quoted_checksum = shlex.quote(f"{remote_path}.sha256")
    script = (
        "set -eu; "
        f'FILE={quoted_file}; MARKER={quoted_marker}; CHECKSUM={quoted_checksum}; '
        'if [ -f "$FILE" ]; then echo "file_exists=yes"; else echo "file_exists=no"; exit 0; fi; '
        'if [ -f "$MARKER" ]; then echo "complete_marker=yes"; cat "$MARKER"; else echo "complete_marker=no"; fi; '
        'if [ -f "$CHECKSUM" ]; then echo "checksum_file=yes"; '
        'printf "checksum_value=%s\\n" "$(tr -d \'[:space:]\' < "$CHECKSUM")"; '
        'else echo "checksum_file=no"; fi; '
        'printf "remote_size_bytes=%s\\n" "$(wc -c < "$FILE" | tr -d \' \')"'
    )
    result = _retry_remote_call(
        lambda: _run_remote(source, ["--", "sh", "-lc", script]),
        should_retry=lambda outcome: outcome.returncode != 0,
    )
    if result.returncode != 0:
        return None
    return _parse_key_value_output(result.stdout or "")


def _source_from_config(
    config: Dict[str, object],
    host: Optional[str] = None,
    path: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    dest_dir: Optional[str] = None,
    poll_interval: Optional[int] = None,
) -> RemoteSource:
    return RemoteSource(
        host=str(host or config.get("remote_host") or "").strip(),
        path=str(path or config.get("remote_path") or "").strip(),
        port=int(port or config.get("remote_port", 22) or 22),
        identity=str(identity or config.get("remote_identity") or "").strip(),
        dest_dir=Path(str(dest_dir or config.get("remote_dest_dir") or "./pipeline_output/remote_imports")).resolve(),
        poll_interval=int(poll_interval or config.get("remote_poll_interval", 8) or 8),
    )


def _run_remote_service_action(
    source: RemoteSource,
    remote_home: str,
    action: str,
    *,
    interface: Optional[str] = None,
    duration: Optional[int] = None,
    output: Optional[str] = None,
) -> subprocess.CompletedProcess:
    return _run_remote(
        source,
        [
            "--",
            "sh",
            "-lc",
            _remote_service_command(
                remote_home=remote_home,
                action=action,
                interface=interface,
                duration=duration,
                output=output,
            ),
        ],
    )


def _run_remote_service_action_with_retry(
    source: RemoteSource,
    remote_home: str,
    action: str,
    *,
    interface: Optional[str] = None,
    duration: Optional[int] = None,
    output: Optional[str] = None,
    attempts: int = REMOTE_RETRY_ATTEMPTS,
) -> subprocess.CompletedProcess:
    result = _retry_remote_call(
        lambda: _run_remote_service_action(
            source,
            remote_home,
            action,
            interface=interface,
            duration=duration,
            output=output,
        ),
        should_retry=lambda outcome: _process_retryable(
            outcome,
            stop_markers=("missing_service", "missing_helper", "unknown argument"),
        ),
        attempts=attempts,
    )
    return result


def _scp_pull_with_retry(
    source: RemoteSource,
    remote_path: str,
    local_path: Path,
    *,
    attempts: int = REMOTE_RETRY_ATTEMPTS,
) -> subprocess.CompletedProcess:
    def _pull_once() -> subprocess.CompletedProcess:
        local_path.unlink(missing_ok=True)
        cmd = _scp_args(source) + [f"{source.host}:{remote_path}", str(local_path)]
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    result = _retry_remote_call(
        _pull_once,
        should_retry=lambda outcome: outcome.returncode != 0,
        attempts=attempts,
    )
    return result


def _rsync_pull_with_retry(
    source: RemoteSource,
    remote_path: str,
    local_path: Path,
    *,
    attempts: int = REMOTE_RETRY_ATTEMPTS,
) -> subprocess.CompletedProcess:
    ssh_parts = _ssh_args(source)
    ssh_parts.pop()  # rsync receives the remote host separately
    remote_spec = f"{source.host}:{remote_path}"

    def _pull_once() -> subprocess.CompletedProcess:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            "rsync",
            "--archive",
            "--partial",
            "--append-verify",
            "--protect-args",
            "-e",
            " ".join(shlex.quote(part) for part in ssh_parts),
            remote_spec,
            str(local_path),
        ]
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    result = _retry_remote_call(
        _pull_once,
        should_retry=lambda outcome: outcome.returncode != 0,
        attempts=attempts,
    )
    return result


def _use_rsync_resume() -> bool:
    return bool(shutil.which("rsync"))


def _temporary_download_path(local_path: Path) -> Path:
    return local_path.with_name(f"{local_path.name}.partial")


def remote_service_host(
    config: Dict[str, object],
    action: str,
    host: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    interface: Optional[str] = None,
    duration: Optional[int] = None,
    output: Optional[str] = None,
) -> Optional[Dict[str, str]]:
    section("Remote Service")

    if not shutil.which("ssh"):
        err("ssh not found on PATH. Install OpenSSH client and re-run.")
        return None

    source = _source_from_config(config, host=host, port=port, identity=identity)
    if not source.host:
        err("Remote host is required. Use --host or set remote_host in config.")
        return None

    remote_home = _resolve_remote_home(source)
    if not remote_home:
        err("Could not determine the remote home directory over SSH.")
        return None

    payload = _run_remote_agent_with_retry(
        source,
        remote_home,
        "service",
        action,
        *(["--interface", interface] if interface else []),
        *(["--duration", int(duration)] if duration is not None else []),
        *(["--output", output] if output else []),
    )
    info_map = _agent_data_map(payload)
    if not payload.get("ok"):
        result = _run_remote_service_action_with_retry(
            source,
            remote_home,
            action,
            interface=interface,
            duration=duration,
            output=output,
        )
        if result.returncode != 0:
            message = str(payload.get("stderr") or payload.get("stdout") or "").strip()
            if not message:
                message = (result.stderr or result.stdout or "remote service command failed").strip()
            if "missing_service" in message:
                err("Remote capture service not found. Run bootstrap-remote first.")
            else:
                err(message)
            return None
        info_map = _parse_key_value_output(result.stdout or "")

    info_map["action"] = action
    if action == "start":
        ok(f"Remote capture service started on {source.host}")
        if info_map.get("output"):
            info(f"Remote output        : {info_map['output']}")
    elif action == "stop":
        ok(f"Remote capture service stop requested on {source.host}")
    elif action == "status":
        info(f"Remote service status : {info_map.get('service_status') or 'unknown'}")
    elif action == "last-capture":
        latest = info_map.get("last_capture")
        if latest:
            info(f"Last remote capture  : {latest}")
        else:
            warn("No remote capture has completed yet.")
    return info_map


def pull_remote_capture(
    config: Dict[str, object],
    host: Optional[str] = None,
    path: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    dest_dir: Optional[str] = None,
    latest_only: bool = True,
    require_complete: bool = False,
) -> Optional[Path]:
    section("Remote Capture Pull")

    if not _has_ssh_tools():
        err("ssh/scp not found on PATH. Install OpenSSH client and re-run.")
        return None

    source = _source_from_config(
        config, host=host, path=path, port=port, identity=identity, dest_dir=dest_dir
    )
    if not source.host or not source.path:
        err("Remote host and path are required. Use --host and --path or set them in config.")
        return None

    remote_path = source.path
    if latest_only and (_is_pattern(remote_path) or remote_path.endswith("/")):
        resolved = _resolve_latest_remote_path(source)
        if not resolved:
            err("Could not resolve a remote capture file. Check the path or pattern.")
            return None
        remote_path = resolved

    remote_home = _resolve_remote_home(source)
    artifact_info = _remote_artifact_info(source, remote_path, remote_home=remote_home)
    if artifact_info:
        if artifact_info.get("file_exists") != "yes":
            err(f"Remote capture file was not found: {remote_path}")
            return None
        marker_ready = artifact_info.get("complete_marker") == "yes"
        checksum_value = str(artifact_info.get("checksum_value") or "").strip()
        checksum_ready = artifact_info.get("checksum_file") == "yes" and bool(checksum_value)
        if require_complete and not marker_ready:
            err("Remote capture is not marked complete yet. Wait for the remote service to finish, then retry.")
            return None
        if not marker_ready:
            warn("Remote file is not marked complete; proceeding without completion guarantees.")
        elif not checksum_ready:
            warn("Remote file is complete but does not have checksum metadata; proceeding with size-only verification.")
    else:
        warn("Could not inspect remote capture metadata before pull; proceeding without integrity verification.")

    source.dest_dir.mkdir(parents=True, exist_ok=True)
    filename = os.path.basename(remote_path.rstrip("/")) or "remote_capture.pcapng"
    local_path = source.dest_dir / filename
    temp_path = _temporary_download_path(local_path)

    info(f"Pulling {remote_path} from {source.host}")
    using_rsync = _use_rsync_resume()
    if using_rsync:
        result = _rsync_pull_with_retry(source, remote_path, temp_path)
    else:
        result = _scp_pull_with_retry(source, remote_path, temp_path)
    if result.returncode != 0:
        if not using_rsync:
            temp_path.unlink(missing_ok=True)
        err(result.stderr.strip() or result.stdout.strip() or "remote transfer failed")
        return None

    if artifact_info:
        remote_size_raw = str(artifact_info.get("remote_size_bytes") or "").strip()
        if remote_size_raw.isdigit():
            remote_size = int(remote_size_raw)
            local_size = temp_path.stat().st_size if temp_path.exists() else -1
            if local_size != remote_size:
                temp_path.unlink(missing_ok=True)
                err(f"Pulled file size mismatch: remote={remote_size} bytes local={local_size} bytes")
                return None
        checksum_value = str(artifact_info.get("checksum_value") or "").strip().lower()
        if checksum_value:
            local_checksum = _sha256_file(temp_path)
            if local_checksum.lower() != checksum_value:
                temp_path.unlink(missing_ok=True)
                err("Pulled file failed SHA-256 verification. The local copy was removed.")
                return None
            ok("Verified remote capture checksum after transfer.")

    if not temp_path.exists():
        err("Remote capture transfer finished without a local file.")
        return None
    os.replace(temp_path, local_path)
    ok(f"Saved remote capture to {local_path}")
    return local_path


def pair_remote_host(
    config: Dict[str, object],
    host: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    create_key: bool = True,
) -> bool:
    section("Remote Pairing")

    if not shutil.which("ssh"):
        err("ssh not found on PATH. Install OpenSSH client and re-run.")
        return False

    source = _source_from_config(config, host=host, port=port, identity=identity)
    if not source.host:
        err("Remote host is required. Use --host or set remote_host in config.")
        return False

    public_key = _ensure_public_key(source.identity or identity, generate_if_missing=create_key)
    if not public_key or not public_key.exists():
        err("No local SSH public key found, and automatic key generation failed.")
        return False

    key_text = public_key.read_text(encoding="utf-8", errors="replace").strip()
    if not key_text:
        err(f"SSH public key is empty: {public_key}")
        return False

    info(f"Installing SSH key from {public_key} on {source.host}")
    install_result = _retry_remote_call(
        lambda: _run_remote(
            source,
            ["--", "sh", "-lc", _authorized_keys_script(key_text)],
            capture_output=False,
            text=False,
        ),
        should_retry=lambda outcome: outcome.returncode != 0,
    )
    if install_result.returncode != 0:
        err("Remote pairing failed while installing the SSH key.")
        return False

    verify_result = _retry_remote_call(
        lambda: _run_remote(source, ["--", "printf", "paired"]),
        should_retry=lambda outcome: outcome.returncode != 0 or "paired" not in (outcome.stdout or ""),
    )
    if verify_result.returncode == 0 and "paired" in (verify_result.stdout or ""):
        ok("SSH key installed and passwordless SSH verified.")
    else:
        warn("SSH key installed, but passwordless verification did not complete cleanly.")

    return True


def bootstrap_remote_host(
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
    section("Remote Bootstrap")

    if not shutil.which("ssh"):
        err("ssh not found on PATH. Install OpenSSH client and re-run.")
        return None

    source = _source_from_config(config, host=host, port=port, identity=identity)
    if not source.host:
        err("Remote host is required. Use --host or set remote_host in config.")
        return None

    if pair and not pair_remote_host(config, host=source.host, port=source.port, identity=source.identity):
        return None

    remote_home = _resolve_remote_home(source)
    if not remote_home:
        err("Could not determine the remote home directory over SSH.")
        return None

    resolved_remote_root = remote_root or f"{remote_home}/wifi-pipeline"
    resolved_capture_dir = capture_dir or f"{resolved_remote_root}/captures"
    chosen_install_profile = _resolve_remote_install_profile(
        install_profile or str(config.get("remote_install_profile") or "").strip() or None
    )
    chosen_health_port = int(health_port if health_port is not None else config.get("remote_health_port", DEFAULT_APPLIANCE_HEALTH_PORT) or DEFAULT_APPLIANCE_HEALTH_PORT)
    chosen_install_mode = _resolve_remote_install_mode(
        install_mode or str(config.get("remote_install_mode") or "").strip() or None,
        prefer_bundle=bool(shutil.which("scp")),
    )

    info(f"Bootstrapping capture helper on {source.host} using {chosen_install_mode} install mode")
    if chosen_install_mode == "bundle":
        info_map = _install_remote_bundle(
            source,
            remote_home=remote_home,
            remote_root=resolved_remote_root,
            capture_dir=resolved_capture_dir,
            install_packages=install_packages,
        )
        if not info_map:
            return None
    else:
        script = _bootstrap_remote_script(
            remote_root=resolved_remote_root,
            capture_dir=resolved_capture_dir,
            install_packages=install_packages,
        )
        result = _run_remote(
            source,
            ["--", "sh", "-s"],
            input=script,
        )
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "remote bootstrap failed").strip()
            err(message)
            return None

        info_map = {}
        for line in (result.stdout or "").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                info_map[key.strip()] = value.strip()

    if chosen_install_profile == "appliance":
        appliance_info = _install_remote_appliance_profile(
            source,
            remote_root=resolved_remote_root,
            capture_dir=resolved_capture_dir,
            health_port=chosen_health_port,
        )
        if not appliance_info:
            return None
        info_map.update(appliance_info)
    else:
        info_map.setdefault("install_profile", "standard")

    validation_config = dict(config)
    validation_config["remote_install_profile"] = chosen_install_profile
    validation_config["remote_health_port"] = chosen_health_port
    validation_report = doctor_remote_host(
        validation_config,
        host=source.host,
        port=source.port,
        identity=source.identity,
        interface=str(config.get("remote_interface") or "").strip() or None,
    )
    validation_errors = _bootstrap_validation_errors(
        validation_report,
        expected_profile=chosen_install_profile,
        expected_health_port=chosen_health_port,
        expected_remote_root=resolved_remote_root,
        expected_capture_dir=resolved_capture_dir,
    )
    if validation_errors:
        err("Remote bootstrap finished, but validation failed:")
        for message in validation_errors:
            err(f"  {message}")
        return None

    validated_remote = dict(validation_report.get("remote") or {})
    info_map["agent_protocol"] = str(validated_remote.get("agent_protocol") or info_map.get("agent_protocol") or "")
    info_map["agent_version"] = str(validated_remote.get("agent_version") or "")
    info_map["health_probe_ok"] = "yes" if validated_remote.get("health_probe_ok") else "no"

    capture_script = info_map.get("capture_cmd") or f"{resolved_remote_root}/bin/wifi-pipeline-capture"
    service_script = info_map.get("service_cmd") or f"{resolved_remote_root}/bin/wifi-pipeline-service"
    agent_script = info_map.get("agent_cmd") or f"{resolved_remote_root}/bin/wifi-pipeline-agent"
    privilege_mode = info_map.get("privilege_mode") or "fallback"
    ok(f"Remote bootstrap complete on {source.host}")
    info(f"Remote capture directory: {info_map.get('capture_dir') or resolved_capture_dir}")
    info(f"Remote capture command : {capture_script} --interface wlan0 --duration 60")
    info(f"Remote service command : {service_script} status")
    info(f"Remote agent command  : {agent_script} doctor")
    if info_map.get("agent_version"):
        info(f"Remote agent version : {info_map['agent_version']}")
    info(f"Remote install mode   : {chosen_install_mode}")
    info(f"Remote install profile: {chosen_install_profile}")
    if info_map.get("health_endpoint"):
        info(f"Remote health endpoint: {info_map['health_endpoint']}")
    if info_map.get("health_probe_ok") == "yes":
        info("Remote health probe  : validated")
    info(f"Remote privilege mode : {privilege_mode}")
    if privilege_mode != "sudoers_runner":
        warn(
            "Remote capture is still in fallback privilege mode. Run bootstrap-remote with a remote account that has sudo access."
        )
    return {
        "remote_root": info_map.get("remote_root") or resolved_remote_root,
        "capture_dir": info_map.get("capture_dir") or resolved_capture_dir,
        "state_dir": info_map.get("state_dir") or f"{resolved_remote_root}/state",
        "capture_cmd": capture_script,
        "service_cmd": service_script,
        "agent_cmd": agent_script,
        "install_mode": chosen_install_mode,
        "install_profile": info_map.get("install_profile") or chosen_install_profile,
        "health_port": str(info_map.get("health_port") or chosen_health_port),
        "health_endpoint": info_map.get("health_endpoint") or "",
        "privilege_mode": privilege_mode,
        "privileged_runner": info_map.get("privileged_runner") or "/usr/local/bin/wifi-pipeline-capture-privileged",
    }


def start_remote_capture(
    config: Dict[str, object],
    host: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    interface: Optional[str] = None,
    duration: Optional[int] = None,
    output: Optional[str] = None,
    dest_dir: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> Optional[Path]:
    section("Remote Capture Start")

    if not _has_ssh_tools():
        err("ssh/scp not found on PATH. Install OpenSSH client and re-run.")
        return None

    source = _source_from_config(config, host=host, port=port, identity=identity, dest_dir=dest_dir)
    if not source.host:
        err("Remote host is required. Use --host or set remote_host in config.")
        return None

    chosen_interface = str(interface or config.get("remote_interface") or "").strip()
    if not chosen_interface:
        err("Remote interface is required. Pass --interface or set remote_interface in config.")
        return None

    chosen_duration = int(duration if duration is not None else config.get("capture_duration", 60) or 60)
    if chosen_duration <= 0:
        err("start-remote requires a positive duration in seconds.")
        return None

    remote_home = _resolve_remote_home(source)
    if not remote_home:
        err("Could not determine the remote home directory over SSH.")
        return None

    info(f"Starting remote capture on {source.host} using interface {chosen_interface}")
    if extra_args:
        warn("start-remote ignores extra tcpdump args when using the managed remote service.")

    start_payload = _run_remote_agent_with_retry(
        source,
        remote_home,
        "service",
        "start",
        "--interface",
        chosen_interface,
        "--duration",
        chosen_duration,
        *(["--output", output] if output else []),
    )
    start_info = _agent_data_map(start_payload)
    if not start_payload.get("ok"):
        start_result = _run_remote_service_action_with_retry(
            source,
            remote_home,
            "start",
            interface=chosen_interface,
            duration=chosen_duration,
            output=output,
        )
        if start_result.returncode != 0:
            message = str(start_payload.get("stderr") or start_payload.get("stdout") or "").strip()
            if not message:
                message = (start_result.stderr or start_result.stdout or "remote capture failed").strip()
            if "missing_service" in message:
                err("Remote capture service not found. Run bootstrap-remote first.")
            else:
                err(message)
            return None
        start_info = _parse_key_value_output(start_result.stdout or "")
    remote_path = start_info.get("output")
    if not remote_path:
        err("Remote capture service started, but no remote output path was returned.")
        return None

    deadline = time.time() + chosen_duration + 20
    final_info = dict(start_info)
    while time.time() <= deadline:
        time.sleep(1)
        status_payload = _run_remote_agent_with_retry(source, remote_home, "service", "status")
        final_info = _agent_data_map(status_payload)
        if not status_payload.get("ok"):
            status_result = _run_remote_service_action_with_retry(source, remote_home, "status")
            if status_result.returncode != 0:
                message = str(status_payload.get("stderr") or status_payload.get("stdout") or "").strip()
                if not message:
                    message = (status_result.stderr or status_result.stdout or "remote service status failed").strip()
                err(message)
                return None
            final_info = _parse_key_value_output(status_result.stdout or "")
        if final_info.get("service_status") != "running":
            break
    else:
        err("Remote capture service did not finish before the timeout window.")
        return None

    last_result = str(final_info.get("last_result") or "")
    if last_result == "failed":
        exit_code = str(final_info.get("last_exit_code") or "")
        if exit_code == "3":
            err(
                "Remote capture privileges are not hardened yet. Re-run bootstrap-remote with a remote user that has sudo access, then run doctor."
            )
        else:
            log_file = str(final_info.get("log_file") or "")
            if log_file:
                err(f"Remote capture service failed. Check the remote log: {log_file}")
            else:
                err("Remote capture service failed.")
        return None
    if last_result == "stopped":
        err("Remote capture was stopped before completion.")
        return None
    if last_result in ("interrupted", "interrupted_reboot"):
        recovery_reason = str(final_info.get("recovery_reason") or "").strip()
        if recovery_reason == "reboot" or last_result == "interrupted_reboot":
            err("Remote capture was interrupted by a remote reboot. Re-run the capture after the appliance is fully back up.")
        else:
            err("Remote capture was interrupted before completion. The managed service cleaned up stale state; retry the capture.")
        return None

    remote_path = str(final_info.get("last_capture") or remote_path).strip()
    if not remote_path:
        err("Remote capture completed, but the output path could not be determined.")
        return None

    ok(f"Remote capture finished: {remote_path}")
    return pull_remote_capture(
        config,
        host=source.host,
        path=remote_path,
        port=source.port,
        identity=source.identity,
        dest_dir=str(source.dest_dir),
        latest_only=False,
        require_complete=True,
    )


def doctor_remote_host(
    config: Dict[str, object],
    host: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    interface: Optional[str] = None,
) -> Dict[str, object]:
    source = _source_from_config(config, host=host, port=port, identity=identity)
    ssh_path = shutil.which("ssh")
    scp_path = shutil.which("scp")
    public_key = _ensure_public_key(source.identity or identity, generate_if_missing=False)
    result: Dict[str, object] = {
        "host": source.host,
        "ok": False,
        "local": {
            "ssh": bool(ssh_path),
            "ssh_path": ssh_path or "",
            "scp": bool(scp_path),
            "scp_path": scp_path or "",
            "public_key": bool(public_key),
            "public_key_path": str(public_key) if public_key else "",
        },
        "remote": {
            "reachable": False,
            "home": "",
            "tcpdump": False,
            "agent": False,
            "agent_path": "",
            "agent_protocol": "",
            "agent_version": "",
            "control_mode": "legacy_shell",
            "remote_root": "",
            "install_profile": "standard",
            "health_port": "",
            "health_path": "",
            "health_endpoint": "",
            "health_probe_ok": None,
            "health_protocol": "",
            "health_agent_version": "",
            "health_device_name": "",
            "health_service": "",
            "health_socket": "",
            "health_socket_enabled": None,
            "health_socket_active": None,
            "appliance_service": "",
            "appliance_service_enabled": None,
            "appliance_service_active": None,
            "helper": False,
            "helper_path": "",
            "helper_version": "",
            "service": False,
            "service_path": "",
            "service_version": "",
            "service_status": "missing",
            "last_result": "",
            "last_exit_code": "",
            "started_at": "",
            "finished_at": "",
            "recovery_reason": "",
            "stale_pid_cleaned": False,
            "state_dir": "",
            "state_dir_exists": False,
            "state_dir_writable": False,
            "privileged_runner": False,
            "privileged_runner_path": "/usr/local/bin/wifi-pipeline-capture-privileged",
            "privilege_mode": "unreachable",
            "capture_dir": "",
            "capture_dir_exists": False,
            "capture_dir_writable": False,
            "complete_marker": False,
            "checksum_file": False,
            "checksum_value": "",
            "remote_size_bytes": "",
            "interface": str(interface or config.get("remote_interface") or "").strip(),
            "interface_exists": None,
            "protocol_compatible": None,
            "version_compatible": None,
        },
    }

    if not ssh_path or not scp_path or not source.host:
        return result

    remote_home = _resolve_remote_home(source)
    if not remote_home:
        return result

    configured_remote_path = str(config.get("remote_path") or "").strip()
    capture_dir = f"{remote_home}/wifi-pipeline/captures"
    if configured_remote_path and configured_remote_path.endswith("/"):
        capture_dir = configured_remote_path.rstrip("/")

    interface_name = str(interface or config.get("remote_interface") or "").strip()
    agent_path = _remote_capture_agent_path(remote_home)
    helper_path = _remote_capture_helper_path(remote_home)
    helper_local_path = f"{remote_home}/.local/bin/wifi-pipeline-capture"
    service_path = _remote_capture_service_path(remote_home)
    service_local_path = f"{remote_home}/.local/bin/wifi-pipeline-service"
    state_dir = f"{remote_home}/wifi-pipeline/state"
    privileged_runner_path = "/usr/local/bin/wifi-pipeline-capture-privileged"
    quoted_capture_dir = shlex.quote(capture_dir)
    quoted_state_dir = shlex.quote(state_dir)
    diag_parts = [
        "set -eu",
        f'HELPER_LOCAL="{helper_local_path}"',
        f'HELPER="{helper_path}"',
        f'SERVICE_LOCAL="{service_local_path}"',
        f'SERVICE="{service_path}"',
        f'PRIVILEGED_RUNNER="{privileged_runner_path}"',
        '[ -x "$HELPER_LOCAL" ] && HELPER="$HELPER_LOCAL"',
        '[ -x "$SERVICE_LOCAL" ] && SERVICE="$SERVICE_LOCAL"',
        'if command -v tcpdump >/dev/null 2>&1; then echo "tcpdump=yes"; else echo "tcpdump=no"; fi',
        'if [ -x "$HELPER" ]; then echo "helper=yes"; else echo "helper=no"; fi',
        'echo "helper_path=$HELPER"',
        'if [ -x "$SERVICE" ]; then echo "service=yes"; else echo "service=no"; fi',
        'echo "service_path=$SERVICE"',
        'if [ -x "$SERVICE" ]; then "$SERVICE" status; else echo "service_status=missing"; fi',
        'if [ -x "$PRIVILEGED_RUNNER" ]; then echo "privileged_runner=yes"; else echo "privileged_runner=no"; fi',
        'echo "privileged_runner_path=$PRIVILEGED_RUNNER"',
        'if [ "$(id -u)" -eq 0 ]; then echo "privilege_mode=root_session"; '
        'elif command -v sudo >/dev/null 2>&1 && sudo -n "$PRIVILEGED_RUNNER" --help >/dev/null 2>&1; then echo "privilege_mode=sudoers_runner"; '
        'else echo "privilege_mode=fallback"; fi',
        f'STATE_DIR={quoted_state_dir}',
        'echo "state_dir=$STATE_DIR"',
        'if [ -d "$STATE_DIR" ]; then echo "state_dir_exists=yes"; else echo "state_dir_exists=no"; fi',
        'if [ -w "$STATE_DIR" ]; then echo "state_dir_writable=yes"; else echo "state_dir_writable=no"; fi',
        f'CAPTURE_DIR={quoted_capture_dir}',
        'echo "capture_dir=$CAPTURE_DIR"',
        'if [ -d "$CAPTURE_DIR" ]; then echo "capture_dir_exists=yes"; else echo "capture_dir_exists=no"; fi',
        'if [ -w "$CAPTURE_DIR" ]; then echo "capture_dir_writable=yes"; else echo "capture_dir_writable=no"; fi',
    ]
    if interface_name:
        quoted_interface = shlex.quote(interface_name)
        diag_parts.extend(
            [
                f'INTERFACE={quoted_interface}',
                'if command -v ip >/dev/null 2>&1; then '
                'if ip link show "$INTERFACE" >/dev/null 2>&1; then echo "interface_exists=yes"; else echo "interface_exists=no"; fi; '
                'elif command -v ifconfig >/dev/null 2>&1; then '
                'if ifconfig "$INTERFACE" >/dev/null 2>&1; then echo "interface_exists=yes"; else echo "interface_exists=no"; fi; '
                'else echo "interface_exists=unknown"; fi',
            ]
        )

    remote: Dict[str, object] = dict(result["remote"])
    remote["reachable"] = True
    remote["home"] = remote_home
    remote["agent_path"] = agent_path
    agent_payload = _run_remote_agent(
        source,
        remote_home,
        "doctor",
        *(["--interface", interface_name] if interface_name else []),
    )
    if agent_payload.get("ok"):
        parsed = _agent_data_map(agent_payload)
        remote["agent"] = parsed.get("agent") == "yes"
        remote["agent_path"] = parsed.get("agent_path") or agent_path
        remote["agent_protocol"] = parsed.get("agent_protocol") or str(agent_payload.get("protocol") or "")
        remote["agent_version"] = parsed.get("agent_version") or ""
        remote["control_mode"] = parsed.get("control_mode") or "agent"
        remote["remote_root"] = parsed.get("remote_root") or remote_home
        remote["install_profile"] = parsed.get("install_profile") or "standard"
        remote["health_port"] = parsed.get("health_port") or ""
        remote["health_path"] = parsed.get("health_path") or ""
        remote["health_endpoint"] = parsed.get("health_endpoint") or ""
        remote["health_service"] = parsed.get("health_service") or ""
        remote["health_socket"] = parsed.get("health_socket") or ""
        appliance_enabled = parsed.get("appliance_service_enabled")
        appliance_active = parsed.get("appliance_service_active")
        socket_enabled = parsed.get("health_socket_enabled")
        socket_active = parsed.get("health_socket_active")
        remote["appliance_service"] = parsed.get("appliance_service") or ""
        remote["appliance_service_enabled"] = True if appliance_enabled == "yes" else False if appliance_enabled == "no" else None
        remote["appliance_service_active"] = True if appliance_active == "yes" else False if appliance_active == "no" else None
        remote["health_socket_enabled"] = True if socket_enabled == "yes" else False if socket_enabled == "no" else None
        remote["health_socket_active"] = True if socket_active == "yes" else False if socket_active == "no" else None
        remote["tcpdump"] = parsed.get("tcpdump") == "yes"
        remote["helper"] = parsed.get("helper") == "yes"
        remote["helper_path"] = parsed.get("helper_path") or helper_path
        remote["helper_version"] = parsed.get("helper_version") or ""
        remote["service"] = parsed.get("service") == "yes"
        remote["service_path"] = parsed.get("service_path") or service_path
        remote["service_version"] = parsed.get("service_version") or ""
        remote["service_status"] = parsed.get("service_status") or "missing"
        remote["last_result"] = parsed.get("last_result") or ""
        remote["last_exit_code"] = parsed.get("last_exit_code") or ""
        remote["started_at"] = parsed.get("started_at") or ""
        remote["finished_at"] = parsed.get("finished_at") or ""
        remote["recovery_reason"] = parsed.get("recovery_reason") or ""
        remote["stale_pid_cleaned"] = parsed.get("stale_pid_cleaned") == "yes"
        remote["state_dir"] = parsed.get("state_dir") or state_dir
        remote["state_dir_exists"] = parsed.get("state_dir_exists") == "yes"
        remote["state_dir_writable"] = parsed.get("state_dir_writable") == "yes"
        remote["privileged_runner"] = parsed.get("privileged_runner") == "yes"
        remote["privileged_runner_path"] = parsed.get("privileged_runner_path") or privileged_runner_path
        remote["privilege_mode"] = parsed.get("privilege_mode") or "fallback"
        remote["capture_dir"] = parsed.get("capture_dir") or capture_dir
        remote["capture_dir_exists"] = parsed.get("capture_dir_exists") == "yes"
        remote["capture_dir_writable"] = parsed.get("capture_dir_writable") == "yes"
        remote["complete_marker"] = parsed.get("complete_marker") == "yes"
        remote["checksum_file"] = parsed.get("checksum_file") == "yes"
        remote["checksum_value"] = parsed.get("checksum_value") or ""
        remote["remote_size_bytes"] = parsed.get("remote_size_bytes") or ""
        if interface_name:
            interface_state = parsed.get("interface_exists")
            if interface_state == "yes":
                remote["interface_exists"] = True
            elif interface_state == "no":
                remote["interface_exists"] = False
            else:
                remote["interface_exists"] = None
    else:
        diag = _run_remote(source, ["--", "sh", "-lc", "; ".join(diag_parts)])
        if diag.returncode == 0:
            parsed = _parse_key_value_output(diag.stdout or "")
            remote["tcpdump"] = parsed.get("tcpdump") == "yes"
            remote["helper"] = parsed.get("helper") == "yes"
            remote["helper_path"] = parsed.get("helper_path") or helper_path
            remote["service"] = parsed.get("service") == "yes"
            remote["service_path"] = parsed.get("service_path") or service_path
            remote["control_mode"] = "legacy_shell"
            remote["remote_root"] = parsed.get("remote_root") or remote_home
            remote["service_status"] = parsed.get("service_status") or "missing"
            remote["last_result"] = parsed.get("last_result") or ""
            remote["last_exit_code"] = parsed.get("last_exit_code") or ""
            remote["started_at"] = parsed.get("started_at") or ""
            remote["finished_at"] = parsed.get("finished_at") or ""
            remote["recovery_reason"] = parsed.get("recovery_reason") or ""
            remote["stale_pid_cleaned"] = parsed.get("stale_pid_cleaned") == "yes"
            remote["state_dir"] = parsed.get("state_dir") or state_dir
            remote["state_dir_exists"] = parsed.get("state_dir_exists") == "yes"
            remote["state_dir_writable"] = parsed.get("state_dir_writable") == "yes"
            remote["privileged_runner"] = parsed.get("privileged_runner") == "yes"
            remote["privileged_runner_path"] = parsed.get("privileged_runner_path") or privileged_runner_path
            remote["privilege_mode"] = parsed.get("privilege_mode") or "fallback"
            remote["capture_dir"] = parsed.get("capture_dir") or capture_dir
            remote["capture_dir_exists"] = parsed.get("capture_dir_exists") == "yes"
            remote["capture_dir_writable"] = parsed.get("capture_dir_writable") == "yes"
            remote["complete_marker"] = parsed.get("complete_marker") == "yes"
            remote["checksum_file"] = parsed.get("checksum_file") == "yes"
            remote["checksum_value"] = parsed.get("checksum_value") or ""
            remote["remote_size_bytes"] = parsed.get("remote_size_bytes") or ""
            if interface_name:
                interface_state = parsed.get("interface_exists")
                if interface_state == "yes":
                    remote["interface_exists"] = True
                elif interface_state == "no":
                    remote["interface_exists"] = False
                else:
                    remote["interface_exists"] = None
        else:
            remote["control_mode"] = "legacy_shell"
            remote["helper_path"] = helper_path
            remote["service_path"] = service_path
            remote["state_dir"] = state_dir
            remote["privileged_runner_path"] = privileged_runner_path
            remote["capture_dir"] = capture_dir
            remote["remote_root"] = remote_home

    remote["protocol_compatible"] = (
        str(remote.get("agent_protocol") or "") == REMOTE_AGENT_PROTOCOL if remote.get("agent") else None
    )
    remote["version_compatible"] = (
        str(remote.get("agent_version") or "") == __version__ if str(remote.get("agent_version") or "").strip() else None
    )

    if str(remote.get("install_profile") or "") == "appliance" and str(remote.get("health_port") or "").strip():
        health_record = _probe_remote_health(
            source,
            health_port=int(str(remote.get("health_port") or DEFAULT_APPLIANCE_HEALTH_PORT)),
            user_hint=str(config.get("remote_user") or "").strip(),
        )
        if health_record:
            remote["health_probe_ok"] = True
            remote["health_protocol"] = str(health_record.get("agent_protocol") or "")
            remote["health_agent_version"] = str(health_record.get("agent_version") or "")
            remote["health_device_name"] = str(health_record.get("device_name") or "")
            remote["health_endpoint"] = str(health_record.get("health_endpoint") or remote.get("health_endpoint") or "")
            if not remote.get("health_path"):
                remote["health_path"] = str(health_record.get("health_path") or "")
        else:
            remote["health_probe_ok"] = False

    result["remote"] = remote
    interface_ok = True
    if interface_name:
        interface_state = remote.get("interface_exists")
        interface_ok = interface_state is not False
    expected_profile = _resolve_remote_install_profile(
        str(config.get("remote_install_profile") or remote.get("install_profile") or "appliance")
    )
    appliance_ok = True
    if expected_profile == "appliance":
        appliance_ok = bool(
            str(remote.get("install_profile") or "") == "appliance"
            and bool(remote.get("health_endpoint"))
            and remote.get("health_probe_ok") is True
            and str(remote.get("health_protocol") or "") == REMOTE_AGENT_PROTOCOL
            and str(remote.get("health_agent_version") or "") == __version__
            and remote.get("health_socket_enabled") is True
            and remote.get("health_socket_active") is True
            and remote.get("appliance_service_enabled") is True
            and remote.get("appliance_service_active") is True
        )
    result["ok"] = bool(
        result["local"]["ssh"]
        and result["local"]["scp"]
        and remote["reachable"]
        and remote["agent"]
        and remote.get("protocol_compatible") is True
        and remote.get("version_compatible") is True
        and remote["tcpdump"]
        and remote["helper"]
        and remote["service"]
        and str(remote.get("service_status") or "") in ("idle", "running", "stopped", "interrupted")
        and str(remote.get("privilege_mode") or "") in ("sudoers_runner", "root_session")
        and remote["state_dir_exists"]
        and remote["state_dir_writable"]
        and remote["capture_dir_exists"]
        and remote["capture_dir_writable"]
        and interface_ok
        and appliance_ok
    )
    return result


def watch_remote_capture(
    config: Dict[str, object],
    host: Optional[str] = None,
    path: Optional[str] = None,
    port: Optional[int] = None,
    identity: Optional[str] = None,
    dest_dir: Optional[str] = None,
    interval: Optional[int] = None,
    latest_only: bool = True,
) -> None:
    source = _source_from_config(
        config, host=host, path=path, port=port, identity=identity, dest_dir=dest_dir, poll_interval=interval
    )
    poll = max(2, int(source.poll_interval))
    info(f"Watching {source.host}:{source.path} every {poll}s (Ctrl-C to stop).")
    try:
        while True:
            pull_remote_capture(
                config,
                host=source.host,
                path=source.path,
                port=source.port,
                identity=source.identity,
                dest_dir=str(source.dest_dir),
                latest_only=latest_only,
            )
            time.sleep(poll)
    except KeyboardInterrupt:
        done("Remote watch stopped.")
