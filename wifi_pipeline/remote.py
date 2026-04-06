from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .ui import done, err, info, ok, section, warn


@dataclass
class RemoteSource:
    host: str
    path: str
    port: int
    identity: str
    dest_dir: Path
    poll_interval: int


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


def _has_ssh_tools() -> bool:
    return bool(shutil.which("ssh")) and bool(shutil.which("scp"))


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
    result = _run_remote(source, ["--", "sh", "-lc", f"ls -t {escaped} 2>/dev/null | head -n 1"])
    if result.returncode != 0:
        return None
    latest = (result.stdout or "").strip()
    return latest or None


def _resolve_remote_home(source: RemoteSource) -> Optional[str]:
    result = _run_remote(source, ["--", "sh", "-lc", 'printf "%s" "$HOME"'])
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

usage() {{
    echo "Usage: wifi-pipeline-service <start|stop|status|last-capture> [--interface <iface>] [--duration <seconds>] [--output <path>]" >&2
}}

resolve_helper() {{
    if [[ -x "$LOCAL_HELPER" ]]; then
        HELPER="$LOCAL_HELPER"
    fi
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
    rm -f "$PID_FILE"
    return 1
}}

emit_status() {{
    local service_status="idle"
    local pid=""
    local current_output=""
    local marker_file=""
    local checksum_file=""
    if pid="$(running_pid)"; then
        service_status="running"
    elif [[ -f "$META_FILE" ]]; then
        local last_result=""
        last_result="$(grep -E '^last_result=' "$META_FILE" | tail -n 1 | cut -d= -f2- || true)"
        current_output="$(grep -E '^output=' "$META_FILE" | tail -n 1 | cut -d= -f2- || true)"
        if [[ "$last_result" == "failed" ]]; then
            service_status="failed"
        fi
    fi
    printf 'service_status=%s\\n' "$service_status"
    if [[ -n "$pid" ]]; then
        printf 'pid=%s\\n' "$pid"
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
    started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
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
    }} > "$META_FILE"

    export HELPER INTERFACE DURATION OUTPUT LOG_FILE META_FILE LAST_FILE PID_FILE started_at checksum_file marker_file
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
    rm -f "$PID_FILE"
    printf 'service_status=stopped\\n'
    printf 'pid=%s\\n' "$pid"
    printf 'log_file=%s\\n' "$LOG_FILE"
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


def _bootstrap_remote_script(remote_root: str, capture_dir: str, install_packages: bool = True) -> str:
    quoted_remote_root = shlex.quote(remote_root)
    quoted_capture_dir = shlex.quote(capture_dir)
    helper_script = _capture_helper_script(capture_dir)
    runner_script = _privileged_capture_runner_script(capture_dir)
    service_script = _capture_service_script(remote_root, capture_dir)
    install_block = ""
    if install_packages:
        install_block = """
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
    return f"""set -eu

REMOTE_ROOT={quoted_remote_root}
CAPTURE_DIR={quoted_capture_dir}
BIN_DIR="$REMOTE_ROOT/bin"
STATE_DIR="$REMOTE_ROOT/state"
HELPER="$BIN_DIR/wifi-pipeline-capture"
SERVICE="$BIN_DIR/wifi-pipeline-service"
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

ln -sf "$HELPER" "$LOCAL_BIN/wifi-pipeline-capture"
ln -sf "$SERVICE" "$LOCAL_BIN/wifi-pipeline-service"
setup_privileged_runner

printf 'remote_root=%s\\n' "$REMOTE_ROOT"
printf 'capture_dir=%s\\n' "$CAPTURE_DIR"
printf 'state_dir=%s\\n' "$STATE_DIR"
printf 'capture_cmd=%s\\n' "$HELPER"
printf 'service_cmd=%s\\n' "$SERVICE"
printf 'privilege_mode=%s\\n' "$PRIVILEGE_MODE"
printf 'privileged_runner=%s\\n' "$PRIVILEGED_RUNNER"
"""


def _remote_capture_helper_path(remote_home: str) -> str:
    return f"{remote_home}/wifi-pipeline/bin/wifi-pipeline-capture"


def _remote_capture_service_path(remote_home: str) -> str:
    return f"{remote_home}/wifi-pipeline/bin/wifi-pipeline-service"


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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _remote_artifact_info(source: RemoteSource, remote_path: str) -> Optional[Dict[str, str]]:
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
    result = _run_remote(source, ["--", "sh", "-lc", script])
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

    result = _run_remote_service_action(
        source,
        remote_home,
        action,
        interface=interface,
        duration=duration,
        output=output,
    )
    if result.returncode != 0:
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

    artifact_info = _remote_artifact_info(source, remote_path)
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

    cmd = _scp_args(source) + [f"{source.host}:{remote_path}", str(local_path)]
    info(f"Pulling {remote_path} from {source.host}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        err(result.stderr.strip() or result.stdout.strip() or "scp failed")
        return None

    if artifact_info:
        remote_size_raw = str(artifact_info.get("remote_size_bytes") or "").strip()
        if remote_size_raw.isdigit():
            remote_size = int(remote_size_raw)
            local_size = local_path.stat().st_size
            if local_size != remote_size:
                local_path.unlink(missing_ok=True)
                err(f"Pulled file size mismatch: remote={remote_size} bytes local={local_size} bytes")
                return None
        checksum_value = str(artifact_info.get("checksum_value") or "").strip().lower()
        if checksum_value:
            local_checksum = _sha256_file(local_path)
            if local_checksum.lower() != checksum_value:
                local_path.unlink(missing_ok=True)
                err("Pulled file failed SHA-256 verification. The local copy was removed.")
                return None
            ok("Verified remote capture checksum after transfer.")

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
    install_result = _run_remote(
        source,
        ["--", "sh", "-lc", _authorized_keys_script(key_text)],
        capture_output=False,
        text=False,
    )
    if install_result.returncode != 0:
        err("Remote pairing failed while installing the SSH key.")
        return False

    verify_result = _run_remote(source, ["--", "printf", "paired"])
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
    script = _bootstrap_remote_script(
        remote_root=resolved_remote_root,
        capture_dir=resolved_capture_dir,
        install_packages=install_packages,
    )

    info(f"Bootstrapping capture helper on {source.host}")
    result = _run_remote(
        source,
        ["--", "sh", "-s"],
        input=script,
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "remote bootstrap failed").strip()
        err(message)
        return None

    info_map: Dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            info_map[key.strip()] = value.strip()

    capture_script = info_map.get("capture_cmd") or f"{resolved_remote_root}/bin/wifi-pipeline-capture"
    service_script = info_map.get("service_cmd") or f"{resolved_remote_root}/bin/wifi-pipeline-service"
    privilege_mode = info_map.get("privilege_mode") or "fallback"
    ok(f"Remote bootstrap complete on {source.host}")
    info(f"Remote capture directory: {info_map.get('capture_dir') or resolved_capture_dir}")
    info(f"Remote capture command : {capture_script} --interface wlan0 --duration 60")
    info(f"Remote service command : {service_script} status")
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

    start_result = _run_remote_service_action(
        source,
        remote_home,
        "start",
        interface=chosen_interface,
        duration=chosen_duration,
        output=output,
    )
    if start_result.returncode != 0:
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
        status_result = _run_remote_service_action(source, remote_home, "status")
        if status_result.returncode != 0:
            err((status_result.stderr or status_result.stdout or "remote service status failed").strip())
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
            "helper": False,
            "helper_path": "",
            "service": False,
            "service_path": "",
            "service_status": "missing",
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

    diag = _run_remote(source, ["--", "sh", "-lc", "; ".join(diag_parts)])
    remote: Dict[str, object] = dict(result["remote"])
    remote["reachable"] = True
    remote["home"] = remote_home
    if diag.returncode == 0:
        parsed = _parse_key_value_output(diag.stdout or "")
        remote["tcpdump"] = parsed.get("tcpdump") == "yes"
        remote["helper"] = parsed.get("helper") == "yes"
        remote["helper_path"] = parsed.get("helper_path") or helper_path
        remote["service"] = parsed.get("service") == "yes"
        remote["service_path"] = parsed.get("service_path") or service_path
        remote["service_status"] = parsed.get("service_status") or "missing"
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
        remote["helper_path"] = helper_path
        remote["service_path"] = service_path
        remote["state_dir"] = state_dir
        remote["privileged_runner_path"] = privileged_runner_path
        remote["capture_dir"] = capture_dir

    result["remote"] = remote
    interface_ok = True
    if interface_name:
        interface_state = remote.get("interface_exists")
        interface_ok = interface_state is not False
    result["ok"] = bool(
        result["local"]["ssh"]
        and result["local"]["scp"]
        and remote["reachable"]
        and remote["tcpdump"]
        and remote["helper"]
        and remote["service"]
        and str(remote.get("privilege_mode") or "") in ("sudoers_runner", "root_session")
        and remote["state_dir_exists"]
        and remote["state_dir_writable"]
        and remote["capture_dir_exists"]
        and remote["capture_dir_writable"]
        and interface_ok
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
