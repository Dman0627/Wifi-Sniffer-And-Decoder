#!/usr/bin/env bash
# WiFi Stream Pipeline dependency installer.
# Primary use: prepare a Raspberry Pi OS or Ubuntu capture device.
# Also usable for development on Linux/macOS.
#
# Usage:
#   chmod +x install_deps.sh
#   ./install_deps.sh              # Install system packages + venv + Python deps
#   ./install_deps.sh --no-system  # Skip system packages
#   ./install_deps.sh --skip-ssh   # Do not create an SSH key
#   ./install_deps.sh --full       # Same as default (kept for compatibility)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

FULL=1
SETUP_SSH=1

log() {
    printf '%s\n' "$*"
}

die() {
    printf '[!] %s\n' "$*" >&2
    exit 1
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

for arg in "$@"; do
    case "$arg" in
        --full) FULL=1 ;;
        --no-system) FULL=0 ;;
        --skip-ssh) SETUP_SSH=0 ;;
        *) die "Unknown argument: $arg" ;;
    esac
done

OS=""
if [[ "$(uname -s)" == "Darwin" ]]; then
    OS="macos"
elif [[ -f /etc/os-release ]]; then
    OS="linux"
else
    die "Unsupported platform: $(uname -s)"
fi

log "[*] Detected platform: $OS"
log "[*] Supported product path: Windows controller + Raspberry Pi OS/Ubuntu capture device"
log "[*] Explicit limits:"
log "    - This project does not make Windows monitor mode adapter-independent"
log "    - Supported remote appliance targets are Raspberry Pi OS and Ubuntu"
log "    - Replay and payload reconstruction remain heuristic"

if [[ "$FULL" -eq 1 ]]; then
    if [[ "$OS" == "linux" ]]; then
        if ! have_cmd apt-get; then
            log "[!] Automatic system package installation currently targets apt-based Raspberry Pi OS/Ubuntu systems."
            log "[!] Skipping system package installation on this distro."
        else
            log "[*] Installing system packages via apt ..."
            sudo apt-get update -qq
            sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
                aircrack-ng \
                hashcat \
                hcxtools \
                openssh-client \
                tcpdump \
                wireshark \
                tshark \
                ffmpeg \
                python3-pip \
                python3-venv
            log "[+] System packages installed."
        fi
    elif [[ "$OS" == "macos" ]]; then
        if ! have_cmd brew; then
            die "Homebrew not found. Install it from https://brew.sh then re-run."
        fi
        log "[*] Installing system packages via Homebrew ..."
        brew install aircrack-ng hashcat hcxtools ffmpeg
        brew install --cask wireshark || true
        log "[+] System packages installed."
        log "[!] Note: tcpdump is built in on macOS. No extra install needed."
        log "[!] Monitor mode uses: sudo tcpdump -I -i <interface>"
    fi
else
    log "[*] Skipping system package install."
fi

if ! have_cmd python3; then
    die "python3 is required. Install Python 3.12+ and re-run this script."
fi

if [[ ! -d .venv ]]; then
    log "[*] Creating Python virtual environment in .venv ..."
    python3 -m venv .venv
    log "[+] Virtual environment created."
else
    log "[*] Virtual environment already exists at .venv; reusing."
fi

log "[*] Installing Python packages from requirements.txt ..."
source .venv/bin/activate
python3 -m pip install --quiet --upgrade pip
python3 -m pip install --quiet -r requirements.txt
log "[+] Python packages installed."

if [[ "$SETUP_SSH" -eq 1 ]]; then
    if have_cmd ssh-keygen; then
        mkdir -p "$HOME/.ssh"
        if [[ ! -f "$HOME/.ssh/id_ed25519" ]]; then
            log "[*] Generating SSH key for remote capture pairing ..."
            ssh-keygen -t ed25519 -f "$HOME/.ssh/id_ed25519" -N "" >/dev/null
            log "[+] SSH key created at $HOME/.ssh/id_ed25519.pub"
        else
            log "[*] SSH key already exists at $HOME/.ssh/id_ed25519"
        fi
    else
        log "[!] ssh-keygen not found; skipping SSH key setup."
    fi
fi

log ""
log "[+] Done. Activate the venv with:"
log "      source .venv/bin/activate"
log ""
log "    Then run:"
log "      (Primary role for Linux: remote capture device)"
log "      python3 videopipeline.py config"
log "      python3 videopipeline.py deps"
log "      python3 videopipeline.py pair-remote --host pi@raspberrypi"
log "      python3 videopipeline.py bootstrap-remote --host pi@raspberrypi"
log "      # bootstrap-remote also tries to configure the no-prompt privileged capture runner"
log "      python3 videopipeline.py start-remote --host pi@raspberrypi --interface wlan0 --duration 60 --run all"
log "      python3 videopipeline.py remote-service status --host pi@raspberrypi"
log "      # the managed service tracks completion markers and SHA-256 metadata for pulls"
log "      python3 videopipeline.py doctor --host pi@raspberrypi --interface wlan0"
log "      bash ./scripts/check.sh"
log "      python3 videopipeline.py"

if [[ "$OS" == "linux" ]]; then
    log ""
    log "    Monitor mode and capture require root:"
    log "      sudo python3 videopipeline.py monitor"
    log "      sudo python3 videopipeline.py wifi"
    log "    Other Linux distributions may work, but Raspberry Pi OS and Ubuntu are the supported appliance targets."
elif [[ "$OS" == "macos" ]]; then
    log ""
    log "    Monitor mode (tcpdump -I) requires root:"
    log "      sudo python3 videopipeline.py monitor --method tcpdump"
    log "    macOS is a development/experimental path, not a supported capture appliance target."
fi
