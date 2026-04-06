#!/usr/bin/env bash
# install_deps.sh — WiFi Stream Pipeline dependency installer
# Primary use: prepare a Raspberry Pi OS or Ubuntu capture device
# Also usable for development on Linux/macOS
# Usage:
#   chmod +x install_deps.sh
#   ./install_deps.sh              # Install system packages + Python venv + pip
#   ./install_deps.sh --no-system  # Skip system packages
#   ./install_deps.sh --skip-ssh   # Do not create an SSH key
#   ./install_deps.sh --full       # Same as default (kept for compatibility)

set -euo pipefail

FULL=1
SETUP_SSH=1
for arg in "$@"; do
    case "$arg" in
        --full) FULL=1 ;;
        --no-system) FULL=0 ;;
        --skip-ssh) SETUP_SSH=0 ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

# ── Detect platform ────────────────────────────────────────────────────────
OS=""
if [[ "$(uname -s)" == "Darwin" ]]; then
    OS="macos"
elif [[ -f /etc/os-release ]]; then
    OS="linux"
else
    echo "Unsupported platform: $(uname -s)"
    exit 1
fi
echo "[*] Detected platform: $OS"
echo "[*] Supported product path: Windows controller + Raspberry Pi OS/Ubuntu capture device"
echo "[*] Explicit limits:"
echo "    - This project does not make Windows monitor mode adapter-independent"
echo "    - Supported remote appliance targets are Raspberry Pi OS and Ubuntu"
echo "    - Replay and payload reconstruction remain heuristic"

# ── System packages ────────────────────────────────────────────────────────
if [[ "$FULL" -eq 1 ]]; then
    if [[ "$OS" == "linux" ]]; then
        echo "[*] Installing system packages via apt ..."
        sudo apt-get update -qq
        sudo apt-get install -y \
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
        echo "[+] System packages installed."

    elif [[ "$OS" == "macos" ]]; then
        if ! command -v brew &>/dev/null; then
            echo "[!] Homebrew not found. Install it from https://brew.sh then re-run."
            exit 1
        fi
        echo "[*] Installing system packages via Homebrew ..."
        brew install aircrack-ng hashcat hcxtools ffmpeg
        # Wireshark is a cask (GUI app); tshark/dumpcap come with it
        brew install --cask wireshark || true
        echo "[+] System packages installed."
        echo "[!] Note: tcpdump is built-in on macOS. No extra install needed."
        echo "[!] Monitor mode uses: sudo tcpdump -I -i <interface>"
    fi
else
    echo "[*] Skipping system package install (pass --full to enable)."
fi

# ── Python virtual environment ────────────────────────────────────────────
if [[ ! -d .venv ]]; then
    echo "[*] Creating Python virtual environment in .venv ..."
    python3 -m venv .venv
    echo "[+] Virtual environment created."
else
    echo "[*] Virtual environment already exists at .venv — reusing."
fi

# ── Activate and install pip packages ────────────────────────────────────
echo "[*] Installing Python packages from requirements.txt ..."
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo "[+] Python packages installed."

if [[ "$SETUP_SSH" -eq 1 ]]; then
    if command -v ssh-keygen &>/dev/null; then
        mkdir -p "$HOME/.ssh"
        if [[ ! -f "$HOME/.ssh/id_ed25519" ]]; then
            echo "[*] Generating SSH key for remote capture pairing ..."
            ssh-keygen -t ed25519 -f "$HOME/.ssh/id_ed25519" -N "" >/dev/null
            echo "[+] SSH key created at $HOME/.ssh/id_ed25519.pub"
        else
            echo "[*] SSH key already exists at $HOME/.ssh/id_ed25519"
        fi
    else
        echo "[!] ssh-keygen not found; skipping SSH key setup."
    fi
fi

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "[+] Done. Activate the venv with:"
echo "      source .venv/bin/activate"
echo ""
echo "    Then run:"
echo "      (Primary role for Linux: remote capture device)"
echo "      python3 videopipeline.py config    # interactive setup"
echo "      python3 videopipeline.py deps      # verify all tools"
echo "      python3 videopipeline.py pair-remote --host pi@raspberrypi"
echo "      python3 videopipeline.py bootstrap-remote --host pi@raspberrypi"
echo "      # bootstrap-remote also tries to configure the no-prompt privileged capture runner"
echo "      python3 videopipeline.py start-remote --host pi@raspberrypi --interface wlan0 --duration 60 --run all"
echo "      python3 videopipeline.py remote-service status --host pi@raspberrypi"
echo "      # the managed service tracks completion markers and SHA-256 metadata for pulls"
echo "      python3 videopipeline.py doctor --host pi@raspberrypi --interface wlan0"
echo "      python3 videopipeline.py           # open guided menu"
if [[ "$OS" == "linux" ]]; then
    echo ""
    echo "    Monitor mode and capture require root:"
    echo "      sudo python3 videopipeline.py monitor"
    echo "      sudo python3 videopipeline.py wifi"
    echo "    Other Linux distributions may work, but Raspberry Pi OS and Ubuntu are the supported appliance targets."
elif [[ "$OS" == "macos" ]]; then
    echo ""
    echo "    Monitor mode (tcpdump -I) requires root:"
    echo "      sudo python3 videopipeline.py monitor --method tcpdump"
    echo "    macOS is a development/experimental path, not a supported capture appliance target."
fi
