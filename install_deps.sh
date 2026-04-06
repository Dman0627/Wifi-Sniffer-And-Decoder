#!/usr/bin/env bash
# install_deps.sh — WiFi Stream Pipeline dependency installer
# Supports Linux (apt-based) and macOS (Homebrew)
# Usage:
#   chmod +x install_deps.sh
#   ./install_deps.sh              # Python venv + pip only
#   ./install_deps.sh --full       # Also install system packages (requires sudo / brew)

set -euo pipefail

FULL=0
for arg in "$@"; do
    case "$arg" in
        --full) FULL=1 ;;
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

# ── System packages ────────────────────────────────────────────────────────
if [[ "$FULL" -eq 1 ]]; then
    if [[ "$OS" == "linux" ]]; then
        echo "[*] Installing system packages via apt ..."
        sudo apt-get update -qq
        sudo apt-get install -y \
            aircrack-ng \
            hashcat \
            hcxtools \
            tcpdump \
            wireshark \
            tshark \
            python3-pip \
            python3-venv
        echo "[+] System packages installed."

    elif [[ "$OS" == "macos" ]]; then
        if ! command -v brew &>/dev/null; then
            echo "[!] Homebrew not found. Install it from https://brew.sh then re-run."
            exit 1
        fi
        echo "[*] Installing system packages via Homebrew ..."
        brew install aircrack-ng hashcat hcxtools
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

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "[+] Done. Activate the venv with:"
echo "      source .venv/bin/activate"
echo ""
echo "    Then run:"
echo "      python3 videopipeline.py config    # interactive setup"
echo "      python3 videopipeline.py deps      # verify all tools"
echo "      python3 videopipeline.py           # open guided menu"
if [[ "$OS" == "linux" ]]; then
    echo ""
    echo "    Monitor mode and capture require root:"
    echo "      sudo python3 videopipeline.py monitor"
    echo "      sudo python3 videopipeline.py wifi"
elif [[ "$OS" == "macos" ]]; then
    echo ""
    echo "    Monitor mode (tcpdump -I) requires root:"
    echo "      sudo python3 videopipeline.py monitor --method tcpdump"
fi
