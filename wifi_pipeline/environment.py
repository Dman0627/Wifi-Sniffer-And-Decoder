from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .ui import BOLD, CYAN, DIM, RESET, ask, confirm, err, info, ok, section, warn

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX   = sys.platform.startswith("linux")
IS_MACOS   = sys.platform == "darwin"


@dataclass
class ToolStatus:
    name: str
    purpose: str
    required: bool
    path: Optional[str]


# Tools required/optional on Windows
WINDOWS_TOOLS = (
    ("dumpcap",      "Packet capture through NPcap/Wireshark",  True),
    ("tshark",       "Packet parsing and inspection",           True),
    ("WlanHelper",   "Npcap Wi-Fi mode helper (monitor/managed)", False),
    ("ffplay",       "Optional playback preview",               False),
    ("airdecap-ng",  "Wi-Fi layer decryption (aircrack-ng)",   False),
    ("aircrack-ng",  "WPA2 handshake capture and cracking",     False),
    ("airodump-ng",  "Targeted WPA2 handshake capture",         False),
    ("aireplay-ng",  "Deauth frames for faster handshake",      False),
    ("besside-ng",   "Automatic multi-AP handshake capture",    False),
    ("hashcat",      "GPU-accelerated WPA2 crack",             False),
)

# Tools required/optional on Linux / Kali
LINUX_TOOLS = (
    ("airmon-ng",    "Enable/disable monitor mode",             True),
    ("airodump-ng",  "Targeted WPA2 handshake capture",         True),
    ("aireplay-ng",  "Deauth frames for faster handshake",      False),
    ("aircrack-ng",  "WPA2 PSK dictionary crack",               True),
    ("besside-ng",   "Automatic multi-AP handshake capture",    False),
    ("airdecap-ng",  "Strip Wi-Fi layer from pcap",             True),
    ("hashcat",      "GPU-accelerated WPA2 crack (optional)",   False),
    ("cap2hccapx",   "Convert .cap to hashcat format",          False),
    ("hcxpcapngtool","Alternative cap converter (hcxtools)",    False),
    ("tcpdump",      "Generic monitor-mode raw capture",        False),
    ("ffplay",       "Optional playback preview",               False),
)

# Tools required/optional on macOS
# Install via: brew install aircrack-ng hashcat hcxtools wireshark
# tcpdump ships with macOS and supports monitor mode via -I flag.
MACOS_TOOLS = (
    ("tcpdump",      "Raw capture + monitor mode (-I flag, built-in)", True),
    ("dumpcap",      "Packet capture via Wireshark (brew --cask wireshark)", False),
    ("tshark",       "Packet parsing (brew install wireshark)",        False),
    ("aircrack-ng",  "WPA2 PSK dictionary crack (brew install aircrack-ng)", True),
    ("airdecap-ng",  "Strip Wi-Fi layer from pcap (included with aircrack-ng)", True),
    ("besside-ng",   "Automatic multi-AP handshake capture",           False),
    ("hashcat",      "GPU-accelerated WPA2 crack (brew install hashcat)", False),
    ("cap2hccapx",   "Convert .cap to hashcat format (brew install hcxtools)", False),
    ("hcxpcapngtool","Alternative cap converter (brew install hcxtools)", False),
    ("ffplay",       "Optional playback preview (brew install ffmpeg)", False),
)

def _find_windows_wlanhelper() -> Optional[str]:
    if not IS_WINDOWS:
        return None

    for name in ("WlanHelper.exe", "WlanHelper"):
        found = shutil.which(name)
        if found:
            return found

    system_root = os.environ.get("SYSTEMROOT") or os.environ.get("SystemRoot") or r"C:\Windows"
    candidates = [
        os.path.join(system_root, "System32", "Npcap", "WlanHelper.exe"),
        os.path.join(system_root, "Sysnative", "Npcap", "WlanHelper.exe"),
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Npcap", "WlanHelper.exe"),
        os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Npcap", "WlanHelper.exe"),
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate

    return None


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    # Linux / macOS: check for root
    return os.geteuid() == 0


def relaunch_as_admin(argv: Optional[List[str]] = None) -> None:
    if not IS_WINDOWS:
        raise RuntimeError("UAC elevation helper is Windows-only; use sudo on Linux/macOS.")
    import ctypes
    argv = list(sys.argv[1:] if argv is None else argv)
    script = os.path.abspath(sys.argv[0])
    args = " ".join([f'"{script}"'] + [f'"{item}"' for item in argv])
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, None, 1)
    if result <= 32:
        raise RuntimeError(f"UAC elevation failed with code {result}")


def check_environment() -> bool:
    section("Environment Check")

    if IS_WINDOWS:
        platform_tools = WINDOWS_TOOLS
    elif IS_MACOS:
        platform_tools = MACOS_TOOLS
    else:
        platform_tools = LINUX_TOOLS
    all_required = True

    ok(f"Python runtime: {sys.executable} ({sys.version.split()[0]})")

    for name, purpose, required in platform_tools:
        if IS_WINDOWS and name.lower().startswith("wlanhelper"):
            path = _find_windows_wlanhelper()
        else:
            path = shutil.which(name)
        status = f"{CYAN}*{RESET}" if path else f"{DIM}-{RESET}"
        requirement = "required" if required else "optional"
        location = path or "not found on PATH"
        print(f"  {status} {name:<16} {purpose} {DIM}({requirement}){RESET}")
        print(f"      {location}")
        if required and not path:
            all_required = False

    # Python packages
    for pkg in ("scapy", "numpy"):
        try:
            __import__(pkg)
            ok(f"Python package available: {pkg}")
        except ImportError:
            warn(f"Python package missing: {pkg}")
            if pkg == "scapy":
                all_required = False

    if not is_admin():
        if IS_WINDOWS:
            warn("Administrator rights are recommended for capture and interface discovery.")
        else:
            warn("Root (sudo) is required for monitor mode and raw socket capture on Linux/macOS.")

    if IS_WINDOWS:
        info("Supported workflow: use Windows as the controller/analyzer and Raspberry Pi OS or Ubuntu as the remote capture device.")
        info("Native Windows monitor-mode and Wi-Fi lab capture remain experimental and adapter-dependent.")
        warn("Unsupported as a guaranteed product path: adapter-independent Windows 802.11 monitor/injection parity with Linux.")
    elif IS_LINUX:
        info("Supported Linux role: Raspberry Pi OS or Ubuntu remote capture device controlled from Windows.")
        warn("Other Linux distributions may work, but Raspberry Pi OS and Ubuntu are the supported appliance targets.")
        warn("Raw capture still requires root or capture capabilities even on the supported Linux path.")
    elif IS_MACOS:
        info("macOS support remains experimental; the primary supported capture path is Raspberry Pi OS or Ubuntu.")
        warn("macOS is not a supported capture appliance target for the primary workflow.")

    info("Long-term limit: replay, payload decoding, and reconstruction remain heuristic and are not guaranteed.")

    return all_required


def _parse_dumpcap_interfaces(output: str) -> List[Tuple[str, str, str]]:
    interfaces: List[Tuple[str, str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or "." not in line:
            continue
        number, rest = line.split(".", 1)
        number = number.strip()
        rest = rest.strip()
        if "(" in rest and rest.endswith(")"):
            name = rest[: rest.index("(")].strip()
            description = rest[rest.index("(") + 1 : -1].strip()
        else:
            name = rest
            description = ""
        interfaces.append((number, name, description))
    return interfaces


def _list_linux_interfaces() -> List[Tuple[str, str, str]]:
    """List wireless interfaces on Linux using iw or iwconfig."""
    interfaces: List[Tuple[str, str, str]] = []
    iw = shutil.which("iw")
    if iw:
        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=5, check=False
        )
        current_iface = None
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                current_iface = line.split()[1]
                interfaces.append((str(len(interfaces) + 1), current_iface, "wireless (iw)"))
        if interfaces:
            return interfaces

    # Fallback: /sys/class/net
    net_path = "/sys/class/net"
    if os.path.isdir(net_path):
        for index, name in enumerate(sorted(os.listdir(net_path)), start=1):
            if name.startswith(("wlan", "wlp", "ath", "mon")):
                interfaces.append((str(index), name, "wireless"))
    return interfaces


def _list_macos_interfaces() -> List[Tuple[str, str, str]]:
    """List network interfaces on macOS using networksetup."""
    interfaces: List[Tuple[str, str, str]] = []
    try:
        result = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        current_port = ""
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Hardware Port:"):
                current_port = line.split(":", 1)[1].strip()
            elif line.startswith("Device:") and current_port:
                iface = line.split(":", 1)[1].strip()
                if iface:
                    interfaces.append((str(len(interfaces) + 1), iface, current_port))
                current_port = ""
    except (OSError, subprocess.TimeoutExpired):
        pass

    if not interfaces:
        # Fallback: list all interfaces from ifconfig
        try:
            result = subprocess.run(
                ["ifconfig", "-l"], capture_output=True, text=True, timeout=5, check=False,
            )
            for index, name in enumerate(result.stdout.split(), start=1):
                interfaces.append((str(index), name, "network interface"))
        except (OSError, subprocess.TimeoutExpired):
            pass

    return interfaces


def list_interfaces() -> List[Tuple[str, str, str]]:
    if IS_MACOS:
        return _list_macos_interfaces()
    if IS_LINUX:
        return _list_linux_interfaces()
    if not IS_WINDOWS:
        return []

    dumpcap = shutil.which("dumpcap")
    if dumpcap:
        try:
            result = subprocess.run(
                [dumpcap, "-D"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except OSError:
            result = None
        if result and result.stdout.strip():
            parsed = _parse_dumpcap_interfaces(result.stdout)
            if parsed:
                return parsed

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-NetAdapter | Select-Object Name,InterfaceDescription,InterfaceGuid "
                "| ConvertTo-Csv -NoTypeInformation",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except OSError:
        return []

    interfaces: List[Tuple[str, str, str]] = []
    for index, line in enumerate(result.stdout.splitlines()[1:], start=1):
        parts = [part.strip().strip('"') for part in line.split('","')]
        if len(parts) < 3:
            continue
        name = f"\\\\Device\\\\NPF_{{{parts[2].strip('{}')}}}"
        description = f"{parts[0]} - {parts[1]}"
        interfaces.append((str(index), name, description))
    return interfaces


def pick_interface(current: str) -> str:
    interfaces = list_interfaces()
    if not interfaces:
        warn("Unable to enumerate interfaces automatically.")
        if IS_WINDOWS:
            print(f"  {BOLD}Tip:{RESET} install Wireshark/NPcap and re-run in an Administrator shell.")
        elif IS_MACOS:
            print(f"  {BOLD}Tip:{RESET} run as root (sudo) and ensure Xcode CLI tools are installed.")
        else:
            print(f"  {BOLD}Tip:{RESET} install iw ('sudo apt install iw') and re-run as root.")
        return ask("Capture interface", current or "")

    section("Available Interfaces")
    for number, name, description in interfaces:
        label = f"  {number}. {name}"
        if description:
            label += f" {DIM}({description}){RESET}"
        print(label)

    selected = ask("Enter interface number or full name", current or interfaces[0][1])
    for number, name, _description in interfaces:
        if selected == number:
            ok(f"Selected {name}")
            return name
    return selected


def maybe_elevate_for_capture(interactive: bool = True) -> bool:
    if IS_LINUX or IS_MACOS:
        if not is_admin():
            warn("Monitor mode and raw capture require root on Linux/macOS. Re-run with sudo.")
        return False   # Don't block — let the underlying tool produce the real error
    if not IS_WINDOWS:
        return False
    if is_admin():
        return False
    warn("Capture usually needs Administrator rights on Windows.")
    if not interactive:
        info("Continuing without elevation because this run is non-interactive.")
        return False
    if confirm("Relaunch as Administrator now?", default=True):
        relaunch_as_admin()
        return True
    info("Continuing without elevation. Capture may fail.")
    return False
