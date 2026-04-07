from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .capabilities import (
    AdapterCapability,
    CapabilityReport,
    CaptureMethodCapability,
    PlatformCapability,
    RemoteSupportCapability,
    ReplayFamilyCapability,
    ToolCapability,
    WPAReadinessCapability,
)
from .reasons import Reason, make_blocker, make_context, make_limitation
from .ui import BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW, ask, confirm, err, info, ok, section, warn

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX   = sys.platform.startswith("linux")
IS_MACOS   = sys.platform == "darwin"

SUPPORTED_PRODUCT_MODES = (
    "Ubuntu standalone",
    "Raspberry Pi OS standalone",
    "Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture",
)
SUPPORTED_PRODUCT_SUMMARY = "; ".join(SUPPORTED_PRODUCT_MODES)


@dataclass
class ToolStatus:
    name: str
    purpose: str
    required: bool
    path: Optional[str]


@dataclass(frozen=True)
class ProductProfile:
    key: str
    label: str
    official: bool
    standalone: bool
    remote_capture: bool
    description: str


@dataclass(frozen=True)
class CommandSupport:
    command: str
    profile: ProductProfile
    status: str
    message: str


@dataclass(frozen=True)
class WorkflowSupport:
    area: str
    tier: str
    summary: str
    detail: str
    reasons: Tuple[Reason, ...] = ()


@dataclass(frozen=True)
class HardwareCatalogEntry:
    family: str
    role: str
    status: str
    profiles: Tuple[str, ...]
    match_terms: Tuple[str, ...]
    monitor_mode: str
    injection: str
    channels: str
    detail: str


@dataclass(frozen=True)
class HardwareQualification:
    area: str
    label: str
    status: str
    summary: str
    detail: str
    monitor_mode: str
    injection: str
    channels: str


PRODUCT_PROFILES: Dict[str, ProductProfile] = {
    "ubuntu_standalone": ProductProfile(
        key="ubuntu_standalone",
        label="Ubuntu standalone",
        official=True,
        standalone=True,
        remote_capture=True,
        description="Full local capture and analysis on Ubuntu.",
    ),
    "pi_standalone": ProductProfile(
        key="pi_standalone",
        label="Raspberry Pi OS standalone",
        official=True,
        standalone=True,
        remote_capture=True,
        description="Full local capture and analysis on Raspberry Pi OS.",
    ),
    "windows_remote": ProductProfile(
        key="windows_remote",
        label="Windows 10/11 + Ubuntu/Raspberry Pi OS remote capture",
        official=True,
        standalone=False,
        remote_capture=True,
        description="Windows controls and analyzes while Linux handles capture.",
    ),
    "windows_experimental_local": ProductProfile(
        key="windows_experimental_local",
        label="Windows local capture (experimental)",
        official=False,
        standalone=False,
        remote_capture=False,
        description="Best-effort native Windows capture and Wi-Fi lab path.",
    ),
    "linux_best_effort": ProductProfile(
        key="linux_best_effort",
        label="Other Linux distro (best effort)",
        official=False,
        standalone=True,
        remote_capture=True,
        description="Linux workflow outside the official Ubuntu/Raspberry Pi OS targets.",
    ),
    "macos_experimental": ProductProfile(
        key="macos_experimental",
        label="macOS experimental",
        official=False,
        standalone=True,
        remote_capture=False,
        description="Experimental macOS workflow.",
    ),
}


SUPPORTED_HARDWARE_CATALOG: Tuple[HardwareCatalogEntry, ...] = (
    HardwareCatalogEntry(
        family="Atheros AR9271 / ath9k_htc",
        role="linux_capture_adapter",
        status="supported",
        profiles=("ubuntu_standalone", "pi_standalone", "linux_best_effort"),
        match_terms=("ath9k_htc", "ar9271", "qca9271", "atheros ar9271"),
        monitor_mode="qualified",
        injection="qualified",
        channels="2.4 GHz",
        detail="Best-supported USB adapter family for the full Linux Wi-Fi lab workflow.",
    ),
    HardwareCatalogEntry(
        family="MediaTek MT7612U / mt76x2u",
        role="linux_capture_adapter",
        status="supported_with_limits",
        profiles=("ubuntu_standalone", "pi_standalone", "linux_best_effort"),
        match_terms=("mt76x2u", "mt7612u"),
        monitor_mode="qualified",
        injection="best effort",
        channels="2.4/5 GHz",
        detail="Good dual-band Linux capture option, but injection and firmware behavior still vary by device.",
    ),
    HardwareCatalogEntry(
        family="Ralink/MediaTek RT5572 / rt2800usb",
        role="linux_capture_adapter",
        status="supported_with_limits",
        profiles=("ubuntu_standalone", "pi_standalone", "linux_best_effort"),
        match_terms=("rt2800usb", "rt5572"),
        monitor_mode="qualified",
        injection="best effort",
        channels="2.4/5 GHz",
        detail="Common dual-band USB capture option; keep expectations conservative for injection-heavy lab steps.",
    ),
    HardwareCatalogEntry(
        family="Intel iwlwifi family",
        role="linux_capture_adapter",
        status="supported_with_limits",
        profiles=("ubuntu_standalone", "linux_best_effort"),
        match_terms=("iwlwifi", "intel wireless", "intel corporation wifi"),
        monitor_mode="available on many chipsets",
        injection="not part of the qualified lab path",
        channels="chipset dependent",
        detail="Useful for pcap-first and sniffing workflows, but not the narrow recommended adapter family for full Wi-Fi lab work.",
    ),
    HardwareCatalogEntry(
        family="Broadcom brcmfmac family",
        role="linux_capture_adapter",
        status="unsupported",
        profiles=("ubuntu_standalone", "pi_standalone", "linux_best_effort"),
        match_terms=("brcmfmac", "broadcom"),
        monitor_mode="limited / chipset dependent",
        injection="not qualified",
        channels="chipset dependent",
        detail="Typical onboard Broadcom Raspberry Pi radios are not part of the qualified monitor/injection hardware program.",
    ),
)


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

WINDOWS_CAPABILITY_TOOLS = (
    ("Npcap",        "Windows packet capture driver/runtime",           False),
)

MACOS_CAPABILITY_TOOLS = (
    ("networksetup", "macOS interface and hardware-port inspection",    False),
    ("airport",      "Apple Wi-Fi diagnostics helper",                  False),
)

LINUX_CAPABILITY_TOOLS = (
    ("iw",           "Wireless PHY and monitor-mode inspection",       False),
    ("ethtool",      "Linux driver and interface inspection",          False),
    ("getcap",       "Linux file capability inspection",               False),
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


def _find_windows_npcap() -> Optional[str]:
    if not IS_WINDOWS:
        return None

    wlanhelper = _find_windows_wlanhelper()
    if wlanhelper:
        return os.path.dirname(wlanhelper)

    system_root = os.environ.get("SYSTEMROOT") or os.environ.get("SystemRoot") or r"C:\Windows"
    candidates = [
        os.path.join(system_root, "System32", "Npcap"),
        os.path.join(system_root, "Sysnative", "Npcap"),
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Npcap"),
        os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Npcap"),
    ]
    markers = ("Packet.dll", "WlanHelper.exe", "NPFInstall.exe")
    for candidate in candidates:
        if candidate and os.path.isdir(candidate) and any(os.path.exists(os.path.join(candidate, marker)) for marker in markers):
            return candidate
    return None


def _find_macos_airport() -> Optional[str]:
    if not IS_MACOS:
        return None

    found = shutil.which("airport")
    if found:
        return found

    candidate = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    return candidate if os.path.exists(candidate) else None


def _tool_path(name: str) -> Optional[str]:
    if IS_WINDOWS and name.lower() == "npcap":
        return _find_windows_npcap()
    if IS_MACOS and name.lower() == "airport":
        return _find_macos_airport()
    if IS_WINDOWS and name.lower().startswith("wlanhelper"):
        return _find_windows_wlanhelper()
    return shutil.which(name)


def _tool_available(name: str) -> bool:
    return bool(_tool_path(name))


def _safe_command_output(command: List[str], timeout: int = 5) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip()


def _tool_reason_key(name: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in name.lower()).strip("_")


def _platform_tool_specs() -> Tuple[Tuple[str, str, bool], ...]:
    if IS_WINDOWS:
        return WINDOWS_TOOLS + WINDOWS_CAPABILITY_TOOLS
    if IS_MACOS:
        return MACOS_TOOLS + MACOS_CAPABILITY_TOOLS
    if IS_LINUX:
        return LINUX_TOOLS + LINUX_CAPABILITY_TOOLS
    return ()


def _safe_json_output(command: List[str], timeout: int = 10) -> List[Dict[str, object]]:
    raw = _safe_command_output(command, timeout=timeout)
    if not raw:
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _tier_sort_key(tier: str) -> int:
    order = {
        "supported": 0,
        "supported_with_limits": 1,
        "heuristic": 2,
        "unsupported": 3,
    }
    return order.get(tier, 99)


def _tier_label(tier: str) -> str:
    labels = {
        "supported": "supported",
        "supported_with_limits": "supported with limits",
        "heuristic": "heuristic",
        "unsupported": "unsupported",
    }
    return labels.get(tier, tier.replace("_", " "))


def _read_text_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _machine_architecture() -> str:
    return platform.machine().strip().lower() or "unknown"


def _linux_binary_has_capture_capabilities(path: Optional[str]) -> bool:
    if not IS_LINUX or not path or not os.path.exists(path):
        return False

    getcap = shutil.which("getcap")
    if not getcap:
        return False

    output = _safe_command_output([getcap, path], timeout=5).lower()
    return "cap_net_raw" in output or "cap_net_admin" in output


def _normalize_windows_guid(value: str) -> str:
    return value.strip().strip("{}").lower()


def _windows_interface_guid(interface: str) -> str:
    marker = "npf_{"
    lowered = interface.lower()
    if marker in lowered:
        start = lowered.index(marker) + len(marker)
        suffix = interface[start:]
        end = suffix.find("}")
        if end != -1:
            return _normalize_windows_guid(suffix[:end])
    return ""


def _windows_adapter_inventory() -> List[Dict[str, str]]:
    if not IS_WINDOWS:
        return []

    records = _safe_json_output(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            (
                "$ErrorActionPreference='SilentlyContinue'; "
                "Get-NetAdapter | "
                "Select-Object Name,InterfaceDescription,InterfaceGuid,Status,DriverFileName,DriverDescription,DriverInformation,MacAddress,LinkSpeed,MediaConnectionState | "
                "ConvertTo-Json -Compress"
            ),
        ],
        timeout=10,
    )
    normalized: List[Dict[str, str]] = []
    for item in records:
        normalized.append(
            {
                "name": str(item.get("Name") or "").strip(),
                "interface_description": str(item.get("InterfaceDescription") or "").strip(),
                "interface_guid": _normalize_windows_guid(str(item.get("InterfaceGuid") or "")),
                "status": str(item.get("Status") or "").strip(),
                "driver_file_name": str(item.get("DriverFileName") or "").strip(),
                "driver_description": str(item.get("DriverDescription") or item.get("DriverInformation") or "").strip(),
                "mac_address": str(item.get("MacAddress") or "").strip(),
                "link_speed": str(item.get("LinkSpeed") or "").strip(),
                "media_connection_state": str(item.get("MediaConnectionState") or "").strip(),
            }
        )
    return normalized


def _windows_matches_adapter_inventory(interface: str, description: str, item: Dict[str, str]) -> bool:
    guid = _windows_interface_guid(interface)
    if guid and guid == item.get("interface_guid", ""):
        return True

    candidates = [interface.strip().lower(), description.strip().lower()]
    adapter_name = str(item.get("name") or "").strip().lower()
    adapter_description = str(item.get("interface_description") or "").strip().lower()
    if any(candidate and candidate == adapter_name for candidate in candidates):
        return True
    if any(candidate and candidate == adapter_description for candidate in candidates):
        return True

    joined = " ".join(candidate for candidate in candidates if candidate)
    if joined:
        if adapter_name and adapter_name in joined:
            return True
        if adapter_description and adapter_description in joined:
            return True
        if any(candidate and candidate in adapter_description for candidate in candidates):
            return True

    return False


def _windows_is_wireless_adapter(*parts: str) -> bool:
    lowered = " ".join(part.strip().lower() for part in parts if part and part.strip())
    return any(
        token in lowered
        for token in (
            "wi-fi",
            "wifi",
            "wireless",
            "wlan",
            "802.11",
            "80211",
            "wireless-ac",
            "wireless-ax",
        )
    )


def _linux_interface_driver(interface: str) -> str:
    if not IS_LINUX or not interface:
        return ""

    uevent_path = os.path.join("/sys/class/net", interface, "device", "uevent")
    if os.path.exists(uevent_path):
        for raw_line in _read_text_file(uevent_path).splitlines():
            if raw_line.startswith("DRIVER="):
                return raw_line.split("=", 1)[1].strip().lower()

    driver_link = os.path.join("/sys/class/net", interface, "device", "driver")
    if os.path.islink(driver_link):
        try:
            return os.path.basename(os.path.realpath(driver_link)).strip().lower()
        except OSError:
            return ""

    return ""


def _linux_interface_fingerprint(interface: str, description: str = "") -> str:
    if not IS_LINUX or not interface:
        return ""

    base = os.path.join("/sys/class/net", interface, "device")
    parts = [
        interface,
        description,
        _linux_interface_driver(interface),
        _read_text_file(os.path.join(base, "vendor")),
        _read_text_file(os.path.join(base, "device")),
        _read_text_file(os.path.join(base, "modalias")),
        _read_text_file(os.path.join(base, "uevent")),
    ]
    return " ".join(part.strip().lower() for part in parts if part and part.strip())


def _linux_interface_phy_name(interface: str) -> str:
    if not IS_LINUX or not interface:
        return ""

    phy_link = os.path.join("/sys/class/net", interface, "phy80211")
    if os.path.islink(phy_link):
        try:
            return os.path.basename(os.path.realpath(phy_link)).strip()
        except OSError:
            return ""

    output = _safe_command_output(["iw", "dev", interface, "info"])
    for raw_line in output.splitlines():
        line = raw_line.strip().lower()
        if line.startswith("wiphy "):
            suffix = line.split(" ", 1)[1].strip()
            if suffix.isdigit():
                return f"phy{suffix}"
    return ""


def _linux_output_supports_monitor(output: str) -> bool | None:
    if not output.strip():
        return None

    saw_supported_modes = False
    in_modes_block = False
    for raw_line in output.splitlines():
        stripped = raw_line.strip().lower()
        if stripped.startswith("supported interface modes"):
            saw_supported_modes = True
            in_modes_block = True
            continue
        if not in_modes_block:
            continue
        if stripped.startswith("*"):
            if "monitor" in stripped:
                return True
            continue
        if stripped and not raw_line.startswith((" ", "\t")):
            break
        if stripped.startswith("valid interface combinations"):
            break

    if saw_supported_modes:
        return False
    return None


def _linux_interface_supports_monitor_mode(interface: str, phy_name: str = "") -> bool | None:
    if not IS_LINUX or not interface or not _tool_available("iw"):
        return None

    if phy_name:
        phy_output = _safe_command_output(["iw", "phy", phy_name, "info"])
        advertised = _linux_output_supports_monitor(phy_output)
        if advertised is not None:
            return advertised

    return _linux_output_supports_monitor(_safe_command_output(["iw", "list"]))


def _match_hardware_catalog(fingerprint: str, profile_key: str) -> Optional[HardwareCatalogEntry]:
    lowered = fingerprint.lower()
    for entry in SUPPORTED_HARDWARE_CATALOG:
        if profile_key not in entry.profiles:
            continue
        if any(term in lowered for term in entry.match_terms):
            return entry
    return None


def _read_os_release() -> Dict[str, str]:
    if not IS_LINUX:
        return {}
    path = "/etc/os-release"
    if not os.path.exists(path):
        return {}

    values: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return values


def _linux_machine_model() -> str:
    if not IS_LINUX:
        return ""

    for path in ("/sys/firmware/devicetree/base/model", "/proc/device-tree/model"):
        if not os.path.exists(path):
            continue
        try:
            return open(path, "r", encoding="utf-8", errors="ignore").read().strip("\x00\r\n ")
        except OSError:
            return ""
    return ""


def _macos_machine_model() -> str:
    if not IS_MACOS:
        return ""
    return _safe_command_output(["sysctl", "-n", "hw.model"], timeout=5)


def linux_distribution_label() -> str:
    if not IS_LINUX:
        return ""

    data = _read_os_release()
    pretty = data.get("PRETTY_NAME") or data.get("NAME") or "Linux"
    model = _linux_machine_model()
    if "raspberry pi" in pretty.lower():
        return pretty
    if "raspberry pi" in model.lower():
        return f"{pretty} on Raspberry Pi".strip()
    return pretty


def default_product_mode() -> str:
    if IS_WINDOWS:
        return "windows_remote"
    if IS_MACOS:
        return "macos_experimental"
    if not IS_LINUX:
        return "macos_experimental"

    data = _read_os_release()
    distro_id = data.get("ID", "").strip().lower()
    pretty = (data.get("PRETTY_NAME") or data.get("NAME") or "").lower()
    model = _linux_machine_model().lower()
    if distro_id == "ubuntu":
        return "ubuntu_standalone"
    if distro_id == "raspbian" or "raspberry pi os" in pretty or "raspberry pi" in model:
        return "pi_standalone"
    return "linux_best_effort"


def resolve_product_profile(config: Optional[Dict[str, object]] = None) -> ProductProfile:
    requested = str((config or {}).get("product_mode") or "").strip().lower().replace("-", "_")
    detected_key = default_product_mode()

    if requested in PRODUCT_PROFILES:
        if IS_WINDOWS and requested in ("windows_remote", "windows_experimental_local"):
            return PRODUCT_PROFILES[requested]
        if IS_MACOS and requested == "macos_experimental":
            return PRODUCT_PROFILES[requested]
        if IS_LINUX and requested == detected_key:
            return PRODUCT_PROFILES[requested]

    return PRODUCT_PROFILES[detected_key]


def _capability_status_from_support(command_status: str, available: bool) -> str:
    if not available:
        return "unsupported"
    if command_status == "official":
        return "supported"
    if command_status == "best_effort":
        return "supported_with_limits"
    if command_status == "experimental":
        return "experimental"
    return "supported_with_limits"


def _current_platform_capability(config: Optional[Dict[str, object]] = None) -> PlatformCapability:
    profile = resolve_product_profile(config)
    if IS_WINDOWS:
        os_name = "windows"
        distribution = "Windows"
        version = platform.release() or platform.version()
        distribution_id = ""
        distribution_version = ""
        machine_model = ""
    elif IS_MACOS:
        os_name = "macos"
        version = platform.mac_ver()[0] or platform.release()
        distribution = f"macOS {version}".strip()
        distribution_id = "macos"
        distribution_version = version or ""
        machine_model = _macos_machine_model()
    else:
        os_release = _read_os_release()
        os_name = "linux"
        distribution = linux_distribution_label() or "Linux"
        version = platform.release()
        distribution_id = os_release.get("ID", "").strip().lower()
        distribution_version = os_release.get("VERSION_ID", "").strip()
        machine_model = _linux_machine_model()

    return PlatformCapability(
        os_name=os_name,
        os_version=version or "unknown",
        distribution=distribution,
        architecture=_machine_architecture(),
        product_profile_key=profile.key,
        product_profile_label=profile.label,
        official=profile.official,
        distribution_id=distribution_id,
        distribution_version=distribution_version,
        machine_model=machine_model,
    )


def _privilege_mode_label() -> str:
    if IS_WINDOWS:
        return "administrator" if is_admin() else "user"
    if is_admin():
        return "root"
    if IS_LINUX:
        capture_paths = [_tool_path(name) for name in ("dumpcap", "tcpdump")]
        if any(_linux_binary_has_capture_capabilities(path) for path in capture_paths):
            return "capture_capabilities"
    return "user"


def _adapter_capture_methods(status: str) -> Tuple[str, ...]:
    methods: List[str] = []
    if _tool_available("dumpcap") or (not IS_WINDOWS and _tool_available("tcpdump")):
        methods.append("local_capture")
    if status != "unsupported" and (
        _tool_available("airodump-ng")
        or _tool_available("airmon-ng")
        or _tool_available("WlanHelper")
        or _tool_available("tcpdump")
        or _tool_available("dumpcap")
    ):
        methods.append("monitor_capture")
    return tuple(methods)


def _macos_is_wireless_interface(*parts: str) -> bool:
    lowered = " ".join(part.strip().lower() for part in parts if part and part.strip())
    return any(
        token in lowered
        for token in (
            "wi-fi",
            "wifi",
            "wireless",
            "airport",
            "802.11",
            "80211",
        )
    )


def _adapter_capabilities(config: Optional[Dict[str, object]] = None) -> Tuple[AdapterCapability, ...]:
    profile = resolve_product_profile(config)
    adapters: List[AdapterCapability] = []
    windows_inventory = _windows_adapter_inventory() if IS_WINDOWS else []

    for _number, name, description in list_interfaces():
        if IS_LINUX:
            driver = _linux_interface_driver(name)
            fingerprint = _linux_interface_fingerprint(name, description)
            phy_name = _linux_interface_phy_name(name)
            monitor_support_advertised = _linux_interface_supports_monitor_mode(name, phy_name)
            entry = _match_hardware_catalog(fingerprint, profile.key)
            if entry:
                reasons = [
                    make_context(
                        "adapter.qualified_family_detected",
                        f"{entry.family} is in the current hardware catalog.",
                        detail=entry.detail,
                    ),
                ]
                if phy_name:
                    reasons.append(
                        make_context(
                            "adapter.phy_detected",
                            f"{name} maps to Linux PHY {phy_name}.",
                        )
                    )
                if monitor_support_advertised is True:
                    reasons.append(
                        make_context(
                            "adapter.monitor_mode_advertised",
                            "iw advertises monitor mode for this adapter.",
                        )
                    )
                elif monitor_support_advertised is False:
                    reasons.append(
                        make_limitation(
                            "adapter.monitor_mode_not_advertised",
                            "iw does not advertise monitor mode for this adapter.",
                            remediation="Use a qualified monitor-mode adapter or verify the current Linux driver and firmware stack.",
                        )
                    )
                adapters.append(
                    AdapterCapability(
                        name=name,
                        description=description,
                        driver=driver,
                        chipset_family=entry.family,
                        phy_name=phy_name,
                        status=entry.status,
                        monitor_mode=entry.monitor_mode,
                        monitor_support_advertised=monitor_support_advertised,
                        injection=entry.injection,
                        channels=entry.channels,
                        capture_methods=_adapter_capture_methods(entry.status),
                        reasons=tuple(reasons),
                    )
                )
                continue

            reasons = []
            if phy_name:
                reasons.append(
                    make_context(
                        "adapter.phy_detected",
                        f"{name} maps to Linux PHY {phy_name}.",
                    )
                )
            if monitor_support_advertised is True:
                reasons.append(
                    make_context(
                        "adapter.monitor_mode_advertised",
                        "iw advertises monitor mode for this adapter.",
                    )
                )
            elif monitor_support_advertised is False:
                reasons.append(
                    make_limitation(
                        "adapter.monitor_mode_not_advertised",
                        "iw does not advertise monitor mode for this adapter.",
                        remediation="Use a monitor-capable Linux adapter or re-check the driver and firmware stack.",
                    )
                )
            reasons.append(
                make_limitation(
                    "adapter.driver_unknown" if not driver else "adapter.family_not_qualified",
                    "The adapter cannot be matched to a qualified hardware family yet.",
                    detail=(
                        "No driver fingerprint was available from sysfs."
                        if not driver
                        else f"Detected driver `{driver}`, but it is not in the qualified adapter catalog."
                    ),
                    remediation="Use the pcap-first path or a qualified Linux USB adapter for the full supported workflow.",
                )
            )
            adapters.append(
                AdapterCapability(
                    name=name,
                    description=description,
                    driver=driver,
                    phy_name=phy_name,
                    status="supported_with_limits" if not driver else "unsupported",
                    monitor_mode=(
                        "advertised by iw"
                        if monitor_support_advertised is True
                        else "not advertised by iw"
                        if monitor_support_advertised is False
                        else "unknown"
                    ),
                    monitor_support_advertised=monitor_support_advertised,
                    injection="unknown",
                    channels="unknown",
                    capture_methods=_adapter_capture_methods("supported_with_limits" if not driver else "unsupported"),
                    reasons=tuple(reasons),
                )
            )
            continue

        if IS_MACOS:
            adapter_description = description.strip()
            wireless_like = _macos_is_wireless_interface(name, adapter_description)
            has_tcpdump = _tool_available("tcpdump")
            has_dumpcap = _tool_available("dumpcap")
            has_airport = _tool_available("airport")
            local_capture_plausible = bool(has_tcpdump or has_dumpcap)
            monitor_capture_plausible = bool(wireless_like and has_tcpdump)
            capture_methods = []
            if local_capture_plausible:
                capture_methods.append("local_capture")
            if monitor_capture_plausible:
                capture_methods.append("monitor_capture")

            reasons = []
            if wireless_like:
                reasons.append(
                    make_context(
                        "adapter.macos_wifi_adapter_detected",
                        "macOS reports a Wi-Fi-capable interface.",
                        detail=adapter_description or name,
                    )
                )
                if has_airport:
                    reasons.append(
                        make_context(
                            "adapter.macos_airport_present",
                            "Apple's airport helper is available for Wi-Fi diagnostics.",
                        )
                    )
                else:
                    reasons.append(
                        make_limitation(
                            "adapter.macos_airport_missing",
                            "Apple's airport helper is not available.",
                            remediation="Keep deeper Wi-Fi diagnostics on the Linux appliance path if you need stronger adapter evidence.",
                        )
                    )
                if local_capture_plausible:
                    reasons.append(
                        make_limitation(
                            "adapter.macos_local_capture_experimental",
                            "macOS local capture is available but remains experimental.",
                            detail="tcpdump or dumpcap is present, but macOS is outside the official capture matrix.",
                            remediation="Prefer Ubuntu or Raspberry Pi OS for the narrow supported capture path.",
                        )
                    )
                else:
                    reasons.append(
                        make_blocker(
                            "adapter.macos_capture_tool_missing",
                            "No local macOS capture backend is available for this adapter.",
                            remediation="Use tcpdump or dumpcap on macOS, or keep capture on the supported Linux appliance path.",
                        )
                    )
                if monitor_capture_plausible:
                    reasons.append(
                        make_limitation(
                            "adapter.macos_monitor_experimental",
                            "macOS monitor-mode attempts remain experimental.",
                            detail="tcpdump -I may work on some Apple hardware, but monitor behavior remains OS- and hardware-dependent.",
                            remediation="Use Linux for the supported monitor-mode workflow.",
                        )
                    )
                else:
                    reasons.append(
                        make_limitation(
                            "adapter.macos_monitor_tool_missing",
                            "No experimental macOS monitor-mode path is available for this adapter.",
                            remediation="Use Linux for monitor-mode capture and Wi-Fi lab work.",
                        )
                    )

            status = "supported_with_limits" if wireless_like and local_capture_plausible else "unsupported" if wireless_like else "unknown"
            adapters.append(
                AdapterCapability(
                    name=name,
                    description=adapter_description,
                    status=status,
                    monitor_mode=(
                        "experimental via tcpdump -I"
                        if monitor_capture_plausible
                        else "blocked without tcpdump monitor support"
                        if wireless_like
                        else "unknown"
                    ),
                    injection="not part of the supported macOS path" if wireless_like else "unknown",
                    channels="adapter dependent" if wireless_like else "unknown",
                    capture_methods=tuple(capture_methods),
                    reasons=tuple(reasons),
                )
            )
            continue

        windows_item = next(
            (item for item in windows_inventory if _windows_matches_adapter_inventory(name, description, item)),
            {},
        )
        adapter_description = str(windows_item.get("interface_description") or description).strip()
        driver_file = str(windows_item.get("driver_file_name") or "").strip()
        driver_description = str(windows_item.get("driver_description") or "").strip()
        driver = driver_file or driver_description
        wireless_like = _windows_is_wireless_adapter(name, adapter_description, driver_description)
        has_dumpcap = _tool_available("dumpcap")
        has_npcap = _tool_available("Npcap")
        has_wlanhelper = _tool_available("WlanHelper")
        local_capture_plausible = bool(has_dumpcap and has_npcap)
        monitor_capture_plausible = bool(local_capture_plausible and wireless_like and has_wlanhelper)
        capture_methods = []
        if local_capture_plausible:
            capture_methods.append("local_capture")
        if monitor_capture_plausible:
            capture_methods.append("monitor_capture")

        reasons = []
        if wireless_like:
            if local_capture_plausible:
                reasons.append(
                    make_limitation(
                        "adapter.windows_local_capture_plausible",
                        "Native Windows Wi-Fi capture looks locally plausible, but it remains experimental.",
                        detail="Npcap and dumpcap are both available for local Windows capture.",
                        remediation="Prefer the Linux appliance path when you need the most predictable Wi-Fi capture behavior.",
                    )
                )
            else:
                if not has_npcap:
                    reasons.append(
                        make_blocker(
                            "adapter.windows_npcap_missing",
                            "Npcap is not detected for this Windows adapter.",
                            remediation="Install Npcap before expecting native Windows packet capture to work.",
                        )
                    )
                if not has_dumpcap:
                    reasons.append(
                        make_blocker(
                            "adapter.windows_dumpcap_missing",
                            "dumpcap is not available for this Windows adapter.",
                            remediation="Install Wireshark/dumpcap before expecting native Windows packet capture to work.",
                        )
                    )
            if monitor_capture_plausible:
                reasons.append(
                    make_limitation(
                        "adapter.windows_monitor_experimental",
                        "WlanHelper is present, so local monitor-mode attempts are possible but still experimental.",
                        remediation="Use the Linux appliance path for the narrow supported monitor-mode workflow.",
                    )
                )
            else:
                reasons.append(
                    make_limitation(
                        "adapter.windows_monitor_helper_missing",
                        "WlanHelper is not available for local monitor-mode helpers.",
                        remediation="Install Npcap with WlanHelper or keep monitor-mode capture on the Linux appliance path.",
                    )
                )
            if driver:
                reasons.append(
                    make_context(
                        "adapter.windows_driver_detected",
                        f"Windows reports driver `{driver}` for this adapter.",
                        detail=driver_description if driver_description and driver_description != driver_file else "",
                    )
                )
            reasons.append(
                make_context(
                    "adapter.windows_wifi_adapter_detected",
                    "Windows reports a Wi-Fi-capable adapter.",
                    detail=adapter_description or description,
                )
            )
        elif driver:
            reasons.append(
                make_context(
                    "adapter.windows_driver_detected",
                    f"Windows reports driver `{driver}` for this adapter.",
                    detail=adapter_description or description,
                )
            )

        status = "supported_with_limits" if wireless_like and local_capture_plausible else "unsupported" if wireless_like else "unknown"
        adapters.append(
            AdapterCapability(
                name=name,
                description=adapter_description or description,
                driver=driver,
                status=status,
                monitor_mode=(
                    "experimental via Npcap/WlanHelper"
                    if monitor_capture_plausible
                    else "local capture only; helper missing"
                    if wireless_like and local_capture_plausible
                    else "blocked without native capture tooling"
                    if wireless_like
                    else "unknown"
                ),
                injection="experimental" if monitor_capture_plausible else "not part of the supported Windows path" if wireless_like else "unknown",
                channels="adapter dependent" if wireless_like else "unknown",
                capture_methods=tuple(capture_methods),
                reasons=tuple(reasons),
            )
        )

    return tuple(adapters)


def _tool_capabilities() -> Tuple[ToolCapability, ...]:
    capabilities: List[ToolCapability] = []
    for name, purpose, required in _platform_tool_specs():
        path = _tool_path(name) or ""
        key = _tool_reason_key(name)
        reasons = []
        if path:
            reasons.append(
                make_context(
                    f"tool.{key}.present",
                    f"{name} is available on PATH.",
                    detail=path,
                )
            )
            status = "available"
        else:
            reason_factory = make_blocker if required else make_limitation
            reasons.append(
                reason_factory(
                    f"tool.{key}.missing_required" if required else f"tool.{key}.missing_optional",
                    f"{name} is not available on PATH.",
                    remediation=f"Install or expose {name} before relying on the workflow that needs it.",
                )
            )
            status = "missing"

        if IS_LINUX and path and name in ("dumpcap", "tcpdump"):
            if _linux_binary_has_capture_capabilities(path):
                reasons.append(
                    make_context(
                        f"tool.{key}.capture_capabilities_present",
                        f"{name} has Linux capture capabilities.",
                        detail="getcap reports cap_net_raw/cap_net_admin on the binary.",
                    )
                )
            elif not is_admin():
                reasons.append(
                    make_limitation(
                        f"tool.{key}.capture_capabilities_missing",
                        f"{name} does not advertise Linux file capabilities.",
                        remediation="Run as root or grant the binary the needed capture capabilities before expecting non-root live capture to work.",
                    )
                )
        capabilities.append(
            ToolCapability(
                name=name,
                purpose=purpose,
                required=required,
                path=path,
                status=status,
                reasons=tuple(reasons),
            )
        )
    return tuple(capabilities)


def _capture_method_capabilities(config: Optional[Dict[str, object]] = None) -> Tuple[CaptureMethodCapability, ...]:
    config = config or {}
    if IS_WINDOWS:
        has_npcap = _tool_available("Npcap")
        has_dumpcap = _tool_available("dumpcap")
        has_wlanhelper = _tool_available("WlanHelper")
        local_tools = tuple(name for name, present in (("Npcap", has_npcap), ("dumpcap", has_dumpcap)) if present)
        monitor_tools = tuple(
            name
            for name, present in (("Npcap", has_npcap), ("dumpcap", has_dumpcap), ("WlanHelper", has_wlanhelper))
            if present
        )
        local_available = has_npcap and has_dumpcap
        monitor_available = has_npcap and has_dumpcap and has_wlanhelper
    elif IS_MACOS:
        has_tcpdump = _tool_available("tcpdump")
        has_dumpcap = _tool_available("dumpcap")
        has_airport = _tool_available("airport")
        has_wireless_adapter = any(_macos_is_wireless_interface(name, description) for _n, name, description in list_interfaces())
        local_tools = tuple(name for name, present in (("tcpdump", has_tcpdump), ("dumpcap", has_dumpcap)) if present)
        monitor_tools = tuple(name for name, present in (("tcpdump", has_tcpdump), ("airport", has_airport)) if present)
        local_available = bool(local_tools)
        monitor_available = bool(has_wireless_adapter and has_tcpdump)
    else:
        local_tools = tuple(
            name for name in ("dumpcap", "tcpdump") if _tool_available(name) and (name != "tcpdump" or not IS_WINDOWS)
        )
        monitor_tools = tuple(name for name in ("WlanHelper", "airmon-ng", "airodump-ng", "tcpdump", "dumpcap") if _tool_available(name))
        local_available = bool(local_tools)
        monitor_available = bool(monitor_tools)
    remote_tools = tuple(name for name in ("ssh", "scp") if _tool_available(name))

    local_support = command_support("capture", config)
    monitor_support = command_support("monitor", config)
    remote_support = command_support("discover-remote", config)
    privilege_mode = _privilege_mode_label()

    local_reasons = []
    if not local_tools:
        local_reasons.append(
            make_blocker(
                "capture.local_tool_missing",
                "No local capture backend is available.",
                detail="Neither dumpcap nor a supported tcpdump path was detected on this machine.",
                remediation="Install Wireshark/dumpcap or tcpdump for the local capture path.",
            )
        )
    if privilege_mode == "user":
        local_reasons.append(
            make_limitation(
                "capture.local_requires_privilege",
                "Local packet capture usually needs elevation.",
                detail="Raw capture often needs Administrator or root privileges depending on the platform.",
                remediation="Run with Administrator rights on Windows or sudo/root on Linux/macOS when capturing live traffic.",
            )
        )
    elif privilege_mode == "capture_capabilities":
        local_reasons.append(
            make_context(
                "capture.local_uses_capabilities",
                "Linux capture binaries appear to have file capabilities.",
                detail="Non-root local capture may work when dumpcap or tcpdump has cap_net_raw/cap_net_admin.",
            )
        )
    if IS_WINDOWS and not _tool_available("Npcap"):
        local_reasons.append(
            make_blocker(
                "capture.windows_npcap_missing",
                "Npcap is not available for native Windows capture.",
                remediation="Install Npcap before expecting local Windows packet capture to work.",
            )
        )
    if IS_MACOS:
        local_reasons.append(
            make_limitation(
                "capture.macos_local_experimental",
                "macOS local capture remains experimental.",
                detail="Packet capture can work through tcpdump or dumpcap, but macOS is outside the official product modes.",
                remediation="Prefer Linux for the narrow supported capture workflow.",
            )
        )
    if local_support.message:
        local_reasons.append(make_context("capture.local_policy", local_support.message))

    monitor_reasons = []
    if not monitor_tools:
        monitor_reasons.append(
            make_blocker(
                "capture.monitor_tool_missing",
                "No monitor-mode toolchain is available.",
                detail="The platform-specific monitor-mode tooling was not found on this machine.",
                remediation="Install the supported monitor-mode tools or use the remote Linux appliance path.",
            )
        )
    if privilege_mode == "user":
        monitor_reasons.append(
            make_limitation(
                "capture.monitor_requires_privilege",
                "Monitor-mode capture requires elevated privileges.",
                detail="Monitor mode and raw 802.11 capture usually need Administrator or root privileges.",
                remediation="Re-run with the appropriate elevated privileges before expecting monitor-mode capture to work.",
            )
        )
    elif privilege_mode == "capture_capabilities":
        monitor_reasons.append(
            make_limitation(
                "capture.monitor_privilege_still_limited",
                "Linux file capabilities do not guarantee full monitor-mode control.",
                detail="Changing interface modes and running the wider monitor/injection toolchain often still needs root or a privileged helper.",
                remediation="Use root on the Linux capture node or keep monitor-mode operations on the supported remote appliance path.",
            )
        )
    if IS_WINDOWS and not _tool_available("Npcap"):
        monitor_reasons.append(
            make_blocker(
                "capture.windows_npcap_missing",
                "Npcap is not available for native Windows monitor attempts.",
                remediation="Install Npcap before expecting local Windows Wi-Fi capture helpers to work.",
            )
        )
    if IS_WINDOWS and not _tool_available("WlanHelper"):
        monitor_reasons.append(
            make_limitation(
                "capture.windows_monitor_helper_missing",
                "WlanHelper is not available for native Windows monitor-mode helpers.",
                remediation="Install Npcap with WlanHelper or keep monitor-mode capture on the Linux appliance path.",
            )
        )
    if IS_MACOS:
        monitor_reasons.append(
            make_limitation(
                "capture.macos_monitor_experimental",
                "macOS monitor-mode capture remains experimental.",
                detail="tcpdump -I may work on some Apple hardware, but the repo does not treat macOS as a supported Wi-Fi lab platform.",
                remediation="Use Ubuntu or Raspberry Pi OS for the supported monitor-mode workflow.",
            )
        )
        if not any(_macos_is_wireless_interface(name, description) for _n, name, description in list_interfaces()):
            monitor_reasons.append(
                make_blocker(
                    "capture.macos_wireless_interface_missing",
                    "No Wi-Fi-capable macOS interface is visible.",
                    remediation="Use a host with a visible Wi-Fi interface or keep monitor-mode work on the Linux appliance path.",
                )
            )
        if not _tool_available("tcpdump"):
            monitor_reasons.append(
                make_blocker(
                    "capture.macos_tcpdump_missing",
                    "tcpdump is not available for experimental macOS monitor-mode attempts.",
                    remediation="Ensure tcpdump is available, or keep monitor-mode work on the supported Linux appliance path.",
                )
            )
    if monitor_support.message:
        monitor_reasons.append(make_context("capture.monitor_policy", monitor_support.message))

    remote_reasons = []
    ssh_available = bool(_tool_available("ssh"))
    scp_available = bool(_tool_available("scp"))
    if not ssh_available:
        remote_reasons.append(
            make_blocker(
                "remote.ssh_missing",
                "SSH is not available locally.",
                detail="The remote appliance path depends on SSH for control and health checks.",
                remediation="Install or expose ssh on PATH before using the remote workflow.",
            )
        )
    if not scp_available:
        remote_reasons.append(
            make_blocker(
                "remote.scp_missing",
                "SCP is not available locally.",
                detail="The remote appliance path depends on SCP for artifact transfer.",
                remediation="Install or expose scp on PATH before using the remote workflow.",
            )
        )
    if remote_support.message:
        remote_reasons.append(make_context("remote.policy", remote_support.message))

    methods = [
        CaptureMethodCapability(
            key="local_capture",
            label="Local packet capture",
            status=_capability_status_from_support(local_support.status, local_available),
            available=local_available,
            requires_privilege=True,
            detail=local_support.message or "Local packet capture is driven by dumpcap or tcpdump availability.",
            tooling=local_tools,
            reasons=tuple(local_reasons),
        ),
        CaptureMethodCapability(
            key="monitor_capture",
            label="Monitor-mode capture",
            status=_capability_status_from_support(monitor_support.status, monitor_available),
            available=monitor_available,
            requires_privilege=True,
            detail=monitor_support.message or "Monitor-mode capture depends on platform-specific radio tooling.",
            tooling=monitor_tools,
            reasons=tuple(monitor_reasons),
        ),
        CaptureMethodCapability(
            key="remote_capture",
            label="Remote Linux appliance capture",
            status=_capability_status_from_support(remote_support.status, bool(remote_tools)),
            available=bool(remote_tools),
            requires_privilege=False,
            detail=remote_support.message or "Remote capture depends on SSH/SCP and a Linux capture node.",
            tooling=remote_tools,
            reasons=tuple(remote_reasons),
        ),
    ]
    return tuple(methods)


def _wpa_capability(config: Optional[Dict[str, object]] = None) -> WPAReadinessCapability:
    config = config or {}
    tooling = tuple(name for name in ("aircrack-ng", "hashcat", "cap2hccapx", "hcxpcapngtool", "airdecap-ng") if _tool_available(name))
    has_wordlist = bool(str(config.get("wordlist_path") or "").strip()) and os.path.exists(str(config.get("wordlist_path")))
    has_crack_tool = _tool_available("aircrack-ng") or (
        _tool_available("hashcat") and (_tool_available("cap2hccapx") or _tool_available("hcxpcapngtool"))
    )
    has_decrypt_tool = _tool_available("airdecap-ng")
    has_essid = bool(str(config.get("ap_essid") or "").strip())
    status = "supported_with_limits" if (has_crack_tool or has_decrypt_tool) else "unsupported"
    reasons = [
        make_context(
            "wpa.readiness_not_evaluated",
            "Handshake or PMKID evidence has not been inspected yet.",
            detail="This capability report only evaluates the local WPA toolchain and configured prerequisites.",
        )
    ]
    detail_parts = ["Handshake/PMKID evidence has not been evaluated yet."]
    if has_crack_tool:
        detail_parts.append("The local crack toolchain is present.")
        reasons.append(make_context("wpa.crack_toolchain_present", "A local crack toolchain is available."))
    else:
        detail_parts.append("The local crack toolchain is missing.")
        reasons.append(
            make_blocker(
                "wpa.crack_toolchain_missing",
                "No supported local crack toolchain is available.",
                remediation="Install aircrack-ng, or install hashcat plus cap2hccapx/hcxpcapngtool.",
            )
        )
    if has_wordlist:
        detail_parts.append("A configured wordlist exists.")
        reasons.append(make_context("wpa.wordlist_present", "A configured wordlist exists."))
    elif str(config.get("wordlist_path") or "").strip():
        detail_parts.append("The configured wordlist path does not exist.")
        reasons.append(
            make_blocker(
                "wpa.wordlist_missing",
                "The configured wordlist path does not exist.",
                remediation="Point wordlist_path at a real file before expecting a supported wordlist attack path.",
            )
        )
    else:
        reasons.append(
            make_blocker(
                "wpa.wordlist_not_configured",
                "No wordlist is configured.",
                remediation="Set wordlist_path before expecting a supported WPA wordlist attack path.",
            )
        )
    if has_decrypt_tool and has_essid:
        detail_parts.append("Decrypt prerequisites look partially ready.")
        reasons.append(make_context("wpa.decrypt_prereqs_present", "Decrypt prerequisites are partially configured."))
    elif has_decrypt_tool:
        detail_parts.append("Set ap_essid before expecting decrypt output.")
        reasons.append(
            make_limitation(
                "wpa.ap_essid_missing",
                "ap_essid is missing for the decrypt step.",
                remediation="Set ap_essid before expecting airdecap-ng output from the decrypt path.",
            )
        )
    else:
        reasons.append(
            make_blocker(
                "wpa.decrypt_tool_missing",
                "airdecap-ng is missing for the decrypt step.",
                remediation="Install airdecap-ng before expecting a supported decrypt path.",
            )
        )

    return WPAReadinessCapability(
        state="not_evaluated",
        status=status,
        crack_ready=bool(has_crack_tool and has_wordlist),
        decrypt_ready=bool(has_decrypt_tool and has_essid),
        detail=" ".join(detail_parts),
        tooling=tooling,
        reasons=tuple(reasons),
    )


def _remote_capability(config: Optional[Dict[str, object]] = None) -> RemoteSupportCapability:
    config = config or {}
    ssh_available = _tool_available("ssh")
    scp_available = _tool_available("scp")
    configured_host = str(config.get("remote_host") or "").strip()
    health_port = config.get("remote_health_port")
    try:
        parsed_health_port = int(health_port) if health_port not in (None, "") else None
    except (TypeError, ValueError):
        parsed_health_port = None

    support = command_support("discover-remote", config)
    status = _capability_status_from_support(support.status, ssh_available and scp_available)
    detail = support.message or "Remote capture depends on SSH/SCP availability and a healthy Linux capture node."
    if configured_host:
        detail += f" Configured host: {configured_host}."
    else:
        detail += " No remote host is configured yet."

    reasons = []
    if not ssh_available:
        reasons.append(
            make_blocker(
                "remote.ssh_missing",
                "SSH is not available locally.",
                remediation="Install or expose ssh on PATH before using the remote appliance workflow.",
            )
        )
    if not scp_available:
        reasons.append(
            make_blocker(
                "remote.scp_missing",
                "SCP is not available locally.",
                remediation="Install or expose scp on PATH before using the remote appliance workflow.",
            )
        )
    if not configured_host:
        reasons.append(
            make_limitation(
                "remote.host_not_configured",
                "No remote host is configured yet.",
                remediation="Run the setup flow or set remote_host before expecting a ready remote capture path.",
            )
        )
    elif parsed_health_port is not None:
        reasons.append(
            make_context(
                "remote.host_configured",
                f"A remote host is configured at {configured_host}.",
                detail=f"Expected health endpoint port: {parsed_health_port}.",
            )
        )

    return RemoteSupportCapability(
        status=status,
        mode="linux_appliance",
        configured_host=configured_host,
        ssh_available=ssh_available,
        scp_available=scp_available,
        health_port=parsed_health_port,
        detail=detail,
        tooling=tuple(name for name in ("ssh", "scp") if _tool_available(name)),
        reasons=tuple(reasons),
    )


def _replay_family_capabilities() -> Tuple[ReplayFamilyCapability, ...]:
    return (
        ReplayFamilyCapability(
            family="structured_text",
            decode_status="supported",
            export_status="supported",
            replay_status="supported",
            detail="Plain text and strongly structured text formats are the most deterministic replay/export path.",
            reasons=(
                make_context(
                    "replay.structured_text_supported",
                    "Structured text is one of the narrowest reliable replay families in the current pipeline.",
                ),
            ),
        ),
        ReplayFamilyCapability(
            family="still_images",
            decode_status="supported",
            export_status="supported",
            replay_status="supported",
            detail="PNG, GIF, BMP, WEBP, and similar strongly signed still-image formats are the narrowest reliable replay path.",
            reasons=(
                make_context(
                    "replay.still_images_supported",
                    "Strongly signed still-image formats are treated as a supported replay family.",
                ),
            ),
        ),
        ReplayFamilyCapability(
            family="audio_video_media",
            decode_status="supported_with_limits",
            export_status="supported_with_limits",
            replay_status="supported_with_limits",
            detail="Audio/video families depend on continuity, framing quality, and correct format hints.",
            reasons=(
                make_limitation(
                    "replay.media_continuity_required",
                    "Audio and video replay depends on stream continuity and framing quality.",
                ),
            ),
        ),
        ReplayFamilyCapability(
            family="archives_documents",
            decode_status="supported_with_limits",
            export_status="supported",
            replay_status="unsupported",
            detail="Archive and document families are better treated as exported artifacts than as replay targets.",
            reasons=(
                make_limitation(
                    "replay.archives_export_only",
                    "Archive and document families should be exported rather than replayed.",
                ),
            ),
        ),
        ReplayFamilyCapability(
            family="opaque_unknown",
            decode_status="heuristic",
            export_status="supported",
            replay_status="unsupported",
            detail="Unknown payloads can be exported as raw artifacts, but meaningful replay is not a supported promise.",
            reasons=(
                make_blocker(
                    "replay.opaque_unknown_unsupported",
                    "Opaque or unknown payloads are not a supported replay family.",
                    remediation="Export the artifact and metadata instead of treating it as a reliable replay target.",
                ),
            ),
        ),
    )


def build_capability_report(config: Optional[Dict[str, object]] = None) -> CapabilityReport:
    return CapabilityReport(
        platform=_current_platform_capability(config),
        privilege_mode=_privilege_mode_label(),
        adapters=_adapter_capabilities(config),
        tools=_tool_capabilities(),
        capture_methods=_capture_method_capabilities(config),
        wpa=_wpa_capability(config),
        remote=_remote_capability(config),
        replay_families=_replay_family_capabilities(),
    )


def _capability_status_text(status: str) -> str:
    if status == "supported":
        return f"{GREEN}{_tier_label(status)}{RESET}"
    if status in ("supported_with_limits", "heuristic", "experimental"):
        label = "experimental" if status == "experimental" else _tier_label(status)
        return f"{YELLOW}{label}{RESET}"
    if status == "unknown":
        return f"{DIM}unknown{RESET}"
    return f"{RED}{_tier_label(status)}{RESET}"


def _workflow_reason_priority(reason: Reason) -> int:
    order = {"blocker": 0, "limitation": 1, "context": 2}
    return order.get(reason.kind, 99)


def _primary_reasons(*groups: Tuple[Reason, ...] | List[Reason], limit: int = 2) -> Tuple[Reason, ...]:
    merged: List[Reason] = []
    seen: set[str] = set()
    for group in groups:
        for reason in group:
            if reason.code in seen:
                continue
            seen.add(reason.code)
            merged.append(reason)
    merged.sort(key=lambda reason: (_workflow_reason_priority(reason), reason.code))
    return tuple(merged[:limit])


def _workflow_tier_from_status(status: str) -> str:
    if status == "supported":
        return "supported"
    if status in ("supported_with_limits", "experimental", "unknown"):
        return "supported_with_limits"
    if status == "heuristic":
        return "heuristic"
    return "unsupported"


def _workflow_tier_text(tier: str) -> str:
    if tier == "supported":
        return f"{GREEN}supported{RESET}"
    if tier in ("supported_with_limits", "heuristic", "experimental"):
        label = "heuristic" if tier == "heuristic" else "limited"
        return f"{YELLOW}{label}{RESET}"
    return f"{RED}blocked{RESET}"


def print_capability_snapshot(report: CapabilityReport) -> None:
    print(f"\n  {BOLD}Capability Snapshot{RESET}")
    print(f"    Platform         : {report.platform.distribution} [{report.platform.product_profile_label}]")
    print(f"    Privilege mode   : {report.privilege_mode}")
    for method in report.capture_methods:
        print(f"    {method.label:<16} {_capability_status_text(method.status)}")
    print(f"    WPA path         : {_capability_status_text(report.wpa.status)} ({report.wpa.state})")
    print(f"    Remote appliance : {_capability_status_text(report.remote.status)}")


def print_capability_hardware(report: CapabilityReport) -> None:
    print(f"\n  {BOLD}Capability-Driven Hardware View{RESET}")
    host_status = "supported" if report.platform.official else "supported_with_limits" if report.platform.os_name == "linux" else "unsupported"
    print(f"    Host             : {_capability_status_text(host_status)}")
    print(f"      {report.platform.distribution} / {report.platform.architecture}")
    print(f"      Profile: {report.platform.product_profile_label}")

    if not report.adapters:
        print(f"    Adapters         : {DIM}none detected{RESET}")
        return

    for adapter in report.adapters:
        label = adapter.name
        if adapter.chipset_family:
            label += f" ({adapter.chipset_family})"
        elif adapter.driver:
            label += f" ({adapter.driver})"
        print(f"    {label:<16} {_capability_status_text(adapter.status)}")
        print(
            "      "
            f"monitor={adapter.monitor_mode}; injection={adapter.injection}; channels={adapter.channels}"
        )
        if adapter.reasons:
            print(f"      {adapter.reasons[0].summary}")


def command_support(
    command: str,
    config: Optional[Dict[str, object]] = None,
    *,
    has_input_pcap: bool = False,
) -> CommandSupport:
    profile = resolve_product_profile(config)

    analysis_commands = {"config", "deps", "hardware", "preflight", "release-gate", "crack-status", "extract", "detect", "analyze", "play", "corpus", "web", "menu"}
    remote_commands = {"remote", "discover-remote", "pair-remote", "bootstrap-remote", "start-remote", "remote-service", "validate-remote", "setup-remote"}
    local_validation_commands = {"validate-local"}
    local_capture_commands = {"capture"}
    local_wifi_commands = {"monitor", "crack", "wifi"}

    if command == "all" and has_input_pcap:
        command = "extract"

    if command == "doctor":
        if profile.official:
            return CommandSupport(command, profile, "official", "")
        if profile.key == "linux_best_effort":
            return CommandSupport(command, profile, "best_effort", "Doctor runs outside the official support matrix on this Linux distro.")
        return CommandSupport(command, profile, "experimental", "Doctor remains available, but this platform is not part of an official product mode.")

    if command in analysis_commands:
        if profile.key == "macos_experimental":
            return CommandSupport(command, profile, "experimental", "macOS remains experimental, so analysis commands run in experimental mode here.")
        if profile.key == "linux_best_effort":
            return CommandSupport(command, profile, "best_effort", "This Linux distro is outside the official support matrix, so analysis runs in best-effort mode.")
        return CommandSupport(command, profile, "official", "")

    if command in remote_commands:
        if profile.key == "windows_remote":
            return CommandSupport(command, profile, "official", "")
        if profile.key in ("ubuntu_standalone", "pi_standalone", "linux_best_effort"):
            return CommandSupport(command, profile, "best_effort", "Remote-controller commands remain available on Linux, but the official Linux modes are standalone.")
        return CommandSupport(command, profile, "experimental", "Remote-controller commands are not part of the official macOS/experimental workflow.")

    if command in local_validation_commands:
        if profile.key in ("ubuntu_standalone", "pi_standalone"):
            return CommandSupport(command, profile, "official", "")
        if profile.key == "linux_best_effort":
            return CommandSupport(command, profile, "best_effort", "Standalone validation runs outside the official support matrix on this Linux distro.")
        if profile.key == "windows_remote":
            experimental = PRODUCT_PROFILES["windows_experimental_local"]
            return CommandSupport(command, experimental, "experimental", "Standalone local validation is experimental on Windows because native capture is not an official Windows mode.")
        return CommandSupport(command, profile, "experimental", "Standalone local validation is not part of an official product mode on this platform.")

    if command in local_capture_commands or (command == "all" and not has_input_pcap):
        if profile.key in ("ubuntu_standalone", "pi_standalone"):
            return CommandSupport(command, profile, "official", "")
        if profile.key == "linux_best_effort":
            return CommandSupport(command, profile, "best_effort", "Local capture is available, but this Linux distro is outside the official support matrix.")
        if profile.key == "windows_remote":
            experimental = PRODUCT_PROFILES["windows_experimental_local"]
            return CommandSupport(command, experimental, "experimental", "Local capture on Windows is available only through the experimental local-capture profile.")
        return CommandSupport(command, profile, "experimental", "Local capture is not an official product mode on this platform.")

    if command in local_wifi_commands:
        if profile.key in ("ubuntu_standalone", "pi_standalone"):
            return CommandSupport(command, profile, "official", "")
        if profile.key == "linux_best_effort":
            return CommandSupport(command, profile, "best_effort", "Local monitor-mode and Wi-Fi lab commands are available, but this distro is outside the official support matrix.")
        if profile.key == "windows_remote":
            experimental = PRODUCT_PROFILES["windows_experimental_local"]
            return CommandSupport(command, experimental, "experimental", "Native Windows monitor-mode and Wi-Fi lab commands remain experimental.")
        return CommandSupport(command, profile, "experimental", "Monitor-mode and Wi-Fi lab commands are not part of an official product mode on this platform.")

    return CommandSupport(command, profile, "official", "")


def workflow_support_matrix(config: Optional[Dict[str, object]] = None) -> List[WorkflowSupport]:
    report = build_capability_report(config)
    capture_methods = {method.key: method for method in report.capture_methods}

    analysis_reasons = (
        (
            make_context(
                "workflow.analysis_profile_official",
                f"{report.platform.product_profile_label} is in the official support matrix for analysis.",
            ),
        )
        if report.platform.official
        else (
            make_limitation(
                "workflow.analysis_profile_limited",
                f"{report.platform.product_profile_label} remains outside the narrow official support matrix.",
                remediation="Keep expectations conservative and prefer the official Linux or Windows+Linux appliance paths when you need the most predictable workflow.",
            ),
        )
    )

    local_capture = capture_methods["local_capture"]
    monitor_capture = capture_methods["monitor_capture"]
    remote_capture = capture_methods["remote_capture"]

    decode_reasons = _primary_reasons(
        tuple(reason for family in report.replay_families for reason in family.reasons if family.decode_status != "supported")
    )
    replay_reasons = _primary_reasons(
        tuple(reason for family in report.replay_families for reason in family.reasons if family.replay_status != "supported")
    )

    replay_statuses = {family.replay_status for family in report.replay_families}
    if "heuristic" in replay_statuses:
        replay_tier = "heuristic"
    elif "unsupported" in replay_statuses and any(status in ("supported", "supported_with_limits") for status in replay_statuses):
        replay_tier = "heuristic"
    elif "supported_with_limits" in replay_statuses:
        replay_tier = "supported_with_limits"
    elif replay_statuses == {"supported"}:
        replay_tier = "supported"
    else:
        replay_tier = "unsupported"

    rows = [
        WorkflowSupport(
            area="pcap import + analysis",
            tier="supported" if report.platform.official else "supported_with_limits",
            summary="Import an existing pcap and run the analysis pipeline.",
            detail=(
                "Importing a pcap and running extract/detect/analyze is a first-class workflow here."
                if report.platform.official
                else f"Analysis remains available here, but {report.platform.product_profile_label} stays outside the narrow official product matrix."
            ),
            reasons=analysis_reasons,
        ),
        WorkflowSupport(
            area="local packet capture",
            tier=_workflow_tier_from_status(local_capture.status),
            summary="Capture a pcap on the current machine.",
            detail=local_capture.detail,
            reasons=_primary_reasons(local_capture.reasons),
        ),
        WorkflowSupport(
            area="monitor mode + Wi-Fi lab capture",
            tier=_workflow_tier_from_status(monitor_capture.status),
            summary="Run monitor-mode capture, handshake collection, and other Wi-Fi lab steps.",
            detail=monitor_capture.detail,
            reasons=_primary_reasons(
                monitor_capture.reasons,
                tuple(reason for adapter in report.adapters for reason in adapter.reasons if "monitor_capture" in adapter.capture_methods),
            ),
        ),
        WorkflowSupport(
            area="remote capture control",
            tier=_workflow_tier_from_status(remote_capture.status),
            summary="Control a remote capture appliance and pull capture artifacts back.",
            detail=report.remote.detail,
            reasons=_primary_reasons(report.remote.reasons),
        ),
        WorkflowSupport(
            area="WPA cracking + Wi-Fi decrypt",
            tier=_workflow_tier_from_status(report.wpa.status),
            summary="Turn a usable handshake capture into decrypted packet data.",
            detail=report.wpa.detail,
            reasons=_primary_reasons(report.wpa.reasons),
        ),
        WorkflowSupport(
            area="payload decoding",
            tier="heuristic" if any(family.decode_status == "heuristic" for family in report.replay_families) else "supported_with_limits",
            summary="Infer promising payload candidates from extracted traffic.",
            detail="Decoding confidence depends on whether the extracted stream matches a known payload family with enough structure and continuity.",
            reasons=decode_reasons,
        ),
        WorkflowSupport(
            area="replay + reconstruction",
            tier=replay_tier,
            summary="Attempt to reconstruct or replay candidate output from the analysis results.",
            detail="Replay is strongest for known families and clean stream material; opaque or weak candidates still fall back to raw artifact export.",
            reasons=replay_reasons,
        ),
    ]

    return sorted(rows, key=lambda row: (_tier_sort_key(row.tier), row.area))


def _host_hardware_qualification(profile: ProductProfile, config: Optional[Dict[str, object]] = None) -> HardwareQualification:
    config = config or {}
    arch = _machine_architecture()
    remote_host = str(config.get("remote_host") or "").strip()

    if profile.key == "windows_remote":
        return HardwareQualification(
            area="host",
            label=f"Windows controller host ({arch})",
            status="supported",
            summary="Qualified controller/analyzer host for the official Windows workflow.",
            detail="Keep packet capture on an Ubuntu or Raspberry Pi OS capture node; this Windows machine is the supported control and analysis side.",
            monitor_mode="handled by Linux capture node",
            injection="handled by Linux capture node",
            channels="depends on remote node",
        )

    if profile.key == "ubuntu_standalone":
        return HardwareQualification(
            area="host",
            label=f"Ubuntu standalone host ({arch})",
            status="supported",
            summary="Qualified full local host for the supported Ubuntu standalone workflow.",
            detail="Ubuntu is the primary standalone Linux target and can also double as a Windows capture node when needed.",
            monitor_mode="supported with a qualified adapter",
            injection="qualified adapters only",
            channels="adapter dependent",
        )

    if profile.key == "pi_standalone":
        model = _linux_machine_model() or "Raspberry Pi"
        return HardwareQualification(
            area="host",
            label=f"{model} host",
            status="supported",
            summary="Qualified compact/appliance host for the supported Raspberry Pi OS workflow.",
            detail="Raspberry Pi OS is an official target, but the full Wi-Fi lab path still expects a qualified USB capture adapter rather than the typical onboard Broadcom radio.",
            monitor_mode="supported with a qualified USB adapter",
            injection="qualified USB adapters only",
            channels="adapter dependent",
        )

    if profile.key == "linux_best_effort":
        distro = linux_distribution_label() or f"Linux ({arch})"
        return HardwareQualification(
            area="host",
            label=distro,
            status="supported_with_limits",
            summary="This Linux host can often run the pipeline, but the distro is outside the official matrix.",
            detail="Ubuntu and Raspberry Pi OS are the only Linux targets we qualify end to end. Other distros stay best effort even with the right adapter.",
            monitor_mode="toolchain dependent",
            injection="adapter dependent",
            channels="adapter dependent",
        )

    return HardwareQualification(
        area="host",
        label=f"macOS host ({arch})" if IS_MACOS else f"Unsupported host ({arch})",
        status="unsupported",
        summary="This host platform is outside the supported hardware program.",
        detail="Stay on Ubuntu standalone, Raspberry Pi OS standalone, or Windows paired with a Linux capture node for the narrow supported path.",
        monitor_mode="experimental",
        injection="experimental",
        channels="adapter dependent",
    )


def _windows_hardware_rows(config: Optional[Dict[str, object]] = None) -> List[HardwareQualification]:
    config = config or {}
    remote_host = str(config.get("remote_host") or "").strip()
    remote_profile = str(config.get("remote_install_profile") or "appliance")
    remote_status = "supported" if remote_host else "supported_with_limits"
    remote_detail = (
        f"Configured capture node: {remote_host}. Keep using the appliance profile for the most predictable Windows experience."
        if remote_host
        else "Run .\\setup_remote.ps1 or bootstrap-remote against an Ubuntu or Raspberry Pi OS node; that is the supported Windows capture path."
    )
    rows = [
        HardwareQualification(
            area="capture_node",
            label="Ubuntu or Raspberry Pi OS capture node",
            status=remote_status,
            summary="The supported capture-node targets are Ubuntu standalone, Raspberry Pi OS standalone, or an appliance-profile remote node.",
            detail=remote_detail,
            monitor_mode="qualified on the Linux node with a supported adapter",
            injection="qualified Linux USB adapters only",
            channels="depends on node radio",
        ),
        HardwareQualification(
            area="local_radio",
            label="Native Windows 802.11 adapter",
            status="unsupported",
            summary="No native Windows adapter family is part of the official hardware program.",
            detail="Even when NPcap and WlanHelper see the adapter, monitor and injection behavior stay driver dependent. Treat local Windows Wi-Fi capture as experimental only.",
            monitor_mode="experimental",
            injection="experimental",
            channels="adapter dependent",
        ),
    ]
    if remote_profile == "appliance":
        rows[0] = HardwareQualification(
            area=rows[0].area,
            label=rows[0].label,
            status=rows[0].status,
            summary=rows[0].summary,
            detail=rows[0].detail,
            monitor_mode=rows[0].monitor_mode,
            injection=rows[0].injection,
            channels=f"{rows[0].channels}; appliance profile preferred",
        )
    return rows


def _linux_hardware_rows(config: Optional[Dict[str, object]] = None) -> List[HardwareQualification]:
    config = config or {}
    profile = resolve_product_profile(config)
    requested = str(config.get("interface") or "").strip()
    seen: set[str] = set()
    interface_rows: List[HardwareQualification] = []

    candidates = list_interfaces()
    if requested and not any(name == requested for _number, name, _description in candidates):
        candidates = [("0", requested, "configured capture interface")] + candidates

    for _number, name, description in candidates:
        if name in seen:
            continue
        seen.add(name)
        driver = _linux_interface_driver(name)
        fingerprint = _linux_interface_fingerprint(name, description)
        entry = _match_hardware_catalog(fingerprint, profile.key)

        if entry:
            interface_rows.append(
                HardwareQualification(
                    area="capture_adapter",
                    label=f"{name} ({entry.family})",
                    status=entry.status,
                    summary=f"Driver `{driver or 'unknown'}` maps to the {entry.family} capture family.",
                    detail=entry.detail,
                    monitor_mode=entry.monitor_mode,
                    injection=entry.injection,
                    channels=entry.channels,
                )
            )
            continue

        if driver:
            interface_rows.append(
                HardwareQualification(
                    area="capture_adapter",
                    label=f"{name} ({driver})",
                    status="unsupported",
                    summary="This adapter family is not in the narrow qualified hardware list yet.",
                    detail="It may still work for pcap-first or best-effort capture, but the full supported Wi-Fi lab path is only qualified for the documented Linux adapter families.",
                    monitor_mode="unknown",
                    injection="unknown",
                    channels="unknown",
                )
            )
        else:
            interface_rows.append(
                HardwareQualification(
                    area="capture_adapter",
                    label=name,
                    status="supported_with_limits",
                    summary="Wireless interface detected, but the driver family could not be fingerprinted from sysfs.",
                    detail="Re-run on Linux with a configured interface if you want adapter qualification, or use the pcap-first flow until the adapter family is known.",
                    monitor_mode="unknown",
                    injection="unknown",
                    channels="unknown",
                )
            )

    if interface_rows:
        return interface_rows

    return [
        HardwareQualification(
            area="capture_adapter",
            label="No wireless interface detected",
            status="unsupported" if profile.key in ("ubuntu_standalone", "pi_standalone") else "supported_with_limits",
            summary="The host is present, but no local wireless capture adapter was detected.",
            detail="Standalone Linux needs a detectable wireless adapter for live capture. You can still use the pcap-first flow without one.",
            monitor_mode="missing",
            injection="missing",
            channels="missing",
        )
    ]


def hardware_qualification_report(config: Optional[Dict[str, object]] = None) -> List[HardwareQualification]:
    profile = resolve_product_profile(config)
    rows = [_host_hardware_qualification(profile, config)]
    if profile.key == "windows_remote":
        rows.extend(_windows_hardware_rows(config))
    elif IS_LINUX:
        rows.extend(_linux_hardware_rows(config))
    else:
        rows.append(
            HardwareQualification(
                area="capture_adapter",
                label="Local wireless adapter",
                status="unsupported",
                summary="This platform is outside the supported local capture hardware program.",
                detail="Use Ubuntu or Raspberry Pi OS for the capture side, or keep this machine in controller/analyzer mode only.",
                monitor_mode="experimental",
                injection="experimental",
                channels="adapter dependent",
            )
        )
    return sorted(rows, key=lambda row: (_tier_sort_key(row.status), row.area, row.label))


def print_hardware_qualification(config: Optional[Dict[str, object]] = None) -> List[HardwareQualification]:
    rows = hardware_qualification_report(config)
    print(f"\n  {BOLD}Hardware Qualification{RESET}")
    for row in rows:
        if row.status == "supported":
            status_text = f"{GREEN}{_tier_label(row.status)}{RESET}"
        elif row.status == "supported_with_limits":
            status_text = f"{YELLOW}{_tier_label(row.status)}{RESET}"
        else:
            status_text = f"{RED}{_tier_label(row.status)}{RESET}"
        print(f"    {row.label:<34} {status_text}")
        print(f"      {row.summary}")
        print(f"      {row.detail}")
        print(
            "      "
            f"monitor={row.monitor_mode}; injection={row.injection}; channels={row.channels}"
        )
    return rows


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    # Linux / macOS: check for root
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    return geteuid() == 0


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


def check_environment(config: Optional[Dict[str, object]] = None) -> bool:
    section("Environment Check")
    profile = resolve_product_profile(config)
    capability_report = build_capability_report(config)

    if IS_WINDOWS:
        platform_tools = WINDOWS_TOOLS
    elif IS_MACOS:
        platform_tools = MACOS_TOOLS
    else:
        platform_tools = LINUX_TOOLS
    all_required = True

    ok(f"Python runtime: {sys.executable} ({sys.version.split()[0]})")
    info(f"Active product profile: {capability_report.platform.product_profile_label}")

    for name, purpose, required in platform_tools:
        path = _tool_path(name)
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

    if capability_report.privilege_mode == "user":
        if IS_WINDOWS:
            warn("Administrator rights are recommended for capture and interface discovery.")
        else:
            warn("Root (sudo) is required for monitor mode and raw socket capture on Linux/macOS.")

    if IS_WINDOWS:
        info("Official Windows mode: controller/analyzer on Windows 10/11 with Ubuntu or Raspberry Pi OS handling remote capture.")
        info("Ubuntu standalone and Raspberry Pi OS standalone are the Linux-first supported product modes.")
        warn("Native Windows monitor-mode and Wi-Fi lab capture remain experimental and adapter-dependent.")
        warn("Unsupported as a guaranteed product path: adapter-independent Windows 802.11 monitor/injection parity with Linux.")
    elif IS_LINUX:
        distro_label = linux_distribution_label()
        if distro_label:
            info(f"Detected Linux target: {distro_label}")
        info("Official Linux modes: Ubuntu standalone and Raspberry Pi OS standalone.")
        info("The same Linux toolchain can also act as the remote capture side for Windows controller runs.")
        warn("Other Linux distributions may work, but Ubuntu and Raspberry Pi OS are the only officially supported Linux targets.")
        warn("Raw capture still requires root or capture capabilities even on the supported Linux path.")
    elif IS_MACOS:
        info("macOS support remains experimental; the official product modes are Ubuntu standalone, Raspberry Pi OS standalone, or Windows with Linux remote capture.")
        warn("macOS is not an officially supported standalone or capture-appliance target.")

    print_capability_snapshot(capability_report)

    print(f"\n  {BOLD}Workflow Tiers{RESET}")
    for row in workflow_support_matrix(config):
        print(f"    {row.area:<30} {_workflow_tier_text(row.tier)}")
        print(f"      {row.summary}")
        print(f"      {row.detail}")
        for reason in row.reasons:
            print(f"      reason: {reason.summary}")

    print_capability_hardware(capability_report)

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
