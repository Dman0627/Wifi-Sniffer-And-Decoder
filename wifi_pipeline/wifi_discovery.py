from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from typing import Dict, Iterable, List, Optional, Sequence


AUTO_TARGET_VALUE = "__auto__"
MANUAL_TARGET_VALUE = "__manual__"

_BSSID_RE = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
_SCAN_CACHE: Dict[str, object] = {"key": None, "expires_at": 0.0, "targets": []}


def _run_command(command: Sequence[str], *, timeout: float) -> str:
    try:
        result = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return ""
    return "\n".join(part for part in (result.stdout, result.stderr) if part).strip()


def _normalize_bssid(value: object) -> str:
    text = str(value or "").strip().lower().replace("-", ":")
    match = _BSSID_RE.search(text)
    return match.group(0).lower() if match else text


def _coerce_int(value: object) -> Optional[int]:
    text = str(value or "").strip()
    if not text:
        return None
    match = re.search(r"-?\d+", text)
    if not match:
        return None
    try:
        return int(match.group(0))
    except ValueError:
        return None


def _dbm_to_quality(value: object) -> Optional[int]:
    dbm = _coerce_int(value)
    if dbm is None:
        return None
    if dbm >= 0:
        return max(0, min(100, dbm))
    # A practical UI quality estimate: -30 dBm is excellent, -90 dBm is weak.
    return max(0, min(100, int((dbm + 90) * 100 / 60)))


def _channel_from_frequency(freq: object) -> Optional[int]:
    mhz = _coerce_int(freq)
    if mhz is None:
        return None
    if 2412 <= mhz <= 2484:
        if mhz == 2484:
            return 14
        return int((mhz - 2407) / 5)
    if 5000 <= mhz <= 5900:
        return int((mhz - 5000) / 5)
    if 5955 <= mhz <= 7115:
        return int((mhz - 5950) / 5)
    return None


def _security_label(*parts: object) -> str:
    seen: List[str] = []
    for part in parts:
        text = str(part or "").strip()
        if not text or text in ("--", "None"):
            continue
        if text.lower() not in {item.lower() for item in seen}:
            seen.append(text)
    return " / ".join(seen) if seen else "unknown"


def _target_record(
    *,
    ssid: object = "",
    bssid: object = "",
    channel: object = None,
    signal: object = None,
    security: object = "",
    source: str,
    connected: bool = False,
) -> Dict[str, object]:
    signal_value = _coerce_int(signal)
    signal_text = str(signal or "").strip()
    if signal_value is not None and "%" in signal_text:
        signal_label = f"{signal_value}%"
    elif signal_value is not None and "dbm" in signal_text.lower():
        signal_label = f"{signal_value} dBm"
    elif signal_text:
        signal_label = signal_text
    else:
        signal_label = ""

    if signal_value is not None and signal_value < 0:
        quality = _dbm_to_quality(signal_value)
    else:
        quality = max(0, min(100, signal_value)) if signal_value is not None else None

    channel_value = _coerce_int(channel)
    return {
        "ssid": str(ssid or "").strip(),
        "bssid": _normalize_bssid(bssid),
        "channel": channel_value if channel_value is not None else "",
        "signal": quality if quality is not None else "",
        "signal_label": signal_label,
        "security": str(security or "").strip() or "unknown",
        "source": source,
        "connected": connected,
    }


def _merge_targets(targets: Iterable[Dict[str, object]]) -> List[Dict[str, object]]:
    merged: Dict[tuple[str, str, str], Dict[str, object]] = {}
    for raw in targets:
        target = dict(raw)
        ssid = str(target.get("ssid") or "").strip()
        bssid = _normalize_bssid(target.get("bssid"))
        channel = str(target.get("channel") or "").strip()
        if not ssid and not bssid:
            continue
        key = (ssid.lower(), bssid, channel)
        current = merged.get(key)
        if current is None:
            merged[key] = target
            continue
        current_signal = _coerce_int(current.get("signal")) or -1
        target_signal = _coerce_int(target.get("signal")) or -1
        if bool(target.get("connected")) or target_signal > current_signal:
            target["connected"] = bool(target.get("connected") or current.get("connected"))
            merged[key] = target
        elif current.get("connected"):
            current["connected"] = True

    def sort_key(item: Dict[str, object]) -> tuple[int, int, str]:
        signal = _coerce_int(item.get("signal"))
        return (
            1 if bool(item.get("connected")) else 0,
            signal if signal is not None else -1,
            str(item.get("ssid") or "").lower(),
        )

    return sorted(merged.values(), key=sort_key, reverse=True)


def parse_windows_netsh_networks(output: str) -> List[Dict[str, object]]:
    targets: List[Dict[str, object]] = []
    current_ssid = ""
    authentication = ""
    encryption = ""
    current_target: Optional[Dict[str, object]] = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        ssid_match = re.match(r"SSID\s+\d+\s*:\s*(.*)$", line, re.IGNORECASE)
        if ssid_match:
            current_ssid = ssid_match.group(1).strip()
            authentication = ""
            encryption = ""
            current_target = None
            continue
        if ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        key_lower = key.lower()
        if key_lower == "authentication":
            authentication = value
        elif key_lower == "encryption":
            encryption = value
        elif key_lower.startswith("bssid"):
            current_target = _target_record(
                ssid=current_ssid,
                bssid=value,
                security=_security_label(authentication, encryption),
                source="netsh",
            )
            targets.append(current_target)
        elif current_target is not None and key_lower == "signal":
            current_target["signal"] = _coerce_int(value) or ""
            current_target["signal_label"] = value
        elif current_target is not None and key_lower == "channel":
            current_target["channel"] = _coerce_int(value) or ""

    return _merge_targets(targets)


def parse_windows_wlan_interfaces(output: str) -> List[Dict[str, object]]:
    targets: List[Dict[str, object]] = []
    fields: Dict[str, str] = {}

    def flush() -> None:
        if fields.get("state", "").lower() != "connected":
            return
        if not fields.get("ssid") and not fields.get("bssid"):
            return
        targets.append(
            _target_record(
                ssid=fields.get("ssid", ""),
                bssid=fields.get("bssid", ""),
                channel=fields.get("channel", ""),
                signal=fields.get("signal", ""),
                security=_security_label(fields.get("authentication"), fields.get("cipher")),
                source="netsh-connected",
                connected=True,
            )
        )

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.lower().startswith("name") and fields:
            flush()
            fields = {}
        if ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        key_lower = key.lower()
        if key_lower in {"state", "ssid", "bssid", "channel", "signal", "authentication", "cipher"}:
            if key_lower == "ssid" and "bssid" in fields:
                continue
            fields[key_lower] = value
    flush()
    return _merge_targets(targets)


def _split_nmcli_fields(line: str) -> List[str]:
    fields: List[str] = []
    buffer: List[str] = []
    escaped = False
    for char in line.rstrip("\n"):
        if escaped:
            buffer.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(buffer))
            buffer = []
        else:
            buffer.append(char)
    if escaped:
        buffer.append("\\")
    fields.append("".join(buffer))
    return fields


def parse_nmcli_wifi_list(output: str) -> List[Dict[str, object]]:
    targets: List[Dict[str, object]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        fields = _split_nmcli_fields(line)
        if len(fields) >= 6 and fields[0].lower() in {"yes", "no"}:
            active, ssid, bssid, channel, signal, security = fields[:6]
            connected = active.lower() == "yes"
        elif len(fields) >= 5:
            ssid, bssid, channel, signal, security = fields[:5]
            connected = False
        else:
            continue
        targets.append(
            _target_record(
                ssid="" if ssid == "--" else ssid,
                bssid=bssid,
                channel=channel,
                signal=f"{signal}%" if str(signal).strip().isdigit() else signal,
                security=security,
                source="nmcli",
                connected=connected,
            )
        )
    return _merge_targets(targets)


def parse_iw_scan(output: str) -> List[Dict[str, object]]:
    targets: List[Dict[str, object]] = []
    current: Dict[str, object] = {}

    def flush() -> None:
        nonlocal current
        if current:
            if not current.get("channel") and current.get("freq"):
                current["channel"] = _channel_from_frequency(current.get("freq")) or ""
            security = "unknown"
            if current.get("rsn"):
                security = "WPA2/WPA3"
            elif current.get("wpa"):
                security = "WPA"
            elif current.get("privacy"):
                security = "secured"
            targets.append(
                _target_record(
                    ssid=current.get("ssid", ""),
                    bssid=current.get("bssid", ""),
                    channel=current.get("channel", ""),
                    signal=current.get("signal", ""),
                    security=security,
                    source="iw",
                )
            )
        current = {}

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("BSS "):
            flush()
            match = _BSSID_RE.search(line)
            current = {"bssid": match.group(0) if match else ""}
            continue
        if not current or ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        key_lower = key.lower()
        if key_lower == "ssid":
            current["ssid"] = value
        elif key_lower == "freq":
            current["freq"] = value
        elif key_lower == "signal":
            current["signal"] = value
        elif key_lower == "ds parameter set":
            current["channel"] = value.replace("channel", "").strip()
        elif key_lower == "rsn":
            current["rsn"] = True
        elif key_lower == "wpa":
            current["wpa"] = True
        elif key_lower == "capability" and "privacy" in value.lower():
            current["privacy"] = True
    flush()
    return _merge_targets(targets)


def parse_iw_link(output: str) -> List[Dict[str, object]]:
    fields: Dict[str, object] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.lower().startswith("connected to "):
            match = _BSSID_RE.search(line)
            if match:
                fields["bssid"] = match.group(0)
        elif line.lower().startswith("ssid:"):
            fields["ssid"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("freq:"):
            fields["channel"] = _channel_from_frequency(line.split(":", 1)[1].strip()) or ""
        elif line.lower().startswith("signal:"):
            fields["signal"] = line.split(":", 1)[1].strip()
    if not fields:
        return []
    return [
        _target_record(
            ssid=fields.get("ssid", ""),
            bssid=fields.get("bssid", ""),
            channel=fields.get("channel", ""),
            signal=fields.get("signal", ""),
            security="unknown",
            source="iw-connected",
            connected=True,
        )
    ]


def parse_airport_scan(output: str) -> List[Dict[str, object]]:
    targets: List[Dict[str, object]] = []
    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or " BSSID " in line:
            continue
        match = re.match(
            r"\s*(?P<ssid>.*?)\s+(?P<bssid>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+"
            r"(?P<rssi>-?\d+)\s+(?P<channel>[0-9,+-]+)\s+.*?\s+(?P<security>\S.*)$",
            line,
        )
        if not match:
            continue
        targets.append(
            _target_record(
                ssid=match.group("ssid"),
                bssid=match.group("bssid"),
                channel=match.group("channel").split(",", 1)[0],
                signal=f"{match.group('rssi')} dBm",
                security=match.group("security"),
                source="airport",
            )
        )
    return _merge_targets(targets)


def parse_airport_info(output: str) -> List[Dict[str, object]]:
    fields: Dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        key_lower = key.lower()
        if key_lower in {"ssid", "bssid", "channel", "agrctlrssi", "link auth"}:
            fields[key_lower] = value
    if not fields:
        return []
    return [
        _target_record(
            ssid=fields.get("ssid", ""),
            bssid=fields.get("bssid", ""),
            channel=fields.get("channel", "").split(",", 1)[0],
            signal=f"{fields.get('agrctlrssi')} dBm" if fields.get("agrctlrssi") else "",
            security=fields.get("link auth", "unknown"),
            source="airport-connected",
            connected=True,
        )
    ]


def _linux_iw_interfaces(timeout: float) -> List[str]:
    iw = shutil.which("iw")
    if not iw:
        return []
    output = _run_command([iw, "dev"], timeout=timeout)
    names: List[str] = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            names.append(line.split()[1])
    return names


def _airport_path() -> Optional[str]:
    found = shutil.which("airport")
    if found:
        return found
    candidate = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    return candidate if os.path.exists(candidate) else None


def _discover_uncached(interface: str, timeout: float) -> List[Dict[str, object]]:
    targets: List[Dict[str, object]] = []
    if sys.platform.startswith("win"):
        targets.extend(parse_windows_wlan_interfaces(_run_command(["netsh", "wlan", "show", "interfaces"], timeout=timeout)))
        targets.extend(parse_windows_netsh_networks(_run_command(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=timeout)))
    elif sys.platform.startswith("linux"):
        nmcli = shutil.which("nmcli")
        if nmcli:
            command = [nmcli, "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list"]
            if interface:
                command.extend(["ifname", interface])
            targets.extend(parse_nmcli_wifi_list(_run_command(command, timeout=timeout)))
        iw = shutil.which("iw")
        if iw and (not targets or not any(target.get("connected") for target in targets)):
            interfaces = [interface] if interface else _linux_iw_interfaces(timeout)
            for name in interfaces[:3]:
                if not name:
                    continue
                targets.extend(parse_iw_link(_run_command([iw, "dev", name, "link"], timeout=timeout)))
                targets.extend(parse_iw_scan(_run_command([iw, "dev", name, "scan"], timeout=timeout)))
    elif sys.platform == "darwin":
        airport = _airport_path()
        if airport:
            targets.extend(parse_airport_info(_run_command([airport, "-I"], timeout=timeout)))
            targets.extend(parse_airport_scan(_run_command([airport, "-s"], timeout=timeout)))
    return _merge_targets(targets)


def discover_wifi_targets(
    interface: str = "",
    *,
    timeout: float = 1.5,
    ttl_seconds: float = 20.0,
    force: bool = False,
) -> List[Dict[str, object]]:
    """Best-effort nearby AP discovery. Returns [] on unsupported hosts or scan failures."""
    key = f"{sys.platform}:{interface.strip()}"
    now = time.monotonic()
    if not force and _SCAN_CACHE.get("key") == key and float(_SCAN_CACHE.get("expires_at") or 0.0) > now:
        return [dict(item) for item in _SCAN_CACHE.get("targets", []) if isinstance(item, dict)]

    targets = _discover_uncached(interface.strip(), timeout)
    _SCAN_CACHE["key"] = key
    _SCAN_CACHE["expires_at"] = now + max(0.0, ttl_seconds)
    _SCAN_CACHE["targets"] = [dict(item) for item in targets]
    return targets


def select_preferred_wifi_target(
    targets: Iterable[Dict[str, object]],
    *,
    configured_essid: str = "",
    configured_bssid: str = "",
) -> Optional[Dict[str, object]]:
    candidates = _merge_targets(targets)
    if not candidates:
        return None

    bssid = _normalize_bssid(configured_bssid)
    if bssid:
        for target in candidates:
            if _normalize_bssid(target.get("bssid")) == bssid:
                return dict(target)

    essid = configured_essid.strip().lower()
    if essid:
        matching = [target for target in candidates if str(target.get("ssid") or "").strip().lower() == essid]
        if matching:
            return dict(matching[0])

    connected = [target for target in candidates if bool(target.get("connected"))]
    if connected:
        return dict(connected[0])

    secured = [
        target
        for target in candidates
        if str(target.get("ssid") or "").strip()
        and str(target.get("security") or "").strip().lower() not in {"", "open", "none", "unknown"}
    ]
    if secured:
        return dict(secured[0])

    visible = [target for target in candidates if str(target.get("ssid") or "").strip()]
    return dict((visible or candidates)[0])
