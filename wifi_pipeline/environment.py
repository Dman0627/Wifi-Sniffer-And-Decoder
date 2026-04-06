from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .ui import BOLD, CYAN, DIM, RESET, ask, confirm, err, info, ok, section, warn

IS_WINDOWS = sys.platform.startswith("win")


@dataclass
class ToolStatus:
    name: str
    purpose: str
    required: bool
    path: Optional[str]


REQUIRED_TOOLS = (
    ("dumpcap", "Packet capture through NPcap/Wireshark", True),
    ("tshark", "Packet parsing and inspection", True),
    ("ffplay", "Optional playback preview", False),
    ("airdecap-ng", "Optional Wi-Fi layer decryption", False),
)


def is_admin() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(argv: Optional[List[str]] = None) -> None:
    if not IS_WINDOWS:
        raise RuntimeError("Elevation helper is only available on Windows")
    import ctypes

    argv = list(sys.argv[1:] if argv is None else argv)
    script = os.path.abspath(sys.argv[0])
    args = " ".join([f'"{script}"'] + [f'"{item}"' for item in argv])
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, None, 1)
    if result <= 32:
        raise RuntimeError(f"UAC elevation failed with code {result}")


def check_environment() -> bool:
    section("Environment Check")
    if not IS_WINDOWS:
        err("This repository is now standardized on native Windows tools.")
        warn("Capture and install scripts expect NPcap/Wireshark, FFmpeg, and PowerShell.")
        return False

    all_required = True
    for name, purpose, required in REQUIRED_TOOLS:
        path = shutil.which(name)
        status = f"{CYAN}*{RESET}" if path else f"{DIM}-{RESET}"
        requirement = "required" if required else "optional"
        location = path or "not found on PATH"
        print(f"  {status} {name:<12} {purpose} {DIM}({requirement}){RESET}")
        print(f"      {location}")
        if required and not path:
            all_required = False

    try:
        import scapy  # noqa: F401

        ok("Python package available: scapy")
    except ImportError:
        warn("Python package missing: scapy")
        all_required = False

    try:
        import numpy  # noqa: F401

        ok("Python package available: numpy")
    except ImportError:
        warn("Python package missing: numpy")

    if not is_admin():
        warn("Administrator rights are recommended for capture and interface discovery.")

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


def list_interfaces() -> List[Tuple[str, str, str]]:
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
        print(f"  {BOLD}Tip:{RESET} install Wireshark/NPcap and re-run in an Administrator shell.")
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
