from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Optional

from .config import resolve_wpa_password
from .environment import IS_WINDOWS, maybe_elevate_for_capture
from .ui import done, err, info, ok, section, warn


class Capture:
    def __init__(self, config: Dict[str, object]) -> None:
        self.config = config
        output_dir = Path(str(config.get("output_dir") or "./pipeline_output"))
        self.raw_capture = output_dir / "raw_capture.pcapng"
        self.decrypted_capture = output_dir / "decrypted_wifi.pcapng"

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

    def run(self, interactive: bool = True) -> Optional[str]:
        section("Stage 1 - Capture")
        if not IS_WINDOWS:
            err("This capture workflow now targets native Windows only.")
            return None
        if maybe_elevate_for_capture(interactive=interactive):
            return None

        dumpcap = shutil.which("dumpcap")
        if not dumpcap:
            err("dumpcap not found. Install Wireshark with NPcap and add it to PATH.")
            return None

        interface = self._ensure_interface()
        if not interface:
            return None

        output_dir = self.raw_capture.parent
        output_dir.mkdir(parents=True, exist_ok=True)
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
