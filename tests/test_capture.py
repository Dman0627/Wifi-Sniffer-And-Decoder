from __future__ import annotations

import subprocess
from pathlib import Path

from wifi_pipeline.capture import Capture


def test_build_capture_filter_joins_target_macs() -> None:
    capture = Capture({"output_dir": ".", "target_macs": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]})

    assert capture.build_capture_filter() == (
        "ether host aa:bb:cc:dd:ee:ff or ether host 11:22:33:44:55:66"
    )


def test_run_uses_dumpcap_when_available(monkeypatch, tmp_path) -> None:
    commands: list[list[str]] = []

    def fake_run(cmd, capture_output, text, check):
        commands.append(cmd)
        (tmp_path / "raw_capture.pcapng").write_bytes(b"pcap")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("wifi_pipeline.capture.maybe_elevate_for_capture", lambda interactive=True: False)
    monkeypatch.setattr(
        "wifi_pipeline.capture.shutil.which",
        lambda tool: "C:\\Tools\\dumpcap.exe" if tool == "dumpcap" else None,
    )
    monkeypatch.setattr("wifi_pipeline.capture.subprocess.run", fake_run)
    capture = Capture(
        {
            "output_dir": str(tmp_path),
            "interface": "eth0",
            "capture_duration": 15,
            "target_macs": ["aa:bb:cc:dd:ee:ff"],
        }
    )

    result = capture.run(interactive=False)

    assert result == str(tmp_path / "raw_capture.pcapng")
    assert commands
    assert commands[0][:5] == ["C:\\Tools\\dumpcap.exe", "-i", "eth0", "-w", str(tmp_path / "raw_capture.pcapng")]
    assert "-f" in commands[0]


def test_run_falls_back_to_tcpdump_on_non_windows(monkeypatch, tmp_path) -> None:
    commands: list[list[str]] = []

    def fake_run(cmd, capture_output, text, timeout=None, check=False):
        commands.append(cmd)
        (tmp_path / "raw_capture.pcapng").write_bytes(b"pcap")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("wifi_pipeline.capture.IS_WINDOWS", False)
    monkeypatch.setattr("wifi_pipeline.capture.maybe_elevate_for_capture", lambda interactive=True: False)
    monkeypatch.setattr(
        "wifi_pipeline.capture.shutil.which",
        lambda tool: None if tool == "dumpcap" else "/usr/sbin/tcpdump",
    )
    monkeypatch.setattr("wifi_pipeline.capture.subprocess.run", fake_run)
    capture = Capture({"output_dir": str(tmp_path), "interface": "eth0", "capture_duration": 5})

    result = capture.run(interactive=False)

    assert result == str(tmp_path / "raw_capture.pcapng")
    assert commands[0][0] == "tcpdump"


def test_strip_wifi_layer_returns_original_when_credentials_missing(monkeypatch, tmp_path) -> None:
    source = tmp_path / "capture.pcapng"
    source.write_bytes(b"pcap")
    monkeypatch.setattr("wifi_pipeline.capture.shutil.which", lambda tool: "C:\\Tools\\airdecap-ng.exe")
    capture = Capture({"output_dir": str(tmp_path), "ap_essid": "", "wpa_password": ""})

    result = capture.strip_wifi_layer(str(source))

    assert result == str(source)


def test_strip_wifi_layer_moves_generated_output(monkeypatch, tmp_path) -> None:
    source = tmp_path / "capture.pcapng"
    source.write_bytes(b"pcap")

    def fake_run(cmd, cwd, capture_output, text, check):
        generated = Path(cwd) / "capture-dec.pcapng"
        generated.write_bytes(b"decrypted")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("wifi_pipeline.capture.shutil.which", lambda tool: "C:\\Tools\\airdecap-ng.exe")
    monkeypatch.setattr("wifi_pipeline.capture.subprocess.run", fake_run)
    capture = Capture(
        {
            "output_dir": str(tmp_path),
            "ap_essid": "TestNet",
            "wpa_password": "secret",
        }
    )

    result = capture.strip_wifi_layer(str(source))

    assert result == str(tmp_path / "decrypted_wifi.pcapng")
    assert (tmp_path / "decrypted_wifi.pcapng").read_bytes() == b"decrypted"


def test_run_monitor_uses_windows_dumpcap_for_tcpdump_mode(monkeypatch, tmp_path) -> None:
    called: list[str] = []

    monkeypatch.setattr("wifi_pipeline.capture.IS_WINDOWS", True)
    monkeypatch.setattr("wifi_pipeline.capture.IS_MACOS", False)
    monkeypatch.setattr("wifi_pipeline.capture.maybe_elevate_for_capture", lambda interactive=True: False)
    monkeypatch.setattr("wifi_pipeline.capture.MonitorMode.enable", lambda self: "wifi0")
    monkeypatch.setattr(
        Capture,
        "_run_dumpcap_monitor_windows",
        lambda self, interface: called.append(interface) or str(tmp_path / "monitor_raw.pcap"),
    )
    capture = Capture({"output_dir": str(tmp_path), "interface": "\\Device\\NPF_{ABC}"})

    result = capture.run_monitor(method="tcpdump", interactive=False)

    assert result == str(tmp_path / "monitor_raw.pcap")
    assert called == ["wifi0"]


def test_run_full_wifi_pipeline_disables_monitor_after_decrypt(monkeypatch, tmp_path) -> None:
    calls: list[str] = []
    capture = Capture({"output_dir": str(tmp_path), "interface": "wifi0"})

    monkeypatch.setattr(Capture, "run_monitor", lambda self, method="airodump", interactive=True: "handshake.cap")
    monkeypatch.setattr(Capture, "crack_and_decrypt", lambda self, handshake_cap=None: "decrypted.pcapng")
    monkeypatch.setattr(Capture, "disable_monitor", lambda self: calls.append("disabled"))

    result = capture.run_full_wifi_pipeline(method="tcpdump", interactive=False)

    assert result == "decrypted.pcapng"
    assert calls == ["disabled"]
