from __future__ import annotations

import shutil
from pathlib import Path

from wifi_pipeline import environment
from wifi_pipeline.status_language import build_machine_summary


def _mock_windows_remote(monkeypatch) -> dict[str, object]:
    monkeypatch.setattr(environment, "IS_WINDOWS", True)
    monkeypatch.setattr(environment, "IS_LINUX", False)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment.platform, "release", lambda: "11")
    monkeypatch.setattr(environment.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(environment, "is_admin", lambda: False)
    monkeypatch.setattr(
        environment,
        "list_interfaces",
        lambda: [("1", r"\\Device\\NPF_{ABCDEF12-3456-7890-ABCD-EF1234567890}", "Wi-Fi")],
    )
    monkeypatch.setattr(
        environment,
        "_windows_adapter_inventory",
        lambda: [
            {
                "name": "Wi-Fi",
                "interface_description": "Intel(R) Wi-Fi 6 AX201 160MHz",
                "interface_guid": "abcdef12-3456-7890-abcd-ef1234567890",
                "status": "Up",
                "driver_file_name": "Netwtw10.sys",
                "driver_description": "Intel(R) Wi-Fi 6 AX201 160MHz",
                "mac_address": "00-11-22-33-44-55",
                "link_speed": "1200 Mbps",
                "media_connection_state": "Connected",
            }
        ],
    )
    monkeypatch.setattr(environment, "_find_windows_npcap", lambda: r"C:\Windows\System32\Npcap")
    monkeypatch.setattr(environment, "_find_windows_wlanhelper", lambda: r"C:\Windows\System32\Npcap\WlanHelper.exe")
    tool_map = {
        "dumpcap": r"C:\Program Files\Wireshark\dumpcap.exe",
        "tshark": r"C:\Program Files\Wireshark\tshark.exe",
        "ssh": r"C:\Windows\System32\OpenSSH\ssh.exe",
        "scp": r"C:\Windows\System32\OpenSSH\scp.exe",
    }
    monkeypatch.setattr(shutil, "which", lambda name: tool_map.get(name))
    return {"remote_host": "pi@raspberrypi"}


def _mock_supported_linux(monkeypatch, tmp_path: Path) -> dict[str, object]:
    wordlist = tmp_path / "wordlist.txt"
    wordlist.write_text("password\n", encoding="utf-8")

    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(
        environment,
        "_read_os_release",
        lambda: {"ID": "ubuntu", "VERSION_ID": "24.04", "PRETTY_NAME": "Ubuntu 24.04 LTS"},
    )
    monkeypatch.setattr(environment, "_linux_machine_model", lambda: "ThinkPad X1 Carbon")
    monkeypatch.setattr(environment.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(environment.platform, "release", lambda: "6.8.0")
    monkeypatch.setattr(environment, "list_interfaces", lambda: [("1", "wlan0", "wireless adapter")])
    monkeypatch.setattr(environment, "_linux_interface_driver", lambda interface: "ath9k_htc")
    monkeypatch.setattr(environment, "_linux_interface_phy_name", lambda interface: "phy0")
    monkeypatch.setattr(environment, "_linux_interface_supports_monitor_mode", lambda interface, phy_name="": True)
    monkeypatch.setattr(
        environment,
        "_linux_interface_fingerprint",
        lambda interface, description="": "wlan0 ath9k_htc qca9271",
    )
    monkeypatch.setattr(environment, "is_admin", lambda: False)
    tool_map = {
        "dumpcap": "/usr/bin/dumpcap",
        "tcpdump": "/usr/sbin/tcpdump",
        "airmon-ng": "/usr/bin/airmon-ng",
        "airodump-ng": "/usr/bin/airodump-ng",
        "aircrack-ng": "/usr/bin/aircrack-ng",
        "airdecap-ng": "/usr/bin/airdecap-ng",
        "iw": "/usr/sbin/iw",
        "getcap": "/usr/sbin/getcap",
        "ssh": "/usr/bin/ssh",
        "scp": "/usr/bin/scp",
    }
    monkeypatch.setattr(shutil, "which", lambda name: tool_map.get(name))
    return {"remote_host": "pi@raspberrypi", "wordlist_path": str(wordlist), "ap_essid": "LabNet"}


def _mock_macos_experimental(monkeypatch) -> dict[str, object]:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", False)
    monkeypatch.setattr(environment, "IS_MACOS", True)
    monkeypatch.setattr(environment.platform, "mac_ver", lambda: ("14.4", ("", "", ""), ""))
    monkeypatch.setattr(environment.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(environment, "_macos_machine_model", lambda: "MacBookPro18,3")
    monkeypatch.setattr(environment, "is_admin", lambda: False)
    monkeypatch.setattr(environment, "list_interfaces", lambda: [("1", "en0", "Wi-Fi")])
    monkeypatch.setattr(
        environment,
        "_find_macos_airport",
        lambda: "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
    )
    tool_map = {
        "tcpdump": "/usr/sbin/tcpdump",
        "networksetup": "/usr/sbin/networksetup",
        "ssh": "/usr/bin/ssh",
        "scp": "/usr/bin/scp",
    }
    monkeypatch.setattr(shutil, "which", lambda name: tool_map.get(name))
    return {}


def test_build_machine_summary_for_supported_linux(monkeypatch, tmp_path) -> None:
    config = _mock_supported_linux(monkeypatch, tmp_path)

    summary = build_machine_summary(
        config,
        wpa_status={"status": "limited", "summary": "A valid handshake exists, but the WPA path still has caveats."},
    )
    by_key = {item["key"]: item for item in summary["items"]}

    assert summary["headline"] == "Ubuntu standalone / privilege=user"
    assert by_key["local_capture"]["status"] == "supported"
    assert by_key["monitor_capture"]["status"] == "supported"
    assert by_key["wpa"]["status"] == "limited"
    assert by_key["remote_capture"]["status"] == "limited"
    assert by_key["replay_export"]["status"] == "limited"


def test_build_machine_summary_for_windows_remote_controller(monkeypatch) -> None:
    config = _mock_windows_remote(monkeypatch)

    summary = build_machine_summary(
        config,
        wpa_status={"status": "blocked", "summary": "WPA needs a usable handshake or PMKID capture first."},
    )
    by_key = {item["key"]: item for item in summary["items"]}

    assert summary["headline"] == "Windows 10/11 + Ubuntu/Raspberry Pi OS remote capture / privilege=user"
    assert by_key["local_capture"]["status"] == "limited"
    assert by_key["monitor_capture"]["status"] == "limited"
    assert by_key["wpa"]["status"] == "blocked"
    assert by_key["remote_capture"]["status"] == "supported"
    assert by_key["replay_export"]["status"] == "limited"


def test_build_machine_summary_for_macos_experimental(monkeypatch) -> None:
    config = _mock_macos_experimental(monkeypatch)

    summary = build_machine_summary(
        config,
        wpa_status={"status": "ready", "summary": "WPA is not part of the current workflow."},
    )
    by_key = {item["key"]: item for item in summary["items"]}

    assert summary["headline"] == "macOS experimental / privilege=user"
    assert by_key["local_capture"]["status"] == "limited"
    assert by_key["monitor_capture"]["status"] == "limited"
    assert by_key["wpa"]["status"] == "ready"
    assert by_key["remote_capture"]["status"] == "limited"
    assert by_key["replay_export"]["status"] == "limited"
