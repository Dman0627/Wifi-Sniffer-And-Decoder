from __future__ import annotations

import shutil

from wifi_pipeline import environment
from wifi_pipeline.capabilities import CapabilityReport, PlatformCapability
from wifi_pipeline.environment import _parse_dumpcap_interfaces


def test_parse_dumpcap_interfaces_basic() -> None:
    raw = "1. \\Device\\NPF_{ABC} (Ethernet)\n2. \\Device\\NPF_{DEF} (Wi-Fi)\n"
    parsed = _parse_dumpcap_interfaces(raw)
    assert parsed[0][0] == "1"
    assert parsed[0][1].startswith("\\Device\\NPF_")
    assert parsed[1][2] == "Wi-Fi"


def test_parse_dumpcap_interfaces_no_parens() -> None:
    raw = "1. \\Device\\NPF_{ABC}\n"
    parsed = _parse_dumpcap_interfaces(raw)
    assert parsed[0][1] == "\\Device\\NPF_{ABC}"


def test_default_product_mode_detects_ubuntu(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "_read_os_release", lambda: {"ID": "ubuntu", "PRETTY_NAME": "Ubuntu 24.04 LTS"})
    monkeypatch.setattr(environment, "_linux_machine_model", lambda: "")

    assert environment.default_product_mode() == "ubuntu_standalone"
    assert environment.resolve_product_profile({}).label == "Ubuntu standalone"


def test_default_product_mode_detects_raspberry_pi(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "_read_os_release", lambda: {"ID": "raspbian", "PRETTY_NAME": "Raspberry Pi OS"})
    monkeypatch.setattr(environment, "_linux_machine_model", lambda: "Raspberry Pi 5")

    assert environment.default_product_mode() == "pi_standalone"
    assert environment.resolve_product_profile({}).label == "Raspberry Pi OS standalone"


def test_command_support_marks_windows_local_capture_experimental(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", True)
    monkeypatch.setattr(environment, "IS_LINUX", False)
    monkeypatch.setattr(environment, "IS_MACOS", False)

    support = environment.command_support("capture", {})

    assert support.status == "experimental"
    assert support.profile.key == "windows_experimental_local"


def test_command_support_marks_linux_wifi_official(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "_read_os_release", lambda: {"ID": "ubuntu", "PRETTY_NAME": "Ubuntu 24.04 LTS"})
    monkeypatch.setattr(environment, "_linux_machine_model", lambda: "")

    support = environment.command_support("wifi", {})

    assert support.status == "official"
    assert support.profile.key == "ubuntu_standalone"


def test_command_support_marks_validate_local_official_on_supported_linux(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "_read_os_release", lambda: {"ID": "ubuntu", "PRETTY_NAME": "Ubuntu 24.04 LTS"})
    monkeypatch.setattr(environment, "_linux_machine_model", lambda: "")

    support = environment.command_support("validate-local", {})

    assert support.status == "official"
    assert support.profile.key == "ubuntu_standalone"


def test_workflow_support_matrix_for_windows_remote(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", True)
    monkeypatch.setattr(environment, "IS_LINUX", False)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "_find_windows_wlanhelper", lambda: r"C:\Npcap\WlanHelper.exe")

    tool_map = {
        "dumpcap": r"C:\Wireshark\dumpcap.exe",
        "tshark": r"C:\Wireshark\tshark.exe",
        "ssh": r"C:\Windows\System32\OpenSSH\ssh.exe",
        "scp": r"C:\Windows\System32\OpenSSH\scp.exe",
        "aircrack-ng": r"C:\aircrack-ng\aircrack-ng.exe",
        "airdecap-ng": r"C:\aircrack-ng\airdecap-ng.exe",
    }
    monkeypatch.setattr(shutil, "which", lambda name: tool_map.get(name))

    rows = {row.area: row for row in environment.workflow_support_matrix({})}

    assert rows["pcap import + analysis"].tier == "supported"
    assert rows["remote capture control"].tier == "supported"
    assert rows["local packet capture"].tier == "supported_with_limits"
    assert rows["monitor mode + Wi-Fi lab capture"].tier == "supported_with_limits"
    assert rows["WPA cracking + Wi-Fi decrypt"].tier == "supported_with_limits"
    assert rows["payload decoding"].tier == "heuristic"
    assert rows["replay + reconstruction"].tier == "heuristic"
    assert any(reason.code == "capture.local_requires_privilege" for reason in rows["local packet capture"].reasons)
    assert any(reason.code == "remote.host_not_configured" for reason in rows["remote capture control"].reasons)
    assert any(reason.code == "wpa.wordlist_not_configured" for reason in rows["WPA cracking + Wi-Fi decrypt"].reasons)


def test_workflow_support_matrix_for_ubuntu_standalone(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "_read_os_release", lambda: {"ID": "ubuntu", "PRETTY_NAME": "Ubuntu 24.04 LTS"})
    monkeypatch.setattr(environment, "_linux_machine_model", lambda: "")
    monkeypatch.setattr(environment, "_find_windows_wlanhelper", lambda: None)

    tool_map = {
        "tcpdump": "/usr/sbin/tcpdump",
        "tshark": "/usr/bin/tshark",
        "airmon-ng": "/usr/bin/airmon-ng",
        "airodump-ng": "/usr/bin/airodump-ng",
        "aircrack-ng": "/usr/bin/aircrack-ng",
        "airdecap-ng": "/usr/bin/airdecap-ng",
        "ssh": "/usr/bin/ssh",
        "scp": "/usr/bin/scp",
    }
    monkeypatch.setattr(shutil, "which", lambda name: tool_map.get(name))

    rows = {row.area: row for row in environment.workflow_support_matrix({})}

    assert rows["pcap import + analysis"].tier == "supported"
    assert rows["local packet capture"].tier == "supported"
    assert rows["monitor mode + Wi-Fi lab capture"].tier == "supported"
    assert rows["remote capture control"].tier == "supported_with_limits"
    assert rows["WPA cracking + Wi-Fi decrypt"].tier == "supported_with_limits"
    assert any(reason.code == "capture.local_requires_privilege" for reason in rows["local packet capture"].reasons)
    assert any(reason.code == "capture.monitor_requires_privilege" for reason in rows["monitor mode + Wi-Fi lab capture"].reasons)
    assert any(reason.code == "remote.host_not_configured" for reason in rows["remote capture control"].reasons)


def test_hardware_qualification_for_windows_remote(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", True)
    monkeypatch.setattr(environment, "IS_LINUX", False)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment.platform, "machine", lambda: "AMD64")

    rows = {row.area: row for row in environment.hardware_qualification_report({"remote_host": "pi@raspberrypi"})}

    assert rows["host"].status == "supported"
    assert "controller" in rows["host"].summary.lower()
    assert rows["capture_node"].status == "supported"
    assert rows["local_radio"].status == "unsupported"


def test_build_capability_report_for_windows_with_local_wifi_evidence(monkeypatch) -> None:
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

    report = environment.build_capability_report({"remote_host": "pi@raspberrypi", "remote_health_port": 8741})

    assert report.platform.os_name == "windows"
    assert report.platform.product_profile_key == "windows_remote"
    tools = {tool.name: tool for tool in report.tools}
    assert tools["Npcap"].status == "available"
    assert tools["WlanHelper"].status == "available"
    assert report.adapters[0].driver == "Netwtw10.sys"
    assert report.adapters[0].status == "supported_with_limits"
    assert report.adapters[0].capture_methods == ("local_capture", "monitor_capture")
    assert any(reason.code == "adapter.windows_local_capture_plausible" for reason in report.adapters[0].reasons)
    assert any(reason.code == "adapter.windows_monitor_experimental" for reason in report.adapters[0].reasons)
    capture_methods = {method.key: method for method in report.capture_methods}
    assert capture_methods["local_capture"].status == "experimental"
    assert capture_methods["monitor_capture"].status == "experimental"
    assert capture_methods["local_capture"].available is True
    assert capture_methods["monitor_capture"].available is True


def test_hardware_qualification_for_ubuntu_with_ath9k_htc(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "_read_os_release", lambda: {"ID": "ubuntu", "PRETTY_NAME": "Ubuntu 24.04 LTS"})
    monkeypatch.setattr(environment, "_linux_machine_model", lambda: "")
    monkeypatch.setattr(environment.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(environment, "list_interfaces", lambda: [("1", "wlan0", "wireless adapter")])
    monkeypatch.setattr(environment, "_linux_interface_driver", lambda interface: "ath9k_htc")
    monkeypatch.setattr(
        environment,
        "_linux_interface_fingerprint",
        lambda interface, description="": "wlan0 ath9k_htc qca9271",
    )

    rows = environment.hardware_qualification_report({"interface": "wlan0"})
    by_area = {row.area: row for row in rows}

    assert by_area["host"].status == "supported"
    adapter_rows = [row for row in rows if row.area == "capture_adapter"]
    assert len(adapter_rows) == 1
    assert adapter_rows[0].status == "supported"
    assert "Atheros AR9271" in adapter_rows[0].label


def test_hardware_qualification_for_pi_with_brcmfmac(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "_read_os_release", lambda: {"ID": "raspbian", "PRETTY_NAME": "Raspberry Pi OS"})
    monkeypatch.setattr(environment, "_linux_machine_model", lambda: "Raspberry Pi 5")
    monkeypatch.setattr(environment.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(environment, "list_interfaces", lambda: [("1", "wlan0", "onboard wireless")])
    monkeypatch.setattr(environment, "_linux_interface_driver", lambda interface: "brcmfmac")
    monkeypatch.setattr(
        environment,
        "_linux_interface_fingerprint",
        lambda interface, description="": "wlan0 brcmfmac broadcom",
    )

    rows = environment.hardware_qualification_report({"interface": "wlan0"})
    adapter_rows = [row for row in rows if row.area == "capture_adapter"]

    assert rows[0].status == "supported"
    assert adapter_rows[0].status == "unsupported"
    assert "Broadcom brcmfmac" in adapter_rows[0].label


def test_capability_report_to_dict_preserves_nested_sections() -> None:
    report = CapabilityReport(
        platform=PlatformCapability(
            os_name="linux",
            os_version="6.8.0",
            distribution="Ubuntu 24.04 LTS",
            architecture="x86_64",
            product_profile_key="ubuntu_standalone",
            product_profile_label="Ubuntu standalone",
            official=True,
        ),
        privilege_mode="user",
    )

    payload = report.to_dict()

    assert payload["platform"]["os_name"] == "linux"
    assert payload["platform"]["product_profile_key"] == "ubuntu_standalone"
    assert payload["privilege_mode"] == "user"
    assert payload["wpa"]["state"] == "not_evaluated"
    assert payload["wpa"]["reasons"] == ()
    assert payload["remote"]["mode"] == "linux_appliance"


def test_linux_output_supports_monitor_modes() -> None:
    advertised = """
    Wiphy phy0
        Supported interface modes:
             * managed
             * monitor
             * AP
    """
    missing = """
    Wiphy phy0
        Supported interface modes:
             * managed
             * AP
    """

    assert environment._linux_output_supports_monitor(advertised) is True
    assert environment._linux_output_supports_monitor(missing) is False
    assert environment._linux_output_supports_monitor("") is None


def test_privilege_mode_prefers_linux_capture_capabilities(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", True)
    monkeypatch.setattr(environment, "IS_MACOS", False)
    monkeypatch.setattr(environment, "is_admin", lambda: False)
    monkeypatch.setattr(
        environment,
        "_tool_path",
        lambda name: "/usr/bin/dumpcap" if name == "dumpcap" else "",
    )
    monkeypatch.setattr(environment, "_linux_binary_has_capture_capabilities", lambda path: bool(path))

    assert environment._privilege_mode_label() == "capture_capabilities"


def test_build_capability_report_for_supported_linux(monkeypatch, tmp_path) -> None:
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

    report = environment.build_capability_report(
        {
            "interface": "wlan0",
            "remote_host": "pi@raspberrypi",
            "remote_health_port": 8741,
            "wordlist_path": str(wordlist),
            "ap_essid": "LabNet",
        }
    )

    assert report.platform.os_name == "linux"
    assert report.platform.product_profile_key == "ubuntu_standalone"
    assert report.platform.distribution_id == "ubuntu"
    assert report.platform.distribution_version == "24.04"
    assert report.platform.machine_model == "ThinkPad X1 Carbon"
    assert report.privilege_mode == "user"
    assert report.adapters[0].driver == "ath9k_htc"
    assert report.adapters[0].phy_name == "phy0"
    assert report.adapters[0].chipset_family == "Atheros AR9271 / ath9k_htc"
    assert report.adapters[0].monitor_support_advertised is True
    assert any(reason.code == "adapter.monitor_mode_advertised" for reason in report.adapters[0].reasons)
    tools = {tool.name: tool for tool in report.tools}
    assert tools["iw"].status == "available"
    assert tools["ethtool"].status == "missing"
    assert report.capture_methods[0].key == "local_capture"
    assert report.capture_methods[0].status == "supported"
    assert any(reason.code == "capture.local_requires_privilege" for reason in report.capture_methods[0].reasons)
    assert report.wpa.state == "not_evaluated"
    assert report.wpa.crack_ready is True
    assert report.wpa.decrypt_ready is True
    assert any(reason.code == "wpa.readiness_not_evaluated" for reason in report.wpa.reasons)
    assert report.remote.status == "supported_with_limits"
    assert report.remote.configured_host == "pi@raspberrypi"
    assert any(reason.code == "remote.host_configured" for reason in report.remote.reasons)
    assert report.replay_families[-1].family == "opaque_unknown"
    assert report.replay_families[-1].reasons[0].code == "replay.opaque_unknown_unsupported"


def test_build_capability_report_for_windows_without_npcap_blocks_local_wifi(monkeypatch) -> None:
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
    monkeypatch.setattr(environment, "_find_windows_npcap", lambda: None)
    monkeypatch.setattr(environment, "_find_windows_wlanhelper", lambda: None)

    tool_map = {
        "dumpcap": r"C:\Program Files\Wireshark\dumpcap.exe",
        "ssh": r"C:\Windows\System32\OpenSSH\ssh.exe",
        "scp": r"C:\Windows\System32\OpenSSH\scp.exe",
    }
    monkeypatch.setattr(shutil, "which", lambda name: tool_map.get(name))

    report = environment.build_capability_report({})

    tools = {tool.name: tool for tool in report.tools}
    assert tools["Npcap"].status == "missing"
    assert report.adapters[0].status == "unsupported"
    assert any(reason.code == "adapter.windows_npcap_missing" for reason in report.adapters[0].reasons)
    capture_methods = {method.key: method for method in report.capture_methods}
    assert capture_methods["local_capture"].available is False
    assert capture_methods["monitor_capture"].available is False
    assert any(reason.code == "capture.windows_npcap_missing" for reason in capture_methods["local_capture"].reasons)


def test_build_capability_report_for_macos_with_wireless_adapter(monkeypatch) -> None:
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

    report = environment.build_capability_report({})

    assert report.platform.os_name == "macos"
    assert report.platform.distribution_id == "macos"
    assert report.platform.distribution_version == "14.4"
    assert report.platform.machine_model == "MacBookPro18,3"
    tools = {tool.name: tool for tool in report.tools}
    assert tools["airport"].status == "available"
    assert tools["networksetup"].status == "available"
    assert report.adapters[0].status == "supported_with_limits"
    assert report.adapters[0].capture_methods == ("local_capture", "monitor_capture")
    assert any(reason.code == "adapter.macos_local_capture_experimental" for reason in report.adapters[0].reasons)
    assert any(reason.code == "adapter.macos_monitor_experimental" for reason in report.adapters[0].reasons)
    methods = {method.key: method for method in report.capture_methods}
    assert methods["local_capture"].status == "experimental"
    assert methods["monitor_capture"].status == "experimental"
    assert any(reason.code == "capture.macos_local_experimental" for reason in methods["local_capture"].reasons)
    assert any(reason.code == "capture.macos_monitor_experimental" for reason in methods["monitor_capture"].reasons)


def test_build_capability_report_for_macos_without_tcpdump_blocks_monitor(monkeypatch) -> None:
    monkeypatch.setattr(environment, "IS_WINDOWS", False)
    monkeypatch.setattr(environment, "IS_LINUX", False)
    monkeypatch.setattr(environment, "IS_MACOS", True)
    monkeypatch.setattr(environment.platform, "mac_ver", lambda: ("14.4", ("", "", ""), ""))
    monkeypatch.setattr(environment.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(environment, "_macos_machine_model", lambda: "MacBookAir10,1")
    monkeypatch.setattr(environment, "is_admin", lambda: False)
    monkeypatch.setattr(environment, "list_interfaces", lambda: [("1", "en0", "Wi-Fi")])
    monkeypatch.setattr(environment, "_find_macos_airport", lambda: None)

    tool_map = {
        "networksetup": "/usr/sbin/networksetup",
        "ssh": "/usr/bin/ssh",
        "scp": "/usr/bin/scp",
    }
    monkeypatch.setattr(shutil, "which", lambda name: tool_map.get(name))

    report = environment.build_capability_report({})

    tools = {tool.name: tool for tool in report.tools}
    assert tools["airport"].status == "missing"
    assert report.adapters[0].status == "unsupported"
    assert any(reason.code == "adapter.macos_capture_tool_missing" for reason in report.adapters[0].reasons)
    assert any(reason.code == "adapter.macos_monitor_tool_missing" for reason in report.adapters[0].reasons)
    methods = {method.key: method for method in report.capture_methods}
    assert methods["local_capture"].available is False
    assert methods["monitor_capture"].available is False
    assert any(reason.code == "capture.macos_tcpdump_missing" for reason in methods["monitor_capture"].reasons)
