from __future__ import annotations

from wifi_pipeline.wifi_discovery import (
    parse_iw_scan,
    parse_nmcli_wifi_list,
    parse_windows_netsh_networks,
    parse_windows_wlan_interfaces,
    select_preferred_wifi_target,
)


def test_parse_windows_netsh_networks_and_connected_interface() -> None:
    scan_output = """
SSID 1 : LabNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:11:22:33:44:55
         Signal             : 82%
         Radio type         : 802.11ac
         Channel            : 11

SSID 2 : Cafe WiFi
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 91%
         Channel            : 6
"""
    interface_output = """
Name                   : Wi-Fi
State                  : connected
SSID                   : LabNet
BSSID                  : 00:11:22:33:44:55
Authentication         : WPA2-Personal
Cipher                 : CCMP
Channel                : 11
Signal                 : 82%
"""

    targets = parse_windows_wlan_interfaces(interface_output) + parse_windows_netsh_networks(scan_output)
    selected = select_preferred_wifi_target(targets)

    assert selected is not None
    assert selected["ssid"] == "LabNet"
    assert selected["bssid"] == "00:11:22:33:44:55"
    assert selected["channel"] == 11
    assert selected["connected"] is True


def test_parse_nmcli_wifi_list_handles_escaped_fields() -> None:
    output = "\n".join(
        [
            r"yes:Lab\:Net:00\:11\:22\:33\:44\:55:11:83:WPA2",
            r"no:OpenCafe:aa\:bb\:cc\:dd\:ee\:ff:1:44:--",
        ]
    )

    targets = parse_nmcli_wifi_list(output)
    selected = select_preferred_wifi_target(targets)

    assert targets[0]["ssid"] == "Lab:Net"
    assert targets[0]["bssid"] == "00:11:22:33:44:55"
    assert targets[0]["signal"] == 83
    assert selected is not None
    assert selected["connected"] is True
    assert selected["ssid"] == "Lab:Net"


def test_parse_iw_scan_extracts_bssid_channel_signal_and_security() -> None:
    output = """
BSS 00:11:22:33:44:55(on wlan0)
    freq: 2462
    signal: -48.00 dBm
    SSID: LabNet
    DS Parameter set: channel 11
    RSN:     * Version: 1
BSS aa:bb:cc:dd:ee:ff(on wlan0)
    freq: 2412
    signal: -80.00 dBm
    SSID: Guest
    capability: ESS Privacy ShortSlotTime (0x0411)
"""

    targets = parse_iw_scan(output)

    assert targets[0]["ssid"] == "LabNet"
    assert targets[0]["bssid"] == "00:11:22:33:44:55"
    assert targets[0]["channel"] == 11
    assert targets[0]["security"] == "WPA2/WPA3"
    assert int(targets[0]["signal"]) > int(targets[1]["signal"])
