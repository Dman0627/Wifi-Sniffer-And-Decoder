from __future__ import annotations

import subprocess
from pathlib import Path

from scapy.all import Ether, IP, LLC, SNAP, TCP, RadioTap, wrpcap
from scapy.layers.dot11 import AKMSuite, Dot11, Dot11AssoReq, Dot11EltRSN, PMKIDListPacket, RSNCipherSuite
from scapy.layers.eap import EAPOL, EAPOL_KEY

from wifi_pipeline.capture import Capture, WPACrackReadiness


def _eapol_key_packet(message_number: int, *, ap: str = "66:77:88:99:aa:bb", client: str = "00:11:22:33:44:55"):
    if message_number in (1, 3):
        addr1, addr2, addr3 = client, ap, ap
    else:
        addr1, addr2, addr3 = ap, client, ap

    key_kwargs = {
        1: {"key_ack": 1, "has_key_mic": 0, "secure": 0, "install": 0},
        2: {"key_ack": 0, "has_key_mic": 1, "secure": 0, "install": 0},
        3: {"key_ack": 1, "has_key_mic": 1, "secure": 1, "install": 1},
        4: {"key_ack": 0, "has_key_mic": 1, "secure": 1, "install": 0},
    }[message_number]
    return (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=addr1, addr2=addr2, addr3=addr3)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0, code=0x888E)
        / EAPOL(version=2, type=3)
        / EAPOL_KEY(
            key_descriptor_type=2,
            key_type=1,
            key_length=16,
            key_replay_counter=message_number,
            key_nonce=b"\x00" * 32,
            key_iv=b"\x00" * 16,
            key_rsc=b"\x00" * 8,
            key_id=b"\x00" * 8,
            key_mic=b"\x00" * 16,
            key_data_length=0,
            key_data=b"",
            **key_kwargs,
        )
    )


def _write_handshake_capture(path: Path, messages: tuple[int, ...], *, ap: str = "66:77:88:99:aa:bb", client: str = "00:11:22:33:44:55") -> None:
    wrpcap(str(path), [_eapol_key_packet(message_number, ap=ap, client=client) for message_number in messages])


def _write_pmkid_capture(path: Path) -> None:
    rsn = Dot11EltRSN(
        group_cipher_suite=RSNCipherSuite(),
        pairwise_cipher_suites=[RSNCipherSuite()],
        akm_suites=[AKMSuite()],
        pmkids=PMKIDListPacket(nb_pmkids=1, pmkid_list=[b"0123456789abcdef"]),
    )
    packet = (
        RadioTap()
        / Dot11(type=0, subtype=0, addr1="00:11:22:33:44:55", addr2="66:77:88:99:aa:bb", addr3="66:77:88:99:aa:bb")
        / Dot11AssoReq()
        / rsn
    )
    wrpcap(str(path), [packet])


def _write_non_80211_capture(path: Path) -> None:
    wrpcap(
        str(path),
        [
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src="192.0.2.1", dst="198.51.100.10")
            / TCP(sport=12345, dport=80)
        ],
    )


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


def test_inspect_wpa_crack_path_reports_known_key_supplied(monkeypatch, tmp_path) -> None:
    handshake = tmp_path / "handshake.cap"
    _write_handshake_capture(handshake, (1, 2))

    monkeypatch.setattr(
        "wifi_pipeline.capture.shutil.which",
        lambda tool: "tool" if tool == "airdecap-ng" else None,
    )
    capture = Capture(
        {
            "output_dir": str(tmp_path),
            "ap_essid": "TestNet",
            "wpa_password": "secret",
        }
    )

    readiness = capture.inspect_wpa_crack_path(str(handshake))

    assert readiness.state == "known_key_supplied"
    assert readiness.handshake_artifact == "valid_handshake"
    assert readiness.crack_ready is True
    assert readiness.decrypt_ready is True
    assert {reason.code for reason in readiness.reasons} >= {"wpa.handshake_valid", "wpa.known_key_supplied"}
    assert "Proceed directly to airdecap-ng or the Wi-Fi strip step." in readiness.next_steps


def test_inspect_wpa_crack_path_reports_wordlist_attack_supported(monkeypatch, tmp_path) -> None:
    handshake = tmp_path / "handshake.cap"
    _write_handshake_capture(handshake, (1, 2))
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("password\n", encoding="utf-8")

    monkeypatch.setattr(
        "wifi_pipeline.capture.shutil.which",
        lambda tool: {
            "aircrack-ng": "/usr/bin/aircrack-ng",
            "airdecap-ng": "/usr/bin/airdecap-ng",
        }.get(tool),
    )
    capture = Capture(
        {
            "output_dir": str(tmp_path),
            "ap_essid": "TestNet",
            "wordlist_path": str(wordlist),
        }
    )

    readiness = capture.inspect_wpa_crack_path(str(handshake))

    assert readiness.state == "known_wordlist_attack_supported"
    assert readiness.handshake_artifact == "valid_handshake"
    assert readiness.crack_ready is True
    assert readiness.status == "supported_with_limits"


def test_inspect_wpa_crack_path_reports_tiny_handshake(monkeypatch, tmp_path) -> None:
    handshake = tmp_path / "handshake.cap"
    handshake.write_bytes(b"x" * 64)
    monkeypatch.setattr(
        "wifi_pipeline.capture.shutil.which",
        lambda tool: "tool" if tool == "airdecap-ng" else None,
    )
    capture = Capture({"output_dir": str(tmp_path), "ap_essid": "TestNet", "wpa_password": "secret"})

    readiness = capture.inspect_wpa_crack_path(str(handshake))

    assert readiness.state == "captured_handshake_insufficient"
    assert readiness.handshake_artifact == "insufficient_capture"
    assert readiness.crack_ready is False
    assert readiness.decrypt_ready is False
    assert readiness.reasons[0].code == "wpa.handshake_too_small"


def test_inspect_wpa_crack_path_reports_missing_prerequisites_with_codes(monkeypatch, tmp_path) -> None:
    handshake = tmp_path / "handshake.cap"
    _write_handshake_capture(handshake, (1, 2))
    monkeypatch.setattr("wifi_pipeline.capture.shutil.which", lambda tool: None)
    capture = Capture({"output_dir": str(tmp_path), "ap_essid": ""})

    readiness = capture.inspect_wpa_crack_path(str(handshake))

    codes = {reason.code for reason in readiness.reasons}

    assert readiness.state == "unsupported"
    assert readiness.handshake_artifact == "valid_handshake"
    assert "wpa.handshake_valid" in codes
    assert "wpa.wordlist_missing" in codes
    assert "wpa.crack_toolchain_missing" in codes
    assert "wpa.decrypt_tool_missing" in codes
    assert "wpa.ap_essid_missing" in codes


def test_inspect_wpa_crack_path_reports_missing_prerequisites_with_guided_detail(monkeypatch, tmp_path) -> None:
    handshake = tmp_path / "handshake.cap"
    _write_handshake_capture(handshake, (1, 2))
    monkeypatch.setattr("wifi_pipeline.capture.shutil.which", lambda tool: None)
    capture = Capture({"output_dir": str(tmp_path), "ap_essid": ""})

    readiness = capture.inspect_wpa_crack_path(str(handshake))

    assert readiness.summary == "The capture exists, but the supported WPA recovery path is not ready."
    assert "a real wordlist_path" in readiness.detail
    assert "aircrack-ng or hashcat" in readiness.detail
    assert "airdecap-ng for the decrypt step" in readiness.detail
    assert "ap_essid for the decrypt step" in readiness.detail
    assert "Set wordlist_path to an existing wordlist file before attempting a supported WPA crack path." in readiness.next_steps
    assert "Install aircrack-ng, or install hashcat plus cap2hccapx/hcxpcapngtool." in readiness.next_steps
    assert "Install airdecap-ng before expecting a supported decrypt path." in readiness.next_steps
    assert "Set ap_essid before expecting decrypted output." in readiness.next_steps


def test_inspect_wpa_crack_path_reports_empty_wordlist(monkeypatch, tmp_path) -> None:
    handshake = tmp_path / "handshake.cap"
    _write_handshake_capture(handshake, (1, 2))
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        "wifi_pipeline.capture.shutil.which",
        lambda tool: {
            "aircrack-ng": "/usr/bin/aircrack-ng",
            "airdecap-ng": "/usr/bin/airdecap-ng",
        }.get(tool),
    )
    capture = Capture(
        {
            "output_dir": str(tmp_path),
            "ap_essid": "TestNet",
            "wordlist_path": str(wordlist),
        }
    )

    readiness = capture.inspect_wpa_crack_path(str(handshake))

    codes = {reason.code for reason in readiness.reasons}
    assert readiness.state == "unsupported"
    assert readiness.crack_ready is False
    assert "wpa.wordlist_empty" in codes


def test_inspect_wpa_crack_path_reports_hashcat_converter_missing(monkeypatch, tmp_path) -> None:
    handshake = tmp_path / "handshake.cap"
    _write_handshake_capture(handshake, (1, 2))
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("password\n", encoding="utf-8")
    monkeypatch.setattr(
        "wifi_pipeline.capture.shutil.which",
        lambda tool: {
            "hashcat": "/usr/bin/hashcat",
            "airdecap-ng": "/usr/bin/airdecap-ng",
        }.get(tool),
    )
    capture = Capture(
        {
            "output_dir": str(tmp_path),
            "ap_essid": "TestNet",
            "wordlist_path": str(wordlist),
        }
    )

    readiness = capture.inspect_wpa_crack_path(str(handshake))

    codes = {reason.code for reason in readiness.reasons}
    assert readiness.state == "unsupported"
    assert readiness.crack_ready is False
    assert "wpa.hashcat_converter_missing" in codes
    assert "wpa.aircrack_missing" in codes


def test_inspect_wpa_crack_path_reports_partial_handshake(monkeypatch, tmp_path) -> None:
    handshake = tmp_path / "partial.cap"
    _write_handshake_capture(handshake, (1,))
    monkeypatch.setattr("wifi_pipeline.capture.shutil.which", lambda tool: None)
    capture = Capture({"output_dir": str(tmp_path)})

    readiness = capture.inspect_wpa_crack_path(str(handshake))

    assert readiness.state == "unsupported"
    assert readiness.handshake_artifact == "partial_handshake"
    assert readiness.crack_ready is False
    assert readiness.reasons[0].code == "wpa.handshake_partial"
    assert "Re-capture until both AP and client handshake messages are visible." in readiness.next_steps


def test_inspect_wpa_crack_path_reports_pmkid_only(monkeypatch, tmp_path) -> None:
    handshake = tmp_path / "pmkid.cap"
    _write_pmkid_capture(handshake)
    monkeypatch.setattr("wifi_pipeline.capture.shutil.which", lambda tool: None)
    capture = Capture({"output_dir": str(tmp_path)})

    readiness = capture.inspect_wpa_crack_path(str(handshake))

    assert readiness.state == "unsupported"
    assert readiness.handshake_artifact == "pmkid_only"
    assert readiness.crack_ready is False
    codes = {reason.code for reason in readiness.reasons}
    assert "wpa.pmkid_only" in codes
    assert "wpa.supported_path_requires_handshake" in codes


def test_inspect_wpa_crack_path_reports_pmkid_only_with_clear_failure_text(monkeypatch, tmp_path) -> None:
    handshake = tmp_path / "pmkid.cap"
    _write_pmkid_capture(handshake)
    monkeypatch.setattr("wifi_pipeline.capture.shutil.which", lambda tool: None)
    capture = Capture({"output_dir": str(tmp_path)})

    readiness = capture.inspect_wpa_crack_path(str(handshake))

    assert readiness.summary == "The capture contains PMKID evidence, but the current supported path still needs a full WPA handshake."
    assert "The current crack/decrypt flow only treats full WPA handshakes as ready for supported recovery." in readiness.detail
    assert "Capture a full WPA handshake before expecting the supported recovery path to be ready." in readiness.next_steps


def test_inspect_wpa_crack_path_requires_valid_handshake_for_decrypt(monkeypatch, tmp_path) -> None:
    handshake = tmp_path / "pmkid.cap"
    _write_pmkid_capture(handshake)
    monkeypatch.setattr(
        "wifi_pipeline.capture.shutil.which",
        lambda tool: "tool" if tool == "airdecap-ng" else None,
    )
    capture = Capture({"output_dir": str(tmp_path), "ap_essid": "TestNet", "wpa_password": "secret"})

    readiness = capture.inspect_wpa_crack_path(str(handshake))

    assert readiness.handshake_artifact == "pmkid_only"
    assert readiness.decrypt_ready is False
    assert readiness.status == "unsupported"


def test_inspect_wpa_crack_path_reports_no_usable_artifact(monkeypatch, tmp_path) -> None:
    handshake = tmp_path / "noise.cap"
    handshake.write_bytes(b"x" * 4096)
    monkeypatch.setattr("wifi_pipeline.capture.shutil.which", lambda tool: None)
    capture = Capture({"output_dir": str(tmp_path)})

    readiness = capture.inspect_wpa_crack_path(str(handshake))

    assert readiness.state == "unsupported"
    assert readiness.handshake_artifact == "no_usable_artifact"
    assert readiness.crack_ready is False
    assert readiness.reasons[0].code == "wpa.no_usable_artifact"


def test_inspect_wpa_crack_path_reports_target_bssid_not_observed(monkeypatch, tmp_path) -> None:
    handshake = tmp_path / "handshake.cap"
    _write_handshake_capture(handshake, (1, 2), ap="66:77:88:99:aa:bb")
    monkeypatch.setattr(
        "wifi_pipeline.capture.shutil.which",
        lambda tool: "tool" if tool == "airdecap-ng" else None,
    )
    capture = Capture(
        {
            "output_dir": str(tmp_path),
            "ap_bssid": "aa:bb:cc:dd:ee:ff",
            "ap_essid": "TestNet",
            "wpa_password": "secret",
        }
    )

    readiness = capture.inspect_wpa_crack_path(str(handshake))

    assert readiness.state == "unsupported"
    assert readiness.handshake_artifact == "valid_handshake"
    assert readiness.crack_ready is False
    assert readiness.decrypt_ready is False
    assert "wpa.capture_target_not_observed" in {reason.code for reason in readiness.reasons}


def test_inspect_wpa_crack_path_reports_non_80211_capture(monkeypatch, tmp_path) -> None:
    capture_file = tmp_path / "ethernet.cap"
    _write_non_80211_capture(capture_file)
    monkeypatch.setattr("wifi_pipeline.capture.shutil.which", lambda tool: None)
    capture = Capture({"output_dir": str(tmp_path)})

    readiness = capture.inspect_wpa_crack_path(str(capture_file))

    codes = {reason.code for reason in readiness.reasons}
    assert readiness.state == "unsupported"
    assert readiness.handshake_artifact == "no_usable_artifact"
    assert "wpa.capture_not_80211" in codes
    assert "wpa.no_usable_artifact" in codes


def test_inspect_wpa_crack_path_reports_missing_airodump_target_settings(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("wifi_pipeline.capture.shutil.which", lambda tool: None)
    capture = Capture({"output_dir": str(tmp_path), "monitor_method": "airodump"})

    readiness = capture.inspect_wpa_crack_path(None)

    codes = {reason.code for reason in readiness.reasons}
    assert readiness.state == "unsupported"
    assert "wpa.handshake_missing" in codes
    assert "wpa.capture_bssid_missing" in codes
    assert "wpa.capture_channel_missing" in codes
    assert any("Set ap_bssid" in step for step in readiness.next_steps)
    assert any("Set ap_channel" in step for step in readiness.next_steps)


def test_print_wpa_crack_status_emits_failure_summary_detail_and_next_steps(monkeypatch, capsys) -> None:
    readiness = WPACrackReadiness(
        state="unsupported",
        status="unsupported",
        handshake_cap="capture.cap",
        handshake_artifact="partial_handshake",
        crack_ready=False,
        decrypt_ready=False,
        summary="Only a partial WPA handshake is present.",
        detail="Detected EAPOL frames, but only one side of the exchange is visible.",
        next_steps=(
            "Re-capture until both AP and client handshake messages are visible.",
            "Set ap_bssid before expecting the targeted airodump-ng retry path to be ready.",
        ),
    )
    monkeypatch.setattr(Capture, "inspect_wpa_crack_path", lambda self, handshake_cap=None: readiness)

    result = Capture({"output_dir": "."}).print_wpa_crack_status("capture.cap")
    output = capsys.readouterr().out

    assert result is readiness
    assert "WPA Crack Readiness" in output
    assert "State: unsupported" in output
    assert "Status: unsupported" in output
    assert "Handshake: capture.cap" in output
    assert "Artifact: partial_handshake" in output
    assert "Only a partial WPA handshake is present." in output
    assert "Detected EAPOL frames, but only one side of the exchange is visible." in output
    assert "Next: Re-capture until both AP and client handshake messages are visible." in output
    assert "Next: Set ap_bssid before expecting the targeted airodump-ng retry path to be ready." in output


def test_crack_and_decrypt_fails_early_when_decrypt_prereqs_missing(monkeypatch, tmp_path) -> None:
    handshake = tmp_path / "handshake.cap"
    _write_handshake_capture(handshake, (1, 2))
    capture = Capture({"output_dir": str(tmp_path), "wpa_password": "secret", "ap_essid": ""})

    monkeypatch.setattr("wifi_pipeline.capture.shutil.which", lambda tool: None)
    monkeypatch.setattr(Capture, "strip_wifi_layer", lambda self, pcap_path=None: "should-not-run")

    result = capture.crack_and_decrypt(str(handshake))

    assert result is None


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
