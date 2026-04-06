from __future__ import annotations

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
