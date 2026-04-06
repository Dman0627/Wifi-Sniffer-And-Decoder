from __future__ import annotations

from wifi_pipeline.extract import PacketPayload, PacketRecord, StreamExtractor, _flow_id, _safe_slug, _stream_id


def _make_record(
    packet_number: int,
    *,
    protocol: str = "udp",
    stream_id: str = "stream-1",
    flow_id: str = "flow-1",
    payload_length: int = 0,
    tcp_seq: int | None = None,
    rtp_sequence: int | None = None,
    rtp_timestamp: int | None = None,
) -> PacketRecord:
    return PacketRecord(
        packet_number=packet_number,
        timestamp=float(packet_number),
        src="10.0.0.1",
        dst="10.0.0.2",
        sport=5004,
        dport=5005,
        protocol=protocol,
        flow_id=flow_id,
        stream_id=stream_id,
        capture_interface="test0",
        payload_length=payload_length,
        header_stripped=0,
        was_truncated=False,
        tcp_seq=tcp_seq,
        rtp_sequence=rtp_sequence,
        rtp_timestamp=rtp_timestamp,
    )


def test_identifier_helpers() -> None:
    assert _safe_slug("udp:10.0.0.1:5004>10.0.0.2:5005|ssrc=abc") == "udp_10.0.0.1_5004_10.0.0.2_5005_ssrc_abc"
    assert _flow_id("udp", "10.0.0.2", 5005, "10.0.0.1", 5004) == "udp:10.0.0.1:5004-10.0.0.2:5005"
    assert _stream_id("udp", "10.0.0.1", 5004, "10.0.0.2", 5005) == "udp:10.0.0.1:5004>10.0.0.2:5005"


def test_emit_tcp_units_reassembles_overlapping_payloads(tmp_path) -> None:
    extractor = StreamExtractor({"output_dir": str(tmp_path)})
    extractor.stream_dir.mkdir(parents=True, exist_ok=True)
    extractor.unit_dir.mkdir(parents=True, exist_ok=True)
    packets = [
        PacketPayload(
            record=_make_record(1, protocol="tcp", tcp_seq=100, payload_length=3),
            payload=b"HEL",
        ),
        PacketPayload(
            record=_make_record(2, protocol="tcp", tcp_seq=102, payload_length=3),
            payload=b"LLO",
        ),
    ]

    summary, units = extractor._emit_tcp_units(1, "tcp-stream", packets)

    assert summary["byte_count"] == 5
    assert summary["reassembly"] == "tcp_stream"
    assert len(units) == 1
    assert extractor.stream_dir.joinpath("stream_001_tcp-stream.bin").read_bytes() == b"HELLO"


def test_emit_udp_units_groups_rtp_packets_into_access_units(tmp_path) -> None:
    extractor = StreamExtractor({"output_dir": str(tmp_path)})
    extractor.stream_dir.mkdir(parents=True, exist_ok=True)
    extractor.unit_dir.mkdir(parents=True, exist_ok=True)
    packets = [
        PacketPayload(
            record=_make_record(2, payload_length=1, rtp_sequence=2, rtp_timestamp=9000),
            payload=b"B",
        ),
        PacketPayload(
            record=_make_record(1, payload_length=1, rtp_sequence=1, rtp_timestamp=9000),
            payload=b"A",
        ),
    ]

    summary, units = extractor._emit_udp_units(1, "udp-stream", packets)

    assert summary["reassembly"] == "rtp_access_unit"
    assert summary["rtp_packets"] == 2
    assert len(units) == 1
    assert extractor.stream_dir.joinpath("stream_001_udp-stream.bin").read_bytes() == b"AB"


def test_emit_other_units_writes_raw_datagrams(tmp_path) -> None:
    extractor = StreamExtractor({"output_dir": str(tmp_path)})
    extractor.stream_dir.mkdir(parents=True, exist_ok=True)
    extractor.unit_dir.mkdir(parents=True, exist_ok=True)
    packets = [
        PacketPayload(record=_make_record(1, protocol="icmp", payload_length=3), payload=b"one"),
        PacketPayload(record=_make_record(2, protocol="icmp", payload_length=3), payload=b"two"),
    ]

    summary, units = extractor._emit_other_units(1, "icmp-stream", packets)

    assert summary["reassembly"] == "raw_datagram"
    assert len(units) == 2
    assert extractor.stream_dir.joinpath("stream_001_icmp-stream.bin").read_bytes() == b"onetwo"


def test_extract_falls_back_to_all_transport_flows(tmp_path, monkeypatch) -> None:
    output_dir = tmp_path / "output"
    extractor = StreamExtractor({"output_dir": str(output_dir), "protocol": "udp", "video_port": 5004})
    source = tmp_path / "capture.pcapng"
    source.write_bytes(b"pcap")
    packets = [
        PacketPayload(record=_make_record(1, payload_length=4, rtp_sequence=None), payload=b"DATA"),
    ]
    calls: list[bool] = []

    def fake_read_pcap(self, _pcap_path: str, match_any: bool = False):
        calls.append(match_any)
        if not match_any:
            return {}, {}, {}, []
        return {}, {"udp-stream": packets}, {}, []

    monkeypatch.setattr("wifi_pipeline.extract.HAS_SCAPY", True)
    monkeypatch.setattr(StreamExtractor, "_read_pcap", fake_read_pcap)

    manifest = extractor.extract(str(source))

    assert calls == [False, True]
    assert manifest["filters"]["selection_scope"] == "all_transport_flows"
    assert manifest["stream_stats"]["total"] == 1
    assert extractor.manifest_path.exists()
