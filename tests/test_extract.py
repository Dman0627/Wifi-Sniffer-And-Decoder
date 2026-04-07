from __future__ import annotations

import json

from wifi_pipeline.extract import (
    FlowAssemblyResult,
    PacketPayload,
    PacketRecord,
    StreamExtractor,
    UnitizedStream,
    _flow_id,
    _safe_slug,
    _stream_id,
)


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


def test_hint_stream_protocols_classifies_reassembly_modes(tmp_path) -> None:
    extractor = StreamExtractor({"output_dir": str(tmp_path)})
    assembly = FlowAssemblyResult(
        tcp_streams={},
        udp_streams={
            "udp-rtp": [
                PacketPayload(record=_make_record(1, payload_length=1, rtp_sequence=1, rtp_timestamp=9000), payload=b"A"),
                PacketPayload(record=_make_record(2, payload_length=1, rtp_sequence=2, rtp_timestamp=9000), payload=b"B"),
            ]
        },
        other_streams={
            "icmp-raw": [
                PacketPayload(record=_make_record(3, protocol="icmp", stream_id="icmp-raw", flow_id="icmp-flow", payload_length=3), payload=b"raw")
            ]
        },
        control_events=[],
        selection_scope="configured_target",
    )

    hints = extractor._hint_stream_protocols(assembly)

    assert hints["udp-rtp"].reassembly == "rtp_access_unit"
    assert "hint:rtp" in hints["udp-rtp"].hint_tags
    assert hints["icmp-raw"].reassembly == "raw_datagram"
    assert "hint:raw_datagram" in hints["icmp-raw"].hint_tags


def test_rank_streams_keeps_protocol_group_order(tmp_path) -> None:
    extractor = StreamExtractor({"output_dir": str(tmp_path)})
    tcp_hint = extractor._hint_stream_protocol(
        "tcp:stream",
        [PacketPayload(record=_make_record(1, protocol="tcp", stream_id="tcp:stream", flow_id="tcp-flow", payload_length=3, tcp_seq=1), payload=b"tcp")],
    )
    udp_hint = extractor._hint_stream_protocol(
        "udp:stream",
        [PacketPayload(record=_make_record(2, protocol="udp", stream_id="udp:stream", flow_id="udp-flow", payload_length=3), payload=b"udp")],
    )
    other_hint = extractor._hint_stream_protocol(
        "icmp:stream",
        [PacketPayload(record=_make_record(3, protocol="icmp", stream_id="icmp:stream", flow_id="icmp-flow", payload_length=3), payload=b"icmp")],
    )

    ranked = extractor._rank_streams(
        [
            UnitizedStream(hint=other_hint, summary={"stream_id": "icmp:stream"}, units=[]),
            UnitizedStream(hint=udp_hint, summary={"stream_id": "udp:stream"}, units=[]),
            UnitizedStream(hint=tcp_hint, summary={"stream_id": "tcp:stream"}, units=[]),
        ]
    )

    assert [item.summary["stream_id"] for item in ranked] == ["tcp:stream", "udp:stream", "icmp:stream"]


def test_hint_stream_protocols_adds_protocol_specific_tags(tmp_path) -> None:
    extractor = StreamExtractor({"output_dir": str(tmp_path)})
    mpegts_payload = bytes([0x47]) + (b"\x00" * 187)
    assembly = FlowAssemblyResult(
        tcp_streams={
            "tcp-rtsp": [
                PacketPayload(
                    record=_make_record(1, protocol="tcp", stream_id="tcp-rtsp", flow_id="tcp-rtsp-flow", payload_length=48, tcp_seq=1),
                    payload=b"DESCRIBE rtsp://camera/stream RTSP/1.0\r\nCSeq: 1\r\n\r\n",
                )
            ],
            "tcp-http": [
                PacketPayload(
                    record=_make_record(2, protocol="tcp", stream_id="tcp-http", flow_id="tcp-http-flow", payload_length=37, tcp_seq=1),
                    payload=b"GET /video HTTP/1.1\r\nHost: example\r\n\r\n",
                )
            ],
            "tcp-png": [
                PacketPayload(
                    record=_make_record(3, protocol="tcp", stream_id="tcp-png", flow_id="tcp-png-flow", payload_length=16, tcp_seq=1),
                    payload=b"\x89PNG\r\n\x1a\npayload",
                )
            ],
        },
        udp_streams={
            "udp-mpegts": [
                PacketPayload(
                    record=_make_record(4, protocol="udp", stream_id="udp-mpegts", flow_id="udp-mpegts-flow", payload_length=len(mpegts_payload)),
                    payload=mpegts_payload,
                )
            ]
        },
        other_streams={},
        control_events=[],
        selection_scope="configured_target",
    )

    hints = extractor._hint_stream_protocols(assembly)

    assert "hint:rtsp_control" in hints["tcp-rtsp"].hint_tags
    assert "hint:text" in hints["tcp-rtsp"].hint_tags
    assert "hint:http_text" in hints["tcp-http"].hint_tags
    assert "hint:text" in hints["tcp-http"].hint_tags
    assert "hint:mpegts" in hints["udp-mpegts"].hint_tags
    assert "signature:mpegts_packet" in hints["udp-mpegts"].hint_tags
    assert "family:video" in hints["udp-mpegts"].hint_tags
    assert "signature:png_image" in hints["tcp-png"].hint_tags
    assert "family:image" in hints["tcp-png"].hint_tags


def test_unitize_stream_attaches_hint_metadata_to_summary(tmp_path) -> None:
    extractor = StreamExtractor({"output_dir": str(tmp_path)})
    extractor.stream_dir.mkdir(parents=True, exist_ok=True)
    extractor.unit_dir.mkdir(parents=True, exist_ok=True)
    packets = [
        PacketPayload(
            record=_make_record(1, protocol="tcp", stream_id="tcp-http", flow_id="tcp-http-flow", payload_length=37, tcp_seq=1),
            payload=b"GET /video HTTP/1.1\r\nHost: example\r\n\r\n",
        )
    ]

    hint = extractor._hint_stream_protocol("tcp-http", packets)
    unitized = extractor._unitize_stream(1, "tcp-http", packets, hint)

    assert "hint:http_text" in unitized.summary["hint_tags"]
    assert "http_text" in unitized.summary["protocol_hints"]
    assert "text" in unitized.summary["payload_family_hints"]
    assert unitized.summary["signature_hints"] == []


def test_rank_streams_prefers_coherent_signature_rich_stream(tmp_path) -> None:
    extractor = StreamExtractor({"output_dir": str(tmp_path)})
    extractor.stream_dir.mkdir(parents=True, exist_ok=True)
    extractor.unit_dir.mkdir(parents=True, exist_ok=True)

    mpegts_payload = bytes([0x47]) + (b"\x00" * 187)
    strong_packets = [
        PacketPayload(
            record=_make_record(
                1,
                protocol="udp",
                stream_id="udp-strong",
                flow_id="udp-strong-flow",
                payload_length=len(mpegts_payload),
                rtp_sequence=1,
                rtp_timestamp=9000,
            ),
            payload=mpegts_payload,
        ),
        PacketPayload(
            record=_make_record(
                2,
                protocol="udp",
                stream_id="udp-strong",
                flow_id="udp-strong-flow",
                payload_length=len(mpegts_payload),
                rtp_sequence=2,
                rtp_timestamp=9000,
            ),
            payload=mpegts_payload,
        ),
        PacketPayload(
            record=_make_record(
                3,
                protocol="udp",
                stream_id="udp-strong",
                flow_id="udp-strong-flow",
                payload_length=len(mpegts_payload),
                rtp_sequence=3,
                rtp_timestamp=9000,
            ),
            payload=mpegts_payload,
        ),
    ]
    weak_packets = [
        PacketPayload(
            record=_make_record(4, protocol="udp", stream_id="udp-weak", flow_id="udp-weak-flow", payload_length=12),
            payload=b"\x10\x20\x30opaque",
        ),
        PacketPayload(
            record=_make_record(5, protocol="udp", stream_id="udp-weak", flow_id="udp-weak-flow", payload_length=11),
            payload=b"\x99\xaa\xbbnoise",
        ),
    ]

    strong_hint = extractor._hint_stream_protocol("udp-strong", strong_packets)
    weak_hint = extractor._hint_stream_protocol("udp-weak", weak_packets)
    ranked = extractor._rank_streams(
        [
            extractor._unitize_stream(1, "udp-weak", weak_packets, weak_hint),
            extractor._unitize_stream(2, "udp-strong", strong_packets, strong_hint),
        ]
    )

    assert ranked[0].summary["stream_id"] == "udp-strong"
    assert ranked[0].summary["ranking_score"] > ranked[1].summary["ranking_score"]
    assert ranked[0].summary["ranking_features"]["continuity_quality"] >= 0.9
    assert ranked[0].summary["ranking_features"]["magic_signature_score"] > ranked[1].summary["ranking_features"]["magic_signature_score"]
    assert "magic bytes or known payload signatures were recognized" in ranked[0].summary["ranking_reasons"]
    assert ranked[0].summary["candidate_metadata"]["signal_strength"] in {"mixed", "strong"}
    assert ranked[0].summary["candidate_metadata"]["top_contributors"][0]["feature"] in {
        "framing_quality",
        "magic_signature_score",
        "continuity_quality",
        "byte_score",
    }
    assert ranked[1].summary["candidate_metadata"]["signal_strength"] == "weak"
    assert "known payload signatures are still sparse" in ranked[1].summary["candidate_metadata"]["negative_signals"]
    assert ranked[1].summary["ranking_weaknesses"] == ranked[1].summary["candidate_metadata"]["negative_signals"]


def test_rank_streams_includes_corpus_similarity(tmp_path, monkeypatch) -> None:
    extractor = StreamExtractor({"output_dir": str(tmp_path)})
    extractor.stream_dir.mkdir(parents=True, exist_ok=True)
    extractor.unit_dir.mkdir(parents=True, exist_ok=True)

    tcp_packets = [
        PacketPayload(
            record=_make_record(1, protocol="tcp", stream_id="tcp-http", flow_id="tcp-http-flow", payload_length=37, tcp_seq=1),
            payload=b"GET /video HTTP/1.1\r\nHost: example\r\n\r\n",
        )
    ]
    udp_packets = [
        PacketPayload(
            record=_make_record(2, protocol="udp", stream_id="udp-opaque", flow_id="udp-opaque-flow", payload_length=8),
            payload=b"\x01\x02\x03\x04\x05\x06\x07\x08",
        )
    ]

    def fake_find_matches(self, manifest, stream_row, limit=5):
        if stream_row.get("stream_id") == "tcp-http":
            return [
                {
                    "entry_id": "entry-1",
                    "similarity": 0.91,
                    "reasons": ["sample prefixes overlap"],
                    "candidate_class": "recognized_text_candidate",
                    "dominant_unit_type": "http_text",
                    "candidate_material_available": False,
                }
            ]
        return []

    monkeypatch.setattr("wifi_pipeline.extract.CorpusStore.find_matches", fake_find_matches)

    ranked = extractor._rank_streams(
        [
            extractor._unitize_stream(1, "udp-opaque", udp_packets, extractor._hint_stream_protocol("udp-opaque", udp_packets)),
            extractor._unitize_stream(2, "tcp-http", tcp_packets, extractor._hint_stream_protocol("tcp-http", tcp_packets)),
        ]
    )

    top = ranked[0].summary
    assert top["stream_id"] == "tcp-http"
    assert top["corpus_similarity"] == 0.91
    assert top["corpus_match"]["entry_id"] == "entry-1"
    assert "stream is similar to archived corpus material" in top["ranking_reasons"]
    assert top["candidate_metadata"]["evidence"]["corpus_match"]["entry_id"] == "entry-1"
    assert any(
        item["feature"] == "corpus_similarity" and item["status"] == "strong"
        for item in top["candidate_metadata"]["feature_breakdown"]
    )


def test_rank_streams_adds_report_friendly_candidate_metadata(tmp_path) -> None:
    extractor = StreamExtractor({"output_dir": str(tmp_path)})
    extractor.stream_dir.mkdir(parents=True, exist_ok=True)
    extractor.unit_dir.mkdir(parents=True, exist_ok=True)

    packets = [
        PacketPayload(
            record=_make_record(1, protocol="tcp", stream_id="tcp-http", flow_id="tcp-http-flow", payload_length=37, tcp_seq=1),
            payload=b"GET /video HTTP/1.1\r\nHost: example\r\n\r\n",
        ),
        PacketPayload(
            record=_make_record(2, protocol="tcp", stream_id="tcp-http", flow_id="tcp-http-flow", payload_length=33, tcp_seq=38),
            payload=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        ),
    ]

    ranked = extractor._rank_streams(
        [
            extractor._unitize_stream(1, "tcp-http", packets, extractor._hint_stream_protocol("tcp-http", packets)),
        ]
    )

    summary = ranked[0].summary
    metadata = summary["candidate_metadata"]

    assert metadata["signal_strength"] in {"mixed", "strong"}
    assert metadata["evidence"]["dominant_unit_type"] == "http_text"
    assert metadata["evidence"]["protocol_hints"] == ["http_text", "text"]
    assert any(item["feature"] == "framing_quality" for item in metadata["feature_breakdown"])
    assert any("payload volume" in item["label"] for item in metadata["feature_breakdown"])
    assert metadata["positive_signals"]
    assert metadata["negative_signals"]


def test_rank_streams_treats_preferred_stream_config_as_pinned_feedback(tmp_path) -> None:
    extractor = StreamExtractor({"output_dir": str(tmp_path), "preferred_stream_id": "tcp-http"})
    extractor.stream_dir.mkdir(parents=True, exist_ok=True)
    extractor.unit_dir.mkdir(parents=True, exist_ok=True)

    packets = [
        PacketPayload(
            record=_make_record(1, protocol="tcp", stream_id="tcp-http", flow_id="tcp-http-flow", payload_length=37, tcp_seq=1),
            payload=b"GET /video HTTP/1.1\r\nHost: example\r\n\r\n",
        )
    ]

    ranked = extractor._rank_streams(
        [
            extractor._unitize_stream(1, "tcp-http", packets, extractor._hint_stream_protocol("tcp-http", packets)),
        ]
    )

    summary = ranked[0].summary
    assert summary["feedback_state"] == "pinned"
    assert summary["feedback_adjustment"] > 0
    assert summary["feedback_matches"][0]["source"] == "config_preferred_stream_id"
    assert summary["ranking_reasons"][0] == "configured preferred stream pins this candidate"


def test_prefer_feedback_reuses_matching_stream_shape_on_later_run(tmp_path) -> None:
    extractor = StreamExtractor({"output_dir": str(tmp_path)})
    extractor.stream_dir.mkdir(parents=True, exist_ok=True)
    extractor.unit_dir.mkdir(parents=True, exist_ok=True)

    first_packets = [
        PacketPayload(
            record=_make_record(1, protocol="tcp", stream_id="tcp-http-a", flow_id="tcp-http-a-flow", payload_length=37, tcp_seq=1),
            payload=b"GET /video HTTP/1.1\r\nHost: example\r\n\r\n",
        )
    ]
    first_summary = extractor._unitize_stream(
        1,
        "tcp-http-a",
        first_packets,
        extractor._hint_stream_protocol("tcp-http-a", first_packets),
    ).summary
    rule = extractor.remember_candidate_feedback(first_summary, "prefer", note="Prefer HTTP control-like streams.")

    later_extractor = StreamExtractor({"output_dir": str(tmp_path)})
    later_extractor.stream_dir.mkdir(parents=True, exist_ok=True)
    later_extractor.unit_dir.mkdir(parents=True, exist_ok=True)
    later_packets = [
        PacketPayload(
            record=_make_record(2, protocol="tcp", stream_id="tcp-http-b", flow_id="tcp-http-b-flow", payload_length=38, tcp_seq=1),
            payload=b"GET /next HTTP/1.1\r\nHost: example\r\n\r\n",
        )
    ]
    weak_packets = [
        PacketPayload(
            record=_make_record(3, protocol="udp", stream_id="udp-opaque-b", flow_id="udp-opaque-b-flow", payload_length=8),
            payload=b"\x01\x02\x03\x04\x05\x06\x07\x08",
        )
    ]

    ranked = later_extractor._rank_streams(
        [
            later_extractor._unitize_stream(
                1,
                "udp-opaque-b",
                weak_packets,
                later_extractor._hint_stream_protocol("udp-opaque-b", weak_packets),
            ),
            later_extractor._unitize_stream(
                2,
                "tcp-http-b",
                later_packets,
                later_extractor._hint_stream_protocol("tcp-http-b", later_packets),
            ),
        ]
    )

    feedback_store = json.loads(later_extractor.feedback_path.read_text(encoding="utf-8"))
    assert rule["action"] == "prefer"
    assert feedback_store["rules"][0]["stream_id"] == "tcp-http-a"
    assert ranked[0].summary["stream_id"] == "tcp-http-b"
    assert ranked[0].summary["feedback_state"] == "preferred"
    assert ranked[0].summary["feedback_adjustment"] > 0
    assert ranked[0].summary["feedback_reason"] == "Prefer HTTP control-like streams."
    assert ranked[0].summary["candidate_metadata"]["evidence"]["feedback_state"] == "preferred"


def test_reject_feedback_penalizes_matching_stream_on_later_run(tmp_path) -> None:
    extractor = StreamExtractor({"output_dir": str(tmp_path)})
    extractor.stream_dir.mkdir(parents=True, exist_ok=True)
    extractor.unit_dir.mkdir(parents=True, exist_ok=True)

    opaque_packets = [
        PacketPayload(
            record=_make_record(1, protocol="udp", stream_id="udp-opaque-a", flow_id="udp-opaque-a-flow", payload_length=8),
            payload=b"\x01\x02\x03\x04\x05\x06\x07\x08",
        )
    ]
    opaque_summary = extractor._unitize_stream(
        1,
        "udp-opaque-a",
        opaque_packets,
        extractor._hint_stream_protocol("udp-opaque-a", opaque_packets),
    ).summary
    extractor.remember_candidate_feedback(opaque_summary, "reject", note="Ignore this noisy opaque stream family.")

    later_extractor = StreamExtractor({"output_dir": str(tmp_path)})
    later_extractor.stream_dir.mkdir(parents=True, exist_ok=True)
    later_extractor.unit_dir.mkdir(parents=True, exist_ok=True)
    rejected_packets = [
        PacketPayload(
            record=_make_record(2, protocol="udp", stream_id="udp-opaque-b", flow_id="udp-opaque-b-flow", payload_length=8),
            payload=b"\x09\x08\x07\x06\x05\x04\x03\x02",
        )
    ]
    preferred_packets = [
        PacketPayload(
            record=_make_record(3, protocol="tcp", stream_id="tcp-http-c", flow_id="tcp-http-c-flow", payload_length=37, tcp_seq=1),
            payload=b"GET /video HTTP/1.1\r\nHost: example\r\n\r\n",
        )
    ]

    ranked = later_extractor._rank_streams(
        [
            later_extractor._unitize_stream(
                1,
                "udp-opaque-b",
                rejected_packets,
                later_extractor._hint_stream_protocol("udp-opaque-b", rejected_packets),
            ),
            later_extractor._unitize_stream(
                2,
                "tcp-http-c",
                preferred_packets,
                later_extractor._hint_stream_protocol("tcp-http-c", preferred_packets),
            ),
        ]
    )

    rejected = next(item.summary for item in ranked if item.summary["stream_id"] == "udp-opaque-b")
    assert ranked[0].summary["stream_id"] == "tcp-http-c"
    assert rejected["feedback_state"] == "rejected"
    assert rejected["feedback_adjustment"] < 0
    assert rejected["candidate_metadata"]["evidence"]["feedback_matches"]
    assert "Ignore this noisy opaque stream family." in rejected["ranking_weaknesses"]


def test_extract_persists_ranking_candidate_metadata_and_feedback_in_manifest(tmp_path, monkeypatch) -> None:
    output_dir = tmp_path / "output"
    extractor = StreamExtractor({"output_dir": str(output_dir), "preferred_stream_id": "tcp-http"})
    source = tmp_path / "capture.pcapng"
    source.write_bytes(b"pcap")

    tcp_packets = [
        PacketPayload(
            record=_make_record(1, protocol="tcp", stream_id="tcp-http", flow_id="tcp-http-flow", payload_length=37, tcp_seq=1),
            payload=b"GET /video HTTP/1.1\r\nHost: example\r\n\r\n",
        ),
        PacketPayload(
            record=_make_record(2, protocol="tcp", stream_id="tcp-http", flow_id="tcp-http-flow", payload_length=33, tcp_seq=38),
            payload=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        ),
    ]
    udp_packets = [
        PacketPayload(
            record=_make_record(3, protocol="udp", stream_id="udp-opaque", flow_id="udp-opaque-flow", payload_length=8),
            payload=b"\x01\x02\x03\x04\x05\x06\x07\x08",
        )
    ]

    def fake_read_pcap(self, _pcap_path: str, match_any: bool = False):
        return {"tcp-http": tcp_packets}, {"udp-opaque": udp_packets}, {}, [{"kind": "control", "stream_id": "tcp-http"}]

    monkeypatch.setattr("wifi_pipeline.extract.HAS_SCAPY", True)
    monkeypatch.setattr("wifi_pipeline.extract.CorpusStore.find_matches", lambda self, manifest, stream_row, limit=1: [])
    monkeypatch.setattr(StreamExtractor, "_read_pcap", fake_read_pcap)

    manifest = extractor.extract(str(source))
    saved_manifest = json.loads(extractor.manifest_path.read_text(encoding="utf-8"))

    assert saved_manifest == manifest
    assert manifest["stream_stats"]["total"] == 2
    assert manifest["control_events"] == [{"kind": "control", "stream_id": "tcp-http"}]
    assert manifest["streams"][0]["stream_id"] == "tcp-http"
    assert manifest["streams"][0]["ranking_score"] > manifest["streams"][1]["ranking_score"]
    assert manifest["streams"][0]["candidate_metadata"]["evidence"]["feedback_state"] == "pinned"
    assert manifest["streams"][0]["candidate_metadata"]["evidence"]["feedback_matches"][0]["source"] == "config_preferred_stream_id"
    assert any(
        item["feature"] == "magic_signature_score"
        for item in manifest["streams"][0]["candidate_metadata"]["feature_breakdown"]
    )
    assert manifest["streams"][1]["candidate_metadata"]["signal_strength"] == "weak"


def test_remember_candidate_feedback_by_stream_id_round_trips_from_saved_manifest(tmp_path, monkeypatch) -> None:
    output_dir = tmp_path / "output"
    extractor = StreamExtractor({"output_dir": str(output_dir)})
    source = tmp_path / "capture.pcapng"
    source.write_bytes(b"pcap")

    tcp_packets = [
        PacketPayload(
            record=_make_record(1, protocol="tcp", stream_id="tcp-http", flow_id="tcp-http-flow", payload_length=37, tcp_seq=1),
            payload=b"GET /video HTTP/1.1\r\nHost: example\r\n\r\n",
        )
    ]

    def fake_read_pcap(self, _pcap_path: str, match_any: bool = False):
        return {"tcp-http": tcp_packets}, {}, {}, []

    monkeypatch.setattr("wifi_pipeline.extract.HAS_SCAPY", True)
    monkeypatch.setattr("wifi_pipeline.extract.CorpusStore.find_matches", lambda self, manifest, stream_row, limit=1: [])
    monkeypatch.setattr(StreamExtractor, "_read_pcap", fake_read_pcap)

    extractor.extract(str(source))
    rule = extractor.remember_candidate_feedback_by_stream_id(
        "tcp-http",
        "prefer",
        note="Keep this exact HTTP stream candidate.",
    )

    store = json.loads(extractor.feedback_path.read_text(encoding="utf-8"))
    assert rule["stream_id"] == "tcp-http"
    assert rule["action"] == "prefer"
    assert store["rules"][0]["note"] == "Keep this exact HTTP stream candidate."

    later_extractor = StreamExtractor({"output_dir": str(output_dir)})
    later_extractor.stream_dir.mkdir(parents=True, exist_ok=True)
    later_extractor.unit_dir.mkdir(parents=True, exist_ok=True)
    ranked = later_extractor._rank_streams(
        [
            later_extractor._unitize_stream(
                1,
                "tcp-http",
                tcp_packets,
                later_extractor._hint_stream_protocol("tcp-http", tcp_packets),
            )
        ]
    )

    summary = ranked[0].summary
    assert summary["feedback_state"] == "preferred"
    assert summary["feedback_reason"] == "Keep this exact HTTP stream candidate."
    assert summary["feedback_matches"][0]["exact_stream_id"] is True
    assert summary["candidate_metadata"]["evidence"]["feedback_matches"][0]["source"] == "feedback_store"


def test_extract_applies_saved_reject_feedback_to_manifest_metadata(tmp_path, monkeypatch) -> None:
    output_dir = tmp_path / "output"
    bootstrap_extractor = StreamExtractor({"output_dir": str(output_dir)})
    bootstrap_extractor.stream_dir.mkdir(parents=True, exist_ok=True)
    bootstrap_extractor.unit_dir.mkdir(parents=True, exist_ok=True)

    rejected_seed_packets = [
        PacketPayload(
            record=_make_record(1, protocol="udp", stream_id="udp-opaque-a", flow_id="udp-opaque-a-flow", payload_length=8),
            payload=b"\x01\x02\x03\x04\x05\x06\x07\x08",
        )
    ]
    rejected_seed_summary = bootstrap_extractor._unitize_stream(
        1,
        "udp-opaque-a",
        rejected_seed_packets,
        bootstrap_extractor._hint_stream_protocol("udp-opaque-a", rejected_seed_packets),
    ).summary
    bootstrap_extractor.remember_candidate_feedback(
        rejected_seed_summary,
        "reject",
        note="Ignore opaque UDP noise in later extracts.",
    )

    extractor = StreamExtractor({"output_dir": str(output_dir)})
    source = tmp_path / "capture-later.pcapng"
    source.write_bytes(b"pcap")

    preferred_packets = [
        PacketPayload(
            record=_make_record(2, protocol="tcp", stream_id="tcp-http", flow_id="tcp-http-flow", payload_length=37, tcp_seq=1),
            payload=b"GET /video HTTP/1.1\r\nHost: example\r\n\r\n",
        )
    ]
    rejected_packets = [
        PacketPayload(
            record=_make_record(3, protocol="udp", stream_id="udp-opaque-b", flow_id="udp-opaque-b-flow", payload_length=8),
            payload=b"\x09\x08\x07\x06\x05\x04\x03\x02",
        )
    ]

    def fake_read_pcap(self, _pcap_path: str, match_any: bool = False):
        return {"tcp-http": preferred_packets}, {"udp-opaque-b": rejected_packets}, {}, []

    monkeypatch.setattr("wifi_pipeline.extract.HAS_SCAPY", True)
    monkeypatch.setattr("wifi_pipeline.extract.CorpusStore.find_matches", lambda self, manifest, stream_row, limit=1: [])
    monkeypatch.setattr(StreamExtractor, "_read_pcap", fake_read_pcap)

    manifest = extractor.extract(str(source))

    rejected = next(item for item in manifest["streams"] if item["stream_id"] == "udp-opaque-b")
    assert rejected["feedback_state"] == "rejected"
    assert rejected["feedback_adjustment"] < 0
    assert rejected["candidate_metadata"]["evidence"]["feedback_matches"]
    assert "Ignore opaque UDP noise in later extracts." in rejected["ranking_weaknesses"]


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
