from __future__ import annotations

import json

from wifi_pipeline.analysis import (
    CryptoAnalyzer,
    FormatDetector,
    _custom_magic_bytes,
    _group_units_by_stream,
    _normalized_hex,
    _rank_candidate_streams,
)


def _write_bytes(tmp_path, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def _sample_manifest(tmp_path) -> dict[str, object]:
    png_path = _write_bytes(tmp_path, "frame.png", b"\x89PNG\r\n\x1a\npayload")
    opaque_path = _write_bytes(tmp_path, "opaque.bin", b"\x01\x02\x03\x04\x05\x06")
    return {
        "streams": [
            {
                "stream_id": "stream-image",
                "flow_id": "flow-image",
                "protocol": "udp",
                "src": "10.0.0.1",
                "dst": "10.0.0.2",
                "sport": 5004,
                "dport": 5005,
                "packet_count": 24,
                "unit_count": 1,
                "byte_count": 8192,
                "duration_seconds": 5.0,
                "average_payload_length": 512.0,
                "payload_length_stddev": 16.0,
                "packets_per_second": 4.8,
                "bytes_per_second": 1638.4,
            },
            {
                "stream_id": "stream-opaque",
                "flow_id": "flow-opaque",
                "protocol": "udp",
                "src": "10.0.0.3",
                "dst": "10.0.0.4",
                "sport": 6000,
                "dport": 6001,
                "packet_count": 10,
                "unit_count": 1,
                "byte_count": 4096,
                "duration_seconds": 1.0,
                "average_payload_length": 400.0,
                "payload_length_stddev": 200.0,
                "packets_per_second": 10.0,
                "bytes_per_second": 4096.0,
            },
        ],
        "units": [
            {
                "stream_id": "stream-image",
                "unit_index": 1,
                "unit_type": "png_image",
                "file": png_path,
            },
            {
                "stream_id": "stream-opaque",
                "unit_index": 2,
                "unit_type": "opaque_chunk",
                "file": opaque_path,
            },
        ],
        "control_events": [],
    }


def test_normalized_hex_and_custom_magic_bytes() -> None:
    assert _normalized_hex("AB cd !!") == "abcd"
    assert _normalized_hex("abc") == ""
    assert _custom_magic_bytes({"custom_magic_hex": "ab cd"}) == b"\xab\xcd"
    assert _custom_magic_bytes({"custom_magic_hex": "xyz"}) == b""


def test_group_units_by_stream() -> None:
    units = [
        {"stream_id": "alpha", "unit_index": 1},
        {"stream_id": "alpha", "unit_index": 2},
        {"stream_id": "beta", "unit_index": 3},
    ]

    grouped = _group_units_by_stream(units)

    assert list(grouped) == ["alpha", "beta"]
    assert [unit["unit_index"] for unit in grouped["alpha"]] == [1, 2]


def test_rank_candidate_streams_prefers_recognized_payloads(tmp_path) -> None:
    manifest = _sample_manifest(tmp_path)

    rows = _rank_candidate_streams(manifest, {"min_candidate_bytes": 1024})

    assert rows[0]["stream_id"] == "stream-image"
    assert rows[0]["candidate_class"] == "recognized_image_candidate"
    assert rows[0]["payload_families"] == ["image"]
    assert rows[0]["score"] > rows[1]["score"]


def test_format_detector_detect_writes_report(tmp_path) -> None:
    output_dir = tmp_path
    manifest = _sample_manifest(tmp_path)
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    detector = FormatDetector({"output_dir": str(output_dir), "min_candidate_bytes": 1024})

    report = detector.detect()

    assert report["selected_candidate_stream"]["stream_id"] == "stream-image"
    assert report["protocol_hits"]["png"] == 1
    assert (output_dir / "detection_report.json").exists()


def test_crypto_analyzer_helper_methods(tmp_path) -> None:
    manifest = _sample_manifest(tmp_path)
    analyzer = CryptoAnalyzer(
        {
            "output_dir": str(tmp_path),
            "min_candidate_bytes": 1024,
            "preferred_stream_id": "stream-opaque",
        }
    )
    encrypted = [
        {
            "length": 12,
            "stream_id": "stream-image",
            "timestamp_start": 1.0,
            "packet_number_start": 100,
            "rtp_timestamp": 500,
        },
        {
            "length": 18,
            "stream_id": "stream-opaque",
            "timestamp_start": 2.0,
            "packet_number_start": 200,
            "rtp_timestamp": 600,
        },
    ]
    decrypted = [
        {
            "length": 12,
            "stream_id": "stream-image",
            "timestamp_start": 1.1,
            "packet_number_start": 101,
            "rtp_timestamp": 500,
        },
        {
            "length": 18,
            "stream_id": "stream-opaque",
            "timestamp_start": 2.1,
            "packet_number_start": 201,
            "rtp_timestamp": 600,
        },
    ]

    aligned = analyzer._align_units(encrypted, decrypted)

    assert len(aligned) == 2
    assert analyzer._xor(b"\x01\x02", b"\x03\x01") == b"\x02\x03"
    assert analyzer._period(b"ABABABAB", max_period=8) == 2
    assert analyzer._selected_stream(manifest)["stream_id"] == "stream-opaque"
