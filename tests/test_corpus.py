from __future__ import annotations

from wifi_pipeline.corpus import CorpusStore


def _manifest_and_stream(tmp_path):
    stream_file = tmp_path / "stream.bin"
    unit_one = tmp_path / "unit1.txt"
    unit_two = tmp_path / "unit2.txt"
    stream_file.write_bytes(b"hello world")
    unit_one.write_bytes(b"hello ")
    unit_two.write_bytes(b"world")
    stream_id = "udp:10.0.0.1:5004>10.0.0.2:5005"
    manifest = {
        "pcap_path": str(tmp_path / "capture.pcapng"),
        "streams": [
            {
                "stream_id": stream_id,
                "flow_id": "udp:10.0.0.1:5004-10.0.0.2:5005",
                "protocol": "udp",
                "src": "10.0.0.1",
                "dst": "10.0.0.2",
                "sport": 5004,
                "dport": 5005,
                "packet_count": 2,
                "byte_count": 11,
                "unit_count": 2,
                "duration_seconds": 1.0,
                "average_payload_length": 5.5,
                "payload_length_stddev": 0.5,
                "packets_per_second": 2.0,
                "bytes_per_second": 11.0,
                "stream_file": str(stream_file),
            }
        ],
        "units": [
            {
                "stream_id": stream_id,
                "unit_index": 1,
                "timestamp_start": 1.0,
                "length": 6,
                "unit_type": "plain_text",
                "file": str(unit_one),
            },
            {
                "stream_id": stream_id,
                "unit_index": 2,
                "timestamp_start": 2.0,
                "length": 5,
                "unit_type": "plain_text",
                "file": str(unit_two),
            },
        ],
    }
    stream_row = {
        "stream_id": stream_id,
        "flow_id": "udp:10.0.0.1:5004-10.0.0.2:5005",
        "protocol": "udp",
        "candidate_class": "recognized_text_candidate",
        "score": 92.0,
        "sport": 5004,
        "dport": 5005,
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "unit_type_counts": {"plain_text": 2},
    }
    return manifest, stream_row


def test_corpus_archive_and_find_matches(tmp_path) -> None:
    store = CorpusStore({"output_dir": str(tmp_path)})
    manifest, stream_row = _manifest_and_stream(tmp_path)

    entry = store.archive_candidate(
        manifest,
        stream_row,
        candidate_material={"mode": "static_xor_candidate", "key_hex": "01"},
    )
    matches = store.find_matches(manifest, stream_row)

    assert entry is not None
    assert entry["candidate_material_available"] is True
    assert store.status()["entry_count"] == 1
    assert matches[0]["similarity"] == 1.0
    assert matches[0]["candidate_material_available"] is True


def test_corpus_archive_deduplicates_existing_streams(tmp_path) -> None:
    store = CorpusStore({"output_dir": str(tmp_path)})
    manifest, stream_row = _manifest_and_stream(tmp_path)

    first = store.archive_candidate(manifest, stream_row)
    second = store.archive_candidate(manifest, stream_row)

    assert first is not None
    assert second is not None
    assert second["seen_count"] == 2
    assert store.status()["entry_count"] == 1
