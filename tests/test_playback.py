from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from wifi_pipeline.playback import (
    CandidateCipher,
    RtpJitterBuffer,
    _extension_for_hint,
    infer_replay_hint,
    reconstruct_from_capture,
)


def test_extension_for_hint() -> None:
    assert _extension_for_hint("json") == ".json"
    assert _extension_for_hint("mpegts") == ".ts"
    assert _extension_for_hint("raw") == ".bin"


def test_infer_replay_hint_fallback() -> None:
    config = {"replay_format_hint": "auto", "video_codec": "raw"}
    report = {"selected_candidate_stream": {"unit_type_counts": {"jpeg_frame": 2}}}
    assert infer_replay_hint(config, report) == "jpeg"


def test_infer_replay_hint_prefers_explicit_config() -> None:
    config = {"replay_format_hint": "png", "video_codec": "raw"}
    report = {"selected_candidate_stream": {"unit_type_counts": {"jpeg_frame": 2}}}
    assert infer_replay_hint(config, report) == "png"


def test_candidate_cipher_static_xor_candidate() -> None:
    cipher = CandidateCipher({"mode": "static_xor_candidate", "key_hex": "0102"})
    assert cipher.load() is True
    assert cipher.decrypt(bytes([0x40, 0x40, 0x42])) == b"ABC"


def test_candidate_cipher_keystream_samples_cycle(tmp_path) -> None:
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "one.bin").write_bytes(b"\x01\x02")
    (key_dir / "two.bin").write_bytes(b"\x03")

    cipher = CandidateCipher({"mode": "keystream_samples", "source": str(key_dir)})
    assert cipher.load() is True
    assert cipher.decrypt(b"BC") == b"CA"
    assert cipher.decrypt(b"C") == b"@"


def test_rtp_jitter_buffer_reorders_packets() -> None:
    buffer = RtpJitterBuffer(4)
    header10 = SimpleNamespace(sequence=10)
    header11 = SimpleNamespace(sequence=11)
    header12 = SimpleNamespace(sequence=12)

    assert buffer.push(header10, b"A") == [(header10, b"A")]
    assert buffer.push(header12, b"C") == []
    assert buffer.push(header11, b"B") == [(header11, b"B"), (header12, b"C")]


def test_reconstruct_from_capture_writes_decrypted_units_and_aggregate(tmp_path) -> None:
    output_dir = tmp_path
    manifest_path = output_dir / "manifest.json"
    encrypted_one = output_dir / "unit1.bin"
    encrypted_two = output_dir / "unit2.bin"
    encrypted_one.write_bytes(bytes(byte ^ 0x01 for byte in b"HELLO "))
    encrypted_two.write_bytes(bytes(byte ^ 0x01 for byte in b"WORLD"))
    manifest = {
        "units": [
            {
                "stream_id": "stream-1",
                "unit_index": 1,
                "timestamp_start": 1.0,
                "unit_type": "plain_text",
                "file": str(encrypted_one),
            },
            {
                "stream_id": "stream-1",
                "unit_index": 2,
                "timestamp_start": 2.0,
                "unit_type": "plain_text",
                "file": str(encrypted_two),
            },
        ]
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    config = {"output_dir": str(output_dir), "replay_format_hint": "auto", "video_codec": "raw"}
    report = {
        "candidate_material": {"mode": "static_xor_candidate", "key_hex": "01"},
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "unit_type_counts": {"plain_text": 2},
        },
    }

    result = reconstruct_from_capture(config, report)

    assert result is not None
    target_dir = Path(result)
    assert target_dir.exists()
    assert (target_dir / "unit_00001.txt").read_bytes() == b"HELLO "
    assert (target_dir / "unit_00002.txt").read_bytes() == b"WORLD"
    assert (target_dir / "stream_reconstructed.txt").read_bytes() == b"HELLO WORLD"
