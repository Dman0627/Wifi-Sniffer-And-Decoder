from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from wifi_pipeline.playback import (
    CandidateCipher,
    RtpJitterBuffer,
    _extension_for_hint,
    _handler_for_report,
    infer_replay_hint,
    replay_confidence_summary,
    replay_support_summary,
    reconstruct_from_capture,
)


def test_extension_for_hint() -> None:
    assert _extension_for_hint("json") == ".json"
    assert _extension_for_hint("mpegts") == ".ts"
    assert _extension_for_hint("jpg") == ".jpg"
    assert _extension_for_hint("raw") == ".bin"


def test_infer_replay_hint_fallback() -> None:
    config = {"replay_format_hint": "auto", "video_codec": "raw"}
    report = {"selected_candidate_stream": {"unit_type_counts": {"jpeg_frame": 2}}}
    assert infer_replay_hint(config, report) == "jpeg"


def test_infer_replay_hint_prefers_explicit_config() -> None:
    config = {"replay_format_hint": "png", "video_codec": "raw"}
    report = {"selected_candidate_stream": {"unit_type_counts": {"jpeg_frame": 2}}}
    assert infer_replay_hint(config, report) == "png"


def test_handler_for_report_uses_known_registry_entry() -> None:
    config = {"replay_format_hint": "auto", "video_codec": "raw"}
    report = {
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "unit_type_counts": {"json_text": 3},
        },
        "selected_protocol_support": {
            "replay_hint": "json",
            "dominant_unit_type": "json_text",
        },
    }

    handler = _handler_for_report(config, report)

    assert handler.handler_id == "json"
    assert handler.output_extension == ".json"
    assert handler.output_mode == "text_export"


@pytest.mark.parametrize(
    ("replay_hint", "unit_counts", "expected_handler", "expected_mode"),
    [
        ("mjpeg", {"jpeg_frame": 2}, "jpeg", "image_stream"),
        ("adts", {"aac_audio": 3}, "aac", "audio_stream"),
        ("hevc", {"h265_nal": 4}, "h265", "video_stream"),
        ("gz", {"gzip_archive": 1}, "gzip", "archive_export"),
    ],
)
def test_handler_for_report_resolves_registry_aliases(
    replay_hint: str,
    unit_counts: dict[str, int],
    expected_handler: str,
    expected_mode: str,
) -> None:
    config = {"replay_format_hint": "auto", "video_codec": "raw"}
    report = {
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "unit_type_counts": unit_counts,
        },
        "selected_protocol_support": {
            "replay_hint": replay_hint,
            "dominant_unit_type": next(iter(unit_counts)),
        },
    }

    handler = _handler_for_report(config, report)

    assert handler.handler_id == expected_handler
    assert handler.output_mode == expected_mode


def test_replay_confidence_summary_supported_stream() -> None:
    config = {"replay_format_hint": "auto", "video_codec": "raw"}
    report = {
        "candidate_material": {"mode": "static_xor_candidate", "key_hex": "01"},
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "unit_type_counts": {"mpegts_packet": 3},
            "candidate_metadata": {"signal_strength": "strong"},
        },
        "selected_protocol_support": {
            "dominant_unit_type": "mpegts_packet",
            "replay_level": "high_confidence",
            "replay_hint": "mpegts",
            "detail": "Replay is supported with good confidence for MPEG-TS payloads.",
        },
    }

    confidence = replay_confidence_summary(config, report)

    assert confidence["handler_id"] == "mpegts"
    assert confidence["delivery_mode"] == "stream_replay"
    assert confidence["confidence_label"] == "high_confidence"
    assert confidence["confidence_band"] in {"good", "strong"}
    assert confidence["candidate_material_ready"] is True


def test_replay_confidence_summary_unsupported_export() -> None:
    config = {"replay_format_hint": "png", "video_codec": "raw"}
    report = {
        "candidate_material": {"mode": "keystream_samples", "source": "samples"},
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "unit_type_counts": {"opaque_chunk": 1},
            "candidate_metadata": {"signal_strength": "weak"},
        },
        "selected_protocol_support": {
            "dominant_unit_type": "opaque_chunk",
            "replay_level": "unsupported",
            "replay_hint": "raw",
            "detail": "This protocol family is not in the supported replay registry yet.",
        },
    }

    confidence = replay_confidence_summary(config, report)

    assert confidence["handler_id"] == "raw"
    assert confidence["delivery_mode"] == "raw_artifact_export"
    assert confidence["confidence_label"] == "unsupported_export"
    assert confidence["supported"] is False
    assert confidence["export_only"] is True


def test_replay_confidence_summary_export_handler_without_candidate_material_ready() -> None:
    config = {"replay_format_hint": "auto", "video_codec": "raw"}
    report = {
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "unit_type_counts": {"png_image": 1},
            "candidate_metadata": {"signal_strength": "strong"},
        },
        "selected_protocol_support": {
            "dominant_unit_type": "png_image",
            "replay_level": "guaranteed",
            "replay_hint": "png",
            "detail": "Replay support is guaranteed for recognized PNG image payloads.",
        },
    }

    confidence = replay_confidence_summary(config, report)

    assert confidence["handler_id"] == "png"
    assert confidence["delivery_mode"] == "artifact_export"
    assert confidence["confidence_label"] == "guaranteed_export"
    assert confidence["candidate_material_ready"] is False
    assert confidence["export_only"] is True
    assert "candidate replay material is not ready yet" in confidence["reasons"]


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
    report_payload = json.loads((target_dir / "reconstruction_report.json").read_text(encoding="utf-8"))
    assert report_payload["handler_id"] == "txt"
    assert report_payload["output_mode"] == "text_export"
    assert report_payload["primary_output"].endswith("stream_reconstructed.txt")
    assert report_payload["replay_confidence"]["handler_id"] == "txt"
    assert report_payload["replay_confidence"]["supported"] is True


def test_reconstruct_from_capture_uses_alias_driven_mjpeg_handler(tmp_path) -> None:
    manifest_path = tmp_path / "manifest.json"
    encrypted_one = tmp_path / "unit1.bin"
    encrypted_two = tmp_path / "unit2.bin"
    jpeg_one = b"\xff\xd8\xff\xe0frame-one"
    jpeg_two = b"\xff\xd8\xff\xe0frame-two"
    encrypted_one.write_bytes(bytes(byte ^ 0x01 for byte in jpeg_one))
    encrypted_two.write_bytes(bytes(byte ^ 0x01 for byte in jpeg_two))
    manifest = {
        "units": [
            {
                "stream_id": "stream-1",
                "unit_index": 1,
                "timestamp_start": 1.0,
                "unit_type": "jpeg_frame",
                "file": str(encrypted_one),
            },
            {
                "stream_id": "stream-1",
                "unit_index": 2,
                "timestamp_start": 2.0,
                "unit_type": "jpeg_frame",
                "file": str(encrypted_two),
            },
        ]
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    config = {"output_dir": str(tmp_path), "replay_format_hint": "auto", "video_codec": "raw"}
    report = {
        "candidate_material": {"mode": "static_xor_candidate", "key_hex": "01"},
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "unit_type_counts": {"jpeg_frame": 2},
        },
        "selected_protocol_support": {
            "dominant_unit_type": "jpeg_frame",
            "replay_level": "high_confidence",
            "replay_hint": "mjpeg",
            "detail": "Replay is supported with good confidence for MJPEG payloads.",
        },
    }

    result = reconstruct_from_capture(config, report)

    assert result is not None
    target_dir = Path(result)
    assert (target_dir / "stream_reconstructed.jpg").read_bytes() == jpeg_one + jpeg_two
    reconstruction_report = json.loads((target_dir / "reconstruction_report.json").read_text(encoding="utf-8"))
    assert reconstruction_report["handler_id"] == "jpeg"
    assert reconstruction_report["output_mode"] == "image_stream"
    assert reconstruction_report["primary_output"].endswith("stream_reconstructed.jpg")
    assert reconstruction_report["replay_confidence"]["handler_id"] == "jpeg"


@pytest.mark.parametrize(
    ("unit_type", "payload", "expected_output", "expected_handler", "expected_mode"),
    [
        ("png_image", b"\x89PNG\r\n\x1a\npayload", "image_export.png", "png", "image_export"),
        ("wav_audio", b"RIFF\x08\x00\x00\x00WAVE", "stream_reconstructed.wav", "wav", "audio_stream"),
        ("mpegts_packet", bytes([0x47]) + (b"\x00" * 187), "stream_reconstructed.ts", "mpegts", "video_stream"),
        ("pdf_document", b"%PDF-1.7\npayload", "document_export.pdf", "pdf", "document_export"),
        ("zip_archive", b"PK\x03\x04payload", "archive_export.zip", "zip", "archive_export"),
    ],
)
def test_reconstruct_from_capture_uses_family_specific_handlers(
    tmp_path,
    unit_type: str,
    payload: bytes,
    expected_output: str,
    expected_handler: str,
    expected_mode: str,
) -> None:
    manifest_path = tmp_path / "manifest.json"
    encrypted = tmp_path / "unit1.bin"
    encrypted.write_bytes(bytes(byte ^ 0x01 for byte in payload))
    manifest = {
        "units": [
            {
                "stream_id": "stream-1",
                "unit_index": 1,
                "timestamp_start": 1.0,
                "unit_type": unit_type,
                "file": str(encrypted),
            }
        ]
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    config = {"output_dir": str(tmp_path), "replay_format_hint": "auto", "video_codec": "raw"}
    report = {
        "candidate_material": {"mode": "static_xor_candidate", "key_hex": "01"},
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "unit_type_counts": {unit_type: 1},
        },
    }

    result = reconstruct_from_capture(config, report)

    assert result is not None
    target_dir = Path(result)
    assert (target_dir / expected_output).read_bytes() == payload
    reconstruction_report = json.loads((target_dir / "reconstruction_report.json").read_text(encoding="utf-8"))
    assert reconstruction_report["handler_id"] == expected_handler
    assert reconstruction_report["output_mode"] == expected_mode
    assert reconstruction_report["primary_output"].endswith(expected_output)
    assert reconstruction_report["replay_confidence"]["handler_id"] == expected_handler


def test_replay_support_summary_and_unsupported_reconstruct(tmp_path) -> None:
    manifest_path = tmp_path / "manifest.json"
    encrypted = tmp_path / "unit1.bin"
    encrypted.write_bytes(b"\x01\x02\x03\x04")
    manifest = {
        "units": [
            {
                "stream_id": "stream-1",
                "unit_index": 1,
                "timestamp_start": 1.0,
                "unit_type": "opaque_chunk",
                "file": str(encrypted),
            }
        ]
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    config = {"output_dir": str(tmp_path), "replay_format_hint": "auto", "video_codec": "raw"}
    report = {
        "candidate_material": {"mode": "static_xor_candidate", "key_hex": "01"},
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "unit_type_counts": {"opaque_chunk": 1},
        },
    }

    support = replay_support_summary(report)
    result = reconstruct_from_capture(config, report)

    assert support["replay_level"] == "unsupported"
    assert result is not None
    target_dir = Path(result)
    assert (target_dir / "raw_export.bin").read_bytes() == b"\x00\x03\x02\x05"
    reconstruction_report = json.loads((target_dir / "reconstruction_report.json").read_text(encoding="utf-8"))
    assert reconstruction_report["handler_id"] == "raw"
    assert reconstruction_report["output_mode"] == "raw_export"
    assert reconstruction_report["replay_supported"] is False
    assert reconstruction_report["export_only"] is True
    assert reconstruction_report["support_detail"]
    assert reconstruction_report["replay_confidence"]["confidence_label"] == "unsupported_export"
    assert reconstruction_report["replay_confidence"]["supported"] is False


def test_unsupported_reconstruct_ignores_explicit_non_raw_hint(tmp_path) -> None:
    manifest_path = tmp_path / "manifest.json"
    encrypted = tmp_path / "unit1.bin"
    encrypted.write_bytes(bytes(byte ^ 0x01 for byte in b"\x99opaque"))
    manifest = {
        "units": [
            {
                "stream_id": "stream-1",
                "unit_index": 1,
                "timestamp_start": 1.0,
                "unit_type": "opaque_chunk",
                "file": str(encrypted),
            }
        ]
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    config = {"output_dir": str(tmp_path), "replay_format_hint": "png", "video_codec": "raw"}
    report = {
        "candidate_material": {"mode": "static_xor_candidate", "key_hex": "01"},
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "unit_type_counts": {"opaque_chunk": 1},
        },
    }

    result = reconstruct_from_capture(config, report)

    assert result is not None
    target_dir = Path(result)
    assert (target_dir / "raw_export.bin").exists()
    assert not (target_dir / "image_export.png").exists()
    reconstruction_report = json.loads((target_dir / "reconstruction_report.json").read_text(encoding="utf-8"))
    assert reconstruction_report["handler_id"] == "raw"
    assert reconstruction_report["replay_confidence"]["handler_id"] == "raw"


def test_unsupported_reconstruct_reports_all_exported_units_for_unknown_payloads(tmp_path) -> None:
    manifest_path = tmp_path / "manifest.json"
    encrypted_one = tmp_path / "unit1.bin"
    encrypted_two = tmp_path / "unit2.bin"
    encrypted_one.write_bytes(bytes(byte ^ 0x01 for byte in b"\x10opaque-one"))
    encrypted_two.write_bytes(bytes(byte ^ 0x01 for byte in b"\x20opaque-two"))
    manifest = {
        "units": [
            {
                "stream_id": "stream-1",
                "unit_index": 1,
                "timestamp_start": 1.0,
                "unit_type": "opaque_chunk",
                "file": str(encrypted_one),
            },
            {
                "stream_id": "stream-1",
                "unit_index": 2,
                "timestamp_start": 2.0,
                "unit_type": "opaque_chunk",
                "file": str(encrypted_two),
            },
        ]
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    config = {"output_dir": str(tmp_path), "replay_format_hint": "auto", "video_codec": "raw"}
    report = {
        "candidate_material": {"mode": "static_xor_candidate", "key_hex": "01"},
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "unit_type_counts": {"opaque_chunk": 2},
        },
    }

    result = reconstruct_from_capture(config, report)

    assert result is not None
    target_dir = Path(result)
    reconstruction_report = json.loads((target_dir / "reconstruction_report.json").read_text(encoding="utf-8"))
    assert reconstruction_report["handler_id"] == "raw"
    assert reconstruction_report["unit_count"] == 2
    assert len(reconstruction_report["units"]) == 2
    assert reconstruction_report["units"][0]["path"].endswith("unit_00001.bin")
    assert reconstruction_report["units"][1]["path"].endswith("unit_00002.bin")
    assert reconstruction_report["primary_output"].endswith("raw_export.bin")
