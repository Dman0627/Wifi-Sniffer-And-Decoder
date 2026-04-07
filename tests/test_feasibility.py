from __future__ import annotations

from wifi_pipeline.capture import WPACrackReadiness
from wifi_pipeline.feasibility import (
    evaluate_pipeline_feasibility,
    evaluate_replay_feasibility,
    evaluate_wpa_feasibility,
)
from wifi_pipeline.reasons import make_blocker


def test_evaluate_pipeline_feasibility_blocks_without_report() -> None:
    result = evaluate_pipeline_feasibility({}, None)

    assert result["status"] == "blocked"
    assert "capabilities" in result
    assert result["replay"]["status"] == "blocked"


def test_evaluate_replay_feasibility_ready_for_supported_text_stream() -> None:
    report = {
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "score": 100,
            "byte_count": 4096,
            "unit_type_counts": {"plain_text": 4},
        },
        "selected_protocol_support": {
            "dominant_unit_type": "plain_text",
            "decode_level": "guaranteed",
            "replay_level": "guaranteed",
            "detail": "supported text",
        },
        "candidate_material": {"mode": "static_xor_candidate", "key_hex": "01"},
    }

    result = evaluate_replay_feasibility({"min_candidate_bytes": 1024}, report)

    assert result["status"] == "ready"
    assert result["blockers"] == []


def test_evaluate_replay_feasibility_blocks_unsupported_family() -> None:
    report = {
        "selected_candidate_stream": {
            "stream_id": "stream-1",
            "score": 80,
            "byte_count": 4096,
            "unit_type_counts": {"opaque_chunk": 3},
        },
        "selected_protocol_support": {
            "dominant_unit_type": "opaque_chunk",
            "decode_level": "heuristic",
            "replay_level": "unsupported",
            "detail": "opaque replay is unsupported",
        },
        "candidate_material": {"mode": "static_xor_candidate", "key_hex": "01"},
    }

    result = evaluate_replay_feasibility({"min_candidate_bytes": 1024}, report)

    assert result["status"] == "blocked"
    assert "opaque replay is unsupported" in result["blockers"][0]


def test_evaluate_wpa_feasibility_not_applicable_without_wifi_context() -> None:
    result = evaluate_wpa_feasibility({"output_dir": "."})

    assert result["status"] == "ready"
    assert result["state"] == "not_applicable"


def test_evaluate_wpa_feasibility_reuses_guided_retry_steps(monkeypatch) -> None:
    monkeypatch.setattr(
        "wifi_pipeline.feasibility.Capture.inspect_wpa_crack_path",
        lambda self, handshake_cap=None: WPACrackReadiness(
            state="unsupported",
            status="unsupported",
            handshake_cap=None,
            handshake_artifact="missing",
            crack_ready=False,
            decrypt_ready=False,
            summary="No handshake capture is available yet.",
            detail="Run monitor or point crack/decrypt at a real handshake capture before attempting WPA recovery.",
            reasons=(
                make_blocker(
                    "wpa.handshake_missing",
                    "No handshake capture is available yet.",
                    remediation="Run monitor or point crack/decrypt at a real handshake capture before attempting WPA recovery.",
                ),
            ),
            next_steps=(
                "Run monitor or point crack/decrypt at a real handshake capture before attempting WPA recovery.",
                "Set ap_bssid before expecting the targeted airodump-ng retry path to be ready.",
            ),
        ),
    )

    result = evaluate_wpa_feasibility({"output_dir": ".", "ap_bssid": "00:11:22:33:44:55"})

    assert result["status"] == "blocked"
    assert result["next_steps"] == [
        "Run monitor or point crack/decrypt at a real handshake capture before attempting WPA recovery.",
        "Set ap_bssid before expecting the targeted airodump-ng retry path to be ready.",
    ]


def test_evaluate_wpa_feasibility_preserves_partial_handshake_failure_reporting(monkeypatch) -> None:
    monkeypatch.setattr(
        "wifi_pipeline.feasibility.Capture.inspect_wpa_crack_path",
        lambda self, handshake_cap=None: WPACrackReadiness(
            state="unsupported",
            status="unsupported",
            handshake_cap="partial.cap",
            handshake_artifact="partial_handshake",
            crack_ready=False,
            decrypt_ready=False,
            summary="Only a partial WPA handshake is present.",
            detail="Detected EAPOL key frames, but only one side of the exchange is visible.",
            next_steps=("Re-capture until both AP and client handshake messages are visible.",),
        ),
    )

    result = evaluate_wpa_feasibility({"output_dir": ".", "ap_bssid": "00:11:22:33:44:55"})

    assert result["status"] == "blocked"
    assert result["state"] == "unsupported"
    assert result["handshake_artifact"] == "partial_handshake"
    assert result["summary"] == "Only a partial WPA handshake is present."
    assert result["reasons"] == ["Detected EAPOL key frames, but only one side of the exchange is visible."]
    assert result["next_steps"] == ["Re-capture until both AP and client handshake messages are visible."]


def test_evaluate_wpa_feasibility_maps_supported_with_limits_to_limited(monkeypatch) -> None:
    monkeypatch.setattr(
        "wifi_pipeline.feasibility.Capture.inspect_wpa_crack_path",
        lambda self, handshake_cap=None: WPACrackReadiness(
            state="known_key_supplied",
            status="supported_with_limits",
            handshake_cap="handshake.cap",
            handshake_artifact="valid_handshake",
            crack_ready=True,
            decrypt_ready=False,
            summary="A WPA key is already configured, so cracking is not required.",
            detail="Detected a valid handshake. Known PSK supplied. Decryption still needs ap_essid in lab.json.",
            next_steps=("Finish the remaining decrypt prerequisites, then run the Wi-Fi strip step.",),
        ),
    )

    result = evaluate_wpa_feasibility({"output_dir": ".", "ap_essid": "LabNet"})

    assert result["status"] == "limited"
    assert result["state"] == "known_key_supplied"
    assert result["handshake_artifact"] == "valid_handshake"
    assert result["summary"] == "A WPA key is already configured, so cracking is not required."
    assert result["next_steps"] == ["Finish the remaining decrypt prerequisites, then run the Wi-Fi strip step."]
