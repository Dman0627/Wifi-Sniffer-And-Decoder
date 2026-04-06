from __future__ import annotations

import argparse

import pytest

from wifi_pipeline import cli


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("extract", ["extract"]),
        ("detect", ["extract", "detect"]),
        ("analyze", ["extract", "detect", "analyze"]),
        ("play", ["extract", "detect", "analyze", "play"]),
        ("all", ["extract", "detect", "analyze", "play"]),
    ],
)
def test_run_after_pull_dispatches_expected_stages(monkeypatch, mode: str, expected: list[str]) -> None:
    calls: list[str] = []

    monkeypatch.setattr(cli, "run_extract", lambda config, pcap: calls.append("extract"))
    monkeypatch.setattr(cli, "run_detect", lambda config, manifest_path=None: calls.append("detect"))
    monkeypatch.setattr(cli, "run_analyze", lambda config, decrypted_dir=None: calls.append("analyze"))
    monkeypatch.setattr(cli, "run_play", lambda config: calls.append("play"))

    cli._run_after_pull({}, "capture.pcapng", mode)

    assert calls == expected


def test_map_legacy_stage_maps_old_commands() -> None:
    args = argparse.Namespace(stage="live", command=None)

    mapped = cli._map_legacy_stage(args)

    assert mapped.command == "play"


def test_build_parser_parses_remote_arguments() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(
        ["remote", "--host", "pi@raspberrypi", "--path", "/tmp/capture.pcapng", "--run", "all"]
    )

    assert args.command == "remote"
    assert args.host == "pi@raspberrypi"
    assert args.run == "all"


def test_run_play_prefers_offline_reconstruction(monkeypatch) -> None:
    report = {
        "candidate_material": {"mode": "static_xor_candidate", "key_hex": "01"},
        "selected_candidate_stream": {"stream_id": "stream-1", "unit_type_counts": {"plain_text": 1}},
    }
    started: list[bool] = []

    class DummyPlayback:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def start(self) -> str:
            started.append(True)
            return "live-output"

    monkeypatch.setattr(cli, "_load_report", lambda config: report)
    monkeypatch.setattr(cli, "infer_replay_hint", lambda config, current_report: "txt")
    monkeypatch.setattr(cli, "reconstruct_from_capture", lambda config, current_report: "offline-output")
    monkeypatch.setattr(cli, "ExperimentalPlayback", DummyPlayback)

    result = cli.run_play({"output_dir": "."})

    assert result == "offline-output"
    assert started == []
