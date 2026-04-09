from __future__ import annotations

import runpy

import pytest


def test_videopipeline_script_exits_with_cli_main_result(monkeypatch) -> None:
    calls: list[str] = []

    def fake_main() -> int:
        calls.append("main")
        return 7

    monkeypatch.setattr("wifi_pipeline.cli.main", fake_main)

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_path("videopipeline.py", run_name="__main__")

    assert calls == ["main"]
    assert excinfo.value.code == 7
