from __future__ import annotations

import subprocess

from wifi_pipeline.remote import _escape_remote, _is_pattern, _latest_patterns


def test_is_pattern() -> None:
    assert _is_pattern("/tmp/*.pcap")
    assert _is_pattern("/tmp/file?.pcapng")
    assert not _is_pattern("/tmp/file.pcapng")


def test_escape_remote() -> None:
    assert _escape_remote("/tmp/with space/file.pcap") == "/tmp/with\\ space/file.pcap"


def test_latest_patterns() -> None:
    assert _latest_patterns("/tmp/") == ["/tmp/*.pcap*", "/tmp/*.cap*"]
    assert _latest_patterns("/tmp/*.pcap") == ["/tmp/*.pcap"]
    assert _latest_patterns("/tmp/file.pcapng") == []


def test_pull_remote_capture_missing_tools(monkeypatch) -> None:
    def fake_which(_name: str):
        return None

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", fake_which)
    from wifi_pipeline import remote

    result = remote.pull_remote_capture({"remote_host": "x", "remote_path": "/tmp/x.pcap"})
    assert result is None


def test_pull_remote_capture_scps(monkeypatch, tmp_path) -> None:
    def fake_which(_name: str):
        return "C:\\Windows\\System32\\fake.exe"

    def fake_run(cmd, capture_output, text, check):
        if cmd[0] == "ssh":
            return subprocess.CompletedProcess(cmd, 0, stdout="/tmp/test.pcapng\n", stderr="")
        if cmd[0] == "scp":
            dest = cmd[-1]
            tmp_path.joinpath(dest).parent.mkdir(parents=True, exist_ok=True)
            tmp_path.joinpath(dest).write_bytes(b"pcap")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", fake_which)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)
    from wifi_pipeline import remote

    config = {"remote_host": "test@host", "remote_path": "/tmp/", "remote_dest_dir": str(tmp_path)}
    result = remote.pull_remote_capture(config, latest_only=True)
    assert result is not None
    assert result.exists()
