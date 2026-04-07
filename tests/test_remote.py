from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from wifi_pipeline import __version__
from wifi_pipeline.remote import (
    REMOTE_AGENT_PROTOCOL,
    _bootstrap_remote_script,
    _bootstrap_validation_errors,
    _appliance_profile_script,
    _capture_agent_script,
    _ensure_public_key,
    _extract_capture_path,
    _escape_remote,
    _is_pattern,
    _latest_patterns,
    _parse_key_value_output,
    _privileged_capture_runner_script,
    _resolve_remote_install_mode,
    _resolve_remote_install_profile,
    bootstrap_remote_host,
    discover_remote_appliances,
    doctor_remote_host,
    pair_remote_host,
    remote_service_host,
    start_remote_capture,
)


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
    checksum = hashlib.sha256(b"pcap").hexdigest()

    def fake_which(name: str):
        if name in ("ssh", "scp"):
            return "C:\\Windows\\System32\\fake.exe"
        return None

    def fake_run(cmd, capture_output=None, text=None, check=False, **_kwargs):
        if cmd[0] == "ssh":
            remote_cmd = cmd[-1]
            if "ls -t" in remote_cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="/tmp/test.pcapng\n", stderr="")
            if "FILE=" in remote_cmd:
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout=(
                        "file_exists=yes\n"
                        "complete_marker=yes\n"
                        "checksum_file=yes\n"
                        f"checksum_value={checksum}\n"
                        "remote_size_bytes=4\n"
                    ),
                    stderr="",
                )
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")
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


def test_pull_remote_capture_retries_transient_scp_failure(monkeypatch, tmp_path) -> None:
    checksum = hashlib.sha256(b"pcap").hexdigest()
    scp_calls = {"count": 0}

    def fake_which(name: str):
        if name in ("ssh", "scp"):
            return "C:\\Windows\\System32\\fake.exe"
        return None

    def fake_run(cmd, capture_output=None, text=None, check=False, **_kwargs):
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=(
                    "file_exists=yes\n"
                    "complete_marker=yes\n"
                    "checksum_file=yes\n"
                    f"checksum_value={checksum}\n"
                    "remote_size_bytes=4\n"
                ),
                stderr="",
            )
        if cmd[0] == "scp":
            scp_calls["count"] += 1
            if scp_calls["count"] == 1:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="network reset")
            dest = Path(cmd[-1])
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"pcap")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", fake_which)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)
    monkeypatch.setattr("wifi_pipeline.remote.time.sleep", lambda _seconds: None)
    from wifi_pipeline import remote

    result = remote.pull_remote_capture(
        {"remote_host": "test@host", "remote_path": "/tmp/test.pcapng", "remote_dest_dir": str(tmp_path)},
        latest_only=False,
    )

    assert result is not None
    assert result.exists()
    assert scp_calls["count"] == 2
    assert not (tmp_path / "test.pcapng.partial").exists()


def test_pull_remote_capture_uses_temp_file_and_preserves_existing_on_checksum_failure(monkeypatch, tmp_path) -> None:
    final_path = tmp_path / "test.pcapng"
    final_path.write_bytes(b"good")

    def fake_which(name: str):
        if name in ("ssh", "scp"):
            return "C:\\Windows\\System32\\fake.exe"
        return None

    def fake_run(cmd, capture_output=None, text=None, check=False, **_kwargs):
        if cmd[0] == "ssh":
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=(
                    "file_exists=yes\n"
                    "complete_marker=yes\n"
                    "checksum_file=yes\n"
                    "checksum_value=deadbeef\n"
                    "remote_size_bytes=4\n"
                ),
                stderr="",
            )
        if cmd[0] == "scp":
            dest = Path(cmd[-1])
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"pcap")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", fake_which)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)
    from wifi_pipeline import remote

    result = remote.pull_remote_capture(
        {"remote_host": "test@host", "remote_path": "/tmp/test.pcapng", "remote_dest_dir": str(tmp_path)},
        latest_only=False,
    )

    assert result is None
    assert final_path.read_bytes() == b"good"
    assert not (tmp_path / "test.pcapng.partial").exists()


def test_pull_remote_capture_uses_rsync_resume_when_available(monkeypatch, tmp_path) -> None:
    checksum = hashlib.sha256(b"pcap").hexdigest()

    def fake_which(name: str):
        if name in ("ssh", "scp", "rsync"):
            return "C:\\Windows\\System32\\fake.exe"
        return None

    def fake_run(cmd, capture_output=None, text=None, check=False, **_kwargs):
        if cmd[0] == "ssh":
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=(
                    "file_exists=yes\n"
                    "complete_marker=yes\n"
                    "checksum_file=yes\n"
                    f"checksum_value={checksum}\n"
                    "remote_size_bytes=4\n"
                ),
                stderr="",
            )
        if cmd[0] == "rsync":
            dest = Path(cmd[-1])
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"pcap")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", fake_which)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)
    from wifi_pipeline import remote

    result = remote.pull_remote_capture(
        {"remote_host": "test@host", "remote_path": "/tmp/test.pcapng", "remote_dest_dir": str(tmp_path)},
        latest_only=False,
    )

    assert result is not None
    assert result.exists()
    assert result.read_bytes() == b"pcap"
    assert not (tmp_path / "test.pcapng.partial").exists()


def test_pull_remote_capture_retries_transient_rsync_failure(monkeypatch, tmp_path) -> None:
    checksum = hashlib.sha256(b"pcap").hexdigest()
    rsync_calls = {"count": 0}

    def fake_which(name: str):
        if name in ("ssh", "scp", "rsync"):
            return "C:\\Windows\\System32\\fake.exe"
        return None

    def fake_run(cmd, capture_output=None, text=None, check=False, **_kwargs):
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=(
                    '{"data":{"checksum_file":"yes","checksum_value":"'
                    + checksum
                    + '","complete_marker":"yes","file_exists":"yes","remote_size_bytes":"4"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n'
                ),
                stderr="",
            )
        if cmd[0] == "rsync":
            rsync_calls["count"] += 1
            dest = Path(cmd[-1])
            dest.parent.mkdir(parents=True, exist_ok=True)
            if rsync_calls["count"] == 1:
                dest.write_bytes(b"pc")
                return subprocess.CompletedProcess(cmd, 23, stdout="", stderr="connection reset")
            dest.write_bytes(b"pcap")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", fake_which)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)
    monkeypatch.setattr("wifi_pipeline.remote.time.sleep", lambda _seconds: None)
    from wifi_pipeline import remote

    result = remote.pull_remote_capture(
        {"remote_host": "test@host", "remote_path": "/tmp/test.pcapng", "remote_dest_dir": str(tmp_path)},
        latest_only=False,
    )

    assert result is not None
    assert result.exists()
    assert result.read_bytes() == b"pcap"
    assert rsync_calls["count"] == 2
    assert not (tmp_path / "test.pcapng.partial").exists()


def test_pull_remote_capture_rejects_checksum_mismatch(monkeypatch, tmp_path) -> None:
    def fake_which(name: str):
        if name in ("ssh", "scp"):
            return "C:\\Windows\\System32\\fake.exe"
        return None

    def fake_run(cmd, capture_output=None, text=None, check=False, **_kwargs):
        if cmd[0] == "ssh":
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=(
                    "file_exists=yes\n"
                    "complete_marker=yes\n"
                    "checksum_file=yes\n"
                    "checksum_value=deadbeef\n"
                    "remote_size_bytes=4\n"
                ),
                stderr="",
            )
        if cmd[0] == "scp":
            dest = Path(cmd[-1])
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"pcap")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", fake_which)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)
    from wifi_pipeline import remote

    result = remote.pull_remote_capture(
        {"remote_host": "test@host", "remote_path": "/tmp/test.pcapng", "remote_dest_dir": str(tmp_path)},
        latest_only=False,
    )

    assert result is None
    assert not (tmp_path / "test.pcapng").exists()


def test_ensure_public_key_generates_missing_key(monkeypatch, tmp_path) -> None:
    private_key = tmp_path / "id_ed25519"

    def fake_run(cmd, capture_output=None, text=None, check=False, **_kwargs):
        private_key.write_text("private", encoding="utf-8")
        Path(str(private_key) + ".pub").write_text("ssh-ed25519 AAAA test@example", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "ssh-keygen" if name == "ssh-keygen" else None)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = _ensure_public_key(str(private_key), generate_if_missing=True)

    assert result == Path(str(private_key) + ".pub")
    assert result.exists()


def test_pair_remote_host_installs_and_verifies_key(monkeypatch, tmp_path) -> None:
    public_key = tmp_path / "id_ed25519.pub"
    public_key.write_text("ssh-ed25519 AAAA test@example", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(cmd, capture_output=None, text=None, check=False, **_kwargs):
        commands.append(cmd)
        if cmd[-2:] == ["--", "printf", "paired"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="paired", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "ssh" if name == "ssh" else None)
    monkeypatch.setattr("wifi_pipeline.remote._ensure_public_key", lambda identity=None, generate_if_missing=True: public_key)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = pair_remote_host({"remote_host": "pi@raspberrypi"}, create_key=False)

    assert result is True
    assert commands[0][0] == "ssh"
    assert "authorized_keys" in commands[0][-1]


def test_bootstrap_remote_script_contains_capture_helper() -> None:
    script = _bootstrap_remote_script("/home/pi/wifi-pipeline", "/home/pi/wifi-pipeline/captures")

    assert "wifi-pipeline-capture" in script
    assert "wifi-pipeline-service" in script
    assert "wifi-pipeline-agent" in script
    assert "wifi-pipeline-capture-privileged" in script
    assert "complete_marker" in script
    assert "checksum_file" in script
    assert "/etc/sudoers.d/wifi-pipeline-capture" in script
    assert "CAPTURE_DIR=/home/pi/wifi-pipeline/captures" in script
    assert "apt-get install -y tcpdump" in script


def test_privileged_runner_script_hardens_output_path() -> None:
    script = _privileged_capture_runner_script("/home/pi/wifi-pipeline/captures")

    assert 'CAPTURE_DIR="/home/pi/wifi-pipeline/captures"' not in script
    assert "CAPTURE_DIR=/home/pi/wifi-pipeline/captures" in script
    assert 'CAPTURE_DIR_REAL="$(cd "$CAPTURE_DIR" && pwd -P)"' in script
    assert 'OUTPUT_REAL="$(cd "$OUTPUT_PARENT" && pwd -P)/$(basename "$OUTPUT")"' in script
    assert 'output path must stay under $CAPTURE_DIR_REAL' in script


def test_capture_agent_script_exposes_service_and_doctor_commands() -> None:
    script = _capture_agent_script("/home/pi/wifi-pipeline", "/home/pi/wifi-pipeline/captures")

    assert "#!/usr/bin/env bash" in script
    assert 'PROTOCOL="capture-agent/v1"' in script
    assert 'run_service()' in script
    assert 'run_doctor()' in script
    assert 'run_artifact_info()' in script


def test_capture_service_script_tracks_lifecycle_recovery_state() -> None:
    script = _bootstrap_remote_script("/home/pi/wifi-pipeline", "/home/pi/wifi-pipeline/captures")

    assert 'current_boot_id()' in script
    assert 'finalize_lifecycle_state()' in script
    assert 'stale_pid_cleaned=yes' in script
    assert 'last_result=starting' in script
    assert 'boot_id=%s' in script
    assert 'recovery_reason=' in script
    assert 'interrupted_reboot' in script
    assert 'service_status="interrupted"' in script


def test_resolve_remote_install_mode_prefers_bundle_when_available() -> None:
    assert _resolve_remote_install_mode("auto", prefer_bundle=True) == "bundle"
    assert _resolve_remote_install_mode("auto", prefer_bundle=False) == "native"
    assert _resolve_remote_install_mode("bundle", prefer_bundle=False) == "bundle"


def test_resolve_remote_install_profile_defaults_to_appliance() -> None:
    assert _resolve_remote_install_profile(None) == "appliance"
    assert _resolve_remote_install_profile("standard") == "standard"
    assert _resolve_remote_install_profile("bogus") == "appliance"


def test_discover_remote_appliances_uses_health_endpoint(monkeypatch) -> None:
    monkeypatch.setattr("wifi_pipeline.remote._candidate_discovery_hosts", lambda *args, **kwargs: ["192.168.1.10", "192.168.1.20"])
    monkeypatch.setattr(
        "wifi_pipeline.remote._probe_remote_appliance",
        lambda host, **kwargs: {
            "host": host,
            "ssh_target": f"pi@{host}",
            "health_endpoint": f"http://{host}:8741/health",
            "device_name": f"node-{host.rsplit('.', 1)[-1]}",
            "install_profile": "appliance",
            "health_port": "8741",
            "health_path": "/health",
            "control_mode": "agent",
            "agent_protocol": "capture-agent/v1",
            "agent_version": "3.0.0",
            "capture_dir": "/home/pi/wifi-pipeline/captures",
            "service_status": "idle",
            "remote_root": "/home/pi/wifi-pipeline",
            "ssh_user": "pi",
        } if host.endswith(".10") else None,
    )

    results = discover_remote_appliances({}, max_hosts=8)

    assert len(results) == 1
    assert results[0]["ssh_target"] == "pi@192.168.1.10"


def test_probe_remote_appliance_retries_transient_failure(monkeypatch) -> None:
    from wifi_pipeline import remote_discovery

    calls = {"count": 0}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return (
                b'{"protocol":"capture-agent/v1","data":{"agent":"yes","device_name":"pi-node","ssh_user":"pi","agent_version":"3.0.0","remote_root":"/home/pi/wifi-pipeline"}}'
            )

    def fake_urlopen(_endpoint, timeout=None):
        calls["count"] += 1
        if calls["count"] == 1:
            raise remote_discovery.urllib.error.URLError("timed out")
        return FakeResponse()

    monkeypatch.setattr("wifi_pipeline.remote_discovery.urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("wifi_pipeline.remote_discovery.time.sleep", lambda _seconds: None)

    record = remote_discovery._probe_remote_appliance("raspberrypi", health_port=8741, timeout=0.1, user_hint="pi")

    assert record is not None
    assert record["ssh_target"] == "pi@raspberrypi"
    assert calls["count"] == 2


def test_appliance_profile_script_installs_health_endpoint() -> None:
    script = _appliance_profile_script("/home/pi/wifi-pipeline", "/home/pi/wifi-pipeline/captures", health_port=9001)

    assert "wifi-pipeline-health-http" in script
    assert "wifi-pipeline-health.socket" in script
    assert "wifi-pipeline-appliance.service" in script
    assert "HEALTH_PORT=9001" in script
    assert "ListenStream=$HEALTH_PORT" in script


def test_bootstrap_remote_host_prepares_remote_helper(monkeypatch) -> None:
    seen_inputs: list[str] = []

    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if input:
            seen_inputs.append(input)
        if cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=(
                "remote_root=/home/pi/wifi-pipeline\n"
                "capture_dir=/home/pi/wifi-pipeline/captures\n"
                "state_dir=/home/pi/wifi-pipeline/state\n"
                "capture_cmd=/home/pi/wifi-pipeline/bin/wifi-pipeline-capture\n"
                "service_cmd=/home/pi/wifi-pipeline/bin/wifi-pipeline-service\n"
                "agent_cmd=/home/pi/wifi-pipeline/bin/wifi-pipeline-agent\n"
                "privilege_mode=sudoers_runner\n"
                "privileged_runner=/usr/local/bin/wifi-pipeline-capture-privileged\n"
            ),
            stderr="",
        )

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "ssh" if name == "ssh" else None)
    monkeypatch.setattr("wifi_pipeline.remote.pair_remote_host", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        "wifi_pipeline.remote._install_remote_appliance_profile",
        lambda *args, **kwargs: {
            "install_profile": "appliance",
            "health_port": "8741",
            "health_endpoint": "http://0.0.0.0:8741/health",
        },
    )
    monkeypatch.setattr(
        "wifi_pipeline.remote.doctor_remote_host",
        lambda *args, **kwargs: {
            "ok": True,
            "remote": {
                "reachable": True,
                "agent": True,
                "agent_path": "/home/pi/wifi-pipeline/bin/wifi-pipeline-agent",
                "agent_protocol": "capture-agent/v1",
                "agent_version": "3.0.0",
                "helper": True,
                "helper_path": "/home/pi/.local/bin/wifi-pipeline-capture",
                "service": True,
                "service_path": "/home/pi/.local/bin/wifi-pipeline-service",
                "service_status": "idle",
                "privilege_mode": "sudoers_runner",
                "state_dir_exists": True,
                "state_dir_writable": True,
                "remote_root": "/home/pi/wifi-pipeline",
                "capture_dir": "/home/pi/wifi-pipeline/captures",
                "capture_dir_exists": True,
                "capture_dir_writable": True,
                "install_profile": "appliance",
                "health_port": "8741",
                "health_path": "/health",
                "health_endpoint": "http://0.0.0.0:8741/health",
                "health_probe_ok": True,
                "health_protocol": "capture-agent/v1",
                "health_agent_version": "3.0.0",
                "health_socket_enabled": True,
                "health_socket_active": True,
                "appliance_service_enabled": True,
                "appliance_service_active": True,
            },
        },
    )
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = bootstrap_remote_host({"remote_host": "pi@raspberrypi"}, pair=True)

    assert result is not None
    assert result["capture_dir"] == "/home/pi/wifi-pipeline/captures"
    assert result["state_dir"] == "/home/pi/wifi-pipeline/state"
    assert result["service_cmd"] == "/home/pi/wifi-pipeline/bin/wifi-pipeline-service"
    assert result["agent_cmd"] == "/home/pi/wifi-pipeline/bin/wifi-pipeline-agent"
    assert result["install_profile"] == "appliance"
    assert result["health_port"] == "8741"
    assert result["health_endpoint"] == "http://0.0.0.0:8741/health"
    assert result["privilege_mode"] == "sudoers_runner"
    assert result["privileged_runner"] == "/usr/local/bin/wifi-pipeline-capture-privileged"
    assert seen_inputs
    assert "wifi-pipeline-capture" in seen_inputs[0]
    assert "wifi-pipeline-agent" in seen_inputs[0]


def test_bootstrap_remote_host_bundle_mode_uploads_bundle(monkeypatch, tmp_path) -> None:
    uploaded: list[list[str]] = []
    seen_inputs: list[str] = []
    bundle_path = tmp_path / "wifi-pipeline-agent-3.0.0-bundle.tar.gz"
    bundle_path.write_bytes(b"bundle")

    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if input:
            seen_inputs.append(input)
        if cmd[0] == "scp":
            uploaded.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh" and "tar -xzf" in cmd[-1]:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=(
                "remote_root=/home/pi/wifi-pipeline\n"
                "capture_dir=/home/pi/wifi-pipeline/captures\n"
                "state_dir=/home/pi/wifi-pipeline/state\n"
                "agent_cmd=/home/pi/wifi-pipeline/bin/wifi-pipeline-agent\n"
                "capture_cmd=/home/pi/wifi-pipeline/bin/wifi-pipeline-capture\n"
                "service_cmd=/home/pi/wifi-pipeline/bin/wifi-pipeline-service\n"
                "privilege_mode=sudoers_runner\n"
                "privileged_runner=/usr/local/bin/wifi-pipeline-capture-privileged\n"
            ),
            stderr="",
        )

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "tool" if name in ("ssh", "scp") else None)
    monkeypatch.setattr("wifi_pipeline.remote.pair_remote_host", lambda *args, **kwargs: True)
    monkeypatch.setattr("wifi_pipeline.remote.build_capture_agent_bundle", lambda **kwargs: bundle_path)
    monkeypatch.setattr(
        "wifi_pipeline.remote._install_remote_appliance_profile",
        lambda *args, **kwargs: {
            "install_profile": "appliance",
            "health_port": "8741",
            "health_endpoint": "http://0.0.0.0:8741/health",
        },
    )
    monkeypatch.setattr(
        "wifi_pipeline.remote.doctor_remote_host",
        lambda *args, **kwargs: {
            "ok": True,
            "remote": {
                "reachable": True,
                "agent": True,
                "agent_path": "/home/pi/wifi-pipeline/bin/wifi-pipeline-agent",
                "agent_protocol": "capture-agent/v1",
                "agent_version": "3.0.0",
                "helper": True,
                "helper_path": "/home/pi/.local/bin/wifi-pipeline-capture",
                "service": True,
                "service_path": "/home/pi/.local/bin/wifi-pipeline-service",
                "service_status": "idle",
                "privilege_mode": "sudoers_runner",
                "state_dir_exists": True,
                "state_dir_writable": True,
                "remote_root": "/home/pi/wifi-pipeline",
                "capture_dir": "/home/pi/wifi-pipeline/captures",
                "capture_dir_exists": True,
                "capture_dir_writable": True,
                "install_profile": "appliance",
                "health_port": "8741",
                "health_path": "/health",
                "health_endpoint": "http://0.0.0.0:8741/health",
                "health_probe_ok": True,
                "health_protocol": "capture-agent/v1",
                "health_agent_version": "3.0.0",
                "health_socket_enabled": True,
                "health_socket_active": True,
                "appliance_service_enabled": True,
                "appliance_service_active": True,
            },
        },
    )
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = bootstrap_remote_host({"remote_host": "pi@raspberrypi"}, pair=True, install_mode="bundle")

    assert result is not None
    assert result["install_mode"] == "bundle"
    assert result["install_profile"] == "appliance"
    assert uploaded
    assert uploaded[0][0] == "scp"
    assert seen_inputs


def test_bootstrap_remote_host_rejects_failed_validation(monkeypatch) -> None:
    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=(
                "remote_root=/home/pi/wifi-pipeline\n"
                "capture_dir=/home/pi/wifi-pipeline/captures\n"
                "state_dir=/home/pi/wifi-pipeline/state\n"
                "capture_cmd=/home/pi/wifi-pipeline/bin/wifi-pipeline-capture\n"
                "service_cmd=/home/pi/wifi-pipeline/bin/wifi-pipeline-service\n"
                "agent_cmd=/home/pi/wifi-pipeline/bin/wifi-pipeline-agent\n"
                "privilege_mode=fallback\n"
                "privileged_runner=/usr/local/bin/wifi-pipeline-capture-privileged\n"
            ),
            stderr="",
        )

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "ssh" if name == "ssh" else None)
    monkeypatch.setattr("wifi_pipeline.remote.pair_remote_host", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        "wifi_pipeline.remote._install_remote_appliance_profile",
        lambda *args, **kwargs: {
            "install_profile": "appliance",
            "health_port": "8741",
            "health_endpoint": "http://0.0.0.0:8741/health",
        },
    )
    monkeypatch.setattr(
        "wifi_pipeline.remote.doctor_remote_host",
        lambda *args, **kwargs: {
            "ok": False,
            "remote": {
                "reachable": True,
                "agent": True,
                "agent_path": "/home/pi/wifi-pipeline/bin/wifi-pipeline-agent",
                "agent_protocol": "capture-agent/v1",
                "agent_version": "2.9.9",
                "helper": True,
                "helper_path": "/home/pi/.local/bin/wifi-pipeline-capture",
                "service": True,
                "service_path": "/home/pi/.local/bin/wifi-pipeline-service",
                "service_status": "idle",
                "privilege_mode": "fallback",
                "state_dir_exists": True,
                "state_dir_writable": True,
                "remote_root": "/home/pi/wifi-pipeline",
                "capture_dir": "/home/pi/wifi-pipeline/captures",
                "capture_dir_exists": True,
                "capture_dir_writable": True,
                "install_profile": "appliance",
                "health_port": "8741",
                "health_path": "/health",
                "health_endpoint": "http://0.0.0.0:8741/health",
                "health_probe_ok": True,
                "health_protocol": "capture-agent/v1",
                "health_agent_version": "2.9.9",
                "health_socket_enabled": True,
                "health_socket_active": True,
                "appliance_service_enabled": True,
                "appliance_service_active": True,
            },
        },
    )
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = bootstrap_remote_host({"remote_host": "pi@raspberrypi"}, pair=True)

    assert result is None


def test_bootstrap_validation_errors_report_appliance_health_and_path_failures() -> None:
    report = {
        "remote": {
            "reachable": True,
            "agent": True,
            "agent_path": "/home/pi/wifi-pipeline/bin/wifi-pipeline-agent",
            "agent_protocol": REMOTE_AGENT_PROTOCOL,
            "agent_version": __version__,
            "helper": True,
            "helper_path": "/home/pi/.local/bin/wifi-pipeline-capture",
            "service": True,
            "service_path": "/home/pi/.local/bin/wifi-pipeline-service",
            "service_status": "idle",
            "privilege_mode": "sudoers_runner",
            "state_dir_exists": False,
            "state_dir_writable": False,
            "remote_root": "/tmp/wrong-root",
            "capture_dir": "/tmp/wrong-captures",
            "capture_dir_exists": False,
            "capture_dir_writable": False,
            "install_profile": "standard",
            "health_port": "9999",
            "health_path": "/status",
            "health_endpoint": "",
            "health_probe_ok": False,
            "health_protocol": "capture-agent/v0",
            "health_agent_version": "0.0.0",
            "health_socket_enabled": False,
            "health_socket_active": False,
            "appliance_service_enabled": False,
            "appliance_service_active": False,
        }
    }

    errors = _bootstrap_validation_errors(
        report,
        expected_profile="appliance",
        expected_health_port=8741,
        expected_remote_root="/home/pi/wifi-pipeline",
        expected_capture_dir="/home/pi/wifi-pipeline/captures",
    )

    assert "Remote state directory is missing after bootstrap." in errors
    assert "Remote state directory is not writable after bootstrap." in errors
    assert "Remote root mismatch: expected /home/pi/wifi-pipeline." in errors
    assert "Remote capture directory mismatch: expected /home/pi/wifi-pipeline/captures." in errors
    assert "Remote capture directory is missing after bootstrap." in errors
    assert "Remote capture directory is not writable after bootstrap." in errors
    assert "Appliance profile was requested, but the remote node did not report appliance mode." in errors
    assert "Remote health port mismatch: expected 8741." in errors
    assert "Remote health path mismatch: expected /health." in errors
    assert "Remote health endpoint was not reported after bootstrap." in errors
    assert "Remote health endpoint did not answer with a valid appliance payload." in errors
    assert "Remote health endpoint protocol is incompatible: expected capture-agent/v1." in errors
    assert f"Remote health endpoint version mismatch: expected {__version__}, got 0.0.0." in errors
    assert "Remote health socket is not enabled after bootstrap." in errors
    assert "Remote health socket is not active after bootstrap." in errors
    assert "Remote appliance service is not enabled after bootstrap." in errors
    assert "Remote appliance service is not active after bootstrap." in errors


def test_extract_capture_path_uses_last_nonempty_line() -> None:
    output = "[*] Saving capture to /tmp/capture.pcap\n/tmp/capture.pcap\n"

    assert _extract_capture_path(output) == "/tmp/capture.pcap"


def test_parse_key_value_output() -> None:
    parsed = _parse_key_value_output("one=1\ntwo=hello world\nignored\n")

    assert parsed == {"one": "1", "two": "hello world"}


def test_start_remote_capture_runs_helper_and_pulls_file(monkeypatch, tmp_path) -> None:
    commands: list[list[str]] = []
    checksum = hashlib.sha256(b"pcap").hexdigest()

    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        commands.append(cmd)
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            remote_cmd = cmd[-1]
            if "wifi-pipeline-agent" in remote_cmd and " service start " in remote_cmd:
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout='{"data":{"output":"/home/pi/wifi-pipeline/captures/capture_20260406_120000.pcap","pid":"1234","service_status":"running"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                    stderr="",
                )
            if "wifi-pipeline-agent" in remote_cmd and " service status" in remote_cmd:
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout='{"data":{"checksum_file":"/home/pi/wifi-pipeline/captures/capture_20260406_120000.pcap.sha256","complete_marker":"/home/pi/wifi-pipeline/captures/capture_20260406_120000.pcap.complete","last_capture":"/home/pi/wifi-pipeline/captures/capture_20260406_120000.pcap","last_exit_code":"0","last_result":"complete","log_file":"/home/pi/wifi-pipeline/state/capture-service.log","service_status":"idle"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                    stderr="",
                )
            if "wifi-pipeline-agent" in remote_cmd and " artifact-info " in remote_cmd:
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout=(
                        '{"data":{"checksum_file":"yes","checksum_value":"'
                        + checksum
                        + '","complete_marker":"yes","file_exists":"yes","remote_size_bytes":"4"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n'
                    ),
                    stderr="",
                )
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")
        if cmd[0] == "scp":
            destination = Path(cmd[-1])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b"pcap")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "tool" if name != "rsync" else None)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = start_remote_capture(
        {"remote_host": "pi@raspberrypi", "remote_dest_dir": str(tmp_path)},
        interface="wlan0",
        duration=30,
    )

    assert result is not None
    assert result.exists()
    assert any("wifi-pipeline-agent" in " ".join(cmd) for cmd in commands if cmd[0] == "ssh")


def test_start_remote_capture_reports_privilege_gap(monkeypatch) -> None:
    statuses = iter(
        [
            subprocess.CompletedProcess(
                ["ssh"],
                0,
                stdout='{"data":{"output":"/home/pi/wifi-pipeline/captures/capture_20260406_120000.pcap","pid":"1234","service_status":"running"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                stderr="",
            ),
            subprocess.CompletedProcess(
                ["ssh"],
                0,
                stdout='{"data":{"last_exit_code":"3","last_result":"failed","log_file":"/home/pi/wifi-pipeline/state/capture-service.log","service_status":"failed"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                stderr="",
            ),
        ]
    )

    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            return next(statuses)
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "tool" if name != "rsync" else None)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = start_remote_capture({"remote_host": "pi@raspberrypi"}, interface="wlan0", duration=30)

    assert result is None


def test_start_remote_capture_reports_reboot_interruption(monkeypatch) -> None:
    statuses = iter(
        [
            subprocess.CompletedProcess(
                ["ssh"],
                0,
                stdout='{"data":{"output":"/home/pi/wifi-pipeline/captures/capture_20260406_120000.pcap","pid":"1234","service_status":"running"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                stderr="",
            ),
            subprocess.CompletedProcess(
                ["ssh"],
                0,
                stdout='{"data":{"last_exit_code":"130","last_result":"interrupted_reboot","recovery_reason":"reboot","service_status":"interrupted"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                stderr="",
            ),
        ]
    )

    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            return next(statuses)
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "tool" if name != "rsync" else None)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = start_remote_capture({"remote_host": "pi@raspberrypi"}, interface="wlan0", duration=30)

    assert result is None


def test_start_remote_capture_reports_stale_pid_recovery_interruption(monkeypatch) -> None:
    statuses = iter(
        [
            subprocess.CompletedProcess(
                ["ssh"],
                0,
                stdout='{"data":{"output":"/home/pi/wifi-pipeline/captures/capture_20260406_120000.pcap","pid":"1234","service_status":"running"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                stderr="",
            ),
            subprocess.CompletedProcess(
                ["ssh"],
                0,
                stdout='{"data":{"last_exit_code":"130","last_result":"interrupted","recovery_reason":"stale_pid","service_status":"interrupted"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                stderr="",
            ),
        ]
    )

    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            return next(statuses)
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "tool" if name != "rsync" else None)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = start_remote_capture({"remote_host": "pi@raspberrypi"}, interface="wlan0", duration=30)

    assert result is None


def test_remote_service_host_retries_remote_home_lookup(monkeypatch) -> None:
    calls = {"home": 0}

    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            calls["home"] += 1
            if calls["home"] == 1:
                return subprocess.CompletedProcess(cmd, 255, stdout="", stderr="connection reset")
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout='{"data":{"last_capture":"/home/pi/wifi-pipeline/captures/capture_latest.pcap","last_result":"complete","service_status":"idle"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                stderr="",
            )
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "ssh" if name == "ssh" else None)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)
    monkeypatch.setattr("wifi_pipeline.remote.time.sleep", lambda _seconds: None)

    result = remote_service_host({"remote_host": "pi@raspberrypi"}, "last-capture")

    assert result is not None
    assert result["last_capture"] == "/home/pi/wifi-pipeline/captures/capture_latest.pcap"
    assert calls["home"] == 2


def test_remote_service_host_retries_transient_agent_failure(monkeypatch) -> None:
    calls = {"agent": 0}

    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            calls["agent"] += 1
            if calls["agent"] == 1:
                return subprocess.CompletedProcess(cmd, 255, stdout="", stderr="connection reset")
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout='{"data":{"last_capture":"/home/pi/wifi-pipeline/captures/capture_latest.pcap","last_result":"complete","service_status":"idle"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                stderr="",
            )
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "ssh" if name == "ssh" else None)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)
    monkeypatch.setattr("wifi_pipeline.remote.time.sleep", lambda _seconds: None)

    result = remote_service_host({"remote_host": "pi@raspberrypi"}, "last-capture")

    assert result is not None
    assert result["last_capture"] == "/home/pi/wifi-pipeline/captures/capture_latest.pcap"
    assert calls["agent"] == 2


def test_doctor_remote_host_reports_success(monkeypatch) -> None:
    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout='{"data":{"agent":"yes","agent_path":"/home/pi/wifi-pipeline/bin/wifi-pipeline-agent","agent_protocol":"capture-agent/v1","agent_version":"3.0.0","appliance_service":"wifi-pipeline-appliance.service","appliance_service_active":"yes","appliance_service_enabled":"yes","capture_dir":"/home/pi/wifi-pipeline/captures","capture_dir_exists":"yes","capture_dir_writable":"yes","checksum_file":"yes","checksum_value":"abcd","complete_marker":"yes","control_mode":"agent","health_endpoint":"http://0.0.0.0:8741/health","health_path":"/health","health_port":"8741","health_service":"wifi-pipeline-health.service","health_socket":"wifi-pipeline-health.socket","health_socket_active":"yes","health_socket_enabled":"yes","helper":"yes","helper_path":"/home/pi/.local/bin/wifi-pipeline-capture","helper_version":"3.0.0","install_profile":"appliance","interface_exists":"yes","privilege_mode":"sudoers_runner","privileged_runner":"yes","privileged_runner_path":"/usr/local/bin/wifi-pipeline-capture-privileged","remote_root":"/home/pi/wifi-pipeline","remote_size_bytes":"4","service":"yes","service_path":"/home/pi/.local/bin/wifi-pipeline-service","service_status":"idle","service_version":"3.0.0","state_dir":"/home/pi/wifi-pipeline/state","state_dir_exists":"yes","state_dir_writable":"yes","tcpdump":"yes"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                stderr="",
            )
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("wifi_pipeline.remote._ensure_public_key", lambda identity=None, generate_if_missing=False: Path("/tmp/id_ed25519.pub"))
    monkeypatch.setattr(
        "wifi_pipeline.remote._probe_remote_appliance",
        lambda host, **kwargs: {
            "host": host,
            "ssh_target": f"pi@{host}",
            "health_endpoint": f"http://{host}:8741/health",
            "device_name": "pi-node",
            "install_profile": "appliance",
            "health_port": "8741",
            "health_path": "/health",
            "control_mode": "agent",
            "agent_protocol": "capture-agent/v1",
            "agent_version": "3.0.0",
            "capture_dir": "/home/pi/wifi-pipeline/captures",
            "service_status": "idle",
            "remote_root": "/home/pi/wifi-pipeline",
            "ssh_user": "pi",
        },
    )
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    report = doctor_remote_host(
        {"remote_host": "pi@raspberrypi", "remote_interface": "wlan0"},
        interface="wlan0",
    )

    assert report["ok"] is True
    assert report["remote"]["agent"] is True
    assert report["remote"]["helper"] is True
    assert report["remote"]["service"] is True
    assert report["remote"]["service_status"] == "idle"
    assert report["remote"]["agent_version"] == "3.0.0"
    assert report["remote"]["protocol_compatible"] is True
    assert report["remote"]["version_compatible"] is True
    assert report["remote"]["install_profile"] == "appliance"
    assert report["remote"]["health_endpoint"] == "http://raspberrypi:8741/health"
    assert report["remote"]["health_probe_ok"] is True
    assert report["remote"]["health_protocol"] == "capture-agent/v1"
    assert report["remote"]["health_agent_version"] == "3.0.0"
    assert report["remote"]["health_socket_enabled"] is True
    assert report["remote"]["appliance_service_enabled"] is True
    assert report["remote"]["state_dir_exists"] is True
    assert report["remote"]["checksum_file"] is True
    assert report["remote"]["privileged_runner"] is True
    assert report["remote"]["privilege_mode"] == "sudoers_runner"
    assert report["remote"]["control_mode"] == "agent"
    assert report["remote"]["capture_dir_writable"] is True
    assert report["remote"]["interface_exists"] is True


def test_doctor_remote_host_reports_interrupted_service_with_recovery_reason(monkeypatch) -> None:
    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout='{"data":{"agent":"yes","agent_path":"/home/pi/wifi-pipeline/bin/wifi-pipeline-agent","agent_protocol":"capture-agent/v1","agent_version":"3.0.0","capture_dir":"/home/pi/wifi-pipeline/captures","capture_dir_exists":"yes","capture_dir_writable":"yes","control_mode":"agent","health_endpoint":"http://0.0.0.0:8741/health","health_path":"/health","health_port":"8741","health_socket_active":"yes","health_socket_enabled":"yes","appliance_service_active":"yes","appliance_service_enabled":"yes","helper":"yes","helper_path":"/home/pi/.local/bin/wifi-pipeline-capture","helper_version":"3.0.0","install_profile":"appliance","interface_exists":"yes","last_exit_code":"130","last_result":"interrupted_reboot","privilege_mode":"sudoers_runner","recovery_reason":"reboot","remote_root":"/home/pi/wifi-pipeline","service":"yes","service_path":"/home/pi/.local/bin/wifi-pipeline-service","service_status":"interrupted","service_version":"3.0.0","stale_pid_cleaned":"yes","state_dir":"/home/pi/wifi-pipeline/state","state_dir_exists":"yes","state_dir_writable":"yes","tcpdump":"yes"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                stderr="",
            )
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("wifi_pipeline.remote._ensure_public_key", lambda identity=None, generate_if_missing=False: Path("/tmp/id_ed25519.pub"))
    monkeypatch.setattr(
        "wifi_pipeline.remote._probe_remote_appliance",
        lambda host, **kwargs: {
            "host": host,
            "ssh_target": f"pi@{host}",
            "health_endpoint": f"http://{host}:8741/health",
            "device_name": "pi-node",
            "install_profile": "appliance",
            "health_port": "8741",
            "health_path": "/health",
            "control_mode": "agent",
            "agent_protocol": "capture-agent/v1",
            "agent_version": "3.0.0",
            "capture_dir": "/home/pi/wifi-pipeline/captures",
            "service_status": "interrupted",
            "remote_root": "/home/pi/wifi-pipeline",
            "ssh_user": "pi",
        },
    )
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    report = doctor_remote_host({"remote_host": "pi@raspberrypi", "remote_interface": "wlan0"}, interface="wlan0")

    assert report["ok"] is True
    assert report["remote"]["service_status"] == "interrupted"
    assert report["remote"]["last_result"] == "interrupted_reboot"
    assert report["remote"]["recovery_reason"] == "reboot"
    assert report["remote"]["stale_pid_cleaned"] is True


def test_doctor_remote_host_reports_missing_helper(monkeypatch) -> None:
    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            if "wifi-pipeline-agent" in cmd[-1]:
                return subprocess.CompletedProcess(cmd, 127, stdout="", stderr="not found")
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=(
                    "tcpdump=yes\n"
                    "helper=no\n"
                    "helper_path=/home/pi/wifi-pipeline/bin/wifi-pipeline-capture\n"
                    "service=no\n"
                    "service_path=/home/pi/wifi-pipeline/bin/wifi-pipeline-service\n"
                    "service_status=missing\n"
                    "state_dir=/home/pi/wifi-pipeline/state\n"
                    "state_dir_exists=yes\n"
                    "state_dir_writable=yes\n"
                    "privileged_runner=no\n"
                    "privileged_runner_path=/usr/local/bin/wifi-pipeline-capture-privileged\n"
                    "privilege_mode=fallback\n"
                    "capture_dir=/home/pi/wifi-pipeline/captures\n"
                    "capture_dir_exists=yes\n"
                    "capture_dir_writable=yes\n"
                ),
                stderr="",
            )
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("wifi_pipeline.remote._ensure_public_key", lambda identity=None, generate_if_missing=False: None)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    report = doctor_remote_host({"remote_host": "pi@raspberrypi"})

    assert report["ok"] is False
    assert report["local"]["public_key"] is False
    assert report["remote"]["agent"] is False
    assert report["remote"]["helper"] is False
    assert report["remote"]["service"] is False
    assert report["remote"]["control_mode"] == "legacy_shell"
    assert report["remote"]["privilege_mode"] == "fallback"


def test_remote_service_host_reports_last_capture(monkeypatch) -> None:
    def fake_run(cmd, capture_output=True, text=True, input=None, check=False, **_kwargs):
        if cmd[0] == "ssh" and cmd[-3:] == ["sh", "-lc", 'printf "%s" "$HOME"']:
            return subprocess.CompletedProcess(cmd, 0, stdout="/home/pi", stderr="")
        if cmd[0] == "ssh":
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout='{"data":{"last_capture":"/home/pi/wifi-pipeline/captures/capture_latest.pcap","last_result":"complete","service_status":"idle"},"ok":true,"protocol":"capture-agent/v1","returncode":0}\n',
                stderr="",
            )
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bad")

    monkeypatch.setattr("wifi_pipeline.remote.shutil.which", lambda name: "ssh" if name == "ssh" else None)
    monkeypatch.setattr("wifi_pipeline.remote.subprocess.run", fake_run)

    result = remote_service_host({"remote_host": "pi@raspberrypi"}, "last-capture")

    assert result is not None
    assert result["last_capture"] == "/home/pi/wifi-pipeline/captures/capture_latest.pcap"
