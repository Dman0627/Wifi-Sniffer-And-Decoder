from __future__ import annotations

import urllib.error

from wifi_pipeline import remote_discovery


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return self._payload


def test_strip_ssh_user_removes_user_prefix() -> None:
    assert remote_discovery._strip_ssh_user("pi@raspberrypi") == "raspberrypi"
    assert remote_discovery._strip_ssh_user("  analyst@10.0.0.5  ") == "10.0.0.5"
    assert remote_discovery._strip_ssh_user("wifi-pipeline.local") == "wifi-pipeline.local"


def test_preferred_discovery_user_prefers_remote_host_user() -> None:
    assert remote_discovery._preferred_discovery_user({"remote_host": "pi@raspberrypi", "remote_user": "ubuntu"}) == "pi"
    assert remote_discovery._preferred_discovery_user({"remote_host": "raspberrypi", "remote_user": "ubuntu"}) == "ubuntu"
    assert remote_discovery._preferred_discovery_user({}) == ""


def test_candidate_discovery_networks_filters_loopback_and_deduplicates(monkeypatch) -> None:
    def fake_getaddrinfo(_hostname, _service, family=None, type=None):
        _unused = family, type
        return [
            (None, None, None, None, ("127.0.0.1", 0)),
            (None, None, None, None, ("169.254.1.20", 0)),
            (None, None, None, None, ("192.168.50.22", 0)),
        ]

    class FakeSocket:
        def __init__(self, _family, _type):
            self._target = ""

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def connect(self, endpoint):
            self._target = str(endpoint[0])
            if self._target == "1.1.1.1":
                raise OSError("network unavailable")

        def getsockname(self):
            if self._target == "8.8.8.8":
                return ("192.168.50.99", 0)
            return ("169.254.10.10", 0)

    monkeypatch.setattr(remote_discovery.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(remote_discovery.socket, "socket", lambda family, socktype: FakeSocket(family, socktype))

    networks = remote_discovery._candidate_discovery_networks()

    assert networks == ["192.168.50.0/24"]


def test_candidate_discovery_hosts_preserves_priority_and_applies_limit() -> None:
    hosts = remote_discovery._candidate_discovery_hosts(
        {"remote_host": "pi@10.0.0.8"},
        networks=["10.1.0.0/30"],
        max_hosts=2,
    )

    assert hosts[0] == "10.0.0.8"
    assert hosts[1:7] == list(remote_discovery.DEFAULT_DISCOVERY_HOSTNAMES)
    assert hosts[-2:] == ["10.1.0.1", "10.1.0.2"]
    assert hosts.count("10.0.0.8") == 1


def test_probe_remote_appliance_applies_defaults_and_user_hint(monkeypatch) -> None:
    payload = (
        b'{"protocol":"capture-agent/v1","data":{"agent":"yes","device_name":"pi-node","agent_version":"3.0.0"}}'
    )

    monkeypatch.setattr(
        remote_discovery.urllib.request,
        "urlopen",
        lambda endpoint, timeout=None: _FakeResponse(payload),
    )

    record = remote_discovery._probe_remote_appliance("raspberrypi", health_port=8741, timeout=0.2, user_hint="pi")

    assert record is not None
    assert record["ssh_target"] == "pi@raspberrypi"
    assert record["device_name"] == "pi-node"
    assert record["install_profile"] == "standard"
    assert record["health_port"] == "8741"
    assert record["health_path"] == "/health"
    assert record["control_mode"] == "agent"
    assert record["ssh_user"] == "pi"


def test_probe_remote_appliance_rejects_invalid_payloads(monkeypatch) -> None:
    invalid_payloads = (
        b"[]",
        b'{"protocol":"wrong","data":{"agent":"yes"}}',
        b'{"protocol":"capture-agent/v1","data":[]}',
        b'{"protocol":"capture-agent/v1","data":{"agent":"no"}}',
    )

    for payload in invalid_payloads:
        monkeypatch.setattr(
            remote_discovery.urllib.request,
            "urlopen",
            lambda endpoint, timeout=None, payload=payload: _FakeResponse(payload),
        )
        assert remote_discovery._probe_remote_appliance("raspberrypi", health_port=8741, timeout=0.2) is None


def test_discover_remote_appliances_sorts_results_and_ignores_probe_failures() -> None:
    seen_calls: list[tuple[str, int, float, str]] = []

    def fake_probe(host: str, *, health_port: int, timeout: float, user_hint: str):
        seen_calls.append((host, health_port, timeout, user_hint))
        if host == "bad-host":
            raise RuntimeError("boom")
        if host == "host-b":
            return {
                "host": host,
                "ssh_target": f"pi@{host}",
                "device_name": "zeta",
            }
        if host == "host-a":
            return {
                "host": host,
                "ssh_target": f"pi@{host}",
                "device_name": "alpha",
            }
        return None

    results = remote_discovery.discover_remote_appliances(
        {"remote_host": "pi@seed-host", "remote_health_port": 9001},
        timeout=0.25,
        max_hosts=8,
        candidate_hosts_fn=lambda config, **kwargs: ["host-b", "bad-host", "host-a", "host-c"],
        probe_fn=fake_probe,
    )

    assert [item["host"] for item in results] == ["host-a", "host-b"]
    assert all(call[1] == 9001 for call in seen_calls)
    assert all(call[2] == 0.25 for call in seen_calls)
    assert all(call[3] == "pi" for call in seen_calls)


def test_probe_remote_appliance_returns_none_after_retryable_errors(monkeypatch) -> None:
    calls = {"count": 0}

    def fake_urlopen(_endpoint, timeout=None):
        _unused = timeout
        calls["count"] += 1
        raise urllib.error.URLError("timed out")

    monkeypatch.setattr(remote_discovery.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(remote_discovery.time, "sleep", lambda _seconds: None)

    record = remote_discovery._probe_remote_appliance("raspberrypi", health_port=8741, timeout=0.1, user_hint="pi")

    assert record is None
    assert calls["count"] == remote_discovery.DEFAULT_DISCOVERY_PROBE_ATTEMPTS
