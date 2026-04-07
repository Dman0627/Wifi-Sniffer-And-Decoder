from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import socket
import time
import urllib.error
import urllib.request
from typing import Callable, Dict, List, Optional

DEFAULT_APPLIANCE_HEALTH_PORT = 8741
DEFAULT_DISCOVERY_TIMEOUT = 0.35
DEFAULT_DISCOVERY_HOST_LIMIT = 64
DEFAULT_DISCOVERY_PROBE_ATTEMPTS = 2
DEFAULT_DISCOVERY_PROBE_BACKOFF_SECONDS = 0.1
DEFAULT_DISCOVERY_HOSTNAMES = (
    "raspberrypi",
    "raspberrypi.local",
    "wifi-pipeline",
    "wifi-pipeline.local",
    "ubuntu",
    "ubuntu.local",
)


def _strip_ssh_user(host: str) -> str:
    value = str(host or "").strip()
    if "@" in value:
        return value.split("@", 1)[1].strip()
    return value


def _preferred_discovery_user(config: Dict[str, object]) -> str:
    host = str(config.get("remote_host") or "").strip()
    if "@" in host:
        return host.split("@", 1)[0].strip()
    return str(config.get("remote_user") or "").strip()


def _candidate_discovery_networks() -> List[str]:
    networks: set[str] = set()
    try:
        host_info = socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET, type=socket.SOCK_DGRAM)
        for entry in host_info:
            address = entry[4][0]
            if address.startswith("127.") or address.startswith("169.254."):
                continue
            network = ipaddress.ip_network(f"{address}/24", strict=False)
            networks.add(str(network))
    except OSError:
        pass

    for target in ("8.8.8.8", "1.1.1.1"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((target, 53))
                address = sock.getsockname()[0]
            if address and not address.startswith("127.") and not address.startswith("169.254."):
                networks.add(str(ipaddress.ip_network(f"{address}/24", strict=False)))
        except OSError:
            continue

    return sorted(networks)


def _candidate_discovery_hosts(
    config: Dict[str, object],
    *,
    networks: Optional[List[str]] = None,
    max_hosts: int = DEFAULT_DISCOVERY_HOST_LIMIT,
) -> List[str]:
    hosts: List[str] = []
    seen: set[str] = set()

    def add_host(value: str) -> None:
        candidate = _strip_ssh_user(value)
        if not candidate or candidate in seen:
            return
        seen.add(candidate)
        hosts.append(candidate)

    add_host(str(config.get("remote_host") or ""))
    for candidate in DEFAULT_DISCOVERY_HOSTNAMES:
        add_host(candidate)

    discovered_networks = networks or _candidate_discovery_networks()
    remaining = max(0, int(max_hosts))
    for network_text in discovered_networks:
        if remaining <= 0:
            break
        try:
            network = ipaddress.ip_network(network_text, strict=False)
        except ValueError:
            continue
        for address in network.hosts():
            add_host(str(address))
            remaining -= 1
            if remaining <= 0:
                break

    return hosts


def _probe_remote_appliance(host: str, *, health_port: int, timeout: float, user_hint: str = "") -> Optional[Dict[str, str]]:
    endpoint = f"http://{host}:{int(health_port)}/health"
    payload = None
    max_attempts = max(1, int(DEFAULT_DISCOVERY_PROBE_ATTEMPTS))
    for attempt in range(1, max_attempts + 1):
        try:
            with urllib.request.urlopen(endpoint, timeout=max(0.1, float(timeout))) as response:
                payload = json.loads(response.read().decode("utf-8"))
            break
        except (OSError, ValueError, urllib.error.URLError, TimeoutError):
            payload = None
            if attempt < max_attempts:
                time.sleep(DEFAULT_DISCOVERY_PROBE_BACKOFF_SECONDS * attempt)
    if payload is None:
        return None

    if not isinstance(payload, dict):
        return None
    if str(payload.get("protocol") or "") != "capture-agent/v1":
        return None
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    if str(data.get("agent") or "") != "yes":
        return None

    ssh_user = str(data.get("ssh_user") or user_hint or "").strip()
    ssh_target = f"{ssh_user}@{host}" if ssh_user else host
    return {
        "host": host,
        "ssh_target": ssh_target,
        "health_endpoint": endpoint,
        "device_name": str(data.get("device_name") or host),
        "install_profile": str(data.get("install_profile") or "standard"),
        "health_port": str(data.get("health_port") or health_port),
        "health_path": str(data.get("health_path") or "/health"),
        "control_mode": str(data.get("control_mode") or "agent"),
        "agent_protocol": str(payload.get("protocol") or ""),
        "agent_version": str(data.get("agent_version") or ""),
        "capture_dir": str(data.get("capture_dir") or ""),
        "service_status": str(data.get("service_status") or ""),
        "remote_root": str(data.get("remote_root") or ""),
        "ssh_user": ssh_user,
    }


def discover_remote_appliances(
    config: Dict[str, object],
    *,
    networks: Optional[List[str]] = None,
    health_port: Optional[int] = None,
    timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
    max_hosts: int = DEFAULT_DISCOVERY_HOST_LIMIT,
    candidate_hosts_fn: Callable[..., List[str]] = _candidate_discovery_hosts,
    probe_fn: Callable[..., Optional[Dict[str, str]]] = _probe_remote_appliance,
    preferred_user_fn: Callable[[Dict[str, object]], str] = _preferred_discovery_user,
) -> List[Dict[str, str]]:
    chosen_port = int(
        health_port if health_port is not None else config.get("remote_health_port", DEFAULT_APPLIANCE_HEALTH_PORT) or DEFAULT_APPLIANCE_HEALTH_PORT
    )
    user_hint = preferred_user_fn(config)
    candidates = candidate_hosts_fn(config, networks=networks, max_hosts=max_hosts)
    results: List[Dict[str, str]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, max(4, len(candidates) or 1))) as executor:
        future_map = {
            executor.submit(probe_fn, host, health_port=chosen_port, timeout=timeout, user_hint=user_hint): host
            for host in candidates
        }
        for future in concurrent.futures.as_completed(future_map):
            try:
                record = future.result()
            except Exception:
                record = None
            if record:
                results.append(record)

    results.sort(key=lambda item: (item.get("device_name") or item.get("host") or "", item.get("host") or ""))
    return results
