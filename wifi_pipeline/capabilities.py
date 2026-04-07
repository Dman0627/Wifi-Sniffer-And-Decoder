from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Tuple

from .reasons import Reason


@dataclass(frozen=True)
class PlatformCapability:
    os_name: str
    os_version: str
    distribution: str
    architecture: str
    product_profile_key: str
    product_profile_label: str
    official: bool
    distribution_id: str = ""
    distribution_version: str = ""
    machine_model: str = ""


@dataclass(frozen=True)
class AdapterCapability:
    name: str
    description: str = ""
    driver: str = ""
    chipset_family: str = ""
    phy_name: str = ""
    status: str = "unknown"
    monitor_mode: str = "unknown"
    monitor_support_advertised: bool | None = None
    injection: str = "unknown"
    channels: str = "unknown"
    capture_methods: Tuple[str, ...] = ()
    reasons: Tuple[Reason, ...] = ()


@dataclass(frozen=True)
class ToolCapability:
    name: str
    purpose: str
    required: bool
    path: str = ""
    status: str = "missing"
    reasons: Tuple[Reason, ...] = ()


@dataclass(frozen=True)
class CaptureMethodCapability:
    key: str
    label: str
    status: str
    available: bool
    requires_privilege: bool
    detail: str
    tooling: Tuple[str, ...] = ()
    reasons: Tuple[Reason, ...] = ()


@dataclass(frozen=True)
class WPAReadinessCapability:
    state: str = "not_evaluated"
    status: str = "unknown"
    handshake_artifact: str = ""
    crack_ready: bool = False
    decrypt_ready: bool = False
    detail: str = ""
    tooling: Tuple[str, ...] = ()
    reasons: Tuple[Reason, ...] = ()


@dataclass(frozen=True)
class RemoteSupportCapability:
    status: str = "unknown"
    mode: str = "linux_appliance"
    configured_host: str = ""
    ssh_available: bool = False
    scp_available: bool = False
    health_port: int | None = None
    detail: str = ""
    tooling: Tuple[str, ...] = ()
    reasons: Tuple[Reason, ...] = ()


@dataclass(frozen=True)
class ReplayFamilyCapability:
    family: str
    decode_status: str
    export_status: str
    replay_status: str
    detail: str
    reasons: Tuple[Reason, ...] = ()


@dataclass(frozen=True)
class CapabilityReport:
    platform: PlatformCapability
    privilege_mode: str
    adapters: Tuple[AdapterCapability, ...] = field(default_factory=tuple)
    tools: Tuple[ToolCapability, ...] = field(default_factory=tuple)
    capture_methods: Tuple[CaptureMethodCapability, ...] = field(default_factory=tuple)
    wpa: WPAReadinessCapability = field(default_factory=WPAReadinessCapability)
    remote: RemoteSupportCapability = field(default_factory=RemoteSupportCapability)
    replay_families: Tuple[ReplayFamilyCapability, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
