from __future__ import annotations

from wifi_pipeline.capabilities import (
    AdapterCapability,
    CapabilityReport,
    CaptureMethodCapability,
    PlatformCapability,
    RemoteSupportCapability,
    ReplayFamilyCapability,
    ToolCapability,
    WPAReadinessCapability,
)
from wifi_pipeline.reasons import make_blocker, make_context, make_limitation


def test_reason_helpers_assign_expected_kinds() -> None:
    blocker = make_blocker("capture.blocked", "Capture is blocked.", detail="Need privilege.", remediation="Run elevated.")
    limitation = make_limitation("capture.limited", "Capture is limited.", detail="Monitor mode unavailable.", remediation="Use remote capture.")
    context = make_context("capture.context", "Capture is remote.", detail="Using appliance workflow.", remediation="No action needed.")

    assert blocker.kind == "blocker"
    assert blocker.code == "capture.blocked"
    assert blocker.detail == "Need privilege."
    assert blocker.remediation == "Run elevated."
    assert limitation.kind == "limitation"
    assert limitation.code == "capture.limited"
    assert context.kind == "context"
    assert context.code == "capture.context"


def test_capability_report_to_dict_serializes_nested_capabilities() -> None:
    report = CapabilityReport(
        platform=PlatformCapability(
            os_name="Linux",
            os_version="6.8",
            distribution="Ubuntu",
            architecture="x86_64",
            product_profile_key="linux_remote",
            product_profile_label="Linux Remote",
            official=True,
            distribution_id="ubuntu",
            distribution_version="24.04",
            machine_model="Mini PC",
        ),
        privilege_mode="sudo",
        adapters=(
            AdapterCapability(
                name="wlan0",
                description="Primary adapter",
                status="supported",
                monitor_mode="experimental",
                capture_methods=("local_capture", "monitor_capture"),
                reasons=(make_context("adapter.context", "Adapter detected."),),
            ),
        ),
        tools=(
            ToolCapability(
                name="tcpdump",
                purpose="packet capture",
                required=True,
                path="/usr/sbin/tcpdump",
                status="available",
                reasons=(make_context("tool.available", "Tool is installed."),),
            ),
        ),
        capture_methods=(
            CaptureMethodCapability(
                key="local_capture",
                label="Local capture",
                status="supported",
                available=True,
                requires_privilege=True,
                detail="Can capture locally with elevation.",
                tooling=("tcpdump",),
                reasons=(make_limitation("capture.requires_privilege", "Requires elevation."),),
            ),
        ),
        wpa=WPAReadinessCapability(
            state="ready",
            status="supported",
            handshake_artifact="capture.hc22000",
            crack_ready=True,
            decrypt_ready=True,
            detail="Handshake is present.",
            tooling=("hashcat",),
            reasons=(make_context("wpa.ready", "Handshake is available."),),
        ),
        remote=RemoteSupportCapability(
            status="supported",
            mode="linux_appliance",
            configured_host="pi@raspberrypi",
            ssh_available=True,
            scp_available=True,
            health_port=8741,
            detail="Remote controller is configured.",
            tooling=("ssh", "scp"),
            reasons=(make_context("remote.ready", "Remote host configured."),),
        ),
        replay_families=(
            ReplayFamilyCapability(
                family="http",
                decode_status="supported",
                export_status="supported",
                replay_status="supported_with_limits",
                detail="HTTP replay can be exported.",
                reasons=(make_blocker("replay.needs_context", "Replay still needs context."),),
            ),
        ),
    )

    payload = report.to_dict()

    assert payload["platform"]["os_name"] == "Linux"
    assert payload["platform"]["machine_model"] == "Mini PC"
    assert payload["privilege_mode"] == "sudo"
    assert payload["adapters"][0]["name"] == "wlan0"
    assert payload["adapters"][0]["reasons"][0]["code"] == "adapter.context"
    assert payload["tools"][0]["status"] == "available"
    assert payload["capture_methods"][0]["tooling"] == ("tcpdump",)
    assert payload["capture_methods"][0]["reasons"][0]["kind"] == "limitation"
    assert payload["wpa"]["handshake_artifact"] == "capture.hc22000"
    assert payload["remote"]["configured_host"] == "pi@raspberrypi"
    assert payload["remote"]["reasons"][0]["code"] == "remote.ready"
    assert payload["replay_families"][0]["family"] == "http"
    assert payload["replay_families"][0]["reasons"][0]["summary"] == "Replay still needs context."
