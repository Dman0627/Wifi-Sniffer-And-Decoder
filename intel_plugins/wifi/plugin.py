from __future__ import annotations

from typing import Optional

from intel_core.contracts import PluginExecutionContext, PluginManifest
from wifi_pipeline import __version__ as WIFI_PIPELINE_VERSION
from wifi_pipeline import cli as wifi_cli


class WifiPipelinePlugin:
    manifest = PluginManifest(
        name="wifi_pipeline",
        version=WIFI_PIPELINE_VERSION,
        plugin_type="workflow",
        description="Compatibility wrapper around the existing Wi-Fi capture and analysis pipeline.",
        capabilities=(
            "pcap-intake",
            "network-session-extraction",
            "protocol-detection",
            "cipher-analysis",
            "artifact-enrichment",
            "local-dashboard",
        ),
        input_types=("pcap", "pcapng", "wifi-capture"),
        output_types=("artifact", "indicator", "relationship", "event"),
        policy_tags=("approved-source", "passive-analysis"),
    )

    @staticmethod
    def supported_stage_ids() -> tuple[str, ...]:
        return ("extract", "detect", "analyze", "enrich", "play", "all")

    def healthcheck(self) -> tuple[str, ...]:
        return ()

    def build_config(self, context: PluginExecutionContext) -> dict[str, object]:
        config = dict(context.config or {})
        if not config.get("output_dir"):
            config["output_dir"] = str(context.output_root)
        return config

    def run_extract(
        self,
        context: PluginExecutionContext,
        pcap_path: Optional[str] = None,
    ) -> Optional[dict[str, object]]:
        return wifi_cli.run_extract(self.build_config(context), pcap_path)

    def run_detect(
        self,
        context: PluginExecutionContext,
        manifest_path: Optional[str] = None,
    ) -> Optional[dict[str, object]]:
        return wifi_cli.run_detect(self.build_config(context), manifest_path)

    def run_analyze(
        self,
        context: PluginExecutionContext,
        decrypted_dir: Optional[str] = None,
    ) -> Optional[dict[str, object]]:
        return wifi_cli.run_analyze(self.build_config(context), decrypted_dir)

    def run_enrich(
        self,
        context: PluginExecutionContext,
        manifest_path: Optional[str] = None,
    ) -> Optional[dict[str, object]]:
        return wifi_cli.run_enrich(self.build_config(context), manifest_path)

    def run_play(self, context: PluginExecutionContext) -> Optional[str]:
        return wifi_cli.run_play(self.build_config(context))

    def run_all(
        self,
        context: PluginExecutionContext,
        *,
        pcap_path: Optional[str] = None,
        decrypted_dir: Optional[str] = None,
        strip_wifi: bool = False,
    ) -> None:
        wifi_cli.run_all(
            self.build_config(context),
            pcap_path,
            decrypted_dir,
            strip_wifi,
        )
