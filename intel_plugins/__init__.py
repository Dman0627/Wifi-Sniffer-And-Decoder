from intel_core.registry import PluginRegistry

from intel_collectors import (
    ApprovedConnectorStubPlugin,
    FileCollectorPlugin,
    HttpFeedCollectorPlugin,
    LogCollectorPlugin,
    PcapCollectorPlugin,
    RdapDomainCollectorPlugin,
    SystemArtifactCollectorPlugin,
)
from intel_correlators import GraphCorrelatorPlugin
from intel_extractors import (
    ArchiveInventoryExtractorPlugin,
    BinaryMetadataExtractorPlugin,
    DocumentStructureExtractorPlugin,
    EmbeddedSignatureExtractorPlugin,
    ExifToolMetadataExtractorPlugin,
    MetadataExtractorPlugin,
    PcapSessionExtractorPlugin,
    StringIndicatorExtractorPlugin,
    SystemArtifactMetadataExtractorPlugin,
    YaraRuleExtractorPlugin,
)
from intel_normalizers import CanonicalRecordNormalizerPlugin
from intel_recovery import PassiveDecodeRecoveryPlugin
from .wifi import WifiPipelinePlugin


def builtin_plugins() -> tuple[object, ...]:
    return (
        FileCollectorPlugin(),
        HttpFeedCollectorPlugin(),
        LogCollectorPlugin(),
        PcapCollectorPlugin(),
        RdapDomainCollectorPlugin(),
        SystemArtifactCollectorPlugin(),
        ArchiveInventoryExtractorPlugin(),
        BinaryMetadataExtractorPlugin(),
        DocumentStructureExtractorPlugin(),
        EmbeddedSignatureExtractorPlugin(),
        ExifToolMetadataExtractorPlugin(),
        MetadataExtractorPlugin(),
        PcapSessionExtractorPlugin(),
        StringIndicatorExtractorPlugin(),
        SystemArtifactMetadataExtractorPlugin(),
        YaraRuleExtractorPlugin(),
        PassiveDecodeRecoveryPlugin(),
        CanonicalRecordNormalizerPlugin(),
        GraphCorrelatorPlugin(),
        WifiPipelinePlugin(),
        ApprovedConnectorStubPlugin(),
    )


def build_builtin_registry() -> PluginRegistry:
    registry = PluginRegistry()
    for plugin in builtin_plugins():
        registry.register_plugin(plugin)
    return registry


__all__ = ["WifiPipelinePlugin", "build_builtin_registry", "builtin_plugins"]
