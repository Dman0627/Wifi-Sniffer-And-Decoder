from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Sequence, runtime_checkable

from .records import ArtifactRecord, RecordBase


def _tuple_of_strings(values: object) -> tuple[str, ...]:
    rows: list[str] = []
    seen = set()
    for value in list(values or []):
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        rows.append(text)
    return tuple(rows)


@dataclass(slots=True, kw_only=True)
class PluginManifest:
    name: str
    version: str
    plugin_type: str
    description: str = ""
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    input_types: tuple[str, ...] = field(default_factory=tuple)
    output_types: tuple[str, ...] = field(default_factory=tuple)
    required_tools: tuple[str, ...] = field(default_factory=tuple)
    policy_tags: tuple[str, ...] = field(default_factory=tuple)
    enabled_by_default: bool = True

    def __post_init__(self) -> None:
        self.name = str(self.name or "").strip()
        self.version = str(self.version or "").strip()
        self.plugin_type = str(self.plugin_type or "").strip()
        self.description = str(self.description or "").strip()
        self.capabilities = _tuple_of_strings(self.capabilities)
        self.input_types = _tuple_of_strings(self.input_types)
        self.output_types = _tuple_of_strings(self.output_types)
        self.required_tools = _tuple_of_strings(self.required_tools)
        self.policy_tags = _tuple_of_strings(self.policy_tags)


@dataclass(slots=True, kw_only=True)
class IngestRequest:
    source_type: str
    locator: str
    display_name: str = ""
    options: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.source_type = str(self.source_type or "").strip()
        self.locator = str(self.locator or "").strip()
        self.display_name = str(self.display_name or "").strip()
        self.options = dict(self.options or {})


@dataclass(slots=True, kw_only=True)
class PluginExecutionContext:
    job_id: str = ""
    case_id: str = ""
    workspace_root: Path = field(default_factory=lambda: Path(".").resolve())
    output_root: Path = field(default_factory=lambda: Path("./pipeline_output").resolve())
    config: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.job_id = str(self.job_id or "").strip()
        self.case_id = str(self.case_id or "").strip()
        self.workspace_root = Path(self.workspace_root).resolve()
        self.output_root = Path(self.output_root).resolve()
        self.config = dict(self.config or {})


@dataclass(slots=True, kw_only=True)
class PluginResult:
    records: tuple[RecordBase, ...] = field(default_factory=tuple)
    artifact_paths: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)
    metrics: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.records = tuple(self.records or ())
        self.artifact_paths = _tuple_of_strings(self.artifact_paths)
        self.warnings = _tuple_of_strings(self.warnings)
        self.errors = _tuple_of_strings(self.errors)
        self.metrics = dict(self.metrics or {})

    @property
    def ok(self) -> bool:
        return not self.errors


@runtime_checkable
class BasePlugin(Protocol):
    manifest: PluginManifest

    def healthcheck(self) -> Sequence[str]:
        ...


@runtime_checkable
class CollectorPlugin(BasePlugin, Protocol):
    def collect(self, context: PluginExecutionContext, request: IngestRequest) -> PluginResult:
        ...


@runtime_checkable
class ExtractorPlugin(BasePlugin, Protocol):
    def extract(self, context: PluginExecutionContext, artifact: ArtifactRecord) -> PluginResult:
        ...


@runtime_checkable
class NormalizerPlugin(BasePlugin, Protocol):
    def normalize(self, context: PluginExecutionContext, records: Sequence[RecordBase]) -> PluginResult:
        ...


@runtime_checkable
class RecoveryPlugin(BasePlugin, Protocol):
    def recover(self, context: PluginExecutionContext, artifact: ArtifactRecord) -> PluginResult:
        ...


@runtime_checkable
class CorrelatorPlugin(BasePlugin, Protocol):
    def correlate(self, context: PluginExecutionContext, records: Sequence[RecordBase]) -> PluginResult:
        ...
