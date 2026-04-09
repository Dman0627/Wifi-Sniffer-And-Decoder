from __future__ import annotations

from pathlib import Path

from .filesystem import _FilesystemCollectorBase
from intel_core import PluginManifest


class SystemArtifactCollectorPlugin(_FilesystemCollectorBase):
    manifest = PluginManifest(
        name="system_artifact_collector",
        version="0.1.0",
        plugin_type="collector",
        description="Collect approved local system artifacts and artifact bundles into intake records.",
        capabilities=("system-artifact-intake", "source-manifest", "queue-extract-job"),
        input_types=("system-artifact", "system-artifact-bundle"),
        output_types=("source", "artifact", "job"),
        policy_tags=("approved-source", "local-ingest", "system-artifact"),
    )
    artifact_type = "system_artifact"
    accepted_source_types = ("system-artifact", "system-artifact-bundle")
    _artifact_suffixes = {
        ".evtx",
        ".sqlite",
        ".db",
        ".dat",
        ".reg",
        ".hve",
        ".plist",
        ".json",
        ".xml",
    }

    def _accepts(self, source_type: str, path: Path) -> bool:
        normalized = str(source_type or "").strip().lower()
        suffix = path.suffix.lower()
        if normalized == "system-artifact":
            return path.is_file() and suffix in self._artifact_suffixes
        if normalized == "system-artifact-bundle":
            if not path.exists():
                return False
            if path.is_file():
                return suffix in self._artifact_suffixes
            return path.is_dir()
        return False

    def _artifact_tags(self, path: Path) -> tuple[str, ...]:
        tags = list(super()._artifact_tags(path))
        tags.extend(["system", "artifact"])
        suffix = path.suffix.lower()
        if suffix == ".evtx":
            tags.append("event-log")
        if suffix in {".reg", ".hve"}:
            tags.append("registry")
        if suffix in {".sqlite", ".db"}:
            tags.append("database")
        return tuple(dict.fromkeys(tags))
