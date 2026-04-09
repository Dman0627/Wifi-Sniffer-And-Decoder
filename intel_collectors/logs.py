from __future__ import annotations

from pathlib import Path

from .filesystem import _FilesystemCollectorBase
from intel_core import PluginManifest


class LogCollectorPlugin(_FilesystemCollectorBase):
    manifest = PluginManifest(
        name="log_collector",
        version="0.1.0",
        plugin_type="collector",
        description="Collect line-oriented logs and log bundles into source/artifact intake records.",
        capabilities=("log-intake", "source-manifest", "queue-extract-job"),
        input_types=("log", "log-bundle"),
        output_types=("source", "artifact", "job"),
        policy_tags=("approved-source", "local-ingest", "log-ingest"),
    )
    artifact_type = "log"
    accepted_source_types = ("log", "log-bundle")
    _log_suffixes = {".log", ".txt", ".jsonl", ".ndjson", ".csv"}

    def _accepts(self, source_type: str, path: Path) -> bool:
        normalized = str(source_type or "").strip().lower()
        suffix = path.suffix.lower()
        if normalized == "log":
            return path.is_file() and suffix in self._log_suffixes
        if normalized == "log-bundle":
            if not path.exists():
                return False
            if path.is_file():
                return suffix in self._log_suffixes
            return path.is_dir()
        return False

    def _artifact_tags(self, path: Path) -> tuple[str, ...]:
        tags = list(super()._artifact_tags(path))
        tags.extend(["log", "text-evidence"])
        return tuple(dict.fromkeys(tags))

    def _is_append_only_change(
        self,
        *,
        path: Path,
        requested_type: str,
        previous_row: dict[str, object],
        size_bytes: int,
        media_type: str,
    ) -> bool:
        previous_size_bytes = int(previous_row.get("size_bytes") or 0)
        if size_bytes <= previous_size_bytes:
            return False
        if path.suffix.lower() in self._log_suffixes:
            return True
        return media_type.startswith("text/")
