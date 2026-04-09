from __future__ import annotations

import hashlib
import json
import mimetypes
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from intel_core import (
    ArtifactRecord,
    Confidence,
    IngestRequest,
    JobRecord,
    PluginExecutionContext,
    PluginManifest,
    PluginResult,
    Provenance,
    SourceRecord,
    new_record_id,
    record_to_dict,
    stable_record_id,
    utc_now,
)
from intel_storage import ensure_workspace_layout, materialize_raw_artifact


@dataclass(slots=True)
class FilesystemSourceSnapshot:
    path: Path
    requested_type: str
    recursive: bool
    display_name: str
    media_type: str
    size_bytes: int
    cursor: str
    content_hash: str
    file_rows: tuple[dict[str, object], ...]
    reused_hash_count: int = 0
    full_hash_count: int = 0
    changed_file_count: int = 0
    append_only_file_count: int = 0
    removed_file_count: int = 0

    @property
    def file_count(self) -> int:
        return len(self.file_rows)


def _sha256_hex(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _guess_media_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".pcap":
        return "application/vnd.tcpdump.pcap"
    if suffix == ".pcapng":
        return "application/x-pcapng"
    guessed, _encoding = mimetypes.guess_type(path.name)
    return guessed or "application/octet-stream"


def _ensure_output_dirs(context: PluginExecutionContext, source_id: str, job_id: str) -> tuple[Path, Path]:
    ensure_workspace_layout(context.output_root)
    intake_dir = context.output_root / "intake" / source_id
    queue_dir = context.output_root / "queues" / "extract"
    job_dir = intake_dir / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    queue_dir.mkdir(parents=True, exist_ok=True)
    return job_dir, queue_dir


def _iter_input_files(path: Path, *, recursive: bool) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.exists():
        return []
    iterator: Iterable[Path]
    iterator = path.rglob("*") if recursive else path.glob("*")
    return sorted(entry for entry in iterator if entry.is_file())


def _relative_path(root: Path, file_path: Path) -> str:
    try:
        return str(file_path.relative_to(root))
    except ValueError:
        return file_path.name


def _source_content_hash(path: Path, file_rows: list[dict[str, object]]) -> str:
    if path.is_file() and file_rows:
        return str(file_rows[0]["sha256"])
    payload = [
        {
            "relative_path": row["relative_path"],
            "sha256": row["sha256"],
            "size_bytes": row["size_bytes"],
        }
        for row in sorted(file_rows, key=lambda item: str(item["relative_path"]))
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _source_cursor(file_rows: list[dict[str, object]]) -> str:
    payload = [
        {
            "relative_path": row["relative_path"],
            "size_bytes": row["size_bytes"],
            "mtime_ns": row["mtime_ns"],
        }
        for row in sorted(file_rows, key=lambda item: str(item["relative_path"]))
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _previous_rows_by_relative_path(previous_watcher_state: dict[str, object] | None) -> dict[str, dict[str, object]]:
    rows: dict[str, dict[str, object]] = {}
    for item in list((previous_watcher_state or {}).get("file_rows") or []):
        if not isinstance(item, dict):
            continue
        relative_path = str(item.get("relative_path") or "").strip()
        if not relative_path:
            continue
        rows[relative_path] = dict(item)
    return rows


class _FilesystemCollectorBase:
    manifest: PluginManifest
    artifact_type: str = "file"
    accepted_source_types: tuple[str, ...] = ()

    def healthcheck(self) -> tuple[str, ...]:
        return ()

    def _accepts(self, source_type: str, path: Path) -> bool:
        normalized = str(source_type or "").strip().lower()
        if normalized in self.accepted_source_types:
            return True
        return False

    def _artifact_tags(self, path: Path) -> tuple[str, ...]:
        tags = ["artifact", "ingested"]
        suffix = path.suffix.lower().lstrip(".")
        if suffix:
            tags.append(suffix)
        if self.artifact_type == "pcap":
            tags.extend(["network", "pcap"])
        return tuple(tags)

    def _is_append_only_change(
        self,
        *,
        path: Path,
        requested_type: str,
        previous_row: dict[str, object],
        size_bytes: int,
        media_type: str,
    ) -> bool:
        return False

    def snapshot_source(
        self,
        request: IngestRequest,
        *,
        previous_watcher_state: dict[str, object] | None = None,
    ) -> FilesystemSourceSnapshot:
        path = Path(request.locator).expanduser().resolve()
        requested_type = str(request.source_type or "").strip().lower()
        recursive = bool(request.options.get("recursive", True))

        if not path.exists():
            raise FileNotFoundError(f"source does not exist: {path}")
        if not self._accepts(requested_type, path):
            raise ValueError(f"{self.manifest.name} does not accept source type {requested_type!r}")

        files = _iter_input_files(path, recursive=recursive)
        if not files:
            raise FileNotFoundError(f"no files found for source: {path}")

        previous_rows = _previous_rows_by_relative_path(previous_watcher_state)
        file_rows_list: list[dict[str, object]] = []
        reused_hash_count = 0
        full_hash_count = 0
        changed_file_count = 0
        append_only_file_count = 0
        current_relative_paths: set[str] = set()

        for file_path in files:
            stat = file_path.stat()
            relative_path = _relative_path(path, file_path) if path.is_dir() else file_path.name
            current_relative_paths.add(str(relative_path))
            media_type = _guess_media_type(file_path)
            size_bytes = stat.st_size
            mtime_ns = int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000)))
            previous_row = dict(previous_rows.get(str(relative_path)) or {})
            previous_sha256 = str(previous_row.get("sha256") or "")
            previous_size_bytes = int(previous_row.get("size_bytes") or 0)
            previous_mtime_ns = int(previous_row.get("mtime_ns") or 0)
            change_kind = "new"
            hash_reused = False
            appended_bytes = 0

            if previous_row and previous_sha256 and previous_size_bytes == size_bytes and previous_mtime_ns == mtime_ns:
                sha256 = previous_sha256
                hash_reused = True
                reused_hash_count += 1
                change_kind = "unchanged"
            else:
                sha256 = _sha256_hex(file_path)
                full_hash_count += 1
                if previous_row:
                    if previous_sha256 and previous_sha256 == sha256 and previous_size_bytes == size_bytes:
                        change_kind = "unchanged"
                    elif self._is_append_only_change(
                        path=file_path,
                        requested_type=requested_type,
                        previous_row=previous_row,
                        size_bytes=size_bytes,
                        media_type=media_type,
                    ):
                        change_kind = "appended"
                        appended_bytes = max(0, size_bytes - previous_size_bytes)
                        append_only_file_count += 1
                    else:
                        change_kind = "modified"

            if change_kind != "unchanged":
                changed_file_count += 1

            file_rows_list.append(
                {
                    "path": file_path,
                    "relative_path": relative_path,
                    "sha256": sha256,
                    "size_bytes": size_bytes,
                    "media_type": media_type,
                    "mtime_ns": mtime_ns,
                    "hash_reused": hash_reused,
                    "change_kind": change_kind,
                    "previous_size_bytes": previous_size_bytes,
                    "previous_mtime_ns": previous_mtime_ns,
                    "appended_bytes": appended_bytes,
                }
            )

        removed_file_count = len(set(previous_rows.keys()) - current_relative_paths)
        changed_file_count += removed_file_count
        file_rows = tuple(file_rows_list)
        return FilesystemSourceSnapshot(
            path=path,
            requested_type=requested_type,
            recursive=recursive,
            display_name=request.display_name or path.name or str(path),
            media_type=_guess_media_type(path) if path.is_file() else "inode/directory",
            size_bytes=path.stat().st_size if path.is_file() else 0,
            cursor=_source_cursor(list(file_rows)),
            content_hash=_source_content_hash(path, list(file_rows)),
            file_rows=file_rows,
            reused_hash_count=reused_hash_count,
            full_hash_count=full_hash_count,
            changed_file_count=changed_file_count,
            append_only_file_count=append_only_file_count,
            removed_file_count=removed_file_count,
        )

    def collect_from_snapshot(
        self,
        context: PluginExecutionContext,
        request: IngestRequest,
        snapshot: FilesystemSourceSnapshot,
    ) -> PluginResult:
        path = snapshot.path
        requested_type = snapshot.requested_type
        source_content_hash = snapshot.content_hash
        source_id = stable_record_id("source", context.case_id, requested_type, str(path), source_content_hash)
        job_id = stable_record_id("job", source_id, "extract", "queued")
        job_dir, queue_dir = _ensure_output_dirs(context, source_id, job_id)

        source_record = SourceRecord(
            id=source_id,
            source_id=source_id,
            case_id=context.case_id,
            source_type=requested_type,
            locator=str(path),
            display_name=snapshot.display_name,
            collector=self.manifest.name,
            media_type=snapshot.media_type,
            content_hash=source_content_hash,
            size_bytes=snapshot.size_bytes,
            provenance=Provenance(
                plugin=self.manifest.name,
                method="collect",
                source_refs=(str(path),),
                notes="ingested by filesystem collector",
            ),
            confidence=Confidence(score=1.0),
            tags=(requested_type, "source"),
            attributes={
                "recursive": str(snapshot.recursive).lower(),
                "workspace_root": str(context.workspace_root),
                "object_store_root": str((context.output_root / "objects" / "raw").resolve()),
            },
        )

        artifacts: list[ArtifactRecord] = []
        for row in snapshot.file_rows:
            file_path = Path(str(row["path"]))
            object_path = materialize_raw_artifact(
                context.output_root,
                file_path,
                content_hash=str(row["sha256"]),
                preferred_name=file_path.name,
            )
            artifacts.append(
                ArtifactRecord(
                    id=stable_record_id(
                        "artifact",
                        source_id,
                        self.artifact_type,
                        str(row["relative_path"]),
                        str(row["sha256"]),
                    ),
                    source_id=source_id,
                    case_id=context.case_id,
                    artifact_type=self.artifact_type,
                    path=str(object_path),
                    media_type=str(row["media_type"]),
                    sha256=str(row["sha256"]),
                    size_bytes=int(row["size_bytes"]),
                    provenance=Provenance(
                        plugin=self.manifest.name,
                        method="collect",
                        source_refs=(source_id,),
                        parent_refs=(source_id,),
                        notes="filesystem ingestion artifact",
                    ),
                    confidence=Confidence(score=1.0),
                    tags=self._artifact_tags(file_path),
                    attributes={
                        "file_name": file_path.name,
                        "suffix": file_path.suffix.lower(),
                        "original_path": str(file_path),
                        "relative_path": str(row["relative_path"]),
                        "object_path": str(object_path),
                    },
                )
            )

        queued_job = JobRecord(
            id=job_id,
            source_id=source_id,
            case_id=context.case_id,
            job_type="pipeline-stage",
            stage="extract",
            status="queued",
            input_refs=tuple(artifact.id for artifact in artifacts),
            output_refs=(),
            worker=self.manifest.name,
            provenance=Provenance(
                plugin=self.manifest.name,
                method="queue",
                source_refs=(source_id,),
                parent_refs=(source_id,),
                notes="queued extract stage after ingestion",
            ),
            confidence=Confidence(score=1.0),
            tags=("job", "queued", "extract"),
            attributes={
                "requested_source_type": requested_type,
                "file_count": str(len(artifacts)),
            },
        )

        manifest_payload = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "plugin": {
                "name": self.manifest.name,
                "version": self.manifest.version,
                "type": self.manifest.plugin_type,
            },
            "request": {
                "source_type": requested_type,
                "locator": str(path),
                "display_name": snapshot.display_name,
                "options": dict(request.options or {}),
            },
            "source": record_to_dict(source_record),
            "artifacts": [record_to_dict(artifact) for artifact in artifacts],
            "queued_jobs": [record_to_dict(queued_job)],
        }
        manifest_path = job_dir / "source_manifest.json"
        manifest_path.write_text(json.dumps(manifest_payload, indent=2), encoding="utf-8")

        queue_payload = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "job": record_to_dict(queued_job),
            "source": record_to_dict(source_record),
            "artifact_refs": [artifact.id for artifact in artifacts],
            "source_manifest_path": str(manifest_path),
        }
        queue_path = queue_dir / f"{job_id}.json"
        queue_path.write_text(json.dumps(queue_payload, indent=2), encoding="utf-8")

        return PluginResult(
            records=(source_record, *artifacts, queued_job),
            artifact_paths=(str(manifest_path), str(queue_path)),
            metrics={
                "source_id": source_id,
                "job_id": job_id,
                "file_count": len(artifacts),
                "artifact_count": len(artifacts),
            },
        )

    def collect(self, context: PluginExecutionContext, request: IngestRequest) -> PluginResult:
        try:
            snapshot = self.snapshot_source(request)
        except (FileNotFoundError, ValueError) as exc:
            return PluginResult(errors=(str(exc),))
        return self.collect_from_snapshot(context, request, snapshot)


class FileCollectorPlugin(_FilesystemCollectorBase):
    manifest = PluginManifest(
        name="file_collector",
        version="0.1.0",
        plugin_type="collector",
        description="Collect individual files and directories into source/artifact intake records.",
        capabilities=("file-intake", "directory-intake", "source-manifest", "queue-extract-job"),
        input_types=("file", "directory"),
        output_types=("source", "artifact", "job"),
        policy_tags=("approved-source", "local-ingest"),
    )
    artifact_type = "file"
    accepted_source_types = ("file", "directory")

    def _accepts(self, source_type: str, path: Path) -> bool:
        normalized = str(source_type or "").strip().lower()
        if normalized == "file":
            return path.is_file()
        if normalized == "directory":
            return path.is_dir()
        return False


class PcapCollectorPlugin(_FilesystemCollectorBase):
    manifest = PluginManifest(
        name="pcap_collector",
        version="0.1.0",
        plugin_type="collector",
        description="Collect pcap and pcapng files into source/artifact intake records.",
        capabilities=("pcap-intake", "source-manifest", "queue-extract-job"),
        input_types=("pcap", "pcapng", "wifi-capture"),
        output_types=("source", "artifact", "job"),
        policy_tags=("approved-source", "network-ingest", "passive-analysis"),
    )
    artifact_type = "pcap"
    accepted_source_types = ("pcap", "pcapng", "wifi-capture")

    def _accepts(self, source_type: str, path: Path) -> bool:
        normalized = str(source_type or "").strip().lower()
        suffix = path.suffix.lower()
        if normalized == "pcap":
            return path.is_file() and suffix == ".pcap"
        if normalized == "pcapng":
            return path.is_file() and suffix == ".pcapng"
        if normalized == "wifi-capture":
            return path.is_file() and suffix in {".pcap", ".pcapng"}
        return False
