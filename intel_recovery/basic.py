from __future__ import annotations

import base64
import binascii
import gzip
import mimetypes
import re
import zipfile
from pathlib import Path
from urllib.parse import unquote

from intel_core import (
    ArtifactRecord,
    Confidence,
    EventRecord,
    PluginExecutionContext,
    PluginManifest,
    PluginResult,
    Provenance,
    RelationshipRecord,
    stable_record_id,
)
from intel_storage import stage_object_dir

MAX_TEXT_BYTES = 512 * 1024
MAX_RECOVERED_BYTES = 2 * 1024 * 1024
MAX_ZIP_MEMBERS = 16
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")
HEX_RE = re.compile(r"^[0-9A-Fa-f\s]+$")


class PassiveDecodeRecoveryPlugin:
    manifest = PluginManifest(
        name="passive_decode_recovery",
        version="0.1.0",
        plugin_type="recovery",
        description="Passively decode text encodings and unpack simple archives into recovered artifacts.",
        capabilities=("base64-decode", "hex-decode", "url-decode", "gzip-unpack", "zip-unpack"),
        input_types=("*",),
        output_types=("artifact", "relationship", "event"),
        policy_tags=("passive-analysis", "offline-recovery"),
    )

    def healthcheck(self) -> tuple[str, ...]:
        return ()

    def recover(self, context: PluginExecutionContext, artifact: ArtifactRecord) -> PluginResult:
        source_path = Path(artifact.path)
        if not source_path.exists():
            return PluginResult(errors=(f"artifact path not found: {source_path}",))

        recovered_dir = stage_object_dir(context.output_root, "recover", artifact.source_id, artifact.id)
        recovered_records: list[ArtifactRecord | RelationshipRecord] = []
        recovered_paths: list[str] = []
        warnings: list[str] = []
        methods: list[str] = []
        seen_ids: set[str] = set()

        try:
            file_bytes = source_path.read_bytes()
        except OSError as exc:
            return PluginResult(errors=(f"failed to read artifact for recovery: {exc}",))

        for method_name, file_name, payload_bytes in self._iter_recoveries(source_path, file_bytes):
            artifact_id = stable_record_id("artifact", artifact.id, method_name, file_name)
            if artifact_id in seen_ids:
                continue
            seen_ids.add(artifact_id)

            output_path = recovered_dir / file_name
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(payload_bytes)
            recovered_paths.append(str(output_path))
            methods.append(method_name)

            recovered_artifact = ArtifactRecord(
                id=artifact_id,
                source_id=artifact.source_id,
                case_id=context.case_id or artifact.case_id,
                artifact_type="file",
                path=str(output_path),
                media_type=_guess_media_type(output_path),
                sha256=_sha256_hex(payload_bytes),
                size_bytes=len(payload_bytes),
                parent_artifact_id=artifact.id,
                provenance=Provenance(
                    plugin=self.manifest.name,
                    method=method_name,
                    source_refs=(artifact.source_id,),
                    parent_refs=(artifact.id,),
                ),
                confidence=Confidence(score=0.82),
                tags=("recover", method_name, "artifact"),
                attributes={
                    "parent_artifact_id": artifact.id,
                    "recovery_method": method_name,
                    "original_artifact_path": artifact.path,
                },
            )
            recovered_records.append(recovered_artifact)
            recovered_records.append(
                RelationshipRecord(
                    id=stable_record_id("relationship", artifact.id, artifact_id, "artifact_recovers_artifact"),
                    source_id=artifact.source_id,
                    case_id=context.case_id or artifact.case_id,
                    relationship_type="artifact_recovers_artifact",
                    source_ref=artifact.id,
                    target_ref=recovered_artifact.id,
                    reason=f"{self.manifest.name} recovered an artifact via {method_name}",
                    provenance=Provenance(
                        plugin=self.manifest.name,
                        method="link",
                        source_refs=(artifact.source_id,),
                        parent_refs=(artifact.id, recovered_artifact.id),
                    ),
                    confidence=Confidence(score=0.82),
                    tags=("recover", "link", method_name),
                )
            )

        if not recovered_records:
            return PluginResult(metrics={"recovered_artifact_count": 0, "recovery_method_count": 0})

        summary = EventRecord(
            id=stable_record_id("event", artifact.id, "recovery_summary", tuple(methods)),
            source_id=artifact.source_id,
            case_id=context.case_id or artifact.case_id,
            event_type="recovery_summary",
            title=f"Recovery summary for {source_path.name}",
            artifact_refs=(artifact.id, *[record.id for record in recovered_records if isinstance(record, ArtifactRecord)]),
            summary="Recovered artifacts through passive decoding and archive/container unpacking.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="recover",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
            ),
            confidence=Confidence(score=0.82),
            tags=("recover", "summary"),
            attributes={
                "artifact_id": artifact.id,
                "recovered_artifact_count": str(sum(1 for record in recovered_records if isinstance(record, ArtifactRecord))),
                "recovery_methods": ",".join(sorted(dict.fromkeys(methods))),
            },
        )

        return PluginResult(
            records=(*recovered_records, summary),
            artifact_paths=tuple(recovered_paths),
            warnings=tuple(warnings),
            metrics={
                "recovered_artifact_count": sum(1 for record in recovered_records if isinstance(record, ArtifactRecord)),
                "recovery_method_count": len(tuple(dict.fromkeys(methods))),
            },
        )

    def _iter_recoveries(self, source_path: Path, file_bytes: bytes) -> list[tuple[str, str, bytes]]:
        rows: list[tuple[str, str, bytes]] = []
        rows.extend(self._recover_archives(source_path, file_bytes))
        rows.extend(self._recover_text_encodings(source_path, file_bytes))
        return rows

    def _recover_archives(self, source_path: Path, file_bytes: bytes) -> list[tuple[str, str, bytes]]:
        rows: list[tuple[str, str, bytes]] = []
        if zipfile.is_zipfile(source_path):
            with zipfile.ZipFile(source_path) as archive:
                member_index = 0
                for member in archive.infolist():
                    if member.is_dir():
                        continue
                    member_index += 1
                    if member_index > MAX_ZIP_MEMBERS:
                        break
                    payload = archive.read(member)
                    if len(payload) > MAX_RECOVERED_BYTES:
                        continue
                    member_name = Path(member.filename).name or f"member_{member_index:03d}.bin"
                    rows.append(("zip_member", f"{member_index:03d}_{member_name}", payload))

        if _looks_like_gzip(source_path, file_bytes):
            try:
                payload = gzip.decompress(file_bytes)
            except OSError:
                payload = b""
            if payload and len(payload) <= MAX_RECOVERED_BYTES:
                output_name = f"{source_path.stem or source_path.name}_gunzip{_guess_extension_from_bytes(payload)}"
                rows.append(("gzip_unpack", output_name, payload))
        return rows

    def _recover_text_encodings(self, source_path: Path, file_bytes: bytes) -> list[tuple[str, str, bytes]]:
        try:
            text = file_bytes[:MAX_TEXT_BYTES].decode("utf-8")
        except UnicodeDecodeError:
            return []

        stripped = text.strip()
        if not stripped:
            return []

        rows: list[tuple[str, str, bytes]] = []

        if len(stripped) % 4 == 0 and len(stripped) >= 16 and BASE64_RE.fullmatch(stripped):
            try:
                decoded = base64.b64decode(stripped, validate=True)
            except (binascii.Error, ValueError):
                decoded = b""
            if decoded and decoded != file_bytes and len(decoded) <= MAX_RECOVERED_BYTES:
                rows.append(("base64_decode", f"{source_path.stem or source_path.name}_base64{_guess_extension_from_bytes(decoded)}", decoded))

        hex_compact = "".join(stripped.split())
        if len(hex_compact) >= 16 and len(hex_compact) % 2 == 0 and HEX_RE.fullmatch(stripped):
            try:
                decoded = bytes.fromhex(hex_compact)
            except ValueError:
                decoded = b""
            if decoded and decoded != file_bytes and len(decoded) <= MAX_RECOVERED_BYTES:
                rows.append(("hex_decode", f"{source_path.stem or source_path.name}_hex{_guess_extension_from_bytes(decoded)}", decoded))

        if "%" in stripped:
            decoded_text = unquote(stripped)
            if decoded_text and decoded_text != stripped:
                decoded = decoded_text.encode("utf-8")
                if len(decoded) <= MAX_RECOVERED_BYTES:
                    rows.append(("url_decode", f"{source_path.stem or source_path.name}_urldecode.txt", decoded))

        return rows


def _looks_like_gzip(source_path: Path, file_bytes: bytes) -> bool:
    if source_path.suffix.lower() == ".gz":
        return True
    return len(file_bytes) >= 3 and file_bytes[:3] == b"\x1f\x8b\x08"


def _guess_extension_from_bytes(payload: bytes) -> str:
    if payload.startswith(b"%PDF-"):
        return ".pdf"
    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if payload.startswith(b"PK\x03\x04"):
        return ".zip"
    if payload.startswith(b"\x1f\x8b\x08"):
        return ".gz"
    try:
        payload.decode("utf-8")
        return ".txt"
    except UnicodeDecodeError:
        return ".bin"


def _guess_media_type(path: Path) -> str:
    guessed, _encoding = mimetypes.guess_type(path.name)
    return guessed or "application/octet-stream"


def _sha256_hex(payload: bytes) -> str:
    import hashlib

    return hashlib.sha256(payload).hexdigest()
