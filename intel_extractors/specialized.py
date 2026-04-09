from __future__ import annotations

import io
import re
import struct
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree as ET

from intel_core import (
    ArtifactRecord,
    Confidence,
    EventRecord,
    PluginExecutionContext,
    PluginManifest,
    PluginResult,
    Provenance,
    stable_record_id,
)

MAX_READ_BYTES = 4 * 1024 * 1024
OOXML_NAMESPACES = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
}
PE_MACHINE_TYPES = {
    0x014C: "x86",
    0x0200: "intel_itanium",
    0x01C0: "arm",
    0xAA64: "arm64",
    0x8664: "x86_64",
}
ELF_MACHINE_TYPES = {
    0x03: "x86",
    0x28: "arm",
    0x3E: "x86_64",
    0xB7: "arm64",
}


def _read_bytes(path: Path, *, limit: int = MAX_READ_BYTES) -> bytes:
    try:
        return path.read_bytes()[:limit]
    except OSError:
        return b""


class DocumentStructureExtractorPlugin:
    manifest = PluginManifest(
        name="document_structure_extractor",
        version="0.1.0",
        plugin_type="extractor",
        description="Extract basic structure and metadata from PDFs and OOXML documents.",
        capabilities=("pdf-structure", "ooxml-metadata", "document-summary"),
        input_types=("*",),
        output_types=("event",),
        policy_tags=("passive-analysis",),
    )

    def healthcheck(self) -> tuple[str, ...]:
        return ()

    def extract(self, context: PluginExecutionContext, artifact: ArtifactRecord) -> PluginResult:
        path = Path(artifact.path)
        if not path.exists():
            return PluginResult(errors=(f"artifact path not found: {path}",))

        suffix = path.suffix.lower()
        if suffix == ".pdf" or artifact.media_type == "application/pdf":
            event = self._extract_pdf(context, artifact, path)
            return PluginResult(records=(event,), metrics={"document_event_count": 1}) if event else PluginResult(metrics={"document_event_count": 0})
        if suffix in {".docx", ".xlsx", ".pptx"}:
            event = self._extract_ooxml(context, artifact, path, suffix=suffix)
            return PluginResult(records=(event,), metrics={"document_event_count": 1}) if event else PluginResult(metrics={"document_event_count": 0})
        return PluginResult(metrics={"document_event_count": 0})

    def _extract_pdf(
        self,
        context: PluginExecutionContext,
        artifact: ArtifactRecord,
        path: Path,
    ) -> EventRecord | None:
        data = _read_bytes(path)
        if not data.startswith(b"%PDF-"):
            return None

        page_count = len(re.findall(rb"/Type\s*/Page\b", data))
        version = data.splitlines()[0].decode("latin-1", errors="replace").strip()
        title = _pdf_metadata_value(data, b"Title")
        author = _pdf_metadata_value(data, b"Author")

        return EventRecord(
            id=stable_record_id("event", artifact.id, "document_structure", "pdf"),
            source_id=artifact.source_id,
            case_id=context.case_id or artifact.case_id,
            event_type="document_structure",
            title=f"Document structure for {path.name}",
            artifact_refs=(artifact.id,),
            summary="Extracted passive PDF structure and metadata fields.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="pdf-signature+regex",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
            ),
            confidence=Confidence(score=0.84),
            tags=("extract", "document", "pdf"),
            attributes={
                "artifact_id": artifact.id,
                "document_format": "pdf",
                "pdf_version": version,
                "page_count": str(page_count),
                "title": title,
                "author": author,
            },
        )

    def _extract_ooxml(
        self,
        context: PluginExecutionContext,
        artifact: ArtifactRecord,
        path: Path,
        *,
        suffix: str,
    ) -> EventRecord | None:
        if not zipfile.is_zipfile(path):
            return None

        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            entry_count = len(names)
            creator = ""
            title = ""
            subject = ""
            if "docProps/core.xml" in names:
                core = ET.fromstring(archive.read("docProps/core.xml"))
                creator = _xml_text(core.find("dc:creator", OOXML_NAMESPACES))
                title = _xml_text(core.find("dc:title", OOXML_NAMESPACES))
                subject = _xml_text(core.find("dc:subject", OOXML_NAMESPACES))

            structure_attributes = {
                "artifact_id": artifact.id,
                "document_format": suffix.lstrip("."),
                "entry_count": str(entry_count),
                "title": title,
                "creator": creator,
                "subject": subject,
            }
            if suffix == ".docx" and "word/document.xml" in names:
                document_tree = ET.fromstring(archive.read("word/document.xml"))
                structure_attributes["paragraph_count"] = str(
                    len(document_tree.findall(".//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p"))
                )
            elif suffix == ".xlsx":
                structure_attributes["worksheet_count"] = str(
                    len([name for name in names if name.startswith("xl/worksheets/") and name.endswith(".xml")])
                )
            elif suffix == ".pptx":
                structure_attributes["slide_count"] = str(
                    len([name for name in names if name.startswith("ppt/slides/slide") and name.endswith(".xml")])
                )

        return EventRecord(
            id=stable_record_id("event", artifact.id, "document_structure", suffix),
            source_id=artifact.source_id,
            case_id=context.case_id or artifact.case_id,
            event_type="document_structure",
            title=f"Document structure for {path.name}",
            artifact_refs=(artifact.id,),
            summary="Extracted passive OOXML structure and core document metadata.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="zip+core-properties",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
            ),
            confidence=Confidence(score=0.88),
            tags=("extract", "document", suffix.lstrip(".")),
            attributes=structure_attributes,
        )


class ArchiveInventoryExtractorPlugin:
    manifest = PluginManifest(
        name="archive_inventory_extractor",
        version="0.1.0",
        plugin_type="extractor",
        description="Inventory basic structure for zip and tar archives.",
        capabilities=("archive-inventory", "archive-member-summary"),
        input_types=("*",),
        output_types=("event",),
        policy_tags=("passive-analysis",),
    )

    def healthcheck(self) -> tuple[str, ...]:
        return ()

    def extract(self, context: PluginExecutionContext, artifact: ArtifactRecord) -> PluginResult:
        path = Path(artifact.path)
        if not path.exists():
            return PluginResult(errors=(f"artifact path not found: {path}",))

        event = self._extract_zip(context, artifact, path) or self._extract_tar(context, artifact, path)
        if event is None:
            return PluginResult(metrics={"archive_event_count": 0})
        return PluginResult(records=(event,), metrics={"archive_event_count": 1})

    def _extract_zip(
        self,
        context: PluginExecutionContext,
        artifact: ArtifactRecord,
        path: Path,
    ) -> EventRecord | None:
        if not zipfile.is_zipfile(path):
            return None
        with zipfile.ZipFile(path) as archive:
            members = [member for member in archive.infolist() if not member.is_dir()]
            sample_members = ", ".join(item.filename for item in members[:5])
            total_uncompressed = sum(item.file_size for item in members)
        return EventRecord(
            id=stable_record_id("event", artifact.id, "archive_inventory", "zip"),
            source_id=artifact.source_id,
            case_id=context.case_id or artifact.case_id,
            event_type="archive_inventory",
            title=f"Archive inventory for {path.name}",
            artifact_refs=(artifact.id,),
            summary="Indexed passive member metadata for a zip-based archive.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="zip-inventory",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
            ),
            confidence=Confidence(score=0.9),
            tags=("extract", "archive", "zip"),
            attributes={
                "artifact_id": artifact.id,
                "archive_format": "zip",
                "member_count": str(len(members)),
                "sample_members": sample_members,
                "total_uncompressed_bytes": str(total_uncompressed),
            },
        )

    def _extract_tar(
        self,
        context: PluginExecutionContext,
        artifact: ArtifactRecord,
        path: Path,
    ) -> EventRecord | None:
        try:
            is_tar = tarfile.is_tarfile(path)
        except OSError:
            is_tar = False
        if not is_tar:
            return None
        with tarfile.open(path) as archive:
            members = [member for member in archive.getmembers() if member.isfile()]
            sample_members = ", ".join(item.name for item in members[:5])
            total_uncompressed = sum(item.size for item in members)
        return EventRecord(
            id=stable_record_id("event", artifact.id, "archive_inventory", "tar"),
            source_id=artifact.source_id,
            case_id=context.case_id or artifact.case_id,
            event_type="archive_inventory",
            title=f"Archive inventory for {path.name}",
            artifact_refs=(artifact.id,),
            summary="Indexed passive member metadata for a tar archive.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="tar-inventory",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
            ),
            confidence=Confidence(score=0.9),
            tags=("extract", "archive", "tar"),
            attributes={
                "artifact_id": artifact.id,
                "archive_format": "tar",
                "member_count": str(len(members)),
                "sample_members": sample_members,
                "total_uncompressed_bytes": str(total_uncompressed),
            },
        )


class BinaryMetadataExtractorPlugin:
    manifest = PluginManifest(
        name="binary_metadata_extractor",
        version="0.1.0",
        plugin_type="extractor",
        description="Extract basic PE and ELF header metadata from binary artifacts.",
        capabilities=("pe-header-parse", "elf-header-parse", "binary-summary"),
        input_types=("*",),
        output_types=("event",),
        policy_tags=("passive-analysis",),
    )

    def healthcheck(self) -> tuple[str, ...]:
        return ()

    def extract(self, context: PluginExecutionContext, artifact: ArtifactRecord) -> PluginResult:
        path = Path(artifact.path)
        if not path.exists():
            return PluginResult(errors=(f"artifact path not found: {path}",))

        event = self._extract_pe(context, artifact, path) or self._extract_elf(context, artifact, path)
        if event is None:
            return PluginResult(metrics={"binary_event_count": 0})
        return PluginResult(records=(event,), metrics={"binary_event_count": 1})

    def _extract_pe(
        self,
        context: PluginExecutionContext,
        artifact: ArtifactRecord,
        path: Path,
    ) -> EventRecord | None:
        data = _read_bytes(path)
        if len(data) < 0x40 or not data.startswith(b"MZ"):
            return None

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return None

        machine, section_count, timestamp = struct.unpack_from("<HHI", data, pe_offset + 4)
        optional_magic = struct.unpack_from("<H", data, pe_offset + 24)[0] if pe_offset + 26 <= len(data) else 0
        return EventRecord(
            id=stable_record_id("event", artifact.id, "binary_metadata", "pe"),
            source_id=artifact.source_id,
            case_id=context.case_id or artifact.case_id,
            event_type="binary_metadata",
            title=f"Binary metadata for {path.name}",
            artifact_refs=(artifact.id,),
            summary="Parsed passive PE/COFF header metadata from a binary artifact.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="pe-header",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
            ),
            confidence=Confidence(score=0.9),
            tags=("extract", "binary", "pe"),
            attributes={
                "artifact_id": artifact.id,
                "binary_format": "pe",
                "machine": PE_MACHINE_TYPES.get(machine, hex(machine)),
                "section_count": str(section_count),
                "compile_time_utc": _unix_time(timestamp),
                "optional_header_magic": hex(optional_magic),
            },
        )

    def _extract_elf(
        self,
        context: PluginExecutionContext,
        artifact: ArtifactRecord,
        path: Path,
    ) -> EventRecord | None:
        data = _read_bytes(path)
        if len(data) < 0x20 or not data.startswith(b"\x7fELF"):
            return None

        elf_class = data[4]
        endian = data[5]
        if endian not in {1, 2}:
            return None
        byte_order = "<" if endian == 1 else ">"
        machine = struct.unpack_from(f"{byte_order}H", data, 18)[0]
        entry_offset = 24 if elf_class == 1 else 24
        entry_format = "I" if elf_class == 1 else "Q"
        entry_point = struct.unpack_from(f"{byte_order}{entry_format}", data, entry_offset)[0]
        return EventRecord(
            id=stable_record_id("event", artifact.id, "binary_metadata", "elf"),
            source_id=artifact.source_id,
            case_id=context.case_id or artifact.case_id,
            event_type="binary_metadata",
            title=f"Binary metadata for {path.name}",
            artifact_refs=(artifact.id,),
            summary="Parsed passive ELF header metadata from a binary artifact.",
            provenance=Provenance(
                plugin=self.manifest.name,
                method="elf-header",
                source_refs=(artifact.source_id,),
                parent_refs=(artifact.id,),
            ),
            confidence=Confidence(score=0.9),
            tags=("extract", "binary", "elf"),
            attributes={
                "artifact_id": artifact.id,
                "binary_format": "elf",
                "machine": ELF_MACHINE_TYPES.get(machine, hex(machine)),
                "elf_class": "elf64" if elf_class == 2 else "elf32",
                "endianness": "little" if endian == 1 else "big",
                "entry_point": hex(entry_point),
            },
        )


def _pdf_metadata_value(data: bytes, name: bytes) -> str:
    match = re.search(rb"/" + name + rb"\s*\(([^)]{0,512})\)", data)
    if not match:
        return ""
    return match.group(1).decode("latin-1", errors="replace").strip()


def _xml_text(node: ET.Element | None) -> str:
    if node is None or node.text is None:
        return ""
    return str(node.text).strip()


def _unix_time(value: int) -> str:
    if value <= 0:
        return ""
    try:
        return datetime.fromtimestamp(value, tz=UTC).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return ""
