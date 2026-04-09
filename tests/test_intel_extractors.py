from __future__ import annotations

import json
import plistlib
import sqlite3
import struct
import sys
import zipfile
from pathlib import Path

from intel_core import ArtifactRecord, PluginExecutionContext
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


def test_metadata_extractor_emits_event_for_artifact(tmp_path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("hello metadata", encoding="utf-8")

    plugin = MetadataExtractorPlugin()
    result = plugin.extract(
        PluginExecutionContext(case_id="case-1", output_root=tmp_path / "out", workspace_root=tmp_path),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="file", path=str(sample), media_type="text/plain"),
    )

    assert result.ok is True
    event = result.records[0]
    assert getattr(event, "event_type", "") == "artifact_metadata"


def test_string_indicator_extractor_emits_url_and_email_indicators(tmp_path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("visit https://example.com and email test@example.com", encoding="utf-8")

    plugin = StringIndicatorExtractorPlugin()
    result = plugin.extract(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="file", path=str(sample), media_type="text/plain"),
    )

    assert result.ok is True
    indicator_types = {getattr(record, "indicator_type", "") for record in result.records if getattr(record, "record_type", "") == "indicator"}
    assert "url" in indicator_types
    assert "email" in indicator_types


def test_document_structure_extractor_summarizes_pdf(tmp_path) -> None:
    sample = tmp_path / "sample.pdf"
    sample.write_bytes(
        b"%PDF-1.7\n"
        b"1 0 obj << /Type /Catalog >> endobj\n"
        b"2 0 obj << /Type /Page >> endobj\n"
        b"3 0 obj << /Type /Page >> endobj\n"
        b"<< /Title (Quarterly Report) /Author (Analyst One) >>\n"
    )

    plugin = DocumentStructureExtractorPlugin()
    result = plugin.extract(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="file", path=str(sample), media_type="application/pdf"),
    )

    assert result.ok is True
    event = result.records[0]
    assert getattr(event, "event_type", "") == "document_structure"
    assert event.attributes["document_format"] == "pdf"
    assert event.attributes["page_count"] == "2"
    assert event.attributes["title"] == "Quarterly Report"


def test_document_structure_extractor_reads_ooxml_metadata(tmp_path) -> None:
    sample = tmp_path / "report.docx"
    with zipfile.ZipFile(sample, "w") as archive:
        archive.writestr(
            "docProps/core.xml",
            """<?xml version="1.0" encoding="UTF-8"?>
            <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                xmlns:dc="http://purl.org/dc/elements/1.1/">
              <dc:title>Threat Report</dc:title>
              <dc:creator>intel-team</dc:creator>
              <dc:subject>Case Summary</dc:subject>
            </cp:coreProperties>""",
        )
        archive.writestr(
            "word/document.xml",
            """<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
            <w:body><w:p /><w:p /><w:p /></w:body></w:document>""",
        )

    plugin = DocumentStructureExtractorPlugin()
    result = plugin.extract(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        ArtifactRecord(
            id="artifact-1",
            source_id="source-1",
            artifact_type="file",
            path=str(sample),
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
    )

    assert result.ok is True
    event = result.records[0]
    assert event.attributes["document_format"] == "docx"
    assert event.attributes["creator"] == "intel-team"
    assert event.attributes["paragraph_count"] == "3"


def test_archive_inventory_extractor_lists_zip_members(tmp_path) -> None:
    sample = tmp_path / "bundle.zip"
    with zipfile.ZipFile(sample, "w") as archive:
        archive.writestr("alpha.txt", "a")
        archive.writestr("nested/beta.txt", "b")

    plugin = ArchiveInventoryExtractorPlugin()
    result = plugin.extract(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="file", path=str(sample), media_type="application/zip"),
    )

    assert result.ok is True
    event = result.records[0]
    assert event.attributes["archive_format"] == "zip"
    assert event.attributes["member_count"] == "2"
    assert "alpha.txt" in event.attributes["sample_members"]


def test_binary_metadata_extractor_reads_pe_header(tmp_path) -> None:
    sample = tmp_path / "program.exe"
    data = bytearray(512)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 3, 1712556000, 0, 0, 0xF0, 0x2022)
    struct.pack_into("<H", data, 0x98, 0x20B)
    sample.write_bytes(bytes(data))

    plugin = BinaryMetadataExtractorPlugin()
    result = plugin.extract(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="file", path=str(sample), media_type="application/octet-stream"),
    )

    assert result.ok is True
    event = result.records[0]
    assert event.attributes["binary_format"] == "pe"
    assert event.attributes["machine"] == "x86_64"
    assert event.attributes["section_count"] == "3"


def test_system_artifact_metadata_extractor_summarizes_sqlite(tmp_path) -> None:
    sample = tmp_path / "evidence.sqlite"
    with sqlite3.connect(sample) as connection:
        connection.execute("CREATE TABLE sessions(id INTEGER PRIMARY KEY, user TEXT)")
        connection.execute("CREATE TABLE hosts(id INTEGER PRIMARY KEY, name TEXT)")
        connection.execute("INSERT INTO sessions(user) VALUES ('alice')")
        connection.commit()

    plugin = SystemArtifactMetadataExtractorPlugin()
    result = plugin.extract(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="system_artifact", path=str(sample), media_type="application/vnd.sqlite3"),
    )

    assert result.ok is True
    event = result.records[0]
    assert event.attributes["artifact_format"] == "sqlite"
    assert event.attributes["table_count"] == "2"
    assert "sessions" in event.attributes["table_names"]


def test_system_artifact_metadata_extractor_summarizes_plist(tmp_path) -> None:
    sample = tmp_path / "settings.plist"
    with sample.open("wb") as handle:
        plistlib.dump({"User": "alice", "Enabled": True, "Count": 3}, handle)

    plugin = SystemArtifactMetadataExtractorPlugin()
    result = plugin.extract(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="system_artifact", path=str(sample), media_type="application/x-plist"),
    )

    assert result.ok is True
    event = result.records[0]
    assert event.attributes["artifact_format"] == "plist"
    assert event.attributes["top_level_type"] == "dict"
    assert "User" in event.attributes["top_level_keys"]


def test_system_artifact_metadata_extractor_summarizes_evtx(tmp_path) -> None:
    sample = tmp_path / "Security.evtx"
    sample.write_bytes(b"ElfFile\x00" + b"\x00" * 64 + b"ElfChnk")

    plugin = SystemArtifactMetadataExtractorPlugin()
    result = plugin.extract(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="system_artifact", path=str(sample), media_type="application/octet-stream"),
    )

    assert result.ok is True
    event = result.records[0]
    assert event.attributes["artifact_format"] == "evtx"
    assert event.attributes["header_signature"] == "ElfFile"


def test_system_artifact_metadata_extractor_summarizes_registry_hive(tmp_path) -> None:
    sample = tmp_path / "SOFTWARE.hve"
    data = bytearray(4096)
    data[0:4] = b"regf"
    data[4:8] = (11).to_bytes(4, "little")
    data[8:12] = (11).to_bytes(4, "little")
    hive_name = "SOFTWARE".encode("utf-16-le")
    data[48:48 + len(hive_name)] = hive_name
    sample.write_bytes(bytes(data))

    plugin = SystemArtifactMetadataExtractorPlugin()
    result = plugin.extract(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="system_artifact", path=str(sample), media_type="application/octet-stream"),
    )

    assert result.ok is True
    event = result.records[0]
    assert event.attributes["artifact_format"] == "registry_hive"
    assert event.attributes["header_signature"] == "regf"


def test_embedded_signature_extractor_carves_child_artifact(tmp_path) -> None:
    sample = tmp_path / "container.bin"
    sample.write_bytes(b"prefix" + b"\x89PNG\r\n\x1a\n" + b"payload")

    plugin = EmbeddedSignatureExtractorPlugin()
    result = plugin.extract(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="file", path=str(sample), media_type="application/octet-stream"),
    )

    assert result.ok is True
    assert any(getattr(record, "record_type", "") == "artifact" for record in result.records)
    assert any(path.endswith(".png") for path in result.artifact_paths)


def test_exiftool_metadata_extractor_skips_cleanly_when_tool_missing(monkeypatch, tmp_path) -> None:
    sample = tmp_path / "sample.jpg"
    sample.write_bytes(b"fake image bytes")

    monkeypatch.setattr("intel_extractors.external.shutil.which", lambda _tool: None)

    plugin = ExifToolMetadataExtractorPlugin()
    result = plugin.extract(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="file", path=str(sample), media_type="image/jpeg"),
    )

    assert result.ok is True
    assert result.records == ()
    assert result.metrics["exiftool_available"] is False
    assert result.metrics["exiftool_field_count"] == 0


def test_exiftool_metadata_extractor_uses_optional_external_command(tmp_path) -> None:
    sample = tmp_path / "sample.jpg"
    sample.write_bytes(b"fake image bytes")
    script = tmp_path / "fake_exiftool.py"
    script.write_text(
        "import json, sys\n"
        "print(json.dumps([{\n"
        "  'SourceFile': sys.argv[-1],\n"
        "  'FileType': 'JPEG',\n"
        "  'MIMEType': 'image/jpeg',\n"
        "  'Author': 'Analyst',\n"
        "  'Software': 'FakeExif 1.0'\n"
        "}]))\n",
        encoding="utf-8",
    )

    plugin = ExifToolMetadataExtractorPlugin()
    result = plugin.extract(
        PluginExecutionContext(
            output_root=tmp_path / "out",
            workspace_root=tmp_path,
            config={"exiftool_command": [sys.executable, str(script)]},
        ),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="file", path=str(sample), media_type="image/jpeg"),
    )

    assert result.ok is True
    assert any(path.endswith("exiftool.json") for path in result.artifact_paths)
    event = result.records[0]
    assert getattr(event, "event_type", "") == "external_metadata_enrichment"
    assert event.attributes["tool"] == "exiftool"
    assert event.attributes["file_type"] == "JPEG"
    assert event.attributes["author"] == "Analyst"
    assert json.loads(Path(result.artifact_paths[0]).read_text(encoding="utf-8"))["MIMEType"] == "image/jpeg"


def test_yara_rule_extractor_requires_rules_configuration(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"binary data")

    plugin = YaraRuleExtractorPlugin()
    result = plugin.extract(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="file", path=str(sample), media_type="application/octet-stream"),
    )

    assert result.ok is True
    assert result.records == ()
    assert result.metrics["yara_configured"] is False
    assert result.metrics["yara_match_count"] == 0


def test_yara_rule_extractor_uses_optional_external_command(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"binary data")
    rules_path = tmp_path / "rules.yar"
    rules_path.write_text("rule suspicious_rule { condition: true }", encoding="utf-8")
    script = tmp_path / "fake_yara.py"
    script.write_text(
        "import sys\n"
        "print(f'suspicious_rule {sys.argv[-1]}')\n",
        encoding="utf-8",
    )

    plugin = YaraRuleExtractorPlugin()
    result = plugin.extract(
        PluginExecutionContext(
            output_root=tmp_path / "out",
            workspace_root=tmp_path,
            config={
                "yara_command": [sys.executable, str(script)],
                "yara_rules_path": str(rules_path),
            },
        ),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="file", path=str(sample), media_type="application/octet-stream"),
    )

    assert result.ok is True
    assert any(path.endswith("yara_matches.txt") for path in result.artifact_paths)
    assert any(getattr(record, "record_type", "") == "indicator" and getattr(record, "indicator_type", "") == "yara_rule" for record in result.records)
    assert any(
        getattr(record, "record_type", "") == "relationship"
        and getattr(record, "relationship_type", "") == "artifact_matches_indicator"
        for record in result.records
    )
    event = next(record for record in result.records if getattr(record, "record_type", "") == "event")
    assert event.attributes["tool"] == "yara"
    assert event.attributes["match_count"] == "1"
    assert "suspicious_rule" in Path(result.artifact_paths[0]).read_text(encoding="utf-8")


def test_pcap_session_extractor_delegates_to_wifi_pipeline(monkeypatch, tmp_path) -> None:
    pcap = tmp_path / "capture.pcapng"
    pcap.write_bytes(b"pcap")
    seen = {}

    def fake_run_extract(config, pcap_path):
        _unused = pcap_path
        output_dir = Path(str(config["output_dir"]))
        seen["output_dir"] = output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = output_dir / "manifest.json"
        manifest_path.write_text('{"streams": [{"stream_id": "s1"}], "units": [{"unit_index": 1}]}', encoding="utf-8")
        return {"streams": [{"stream_id": "s1"}], "units": [{"unit_index": 1}]}

    monkeypatch.setattr("intel_extractors.pcap.wifi_cli.run_extract", fake_run_extract)

    plugin = PcapSessionExtractorPlugin()
    result = plugin.extract(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="pcap", path=str(pcap), media_type="application/x-pcapng"),
    )

    assert result.ok is True
    assert any(getattr(record, "artifact_type", "") == "network_manifest" for record in result.records if getattr(record, "record_type", "") == "artifact")
    assert "objects" in str(seen["output_dir"])
