from __future__ import annotations

import base64
import zipfile
from pathlib import Path

from intel_core import ArtifactRecord, PluginExecutionContext
from intel_recovery import PassiveDecodeRecoveryPlugin


def test_passive_decode_recovery_decodes_base64_text(tmp_path) -> None:
    sample = tmp_path / "encoded.txt"
    sample.write_text(
        base64.b64encode(b"https://decoded.example/path email=decoded@example.com").decode("ascii"),
        encoding="utf-8",
    )

    plugin = PassiveDecodeRecoveryPlugin()
    result = plugin.recover(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="file", path=str(sample), media_type="text/plain"),
    )

    assert result.ok is True
    assert result.metrics["recovered_artifact_count"] >= 1
    recovered_artifact = next(record for record in result.records if getattr(record, "record_type", "") == "artifact")
    assert recovered_artifact.attributes["recovery_method"] == "base64_decode"
    recovered_text = Path(recovered_artifact.path).read_text(encoding="utf-8")
    assert "decoded.example" in recovered_text


def test_passive_decode_recovery_unpacks_zip_member(tmp_path) -> None:
    sample = tmp_path / "archive.zip"
    with zipfile.ZipFile(sample, "w") as archive:
        archive.writestr("inner.txt", "decoded member")

    plugin = PassiveDecodeRecoveryPlugin()
    result = plugin.recover(
        PluginExecutionContext(output_root=tmp_path / "out", workspace_root=tmp_path),
        ArtifactRecord(id="artifact-1", source_id="source-1", artifact_type="file", path=str(sample), media_type="application/zip"),
    )

    assert result.ok is True
    assert any(path.endswith("inner.txt") for path in result.artifact_paths)
