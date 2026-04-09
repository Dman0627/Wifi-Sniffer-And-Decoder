from __future__ import annotations

import hashlib
import json
import mimetypes
import time
from pathlib import Path
from typing import Dict, List, Optional

from .protocols import payload_family, shannon_entropy
from .ui import done, err, info, section, warn


def _load_manifest(path: Path) -> Dict[str, object]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _read_bytes(path: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError:
        return b""


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest() if data else ""


def _prefix_hex(data: bytes, size: int = 16) -> str:
    return data[:size].hex() if data else ""


class ArtifactEnricher:
    def __init__(self, config: Dict[str, object]) -> None:
        self.config = config
        self.output_dir = Path(str(config.get("output_dir") or "./pipeline_output")).resolve()
        self.manifest_path = self.output_dir / "manifest.json"
        self.report_path = self.output_dir / "enrichment_report.json"

    def _artifact_row(self, unit: Dict[str, object]) -> Optional[Dict[str, object]]:
        file_path = str(unit.get("file") or "").strip()
        if not file_path:
            return None

        resolved = Path(file_path)
        payload = _read_bytes(file_path)
        unit_type = str(unit.get("unit_type") or "opaque_chunk")
        extension = resolved.suffix.lower()
        mime_type, _encoding = mimetypes.guess_type(resolved.name)

        return {
            "unit_index": int(unit.get("unit_index", 0) or 0),
            "stream_id": str(unit.get("stream_id") or ""),
            "file": str(resolved),
            "exists": resolved.exists(),
            "unit_type": unit_type,
            "payload_family": payload_family(unit_type),
            "extension": extension,
            "mime_type": mime_type or "",
            "size_bytes": int(unit.get("length", len(payload)) or len(payload)),
            "entropy": round(shannon_entropy(payload), 3) if payload else 0.0,
            "sha256": _sha256_hex(payload),
            "prefix_hex": _prefix_hex(payload),
        }

    def enrich(self, manifest_path: Optional[str] = None) -> Dict[str, object]:
        section("Stage 5 - Artifact Enrichment")
        path = Path(manifest_path).resolve() if manifest_path else self.manifest_path
        if not path.exists():
            err(f"Manifest not found: {path}")
            return {}

        manifest = _load_manifest(path)
        units = list(manifest.get("units", []))
        streams = list(manifest.get("streams", []))
        if not units:
            warn("Manifest contains no extracted units.")
            return {}

        artifacts: List[Dict[str, object]] = []
        stream_artifacts: Dict[str, List[Dict[str, object]]] = {}
        unit_type_counts: Dict[str, int] = {}
        payload_family_counts: Dict[str, int] = {}

        for unit in units:
            artifact = self._artifact_row(dict(unit))
            if not artifact:
                continue
            artifacts.append(artifact)
            stream_id = str(artifact.get("stream_id") or "")
            stream_artifacts.setdefault(stream_id, []).append(artifact)
            unit_type = str(artifact.get("unit_type") or "opaque_chunk")
            family = str(artifact.get("payload_family") or "opaque")
            unit_type_counts[unit_type] = unit_type_counts.get(unit_type, 0) + 1
            payload_family_counts[family] = payload_family_counts.get(family, 0) + 1

        stream_summaries: List[Dict[str, object]] = []
        for stream in streams:
            stream_id = str(stream.get("stream_id") or "")
            rows = list(stream_artifacts.get(stream_id, []))
            rows.sort(
                key=lambda item: (
                    str(item.get("payload_family") or "opaque") == "opaque",
                    -int(item.get("size_bytes", 0) or 0),
                    int(item.get("unit_index", 0) or 0),
                )
            )
            families = sorted({str(item.get("payload_family") or "opaque") for item in rows if str(item.get("payload_family") or "opaque") != "opaque"})
            unit_types = [str(item.get("unit_type") or "opaque_chunk") for item in rows]
            dominant_unit_type = max(set(unit_types), key=unit_types.count) if unit_types else "opaque_chunk"
            entropy_values = [float(item.get("entropy", 0.0) or 0.0) for item in rows]
            stream_summaries.append(
                {
                    "stream_id": stream_id,
                    "protocol": str(stream.get("protocol") or ""),
                    "unit_count": int(stream.get("unit_count", len(rows)) or len(rows)),
                    "byte_count": int(stream.get("byte_count", 0) or 0),
                    "dominant_unit_type": dominant_unit_type,
                    "payload_families": families,
                    "recognized_artifact_count": sum(
                        1 for item in rows if str(item.get("payload_family") or "opaque") != "opaque"
                    ),
                    "average_entropy": round(sum(entropy_values) / len(entropy_values), 3) if entropy_values else 0.0,
                    "artifacts": rows[:8],
                }
            )

        artifacts.sort(
            key=lambda item: (
                str(item.get("payload_family") or "opaque") == "opaque",
                -int(item.get("size_bytes", 0) or 0),
                int(item.get("unit_index", 0) or 0),
            )
        )

        report = {
            "schema_version": 1,
            "generated_at": time.time(),
            "manifest_path": str(path),
            "units_analyzed": len(artifacts),
            "streams_analyzed": len(stream_summaries),
            "recognized_artifact_count": sum(
                1 for item in artifacts if str(item.get("payload_family") or "opaque") != "opaque"
            ),
            "unit_type_counts": unit_type_counts,
            "payload_family_counts": payload_family_counts,
            "top_artifacts": artifacts[:32],
            "streams": stream_summaries,
        }

        self.report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        info(
            f"Analyzed {report['units_analyzed']} extracted units across "
            f"{report['streams_analyzed']} streams."
        )
        done(f"Enrichment report written to {self.report_path}")
        return report
