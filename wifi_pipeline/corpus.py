from __future__ import annotations

import hashlib
import json
import math
import shutil
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .protocols import payload_family, shannon_entropy, suggested_extension

CORPUS_SCHEMA_VERSION = 1
MAX_SIGNATURE_UNITS = 16
MAX_SIGNATURE_BYTES_PER_UNIT = 4096
MAX_ARCHIVED_UNIT_SAMPLES = 8


def _safe_slug(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "._-" else "_" for char in value)
    return cleaned.strip("_") or "stream"


def _read_bytes(path: object, limit: Optional[int] = None) -> bytes:
    try:
        data = Path(str(path or "")).read_bytes()
    except OSError:
        return b""
    if limit is not None:
        return data[:limit]
    return data


def _mean(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _stddev(values: Sequence[float]) -> float:
    if len(values) <= 1:
        return 0.0
    mean_value = _mean(values)
    variance = sum((value - mean_value) ** 2 for value in values) / len(values)
    return math.sqrt(variance)


def _bucket_histogram(payloads: Sequence[bytes], buckets: int = 16) -> List[float]:
    counts = [0] * buckets
    total = 0
    bucket_size = max(1, 256 // buckets)
    for payload in payloads:
        for byte in payload:
            counts[min(buckets - 1, byte // bucket_size)] += 1
            total += 1
    if total == 0:
        return [0.0] * buckets
    return [round(count / total, 6) for count in counts]


def _size_signature(lengths: Sequence[int], limit: int = 12) -> List[int]:
    return [int(length) for length in lengths[:limit] if int(length) >= 0]


def _prefix_signature(payloads: Sequence[bytes], limit: int = 4, prefix_bytes: int = 8) -> List[str]:
    prefixes: List[str] = []
    for payload in payloads:
        if not payload:
            continue
        prefixes.append(payload[:prefix_bytes].hex())
        if len(prefixes) >= limit:
            break
    return prefixes


def _sample_sha256(payloads: Sequence[bytes]) -> str:
    if not payloads:
        return ""
    digest = hashlib.sha256()
    for payload in payloads:
        digest.update(payload)
    return digest.hexdigest()


def _dominant_unit_type(stream_row: Dict[str, object], units: Sequence[Dict[str, object]]) -> str:
    counts = dict(stream_row.get("unit_type_counts") or {})
    if counts:
        return str(max(counts.items(), key=lambda item: item[1])[0])

    unit_counts: Dict[str, int] = {}
    for unit in units:
        unit_type = str(unit.get("unit_type") or "opaque_chunk")
        unit_counts[unit_type] = unit_counts.get(unit_type, 0) + 1
    if unit_counts:
        return str(max(unit_counts.items(), key=lambda item: item[1])[0])
    return "opaque_chunk"


def _sequence_similarity(left: Sequence[int], right: Sequence[int]) -> float:
    if not left or not right:
        return 0.0
    limit = min(len(left), len(right))
    scores: List[float] = []
    for index in range(limit):
        lhs = max(1, int(left[index]))
        rhs = max(1, int(right[index]))
        scores.append(max(0.0, 1.0 - (abs(lhs - rhs) / max(lhs, rhs))))
    return _mean(scores)


def _ratio_similarity(left: float, right: float, max_ratio: float) -> float:
    lhs = max(left, 1e-6)
    rhs = max(right, 1e-6)
    ratio = max(lhs, rhs) / min(lhs, rhs)
    if ratio <= 1.0:
        return 1.0
    if ratio >= max_ratio:
        return 0.0
    return max(0.0, 1.0 - (math.log(ratio, 2) / math.log(max_ratio, 2)))


def _histogram_similarity(left: Sequence[float], right: Sequence[float]) -> float:
    if not left or not right or len(left) != len(right):
        return 0.0
    distance = 0.5 * sum(abs(float(lhs) - float(rhs)) for lhs, rhs in zip(left, right))
    return max(0.0, 1.0 - distance)


def _fingerprint_similarity(left: Dict[str, object], right: Dict[str, object]) -> Tuple[float, List[str]]:
    if left.get("sample_sha256") and left.get("sample_sha256") == right.get("sample_sha256"):
        return 1.0, ["sample hash matched exactly"]

    reasons: List[str] = []
    score = 0.0

    if left.get("protocol") and left.get("protocol") == right.get("protocol"):
        score += 0.08
        reasons.append("same transport protocol")

    if left.get("dominant_unit_type") and left.get("dominant_unit_type") == right.get("dominant_unit_type"):
        score += 0.18
        reasons.append("same dominant payload type")
    else:
        left_families = set(left.get("payload_families") or [])
        right_families = set(right.get("payload_families") or [])
        if left_families and right_families and left_families & right_families:
            score += 0.1
            reasons.append("payload families overlap")

    entropy_similarity = max(
        0.0,
        1.0 - (abs(float(left.get("mean_entropy", 0.0)) - float(right.get("mean_entropy", 0.0))) / 2.5),
    )
    if entropy_similarity >= 0.7:
        reasons.append("entropy profile is close")
    score += entropy_similarity * 0.14

    histogram_similarity = _histogram_similarity(
        list(left.get("histogram_16") or []),
        list(right.get("histogram_16") or []),
    )
    if histogram_similarity >= 0.75:
        reasons.append("byte histogram is close")
    score += histogram_similarity * 0.18

    size_similarity = _sequence_similarity(
        list(left.get("size_signature") or []),
        list(right.get("size_signature") or []),
    )
    if size_similarity >= 0.7:
        reasons.append("unit length pattern is similar")
    score += size_similarity * 0.18

    average_length_similarity = _ratio_similarity(
        float(left.get("average_payload_length", 0.0)),
        float(right.get("average_payload_length", 0.0)),
        max_ratio=8.0,
    )
    score += average_length_similarity * 0.1

    cadence_similarity = _ratio_similarity(
        float(left.get("packets_per_second", 0.0)) + 0.1,
        float(right.get("packets_per_second", 0.0)) + 0.1,
        max_ratio=12.0,
    )
    if cadence_similarity >= 0.7:
        reasons.append("packet cadence lines up")
    score += cadence_similarity * 0.07

    throughput_similarity = _ratio_similarity(
        float(left.get("bytes_per_second", 0.0)) + 1.0,
        float(right.get("bytes_per_second", 0.0)) + 1.0,
        max_ratio=20.0,
    )
    score += throughput_similarity * 0.07

    unit_count_similarity = _ratio_similarity(
        float(left.get("unit_count", 0.0)) + 1.0,
        float(right.get("unit_count", 0.0)) + 1.0,
        max_ratio=16.0,
    )
    score += unit_count_similarity * 0.05

    left_ports = set(int(port) for port in list(left.get("ports") or []) if port is not None)
    right_ports = set(int(port) for port in list(right.get("ports") or []) if port is not None)
    if left_ports and right_ports and left_ports & right_ports:
        score += 0.05
        reasons.append("ports overlap")

    left_prefixes = set(str(prefix) for prefix in list(left.get("prefixes") or []) if prefix)
    right_prefixes = set(str(prefix) for prefix in list(right.get("prefixes") or []) if prefix)
    if left_prefixes and right_prefixes and left_prefixes & right_prefixes:
        score += 0.08
        reasons.append("sample prefixes overlap")

    if left.get("candidate_class") and left.get("candidate_class") == right.get("candidate_class"):
        score += 0.05

    return round(min(score, 1.0), 3), reasons


class CorpusStore:
    def __init__(self, config: Dict[str, object]) -> None:
        self.config = config
        self.output_dir = Path(str(config.get("output_dir") or "./pipeline_output")).resolve()
        self.corpus_dir = self.output_dir / "corpus"
        self.entries_dir = self.corpus_dir / "entries"
        self.index_path = self.corpus_dir / "index.json"

    def _empty_index(self) -> Dict[str, object]:
        return {
            "schema_version": CORPUS_SCHEMA_VERSION,
            "generated_at": time.time(),
            "entries": [],
        }

    def _load_index(self) -> Dict[str, object]:
        if not self.index_path.exists():
            return self._empty_index()
        try:
            with open(self.index_path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return self._empty_index()
        if int(loaded.get("schema_version", 0) or 0) != CORPUS_SCHEMA_VERSION:
            return self._empty_index()
        loaded.setdefault("entries", [])
        return loaded

    def _save_index(self, index: Dict[str, object]) -> None:
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.entries_dir.mkdir(parents=True, exist_ok=True)
        index["generated_at"] = time.time()
        self.index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")

    def status(self) -> Dict[str, object]:
        index = self._load_index()
        entries = list(index.get("entries", []))
        material_entries = [entry for entry in entries if entry.get("candidate_material")]
        latest = max(entries, key=lambda item: float(item.get("last_seen_at", 0.0)), default=None)
        return {
            "entry_count": len(entries),
            "candidate_material_count": len(material_entries),
            "latest_entry": latest,
        }

    def recent_entries(self, limit: int = 8) -> List[Dict[str, object]]:
        index = self._load_index()
        entries = list(index.get("entries", []))
        entries.sort(key=lambda item: float(item.get("last_seen_at", 0.0)), reverse=True)
        return entries[:limit]

    def _stream_profile(
        self, manifest: Dict[str, object], stream_row: Dict[str, object]
    ) -> Optional[Dict[str, object]]:
        stream_id = str(stream_row.get("stream_id") or "").strip()
        if not stream_id:
            return None

        stream_summary = next(
            (stream for stream in manifest.get("streams", []) if str(stream.get("stream_id") or "") == stream_id),
            None,
        )
        units = [
            unit
            for unit in manifest.get("units", [])
            if str(unit.get("stream_id") or "") == stream_id
        ]
        units.sort(key=lambda unit: (float(unit.get("timestamp_start", 0.0) or 0.0), int(unit.get("unit_index", 0) or 0)))

        if not stream_summary and not units:
            return None

        payloads = [
            _read_bytes(unit.get("file"), limit=MAX_SIGNATURE_BYTES_PER_UNIT)
            for unit in units[:MAX_SIGNATURE_UNITS]
        ]
        payloads = [payload for payload in payloads if payload]

        sample_lengths = [int(unit.get("length", 0) or 0) for unit in units[:MAX_SIGNATURE_UNITS]]
        entropies = [shannon_entropy(payload) for payload in payloads]
        dominant_unit_type = _dominant_unit_type(stream_row, units)
        unit_type_counts = dict(stream_row.get("unit_type_counts") or {})
        if not unit_type_counts:
            for unit in units:
                unit_type = str(unit.get("unit_type") or "opaque_chunk")
                unit_type_counts[unit_type] = unit_type_counts.get(unit_type, 0) + 1

        payload_families = sorted(
            {
                payload_family(unit_type)
                for unit_type in unit_type_counts
                if payload_family(unit_type) != "opaque"
            }
        )

        stream_data = dict(stream_summary or {})
        fingerprint = {
            "protocol": str(stream_data.get("protocol") or stream_row.get("protocol") or ""),
            "candidate_class": str(stream_row.get("candidate_class") or ""),
            "dominant_unit_type": dominant_unit_type,
            "payload_families": payload_families,
            "sample_sha256": _sample_sha256(payloads),
            "histogram_16": _bucket_histogram(payloads),
            "size_signature": _size_signature(sample_lengths),
            "prefixes": _prefix_signature(payloads),
            "mean_entropy": round(_mean(entropies), 4),
            "entropy_stddev": round(_stddev(entropies), 4),
            "average_payload_length": round(float(stream_data.get("average_payload_length", 0.0) or 0.0), 3),
            "packets_per_second": round(float(stream_data.get("packets_per_second", 0.0) or 0.0), 3),
            "bytes_per_second": round(float(stream_data.get("bytes_per_second", 0.0) or 0.0), 3),
            "unit_count": int(stream_data.get("unit_count", len(units)) or len(units)),
            "packet_count": int(stream_data.get("packet_count", 0) or 0),
            "byte_count": int(stream_data.get("byte_count", 0) or 0),
            "ports": [
                int(stream_data.get("sport", stream_row.get("sport", 0)) or 0),
                int(stream_data.get("dport", stream_row.get("dport", 0)) or 0),
            ],
        }

        return {
            "stream_id": stream_id,
            "flow_id": str(stream_row.get("flow_id") or stream_data.get("flow_id") or ""),
            "protocol": fingerprint["protocol"],
            "candidate_class": str(stream_row.get("candidate_class") or ""),
            "score": round(float(stream_row.get("score", 0.0) or 0.0), 3),
            "dominant_unit_type": dominant_unit_type,
            "payload_families": payload_families,
            "unit_type_counts": unit_type_counts,
            "fingerprint": fingerprint,
            "stream_summary": {
                "byte_count": int(stream_data.get("byte_count", 0) or 0),
                "packet_count": int(stream_data.get("packet_count", 0) or 0),
                "unit_count": int(stream_data.get("unit_count", len(units)) or len(units)),
                "duration_seconds": round(float(stream_data.get("duration_seconds", 0.0) or 0.0), 3),
                "average_payload_length": round(float(stream_data.get("average_payload_length", 0.0) or 0.0), 3),
                "payload_length_stddev": round(float(stream_data.get("payload_length_stddev", 0.0) or 0.0), 3),
                "packets_per_second": round(float(stream_data.get("packets_per_second", 0.0) or 0.0), 3),
                "bytes_per_second": round(float(stream_data.get("bytes_per_second", 0.0) or 0.0), 3),
                "sport": int(stream_data.get("sport", stream_row.get("sport", 0)) or 0),
                "dport": int(stream_data.get("dport", stream_row.get("dport", 0)) or 0),
                "src": str(stream_data.get("src") or stream_row.get("src") or ""),
                "dst": str(stream_data.get("dst") or stream_row.get("dst") or ""),
                "stream_file": str(stream_data.get("stream_file") or ""),
            },
            "sample_unit_files": [
                str(unit.get("file") or "")
                for unit in units[:MAX_ARCHIVED_UNIT_SAMPLES]
                if str(unit.get("file") or "")
            ],
            "pcap_path": str(manifest.get("pcap_path") or ""),
        }

    def _copy_stream_artifacts(self, entry_dir: Path, profile: Dict[str, object]) -> Dict[str, object]:
        archive: Dict[str, object] = {
            "entry_dir": str(entry_dir),
            "stream_file": "",
            "unit_samples": [],
        }
        stream_file = Path(str(profile.get("stream_summary", {}).get("stream_file") or ""))
        if stream_file.exists():
            suffix = stream_file.suffix or suggested_extension(str(profile.get("dominant_unit_type") or "opaque_chunk"))
            target = entry_dir / f"stream_capture{suffix}"
            shutil.copy2(stream_file, target)
            archive["stream_file"] = str(target)

        sample_dir = entry_dir / "sample_units"
        sample_dir.mkdir(parents=True, exist_ok=True)
        copied_samples: List[str] = []
        for sample_path in list(profile.get("sample_unit_files") or []):
            source = Path(str(sample_path))
            if not source.exists():
                continue
            target = sample_dir / source.name
            shutil.copy2(source, target)
            copied_samples.append(str(target))
        archive["unit_samples"] = copied_samples
        return archive

    def _archive_candidate_material(
        self, entry_dir: Path, candidate_material: Optional[Dict[str, object]]
    ) -> Dict[str, object]:
        material = dict(candidate_material or {})
        if not material:
            return {}

        archived = dict(material)
        source = str(archived.get("source") or "").strip()
        if source:
            source_path = Path(source)
            material_dir = entry_dir / "candidate_material"
            material_dir.mkdir(parents=True, exist_ok=True)
            if source_path.is_dir():
                target_dir = material_dir / source_path.name
                if source_path.exists() and source_path.resolve() == target_dir.resolve():
                    archived["source"] = str(target_dir)
                else:
                    if target_dir.exists():
                        shutil.rmtree(target_dir)
                    shutil.copytree(source_path, target_dir)
                    archived["source"] = str(target_dir)
            elif source_path.exists():
                target_file = material_dir / source_path.name
                if source_path.resolve() != target_file.resolve():
                    shutil.copy2(source_path, target_file)
                archived["source"] = str(target_file)
        (entry_dir / "candidate_material.json").write_text(json.dumps(archived, indent=2), encoding="utf-8")
        return archived

    def archive_candidate(
        self,
        manifest: Dict[str, object],
        stream_row: Dict[str, object],
        candidate_material: Optional[Dict[str, object]] = None,
    ) -> Optional[Dict[str, object]]:
        profile = self._stream_profile(manifest, stream_row)
        if not profile:
            return None

        index = self._load_index()
        entries = list(index.get("entries", []))
        sample_sha256 = str(profile["fingerprint"].get("sample_sha256") or "")
        existing = None
        if sample_sha256:
            existing = next(
                (
                    entry
                    for entry in entries
                    if str(entry.get("sample_sha256") or "") == sample_sha256
                    and str(entry.get("dominant_unit_type") or "") == str(profile.get("dominant_unit_type") or "")
                ),
                None,
            )
        timestamp = time.time()

        if existing:
            entry_dir = Path(str(existing.get("archive", {}).get("entry_dir") or ""))
            existing["last_seen_at"] = timestamp
            existing["seen_count"] = int(existing.get("seen_count", 1) or 1) + 1
            existing["pcap_path"] = str(profile.get("pcap_path") or "")
            existing["stream_id"] = str(profile.get("stream_id") or existing.get("stream_id") or "")
            existing["flow_id"] = str(profile.get("flow_id") or existing.get("flow_id") or "")
            existing["candidate_class"] = str(profile.get("candidate_class") or existing.get("candidate_class") or "")
            existing["score"] = round(float(profile.get("score", 0.0) or 0.0), 3)
            existing["stream_summary"] = dict(profile.get("stream_summary") or {})
            existing["fingerprint"] = dict(profile.get("fingerprint") or {})
            existing["payload_families"] = list(profile.get("payload_families") or [])
            existing["unit_type_counts"] = dict(profile.get("unit_type_counts") or {})
            if candidate_material and entry_dir.exists():
                archived_material = self._archive_candidate_material(entry_dir, candidate_material)
                existing["candidate_material"] = archived_material
                existing["candidate_material_available"] = bool(archived_material)
            if entry_dir.exists():
                (entry_dir / "entry.json").write_text(json.dumps(existing, indent=2), encoding="utf-8")
            self._save_index(index)
            return existing

        entry_hash = sample_sha256[:12] or hashlib.sha256(
            f"{profile.get('stream_id')}|{timestamp}".encode("utf-8")
        ).hexdigest()[:12]
        entry_id = f"{time.strftime('%Y%m%d_%H%M%S')}_{entry_hash}"
        entry_dir = self.entries_dir / entry_id
        entry_dir.mkdir(parents=True, exist_ok=True)

        archive = self._copy_stream_artifacts(entry_dir, profile)
        archived_material = self._archive_candidate_material(entry_dir, candidate_material)
        entry = {
            "entry_id": entry_id,
            "archived_at": timestamp,
            "last_seen_at": timestamp,
            "seen_count": 1,
            "pcap_path": str(profile.get("pcap_path") or ""),
            "stream_id": str(profile.get("stream_id") or ""),
            "flow_id": str(profile.get("flow_id") or ""),
            "protocol": str(profile.get("protocol") or ""),
            "candidate_class": str(profile.get("candidate_class") or ""),
            "score": round(float(profile.get("score", 0.0) or 0.0), 3),
            "dominant_unit_type": str(profile.get("dominant_unit_type") or "opaque_chunk"),
            "payload_families": list(profile.get("payload_families") or []),
            "unit_type_counts": dict(profile.get("unit_type_counts") or {}),
            "sample_sha256": sample_sha256,
            "fingerprint": dict(profile.get("fingerprint") or {}),
            "stream_summary": dict(profile.get("stream_summary") or {}),
            "candidate_material": archived_material,
            "candidate_material_available": bool(archived_material),
            "archive": archive,
        }

        (entry_dir / "entry.json").write_text(json.dumps(entry, indent=2), encoding="utf-8")
        entries.append(entry)
        entries.sort(key=lambda item: float(item.get("last_seen_at", 0.0)), reverse=True)
        index["entries"] = entries
        self._save_index(index)
        return entry

    def find_matches(
        self,
        manifest: Dict[str, object],
        stream_row: Dict[str, object],
        limit: int = 5,
    ) -> List[Dict[str, object]]:
        profile = self._stream_profile(manifest, stream_row)
        if not profile:
            return []

        current_fingerprint = dict(profile.get("fingerprint") or {})
        index = self._load_index()
        rows: List[Dict[str, object]] = []
        for entry in index.get("entries", []):
            fingerprint = dict(entry.get("fingerprint") or {})
            similarity, reasons = _fingerprint_similarity(current_fingerprint, fingerprint)
            if similarity < 0.45:
                continue
            rows.append(
                {
                    "entry_id": str(entry.get("entry_id") or ""),
                    "similarity": similarity,
                    "candidate_material_available": bool(entry.get("candidate_material")),
                    "candidate_material": dict(entry.get("candidate_material") or {}),
                    "candidate_class": str(entry.get("candidate_class") or ""),
                    "dominant_unit_type": str(entry.get("dominant_unit_type") or ""),
                    "archived_at": float(entry.get("archived_at", 0.0) or 0.0),
                    "last_seen_at": float(entry.get("last_seen_at", 0.0) or 0.0),
                    "seen_count": int(entry.get("seen_count", 1) or 1),
                    "stream_id": str(entry.get("stream_id") or ""),
                    "reasons": reasons[:6],
                    "archive": dict(entry.get("archive") or {}),
                }
            )
        rows.sort(key=lambda item: (float(item.get("similarity", 0.0)), float(item.get("last_seen_at", 0.0))), reverse=True)
        return rows[:limit]
