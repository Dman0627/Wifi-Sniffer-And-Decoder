from __future__ import annotations

import json
import os
import statistics
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .corpus import CorpusStore
from .protocols import (
    guess_unit_type,
    payload_family,
    shannon_entropy,
    summarize_protocol_hits,
)
from .ui import done, err, info, ok, section, warn

try:
    import numpy as np

    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


def _load_manifest(path: Path) -> Dict[str, object]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _safe_read_bytes(path: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError:
        return b""


def _normalized_hex(value: object) -> str:
    raw = "".join(ch for ch in str(value or "") if ch.lower() in "0123456789abcdef")
    if len(raw) % 2 != 0:
        return ""
    return raw.lower()


def _custom_magic_bytes(config: Dict[str, object]) -> bytes:
    normalized = _normalized_hex(config.get("custom_magic_hex"))
    if not normalized:
        return b""
    try:
        return bytes.fromhex(normalized)
    except ValueError:
        return b""


def _group_units_by_stream(units: List[Dict[str, object]]) -> Dict[str, List[Dict[str, object]]]:
    grouped: Dict[str, List[Dict[str, object]]] = {}
    for unit in units:
        stream_id = str(unit.get("stream_id") or "")
        grouped.setdefault(stream_id, []).append(unit)
    return grouped


def _classify_stream_candidate(
    stream: Dict[str, object],
    units: List[Dict[str, object]],
    rtsp_controls: List[Dict[str, object]],
    config: Dict[str, object],
) -> Dict[str, object]:
    reasons: List[str] = []
    score = 0.0

    byte_count = int(stream.get("byte_count", 0) or 0)
    packet_count = int(stream.get("packet_count", 0) or 0)
    unit_count = int(stream.get("unit_count", 0) or 0)
    duration_seconds = float(stream.get("duration_seconds", 0.0) or 0.0)
    avg_payload_length = float(stream.get("average_payload_length", 0.0) or 0.0)
    payload_length_stddev = float(stream.get("payload_length_stddev", 0.0) or 0.0)
    packets_per_second = float(stream.get("packets_per_second", 0.0) or 0.0)

    unit_type_counts: Dict[str, int] = {}
    entropy_samples: List[float] = []
    custom_magic_hits = 0
    custom_magic = _custom_magic_bytes(config)
    recognized_payload_hits = 0
    payload_families = set()
    for unit in units[:16]:
        unit_type = str(unit.get("unit_type") or "opaque_chunk")
        unit_type_counts[unit_type] = unit_type_counts.get(unit_type, 0) + 1
        family = payload_family(unit_type)
        payload_families.add(family)
        payload = _safe_read_bytes(str(unit.get("file") or ""))
        if payload:
            entropy_samples.append(shannon_entropy(payload))
            if custom_magic and payload.startswith(custom_magic):
                custom_magic_hits += 1
        if family != "opaque":
            recognized_payload_hits += 1

    mean_entropy = round(statistics.mean(entropy_samples), 3) if entropy_samples else 0.0
    coeff_var = payload_length_stddev / avg_payload_length if avg_payload_length > 0 else 0.0

    min_candidate_bytes = int(config.get("min_candidate_bytes", 4096) or 4096)
    if recognized_payload_hits:
        score += 60.0
        reasons.append("recognized payload signatures present")
    if custom_magic_hits:
        score += 45.0
        reasons.append(f"custom magic matched in {custom_magic_hits} sampled units")
    if byte_count >= min_candidate_bytes:
        score += min(24.0, byte_count / max(1.0, min_candidate_bytes))
        reasons.append("stream carries enough sustained payload to be a serious candidate")
    if packet_count >= 12:
        score += 8.0
        reasons.append("multiple payload-bearing packets in one flow")
    if duration_seconds >= 3.0:
        score += 8.0
        reasons.append("traffic persists over time instead of looking like a one-off exchange")
    if packets_per_second >= 2.0:
        score += 6.0
        reasons.append("steady packet cadence")
    if avg_payload_length >= 256 and coeff_var <= 0.35:
        score += 10.0
        reasons.append("payload sizes are relatively consistent")
    if 6.0 <= mean_entropy <= 8.2:
        score += 6.0
        reasons.append("payload entropy is consistent with compressed or encrypted media")
    if str(stream.get("protocol") or "") == "udp":
        score += 4.0
        reasons.append("udp transport is compatible with custom live media flows")
    if any(
        event.get("src") in (stream.get("src"), stream.get("dst"))
        and event.get("dst") in (stream.get("src"), stream.get("dst"))
        for event in rtsp_controls
    ):
        score += 12.0
        reasons.append("rtsp control traffic correlates with the same endpoints")
    if "text" in payload_families:
        score += 8.0
        reasons.append("text-like payloads detected")
    if "image" in payload_families:
        score += 8.0
        reasons.append("image signatures detected")
    if "audio" in payload_families:
        score += 8.0
        reasons.append("audio signatures detected")
    if "document" in payload_families:
        score += 6.0
        reasons.append("document signatures detected")
    if "archive" in payload_families:
        score += 4.0
        reasons.append("archive/container signatures detected")
    if "video" in payload_families:
        score += 10.0
        reasons.append("video-oriented signatures detected")

    low_value_ports = {53, 137, 1900, 5353}
    if (
        int(stream.get("sport", 0) or 0) in low_value_ports
        or int(stream.get("dport", 0) or 0) in low_value_ports
    ) and not recognized_payload_hits and not custom_magic_hits:
        score -= 18.0
        reasons.append("service/discovery port lowers confidence")

    family_to_class = {
        "video": "recognized_video_candidate",
        "image": "recognized_image_candidate",
        "audio": "recognized_audio_candidate",
        "text": "recognized_text_candidate",
        "document": "recognized_document_candidate",
        "archive": "recognized_archive_candidate",
    }
    strongest_family = next(
        (family for family in ("video", "image", "audio", "text", "document", "archive") if family in payload_families),
        None,
    )
    if strongest_family:
        candidate_class = family_to_class[strongest_family]
    elif custom_magic_hits:
        candidate_class = "custom_magic_candidate"
    elif byte_count >= min_candidate_bytes and unit_count >= 8 and mean_entropy >= 5.0:
        candidate_class = "opaque_custom_candidate"
    else:
        candidate_class = "background_transport"

    return {
        "stream_id": stream.get("stream_id"),
        "flow_id": stream.get("flow_id"),
        "score": round(score, 2),
        "candidate_class": candidate_class,
        "packet_count": packet_count,
        "unit_count": unit_count,
        "byte_count": byte_count,
        "duration_seconds": round(duration_seconds, 3),
        "packets_per_second": round(packets_per_second, 3),
        "average_payload_length": round(avg_payload_length, 2),
            "payload_length_stddev": round(payload_length_stddev, 2),
            "mean_sample_entropy": mean_entropy,
            "payload_families": sorted(family for family in payload_families if family != "opaque"),
            "unit_type_counts": unit_type_counts,
            "custom_magic_hits": custom_magic_hits,
            "reasons": reasons,
        }


def _rank_candidate_streams(manifest: Dict[str, object], config: Dict[str, object]) -> List[Dict[str, object]]:
    units = list(manifest.get("units", []))
    streams = list(manifest.get("streams", []))
    grouped_units = _group_units_by_stream(units)
    rtsp_controls = [
        event
        for event in manifest.get("control_events", [])
        if event.get("type") == "rtsp_control"
    ]
    rows = [
        _classify_stream_candidate(stream, grouped_units.get(str(stream.get("stream_id") or ""), []), rtsp_controls, config)
        for stream in streams
    ]
    rows.sort(key=lambda item: item["score"], reverse=True)
    return rows


def _chi_squared(data: bytes) -> float:
    if not data:
        return 0.0
    if HAS_NUMPY:
        sample = np.frombuffer(data, dtype=np.uint8)
        counts, _ = np.histogram(sample, bins=256, range=(0, 256))
        expected = len(data) / 256
        return float(np.sum((counts - expected) ** 2 / expected))
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    expected = len(data) / 256
    return float(sum((count - expected) ** 2 / expected for count in counts))


class FormatDetector:
    def __init__(self, config: Dict[str, object]) -> None:
        self.config = config
        self.output_dir = Path(str(config.get("output_dir") or "./pipeline_output")).resolve()
        self.manifest_path = self.output_dir / "manifest.json"
        self.report_path = self.output_dir / "detection_report.json"

    def detect(self, manifest_path: Optional[str] = None) -> Dict[str, object]:
        section("Stage 3 - Payload Detection")
        path = Path(manifest_path).resolve() if manifest_path else self.manifest_path
        if not path.exists():
            err(f"Manifest not found: {path}")
            return {}

        manifest = _load_manifest(path)
        units = manifest.get("units", [])
        streams = manifest.get("streams", [])
        if not units:
            warn("Manifest contains no extracted units.")
            return {}

        sample_payloads: List[bytes] = []
        entropy_samples: List[float] = []
        content_type_counts: Dict[str, int] = {}
        for unit in units[:64]:
            try:
                payload = Path(unit["file"]).read_bytes()
            except OSError:
                continue
            sample_payloads.append(payload)
            entropy_samples.append(shannon_entropy(payload))
            content_type = str(unit.get("unit_type") or guess_unit_type(payload))
            content_type_counts[content_type] = content_type_counts.get(content_type, 0) + 1

        protocol_hits = summarize_protocol_hits(sample_payloads)
        if any(str(unit.get("unit_type") or "").startswith("mpegts") for unit in units):
            protocol_hits["mpegts"] = max(protocol_hits.get("mpegts", 0), sum(
                1 for unit in units if str(unit.get("unit_type") or "").startswith("mpegts")
            ))
        rtsp_controls = [
            event
            for event in manifest.get("control_events", [])
            if event.get("type") == "rtsp_control"
        ]

        stream_scores = _rank_candidate_streams(manifest, self.config)
        mean_entropy = round(sum(entropy_samples) / len(entropy_samples), 3) if entropy_samples else 0.0
        report = {
            "units_sampled": len(sample_payloads),
            "average_entropy": mean_entropy,
            "content_type_counts": content_type_counts,
            "protocol_hits": protocol_hits,
            "payload_hits": protocol_hits,
            "rtsp_control_events": len(rtsp_controls),
            "custom_magic_hex": _normalized_hex(self.config.get("custom_magic_hex")),
            "selected_candidate_stream": stream_scores[0] if stream_scores else None,
            "top_streams": stream_scores[:10],
        }

        self.report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        info(f"Average entropy across sampled units: {mean_entropy}")
        for label, count in protocol_hits.items():
            if count:
                ok(f"Detected {label} indicators in {count} sampled units")
        if rtsp_controls:
            ok(f"Observed {len(rtsp_controls)} RTSP control messages alongside the capture")
        if stream_scores:
            top = stream_scores[0]
            info(
                f"Top candidate stream: {top['stream_id']} "
                f"[{top['candidate_class']}, score={top['score']}]"
            )
        done(f"Detection report written to {self.report_path}")
        return report


class CryptoAnalyzer:
    def __init__(self, config: Dict[str, object]) -> None:
        self.config = config
        self.output_dir = Path(str(config.get("output_dir") or "./pipeline_output")).resolve()
        self.manifest_path = self.output_dir / "manifest.json"
        self.report_path = self.output_dir / "analysis_report.json"
        self.keystream_dir = self.output_dir / "candidate_keystreams"
        self.corpus = CorpusStore(config)

    def _load_encrypted_units(self) -> List[Dict[str, object]]:
        if self.manifest_path.exists():
            manifest = _load_manifest(self.manifest_path)
            return list(manifest.get("units", []))

        legacy_dir = self.output_dir / "encrypted_frames"
        if not legacy_dir.exists():
            return []
        units = []
        for index, file_path in enumerate(sorted(legacy_dir.glob("*.bin")), start=1):
            units.append(
                {
                    "unit_index": index,
                    "file": str(file_path.resolve()),
                    "length": file_path.stat().st_size,
                    "timestamp_start": float(index),
                    "timestamp_end": float(index),
                    "packet_number_start": index,
                    "packet_number_end": index,
                    "packet_numbers": [index],
                    "stream_id": "legacy",
                    "flow_id": "legacy",
                    "protocol": str(self.config.get("protocol") or "udp"),
                    "src": "",
                    "dst": "",
                    "sport": int(self.config.get("video_port", 5004) or 5004),
                    "dport": int(self.config.get("video_port", 5004) or 5004),
                }
            )
        return units

    def _load_decrypted_units(self, decrypted_dir: str) -> List[Dict[str, object]]:
        directory = Path(decrypted_dir).resolve()
        manifest_path = directory / "manifest.json"
        if manifest_path.exists():
            manifest = _load_manifest(manifest_path)
            return list(manifest.get("units", []))

        units = []
        for index, file_path in enumerate(sorted(directory.glob("*.bin")), start=1):
            units.append(
                {
                    "unit_index": index,
                    "file": str(file_path.resolve()),
                    "length": file_path.stat().st_size,
                    "timestamp_start": float(index),
                    "timestamp_end": float(index),
                    "packet_number_start": index,
                    "packet_number_end": index,
                    "packet_numbers": [index],
                    "stream_id": "",
                    "flow_id": "",
                }
            )
        return units

    def _align_score(self, enc: Dict[str, object], dec: Dict[str, object], enc_index: int, dec_index: int) -> float:
        enc_length = max(1, int(enc.get("length", 0) or 0))
        dec_length = max(1, int(dec.get("length", 0) or 0))
        size_gap = abs(enc_length - dec_length) / max(enc_length, dec_length)
        order_gap = abs(enc_index - dec_index) / 8.0
        score = 4.0 - (size_gap * 3.0) - order_gap

        if enc.get("stream_id") and enc.get("stream_id") == dec.get("stream_id"):
            score += 1.5

        enc_ts = enc.get("timestamp_start")
        dec_ts = dec.get("timestamp_start")
        if enc_ts is not None and dec_ts is not None:
            try:
                score -= min(abs(float(enc_ts) - float(dec_ts)), 10.0) / 4.0
            except (TypeError, ValueError):
                pass

        enc_packet = enc.get("packet_number_start")
        dec_packet = dec.get("packet_number_start")
        if enc_packet is not None and dec_packet is not None:
            try:
                score -= min(abs(int(enc_packet) - int(dec_packet)), 16) / 8.0
            except (TypeError, ValueError):
                pass

        enc_rtp = enc.get("rtp_timestamp")
        dec_rtp = dec.get("rtp_timestamp")
        if enc_rtp is not None and dec_rtp is not None and enc_rtp == dec_rtp:
            score += 2.0
        return score

    def _align_units(
        self, encrypted: List[Dict[str, object]], decrypted: List[Dict[str, object]]
    ) -> List[Tuple[Dict[str, object], Dict[str, object], float]]:
        aligned: List[Tuple[Dict[str, object], Dict[str, object], float]] = []
        used_decrypted = set()
        window = 8
        for enc_index, enc in enumerate(encrypted):
            best_index = None
            best_score = float("-inf")
            start = max(0, enc_index - window)
            end = min(len(decrypted), enc_index + window + 1)
            for dec_index in range(start, end):
                if dec_index in used_decrypted:
                    continue
                candidate = decrypted[dec_index]
                score = self._align_score(enc, candidate, enc_index, dec_index)
                if score > best_score:
                    best_score = score
                    best_index = dec_index
            if best_index is None or best_score < 0.4:
                continue
            used_decrypted.add(best_index)
            aligned.append((enc, decrypted[best_index], round(best_score, 3)))
        return aligned

    def _xor(self, left: bytes, right: bytes) -> bytes:
        size = min(len(left), len(right))
        return bytes(left[index] ^ right[index] for index in range(size))

    def _period(self, data: bytes, max_period: int = 128) -> Optional[int]:
        for period in range(1, min(max_period, max(2, len(data) // 2))):
            sample = data[: period * 4]
            if sample and all(sample[index] == sample[index % period] for index in range(len(sample))):
                return period
        return None

    def _selected_stream(self, manifest: Dict[str, object]) -> Optional[Dict[str, object]]:
        preferred_stream_id = str(self.config.get("preferred_stream_id") or "").strip()
        stream_rows = _rank_candidate_streams(manifest, self.config)
        if preferred_stream_id:
            for row in stream_rows:
                if row.get("stream_id") == preferred_stream_id:
                    return row
        return stream_rows[0] if stream_rows else None

    def analyze(self, decrypted_dir: Optional[str] = None) -> Dict[str, object]:
        section("Stage 4 - Cipher Heuristics")
        manifest = _load_manifest(self.manifest_path) if self.manifest_path.exists() else {}
        encrypted_units = self._load_encrypted_units()
        if not encrypted_units:
            err("No extracted units found. Run the extract step first.")
            return {}

        selected_stream = self._selected_stream(manifest) if manifest else None
        if selected_stream:
            filtered_units = [
                unit for unit in encrypted_units if unit.get("stream_id") == selected_stream.get("stream_id")
            ]
            if filtered_units:
                encrypted_units = filtered_units
                info(
                    f"Focusing analysis on candidate stream {selected_stream['stream_id']} "
                    f"[{selected_stream['candidate_class']}, score={selected_stream['score']}]"
                )

        corpus_review_threshold = float(self.config.get("corpus_review_threshold", 0.62) or 0.62)
        corpus_auto_reuse_threshold = float(self.config.get("corpus_auto_reuse_threshold", 0.88) or 0.88)
        corpus_matches: List[Dict[str, object]] = []
        if manifest and selected_stream:
            corpus_matches = self.corpus.find_matches(manifest, selected_stream, limit=5)
            if corpus_matches and float(corpus_matches[0].get("similarity", 0.0) or 0.0) >= corpus_review_threshold:
                top = corpus_matches[0]
                info(
                    f"Closest archived match: {top['entry_id']} "
                    f"(similarity={top['similarity']}, material={'yes' if top['candidate_material_available'] else 'no'})"
                )

        encrypted_payloads = []
        for unit in encrypted_units:
            try:
                encrypted_payloads.append(Path(unit["file"]).read_bytes())
            except OSError:
                continue
        if not encrypted_payloads:
            err("Unable to read extracted unit payloads from disk.")
            return {}

        entropy_values = [shannon_entropy(payload) for payload in encrypted_payloads[:128]]
        flat_sample = b"".join(encrypted_payloads[:32])
        chi_value = round(_chi_squared(flat_sample), 2)
        mean_entropy = round(sum(entropy_values) / len(entropy_values), 3) if entropy_values else 0.0

        hypotheses: List[Dict[str, object]] = []
        limitations = [
            "These checks look for weak patterns and lab-style reuse, not general-purpose decryption.",
            "Modern authenticated encryption can still look uniform here and remain completely impractical to decode.",
        ]
        recommendations: List[str] = []

        if chi_value < 300:
            hypotheses.append(
                {
                    "name": "non_uniform_distribution",
                    "confidence": "low",
                    "details": "Ciphertext distribution departs from uniform. Investigate framing residue, compression artifacts, or weak XOR-like schemes.",
                }
            )
            recommendations.append("Inspect framing and header boundaries before assuming a cryptographic weakness.")
        else:
            hypotheses.append(
                {
                    "name": "uniform_distribution",
                    "confidence": "informational",
                    "details": "Sampled bytes look close to uniformly distributed. That is consistent with compressed data or strong stream-cipher output.",
                }
            )

        candidate_material: Dict[str, object] = {}
        alignment_summary: Dict[str, object] = {"attempted": False, "matched_pairs": 0, "average_score": 0.0}

        if decrypted_dir and os.path.isdir(decrypted_dir):
            info("Running alignment experiments against decrypted reference data.")
            decrypted_units = self._load_decrypted_units(decrypted_dir)
            aligned_pairs = self._align_units(encrypted_units, decrypted_units)
            alignment_summary = {
                "attempted": True,
                "matched_pairs": len(aligned_pairs),
                "average_score": round(
                    sum(score for _enc, _dec, score in aligned_pairs) / len(aligned_pairs), 3
                )
                if aligned_pairs
                else 0.0,
                "strategy": "windowed order, size, timestamp, metadata scoring",
            }

            if aligned_pairs:
                self.keystream_dir.mkdir(parents=True, exist_ok=True)
                keystreams: List[bytes] = []
                repeating_periods: List[int] = []
                repeated_prefix_hits = 0
                for pair_index, (enc_meta, dec_meta, _score) in enumerate(aligned_pairs[:32], start=1):
                    enc_payload = Path(enc_meta["file"]).read_bytes()
                    dec_payload = Path(dec_meta["file"]).read_bytes()
                    keystream = self._xor(enc_payload, dec_payload)
                    keystreams.append(keystream)
                    (self.keystream_dir / f"candidate_{pair_index:04d}.bin").write_bytes(keystream)
                    period = self._period(keystream)
                    if period:
                        repeating_periods.append(period)
                for index in range(len(keystreams) - 1):
                    if keystreams[index][:32] == keystreams[index + 1][:32]:
                        repeated_prefix_hits += 1

                if repeated_prefix_hits:
                    hypotheses.append(
                        {
                            "name": "possible_keystream_reuse",
                            "confidence": "low",
                            "details": f"{repeated_prefix_hits} adjacent aligned pairs shared the same first 32 keystream bytes.",
                        }
                    )
                    recommendations.append("Verify alignment manually before treating repeated prefixes as nonce reuse.")

                if repeating_periods:
                    best_period = min(set(repeating_periods), key=repeating_periods.count)
                    key_bytes = keystreams[0][:best_period]
                    candidate_material = {
                        "mode": "static_xor_candidate",
                        "confidence": "experimental",
                        "period_bytes": best_period,
                        "key_hex": key_bytes.hex(),
                        "source": str(self.keystream_dir),
                        "notes": "Candidate derived from repeating-period experiments on aligned pairs.",
                    }
                    hypotheses.append(
                        {
                            "name": "repeating_keystream_period",
                            "confidence": "low",
                            "details": f"Observed repeating period candidates around {best_period} bytes across aligned samples.",
                        }
                    )
                else:
                    candidate_material = {
                        "mode": "keystream_samples",
                        "confidence": "experimental",
                        "source": str(self.keystream_dir),
                        "notes": "Saved XOR samples for offline inspection and replay experiments.",
                    }
            else:
                warn("No convincing encrypted/decrypted matches were found inside the alignment window.")
        else:
            info("No decrypted reference directory provided. Known-plaintext experiments skipped.")

        reused_from_corpus = False
        selected_stream_is_opaque = False
        if selected_stream:
            payload_families = list(selected_stream.get("payload_families") or [])
            candidate_class = str(selected_stream.get("candidate_class") or "")
            selected_stream_is_opaque = not payload_families or candidate_class in {
                "background_transport",
                "opaque_custom_candidate",
                "custom_magic_candidate",
            }

        if not candidate_material and selected_stream_is_opaque and corpus_matches:
            top = corpus_matches[0]
            top_similarity = float(top.get("similarity", 0.0) or 0.0)
            archived_material = dict(top.get("candidate_material") or {})
            if archived_material and top_similarity >= corpus_auto_reuse_threshold:
                archived_material["reused_from_corpus"] = True
                archived_material["reused_from_entry"] = str(top.get("entry_id") or "")
                archived_material["match_similarity"] = round(top_similarity, 3)
                candidate_material = archived_material
                reused_from_corpus = True
                hypotheses.append(
                    {
                        "name": "corpus_material_reuse",
                        "confidence": "experimental",
                        "details": (
                            f"Reused experimental candidate material from archived entry {top.get('entry_id')} "
                            f"with similarity score {top_similarity}."
                        ),
                    }
                )
                recommendations.append(
                    "Validate any corpus-reused material against known plaintext or manual stream inspection before trusting the output."
                )
                warn(
                    f"Reusing archived experimental material from {top.get('entry_id')} "
                    f"(similarity={top_similarity})."
                )

        archived_entry = self.corpus.archive_candidate(
            manifest,
            selected_stream,
            candidate_material=candidate_material,
        ) if manifest and selected_stream else None
        corpus_status = self.corpus.status()
        best_corpus_match = None
        if corpus_matches:
            best_corpus_match = dict(corpus_matches[0])
            best_corpus_match.pop("candidate_material", None)

        report = {
            "total_units": len(encrypted_units),
            "average_unit_size": int(sum(len(payload) for payload in encrypted_payloads) / len(encrypted_payloads)),
            "selected_candidate_stream": selected_stream,
            "ciphertext_observations": {
                "chi_squared": chi_value,
                "average_entropy": mean_entropy,
            },
            "alignment": alignment_summary,
            "hypotheses": hypotheses,
            "candidate_material": candidate_material,
            "corpus": {
                "entries": int(corpus_status.get("entry_count", 0) or 0),
                "entries_with_candidate_material": int(corpus_status.get("candidate_material_count", 0) or 0),
                "current_entry_id": archived_entry.get("entry_id") if archived_entry else None,
                "match_count": len(corpus_matches),
                "best_match": best_corpus_match,
                "reused_candidate_material": reused_from_corpus,
            },
            "limitations": limitations,
            "recommendations": recommendations,
        }

        self.report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        info(f"Chi-squared sample score: {chi_value}")
        info(f"Average entropy across sampled units: {mean_entropy}")
        if candidate_material:
            ok(f"Experimental replay material prepared: {candidate_material.get('mode')}")
        if archived_entry:
            ok(f"Archived this candidate stream into corpus entry {archived_entry.get('entry_id')}")
        done(f"Analysis report written to {self.report_path}")
        return report
