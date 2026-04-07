from __future__ import annotations

import json
import math
import os
import re
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .corpus import CorpusStore
from .protocols import (
    guess_unit_type,
    looks_like_http,
    looks_like_mpegts,
    looks_like_rtsp,
    payload_family,
    shannon_entropy,
    suggested_extension,
    split_payload_units,
    strip_rtp_header,
)
from .ui import done, err, info, ok, section, warn

try:
    # IPv6 and ICMP added alongside the original imports
    from scapy.all import (  # type: ignore
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
        ICMPv6EchoRequest,
        ICMPv6EchoReply,
        PcapReader,
        Raw,
        GRE,
        SCTP,
    )

    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


FEEDBACK_SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Helpers to abstract IPv4 / IPv6 differences
# ---------------------------------------------------------------------------

def _get_ip_layer(packet):
    """Return the IP or IPv6 layer, whichever is present (IPv4 preferred)."""
    if IP in packet:
        return packet[IP]
    if IPv6 in packet:
        return packet[IPv6]
    return None


def _has_ip(packet) -> bool:
    """True when the packet carries any IP-layer (v4 or v6)."""
    return IP in packet or IPv6 in packet


def _ip_version(packet) -> int:
    """Return 4 or 6."""
    return 6 if (IPv6 in packet and IP not in packet) else 4


# ---------------------------------------------------------------------------
# Data classes (unchanged except protocol field now carries icmp/gre/sctp/other)
# ---------------------------------------------------------------------------

@dataclass
class PacketRecord:
    packet_number: int
    timestamp: float
    src: str
    dst: str
    sport: int
    dport: int
    protocol: str
    flow_id: str
    stream_id: str
    capture_interface: str
    payload_length: int
    header_stripped: int
    was_truncated: bool
    ip_version: int = 4
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    rtp_sequence: Optional[int] = None
    rtp_timestamp: Optional[int] = None
    rtp_ssrc: Optional[int] = None


@dataclass
class PacketPayload:
    record: PacketRecord
    payload: bytes


@dataclass
class FlowAssemblyResult:
    tcp_streams: Dict[str, List[PacketPayload]]
    udp_streams: Dict[str, List[PacketPayload]]
    other_streams: Dict[str, List[PacketPayload]]
    control_events: List[Dict[str, object]]
    selection_scope: str


@dataclass(frozen=True)
class StreamProtocolHint:
    stream_id: str
    protocol: str
    ip_version: int
    packet_count: int
    byte_count: int
    reassembly: str
    protocol_group: int
    hint_tags: Tuple[str, ...] = ()


@dataclass
class UnitizedStream:
    hint: StreamProtocolHint
    summary: Dict[str, object]
    units: List[Dict[str, object]]


def _safe_slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "stream"


def _flow_id(protocol: str, src: str, sport: int, dst: str, dport: int) -> str:
    left = (src, sport)
    right = (dst, dport)
    first, second = sorted((left, right))
    return f"{protocol}:{first[0]}:{first[1]}-{second[0]}:{second[1]}"


def _stream_id(protocol: str, src: str, sport: int, dst: str, dport: int) -> str:
    return f"{protocol}:{src}:{sport}>{dst}:{dport}"


class StreamExtractor:
    def __init__(self, config: Dict[str, object]) -> None:
        self.config = config
        self.output_dir = Path(str(config.get("output_dir") or "./pipeline_output")).resolve()
        self.stream_dir = self.output_dir / "reassembled_streams"
        self.unit_dir = self.output_dir / "extracted_units"
        self.manifest_path = self.output_dir / "manifest.json"
        self.feedback_path = self.output_dir / "candidate_feedback.json"

    # ------------------------------------------------------------------
    # Extraction pipeline stages
    # ------------------------------------------------------------------

    def _assemble_flows(self, pcap_path: str) -> FlowAssemblyResult:
        tcp_streams, udp_streams, other_streams, control_events = self._read_pcap(str(pcap_path))
        selection_scope = "configured_target"

        if not tcp_streams and not udp_streams and not other_streams:
            warn(
                "No payload-bearing packets matched the configured protocol/port. "
                "Falling back to all transport flows (TCP, UDP, ICMP, SCTP, GRE, raw IP, IPv6)."
            )
            tcp_streams, udp_streams, other_streams, control_events = self._read_pcap(
                str(pcap_path), match_any=True
            )
            selection_scope = "all_transport_flows"

        return FlowAssemblyResult(
            tcp_streams=tcp_streams,
            udp_streams=udp_streams,
            other_streams=other_streams,
            control_events=control_events,
            selection_scope=selection_scope,
        )

    def _iter_stream_packets(self, assembly: FlowAssemblyResult) -> List[Tuple[str, List[PacketPayload]]]:
        ordered: List[Tuple[str, List[PacketPayload]]] = []
        ordered.extend((stream_id, assembly.tcp_streams[stream_id]) for stream_id in sorted(assembly.tcp_streams))
        ordered.extend((stream_id, assembly.udp_streams[stream_id]) for stream_id in sorted(assembly.udp_streams))
        ordered.extend((stream_id, assembly.other_streams[stream_id]) for stream_id in sorted(assembly.other_streams))
        return ordered

    @staticmethod
    def _empty_feedback_store() -> Dict[str, object]:
        return {
            "schema_version": FEEDBACK_SCHEMA_VERSION,
            "updated_at": 0.0,
            "rules": [],
        }

    def _load_feedback_store(self) -> Dict[str, object]:
        if not self.feedback_path.exists():
            return self._empty_feedback_store()
        try:
            with open(self.feedback_path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return self._empty_feedback_store()
        if not isinstance(loaded, dict):
            return self._empty_feedback_store()
        if int(loaded.get("schema_version", 0) or 0) != FEEDBACK_SCHEMA_VERSION:
            return self._empty_feedback_store()
        rules = loaded.get("rules", [])
        if not isinstance(rules, list):
            rules = []
        loaded["rules"] = rules
        return loaded

    def _save_feedback_store(self, store: Dict[str, object]) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        store["schema_version"] = FEEDBACK_SCHEMA_VERSION
        store["updated_at"] = time.time()
        self.feedback_path.write_text(json.dumps(store, indent=2), encoding="utf-8")

    @staticmethod
    def _normalize_feedback_action(action: str) -> str:
        normalized = str(action or "").strip().lower()
        if normalized not in {"pin", "prefer", "reject"}:
            raise ValueError(f"Unsupported feedback action: {action!r}")
        return normalized

    def _feedback_rule_from_summary(self, summary: Dict[str, object], action: str, note: str = "") -> Dict[str, object]:
        normalized_action = self._normalize_feedback_action(action)
        return {
            "action": normalized_action,
            "stream_id": str(summary.get("stream_id") or ""),
            "protocol": str(summary.get("protocol") or ""),
            "sport": int(summary.get("sport", 0) or 0),
            "dport": int(summary.get("dport", 0) or 0),
            "reassembly": str(summary.get("reassembly") or ""),
            "dominant_unit_type": str(summary.get("dominant_unit_type") or "opaque_chunk"),
            "protocol_hints": list(summary.get("protocol_hints") or []),
            "payload_family_hints": list(summary.get("payload_family_hints") or []),
            "signature_hints": list(summary.get("signature_hints") or []),
            "created_at": time.time(),
            "note": str(note or "").strip(),
        }

    def remember_candidate_feedback(self, summary: Dict[str, object], action: str, note: str = "") -> Dict[str, object]:
        rule = self._feedback_rule_from_summary(summary, action, note=note)
        store = self._load_feedback_store()
        stream_id = str(rule.get("stream_id") or "").strip()
        rules = [
            existing
            for existing in list(store.get("rules") or [])
            if str(existing.get("stream_id") or "").strip() != stream_id
        ]
        rules.insert(0, rule)
        store["rules"] = rules[:256]
        self._save_feedback_store(store)
        return rule

    def remember_candidate_feedback_by_stream_id(
        self,
        stream_id: str,
        action: str,
        *,
        manifest_path: Optional[str] = None,
        note: str = "",
    ) -> Dict[str, object]:
        path = Path(manifest_path).resolve() if manifest_path else self.manifest_path
        if not path.exists():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as handle:
                manifest = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(manifest, dict):
            return {}
        for summary in list(manifest.get("streams", [])):
            if str(summary.get("stream_id") or "") == str(stream_id or ""):
                return self.remember_candidate_feedback(dict(summary), action, note=note)
        return {}

    def _feedback_match(self, rule: Dict[str, object], summary: Dict[str, object]) -> Optional[Dict[str, object]]:
        action = str(rule.get("action") or "").strip().lower()
        if action not in {"pin", "prefer", "reject"}:
            return None

        stream_id = str(summary.get("stream_id") or "")
        rule_stream_id = str(rule.get("stream_id") or "")
        if rule_stream_id and rule_stream_id == stream_id:
            return {
                "action": action,
                "match_score": 1.0,
                "exact_stream_id": True,
                "source": "feedback_store",
                "note": str(rule.get("note") or ""),
                "created_at": float(rule.get("created_at", 0.0) or 0.0),
                "reasons": ["exact stream id match"],
            }

        score = 0.0
        reasons: List[str] = []

        if str(rule.get("protocol") or "") and str(rule.get("protocol")) == str(summary.get("protocol") or ""):
            score += 0.14
            reasons.append("protocol matched")
        if str(rule.get("reassembly") or "") and str(rule.get("reassembly")) == str(summary.get("reassembly") or ""):
            score += 0.08
            reasons.append("reassembly matched")
        if str(rule.get("dominant_unit_type") or "") and str(rule.get("dominant_unit_type")) == str(summary.get("dominant_unit_type") or ""):
            score += 0.26
            reasons.append("dominant unit type matched")

        rule_ports = {
            int(rule.get("sport", 0) or 0),
            int(rule.get("dport", 0) or 0),
        } - {0}
        summary_ports = {
            int(summary.get("sport", 0) or 0),
            int(summary.get("dport", 0) or 0),
        } - {0}
        if rule_ports and summary_ports and rule_ports & summary_ports:
            score += 0.14
            reasons.append("ports overlap")

        rule_protocol_hints = set(str(value) for value in list(rule.get("protocol_hints") or []) if value)
        summary_protocol_hints = set(str(value) for value in list(summary.get("protocol_hints") or []) if value)
        if rule_protocol_hints and summary_protocol_hints and rule_protocol_hints & summary_protocol_hints:
            score += 0.12
            reasons.append("protocol hints overlap")

        rule_family_hints = set(str(value) for value in list(rule.get("payload_family_hints") or []) if value)
        summary_family_hints = set(str(value) for value in list(summary.get("payload_family_hints") or []) if value)
        if rule_family_hints and summary_family_hints and rule_family_hints & summary_family_hints:
            score += 0.18
            reasons.append("payload families overlap")

        rule_signature_hints = set(str(value) for value in list(rule.get("signature_hints") or []) if value)
        summary_signature_hints = set(str(value) for value in list(summary.get("signature_hints") or []) if value)
        if rule_signature_hints and summary_signature_hints and rule_signature_hints & summary_signature_hints:
            score += 0.18
            reasons.append("signature hints overlap")

        if score < 0.45:
            return None

        return {
            "action": action,
            "match_score": round(min(score, 1.0), 3),
            "exact_stream_id": False,
            "source": "feedback_store",
            "note": str(rule.get("note") or ""),
            "created_at": float(rule.get("created_at", 0.0) or 0.0),
            "reasons": reasons[:5],
        }

    def _attach_feedback_metadata(self, summary: Dict[str, object], store: Dict[str, object]) -> None:
        matches: List[Dict[str, object]] = []
        preferred_stream_id = str(self.config.get("preferred_stream_id") or "").strip()
        if preferred_stream_id and preferred_stream_id == str(summary.get("stream_id") or ""):
            matches.append(
                {
                    "action": "pin",
                    "match_score": 1.0,
                    "exact_stream_id": True,
                    "source": "config_preferred_stream_id",
                    "note": "",
                    "created_at": float("inf"),
                    "reasons": ["configured preferred stream id"],
                }
            )

        for rule in list(store.get("rules") or []):
            if not isinstance(rule, dict):
                continue
            matched = self._feedback_match(rule, summary)
            if matched:
                matches.append(matched)

        matches.sort(
            key=lambda item: (
                bool(item.get("exact_stream_id")),
                float(item.get("match_score", 0.0) or 0.0),
                float(item.get("created_at", 0.0) or 0.0),
            ),
            reverse=True,
        )

        applied = matches[0] if matches else None
        state = "none"
        adjustment = 0.0
        reason = ""

        if applied:
            action = str(applied.get("action") or "")
            scale = 1.0 if applied.get("exact_stream_id") else max(0.55, float(applied.get("match_score", 0.0) or 0.0))
            if action == "pin":
                state = "pinned"
                adjustment = 42.0 * scale
                reason = "saved user feedback pins this stream"
            elif action == "prefer":
                state = "preferred"
                adjustment = 18.0 * scale
                reason = "saved user feedback prefers this stream"
            elif action == "reject":
                state = "rejected"
                adjustment = -34.0 * scale
                reason = "saved user feedback rejected this stream previously"

            if str(applied.get("source") or "") == "config_preferred_stream_id":
                reason = "configured preferred stream pins this candidate"
            elif str(applied.get("note") or "").strip():
                reason = str(applied.get("note") or "").strip()

        summary["feedback_matches"] = [
            {
                "action": str(match.get("action") or ""),
                "match_score": round(float(match.get("match_score", 0.0) or 0.0), 3),
                "exact_stream_id": bool(match.get("exact_stream_id")),
                "source": str(match.get("source") or ""),
                "reasons": list(match.get("reasons") or []),
                "note": str(match.get("note") or ""),
            }
            for match in matches[:4]
        ]
        summary["feedback_state"] = state
        summary["feedback_adjustment"] = round(adjustment, 2)
        summary["feedback_reason"] = reason

    @staticmethod
    def _merge_hint_tags(base_tags: Tuple[str, ...], extra_tags: List[str]) -> Tuple[str, ...]:
        merged = list(base_tags)
        for tag in extra_tags:
            if tag not in merged:
                merged.append(tag)
        return tuple(merged)

    @staticmethod
    def _tags_for_unit_type(unit_type: str) -> List[str]:
        normalized = str(unit_type or "opaque_chunk")
        tags: List[str] = []
        family = payload_family(normalized)

        if normalized == "rtsp_text":
            tags.extend(["hint:rtsp_control", "hint:text"])
        elif normalized == "http_text":
            tags.extend(["hint:http_text", "hint:text"])
        elif normalized in {"json_text", "xml_text", "command_text", "plain_text"}:
            tags.append("hint:text")
        elif normalized == "mpegts_packet":
            tags.append("hint:mpegts")

        if family != "opaque":
            tags.append(f"family:{family}")

        if normalized in {
            "mpegts_packet",
            "jpeg_frame",
            "png_image",
            "gif_image",
            "bmp_image",
            "webp_image",
            "h264_nal",
            "h265_nal",
            "wav_audio",
            "mp3_audio",
            "ogg_audio",
            "flac_audio",
            "aac_audio",
            "pdf_document",
            "zip_archive",
            "gzip_archive",
        }:
            tags.append(f"signature:{normalized}")

        return tags

    def _stream_payload_samples(self, packets: List[PacketPayload]) -> List[bytes]:
        samples: List[bytes] = []
        seen: set[bytes] = set()

        def add_sample(payload: bytes) -> None:
            sample = bytes(payload[:65536])
            if not sample or sample in seen:
                return
            seen.add(sample)
            samples.append(sample)

        if not packets:
            return samples

        merged = b"".join(item.payload for item in packets[:32] if item.payload)
        add_sample(merged)

        for item in packets[:8]:
            add_sample(item.payload)

        if any(item.record.rtp_sequence is not None for item in packets):
            groups: Dict[int, List[PacketPayload]] = {}
            for item in packets:
                timestamp = int(item.record.rtp_timestamp or item.record.packet_number)
                groups.setdefault(timestamp, []).append(item)
            for timestamp in sorted(groups)[:4]:
                access_unit = b"".join(
                    member.payload
                    for member in sorted(
                        groups[timestamp],
                        key=lambda member: (int(member.record.rtp_sequence or 0), member.record.packet_number),
                    )
                )
                add_sample(access_unit)

        return samples

    def _payload_hint_tags(self, packets: List[PacketPayload]) -> List[str]:
        hits: List[str] = []
        for sample in self._stream_payload_samples(packets):
            if looks_like_rtsp(sample) and "hint:rtsp_control" not in hits:
                hits.extend(tag for tag in ("hint:rtsp_control", "hint:text") if tag not in hits)
            if looks_like_http(sample) and "hint:http_text" not in hits:
                hits.extend(tag for tag in ("hint:http_text", "hint:text") if tag not in hits)
            if looks_like_mpegts(sample) and "hint:mpegts" not in hits:
                hits.append("hint:mpegts")
            for tag in self._tags_for_unit_type(guess_unit_type(sample)):
                if tag not in hits:
                    hits.append(tag)
        return hits

    @staticmethod
    def _attach_hint_metadata(summary: Dict[str, object], hint: StreamProtocolHint) -> None:
        hint_tags = list(hint.hint_tags)
        summary["hint_tags"] = hint_tags
        summary["protocol_hints"] = [tag.split(":", 1)[1] for tag in hint_tags if tag.startswith("hint:")]
        summary["payload_family_hints"] = [tag.split(":", 1)[1] for tag in hint_tags if tag.startswith("family:")]
        summary["signature_hints"] = [tag.split(":", 1)[1] for tag in hint_tags if tag.startswith("signature:")]

    @staticmethod
    def _bounded_score(value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    @staticmethod
    def _unit_type_counts(units: List[Dict[str, object]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for unit in units:
            unit_type = str(unit.get("unit_type") or "opaque_chunk")
            counts[unit_type] = counts.get(unit_type, 0) + 1
        return counts

    @staticmethod
    def _dominant_unit_type(unit_type_counts: Dict[str, int]) -> str:
        if not unit_type_counts:
            return "opaque_chunk"
        return str(max(unit_type_counts.items(), key=lambda item: item[1])[0])

    def _sample_unit_payloads(
        self,
        summary: Dict[str, object],
        units: List[Dict[str, object]],
        limit: int = 8,
        read_limit: int = 4096,
    ) -> List[bytes]:
        payloads: List[bytes] = []
        for unit in units[:limit]:
            path = Path(str(unit.get("file") or ""))
            try:
                payload = path.read_bytes()[:read_limit]
            except OSError:
                payload = b""
            if payload:
                payloads.append(payload)
        if payloads:
            return payloads
        stream_path = Path(str(summary.get("stream_file") or ""))
        try:
            fallback = stream_path.read_bytes()[:read_limit]
        except OSError:
            fallback = b""
        return [fallback] if fallback else []

    def _continuity_quality(self, packets: List[PacketPayload], hint: StreamProtocolHint) -> float:
        if len(packets) <= 1:
            return 0.45

        if hint.protocol == "tcp":
            ordered = sorted(
                packets,
                key=lambda item: ((item.record.tcp_seq or 0), item.record.packet_number),
            )
            gap_bytes = 0
            covered_bytes = 0
            current_end: Optional[int] = None
            for item in ordered:
                sequence = int(item.record.tcp_seq or 0)
                length = len(item.payload)
                if length <= 0:
                    continue
                end_sequence = sequence + length
                if current_end is None:
                    current_end = end_sequence
                    covered_bytes += length
                    continue
                if sequence > current_end:
                    gap_bytes += sequence - current_end
                    covered_bytes += length
                    current_end = end_sequence
                    continue
                if end_sequence > current_end:
                    covered_bytes += end_sequence - current_end
                    current_end = end_sequence
            total_span = covered_bytes + gap_bytes
            if total_span <= 0:
                return 0.0
            return self._bounded_score(covered_bytes / total_span)

        if hint.reassembly == "rtp_access_unit":
            sequences = sorted(
                {
                    int(item.record.rtp_sequence)
                    for item in packets
                    if item.record.rtp_sequence is not None
                }
            )
            if len(sequences) <= 1:
                return 0.55
            expected_span = max(1, sequences[-1] - sequences[0] + 1)
            return self._bounded_score(len(sequences) / expected_span)

        packet_numbers = sorted(item.record.packet_number for item in packets)
        if len(packet_numbers) <= 1:
            return 0.45
        expected_span = max(1, packet_numbers[-1] - packet_numbers[0] + 1)
        return self._bounded_score(len(packet_numbers) / expected_span)

    def _timing_regularity(self, packets: List[PacketPayload]) -> float:
        timestamps = sorted(float(item.record.timestamp) for item in packets)
        if len(timestamps) <= 2:
            return 0.5 if len(timestamps) == 2 else 0.35
        intervals = [
            timestamps[index + 1] - timestamps[index]
            for index in range(len(timestamps) - 1)
            if timestamps[index + 1] - timestamps[index] > 0
        ]
        if not intervals:
            return 0.0
        mean_interval = statistics.mean(intervals)
        if mean_interval <= 0:
            return 0.0
        coefficient = statistics.pstdev(intervals) / mean_interval if len(intervals) > 1 else 0.0
        return self._bounded_score(1.0 - min(coefficient, 2.0) / 2.0)

    def _attach_stream_metrics(
        self,
        summary: Dict[str, object],
        packets: List[PacketPayload],
        units: List[Dict[str, object]],
        hint: StreamProtocolHint,
    ) -> None:
        unit_type_counts = self._unit_type_counts(units)
        dominant_unit_type = self._dominant_unit_type(unit_type_counts)
        recognized_units = sum(count for unit_type, count in unit_type_counts.items() if unit_type != "opaque_chunk")
        unit_count = max(1, len(units))
        payload_families = list(summary.get("payload_family_hints") or [])
        signature_hints = list(summary.get("signature_hints") or [])
        payloads = self._sample_unit_payloads(summary, units)
        entropies = [shannon_entropy(payload) for payload in payloads if payload]
        mean_entropy = statistics.mean(entropies) if entropies else 0.0

        continuity_quality = self._continuity_quality(packets, hint)
        timing_regularity = self._timing_regularity(packets)
        recognized_ratio = recognized_units / unit_count

        framing_quality = 0.15 + (recognized_ratio * 0.5)
        if dominant_unit_type != "opaque_chunk":
            framing_quality += 0.15
        if len(unit_type_counts) == 1 and unit_count >= 2:
            framing_quality += 0.1
        framing_quality += min(0.2, len(signature_hints) * 0.1)
        if hint.reassembly == "rtp_access_unit" and any(
            signature.startswith(("mpegts_", "jpeg_", "h264_", "h265_"))
            for signature in signature_hints
        ):
            framing_quality += 0.1
        framing_quality = self._bounded_score(framing_quality)

        if "text" in payload_families:
            entropy_quality = self._bounded_score(1.0 - (abs(mean_entropy - 4.0) / 3.0))
        elif any(family in payload_families for family in ("video", "audio", "image", "archive", "document")):
            entropy_quality = self._bounded_score(1.0 - (abs(mean_entropy - 6.8) / 2.4))
        else:
            entropy_quality = self._bounded_score(mean_entropy / 8.0)

        magic_signature_score = self._bounded_score(
            (len(signature_hints) * 0.35)
            + (len(payload_families) * 0.12)
            + (recognized_ratio * 0.35)
            + (0.18 if dominant_unit_type != "opaque_chunk" else 0.0)
        )

        byte_score = self._bounded_score(math.log1p(float(summary.get("byte_count", 0) or 0)) / math.log1p(65536.0))

        summary["unit_type_counts"] = unit_type_counts
        summary["dominant_unit_type"] = dominant_unit_type
        summary["recognized_unit_ratio"] = round(recognized_ratio, 3)
        summary["mean_sample_entropy"] = round(mean_entropy, 3)
        summary["ranking_features"] = {
            "continuity_quality": round(continuity_quality, 3),
            "byte_score": round(byte_score, 3),
            "timing_regularity": round(timing_regularity, 3),
            "framing_quality": round(framing_quality, 3),
            "entropy_quality": round(entropy_quality, 3),
            "magic_signature_score": round(magic_signature_score, 3),
            "corpus_similarity": 0.0,
        }

    @staticmethod
    def _feature_specs() -> List[Dict[str, object]]:
        return [
            {
                "key": "continuity_quality",
                "label": "packet continuity",
                "weight": 16.0,
                "positive": "packet sequence stays continuous across the stream",
                "negative": "packet continuity is weak or gapped",
            },
            {
                "key": "byte_score",
                "label": "payload volume",
                "weight": 16.0,
                "positive": "stream carries enough payload to be a serious candidate",
                "negative": "payload volume is still thin",
            },
            {
                "key": "timing_regularity",
                "label": "timing regularity",
                "weight": 12.0,
                "positive": "packet timing is regular instead of bursty noise",
                "negative": "packet timing is erratic",
            },
            {
                "key": "framing_quality",
                "label": "unit framing",
                "weight": 18.0,
                "positive": "unit framing looks coherent",
                "negative": "unit framing remains weak",
            },
            {
                "key": "entropy_quality",
                "label": "entropy fit",
                "weight": 10.0,
                "positive": "entropy profile matches the detected payload family",
                "negative": "entropy profile does not fit the detected family well",
            },
            {
                "key": "magic_signature_score",
                "label": "signature evidence",
                "weight": 12.0,
                "positive": "magic bytes or known payload signatures were recognized",
                "negative": "known payload signatures are still sparse",
            },
            {
                "key": "corpus_similarity",
                "label": "corpus similarity",
                "weight": 16.0,
                "positive": "stream is similar to archived corpus material",
                "negative": "no strong corpus match contributed to this ranking",
                "optional": True,
            },
        ]

    @staticmethod
    def _feature_status(value: float, optional: bool = False, available: bool = True) -> str:
        if optional and not available:
            return "not_available"
        if value >= 0.7:
            return "strong"
        if value >= 0.4:
            return "mixed"
        return "weak"

    def _candidate_metadata(
        self,
        summary: Dict[str, object],
        top_corpus_match: Optional[Dict[str, object]],
        score: float,
    ) -> Dict[str, object]:
        features = dict(summary.get("ranking_features") or {})
        evidence = {
            "reassembly": str(summary.get("reassembly") or ""),
            "protocol_hints": list(summary.get("protocol_hints") or []),
            "payload_family_hints": list(summary.get("payload_family_hints") or []),
            "signature_hints": list(summary.get("signature_hints") or []),
            "dominant_unit_type": str(summary.get("dominant_unit_type") or "opaque_chunk"),
            "unit_type_counts": dict(summary.get("unit_type_counts") or {}),
            "recognized_unit_ratio": float(summary.get("recognized_unit_ratio", 0.0) or 0.0),
            "mean_sample_entropy": float(summary.get("mean_sample_entropy", 0.0) or 0.0),
            "corpus_match": dict(summary.get("corpus_match") or {}),
            "feedback_state": str(summary.get("feedback_state") or "none"),
            "feedback_adjustment": float(summary.get("feedback_adjustment", 0.0) or 0.0),
            "feedback_reason": str(summary.get("feedback_reason") or ""),
            "feedback_matches": list(summary.get("feedback_matches") or []),
        }

        breakdown: List[Dict[str, object]] = []
        positive_signals: List[str] = []
        negative_signals: List[str] = []
        top_contributors: List[Dict[str, object]] = []

        for spec in self._feature_specs():
            key = str(spec["key"])
            value = round(float(features.get(key, 0.0) or 0.0), 3)
            weight = float(spec["weight"])
            optional = bool(spec.get("optional"))
            available = not optional or top_corpus_match is not None
            status = self._feature_status(value, optional=optional, available=available)
            contribution = round(value * weight, 2) if available else 0.0
            if status == "strong":
                explanation = str(spec["positive"])
                positive_signals.append(explanation)
            elif status == "weak" and available:
                explanation = str(spec["negative"])
                negative_signals.append(explanation)
            elif status == "not_available":
                explanation = "no archived corpus match contributed to this ranking"
            else:
                explanation = f"{spec['label']} is present but not decisive yet"
            row = {
                "feature": key,
                "label": str(spec["label"]),
                "value": value,
                "weight": weight,
                "contribution": contribution,
                "status": status,
                "explanation": explanation,
            }
            breakdown.append(row)
            if contribution > 0:
                top_contributors.append(row)

        top_contributors.sort(key=lambda item: float(item.get("contribution", 0.0) or 0.0), reverse=True)

        feedback_state = str(summary.get("feedback_state") or "none")
        feedback_reason = str(summary.get("feedback_reason") or "")
        if feedback_state in {"pinned", "preferred"}:
            positive_signals.insert(0, feedback_reason or "saved user feedback prefers this stream")
        elif feedback_state == "rejected":
            negative_signals.insert(0, feedback_reason or "saved user feedback rejected this stream previously")

        if score >= 70.0:
            signal_strength = "strong"
        elif score >= 45.0:
            signal_strength = "mixed"
        else:
            signal_strength = "weak"

        if not positive_signals:
            positive_signals.append("no single feature is dominant yet")
        if not negative_signals:
            negative_signals.append("no major weaknesses stand out from the current evidence")

        return {
            "signal_strength": signal_strength,
            "positive_signals": positive_signals[:6],
            "negative_signals": negative_signals[:6],
            "feature_breakdown": breakdown,
            "top_contributors": top_contributors[:3],
            "evidence": evidence,
        }

    def _score_stream(self, summary: Dict[str, object], top_corpus_match: Optional[Dict[str, object]]) -> Tuple[float, List[str]]:
        features = dict(summary.get("ranking_features") or {})
        corpus_similarity = round(float((top_corpus_match or {}).get("similarity", 0.0) or 0.0), 3)
        features["corpus_similarity"] = corpus_similarity
        summary["ranking_features"] = features
        summary["corpus_similarity"] = corpus_similarity
        feedback_state = str(summary.get("feedback_state") or "none")
        feedback_adjustment = float(summary.get("feedback_adjustment", 0.0) or 0.0)
        feedback_reason = str(summary.get("feedback_reason") or "")

        if top_corpus_match:
            summary["corpus_match"] = {
                "entry_id": str(top_corpus_match.get("entry_id") or ""),
                "similarity": corpus_similarity,
                "reasons": list(top_corpus_match.get("reasons") or []),
                "candidate_class": str(top_corpus_match.get("candidate_class") or ""),
                "dominant_unit_type": str(top_corpus_match.get("dominant_unit_type") or ""),
                "candidate_material_available": bool(top_corpus_match.get("candidate_material_available")),
            }
        else:
            summary.pop("corpus_match", None)

        score = (
            float(features.get("continuity_quality", 0.0) or 0.0) * 16.0
            + float(features.get("byte_score", 0.0) or 0.0) * 16.0
            + float(features.get("timing_regularity", 0.0) or 0.0) * 12.0
            + float(features.get("framing_quality", 0.0) or 0.0) * 18.0
            + float(features.get("entropy_quality", 0.0) or 0.0) * 10.0
            + float(features.get("magic_signature_score", 0.0) or 0.0) * 12.0
            + corpus_similarity * 16.0
            + feedback_adjustment
        )

        reasons: List[str] = []
        if feedback_state in {"pinned", "preferred"} and feedback_reason:
            reasons.append(feedback_reason)
        if float(features.get("continuity_quality", 0.0) or 0.0) >= 0.75:
            reasons.append("packet sequence stays continuous across the stream")
        if float(features.get("byte_score", 0.0) or 0.0) >= 0.55:
            reasons.append("stream carries enough payload to be a serious candidate")
        if float(features.get("timing_regularity", 0.0) or 0.0) >= 0.7:
            reasons.append("packet timing is regular instead of bursty noise")
        if float(features.get("framing_quality", 0.0) or 0.0) >= 0.7:
            reasons.append("unit framing looks coherent")
        if float(features.get("entropy_quality", 0.0) or 0.0) >= 0.7:
            reasons.append("entropy profile matches the detected payload family")
        if float(features.get("magic_signature_score", 0.0) or 0.0) >= 0.7:
            reasons.append("magic bytes or known payload signatures were recognized")
        if corpus_similarity >= 0.45:
            reasons.append("stream is similar to archived corpus material")
        if feedback_state == "rejected" and feedback_reason:
            reasons.append("stream remains in the candidate set despite saved rejection feedback")
        if not reasons:
            reasons.append("stream has limited framing or payload evidence so far")
        rounded_score = round(score, 2)
        candidate_metadata = self._candidate_metadata(summary, top_corpus_match, rounded_score)
        summary["candidate_metadata"] = candidate_metadata
        summary["ranking_weaknesses"] = list(candidate_metadata.get("negative_signals") or [])
        return rounded_score, reasons[:6]

    def _hint_stream_protocol(self, stream_id: str, packets: List[PacketPayload]) -> StreamProtocolHint:
        first = packets[0].record
        protocol = first.protocol
        packet_count = len(packets)
        byte_count = sum(len(item.payload) for item in packets)
        payload_hints = self._payload_hint_tags(packets)

        if protocol == "tcp":
            return StreamProtocolHint(
                stream_id=stream_id,
                protocol=protocol,
                ip_version=first.ip_version,
                packet_count=packet_count,
                byte_count=byte_count,
                reassembly="tcp_stream",
                protocol_group=0,
                hint_tags=self._merge_hint_tags(("transport:tcp",), payload_hints),
            )

        if protocol == "udp":
            rtp_packets = sum(1 for item in packets if item.record.rtp_sequence is not None)
            is_rtp = rtp_packets >= max(1, packet_count // 2)
            hint_tags = ("transport:udp", "hint:rtp") if is_rtp else ("transport:udp", "hint:datagram")
            return StreamProtocolHint(
                stream_id=stream_id,
                protocol=protocol,
                ip_version=first.ip_version,
                packet_count=packet_count,
                byte_count=byte_count,
                reassembly="rtp_access_unit" if is_rtp else "udp_datagram",
                protocol_group=1,
                hint_tags=self._merge_hint_tags(hint_tags, payload_hints),
            )

        return StreamProtocolHint(
            stream_id=stream_id,
            protocol=protocol,
            ip_version=first.ip_version,
            packet_count=packet_count,
            byte_count=byte_count,
            reassembly="raw_datagram",
            protocol_group=2,
            hint_tags=self._merge_hint_tags((f"transport:{protocol}", "hint:raw_datagram"), payload_hints),
        )

    def _hint_stream_protocols(self, assembly: FlowAssemblyResult) -> Dict[str, StreamProtocolHint]:
        hints: Dict[str, StreamProtocolHint] = {}
        for stream_id, packets in self._iter_stream_packets(assembly):
            if packets:
                hints[stream_id] = self._hint_stream_protocol(stream_id, packets)
        return hints

    def _unitize_stream(
        self,
        stream_index: int,
        stream_id: str,
        packets: List[PacketPayload],
        hint: StreamProtocolHint,
    ) -> UnitizedStream:
        if hint.protocol == "tcp":
            summary, units = self._emit_tcp_units(stream_index, stream_id, packets)
        elif hint.protocol == "udp":
            summary, units = self._emit_udp_units(stream_index, stream_id, packets)
        else:
            summary, units = self._emit_other_units(stream_index, stream_id, packets)
        self._attach_hint_metadata(summary, hint)
        self._attach_stream_metrics(summary, packets, units, hint)
        return UnitizedStream(hint=hint, summary=summary, units=units)

    def _unitize_streams(
        self,
        assembly: FlowAssemblyResult,
        hints: Dict[str, StreamProtocolHint],
    ) -> List[UnitizedStream]:
        unitized: List[UnitizedStream] = []
        for stream_index, (stream_id, packets) in enumerate(self._iter_stream_packets(assembly), start=1):
            hint = hints.get(stream_id)
            if hint is None:
                continue
            unitized.append(self._unitize_stream(stream_index, stream_id, packets, hint))
        return unitized

    def _rank_streams(self, unitized: List[UnitizedStream]) -> List[UnitizedStream]:
        manifest = {
            "streams": [item.summary for item in unitized],
            "units": [unit for item in unitized for unit in item.units],
            "pcap_path": "",
        }
        corpus = CorpusStore(self.config)
        feedback_store = self._load_feedback_store()

        for item in unitized:
            self._attach_feedback_metadata(item.summary, feedback_store)
            matches = corpus.find_matches(manifest, item.summary, limit=1)
            top_match = matches[0] if matches else None
            score, reasons = self._score_stream(item.summary, top_match)
            item.summary["ranking_score"] = score
            item.summary["ranking_reasons"] = reasons

        return sorted(
            unitized,
            key=lambda item: (
                -float(item.summary.get("ranking_score", 0.0) or 0.0),
                item.hint.protocol_group,
                -int(item.summary.get("byte_count", 0) or 0),
                item.hint.stream_id,
            ),
        )

    # ------------------------------------------------------------------
    # Packet matching
    # ------------------------------------------------------------------

    def _packet_matches_target(self, packet, protocol_name: str, port: int, match_any: bool = False) -> bool:
        """
        Extended matching:
          match_any=True  → accept TCP, UDP, ICMP, ICMPv6, SCTP, GRE, and raw IP
          otherwise       → port/protocol-specific as before
        """
        if match_any:
            return (
                TCP in packet
                or UDP in packet
                or ICMP in packet
                or ICMPv6EchoRequest in packet
                or ICMPv6EchoReply in packet
                or SCTP in packet
                or GRE in packet
            )
        if protocol_name == "tcp" and TCP in packet:
            return packet[TCP].sport == port or packet[TCP].dport == port
        if protocol_name == "udp" and UDP in packet:
            return packet[UDP].sport == port or packet[UDP].dport == port
        if protocol_name == "icmp" and (ICMP in packet or ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet):
            return True
        if protocol_name == "sctp" and SCTP in packet:
            return True
        if protocol_name == "gre" and GRE in packet:
            return True
        return False

    # ------------------------------------------------------------------
    # Protocol-name + pseudo-port helper
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_transport(packet) -> Tuple[str, object, int, int]:
        """
        Return (protocol_name, layer, sport, dport).
        For protocols without ports, sport/dport are set to 0.
        """
        if TCP in packet:
            l = packet[TCP]
            return "tcp", l, int(l.sport), int(l.dport)
        if UDP in packet:
            l = packet[UDP]
            return "udp", l, int(l.sport), int(l.dport)
        if SCTP in packet:
            l = packet[SCTP]
            return "sctp", l, int(l.sport), int(l.dport)
        if GRE in packet:
            return "gre", packet[GRE], 0, 0
        if ICMP in packet:
            l = packet[ICMP]
            return "icmp", l, int(l.type), int(l.code)
        if ICMPv6EchoRequest in packet:
            l = packet[ICMPv6EchoRequest]
            return "icmpv6", l, 0, 0
        if ICMPv6EchoReply in packet:
            l = packet[ICMPv6EchoReply]
            return "icmpv6", l, 0, 0
        # Raw IP / unknown transport
        ip = _get_ip_layer(packet)
        proto_num = getattr(ip, "proto", getattr(ip, "nh", 0))
        return f"ip_proto_{proto_num}", ip, 0, 0

    # ------------------------------------------------------------------
    # Core pcap reader — now handles IPv6 and non-TCP/UDP
    # ------------------------------------------------------------------

    def _read_pcap(
        self, pcap_path: str, match_any: bool = False
    ) -> Tuple[
        Dict[str, List[PacketPayload]],
        Dict[str, List[PacketPayload]],
        Dict[str, List[PacketPayload]],  # NEW: non-TCP/UDP streams
        List[Dict[str, object]],
    ]:
        tcp_streams: Dict[str, List[PacketPayload]] = {}
        udp_streams: Dict[str, List[PacketPayload]] = {}
        other_streams: Dict[str, List[PacketPayload]] = {}  # icmp / sctp / gre / raw
        control_events: List[Dict[str, object]] = []

        default_protocol = str(self.config.get("protocol") or "udp").lower()
        port = int(self.config.get("video_port", 5004) or 5004)
        custom_header_size = int(self.config.get("custom_header_size", 0) or 0)
        capture_interface = str(self.config.get("interface") or "")

        reader = PcapReader(pcap_path)
        try:
            for packet_number, packet in enumerate(reader, start=1):
                # ── FIXED: was `if IP not in packet: continue`
                #    Now accepts both IPv4 and IPv6 frames.
                if not _has_ip(packet):
                    continue

                ip_layer = _get_ip_layer(packet)
                ip_ver = _ip_version(packet)
                src_addr = str(ip_layer.src)
                dst_addr = str(ip_layer.dst)

                payload = bytes(packet[Raw]) if Raw in packet else b""

                # RTSP control event detection (TCP only, same as before)
                if TCP in packet and payload and looks_like_rtsp(payload):
                    control_events.append(
                        {
                            "packet_number": packet_number,
                            "timestamp": float(packet.time),
                            "src": src_addr,
                            "dst": dst_addr,
                            "sport": int(packet[TCP].sport),
                            "dport": int(packet[TCP].dport),
                            "type": "rtsp_control",
                            "preview": payload[:80].decode("latin-1", errors="replace"),
                        }
                    )

                if not self._packet_matches_target(
                    packet, default_protocol, port, match_any=match_any
                ):
                    continue

                # For ICMP / GRE / raw-IP the payload is the full packet body
                # when Raw is absent (e.g. ICMP echo data lives in the ICMP layer).
                if not payload:
                    if ICMP in packet:
                        payload = bytes(packet[ICMP].payload)
                    elif ICMPv6EchoRequest in packet:
                        payload = bytes(packet[ICMPv6EchoRequest].data)
                    elif ICMPv6EchoReply in packet:
                        payload = bytes(packet[ICMPv6EchoReply].data)
                    elif GRE in packet:
                        payload = bytes(packet[GRE].payload)
                    elif SCTP in packet:
                        payload = bytes(packet[SCTP].payload)

                if not payload:
                    continue

                protocol_name, layer, sport, dport = self._classify_transport(packet)

                application_payload = payload
                rtp_header = None

                if protocol_name == "tcp":
                    pass  # no RTP stripping for TCP
                elif protocol_name == "udp":
                    application_payload, rtp_header = strip_rtp_header(payload)
                # All other protocols pass payload through as-is

                header_stripped = 0
                was_truncated = False
                if custom_header_size:
                    header_stripped = min(custom_header_size, len(application_payload))
                    application_payload = application_payload[header_stripped:]
                    was_truncated = header_stripped < custom_header_size

                if not application_payload:
                    continue

                conversation_id = _flow_id(protocol_name, src_addr, sport, dst_addr, dport)
                sid = _stream_id(protocol_name, src_addr, sport, dst_addr, dport)
                if rtp_header:
                    sid = f"{sid}|ssrc={rtp_header.ssrc:08x}"

                record = PacketRecord(
                    packet_number=packet_number,
                    timestamp=float(packet.time),
                    src=src_addr,
                    dst=dst_addr,
                    sport=sport,
                    dport=dport,
                    protocol=protocol_name,
                    flow_id=conversation_id,
                    stream_id=sid,
                    capture_interface=capture_interface,
                    payload_length=len(application_payload),
                    header_stripped=header_stripped,
                    was_truncated=was_truncated,
                    ip_version=ip_ver,
                    tcp_seq=int(layer.seq) if protocol_name == "tcp" else None,
                    tcp_ack=int(layer.ack) if protocol_name == "tcp" else None,
                    rtp_sequence=rtp_header.sequence if rtp_header else None,
                    rtp_timestamp=rtp_header.timestamp if rtp_header else None,
                    rtp_ssrc=rtp_header.ssrc if rtp_header else None,
                )
                item = PacketPayload(record=record, payload=application_payload)

                if protocol_name == "tcp":
                    tcp_streams.setdefault(sid, []).append(item)
                elif protocol_name == "udp":
                    udp_streams.setdefault(sid, []).append(item)
                else:
                    other_streams.setdefault(sid, []).append(item)

        finally:
            reader.close()

        return tcp_streams, udp_streams, other_streams, control_events

    # ------------------------------------------------------------------
    # File writers (unchanged)
    # ------------------------------------------------------------------

    def _write_stream_file(self, stream_index: int, slug: str, part: int, payload: bytes) -> str:
        suffix = f"_part{part:03d}" if part else ""
        path = self.stream_dir / f"stream_{stream_index:03d}_{slug}{suffix}.bin"
        path.write_bytes(payload)
        return str(path)

    def _write_unit_file(
        self, stream_index: int, unit_index: int, slug: str, payload: bytes, unit_type: str
    ) -> str:
        extension = suggested_extension(unit_type)
        path = self.unit_dir / f"unit_{stream_index:03d}_{unit_index:05d}_{slug}{extension}"
        path.write_bytes(payload)
        return str(path)

    # ------------------------------------------------------------------
    # Metadata builders (unchanged, now also propagates ip_version)
    # ------------------------------------------------------------------

    def _unit_metadata(
        self,
        records: List[PacketRecord],
        stream_id: str,
        stream_file: str,
        unit_file: str,
        unit_index: int,
        unit_type: str,
        payload: bytes,
        reassembly: str,
    ) -> Dict[str, object]:
        packet_numbers = [record.packet_number for record in records]
        first = records[0]
        last = records[-1]
        return {
            "unit_index": unit_index,
            "file": unit_file,
            "stream_file": stream_file,
            "stream_id": stream_id,
            "flow_id": first.flow_id,
            "conversation_id": first.flow_id,
            "guessed_stream_id": stream_id,
            "protocol": first.protocol,
            "ip_version": first.ip_version,
            "src": first.src,
            "dst": first.dst,
            "sport": first.sport,
            "dport": first.dport,
            "timestamp_start": min(record.timestamp for record in records),
            "timestamp_end": max(record.timestamp for record in records),
            "packet_numbers": packet_numbers,
            "packet_number_start": min(packet_numbers),
            "packet_number_end": max(packet_numbers),
            "packet_count": len(packet_numbers),
            "length": len(payload),
            "capture_interface": first.capture_interface,
            "header_stripped": max(record.header_stripped for record in records),
            "was_truncated": any(record.was_truncated for record in records),
            "tcp_seq_start": min(record.tcp_seq for record in records if record.tcp_seq is not None)
            if any(record.tcp_seq is not None for record in records)
            else None,
            "tcp_seq_end": max(record.tcp_seq for record in records if record.tcp_seq is not None)
            if any(record.tcp_seq is not None for record in records)
            else None,
            "rtp_sequence_start": min(
                record.rtp_sequence for record in records if record.rtp_sequence is not None
            )
            if any(record.rtp_sequence is not None for record in records)
            else None,
            "rtp_sequence_end": max(
                record.rtp_sequence for record in records if record.rtp_sequence is not None
            )
            if any(record.rtp_sequence is not None for record in records)
            else None,
            "rtp_timestamp": records[0].rtp_timestamp if records[0].rtp_timestamp is not None else None,
            "rtp_ssrc": records[0].rtp_ssrc if records[0].rtp_ssrc is not None else None,
            "unit_type": unit_type,
            "guessed_content_type": guess_unit_type(payload),
            "reassembly": reassembly,
        }

    def _stream_summary(
        self,
        stream_id: str,
        records: List[PacketRecord],
        unit_count: int,
        byte_count: int,
        stream_file: str,
        reassembly: str,
    ) -> Dict[str, object]:
        payload_samples = [record.payload_length for record in records[:8]]
        payload_lengths = [record.payload_length for record in records]
        duration_seconds = max(
            0.0,
            max(record.timestamp for record in records) - min(record.timestamp for record in records),
        )
        average_payload_length = statistics.mean(payload_lengths) if payload_lengths else 0.0
        payload_length_stddev = statistics.pstdev(payload_lengths) if len(payload_lengths) > 1 else 0.0
        return {
            "stream_id": stream_id,
            "flow_id": records[0].flow_id,
            "protocol": records[0].protocol,
            "ip_version": records[0].ip_version,
            "src": records[0].src,
            "dst": records[0].dst,
            "sport": records[0].sport,
            "dport": records[0].dport,
            "packet_count": len(records),
            "byte_count": byte_count,
            "unit_count": unit_count,
            "stream_file": stream_file,
            "timestamp_start": min(record.timestamp for record in records),
            "timestamp_end": max(record.timestamp for record in records),
            "duration_seconds": round(duration_seconds, 3),
            "capture_interface": records[0].capture_interface,
            "rtp_packets": sum(1 for record in records if record.rtp_sequence is not None),
            "sample_payload_lengths": payload_samples,
            "average_payload_length": round(average_payload_length, 2),
            "payload_length_stddev": round(payload_length_stddev, 2),
            "payload_length_min": min(payload_lengths) if payload_lengths else 0,
            "payload_length_max": max(payload_lengths) if payload_lengths else 0,
            "bytes_per_second": round(byte_count / duration_seconds, 2) if duration_seconds > 0 else float(byte_count),
            "packets_per_second": round(len(records) / duration_seconds, 2) if duration_seconds > 0 else float(len(records)),
            "reassembly": reassembly,
        }

    # ------------------------------------------------------------------
    # TCP reassembly (unchanged)
    # ------------------------------------------------------------------

    def _emit_tcp_units(
        self, stream_index: int, stream_id: str, packets: List[PacketPayload]
    ) -> Tuple[Dict[str, object], List[Dict[str, object]]]:
        ordered = sorted(
            packets,
            key=lambda item: ((item.record.tcp_seq or 0), item.record.packet_number),
        )
        spans: List[Tuple[bytearray, List[PacketRecord]]] = []
        current_payload: Optional[bytearray] = None
        current_records: List[PacketRecord] = []
        current_end_seq: Optional[int] = None

        for item in ordered:
            sequence = int(item.record.tcp_seq or 0)
            payload = item.payload
            if current_payload is None:
                current_payload = bytearray(payload)
                current_records = [item.record]
                current_end_seq = sequence + len(payload)
                continue
            if sequence > int(current_end_seq or 0):
                spans.append((current_payload, current_records))
                current_payload = bytearray(payload)
                current_records = [item.record]
                current_end_seq = sequence + len(payload)
                continue
            overlap = max(0, int(current_end_seq or 0) - sequence)
            if overlap < len(payload):
                current_payload.extend(payload[overlap:])
                current_end_seq = sequence + len(payload)
            current_records.append(item.record)

        if current_payload is not None:
            spans.append((current_payload, current_records))

        units: List[Dict[str, object]] = []
        stream_files: List[str] = []
        unit_counter = 0
        total_bytes = 0
        all_records: List[PacketRecord] = []

        for part_index, (payload, records) in enumerate(spans):
            all_records.extend(records)
            payload_bytes = bytes(payload)
            total_bytes += len(payload_bytes)
            slug = _safe_slug(stream_id)
            stream_file = self._write_stream_file(stream_index, slug, part_index, payload_bytes)
            stream_files.append(stream_file)
            split_units, unit_type = split_payload_units(payload_bytes)
            for split_unit in split_units:
                unit_counter += 1
                unit_file = self._write_unit_file(stream_index, unit_counter, slug, split_unit, unit_type)
                units.append(
                    self._unit_metadata(
                        records=records,
                        stream_id=stream_id,
                        stream_file=stream_file,
                        unit_file=unit_file,
                        unit_index=unit_counter,
                        unit_type=unit_type,
                        payload=split_unit,
                        reassembly="tcp_stream",
                    )
                )

        summary = self._stream_summary(
            stream_id=stream_id,
            records=all_records,
            unit_count=len(units),
            byte_count=total_bytes,
            stream_file=stream_files[0] if stream_files else "",
            reassembly="tcp_stream",
        )
        return summary, units

    # ------------------------------------------------------------------
    # UDP / RTP reassembly (unchanged)
    # ------------------------------------------------------------------

    def _emit_udp_units(
        self, stream_index: int, stream_id: str, packets: List[PacketPayload]
    ) -> Tuple[Dict[str, object], List[Dict[str, object]]]:
        ordered = sorted(packets, key=lambda item: item.record.packet_number)
        slug = _safe_slug(stream_id)
        units: List[Dict[str, object]] = []
        unit_counter = 0

        rtp_packets = [item for item in ordered if item.record.rtp_sequence is not None]
        is_rtp = len(rtp_packets) >= max(1, len(ordered) // 2)

        stream_payload = bytearray()
        if is_rtp:
            groups: Dict[int, List[PacketPayload]] = {}
            for item in ordered:
                timestamp = int(item.record.rtp_timestamp or item.record.packet_number)
                groups.setdefault(timestamp, []).append(item)
            for timestamp in sorted(groups):
                group = sorted(
                    groups[timestamp],
                    key=lambda item: (int(item.record.rtp_sequence or 0), item.record.packet_number),
                )
                access_unit = b"".join(item.payload for item in group)
                if not access_unit:
                    continue
                stream_payload.extend(access_unit)
                split_units, unit_type = split_payload_units(access_unit)
                records = [item.record for item in group]
                for split_unit in split_units:
                    unit_counter += 1
                    unit_file = self._write_unit_file(stream_index, unit_counter, slug, split_unit, unit_type)
                    units.append(
                        self._unit_metadata(
                            records=records,
                            stream_id=stream_id,
                            stream_file="",
                            unit_file=unit_file,
                            unit_index=unit_counter,
                            unit_type=unit_type,
                            payload=split_unit,
                            reassembly="rtp_access_unit",
                        )
                    )
        else:
            for item in ordered:
                if not item.payload:
                    continue
                stream_payload.extend(item.payload)
                split_units, unit_type = split_payload_units(item.payload)
                for split_unit in split_units:
                    unit_counter += 1
                    unit_file = self._write_unit_file(stream_index, unit_counter, slug, split_unit, unit_type)
                    units.append(
                        self._unit_metadata(
                            records=[item.record],
                            stream_id=stream_id,
                            stream_file="",
                            unit_file=unit_file,
                            unit_index=unit_counter,
                            unit_type=unit_type,
                            payload=split_unit,
                            reassembly="udp_datagram",
                        )
                    )

        stream_file = self._write_stream_file(stream_index, slug, 0, bytes(stream_payload))
        for unit in units:
            unit["stream_file"] = stream_file

        summary = self._stream_summary(
            stream_id=stream_id,
            records=[item.record for item in ordered],
            unit_count=len(units),
            byte_count=len(stream_payload),
            stream_file=stream_file,
            reassembly="rtp_access_unit" if is_rtp else "udp_datagram",
        )
        return summary, units

    # ------------------------------------------------------------------
    # NEW: generic emitter for ICMP / SCTP / GRE / raw-IP flows
    # Each packet is treated as an independent datagram unit.
    # ------------------------------------------------------------------

    def _emit_other_units(
        self, stream_index: int, stream_id: str, packets: List[PacketPayload]
    ) -> Tuple[Dict[str, object], List[Dict[str, object]]]:
        ordered = sorted(packets, key=lambda item: item.record.packet_number)
        slug = _safe_slug(stream_id)
        units: List[Dict[str, object]] = []
        unit_counter = 0
        stream_payload = bytearray()

        for item in ordered:
            if not item.payload:
                continue
            stream_payload.extend(item.payload)
            split_units, unit_type = split_payload_units(item.payload)
            for split_unit in split_units:
                unit_counter += 1
                unit_file = self._write_unit_file(stream_index, unit_counter, slug, split_unit, unit_type)
                units.append(
                    self._unit_metadata(
                        records=[item.record],
                        stream_id=stream_id,
                        stream_file="",
                        unit_file=unit_file,
                        unit_index=unit_counter,
                        unit_type=unit_type,
                        payload=split_unit,
                        reassembly="raw_datagram",
                    )
                )

        stream_file = self._write_stream_file(stream_index, slug, 0, bytes(stream_payload))
        for unit in units:
            unit["stream_file"] = stream_file

        summary = self._stream_summary(
            stream_id=stream_id,
            records=[item.record for item in ordered],
            unit_count=len(units),
            byte_count=len(stream_payload),
            stream_file=stream_file,
            reassembly="raw_datagram",
        )
        return summary, units

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def extract(self, pcap_path: str) -> Dict[str, object]:
        section("Stage 2 - Stream Extraction")
        if not HAS_SCAPY:
            err("scapy is not installed. Run: pip install scapy  (or pip3 on Linux/macOS, or install_deps.ps1 on Windows)")
            return {}

        source = Path(pcap_path)
        if not source.exists():
            err(f"pcap not found: {pcap_path}")
            return {}

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.stream_dir.mkdir(parents=True, exist_ok=True)
        self.unit_dir.mkdir(parents=True, exist_ok=True)

        info(f"Reading {source}")
        assembly = self._assemble_flows(str(source))
        hints = self._hint_stream_protocols(assembly)
        unitized = self._unitize_streams(assembly, hints)
        ranked = self._rank_streams(unitized)
        streams = [item.summary for item in ranked]
        units = [unit for item in ranked for unit in item.units]

        ipv6_count = sum(1 for s in streams if s.get("ip_version") == 6)
        other_count = sum(1 for s in streams if s.get("protocol", "").startswith(("icmp", "sctp", "gre", "ip_proto")))

        manifest = {
            "schema_version": 3,
            "generated_at": time.time(),
            "pcap_path": str(source.resolve()),
            "capture_interface": str(self.config.get("interface") or ""),
            "environment_model": str(self.config.get("environment_model") or "unknown"),
            "filters": {
                "protocol": str(self.config.get("protocol") or "udp"),
                "video_port": int(self.config.get("video_port", 5004) or 5004),
                "custom_header_size": int(self.config.get("custom_header_size", 0) or 0),
                "selection_scope": assembly.selection_scope,
            },
            "stream_stats": {
                "total": len(streams),
                "tcp": sum(1 for s in streams if s.get("protocol") == "tcp"),
                "udp": sum(1 for s in streams if s.get("protocol") == "udp"),
                "ipv6": ipv6_count,
                "other_protocols": other_count,
            },
            "streams": streams,
            "units": units,
            "control_events": assembly.control_events,
        }
        self.manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        ok(
            f"Extracted {len(units)} units across {len(streams)} streams "
            f"(IPv6: {ipv6_count}, other protocols: {other_count})"
        )
        done(f"Manifest written to {self.manifest_path}")
        return manifest
