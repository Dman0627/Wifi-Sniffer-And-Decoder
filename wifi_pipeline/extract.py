from __future__ import annotations

import json
import os
import re
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .protocols import (
    guess_unit_type,
    looks_like_rtsp,
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
        tcp_streams, udp_streams, other_streams, control_events = self._read_pcap(str(source))
        selection_scope = "configured_target"

        if not tcp_streams and not udp_streams and not other_streams:
            warn(
                "No payload-bearing packets matched the configured protocol/port. "
                "Falling back to all transport flows (TCP, UDP, ICMP, SCTP, GRE, raw IP, IPv6)."
            )
            tcp_streams, udp_streams, other_streams, control_events = self._read_pcap(
                str(source), match_any=True
            )
            selection_scope = "all_transport_flows"

        streams: List[Dict[str, object]] = []
        units: List[Dict[str, object]] = []
        stream_index = 0

        for stream_id in sorted(tcp_streams):
            stream_index += 1
            summary, emitted = self._emit_tcp_units(stream_index, stream_id, tcp_streams[stream_id])
            streams.append(summary)
            units.extend(emitted)

        for stream_id in sorted(udp_streams):
            stream_index += 1
            summary, emitted = self._emit_udp_units(stream_index, stream_id, udp_streams[stream_id])
            streams.append(summary)
            units.extend(emitted)

        for stream_id in sorted(other_streams):
            stream_index += 1
            summary, emitted = self._emit_other_units(stream_index, stream_id, other_streams[stream_id])
            streams.append(summary)
            units.extend(emitted)

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
                "selection_scope": selection_scope,
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
            "control_events": control_events,
        }
        self.manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        ok(
            f"Extracted {len(units)} units across {len(streams)} streams "
            f"(IPv6: {ipv6_count}, other protocols: {other_count})"
        )
        done(f"Manifest written to {self.manifest_path}")
        return manifest
