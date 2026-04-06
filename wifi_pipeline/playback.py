from __future__ import annotations

import glob
import json
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .protocols import strip_rtp_header, suggested_extension
from .ui import done, err, info, ok, section, warn

FFPLAY_FORMATS = {
    "mpegts": "mpegts",
    "mjpeg": "mjpeg",
    "jpeg": "mjpeg",
    "jpg": "mjpeg",
    "h264": "h264",
    "h265": "hevc",
    "hevc": "hevc",
    "wav": "wav",
    "mp3": "mp3",
    "ogg": "ogg",
    "flac": "flac",
    "aac": "aac",
    "adts": "aac",
}


def _normalize_replay_hint(config: Dict[str, object]) -> str:
    return str(config.get("replay_format_hint") or config.get("video_codec") or "raw").strip().lower()


def _extension_for_hint(format_hint: str) -> str:
    normalized = format_hint.lower().lstrip(".")
    explicit = {
        "txt": ".txt",
        "text": ".txt",
        "json": ".json",
        "xml": ".xml",
        "jpeg": ".jpg",
        "jpg": ".jpg",
        "png": ".png",
        "gif": ".gif",
        "bmp": ".bmp",
        "webp": ".webp",
        "wav": ".wav",
        "mp3": ".mp3",
        "ogg": ".ogg",
        "flac": ".flac",
        "aac": ".aac",
        "mpegts": ".ts",
        "ts": ".ts",
        "h264": ".h264",
        "h265": ".h265",
        "hevc": ".h265",
        "pdf": ".pdf",
        "zip": ".zip",
        "gz": ".gz",
        "gzip": ".gz",
        "raw": ".bin",
    }
    return explicit.get(normalized, ".bin")


class ReplaySink:
    def __init__(self, config: Dict[str, object]) -> None:
        self.config = config
        replay_dir = Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "replay"
        replay_dir.mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.format_hint = _normalize_replay_hint(config)
        extension = _extension_for_hint(self.format_hint)
        self.output_path = replay_dir / f"reconstructed_{timestamp}{extension}"
        self.handle = self.output_path.open("wb")
        self.player: Optional[subprocess.Popen] = None

        mode = str(config.get("playback_mode") or "both").lower()
        codec = FFPLAY_FORMATS.get(self.format_hint)
        ffplay = shutil.which("ffplay")
        if mode in ("ffplay", "both") and ffplay and codec:
            self.player = subprocess.Popen(
                [
                    ffplay,
                    "-loglevel",
                    "warning",
                    "-fflags",
                    "nobuffer",
                    "-flags",
                    "low_delay",
                    "-framedrop",
                    "-autoexit",
                    "-f",
                    codec,
                    "-i",
                    "-",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            ok(f"Streaming experimental output into ffplay using format hint {codec}.")
        elif mode in ("ffplay", "both") and not ffplay:
            warn("ffplay is not on PATH. Falling back to writing a reconstructed file only.")
        elif mode in ("ffplay", "both") and not codec:
            warn(f"Format hint {self.format_hint!r} is file-only. Writing a reconstructed file without ffplay.")

    def write(self, payload: bytes) -> None:
        self.handle.write(payload)
        self.handle.flush()
        if self.player and self.player.stdin:
            try:
                self.player.stdin.write(payload)
                self.player.stdin.flush()
            except OSError:
                warn("ffplay stdin closed unexpectedly. Continuing with file output only.")
                self.player = None

    def close(self) -> str:
        self.handle.close()
        if self.player:
            try:
                if self.player.stdin:
                    self.player.stdin.close()
            except OSError:
                pass
            try:
                self.player.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.player.terminate()
        return str(self.output_path)


class CandidateCipher:
    def __init__(self, candidate_material: Dict[str, object]) -> None:
        self.candidate_material = candidate_material
        self.mode = str(candidate_material.get("mode") or "")
        self.key: bytes = b""
        self.keystreams: List[bytes] = []
        self.keystream_index = 0

    def load(self) -> bool:
        if self.mode == "static_xor_candidate":
            key_hex = str(self.candidate_material.get("key_hex") or "")
            if not key_hex:
                return False
            self.key = bytes.fromhex(key_hex)
            return bool(self.key)
        if self.mode == "keystream_samples":
            source = str(self.candidate_material.get("source") or "")
            for file_path in sorted(glob.glob(str(Path(source) / "*.bin"))):
                self.keystreams.append(Path(file_path).read_bytes())
            return bool(self.keystreams)
        return False

    def decrypt(self, payload: bytes) -> bytes:
        if self.mode == "static_xor_candidate" and self.key:
            return bytes(payload[index] ^ self.key[index % len(self.key)] for index in range(len(payload)))
        if self.mode == "keystream_samples" and self.keystreams:
            keystream = self.keystreams[self.keystream_index % len(self.keystreams)]
            self.keystream_index += 1
            size = min(len(payload), len(keystream))
            mixed = bytearray(payload[index] ^ keystream[index] for index in range(size))
            mixed.extend(payload[size:])
            return bytes(mixed)
        return payload


def _load_json(path: Path) -> Optional[Dict[str, object]]:
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _dominant_unit_type(selected_stream: Dict[str, object]) -> str:
    counts = dict(selected_stream.get("unit_type_counts") or {})
    if not counts:
        return "opaque_chunk"
    return max(counts.items(), key=lambda item: item[1])[0]


def infer_replay_hint(config: Dict[str, object], report: Dict[str, object]) -> str:
    configured = _normalize_replay_hint(config)
    if configured not in ("", "auto", "raw"):
        return configured
    selected_stream = dict(report.get("selected_candidate_stream") or {})
    dominant = _dominant_unit_type(selected_stream)
    mapping = {
        "plain_text": "txt",
        "command_text": "txt",
        "json_text": "json",
        "xml_text": "xml",
        "http_text": "txt",
        "rtsp_text": "txt",
        "jpeg_frame": "jpeg",
        "png_image": "png",
        "gif_image": "gif",
        "bmp_image": "bmp",
        "webp_image": "webp",
        "wav_audio": "wav",
        "mp3_audio": "mp3",
        "ogg_audio": "ogg",
        "flac_audio": "flac",
        "aac_audio": "aac",
        "pdf_document": "pdf",
        "zip_archive": "zip",
        "gzip_archive": "gzip",
        "mpegts_packet": "mpegts",
        "h264_nal": "h264",
        "h265_nal": "h265",
    }
    return mapping.get(dominant, "raw")


def reconstruct_from_capture(config: Dict[str, object], report: Dict[str, object]) -> Optional[str]:
    candidate_material = dict(report.get("candidate_material") or {})
    if not candidate_material:
        return None

    manifest_path = Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "manifest.json"
    manifest = _load_json(manifest_path)
    if not manifest:
        return None

    selected_stream = dict(report.get("selected_candidate_stream") or {})
    stream_id = str(selected_stream.get("stream_id") or "").strip()
    if not stream_id:
        return None

    cipher = CandidateCipher(candidate_material)
    if not cipher.load():
        return None

    replay_hint = infer_replay_hint(config, report)
    replay_dir = Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "replay"
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    target_dir = replay_dir / f"reconstructed_capture_{timestamp}"
    target_dir.mkdir(parents=True, exist_ok=True)

    units = [unit for unit in manifest.get("units", []) if unit.get("stream_id") == stream_id]
    if not units:
        return None
    units.sort(key=lambda unit: (unit.get("timestamp_start", 0), unit.get("unit_index", 0)))

    aggregate = bytearray()
    dominant_type = _dominant_unit_type(selected_stream)
    aggregate_extension = _extension_for_hint(replay_hint or dominant_type)
    for index, unit in enumerate(units, start=1):
        file_path = Path(str(unit.get("file") or ""))
        if not file_path.exists():
            continue
        encrypted = file_path.read_bytes()
        decrypted = cipher.decrypt(encrypted)
        unit_type = str(unit.get("unit_type") or dominant_type or "opaque_chunk")
        extension = suggested_extension(unit_type)
        output_path = target_dir / f"unit_{index:05d}{extension}"
        output_path.write_bytes(decrypted)
        aggregate.extend(decrypted)

    aggregate_path = target_dir / f"stream_reconstructed{aggregate_extension}"
    aggregate_path.write_bytes(bytes(aggregate))
    done(f"Offline reconstruction written to {target_dir}")
    return str(target_dir)


class RtpJitterBuffer:
    def __init__(self, size: int) -> None:
        self.size = max(4, size)
        self.pending: Dict[int, Tuple[object, bytes]] = {}
        self.expected: Optional[int] = None

    def push(self, header, payload: bytes) -> List[Tuple[object, bytes]]:
        sequence = int(header.sequence)
        if self.expected is None:
            self.expected = sequence
        self.pending[sequence] = (header, payload)
        return self._drain(force=len(self.pending) >= self.size)

    def flush(self) -> List[Tuple[object, bytes]]:
        return self._drain(force=True, flush_all=True)

    def _drain(self, force: bool, flush_all: bool = False) -> List[Tuple[object, bytes]]:
        ready: List[Tuple[object, bytes]] = []
        while self.expected is not None and self.expected in self.pending:
            ready.append(self.pending.pop(self.expected))
            self.expected = (self.expected + 1) % 65536
        if force and self.pending:
            next_sequence = min(self.pending)
            self.expected = next_sequence
            while self.expected in self.pending:
                ready.append(self.pending.pop(self.expected))
                self.expected = (self.expected + 1) % 65536
        if flush_all and self.pending:
            for sequence in sorted(self.pending):
                ready.append(self.pending[sequence])
            self.pending.clear()
        return ready


class ExperimentalPlayback:
    def __init__(self, config: Dict[str, object], candidate_material: Dict[str, object]) -> None:
        self.config = config
        self.candidate_material = candidate_material
        self.running = False
        self.frame_count = 0
        self.in_port = int(config.get("video_port", 5004) or 5004)
        self.protocol = str(config.get("protocol") or "udp").lower()
        self.key: bytes = b""
        self.keystreams: List[bytes] = []
        self.keystream_index = 0
        self.sink = ReplaySink(config)
        self.jitter = RtpJitterBuffer(int(config.get("jitter_buffer_packets", 24) or 24))
        self.current_timestamp: Optional[int] = None
        self.current_access_unit = bytearray()
        self.cipher = CandidateCipher(candidate_material)

    def load_candidate(self) -> bool:
        if not self.cipher.load():
            err("No usable experimental replay material was found in the analysis report.")
            return False
        if self.cipher.mode == "static_xor_candidate":
            ok(f"Loaded experimental static XOR candidate ({len(self.cipher.key)} bytes).")
        elif self.cipher.mode == "keystream_samples":
            ok(f"Loaded {len(self.cipher.keystreams)} experimental keystream samples.")
        return True

    def decrypt_bytes(self, payload: bytes) -> bytes:
        return self.cipher.decrypt(payload)

    def _flush_access_unit(self) -> None:
        if not self.current_access_unit:
            return
        self.sink.write(bytes(self.current_access_unit))
        self.current_access_unit.clear()

    def _handle_rtp_payload(self, header, payload: bytes) -> None:
        if self.current_timestamp is None:
            self.current_timestamp = int(header.timestamp)
        if int(header.timestamp) != self.current_timestamp:
            self._flush_access_unit()
            self.current_timestamp = int(header.timestamp)
        self.current_access_unit.extend(payload)
        if getattr(header, "marker", False):
            self._flush_access_unit()

    def _process_udp_datagram(self, datagram: bytes) -> None:
        application_payload, header = strip_rtp_header(datagram)
        decrypted_payload = self.decrypt_bytes(application_payload)
        if header:
            ready_packets = self.jitter.push(header, decrypted_payload)
            for ready_header, ready_payload in ready_packets:
                self._handle_rtp_payload(ready_header, ready_payload)
        else:
            self.sink.write(decrypted_payload)
        self.frame_count += 1

    def _listen_udp(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", self.in_port))
        sock.settimeout(1.0)
        info(f"Listening for UDP input on port {self.in_port}")
        while self.running:
            try:
                payload, _addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            self._process_udp_datagram(payload)
        for header, payload in self.jitter.flush():
            self._handle_rtp_payload(header, payload)
        self._flush_access_unit()
        sock.close()

    def _listen_tcp(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", self.in_port))
        server.listen(1)
        server.settimeout(1.0)
        info(f"Listening for TCP input on port {self.in_port}")
        while self.running:
            try:
                connection, address = server.accept()
            except socket.timeout:
                continue
            ok(f"Accepted connection from {address[0]}:{address[1]}")
            connection.settimeout(1.0)
            with connection:
                while self.running:
                    try:
                        chunk = connection.recv(65535)
                    except socket.timeout:
                        continue
                    if not chunk:
                        break
                    self.sink.write(self.decrypt_bytes(chunk))
                    self.frame_count += 1
        server.close()

    def start(self) -> Optional[str]:
        section("Stage 5 - Experimental Replay")
        if not self.load_candidate():
            return None

        self.running = True
        try:
            if self.protocol == "tcp":
                self._listen_tcp()
            else:
                self._listen_udp()
        except KeyboardInterrupt:
            warn("Replay interrupted by user.")
        finally:
            self.running = False
            output_path = self.sink.close()
            done(f"Reconstructed output written to {output_path}")
        return output_path
