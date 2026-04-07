from __future__ import annotations

import glob
import json
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .protocols import strip_rtp_header, suggested_extension, summarize_stream_support
from .ui import done, err, info, ok, section, warn


@dataclass(frozen=True)
class ReplayHandler:
    handler_id: str
    hint_aliases: Tuple[str, ...]
    output_extension: str
    unit_types: Tuple[str, ...] = ()
    ffplay_format: Optional[str] = None
    output_mode: str = "stream"


@dataclass(frozen=True)
class ReconstructedUnit:
    unit_index: int
    unit_type: str
    output_path: Path
    payload: bytes


REPLAY_HANDLERS: Tuple[ReplayHandler, ...] = (
    ReplayHandler(
        handler_id="txt",
        hint_aliases=("txt", "text"),
        output_extension=".txt",
        unit_types=("plain_text", "command_text", "http_text", "rtsp_text"),
        output_mode="text_export",
    ),
    ReplayHandler(
        handler_id="json",
        hint_aliases=("json",),
        output_extension=".json",
        unit_types=("json_text",),
        output_mode="text_export",
    ),
    ReplayHandler(
        handler_id="xml",
        hint_aliases=("xml",),
        output_extension=".xml",
        unit_types=("xml_text",),
        output_mode="text_export",
    ),
    ReplayHandler(
        handler_id="jpeg",
        hint_aliases=("jpeg", "jpg", "mjpeg"),
        output_extension=".jpg",
        unit_types=("jpeg_frame",),
        ffplay_format="mjpeg",
        output_mode="image_stream",
    ),
    ReplayHandler(
        handler_id="png",
        hint_aliases=("png",),
        output_extension=".png",
        unit_types=("png_image",),
        output_mode="image_export",
    ),
    ReplayHandler(
        handler_id="gif",
        hint_aliases=("gif",),
        output_extension=".gif",
        unit_types=("gif_image",),
        output_mode="image_export",
    ),
    ReplayHandler(
        handler_id="bmp",
        hint_aliases=("bmp",),
        output_extension=".bmp",
        unit_types=("bmp_image",),
        output_mode="image_export",
    ),
    ReplayHandler(
        handler_id="webp",
        hint_aliases=("webp",),
        output_extension=".webp",
        unit_types=("webp_image",),
        output_mode="image_export",
    ),
    ReplayHandler(
        handler_id="wav",
        hint_aliases=("wav",),
        output_extension=".wav",
        unit_types=("wav_audio",),
        ffplay_format="wav",
        output_mode="audio_stream",
    ),
    ReplayHandler(
        handler_id="mp3",
        hint_aliases=("mp3",),
        output_extension=".mp3",
        unit_types=("mp3_audio",),
        ffplay_format="mp3",
        output_mode="audio_stream",
    ),
    ReplayHandler(
        handler_id="ogg",
        hint_aliases=("ogg",),
        output_extension=".ogg",
        unit_types=("ogg_audio",),
        ffplay_format="ogg",
        output_mode="audio_stream",
    ),
    ReplayHandler(
        handler_id="flac",
        hint_aliases=("flac",),
        output_extension=".flac",
        unit_types=("flac_audio",),
        ffplay_format="flac",
        output_mode="audio_stream",
    ),
    ReplayHandler(
        handler_id="aac",
        hint_aliases=("aac", "adts"),
        output_extension=".aac",
        unit_types=("aac_audio",),
        ffplay_format="aac",
        output_mode="audio_stream",
    ),
    ReplayHandler(
        handler_id="mpegts",
        hint_aliases=("mpegts", "ts"),
        output_extension=".ts",
        unit_types=("mpegts_packet",),
        ffplay_format="mpegts",
        output_mode="video_stream",
    ),
    ReplayHandler(
        handler_id="h264",
        hint_aliases=("h264",),
        output_extension=".h264",
        unit_types=("h264_nal",),
        ffplay_format="h264",
        output_mode="video_stream",
    ),
    ReplayHandler(
        handler_id="h265",
        hint_aliases=("h265", "hevc"),
        output_extension=".h265",
        unit_types=("h265_nal",),
        ffplay_format="hevc",
        output_mode="video_stream",
    ),
    ReplayHandler(
        handler_id="pdf",
        hint_aliases=("pdf",),
        output_extension=".pdf",
        unit_types=("pdf_document",),
        output_mode="document_export",
    ),
    ReplayHandler(
        handler_id="zip",
        hint_aliases=("zip",),
        output_extension=".zip",
        unit_types=("zip_archive",),
        output_mode="archive_export",
    ),
    ReplayHandler(
        handler_id="gzip",
        hint_aliases=("gzip", "gz"),
        output_extension=".gz",
        unit_types=("gzip_archive",),
        output_mode="archive_export",
    ),
    ReplayHandler(
        handler_id="raw",
        hint_aliases=("raw",),
        output_extension=".bin",
        unit_types=("opaque_chunk",),
        output_mode="raw_export",
    ),
)

REPLAY_HANDLER_BY_HINT: Dict[str, ReplayHandler] = {}
REPLAY_HANDLER_BY_UNIT_TYPE: Dict[str, ReplayHandler] = {}
for _handler in REPLAY_HANDLERS:
    for _alias in _handler.hint_aliases:
        REPLAY_HANDLER_BY_HINT[_alias] = _handler
    for _unit_type in _handler.unit_types:
        REPLAY_HANDLER_BY_UNIT_TYPE[_unit_type] = _handler

DEFAULT_REPLAY_HANDLER = REPLAY_HANDLER_BY_HINT["raw"]


def _normalize_replay_hint(config: Dict[str, object]) -> str:
    return str(config.get("replay_format_hint") or config.get("video_codec") or "raw").strip().lower()


def _handler_for_hint(format_hint: str) -> ReplayHandler:
    normalized = str(format_hint or "raw").strip().lower().lstrip(".")
    return REPLAY_HANDLER_BY_HINT.get(normalized, DEFAULT_REPLAY_HANDLER)


def _handler_for_unit_type(unit_type: str) -> ReplayHandler:
    normalized = str(unit_type or "opaque_chunk").strip().lower()
    return REPLAY_HANDLER_BY_UNIT_TYPE.get(normalized, DEFAULT_REPLAY_HANDLER)


def _extension_for_hint(format_hint: str) -> str:
    return _handler_for_hint(format_hint).output_extension


def _handler_for_report(config: Dict[str, object], report: Dict[str, object]) -> ReplayHandler:
    configured = _normalize_replay_hint(config)
    if configured not in ("", "auto", "raw"):
        return _handler_for_hint(configured)

    selected_stream = dict(report.get("selected_candidate_stream") or {})
    support = dict(
        report.get("selected_protocol_support")
        or summarize_stream_support(dict(selected_stream.get("unit_type_counts") or {}))
    )
    support_hint = str(support.get("replay_hint") or "").strip().lower()
    if support_hint and support_hint != "raw":
        return _handler_for_hint(support_hint)

    return _handler_for_unit_type(_dominant_unit_type(selected_stream))


def _choose_primary_unit(exports: List[ReconstructedUnit], handler: ReplayHandler) -> Optional[ReconstructedUnit]:
    eligible = [item for item in exports if item.unit_type in handler.unit_types]
    if not eligible:
        eligible = list(exports)
    if not eligible:
        return None
    return max(eligible, key=lambda item: (len(item.payload), -item.unit_index))


def _write_stream_output(target_dir: Path, handler: ReplayHandler, exports: List[ReconstructedUnit]) -> Optional[Path]:
    payload = b"".join(item.payload for item in exports if item.payload)
    if not payload:
        return None
    output_path = target_dir / f"stream_reconstructed{handler.output_extension}"
    output_path.write_bytes(payload)
    return output_path


def _write_primary_export(target_dir: Path, handler: ReplayHandler, exports: List[ReconstructedUnit]) -> Optional[Path]:
    primary = _choose_primary_unit(exports, handler)
    if primary is None or not primary.payload:
        return None
    label = {
        "image_export": "image_export",
        "document_export": "document_export",
        "archive_export": "archive_export",
        "raw_export": "raw_export",
    }.get(handler.output_mode, "primary_export")
    output_path = target_dir / f"{label}{handler.output_extension}"
    output_path.write_bytes(primary.payload)
    return output_path


def _write_reconstruction_manifest(
    target_dir: Path,
    handler: ReplayHandler,
    selected_stream: Dict[str, object],
    support: Dict[str, object],
    exports: List[ReconstructedUnit],
    primary_output: Optional[Path],
    confidence: Dict[str, object],
) -> Path:
    report = {
        "handler_id": handler.handler_id,
        "output_mode": handler.output_mode,
        "primary_output": str(primary_output) if primary_output else "",
        "stream_id": str(selected_stream.get("stream_id") or ""),
        "dominant_unit_type": str(support.get("dominant_unit_type") or _dominant_unit_type(selected_stream)),
        "replay_level": str(support.get("replay_level") or ""),
        "replay_supported": str(support.get("replay_level") or "") != "unsupported",
        "export_only": handler.output_mode in {"image_export", "document_export", "archive_export", "raw_export"},
        "support_detail": str(support.get("detail") or ""),
        "replay_confidence": confidence,
        "unit_count": len(exports),
        "units": [
            {
                "unit_index": item.unit_index,
                "unit_type": item.unit_type,
                "length": len(item.payload),
                "path": str(item.output_path),
            }
            for item in exports
        ],
    }
    manifest_path = target_dir / "reconstruction_report.json"
    manifest_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return manifest_path


def _finalize_reconstruction(
    target_dir: Path,
    handler: ReplayHandler,
    selected_stream: Dict[str, object],
    support: Dict[str, object],
    exports: List[ReconstructedUnit],
    confidence: Dict[str, object],
) -> Optional[Path]:
    if handler.output_mode in {"text_export", "audio_stream", "video_stream", "image_stream"}:
        primary_output = _write_stream_output(target_dir, handler, exports)
    else:
        primary_output = _write_primary_export(target_dir, handler, exports)

    _write_reconstruction_manifest(
        target_dir=target_dir,
        handler=handler,
        selected_stream=selected_stream,
        support=support,
        exports=exports,
        primary_output=primary_output,
        confidence=confidence,
    )
    return primary_output


class ReplaySink:
    def __init__(self, config: Dict[str, object]) -> None:
        self.config = config
        replay_dir = Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "replay"
        replay_dir.mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.handler = _handler_for_hint(_normalize_replay_hint(config))
        self.format_hint = self.handler.handler_id
        extension = self.handler.output_extension
        self.output_path = replay_dir / f"reconstructed_{timestamp}{extension}"
        self.handle = self.output_path.open("wb")
        self.player: Optional[subprocess.Popen] = None

        mode = str(config.get("playback_mode") or "both").lower()
        codec = self.handler.ffplay_format
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
            warn(
                f"Replay handler {self.handler.handler_id!r} is file-only. "
                "Writing a reconstructed file without ffplay."
            )

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
    return _handler_for_report(config, report).handler_id


def replay_support_summary(report: Dict[str, object]) -> Dict[str, object]:
    selected_stream = dict(report.get("selected_candidate_stream") or {})
    support = dict(report.get("selected_protocol_support") or summarize_stream_support(dict(selected_stream.get("unit_type_counts") or {})))
    if not support:
        support = summarize_stream_support({})
    return support


def replay_confidence_summary(config: Dict[str, object], report: Dict[str, object]) -> Dict[str, object]:
    support = replay_support_summary(report)
    selected_stream = dict(report.get("selected_candidate_stream") or {})
    candidate_material = dict(report.get("candidate_material") or {})
    replay_level = str(support.get("replay_level") or "unsupported")
    handler = DEFAULT_REPLAY_HANDLER if replay_level == "unsupported" else _handler_for_report(config, report)

    export_only = handler.output_mode in {"image_export", "document_export", "archive_export", "raw_export"}
    supports_live_replay = bool(handler.ffplay_format)
    candidate_material_mode = str(candidate_material.get("mode") or "")
    candidate_material_ready = bool(candidate_material_mode)

    base_scores = {
        "guaranteed": 0.94,
        "high_confidence": 0.82,
        "heuristic": 0.56,
        "unsupported": 0.18,
    }
    confidence_score = base_scores.get(replay_level, 0.2)
    reasons: List[str] = []

    if replay_level == "guaranteed":
        reasons.append("selected payload family is in the guaranteed replay registry")
    elif replay_level == "high_confidence":
        reasons.append("selected payload family is in the high-confidence replay registry")
    elif replay_level == "heuristic":
        reasons.append("selected payload family is supported only heuristically")
    else:
        reasons.append("selected payload family is outside the replay registry")

    if export_only:
        reasons.append("chosen handler exports artifacts rather than claiming live replay")
        if replay_level != "unsupported":
            confidence_score -= 0.03
    elif supports_live_replay:
        reasons.append(f"chosen handler supports ffplay streaming via {handler.ffplay_format}")
        confidence_score += 0.02
    else:
        reasons.append("chosen handler writes a reconstructed file without live replay support")

    if candidate_material_ready:
        reasons.append(f"candidate replay material is ready ({candidate_material_mode})")
        confidence_score += 0.02
    else:
        reasons.append("candidate replay material is not ready yet")
        confidence_score -= 0.08

    signal_strength = str((selected_stream.get("candidate_metadata") or {}).get("signal_strength") or "").strip().lower()
    if signal_strength == "strong":
        reasons.append("candidate stream evidence is strong")
        confidence_score += 0.03
    elif signal_strength == "weak":
        reasons.append("candidate stream evidence is weak")
        confidence_score -= 0.06
    elif signal_strength == "mixed":
        reasons.append("candidate stream evidence is mixed")

    confidence_score = max(0.0, min(0.99, round(confidence_score, 3)))
    if confidence_score >= 0.85:
        confidence_band = "strong"
    elif confidence_score >= 0.65:
        confidence_band = "good"
    elif confidence_score >= 0.4:
        confidence_band = "limited"
    else:
        confidence_band = "low"

    if replay_level == "unsupported":
        confidence_label = "unsupported_export"
    elif export_only:
        confidence_label = f"{replay_level}_export"
    else:
        confidence_label = replay_level

    if replay_level == "unsupported":
        delivery_mode = "raw_artifact_export"
        summary = (
            "Replay stays unsupported for this family, but raw bytes can still be exported "
            "with metadata for manual inspection."
        )
    elif export_only:
        delivery_mode = "artifact_export"
        summary = (
            f"Confidence is {confidence_band} for exporting this family through the "
            f"{handler.handler_id} handler."
        )
    elif supports_live_replay:
        delivery_mode = "stream_replay"
        summary = (
            f"Confidence is {confidence_band} for replaying or reconstructing this family "
            f"through the {handler.handler_id} handler."
        )
    else:
        delivery_mode = "reconstructed_file_export"
        summary = (
            f"Confidence is {confidence_band} for reconstructing this family to a file "
            f"through the {handler.handler_id} handler."
        )

    return {
        "handler_id": handler.handler_id,
        "output_mode": handler.output_mode,
        "delivery_mode": delivery_mode,
        "replay_level": replay_level,
        "confidence_label": confidence_label,
        "confidence_band": confidence_band,
        "confidence_score": confidence_score,
        "candidate_material_ready": candidate_material_ready,
        "candidate_material_mode": candidate_material_mode,
        "supports_live_replay": supports_live_replay,
        "export_only": export_only,
        "supported": replay_level != "unsupported",
        "detail": str(support.get("detail") or ""),
        "reasons": reasons[:6],
        "summary": summary,
    }


def reconstruct_from_capture(config: Dict[str, object], report: Dict[str, object]) -> Optional[str]:
    candidate_material = dict(report.get("candidate_material") or {})
    if not candidate_material:
        return None

    support = replay_support_summary(report)
    replay_level = str(support.get("replay_level") or "unsupported")
    replay_handler = _handler_for_report(config, report)
    if replay_level == "unsupported":
        warn("The selected stream does not belong to a supported replay family.")
        warn(str(support.get("detail") or "Replay stays unsupported for this protocol family."))
        info("Exporting raw bytes with reconstruction metadata instead of claiming replay support.")
        replay_handler = DEFAULT_REPLAY_HANDLER
    if replay_level == "heuristic":
        warn(str(support.get("detail") or "Replay remains heuristic for this protocol family."))
    elif replay_level != "unsupported":
        info(
            f"Replay family support: {replay_level.replace('_', ' ')} "
            f"for {support.get('dominant_unit_type') or 'selected stream'}."
        )
    confidence = replay_confidence_summary(config, report)
    info(
        f"Replay/export confidence: {confidence.get('confidence_band')} "
        f"[{confidence.get('confidence_label')}, score={confidence.get('confidence_score')}]"
    )

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

    replay_dir = Path(str(config.get("output_dir") or "./pipeline_output")).resolve() / "replay"
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    target_dir = replay_dir / f"reconstructed_capture_{timestamp}"
    target_dir.mkdir(parents=True, exist_ok=True)

    units = [unit for unit in manifest.get("units", []) if unit.get("stream_id") == stream_id]
    if not units:
        return None
    units.sort(key=lambda unit: (unit.get("timestamp_start", 0), unit.get("unit_index", 0)))

    dominant_type = _dominant_unit_type(selected_stream)
    reconstructed_units: List[ReconstructedUnit] = []
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
        reconstructed_units.append(
            ReconstructedUnit(
                unit_index=index,
                unit_type=unit_type,
                output_path=output_path,
                payload=decrypted,
            )
        )

    if not reconstructed_units:
        return None

    _finalize_reconstruction(
        target_dir=target_dir,
        handler=replay_handler,
        selected_stream=selected_stream,
        support=support,
        exports=reconstructed_units,
        confidence=confidence,
    )
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
