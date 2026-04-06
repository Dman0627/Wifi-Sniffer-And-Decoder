from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

RTSP_PREFIXES = (
    b"OPTIONS ",
    b"DESCRIBE ",
    b"SETUP ",
    b"PLAY ",
    b"PAUSE ",
    b"TEARDOWN ",
    b"ANNOUNCE ",
    b"GET_PARAMETER ",
    b"SET_PARAMETER ",
    b"RTSP/",
)

HTTP_PREFIXES = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"PATCH ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"HTTP/1.",
    b"HTTP/2",
)

COMMAND_PREFIXES = (
    "ls",
    "cd ",
    "pwd",
    "cat ",
    "echo ",
    "rm ",
    "mv ",
    "cp ",
    "mkdir ",
    "rmdir ",
    "python ",
    "python3 ",
    "powershell",
    "cmd.exe",
    "whoami",
    "uname",
    "set ",
    "export ",
    "curl ",
    "wget ",
    "scp ",
    "ssh ",
    "ffmpeg ",
    "ffplay ",
    "tcpdump ",
    "dumpcap ",
    "airdecap-ng ",
    "tshark ",
    "AT+",
)

PAYLOAD_EXTENSION_MAP = {
    "mpegts_packet": ".ts",
    "jpeg_frame": ".jpg",
    "png_image": ".png",
    "gif_image": ".gif",
    "bmp_image": ".bmp",
    "webp_image": ".webp",
    "wav_audio": ".wav",
    "mp3_audio": ".mp3",
    "ogg_audio": ".ogg",
    "flac_audio": ".flac",
    "aac_audio": ".aac",
    "pdf_document": ".pdf",
    "zip_archive": ".zip",
    "gzip_archive": ".gz",
    "json_text": ".json",
    "xml_text": ".xml",
    "http_text": ".http",
    "rtsp_text": ".rtsp",
    "command_text": ".txt",
    "plain_text": ".txt",
    "h264_nal": ".h264",
    "h265_nal": ".h265",
    "opaque_chunk": ".bin",
}

PAYLOAD_FAMILY_MAP = {
    "mpegts_packet": "video",
    "jpeg_frame": "image",
    "png_image": "image",
    "gif_image": "image",
    "bmp_image": "image",
    "webp_image": "image",
    "wav_audio": "audio",
    "mp3_audio": "audio",
    "ogg_audio": "audio",
    "flac_audio": "audio",
    "aac_audio": "audio",
    "pdf_document": "document",
    "zip_archive": "archive",
    "gzip_archive": "archive",
    "json_text": "text",
    "xml_text": "text",
    "http_text": "text",
    "rtsp_text": "text",
    "command_text": "text",
    "plain_text": "text",
    "h264_nal": "video",
    "h265_nal": "video",
    "opaque_chunk": "opaque",
}


@dataclass
class RtpHeader:
    payload_type: int
    sequence: int
    timestamp: int
    ssrc: int
    marker: bool
    header_length: int


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    return -sum(
        (count / len(data)) * math.log2(count / len(data))
        for count in counts
        if count
    )


def looks_like_rtsp(payload: bytes) -> bool:
    head = payload[:32].upper()
    return any(head.startswith(prefix) for prefix in RTSP_PREFIXES)


def looks_like_http(payload: bytes) -> bool:
    head = payload[:32].upper()
    return any(head.startswith(prefix) for prefix in HTTP_PREFIXES)


def parse_rtp_header(payload: bytes) -> Optional[RtpHeader]:
    if len(payload) < 12:
        return None
    first = payload[0]
    second = payload[1]
    version = first >> 6
    if version != 2:
        return None
    csrc_count = first & 0x0F
    extension = bool(first & 0x10)
    header_length = 12 + (csrc_count * 4)
    if len(payload) < header_length:
        return None
    if extension:
        if len(payload) < header_length + 4:
            return None
        extension_words = int.from_bytes(payload[header_length + 2 : header_length + 4], "big")
        header_length += 4 + (extension_words * 4)
        if len(payload) < header_length:
            return None
    if len(payload) <= header_length:
        return None
    return RtpHeader(
        payload_type=second & 0x7F,
        sequence=int.from_bytes(payload[2:4], "big"),
        timestamp=int.from_bytes(payload[4:8], "big"),
        ssrc=int.from_bytes(payload[8:12], "big"),
        marker=bool(second & 0x80),
        header_length=header_length,
    )


def strip_rtp_header(payload: bytes) -> Tuple[bytes, Optional[RtpHeader]]:
    header = parse_rtp_header(payload)
    if not header:
        return payload, None
    return payload[header.header_length :], header


def _mpegts_offset(data: bytes) -> Optional[int]:
    if len(data) < 188 * 3:
        return None
    for offset in range(min(188, len(data))):
        hits = 0
        checks = 0
        for index in range(offset, len(data), 188):
            checks += 1
            if data[index] == 0x47:
                hits += 1
            if checks >= 5:
                break
        if checks >= 3 and hits / checks >= 0.8:
            return offset
    return None


def looks_like_mpegts(data: bytes) -> bool:
    if len(data) >= 188 and len(data) % 188 == 0:
        packets = len(data) // 188
        if packets >= 1 and all(data[index * 188] == 0x47 for index in range(packets)):
            return True
    return _mpegts_offset(data) is not None


def split_mpegts_packets(data: bytes) -> List[bytes]:
    offset = _mpegts_offset(data)
    if offset is None:
        return []
    packets = []
    for start in range(offset, len(data) - 187, 188):
        chunk = data[start : start + 188]
        if len(chunk) == 188 and chunk[0] == 0x47:
            packets.append(chunk)
    return packets


def split_jpeg_images(data: bytes) -> List[bytes]:
    images: List[bytes] = []
    cursor = 0
    while True:
        start = data.find(b"\xff\xd8", cursor)
        if start < 0:
            break
        end = data.find(b"\xff\xd9", start + 2)
        if end < 0:
            break
        images.append(data[start : end + 2])
        cursor = end + 2
    return images


def looks_like_png(data: bytes) -> bool:
    return data.startswith(b"\x89PNG\r\n\x1a\n")


def looks_like_gif(data: bytes) -> bool:
    return data.startswith((b"GIF87a", b"GIF89a"))


def looks_like_bmp(data: bytes) -> bool:
    return data.startswith(b"BM")


def looks_like_webp(data: bytes) -> bool:
    return len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP"


def looks_like_wav(data: bytes) -> bool:
    return len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WAVE"


def looks_like_ogg(data: bytes) -> bool:
    return data.startswith(b"OggS")


def looks_like_flac(data: bytes) -> bool:
    return data.startswith(b"fLaC")


def looks_like_mp3(data: bytes) -> bool:
    if data.startswith(b"ID3"):
        return True
    return len(data) >= 2 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0 and (data[1] & 0x18) != 0x08


def looks_like_aac_adts(data: bytes) -> bool:
    return len(data) >= 7 and data[0] == 0xFF and (data[1] & 0xF0) == 0xF0 and (data[1] & 0x06) == 0x00


def looks_like_pdf(data: bytes) -> bool:
    return data.startswith(b"%PDF-")


def looks_like_zip(data: bytes) -> bool:
    return data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))


def looks_like_gzip(data: bytes) -> bool:
    return data.startswith(b"\x1f\x8b")


def _decode_text(data: bytes) -> Optional[str]:
    sample = data[:4096]
    if not sample or b"\x00" in sample:
        return None
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(char.isprintable() or char in "\r\n\t" for char in text)
    if not text:
        return None
    if printable / len(text) < 0.9:
        return None
    return text


def looks_like_json_text(data: bytes) -> bool:
    text = _decode_text(data)
    if not text:
        return False
    stripped = text.lstrip()
    return stripped.startswith("{") or stripped.startswith("[")


def looks_like_xml_text(data: bytes) -> bool:
    text = _decode_text(data)
    if not text:
        return False
    stripped = text.lstrip()
    return stripped.startswith("<?xml") or (stripped.startswith("<") and ">" in stripped and "</" in stripped)


def looks_like_command_text(data: bytes) -> bool:
    text = _decode_text(data)
    if not text:
        return False
    first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
    lowered = first_line.lower()
    return any(lowered.startswith(prefix) for prefix in COMMAND_PREFIXES)


def looks_like_plain_text(data: bytes) -> bool:
    return _decode_text(data) is not None


def _start_code_positions(data: bytes) -> List[int]:
    positions: List[int] = []
    index = 0
    limit = len(data) - 3
    while index < limit:
        if data[index : index + 4] == b"\x00\x00\x00\x01":
            positions.append(index)
            index += 4
            continue
        if data[index : index + 3] == b"\x00\x00\x01":
            positions.append(index)
            index += 3
            continue
        index += 1
    return positions


def split_nal_units(data: bytes) -> Tuple[List[bytes], Optional[str]]:
    positions = _start_code_positions(data)
    if len(positions) < 2:
        return [], None
    units: List[bytes] = []
    codec_votes: Dict[str, int] = {"h264": 0, "h265": 0}
    for index, start in enumerate(positions):
        end = positions[index + 1] if index + 1 < len(positions) else len(data)
        unit = data[start:end]
        if len(unit) < 5:
            continue
        units.append(unit)
        prefix = 4 if unit[:4] == b"\x00\x00\x00\x01" else 3
        if len(unit) <= prefix:
            continue
        header = unit[prefix]
        h264_type = header & 0x1F
        h265_type = (header >> 1) & 0x3F
        if 1 <= h264_type <= 23:
            codec_votes["h264"] += 1
        if 0 < h265_type < 48:
            codec_votes["h265"] += 1
    if not units:
        return [], None
    codec = max(codec_votes, key=codec_votes.get) if any(codec_votes.values()) else None
    return units, codec


def guess_unit_type(data: bytes) -> str:
    if looks_like_mpegts(data):
        return "mpegts_packet"
    if split_jpeg_images(data):
        return "jpeg_frame"
    if looks_like_png(data):
        return "png_image"
    if looks_like_gif(data):
        return "gif_image"
    if looks_like_bmp(data):
        return "bmp_image"
    if looks_like_webp(data):
        return "webp_image"
    if looks_like_wav(data):
        return "wav_audio"
    if looks_like_mp3(data):
        return "mp3_audio"
    if looks_like_ogg(data):
        return "ogg_audio"
    if looks_like_flac(data):
        return "flac_audio"
    if looks_like_aac_adts(data):
        return "aac_audio"
    if looks_like_pdf(data):
        return "pdf_document"
    if looks_like_zip(data):
        return "zip_archive"
    if looks_like_gzip(data):
        return "gzip_archive"
    _, codec = split_nal_units(data)
    if codec == "h264":
        return "h264_nal"
    if codec == "h265":
        return "h265_nal"
    if looks_like_http(data):
        return "http_text"
    if looks_like_rtsp(data):
        return "rtsp_text"
    if looks_like_json_text(data):
        return "json_text"
    if looks_like_xml_text(data):
        return "xml_text"
    if looks_like_command_text(data):
        return "command_text"
    if looks_like_plain_text(data):
        return "plain_text"
    return "opaque_chunk"


def split_payload_units(data: bytes) -> Tuple[List[bytes], str]:
    packets = split_mpegts_packets(data)
    if packets:
        return packets, "mpegts_packet"
    images = split_jpeg_images(data)
    if images:
        return images, "jpeg_frame"
    nals, codec = split_nal_units(data)
    if nals:
        if codec == "h265":
            return nals, "h265_nal"
        return nals, "h264_nal"
    return [data], guess_unit_type(data)


def payload_family(unit_type: str) -> str:
    return PAYLOAD_FAMILY_MAP.get(unit_type, "opaque")


def suggested_extension(unit_type: str) -> str:
    return PAYLOAD_EXTENSION_MAP.get(unit_type, ".bin")


def summarize_protocol_hits(chunks: Sequence[bytes]) -> Dict[str, int]:
    summary = {
        "mpegts": 0,
        "jpeg": 0,
        "png": 0,
        "gif": 0,
        "bmp": 0,
        "webp": 0,
        "h264": 0,
        "h265": 0,
        "wav": 0,
        "mp3": 0,
        "ogg": 0,
        "flac": 0,
        "aac": 0,
        "pdf": 0,
        "zip": 0,
        "gzip": 0,
        "json": 0,
        "xml": 0,
        "http": 0,
        "rtsp": 0,
        "command": 0,
        "text": 0,
        "opaque": 0,
    }
    for chunk in chunks:
        unit_type = guess_unit_type(chunk)
        if unit_type == "mpegts_packet":
            summary["mpegts"] += 1
        elif unit_type == "jpeg_frame":
            summary["jpeg"] += 1
        elif unit_type == "png_image":
            summary["png"] += 1
        elif unit_type == "gif_image":
            summary["gif"] += 1
        elif unit_type == "bmp_image":
            summary["bmp"] += 1
        elif unit_type == "webp_image":
            summary["webp"] += 1
        elif unit_type == "h264_nal":
            summary["h264"] += 1
        elif unit_type == "h265_nal":
            summary["h265"] += 1
        elif unit_type == "wav_audio":
            summary["wav"] += 1
        elif unit_type == "mp3_audio":
            summary["mp3"] += 1
        elif unit_type == "ogg_audio":
            summary["ogg"] += 1
        elif unit_type == "flac_audio":
            summary["flac"] += 1
        elif unit_type == "aac_audio":
            summary["aac"] += 1
        elif unit_type == "pdf_document":
            summary["pdf"] += 1
        elif unit_type == "zip_archive":
            summary["zip"] += 1
        elif unit_type == "gzip_archive":
            summary["gzip"] += 1
        elif unit_type == "json_text":
            summary["json"] += 1
        elif unit_type == "xml_text":
            summary["xml"] += 1
        elif unit_type == "http_text":
            summary["http"] += 1
        elif unit_type == "rtsp_text":
            summary["rtsp"] += 1
        elif unit_type == "command_text":
            summary["command"] += 1
        elif unit_type == "plain_text":
            summary["text"] += 1
        else:
            summary["opaque"] += 1
    return summary
