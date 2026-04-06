from __future__ import annotations

from pathlib import Path

from scapy.all import IP, UDP, Raw, wrpcap  # type: ignore

from wifi_pipeline.analysis import CryptoAnalyzer, FormatDetector
from wifi_pipeline.extract import StreamExtractor
from wifi_pipeline.playback import reconstruct_from_capture


def test_end_to_end_pipeline_with_generated_pcap(tmp_path) -> None:
    output_dir = tmp_path / "pipeline_output"
    capture_path = tmp_path / "sample_capture.pcap"
    packets = [
        IP(src="10.1.0.10", dst="10.1.0.20") / UDP(sport=41000, dport=5004) / Raw(load=b"frame-one\n"),
        IP(src="10.1.0.10", dst="10.1.0.20") / UDP(sport=41000, dport=5004) / Raw(load=b"frame-two\n"),
    ]
    wrpcap(str(capture_path), packets)
    config = {
        "output_dir": str(output_dir),
        "protocol": "udp",
        "video_port": 5004,
        "replay_format_hint": "auto",
        "video_codec": "raw",
        "min_candidate_bytes": 1,
    }

    manifest = StreamExtractor(config).extract(str(capture_path))
    detection = FormatDetector(config).detect()
    analysis = CryptoAnalyzer(config).analyze(decrypted_dir=str(output_dir))
    replay_dir = reconstruct_from_capture(config, analysis)

    assert manifest["stream_stats"]["total"] == 1
    assert detection["selected_candidate_stream"]["candidate_class"] == "recognized_text_candidate"
    assert analysis["candidate_material"]["mode"] == "static_xor_candidate"
    assert replay_dir is not None
    reconstructed = Path(replay_dir) / "stream_reconstructed.txt"
    assert reconstructed.read_bytes() == b"frame-one\nframe-two\n"
