# Wifi-Sniffer-And-Decoder

This repository now uses a single environment model:

- Native Windows for capture and tool execution
- Wireshark/NPcap tools on PATH
- Native Windows Python for the CLI

## Setup

```powershell
.\install_deps.ps1
.\.venv\Scripts\Activate.ps1
python .\videopipeline.py config
python .\videopipeline.py deps
```

To install Wireshark and FFmpeg automatically with `winget`, run:

```powershell
.\install_deps.ps1 -InstallWingetPackages
```

If you want Wi-Fi layer stripping, install the Windows aircrack-ng bundle separately and add `airdecap-ng` to PATH.

## Commands

```powershell
python .\videopipeline.py
python .\videopipeline.py menu
python .\videopipeline.py web
python .\videopipeline.py capture
python .\videopipeline.py extract --pcap .\pipeline_output\raw_capture.pcapng
python .\videopipeline.py detect
python .\videopipeline.py analyze --decrypted .\known_plaintext
python .\videopipeline.py play
python .\videopipeline.py corpus
python .\videopipeline.py all
```

Running `python .\videopipeline.py` with no subcommand opens the guided dashboard interface.
Running `python .\videopipeline.py web` starts a local browser dashboard on `http://127.0.0.1:8765/`.

## What Changed

- Extraction is flow-based and uses `scapy.PcapReader` instead of `rdpcap()`.
- TCP payloads are reassembled as byte streams before unit splitting.
- RTP/UDP traffic is grouped by timestamp and sequence when possible.
- The manifest now stores richer stream and packet metadata.
- Detection reports use multiple units and flow scoring rather than one sample.
- Payload detection is no longer video-only: it can surface text, command-like data, photos, audio, documents, archives, and custom opaque streams.
- Recognized extracted units are written with readable file extensions where possible.
- Analysis now archives candidate streams into a local corpus and compares future captures against that history; strong matches can reuse prior experimental material.
- There is now a browser dashboard for config, pipeline actions, candidate review, corpus status, and action logs.
- Full runs now auto-attempt offline reconstruction when analysis produces usable candidate material.
- Crypto output is framed as heuristic analysis and experimental replay material, not guaranteed decryption.
