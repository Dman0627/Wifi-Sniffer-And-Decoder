# Wifi-Sniffer-And-Decoder

A packet and payload inspection pipeline built around a simple flow:

1. capture or import a pcap/pcapng
2. extract payload-bearing streams and units
3. rank likely candidate streams
4. run heuristic analysis on the selected candidate
5. attempt offline reconstruction or experimental playback

The project is cross-platform for the **core post-capture workflow** (`extract`, `detect`, `analyze`, `play`, `web`). It also contains additional **Wi-Fi lab helpers** for monitor-mode capture, handshake collection, and WPA-related processing, but those platform-specific features do **not** have equal support on Windows.

Highlights:

- pcap-first workflow that works on Windows, Linux, and macOS
- stream extraction, heuristic ranking, and offline reconstruction
- optional Wi-Fi lab helpers when the native toolchain is available

## Quickstart (pcap-first)

If you already have a capture file, this is the fastest path:

```bash
python videopipeline.py deps
python videopipeline.py config
python videopipeline.py extract --pcap path/to/input.pcapng
python videopipeline.py detect
python videopipeline.py analyze
python videopipeline.py play
```

---

## What the project does

At a high level, this codebase is a packet-to-artifact pipeline:

- **Capture / import** traffic into a pcap/pcapng file
- **Extract** TCP, UDP, IPv6, and some other transport flows into per-stream units
- **Detect** likely content types and rank the most interesting streams
- **Analyze** a chosen stream with heuristic methods and optional corpus reuse
- **Reconstruct** or replay the chosen stream into files under `pipeline_output/replay/`
- **Inspect** the whole run from a local browser dashboard

The project is strongest when used as a **local packet analysis and reconstruction tool**. Windows is best supported for normal capture/import plus the analysis pipeline. Linux and macOS expose extra low-level network features through external tools when they are installed.

---

## Current platform support

This table reflects the code as it exists now.

| Feature | Windows | Linux / Kali | macOS |
|---|---:|---:|---:|
| Guided menu / CLI / web dashboard | ✅ | ✅ | ✅ |
| Standard capture via `dumpcap` | ✅ | ✅ | ✅ |
| Fallback capture via `tcpdump` | ❌ | ✅ | ✅ |
| Extract / detect / analyze / replay | ✅ | ✅ | ✅ |
| Corpus archive / reuse | ✅ | ✅ | ✅ |
| Monitor mode via `airmon-ng` | ❌ | ✅ | ❌ |
| Monitor mode via `tcpdump -I` | ❌ | ❌ | ✅ |
| Monitor mode via Npcap `WlanHelper` | Limited / adapter-dependent | ❌ | ❌ |
| Targeted handshake helpers in CLI | Limited / adapter-dependent | ✅ | Limited / partial |
| WPA crack / Wi-Fi layer strip helpers in code | Limited | ✅ | ✅ |

### Important note on parity

The codebase does **not** currently offer equal low-level Wi-Fi functionality across platforms. The **core analysis pipeline** is cross-platform. The **monitor / crack / full Wi-Fi lab pipeline** is most reliable on Linux, partially available on macOS, and on Windows is adapter/driver dependent (Npcap monitor mode).

---

## Project layout

The source is organized around small modules with one main responsibility each.

| File | Purpose |
|---|---|
| `videopipeline.py` | Thin launcher that calls the CLI entrypoint |
| `cli.py` | Main command parser, guided menu, stage orchestration |
| `config.py` | Default config, config loading/saving, interactive configuration |
| `environment.py` | Platform detection, tool checks, interface discovery, privilege helpers |
| `capture.py` | Standard capture plus platform-specific Wi-Fi helper logic |
| `extract.py` | Reads pcaps, groups flows, emits stream/unit artifacts, writes `manifest.json` |
| `analysis.py` | Payload detection, candidate ranking, heuristic stream analysis |
| `playback.py` | Offline reconstruction and experimental playback |
| `corpus.py` | Archives candidate stream fingerprints and reusable material |
| `protocols.py` | Payload signatures, entropy helpers, RTP/header logic |
| `webapp.py` | Local browser dashboard for running stages and reviewing results |
| `ui.py` | Terminal formatting and prompt helpers |
| `install_deps.ps1` / `install_deps.sh` | Environment bootstrap scripts |
| `lab.json` | Saved runtime configuration |

---

## Requirements

### Python packages

Install the Python dependencies first:

```bash
pip install -r requirements.txt
```

Current `requirements.txt` is intentionally small:

- `numpy>=1.26`
- `scapy[basic]>=2.5`

### Native tools

The project checks for different native tools depending on platform.

#### Windows

Recommended:

- Wireshark / NPcap (`dumpcap`, `tshark`)
- NPcap `WlanHelper.exe` (monitor mode toggle; typically at `C:\Windows\System32\Npcap\WlanHelper.exe`)
- optional: `ffplay`
- optional (Wi-Fi lab): `aircrack-ng`, `airodump-ng`, `airdecap-ng`, `hashcat`, `besside-ng`, `aireplay-ng`

#### Linux / Kali

Commonly used by the project:

- `airmon-ng`
- `airodump-ng`
- `aircrack-ng`
- `airdecap-ng`
- optional: `besside-ng`, `aireplay-ng`, `hashcat`, `tcpdump`, `ffplay`

#### macOS

Commonly used by the project:

- built-in `tcpdump`
- optional Wireshark tools: `dumpcap`, `tshark`
- `aircrack-ng`
- `airdecap-ng`
- optional: `besside-ng`, `hashcat`, `ffplay`

---

## Setup

### Windows

```powershell
.\install_deps.ps1
.\.venv\Scripts\Activate.ps1
python .\videopipeline.py deps
python .\videopipeline.py config
```

Run capture or monitor-mode steps from an elevated PowerShell window when possible.

### Linux / Kali

```bash
chmod +x install_deps.sh
./install_deps.sh
python3 videopipeline.py deps
python3 videopipeline.py config
```

For full system package installation on apt-based systems:

```bash
./install_deps.sh --full
```

### macOS

You can use the shell installer for the Python environment, or install the native tools manually with Homebrew and then run:

```bash
python3 videopipeline.py deps
python3 videopipeline.py config
```

---

## Windows monitor-mode notes (Npcap)

Monitor mode on Windows is adapter and driver dependent. If your adapter supports it:

1. Install Npcap with "Support raw 802.11 traffic and monitor mode" enabled.
2. Confirm `WlanHelper.exe` is present (usually `C:\Windows\System32\Npcap\WlanHelper.exe`).
3. Run PowerShell as Administrator.
4. Toggle the adapter into monitor mode with `WlanHelper.exe`, then use the `monitor` or `wifi` commands.

Example:

```powershell
& "C:\Windows\System32\Npcap\WlanHelper.exe" "<Wi-Fi Name or GUID>" mode monitor
python .\videopipeline.py monitor --method tcpdump
```

If you get no traffic in monitor mode, your adapter likely lacks support. Consider a USB adapter known to support monitor mode, or use WSL2 with a Linux toolchain for full parity.

## Commands

These are the commands exposed by `cli.py`.

| Command | What it does |
|---|---|
| `python videopipeline.py` | Opens the guided interactive menu |
| `python videopipeline.py menu` | Same as above |
| `python videopipeline.py config` | Opens interactive configuration |
| `python videopipeline.py deps` | Checks required native tools and Python packages |
| `python videopipeline.py capture` | Runs a standard capture into `pipeline_output/raw_capture.pcapng` |
| `python videopipeline.py extract --pcap <file>` | Extracts payload streams from a pcap/pcapng |
| `python videopipeline.py detect` | Builds `detection_report.json` from the manifest |
| `python videopipeline.py analyze` | Builds `analysis_report.json` using heuristic analysis |
| `python videopipeline.py play` | Attempts replay/reconstruction using the last analysis report |
| `python videopipeline.py corpus` | Shows archived candidate stream information |
| `python videopipeline.py web` | Starts the local web dashboard |
| `python videopipeline.py all` | Runs capture → extract → detect → analyze, then play when possible |
| `python videopipeline.py monitor` | Platform-specific monitor-mode helper |
| `python videopipeline.py crack` | Platform-specific Wi-Fi helper |
| `python videopipeline.py wifi` | Platform-specific full Wi-Fi lab pipeline |

### Standard capture workflow

If your platform has working capture tooling configured:

```bash
python videopipeline.py capture
python videopipeline.py detect
python videopipeline.py analyze
python videopipeline.py play
```

### One-command workflow

```bash
python videopipeline.py all
```

---

## How the pipeline works

### 1) Configure

Run:

```bash
python videopipeline.py config
```

This writes settings to `lab.json`. Important groups of settings include:

- interface and capture duration
- protocol and target port
- output directory
- payload header stripping and custom magic bytes
- replay format hints
- corpus thresholds
- optional Wi-Fi-lab-related fields

The WPA password field is intentionally **not** written back to disk. If you use that part of the project, the saved config is sanitized on write.

### 2) Capture or import

You can either:

- capture traffic with `capture`, or
- point `extract` at an existing pcap/pcapng file

If extraction finds no matching traffic for the configured protocol/port, it falls back to scanning all transport flows it knows how to process.

### 3) Extract

`extract.py` writes:

- `pipeline_output/manifest.json`
- `pipeline_output/reassembled_streams/`
- `pipeline_output/extracted_units/`

The manifest includes:

- source pcap path
- capture interface and platform model
- filter settings
- stream statistics
- stream summaries
- emitted units
- control events

### 4) Detect

`detect` samples extracted units and writes `pipeline_output/detection_report.json`.

This stage:

- computes entropy samples
- records content-type counts
- checks for known protocol/payload indicators
- correlates some control traffic
- ranks candidate streams and selects a top candidate

### 5) Analyze

`analyze` writes `pipeline_output/analysis_report.json`.

This stage tries to answer questions like:

- which stream is the best candidate to focus on?
- what does the ciphertext/statistical profile look like?
- is there reusable material in the local corpus?
- is there enough candidate material to attempt reconstruction?

If it can prepare candidate material, it also archives the result into the corpus and may produce artifacts under:

- `pipeline_output/candidate_keystreams/`
- `pipeline_output/corpus/`

### 6) Replay / reconstruct

`play` uses the latest analysis result and attempts one of two things:

- **offline reconstruction** into files under `pipeline_output/replay/`, or
- **experimental playback** with `ffplay` when the format hint and environment support it

---

## Output directory layout

A typical run writes files under `pipeline_output/`:

```text
pipeline_output/
├── raw_capture.pcapng
├── manifest.json
├── detection_report.json
├── analysis_report.json
├── extracted_units/
├── reassembled_streams/
├── candidate_keystreams/
├── replay/
└── corpus/
```

Not every run will produce every directory.

---

## Web dashboard

Start it with:

```bash
python videopipeline.py web
```

Default address:

- `http://127.0.0.1:8765/`

The dashboard exposes the current config, recent artifacts, candidate stream information, corpus status, and buttons/forms for running the same major stages exposed by the CLI.

---

## Key config fields

These are the most important settings for the core workflow.

| Key | Meaning |
|---|---|
| `interface` | Capture interface name |
| `capture_duration` | Capture time in seconds (`0` means manual stop) |
| `output_dir` | Base output directory |
| `protocol` | Primary transport filter (`udp` or `tcp`) |
| `video_port` | Primary port filter |
| `custom_header_size` | Extra bytes to strip after the transport header |
| `custom_magic_hex` | Optional hex signature used to boost candidate ranking |
| `preferred_stream_id` | Stream to prioritize in later stages |
| `min_candidate_bytes` | Minimum size before a stream is treated as serious |
| `replay_format_hint` | Output/replay hint such as `raw`, `json`, `jpeg`, `mpegts`, `h264`, `h265` |
| `corpus_review_threshold` | Similarity threshold for surfacing prior corpus matches |
| `corpus_auto_reuse_threshold` | Similarity threshold for auto-reusing candidate material |
| `playback_mode` | `file`, `ffplay`, or `both` |
| `jitter_buffer_packets` | UDP jitter buffer size used by playback logic |

There are additional Wi-Fi-specific fields in `lab.json`, but they are only relevant if you are using those platform-specific helpers.

---

## What is accurate to say about this repo right now

This repo is best described as:

> a cross-platform packet and payload analysis pipeline with standard capture/import support on all major desktop platforms, plus additional platform-specific Wi-Fi helper code that is currently most complete on Linux.

It is **not** accurate to describe the project as having full feature parity between Windows and Linux for low-level Wi-Fi operations.

---

## Limitations

- Windows does not have equal support for the low-level Wi-Fi helper path.
- The project depends heavily on external native tools for capture and some replay/decryption-related features.
- Some format detection and reconstruction paths are heuristic and may require tuning via `lab.json`.
- The launcher expects a package layout where the modules are importable as `wifi_pipeline.*`.

---

## Suggested next cleanup tasks

If you continue developing this project, the biggest quality improvements would be:

1. separate the **core analysis pipeline** from the platform-specific Wi-Fi helper code
2. add a centralized capability map so the UI only shows supported actions per platform
3. make the package layout explicit in the repo structure
4. improve Windows parity for the standard capture/import and analysis path
5. add tests for manifest generation, candidate ranking, and reconstruction
