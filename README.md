# Wifi-Sniffer-And-Decoder

[![CI](https://github.com/Potato4507/Wifi-Sniffer-And-Decoder/actions/workflows/ci.yml/badge.svg)](https://github.com/Potato4507/Wifi-Sniffer-And-Decoder/actions/workflows/ci.yml)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)
![Supported modes](https://img.shields.io/badge/supported-ubuntu%20%7C%20pi%20standalone%20%7C%20windows%20remote-2d7d46.svg)

Capability-driven Wi-Fi capture and pcap analysis with a narrow, explicit support matrix. This project is designed to tell you what the current machine can actually do, guide you onto the reliable supported paths, and stay honest when capture, WPA decrypt, extraction, or replay are limited.

## Start here

Read [`GETTING_STARTED.md`](GETTING_STARTED.md) for the copy-paste setup guide.

| If you are on | Best path | Start here |
|---|---|---|
| Windows 10/11 | Use Ubuntu or Raspberry Pi OS as the capture device | `GETTING_STARTED.md` -> `The easiest path for most Windows users` |
| Ubuntu | Run capture and analysis on one machine | `GETTING_STARTED.md` -> `Ubuntu standalone` |
| Raspberry Pi OS | Run locally or use it as a capture appliance | `GETTING_STARTED.md` -> `Raspberry Pi OS standalone` |
| Any supported machine with a `.pcap` or `.pcapng` | Skip live capture and analyze the file | `GETTING_STARTED.md` -> `I already have a capture file` |

## What it does

- Report machine, adapter, privilege, WPA, remote, and replay capability before you commit to a workflow
- Capture live traffic or import an existing pcap/pcapng
- Extract TCP and UDP streams and rank likely payload candidates
- Run protocol-aware heuristic analysis and reconstruction
- Track artifacts and results in a local web dashboard
- Support Windows-first remote capture through an Ubuntu or Raspberry Pi OS device

## What this repo promises

- It tells you what is `supported`, `limited`, or `blocked` on the current machine instead of assuming the full workflow will work everywhere.
- It is optimized for reliable supported paths: `Ubuntu standalone`, `Raspberry Pi OS standalone`, and `Windows controller/analyzer + Linux remote capture`.
- It reports WPA readiness, remote appliance health, candidate confidence, and replay/export confidence in the CLI and dashboard before you invest time in a full run.
- It exports honest artifacts for unknown payload families instead of pretending every stream is replayable.

## What it does not promise

- It is not a universal decoder for arbitrary Wi-Fi traffic.
- It does not make native Windows monitor-mode capture equivalent to Linux monitor-mode support.
- It does not bypass WPA requirements; decrypt remains conditional on real capture artifacts, usable credentials, and the required external toolchain.
- It does not guarantee meaningful extraction or replay for opaque or unsupported payload families; those fall back to ranked candidates plus raw/exported artifacts.

## Official support matrix

| Role | Status | Notes |
|---|---|---|
| Ubuntu standalone | Supported | Primary full local workflow |
| Raspberry Pi OS standalone | Supported | Preferred compact/appliance workflow |
| Windows controller/analyzer + Ubuntu remote capture | Supported | Official Windows path |
| Windows controller/analyzer + Raspberry Pi OS remote capture | Supported | Preferred Windows path |
| Other Linux distros | Best effort | May work, not an official target |
| macOS local analysis/capture | Experimental | Not an official target |
| Native Windows monitor-mode capture | Experimental | Adapter and driver dependent |

Windows is qualified as the controller/analyzer host, not as the official raw-capture host. For the most reliable path, keep raw capture on Linux and run control plus analysis on Windows.

## Key commands

```bash
python videopipeline.py deps
python videopipeline.py hardware
python videopipeline.py preflight
python videopipeline.py crack-status
python videopipeline.py web
python videopipeline.py all
```

Use these commands as the capability and readiness path:

- `deps`: verifies required tooling on the current host
- `hardware`: reports what this machine, adapter, and privilege mode can actually do
- `preflight`: explains whether the selected pipeline path is supported, limited, or blocked
- `crack-status`: explains WPA artifact and decrypt readiness instead of guessing
- `doctor`: validates the remote appliance path before a remote capture run

Official Windows remote-flow commands:

```powershell
python .\videopipeline.py discover-remote
python .\videopipeline.py pair-remote --host pi@raspberrypi
python .\videopipeline.py bootstrap-remote --host pi@raspberrypi
python .\videopipeline.py doctor --host pi@raspberrypi --interface wlan0
python .\videopipeline.py start-remote --host pi@raspberrypi --interface wlan0 --duration 60 --run all
```

## Hardware and replay expectations

- Qualified local capture hosts: `Ubuntu standalone` and `Raspberry Pi OS standalone`
- Qualified Windows role: `controller/analyzer + Linux remote capture`
- Replay and decoding are intentionally classified as `guaranteed`, `high_confidence`, `heuristic`, or `unsupported`
- WPA readiness is explicitly reported instead of guessed; use `crack-status` before assuming decrypt will work
- Unknown or unsupported payload families are exported with metadata instead of being presented as successful replay

## Development

Install the project locally:

```bash
python -m pip install .
```

Install contributor tooling:

```bash
python -m pip install -e ".[dev]"
```

Run checks:

```bash
python -m pytest -q
python -m compileall -q wifi_pipeline
```

Shortcut helpers:

```powershell
.\scripts\check.ps1
```

```bash
bash ./scripts/check.sh
```

## Release gate

Tagged releases are expected to include real validation artifacts in [`validation_matrix`](validation_matrix/README.md) and pass the release gate:

```bash
python scripts/release_gate.py \
  --ubuntu-report validation_matrix/ubuntu_standalone_validation.json \
  --pi-report validation_matrix/pi_standalone_validation.json \
  --windows-report validation_matrix/windows_remote_validation.json \
  --sample-report validation_matrix/sample_text_analysis.json
```

For the full release checklist, see [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md).

## More docs

- [`GETTING_STARTED.md`](GETTING_STARTED.md): setup and daily-use guide
- [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md): release criteria and validation expectations
- [`validation_matrix/README.md`](validation_matrix/README.md): required real-hardware reports
- [`CHANGELOG.md`](CHANGELOG.md): release history
