# Getting Started

This guide is the easiest way to install and use the project without digging through the full README first.

Pick the path that matches you:

| You are using | Best path | Why |
|---|---|---|
| Windows 10/11 | Windows + Ubuntu or Raspberry Pi OS remote capture | This is the supported Windows workflow and the most reliable option |
| Ubuntu | Ubuntu standalone | One machine can install, capture, analyze, and replay locally |
| Raspberry Pi OS | Raspberry Pi OS standalone | Good for a small dedicated capture box or a compact all-in-one setup |
| Any supported machine with an existing `.pcap` or `.pcapng` | Pcap-only analysis | Fastest way to test the pipeline without live capture |

## Before you start

You need:

- a copy of this repository on the machine you are using
- Python 3.12 or newer
- a terminal opened in the repository folder

If you are on Windows, use PowerShell.

If you are on Ubuntu or Raspberry Pi OS, use a normal shell.

## What to expect from this project

This repo is built around capability reporting and supported paths, not around promising that every machine or every capture can be decoded.

- Start with the path that matches your OS and hardware instead of assuming every workflow is available everywhere.
- Use `deps`, `hardware`, `doctor`, `preflight`, and `crack-status` when you want the project to tell you what is supported, limited, or blocked on this machine.
- The most reliable workflows keep raw capture on Linux, either locally on Ubuntu or Raspberry Pi OS or remotely from Windows.
- Extraction and replay are confidence-based. Known families can reconstruct or export cleanly; unknown families may only produce ranked candidates and raw exported artifacts.

## The easiest path for most Windows users

Use Windows as the controller and analyzer, and let a second device running Ubuntu or Raspberry Pi OS handle capture.

### What you need

- a Windows 10/11 machine
- a second device running Ubuntu or Raspberry Pi OS
- SSH access to the Linux device
- the Wi-Fi interface name on the Linux device, usually `wlan0`

To find the interface name on the Linux device, run:

```bash
iw dev
```

### First-time setup

From PowerShell in the repository folder on Windows:

```powershell
.\setup_remote.ps1
```

What this does:

- installs missing local dependencies
- helps set up SSH
- bootstraps the Linux capture device
- saves the remote settings for later

### Validate the setup

Replace `pi@raspberrypi` and `wlan0` with your real host and interface:

```powershell
.\validate_remote.ps1 -Host pi@raspberrypi -Interface wlan0
```

This checks:

- your local install
- your SSH connection
- the remote capture agent
- the capture interface
- a short end-to-end smoke test

### Run a capture and process it

```powershell
.\run_remote.ps1 -Host pi@raspberrypi -Interface wlan0 -DoctorFirst
```

That command:

- checks readiness first
- starts the remote capture
- pulls the finished capture back to Windows
- runs the pipeline locally

### Daily use

After setup, this is usually the only command you need:

```powershell
.\run_remote.ps1 -Host pi@raspberrypi -Interface wlan0
```

### Advanced Windows remote workflow

If you want the raw CLI route instead of the helper scripts:

```powershell
.\install_deps.ps1
.\.venv\Scripts\Activate.ps1
python .\videopipeline.py discover-remote
python .\videopipeline.py pair-remote --host pi@raspberrypi
python .\videopipeline.py bootstrap-remote --host pi@raspberrypi --install-profile appliance
python .\videopipeline.py doctor --host pi@raspberrypi --interface wlan0
python .\videopipeline.py start-remote --host pi@raspberrypi --interface wlan0 --duration 60 --run all
```

Notes:

- `discover-remote` looks for appliance-style Linux capture nodes from their health endpoint
- `bootstrap-remote` installs the managed capture agent and remote helper scripts
- `doctor` is the fastest way to find SSH, privilege, or interface issues before a live run
- `doctor` and `preflight` are capability-driven, so they will tell you whether the current remote path is supported, limited, or blocked
- `remote-service status`, `remote-service start`, and `remote-service last-capture` are useful when you want to control the appliance directly

## Ubuntu standalone

Use this when you want one Ubuntu machine to do everything locally.

### First-time setup

```bash
chmod +x install_deps.sh setup_local.sh validate_local.sh run_local.sh
./setup_local.sh
```

What this does:

- installs missing dependencies
- prepares the local Python environment
- helps you save the local configuration

### Validate the setup

Replace `wlan0` if your interface has a different name:

```bash
./validate_local.sh --interface wlan0
```

### Run the pipeline

```bash
./run_local.sh
```

### Daily use

After setup, this is usually the only command you need:

```bash
./run_local.sh
```

If your adapter supports monitor mode and you want the Wi-Fi lab workflow:

```bash
sudo python3 videopipeline.py monitor
sudo python3 videopipeline.py wifi
```

### Raw CLI route

If you prefer to stay in the CLI after install:

```bash
./install_deps.sh
source .venv/bin/activate
python3 videopipeline.py deps
python3 videopipeline.py config
python3 videopipeline.py validate-local --interface wlan0
python3 videopipeline.py all
python3 videopipeline.py web
```

## Raspberry Pi OS standalone

The steps are the same as Ubuntu standalone:

```bash
chmod +x install_deps.sh setup_local.sh validate_local.sh run_local.sh
./setup_local.sh
./validate_local.sh --interface wlan0
./run_local.sh
```

Use Raspberry Pi OS standalone when you want:

- a compact all-in-one system
- a dedicated test box
- a device that can also act as the Windows capture appliance later

## I already have a capture file

If you already have a `.pcap` or `.pcapng`, you can skip live capture and go straight to analysis.

### Windows

```powershell
.\install_deps.ps1
.\.venv\Scripts\Activate.ps1
python .\videopipeline.py extract --pcap .\path\to\capture.pcapng
python .\videopipeline.py detect
python .\videopipeline.py analyze
python .\videopipeline.py play
```

### Ubuntu or Raspberry Pi OS

```bash
./install_deps.sh
source .venv/bin/activate
python3 videopipeline.py extract --pcap ./path/to/capture.pcapng
python3 videopipeline.py detect
python3 videopipeline.py analyze
python3 videopipeline.py play
```

This is the easiest way to try the project without setting up live capture first.

Keep in mind that importing a pcap does not guarantee a meaningful decode. The pipeline will rank candidate streams, explain the confidence it has in them, and only claim replay or export support for known payload families.

## What the helper scripts do

| Script | Use it for |
|---|---|
| `setup_remote.ps1` | First-time Windows setup |
| `validate_remote.ps1` | Testing the Windows + Linux remote workflow |
| `run_remote.ps1` | Daily Windows remote capture and processing |
| `setup_local.sh` | First-time Ubuntu or Raspberry Pi OS setup |
| `validate_local.sh` | Testing the Linux standalone workflow |
| `run_local.sh` | Daily Ubuntu or Raspberry Pi OS capture and processing |

All of these helper scripts auto-install missing supported dependencies by default.

If you want to skip auto-install:

- PowerShell helpers: add `-SkipInstallDeps`
- shell helpers: add `--no-install-deps`

## Checks and contributor setup

Install the project with contributor tooling:

```bash
python -m pip install -e ".[dev]"
```

Run the full test suite:

```bash
python -m pytest -q
```

Quick check helpers:

```powershell
.\scripts\check.ps1
```

```bash
bash ./scripts/check.sh
```

Those helpers resolve the repo root automatically and install missing Python test dependencies from the local package extras if needed.

## Where results go

Most outputs are written to:

```text
pipeline_output/
```

Useful files there include:

- `raw_capture.pcapng`
- `detection_report.json`
- `analysis_report.json`
- `replay/`

## If something fails

Start with the built-in checks.

### Windows

```powershell
python .\videopipeline.py doctor --host pi@raspberrypi --interface wlan0
```

### Ubuntu or Raspberry Pi OS

```bash
python3 videopipeline.py deps
python3 videopipeline.py hardware
python3 videopipeline.py preflight
```

What those checks are for:

- `deps`: confirms the local toolchain is present
- `hardware`: reports adapter, privilege, monitor-mode, remote, and replay capability for this machine
- `doctor`: validates the managed remote appliance path
- `preflight`: tells you whether the configured run is supported, limited, or blocked
- `crack-status`: tells you whether WPA decrypt is actually ready or still missing required artifacts or tools

## If you want the guided menu

You can always open the guided CLI menu instead of remembering commands:

### Windows

```powershell
python .\videopipeline.py
```

### Ubuntu or Raspberry Pi OS

```bash
python3 videopipeline.py
```

## Next places to look

- For the full project details, read `README.md`
- For validation and release requirements, read `RELEASE_CHECKLIST.md`
- For the real-hardware validation matrix, read `validation_matrix/README.md`
