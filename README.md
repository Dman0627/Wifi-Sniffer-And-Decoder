# Wifi-Sniffer-And-Decoder

[![CI](https://github.com/Dman0627/Wifi-Sniffer-And-Decoder/actions/workflows/ci.yml/badge.svg)](https://github.com/Dman0627/Wifi-Sniffer-And-Decoder/actions/workflows/ci.yml)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)
![Supported path](https://img.shields.io/badge/supported-windows%20%2B%20pi%2Fubuntu-2d7d46.svg)

Windows-first stream analysis with a Linux capture appliance. The supported product path is: run the controller and analysis on Windows, and capture packets on Raspberry Pi OS or Ubuntu over SSH.

## What it does

- Capture or import a pcap or pcapng
- Extract streams and payload units across TCP and UDP
- Rank candidate payloads and run heuristic analysis
- Reconstruct or replay candidate output
- Inspect runs in a local web dashboard

## Supported target

This project now treats one workflow as the official supported path:

- `Windows 10/11` as the controller, launcher, and analysis machine
- `Raspberry Pi OS` or `Ubuntu` as the remote capture device
- `SSH` as the control plane between them

Supported matrix:

| Role | Officially supported | Notes |
|---|---|---|
| Windows controller/analyzer | Yes | Primary day to day workflow |
| Raspberry Pi OS remote capture | Yes | Preferred capture appliance target |
| Ubuntu remote capture | Yes | Secondary supported capture target |
| Native Linux local analysis | Partial | Useful for development and advanced users |
| macOS local analysis/capture | Experimental | Not a primary target |
| Native Windows monitor-mode Wi-Fi capture | Experimental | Driver and adapter dependent |

What this means in practice:

- If you want the most reliable experience, use `pair-remote`, `bootstrap-remote`, `doctor`, and `start-remote`
- Local Windows capture still exists, but it is no longer the primary product path
- Windows monitor-mode and Wi-Fi lab helpers are best-effort, not the main promise of the repo

## Quickstart

### Windows

```powershell
.\install_deps.ps1
.\.venv\Scripts\Activate.ps1
python .\videopipeline.py deps
python .\videopipeline.py config
python .\videopipeline.py
```

Windows is the primary controller/analyzer target. The installer will attempt to install Wireshark, Npcap, FFmpeg, and OpenSSH. Use `-SkipSystemPackages`, `-SkipWifiTools`, or `-SkipSshSetup` to opt out.

For the supported workflow, use Windows to control a remote Raspberry Pi OS or Ubuntu capture device instead of relying on native Windows monitor mode.

For the easiest first run on Windows, use the setup wizard:

```powershell
.\setup_remote.ps1 -InstallDeps
```

To validate a real supported setup after pairing/bootstrap, use:

```powershell
.\validate_remote.ps1 -Host pi@raspberrypi -Interface wlan0
```

### Linux or Raspberry Pi

```bash
chmod +x install_deps.sh
./install_deps.sh
python3 videopipeline.py deps
python3 videopipeline.py config
python3 videopipeline.py
```

To skip system package installation:

```bash
./install_deps.sh --no-system
```

Linux is primarily the remote capture target. Raspberry Pi OS and Ubuntu are the supported remote appliance choices.

### macOS

```bash
./install_deps.sh
python3 videopipeline.py deps
python3 videopipeline.py config
python3 videopipeline.py
```

macOS remains available for development and experimentation, but it is not part of the primary supported capture workflow.

## Plug and play remote capture

This is the primary supported workflow. Capture on a Raspberry Pi OS or Ubuntu device, then pull the file to Windows automatically and run the pipeline.

Bootstrap the remote device first:

```powershell
python .\videopipeline.py bootstrap-remote --host pi@raspberrypi
```

That will:

- install `tcpdump` on the remote device when a supported package manager is available
- create `~/wifi-pipeline/captures`
- create `~/wifi-pipeline/state`
- install a helper command at `~/wifi-pipeline/bin/wifi-pipeline-capture`
- install a managed service command at `~/wifi-pipeline/bin/wifi-pipeline-service`
- symlink it into `~/.local/bin/wifi-pipeline-capture`
- symlink it into `~/.local/bin/wifi-pipeline-service`
- write completion markers and SHA-256 metadata for service-generated captures
- try to install a constrained privileged runner at `/usr/local/bin/wifi-pipeline-capture-privileged`
- try to add a matching sudoers rule so `start-remote` can capture without an interactive password prompt

On the capture device:

```bash
wifi-pipeline-capture --interface wlan0 --duration 60
```

On Windows:

```powershell
python .\videopipeline.py start-remote --host pi@raspberrypi --interface wlan0 --duration 60 --run all
```

Windows shortcut:

```powershell
.\run_remote.ps1 -Host pi@raspberrypi -Interface wlan0 -Duration 60
```

First-run shortcut:

```powershell
.\setup_remote.ps1 -InstallDeps
```

If your PowerShell execution policy blocks `.ps1` scripts, use:

```bat
.\run_remote.bat -Host pi@raspberrypi -Interface wlan0 -Duration 60
```

or:

```bat
.\setup_remote.bat
```

Or, if you already have a capture file on the remote device:

```powershell
python .\videopipeline.py remote --host pi@raspberrypi --path /home/pi/wifi-pipeline/captures/ --run all
```

`start-remote` is the most complete one-shot flow: it starts the remote capture helper, waits for the timed capture to finish, checks the remote completion marker and checksum metadata, pulls the exact file back, verifies the transfer, and runs the local stages you choose.

If you want the remote box to behave more like an appliance, you can drive the managed service directly:

```powershell
python .\videopipeline.py remote-service status --host pi@raspberrypi
python .\videopipeline.py remote-service start --host pi@raspberrypi --interface wlan0 --duration 60
python .\videopipeline.py remote-service last-capture --host pi@raspberrypi
python .\videopipeline.py remote-service stop --host pi@raspberrypi
```

That service keeps state under `~/wifi-pipeline/state`, tracks the last completed capture, and gives `start-remote` a stable control surface instead of relying on a one-off shell command.

`setup_remote.ps1` is the Windows-first first-run wizard. It prompts for the remote host, interface, and local import directory, saves those values to `lab.json`, runs pairing, bootstraps the remote appliance, and finishes with doctor. Add `-SmokeTest` if you want it to run a short remote capture at the end.

`run_remote.ps1` is the Windows-first wrapper around the normal day-to-day capture flow. It can also bootstrap and/or run doctor first:

```powershell
.\run_remote.ps1 -Host pi@raspberrypi -Interface wlan0 -Bootstrap -DoctorFirst
```

`validate_remote.ps1` is the Windows-first supported-hardware validation flow. It runs environment checks, doctor, captures a short smoke file by default, and writes a JSON report to `pipeline_output/validation_report.json`.

```powershell
.\validate_remote.ps1 -Host pi@raspberrypi -Interface wlan0
.\validate_remote.ps1 -Host pi@raspberrypi -Interface wlan0 -SkipSmoke
```

If you give `remote` a directory or pattern, the tool will pull the newest file. For continuous pulls, use `--watch` and `--interval 5`.

To verify the whole setup:

```powershell
python .\videopipeline.py doctor --host pi@raspberrypi --interface wlan0
```

That checks local tools, SSH/SCP availability, remote reachability, whether `tcpdump` is present, whether the remote helper and service exist, whether the no-prompt privileged runner is ready, whether the state/capture directories are writable, and whether the latest service-generated capture has integrity metadata.

For the supported path, you want doctor to show `Privilege mode: hardened`. If it falls back instead, re-run `bootstrap-remote` using a remote account that has `sudo` access.

To create a repeatable hardware-validation report:

```powershell
python .\videopipeline.py validate-remote --host pi@raspberrypi --interface wlan0
```

That writes a report to `pipeline_output/validation_report.json` unless you override it with `--report`.

## Secure connection setup

Remote pulls use SSH and SCP. The Windows installer will create an SSH key if needed. To add the key to your capture device:

Fast path:

```powershell
python .\videopipeline.py pair-remote --host pi@raspberrypi
python .\videopipeline.py bootstrap-remote --host pi@raspberrypi
```

Those commands will find or create your local SSH key, install it on the remote device, verify passwordless SSH, set up the standard capture helper, and try to harden remote capture privileges for no-prompt runs.

Manual path:

1. On Windows, show your public key:

```powershell
type $env:USERPROFILE\.ssh\id_ed25519.pub
```

2. On the capture device, append it to `~/.ssh/authorized_keys`:

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo "PASTE_YOUR_PUBLIC_KEY_HERE" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Test the connection:

```powershell
ssh pi@raspberrypi
```

## Tests and checks

Install test dependencies:

```bash
pip install -r requirements-dev.txt
```

Run tests:

```bash
python -m pytest -q
```

GitHub Actions now runs the same compile and test checks on Windows, Linux, and macOS for pushes and pull requests.

Run the quick check script (syntax plus tests):

```powershell
.\scripts\check.ps1
```

```bash
./scripts/check.sh
```

## Packaging and release

You can install the project as a local Python package now:

```bash
python -m pip install .
videopipeline --help
```

If you want a release-style bundle from your local checkout:

```bash
python scripts/build_release.py
```

That writes a portable zip plus a release manifest into `dist/`.

GitHub also has a release workflow now:

- pushes on tags like `v3.0.0` build a wheel, source distribution, and portable zip
- manual runs via GitHub Actions also build the same artifacts
- the workflow uploads artifacts to GitHub Releases for tagged builds

## Unsupported paths and long-term limits

These are intentional boundaries of the project as it stands today:

| Area | Status | What it means |
|---|---|---|
| Native Windows monitor-mode capture as the primary workflow | Unsupported as the main product path | It may work on some adapters, but it is not the reliability target for this repo |
| Adapter-independent Windows 802.11 parity with Linux | Not achievable here | Driver and hardware limits cannot be removed in software |
| Remote capture on arbitrary Linux distributions | Best effort only | The supported appliance targets are Raspberry Pi OS and Ubuntu |
| Remote capture on devices without a normal shell toolchain | Unsupported | The remote helper assumes SSH, bash, nohup, sudo/capabilities, and standard filesystem tools |
| Guaranteed WPA cracking, payload decoding, or replay | Unsupported | Analysis and replay are heuristic and may require manual tuning in `lab.json` |

Long-term limits that still apply even on the supported path:

- Raw packet capture still needs elevated privileges somewhere, even after bootstrap hardening
- Radio capture quality still depends on the remote adapter, antenna placement, channel conditions, and packet loss
- Some Wi-Fi lab helpers remain toolchain dependent and are more fragile than the pcap-first remote workflow
- Unknown or encrypted payloads may still produce false positives, partial reconstruction, or no usable replay at all

If you want the most reliable experience, stay on the supported product path:

- `Windows 10/11` for control, import, analysis, and replay
- `Raspberry Pi OS` or `Ubuntu` for remote capture
- `pair-remote -> bootstrap-remote -> doctor -> start-remote`

## Commands

| Command | What it does |
|---|---|
| `python videopipeline.py` | Open the guided menu |
| `python videopipeline.py deps` | Check tools and Python packages |
| `python videopipeline.py pair-remote --host ...` | Install your SSH key on a remote capture device |
| `python videopipeline.py bootstrap-remote --host ...` | Prepare a Pi/Linux capture device and install the helper script |
| `python videopipeline.py setup-remote --host ... --interface wlan0` | Run the guided first-run setup flow and save the supported remote-capture config |
| `python videopipeline.py start-remote --host ... --interface wlan0 --duration 60 --run all` | Run a timed remote capture through the managed remote service, pull it back, and process it |
| `python videopipeline.py validate-remote --host ... --interface wlan0` | Run the supported smoke-validation flow and write a JSON validation report |
| `python videopipeline.py remote-service status --host ...` | Inspect the remote capture service state |
| `python videopipeline.py remote-service start --host ... --interface wlan0 --duration 60` | Start a timed capture on the remote appliance without pulling it yet |
| `python videopipeline.py remote-service last-capture --host ...` | Show the last completed capture path on the remote appliance |
| `python videopipeline.py remote-service stop --host ...` | Stop the running remote capture service |
| `python videopipeline.py doctor --host ... --interface wlan0` | Check local and remote capture readiness |
| `.\setup_remote.ps1 -InstallDeps` | Windows first-run wizard for install, pairing, bootstrap, and doctor |
| `.\validate_remote.ps1 -Host ... -Interface wlan0` | Windows supported-hardware validation helper |
| `.\run_remote.ps1 -Host ... -Interface wlan0 -Duration 60` | Windows helper for bootstrap, doctor, and start-remote |
| `python videopipeline.py capture` | Capture to `pipeline_output/raw_capture.pcapng` |
| `python videopipeline.py extract --pcap <file>` | Extract payload streams |
| `python videopipeline.py detect` | Build detection report |
| `python videopipeline.py analyze` | Build analysis report |
| `python videopipeline.py play` | Attempt replay or reconstruction |
| `python videopipeline.py web` | Launch the local dashboard |
| `python videopipeline.py all` | Run capture then extract, detect, analyze |
| `python videopipeline.py remote --host ... --path ... --run all` | Pull remote pcap and run the pipeline |

## Output layout

```
pipeline_output/
  raw_capture.pcapng
  manifest.json
  detection_report.json
  analysis_report.json
  extracted_units/
  reassembled_streams/
  candidate_keystreams/
  replay/
  corpus/
```

## Why Windows is limited

Full 802.11 monitor capture depends on the adapter and driver. Windows drivers are often restricted, so the reliable solution is to capture on Linux or a Pi and analyze on Windows. The remote pull flow makes that plug and play.

## Notes

- The core analysis pipeline is cross platform, but the product is optimized around `Windows + Raspberry Pi OS/Ubuntu`.
- Wi Fi lab helpers require external tools like aircrack ng and remain more fragile than the remote pcap-first path.
- Some reconstruction paths are heuristic and may require tuning in `lab.json`.
