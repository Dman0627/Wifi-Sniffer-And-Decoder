# Wifi-Sniffer-And-Decoder

[![CI](https://github.com/Dman0627/Wifi-Sniffer-And-Decoder/actions/workflows/ci.yml/badge.svg)](https://github.com/Dman0627/Wifi-Sniffer-And-Decoder/actions/workflows/ci.yml)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)
![Supported modes](https://img.shields.io/badge/supported-ubuntu%20%7C%20pi%20standalone%20%7C%20windows%20remote-2d7d46.svg)

Wi-Fi capture and analysis with a narrow, honest support matrix. The official product modes are Ubuntu standalone, Raspberry Pi OS standalone, and Windows 10/11 paired with Ubuntu or Raspberry Pi OS for remote capture.

## New here

If you want the easiest possible setup, start with `GETTING_STARTED.md`.

That guide gives you:

- the simplest path for Windows users
- the simplest path for Ubuntu and Raspberry Pi OS users
- a pcap-only path if you already have a capture file
- exact copy-paste commands for first run and daily use

Quick chooser:

| If you are on | Best path | Start here |
|---|---|---|
| Windows 10/11 | Use another device running Ubuntu or Raspberry Pi OS for capture | `GETTING_STARTED.md` -> `Windows + remote capture` |
| Ubuntu | Run everything on the same machine | `GETTING_STARTED.md` -> `Ubuntu standalone` |
| Raspberry Pi OS | Run everything on the same machine, or use it as a capture appliance | `GETTING_STARTED.md` -> `Raspberry Pi OS standalone` |
| Any supported machine with an existing `.pcap` or `.pcapng` | Skip live capture and analyze the file you already have | `GETTING_STARTED.md` -> `I already have a capture file` |

## What it does

- Capture or import a pcap or pcapng
- Extract streams and payload units across TCP and UDP
- Rank candidate payloads and run heuristic analysis
- Reconstruct or replay candidate output
- Inspect runs in a local web dashboard

## Supported target

This project now treats three modes as the official product surface:

- `Ubuntu standalone`
- `Raspberry Pi OS standalone`
- `Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture`

Supported matrix:

| Role | Officially supported | Notes |
|---|---|---|
| Ubuntu standalone | Yes | Primary full local workflow on Linux |
| Raspberry Pi OS standalone | Yes | Preferred compact/appliance Linux workflow |
| Windows controller/analyzer + Ubuntu remote capture | Yes | Supported Windows path |
| Windows controller/analyzer + Raspberry Pi OS remote capture | Yes | Preferred Windows path |
| Other Linux distros | Best effort | May work, but not an official target |
| macOS local analysis/capture | Experimental | Not an official target |
| Native Windows monitor-mode Wi-Fi capture | Experimental | Driver and adapter dependent |

What this means in practice:

- If you want standalone capture plus analysis on one machine, use `Ubuntu` or `Raspberry Pi OS`
- If you want to stay on Windows, use `pair-remote`, `bootstrap-remote`, `doctor`, and `start-remote`
- Local Windows capture still exists, but it is no longer an official product mode
- Windows monitor-mode and Wi-Fi lab helpers are best-effort, not the main promise of the repo

## Supported hardware qualification

The supported hardware program is intentionally narrow. We would rather tell you exactly which hosts and adapter families we qualify than pretend every radio behaves the same.

Use either of these commands to see the live qualification report for the current machine:

```bash
python videopipeline.py deps
python videopipeline.py hardware
```

Qualified hardware families:

| Host or adapter family | Status | Why |
|---|---|---|
| Ubuntu host (`x86_64` or `arm64`) | Supported | Official standalone target and official Linux capture-node target |
| Raspberry Pi OS host (Pi 4/5 style appliance) | Supported | Official compact/appliance target |
| Atheros `AR9271` / `ath9k_htc` | Supported | Narrow best-known Linux USB adapter family for monitor mode and injection |
| MediaTek `MT7612U` / `mt76x2u` | Supported with limits | Strong dual-band Linux option, but injection/firmware behavior still varies |
| Ralink or MediaTek `RT5572` / `rt2800usb` | Supported with limits | Common dual-band Linux option; keep injection expectations conservative |
| Intel `iwlwifi` family | Supported with limits | Useful for pcap-first and sniffing workflows, but not the narrow recommended lab adapter family |
| Broadcom `brcmfmac` onboard Raspberry Pi radios | Unsupported for the full lab path | Fine for some general wireless tasks, but not part of the qualified monitor/injection hardware program |
| Native Windows 802.11 adapters | Unsupported as an official capture target | Keep Windows in the controller/analyzer role and move raw capture to Linux |

This is the current hardware story:

- `Ubuntu standalone` and `Raspberry Pi OS standalone` are the only local capture hosts we qualify end to end
- `Windows 10/11` is qualified as the controller/analyzer host, not as the official raw-capture host
- When in doubt, pair Windows with a Linux appliance node and a qualified USB capture adapter

## WPA crack readiness

WPA recovery is no longer treated as a vague "maybe." The pipeline now classifies the current crack/decrypt path into one of four states:

- `known_key_supplied`
- `known_wordlist_attack_supported`
- `captured_handshake_insufficient`
- `unsupported`

Use:

```bash
python videopipeline.py crack-status
python videopipeline.py crack-status --cap /path/to/handshake.cap
```

The readiness check looks at:

- whether a handshake artifact actually exists
- whether that artifact is large enough to be worth attempting
- whether a known PSK is already configured
- whether a real wordlist attack path exists (`aircrack-ng` or `hashcat` plus conversion tooling)
- whether `ap_essid` and `airdecap-ng` are present for the decrypt step

That means the project now fails earlier and more honestly when the problem is "handshake too small" or "wordlist/tooling is missing," instead of just trying the crack path and hoping.

## Supported decode and replay families

Decode and replay are no longer treated as one giant heuristic bucket. The pipeline now classifies the dominant payload family for the selected stream and reports explicit support levels:

- `guaranteed`
- `high_confidence`
- `heuristic`
- `unsupported`

Current narrow support model:

| Dominant unit type | Decode | Replay | Notes |
|---|---|---|---|
| `plain_text`, `json_text`, `xml_text`, `http_text`, `rtsp_text`, `command_text` | Guaranteed | Guaranteed | Best deterministic reconstruction path |
| `png_image`, `gif_image`, `bmp_image`, `webp_image` | Guaranteed | Guaranteed | Strong signatures and direct file reconstruction |
| `jpeg_frame`, `wav_audio`, `mp3_audio`, `ogg_audio`, `flac_audio`, `aac_audio`, `pdf_document`, `zip_archive`, `gzip_archive`, `mpegts_packet`, `h264_nal`, `h265_nal` | High confidence | High confidence | Strong signatures, but continuity and capture quality still matter |
| `opaque_chunk` or unknown families | Heuristic | Unsupported | We still analyze them, but we do not present them as supported replay targets |

You will see these levels in:

- `python videopipeline.py detect`
- `python videopipeline.py analyze`
- `python videopipeline.py play`
- the dashboard and latest-report summary views

## Pipeline preflight

Before long-running decode or replay work, the project can now tell you exactly why the current path is ready, limited, or blocked:

```bash
python videopipeline.py preflight
```

The preflight check combines:

- capture quality and selected-stream strength
- replay-family support level
- whether analysis actually produced replay material
- WPA crack/decrypt readiness when the current workflow is Wi-Fi related

Instead of blindly starting replay, the pipeline now gives exact blockers and next steps like:

- no selected candidate stream
- selected stream too thin
- replay family unsupported
- no replay material was produced
- handshake too small
- missing wordlist, ESSID, or decrypt tooling

## Release gate

The release workflow now expects a real validation matrix under `validation_matrix/`.

Run it locally with:

```bash
python scripts/release_gate.py \
  --ubuntu-report validation_matrix/ubuntu_standalone_validation.json \
  --pi-report validation_matrix/pi_standalone_validation.json \
  --windows-report validation_matrix/windows_remote_validation.json \
  --sample-report validation_matrix/sample_text_analysis.json \
  --sample-report validation_matrix/sample_video_analysis.json
```

Or through the CLI:

```bash
python videopipeline.py release-gate \
  --ubuntu-report validation_matrix/ubuntu_standalone_validation.json \
  --pi-report validation_matrix/pi_standalone_validation.json \
  --windows-report validation_matrix/windows_remote_validation.json \
  --sample-report validation_matrix/sample_text_analysis.json \
  --sample-report validation_matrix/sample_video_analysis.json
```

That gate requires:

- `validation_matrix/ubuntu_standalone_validation.json`
- `validation_matrix/pi_standalone_validation.json`
- `validation_matrix/windows_remote_validation.json`
- one or more supported sample analysis reports with non-blocked replay feasibility

If those artifacts are missing or blocked, the tag-based release workflow now fails on purpose.

Recommended release-closeout order:

1. collect `validate-local` and `validate-remote` reports into `validation_matrix/`
2. copy one or more supported sample `analysis_report.json` files into `validation_matrix/`
3. run `python scripts/release_gate.py ...`
4. only tag a release after the gate says `fully validated`

## Start here

If you are brand new, read `GETTING_STARTED.md` first. The section below is the short version.

Use the installer that matches the machine you are sitting at:

| You are on | Official mode | Start with |
|---|---|---|
| Windows 10/11 | Controller/analyzer paired with Ubuntu or Raspberry Pi OS | `.\setup_remote.ps1` |
| Ubuntu | Standalone local capture + analysis | `./install_deps.sh` |
| Raspberry Pi OS | Standalone local capture + analysis, or remote capture appliance | `./install_deps.sh` |
| Other Linux distros | Best effort only | `./install_deps.sh` |
| macOS | Experimental only | `./install_deps.sh` |

`Windows 10/11 -> Ubuntu or Raspberry Pi OS remote capture`

```powershell
.\setup_remote.ps1
.\validate_remote.ps1 -Host pi@raspberrypi -Interface wlan0
.\run_remote.ps1 -Host pi@raspberrypi -Interface wlan0 -DoctorFirst
```

That is the supported Windows onboarding path. It installs local dependencies, pairs SSH, bootstraps the Linux capture device, writes a validation report, and leaves you with a repeatable daily-use command.

`Ubuntu or Raspberry Pi OS standalone`

```bash
./setup_local.sh
./validate_local.sh --interface wlan0
./run_local.sh
```

That is the supported Linux standalone path. `./setup_local.sh` wraps first-run config, `./validate_local.sh` writes a standalone validation report, and `./run_local.sh` is the day-to-day local workflow. All of the helper scripts auto-install missing supported dependencies by default.

Helper defaults:

- Supported helper scripts auto-install missing supported dependencies by default
- Use `-SkipInstallDeps` on the PowerShell helpers if you want to skip that check
- Use `--no-install-deps` on the shell helpers if you want to skip that check
- `.\scripts\check.ps1` and `bash ./scripts/check.sh` auto-install missing Python test dependencies

If your adapter supports monitor mode and the Wi-Fi lab workflow, add:

```bash
sudo python3 videopipeline.py monitor
sudo python3 videopipeline.py wifi
```

## Quickstart

### Windows

```powershell
.\setup_remote.ps1
.\validate_remote.ps1 -Host pi@raspberrypi -Interface wlan0
.\run_remote.ps1 -Host pi@raspberrypi -Interface wlan0 -DoctorFirst
```

Windows is an official controller/analyzer target only when paired with Ubuntu or Raspberry Pi OS over SSH. `.\setup_remote.ps1` wraps the Windows-first flow: local install, guided remote setup, and saved config.

If you have already bootstrapped an appliance profile on the remote box, `.\setup_remote.ps1` can now discover it automatically from the health endpoint when no `-Host` is provided.

If you prefer the raw installer/CLI route, the equivalent sequence is:

```powershell
.\install_deps.ps1
.\.venv\Scripts\Activate.ps1
python .\videopipeline.py pair-remote --host pi@raspberrypi
python .\videopipeline.py bootstrap-remote --host pi@raspberrypi
.\validate_remote.ps1 -Host pi@raspberrypi -Interface wlan0
.\run_remote.ps1 -Host pi@raspberrypi -Interface wlan0 -DoctorFirst
```

Use `-SkipSystemPackages`, `-SkipWifiTools`, or `-SkipSshSetup` to opt out of parts of the Windows installer. Native Windows monitor-mode capture remains experimental.

### Linux or Raspberry Pi

```bash
chmod +x install_deps.sh
./setup_local.sh
./validate_local.sh --interface wlan0
./run_local.sh
```

Ubuntu and Raspberry Pi OS are the official Linux standalone targets. This is the path to use when you want one machine to capture and analyze locally.

If you prefer the raw installer/CLI route, the equivalent sequence is:

```bash
./install_deps.sh
source .venv/bin/activate
python3 videopipeline.py deps
python3 videopipeline.py config
python3 videopipeline.py validate-local --interface wlan0
python3 videopipeline.py all
```

If your adapter supports monitor mode and the Wi-Fi lab workflow:

```bash
sudo python3 videopipeline.py monitor
sudo python3 videopipeline.py wifi
```

If this Linux machine will act as the capture appliance for a Windows controller, still install it locally here with `./install_deps.sh`, then return to Windows and run:

```powershell
.\setup_remote.ps1
.\validate_remote.ps1 -Host pi@raspberrypi -Interface wlan0
```

To skip system package installation on Linux:

```bash
./install_deps.sh --no-system
```

Other Linux distros may work, but they are best effort only.

### macOS

```bash
./install_deps.sh
python3 videopipeline.py deps
python3 videopipeline.py config
python3 videopipeline.py
```

macOS remains available for development and experimentation, but it is not an official supported target.

## Plug and play remote capture

This section is for the official Windows workflow. Capture on a Raspberry Pi OS or Ubuntu device, then pull the file to Windows automatically and run the pipeline there.

Bootstrap the remote device from Windows first:

```powershell
python .\videopipeline.py bootstrap-remote --host pi@raspberrypi
```

You can choose how the remote install lands:

- `--install-mode auto` chooses the bundle path when `scp` is available, otherwise falls back to the native inline bootstrap
- `--install-mode bundle` uploads the self-contained agent bundle and installs it on the remote box
- `--install-mode native` keeps using the inline SSH bootstrap script
- `--install-profile appliance` enables the systemd-based appliance profile with a health endpoint
- `--install-profile standard` leaves the remote box in the lighter managed-agent mode without the appliance extras

For example:

```powershell
python .\videopipeline.py bootstrap-remote --host pi@raspberrypi --install-mode bundle --install-profile appliance
```

To discover appliance nodes from Windows before pairing:

```powershell
python .\videopipeline.py discover-remote
```

That will:

- install `tcpdump` on the remote device when a supported package manager is available
- create `~/wifi-pipeline/captures`
- create `~/wifi-pipeline/state`
- install a managed capture agent at `~/wifi-pipeline/bin/wifi-pipeline-agent`
- install a helper command at `~/wifi-pipeline/bin/wifi-pipeline-capture`
- install a managed service command at `~/wifi-pipeline/bin/wifi-pipeline-service`
- symlink it into `~/.local/bin/wifi-pipeline-agent`
- symlink it into `~/.local/bin/wifi-pipeline-capture`
- symlink it into `~/.local/bin/wifi-pipeline-service`
- write completion markers and SHA-256 metadata for service-generated captures
- try to install a constrained privileged runner at `/usr/local/bin/wifi-pipeline-capture-privileged`
- try to add a matching sudoers rule so `start-remote` can capture without an interactive password prompt

The managed agent is now a shell-based self-contained runtime, so the remote capture box does not need a local Python install just to run the control path.

With `--install-profile appliance`, bootstrap also:

- installs a systemd appliance unit so the capture box comes back up in a known-good state after reboot
- installs a socket-activated health endpoint on port `8741` by default
- writes appliance metadata under `~/wifi-pipeline/state/appliance.env`

You can check the appliance health endpoint from another machine with:

```bash
curl http://raspberrypi:8741/health
```

On the Linux capture device:

```bash
wifi-pipeline-agent doctor --interface wlan0
wifi-pipeline-agent service start --interface wlan0 --duration 60
```

Back on Windows:

```powershell
python .\videopipeline.py start-remote --host pi@raspberrypi --interface wlan0 --duration 60 --run all
```

Windows shortcut:

```powershell
.\run_remote.ps1 -Host pi@raspberrypi -Interface wlan0 -Duration 60
```

First-run shortcut:

```powershell
.\setup_remote.ps1
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

`start-remote` is the most complete one-shot flow: it talks to the managed capture agent on the remote box, waits for the timed capture to finish, checks the remote completion marker and checksum metadata, pulls the exact file back, verifies the transfer, and runs the local stages you choose.

If you want the remote box to behave more like an appliance, you can drive the managed service directly:

```powershell
python .\videopipeline.py remote-service status --host pi@raspberrypi
python .\videopipeline.py remote-service start --host pi@raspberrypi --interface wlan0 --duration 60
python .\videopipeline.py remote-service last-capture --host pi@raspberrypi
python .\videopipeline.py remote-service stop --host pi@raspberrypi
```

That service keeps state under `~/wifi-pipeline/state`, tracks the last completed capture, and now sits behind the managed capture agent instead of relying on ad-hoc shell orchestration.

If you want to pre-build the remote runtime for release packaging or manual transfer, run:

```powershell
python .\scripts\build_agent_bundle.py
```

That writes a self-contained `wifi-pipeline-agent-<version>-bundle.tar.gz` archive under `dist\`.

`setup_remote.ps1` is the Windows-first first-run wizard. It prompts for the remote host, interface, and local import directory, saves those values to `lab.json`, runs pairing, bootstraps the remote appliance, and finishes with doctor. Add `-SmokeTest` if you want it to run a short remote capture at the end.

`run_remote.ps1` is the Windows-first wrapper around the normal day-to-day capture flow. It can also bootstrap and/or run doctor first:

```powershell
.\run_remote.ps1 -Host pi@raspberrypi -Interface wlan0 -Bootstrap -DoctorFirst
```

All three Windows helper scripts resolve the repo root automatically, so you can run them from any PowerShell working directory:

| Script | Best use |
|---|---|
| `.\setup_remote.ps1` | First-run setup, pairing, bootstrap, and optional smoke test |
| `.\validate_remote.ps1` | Supported-hardware validation and JSON report generation |
| `.\run_remote.ps1` | Day-to-day remote capture and local processing |

Linux helper scripts follow the same idea for the standalone path:

| Script | Best use |
|---|---|
| `./setup_local.sh` | First-run Linux setup and optional standalone validation |
| `./validate_local.sh` | Standalone validation report for Ubuntu/Raspberry Pi OS |
| `./run_local.sh` | Day-to-day local capture and processing |

These Linux helper scripts also resolve the repo root automatically, so you can launch them from outside the repository directory. Use `-SkipInstallDeps` on the PowerShell helpers or `--no-install-deps` on the shell helpers if you want to skip the automatic installer check.

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

For the official Windows remote path, you want doctor to show `Privilege mode: hardened`. If it falls back instead, re-run `bootstrap-remote` using a remote account that has `sudo` access.

To create a repeatable hardware-validation report:

```powershell
python .\videopipeline.py validate-remote --host pi@raspberrypi --interface wlan0
```

That writes a report to `pipeline_output/validation_report.json` unless you override it with `--report`.

For the official Linux standalone path, use:

```bash
./validate_local.sh --interface wlan0
python3 videopipeline.py validate-local --interface wlan0
```

That writes a standalone validation report to `pipeline_output/standalone_validation_report.json` unless you override it with `--report`.

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
bash ./scripts/check.sh
```

Both check scripts resolve the repo root automatically, so they work even if your shell is not already sitting in the repository root.
They also auto-install missing Python test dependencies from `requirements.txt` and `requirements-dev.txt`.

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
- `CHANGELOG.md` now captures the narrowed support matrix and release story for `3.0.0`
- `RELEASE_CHECKLIST.md` captures the simulated-vs-hardware validation gate for the supported matrix

Recommended release gate before calling the supported matrix done:

- `./validate_local.sh --interface wlan0` on Ubuntu
- `./validate_local.sh --interface wlan0` on Raspberry Pi OS
- `.\validate_remote.ps1 -Host pi@raspberrypi -Interface wlan0` on Windows with a Linux capture device

## Unsupported paths and long-term limits

These are intentional boundaries of the project as it stands today:

| Area | Status | What it means |
|---|---|---|
| Native Windows monitor-mode capture as the primary workflow | Unsupported as the main product path | It may work on some adapters, but it is not the reliability target for this repo |
| Adapter-independent Windows 802.11 parity with Linux | Not achievable here | Driver and hardware limits cannot be removed in software |
| Other Linux distributions outside Ubuntu and Raspberry Pi OS | Best effort only | They may work, but they are not part of the official support matrix |
| Remote capture on devices without a normal shell toolchain | Unsupported | The remote helper assumes SSH, bash, nohup, sudo/capabilities, and standard filesystem tools |
| Guaranteed WPA cracking, payload decoding, or replay | Unsupported | WPA and replay now report explicit support states, but universal cracking/decoding/replay is still not realistic |

Long-term limits that still apply even on the supported path:

- Raw packet capture still needs elevated privileges somewhere, even after bootstrap hardening
- Radio capture quality still depends on the remote adapter, antenna placement, channel conditions, and packet loss
- Some Wi-Fi lab helpers remain toolchain dependent and are more fragile than the pcap-first remote workflow
- Unknown or encrypted payloads may still produce false positives, partial reconstruction, or no usable replay at all

If you want the most reliable experience, stay on one of the official product modes:

- `Ubuntu standalone`
- `Raspberry Pi OS standalone`
- `Windows 10/11 + Ubuntu/Raspberry Pi OS remote capture`

## Troubleshooting

| Symptom | What to do |
|---|---|
| `doctor` reports fallback privilege mode | Re-run `python .\videopipeline.py bootstrap-remote --host ...` with a remote account that has `sudo` |
| SSH works but capture will not start | Verify the remote interface with `iw dev` on the Pi/Linux box, then rerun with `--interface wlan0` or the correct name |
| `validate-remote` fails before capture | Run `python .\videopipeline.py doctor --host ... --interface ...` and fix the first failing check |
| PowerShell blocks the helper scripts | Use `.\run_remote.bat`, `.\setup_remote.bat`, or `.\validate_remote.bat` |
| You want the quickest sanity check | Run `.\scripts\check.ps1` on Windows or `bash ./scripts/check.sh` on Linux/macOS |

## Commands

| Command | What it does |
|---|---|
| `python videopipeline.py` | Open the guided menu |
| `python videopipeline.py deps` | Check tools, workflow support tiers, hardware qualification, and Python packages |
| `python videopipeline.py hardware` | Print the supported hardware qualification report for the current machine |
| `python videopipeline.py preflight` | Fail early with exact replay/WPA blockers before long-running decode or replay work |
| `python videopipeline.py release-gate [--sample-report ...]` | Require the real validation matrix and supported sample analysis reports before calling a release fully validated |
| `python videopipeline.py crack-status [--cap handshake.cap]` | Show whether the WPA crack/decrypt path is actually ready, limited, or blocked |
| `python videopipeline.py discover-remote [--network 192.168.1.0/24]` | Discover appliance-style capture nodes from their health endpoint |
| `python videopipeline.py pair-remote --host ...` | Install your SSH key on a remote capture device |
| `python videopipeline.py bootstrap-remote --host ... [--install-mode auto|native|bundle] [--install-profile standard|appliance]` | Prepare a Pi/Linux capture device and install the managed capture agent/service |
| `python videopipeline.py setup-remote --host ... --interface wlan0` | Run the guided first-run setup flow and save the official Windows remote-capture config |
| `python videopipeline.py start-remote --host ... --interface wlan0 --duration 60 --run all` | Run the official Windows remote-capture flow, pull it back, and process it |
| `python videopipeline.py validate-remote --host ... --interface wlan0` | Run the official Windows remote-capture validation flow and write a JSON validation report |
| `python videopipeline.py validate-local --interface wlan0` | Run the Linux standalone validation flow and write a JSON validation report |
| `python videopipeline.py remote-service status --host ...` | Inspect the remote capture service state |
| `python videopipeline.py remote-service start --host ... --interface wlan0 --duration 60` | Start a timed capture on the remote appliance without pulling it yet |
| `python videopipeline.py remote-service last-capture --host ...` | Show the last completed capture path on the remote appliance |
| `python videopipeline.py remote-service stop --host ...` | Stop the running remote capture service |
| `python videopipeline.py doctor --host ... --interface wlan0` | Check local and remote capture readiness |
| `.\setup_remote.ps1` | Windows first-run wizard for install, pairing, bootstrap, and doctor |
| `.\validate_remote.ps1 -Host ... -Interface wlan0` | Windows remote-capture validation helper |
| `.\run_remote.ps1 -Host ... -Interface wlan0 -Duration 60` | Windows helper for bootstrap, doctor, and start-remote |
| `./setup_local.sh` | Linux first-run helper for config and optional standalone validation |
| `./validate_local.sh --interface wlan0` | Linux standalone validation helper |
| `./run_local.sh` | Linux helper for local capture and processing |
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

- The core analysis pipeline is cross platform, but the official product modes are `Ubuntu standalone`, `Raspberry Pi OS standalone`, and `Windows + Ubuntu/Raspberry Pi OS remote capture`.
- Wi-Fi lab helpers require external tools like `aircrack-ng` and remain more fragile than the remote pcap-first path.
- Some reconstruction paths are heuristic and may require tuning in `lab.json`.
