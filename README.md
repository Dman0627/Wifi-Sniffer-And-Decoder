# Wifi-Sniffer-And-Decoder

Cross platform packet capture, stream extraction, and offline reconstruction. Capture can run on Linux or a Raspberry Pi, while Windows handles the analysis reliably without special adapters.

## What it does

- Capture or import a pcap or pcapng
- Extract streams and payload units across TCP and UDP
- Rank candidate payloads and run heuristic analysis
- Reconstruct or replay candidate output
- Inspect runs in a local web dashboard

## Quickstart

### Windows

```powershell
.\install_deps.ps1
.\.venv\Scripts\Activate.ps1
python .\videopipeline.py deps
python .\videopipeline.py config
python .\videopipeline.py
```

Run capture and monitor steps from an elevated PowerShell window when possible. The installer will attempt to install Wireshark, Npcap, FFmpeg, and OpenSSH. Use `-SkipSystemPackages`, `-SkipWifiTools`, or `-SkipSshSetup` to opt out.

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

### macOS

```bash
./install_deps.sh
python3 videopipeline.py deps
python3 videopipeline.py config
python3 videopipeline.py
```

## Plug and play remote capture

This is the clean way to get full functionality without depending on Windows monitor mode. Capture on a Pi or Linux laptop, then pull the file to Windows automatically and run the pipeline.

On the capture device:

```bash
sudo tcpdump -i wlan0 -w /tmp/remote_capture.pcapng
```

On Windows:

```powershell
python .\videopipeline.py remote --host pi@raspberrypi --path /tmp/remote_capture.pcapng --run all
```

If you give a directory or pattern, the tool will pull the newest file. For continuous pulls, use `--watch` and `--interval 5`.

## Secure connection setup

Remote pulls use SSH and SCP. The Windows installer will create an SSH key if needed. To add the key to your capture device:

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

Run the quick check script (syntax plus tests):

```powershell
.\scripts\check.ps1
```

```bash
./scripts/check.sh
```

## Commands

| Command | What it does |
|---|---|
| `python videopipeline.py` | Open the guided menu |
| `python videopipeline.py deps` | Check tools and Python packages |
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

- The core analysis pipeline is cross platform.
- Wi Fi lab helpers require external tools like aircrack ng.
- Some reconstruction paths are heuristic and may require tuning in `lab.json`.
