# Validation Matrix

This directory is the real-hardware release gate.

Expected reports:

- `ubuntu_standalone_validation.json`
- `pi_standalone_validation.json`
- `windows_remote_validation.json`
- one or more supported sample analysis reports, for example:
  - `sample_text_analysis.json`
  - `sample_image_analysis.json`
  - `sample_video_analysis.json`

Recommended collection flow:

```bash
./validate_local.sh --interface wlan0 --report validation_matrix/ubuntu_standalone_validation.json
./validate_local.sh --interface wlan0 --report validation_matrix/pi_standalone_validation.json
```

```powershell
.\validate_remote.ps1 -Host pi@raspberrypi -Interface wlan0 -Report .\validation_matrix\windows_remote_validation.json
```

Then copy one or more analysis reports from supported decode/replay sample runs into this directory and run:

```bash
python scripts/release_gate.py \
  --ubuntu-report validation_matrix/ubuntu_standalone_validation.json \
  --pi-report validation_matrix/pi_standalone_validation.json \
  --windows-report validation_matrix/windows_remote_validation.json \
  --sample-report validation_matrix/sample_text_analysis.json \
  --sample-report validation_matrix/sample_video_analysis.json
```

The release is only `fully validated` when that command exits successfully.

The validation reports are expected to carry the capability-driven evidence that the CLI now emits:

- local and remote validation reports should include `capability_report` and `status_bundle`
- standalone validation reports should also include replay-confidence data from the smoke analysis path
- sample analysis reports should include `selected_replay_confidence` and the selected stream's candidate metadata

Tips:

- Use clear sample names like `sample_text_analysis.json` or `sample_video_analysis.json`
- Keep only real hardware validation artifacts here; simulated test fixtures belong in `tests/`
- The release workflow uses this directory directly, so missing files here will intentionally block tagged releases
