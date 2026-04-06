#!/usr/bin/env bash
set -euo pipefail

python3 -m compileall -q wifi_pipeline
python3 -m pytest -q
