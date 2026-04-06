#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON_BIN="$REPO_ROOT/.venv/bin/python"
NO_COMPILE=0

for arg in "$@"; do
    case "$arg" in
        --no-compile) NO_COMPILE=1 ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

if [[ ! -x "$PYTHON_BIN" ]]; then
    PYTHON_BIN="${PYTHON:-python3}"
fi

cd "$REPO_ROOT"

if [[ "$NO_COMPILE" -eq 0 ]]; then
    "$PYTHON_BIN" -m compileall -q wifi_pipeline
fi

"$PYTHON_BIN" -m pytest -q
