param(
    [switch]$NoCompile
)

$ErrorActionPreference = "Stop"

if (-not $NoCompile) {
    python -m compileall -q wifi_pipeline
}

python -m pytest -q
