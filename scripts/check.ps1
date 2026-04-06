param(
    [switch]$NoCompile
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$PythonExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

if (-not $NoCompile) {
    & $PythonExe -m compileall -q (Join-Path $RepoRoot "wifi_pipeline")
}

Push-Location $RepoRoot
try {
    & $PythonExe -m pytest -q
}
finally {
    Pop-Location
}
