[CmdletBinding()]
param(
    [Alias("Host")]
    [string]$RemoteHost = "",
    [string]$Interface = "",
    [int]$Duration = 15,
    [string]$Config = "",
    [string]$Identity = "",
    [int]$Port = 22,
    [string]$Dest = "",
    [string]$Report = "",
    [switch]$SkipSmoke,
    [switch]$InstallDeps
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallScript = Join-Path $RepoRoot "install_deps.ps1"
$ScriptPath = Join-Path $RepoRoot "videopipeline.py"
$PythonExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"

if ($InstallDeps -or -not (Test-Path $PythonExe)) {
    if (-not (Test-Path $InstallScript)) {
        throw "install_deps.ps1 was not found."
    }
    Write-Host ""
    Write-Host ("> powershell -ExecutionPolicy Bypass -File {0}" -f $InstallScript)
    powershell -ExecutionPolicy Bypass -File $InstallScript
    if ($LASTEXITCODE -ne 0) {
        throw ("install_deps.ps1 failed with exit code {0}" -f $LASTEXITCODE)
    }
}

if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

$argsList = @()
if ($Config) {
    $argsList += @("--config", $Config)
}
$argsList += @("validate-remote")
if ($RemoteHost) {
    $argsList += @("--host", $RemoteHost)
}
if ($Interface) {
    $argsList += @("--interface", $Interface)
}
if ($Identity) {
    $argsList += @("--identity", $Identity)
}
if ($Dest) {
    $argsList += @("--dest", $Dest)
}
if ($Report) {
    $argsList += @("--report", $Report)
}
if ($Port -gt 0) {
    $argsList += @("--port", [string]$Port)
}
if ($Duration -gt 0) {
    $argsList += @("--duration", [string]$Duration)
}
if ($SkipSmoke) {
    $argsList += "--skip-smoke"
}

Write-Host ""
Write-Host ("> {0} {1} {2}" -f $PythonExe, $ScriptPath, ($argsList -join " "))
& $PythonExe $ScriptPath @argsList
exit $LASTEXITCODE
