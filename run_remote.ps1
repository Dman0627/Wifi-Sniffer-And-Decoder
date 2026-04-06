<#
.SYNOPSIS
Runs the supported Windows-to-remote capture flow.

.DESCRIPTION
This helper wraps `videopipeline.py start-remote` and can optionally install
dependencies, bootstrap the remote appliance, and run doctor first.

.EXAMPLE
.\run_remote.ps1 -Host pi@raspberrypi -Interface wlan0 -DoctorFirst

.EXAMPLE
.\run_remote.ps1 -InstallDeps -Host pi@raspberrypi -Interface wlan0 -Bootstrap
#>

[CmdletBinding()]
param(
    [Alias("Host")]
    [string]$RemoteHost = "",
    [string]$Interface = "",
    [ValidateRange(1, 86400)]
    [int]$Duration = 60,
    [ValidateSet("none", "extract", "detect", "analyze", "play", "all")]
    [string]$Run = "all",
    [string]$Config = "",
    [string]$Identity = "",
    [ValidateRange(1, 65535)]
    [int]$Port = 22,
    [string]$Output = "",
    [switch]$Bootstrap,
    [switch]$DoctorFirst,
    [switch]$InstallDeps
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $RepoRoot "scripts\common.ps1")

Ensure-RepoInstallDeps -RepoRoot $RepoRoot -InstallDeps:$InstallDeps

if (-not $RemoteHost -and -not $Config) {
    Write-Host "No host was provided on the command line; saved config values will be used if available."
}

if ($DoctorFirst) {
    $doctorArgs = [System.Collections.Generic.List[string]]::new()
    $doctorArgs.Add("doctor")
    Add-ArgumentPair -List $doctorArgs -Name "--host" -Value $RemoteHost
    Add-ArgumentPair -List $doctorArgs -Name "--interface" -Value $Interface
    Add-ArgumentPair -List $doctorArgs -Name "--identity" -Value $Identity
    $doctorArgs.Add("--port")
    $doctorArgs.Add([string]$Port)
    Invoke-RepoPipeline -RepoRoot $RepoRoot -Config $Config -CommandArgs $doctorArgs.ToArray()
}

if ($Bootstrap) {
    $bootstrapArgs = [System.Collections.Generic.List[string]]::new()
    $bootstrapArgs.Add("bootstrap-remote")
    Add-ArgumentPair -List $bootstrapArgs -Name "--host" -Value $RemoteHost
    Add-ArgumentPair -List $bootstrapArgs -Name "--identity" -Value $Identity
    $bootstrapArgs.Add("--port")
    $bootstrapArgs.Add([string]$Port)
    Invoke-RepoPipeline -RepoRoot $RepoRoot -Config $Config -CommandArgs $bootstrapArgs.ToArray()
}

$startArgs = [System.Collections.Generic.List[string]]::new()
$startArgs.Add("start-remote")
Add-ArgumentPair -List $startArgs -Name "--host" -Value $RemoteHost
Add-ArgumentPair -List $startArgs -Name "--interface" -Value $Interface
Add-ArgumentPair -List $startArgs -Name "--identity" -Value $Identity
Add-ArgumentPair -List $startArgs -Name "--output" -Value $Output
$startArgs.Add("--port")
$startArgs.Add([string]$Port)
$startArgs.Add("--duration")
$startArgs.Add([string]$Duration)
$startArgs.Add("--run")
$startArgs.Add($Run)

Invoke-RepoPipeline -RepoRoot $RepoRoot -Config $Config -CommandArgs $startArgs.ToArray()
