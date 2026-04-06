<#
.SYNOPSIS
Runs the first-run setup flow for the supported remote capture path.

.DESCRIPTION
This helper wraps `videopipeline.py setup-remote` and can optionally run the
Windows dependency installer before launching the guided setup flow.

.EXAMPLE
.\setup_remote.ps1 -InstallDeps

.EXAMPLE
.\setup_remote.ps1 -Host pi@raspberrypi -Interface wlan0 -SmokeTest
#>

[CmdletBinding()]
param(
    [Alias("Host")]
    [string]$RemoteHost = "",
    [string]$Interface = "",
    [ValidateRange(1, 86400)]
    [int]$Duration = 60,
    [string]$Config = "",
    [string]$Identity = "",
    [ValidateRange(1, 65535)]
    [int]$Port = 22,
    [string]$Dest = "",
    [switch]$SmokeTest,
    [switch]$InstallDeps
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $RepoRoot "scripts\common.ps1")

Ensure-RepoInstallDeps -RepoRoot $RepoRoot -InstallDeps:$InstallDeps

$argsList = [System.Collections.Generic.List[string]]::new()
$argsList.Add("setup-remote")
Add-ArgumentPair -List $argsList -Name "--host" -Value $RemoteHost
Add-ArgumentPair -List $argsList -Name "--interface" -Value $Interface
Add-ArgumentPair -List $argsList -Name "--identity" -Value $Identity
Add-ArgumentPair -List $argsList -Name "--dest" -Value $Dest
$argsList.Add("--port")
$argsList.Add([string]$Port)
$argsList.Add("--duration")
$argsList.Add([string]$Duration)
if ($SmokeTest) {
    $argsList.Add("--smoke-test")
}

Invoke-RepoPipeline -RepoRoot $RepoRoot -Config $Config -CommandArgs $argsList.ToArray()
