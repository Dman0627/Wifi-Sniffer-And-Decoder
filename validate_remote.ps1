<#
.SYNOPSIS
Validates the supported Windows + remote capture workflow.

.DESCRIPTION
This helper wraps `videopipeline.py validate-remote` and can optionally run the
dependency installer first. By default it performs a short smoke capture.

.EXAMPLE
.\validate_remote.ps1 -Host pi@raspberrypi -Interface wlan0

.EXAMPLE
.\validate_remote.ps1 -InstallDeps -Host pi@raspberrypi -Interface wlan0 -SkipSmoke
#>

[CmdletBinding()]
param(
    [Alias("Host")]
    [string]$RemoteHost = "",
    [string]$Interface = "",
    [ValidateRange(1, 3600)]
    [int]$Duration = 15,
    [string]$Config = "",
    [string]$Identity = "",
    [ValidateRange(1, 65535)]
    [int]$Port = 22,
    [string]$Dest = "",
    [string]$Report = "",
    [switch]$SkipSmoke,
    [switch]$InstallDeps
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $RepoRoot "scripts\common.ps1")

Ensure-RepoInstallDeps -RepoRoot $RepoRoot -InstallDeps:$InstallDeps

$argsList = [System.Collections.Generic.List[string]]::new()
$argsList.Add("validate-remote")
Add-ArgumentPair -List $argsList -Name "--host" -Value $RemoteHost
Add-ArgumentPair -List $argsList -Name "--interface" -Value $Interface
Add-ArgumentPair -List $argsList -Name "--identity" -Value $Identity
Add-ArgumentPair -List $argsList -Name "--dest" -Value $Dest
Add-ArgumentPair -List $argsList -Name "--report" -Value $Report
$argsList.Add("--port")
$argsList.Add([string]$Port)
$argsList.Add("--duration")
$argsList.Add([string]$Duration)
if ($SkipSmoke) {
    $argsList.Add("--skip-smoke")
}

Invoke-RepoPipeline -RepoRoot $RepoRoot -Config $Config -CommandArgs $argsList.ToArray()
