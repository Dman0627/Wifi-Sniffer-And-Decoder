[CmdletBinding()]
param(
    [Alias("Host")]
    [string]$RemoteHost = "",
    [string]$Interface = "",
    [int]$Duration = 60,
    [ValidateSet("none", "extract", "detect", "analyze", "play", "all")]
    [string]$Run = "all",
    [string]$Config = "",
    [string]$Identity = "",
    [int]$Port = 22,
    [string]$Output = "",
    [switch]$Bootstrap,
    [switch]$DoctorFirst
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptPath = Join-Path $RepoRoot "videopipeline.py"
$PythonExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

function Invoke-PipelineCommand {
    param(
        [string[]]$CommandArgs
    )

    $argsList = @()
    if ($Config) {
        $argsList += @("--config", $Config)
    }
    $argsList += $CommandArgs

    Write-Host ""
    Write-Host ("> {0} {1} {2}" -f $PythonExe, $ScriptPath, ($argsList -join " "))
    & $PythonExe $ScriptPath @argsList
    if ($LASTEXITCODE -ne 0) {
        throw ("Command failed with exit code {0}" -f $LASTEXITCODE)
    }
}

function Add-OptionalArgument {
    param(
        [System.Collections.Generic.List[string]]$List,
        [string]$Name,
        [string]$Value
    )

    if ($Value) {
        $List.Add($Name)
        $List.Add($Value)
    }
}

if ($DoctorFirst) {
    $doctorArgs = [System.Collections.Generic.List[string]]::new()
    $doctorArgs.Add("doctor")
    Add-OptionalArgument -List $doctorArgs -Name "--host" -Value $RemoteHost
    Add-OptionalArgument -List $doctorArgs -Name "--interface" -Value $Interface
    Add-OptionalArgument -List $doctorArgs -Name "--identity" -Value $Identity
    if ($Port -gt 0) {
        $doctorArgs.Add("--port")
        $doctorArgs.Add([string]$Port)
    }
    Invoke-PipelineCommand -CommandArgs $doctorArgs.ToArray()
}

if ($Bootstrap) {
    $bootstrapArgs = [System.Collections.Generic.List[string]]::new()
    $bootstrapArgs.Add("bootstrap-remote")
    Add-OptionalArgument -List $bootstrapArgs -Name "--host" -Value $RemoteHost
    Add-OptionalArgument -List $bootstrapArgs -Name "--identity" -Value $Identity
    if ($Port -gt 0) {
        $bootstrapArgs.Add("--port")
        $bootstrapArgs.Add([string]$Port)
    }
    Invoke-PipelineCommand -CommandArgs $bootstrapArgs.ToArray()
}

$startArgs = [System.Collections.Generic.List[string]]::new()
$startArgs.Add("start-remote")
Add-OptionalArgument -List $startArgs -Name "--host" -Value $RemoteHost
Add-OptionalArgument -List $startArgs -Name "--interface" -Value $Interface
Add-OptionalArgument -List $startArgs -Name "--identity" -Value $Identity
Add-OptionalArgument -List $startArgs -Name "--output" -Value $Output
if ($Port -gt 0) {
    $startArgs.Add("--port")
    $startArgs.Add([string]$Port)
}
$startArgs.Add("--duration")
$startArgs.Add([string]$Duration)
$startArgs.Add("--run")
$startArgs.Add($Run)

Invoke-PipelineCommand -CommandArgs $startArgs.ToArray()
