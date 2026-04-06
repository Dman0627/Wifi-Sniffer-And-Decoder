Set-StrictMode -Version Latest

function Format-DisplayArgument {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ($Value -match "[\s`"]") {
        return '"' + $Value.Replace('"', '\"') + '"'
    }
    return $Value
}

function Resolve-RepoPythonExe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $venvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) {
        return $venvPython
    }
    return "python"
}

function Add-ArgumentPair {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$List,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string]$Value
    )

    if ($Value) {
        $List.Add($Name)
        $List.Add($Value)
    }
}

function Ensure-RepoInstallDeps {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,
        [switch]$InstallDeps
    )

    $venvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
    if (-not $InstallDeps -and (Test-Path $venvPython)) {
        return
    }

    $installScript = Join-Path $RepoRoot "install_deps.ps1"
    if (-not (Test-Path $installScript)) {
        throw "install_deps.ps1 was not found."
    }

    Write-Host ""
    Write-Host ("> powershell -NoProfile -ExecutionPolicy Bypass -File {0}" -f $installScript)
    & powershell -NoProfile -ExecutionPolicy Bypass -File $installScript
    if ($LASTEXITCODE -ne 0) {
        throw ("install_deps.ps1 failed with exit code {0}" -f $LASTEXITCODE)
    }
}

function Invoke-RepoPipeline {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,
        [string]$Config = "",
        [Parameter(Mandatory = $true)]
        [string[]]$CommandArgs
    )

    $scriptPath = Join-Path $RepoRoot "videopipeline.py"
    if (-not (Test-Path $scriptPath)) {
        throw "videopipeline.py was not found."
    }

    $pythonExe = Resolve-RepoPythonExe -RepoRoot $RepoRoot
    $argsList = @()
    if ($Config) {
        $argsList += @("--config", $Config)
    }
    $argsList += $CommandArgs

    $displayArgs = $argsList | ForEach-Object { Format-DisplayArgument -Value $_ }
    Write-Host ""
    Write-Host ("> {0} {1} {2}" -f (Format-DisplayArgument -Value $pythonExe), (Format-DisplayArgument -Value $scriptPath), ($displayArgs -join " "))
    & $pythonExe $scriptPath @argsList
    if ($LASTEXITCODE -ne 0) {
        throw ("Command failed with exit code {0}" -f $LASTEXITCODE)
    }
}
