param(
    [switch]$InstallWingetPackages
)

$ErrorActionPreference = "Stop"

Write-Host "Setting up Wifi-Sniffer-And-Decoder for native Windows..."
Write-Host ""
Write-Host "This repository now assumes:"
Write-Host "  - Native Windows Python"
Write-Host "  - Wireshark/NPcap tools on PATH"
Write-Host "  - FFmpeg/ffplay on PATH"
Write-Host ""

if (-not (Get-Command py.exe -ErrorAction SilentlyContinue)) {
    Write-Host "py.exe was not found. Install Python 3.12+ for Windows first."
    exit 1
}

if ($InstallWingetPackages) {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        Write-Host "winget was not found, so automatic tool installation is unavailable."
        exit 1
    }

    Write-Host "Installing Wireshark and FFmpeg via winget..."
    winget install --id WiresharkFoundation.Wireshark -e --accept-source-agreements --accept-package-agreements
    winget install --id Gyan.FFmpeg -e --accept-source-agreements --accept-package-agreements
    Write-Host ""
    Write-Host "airdecap-ng is still optional and must be installed separately if you want Wi-Fi layer stripping."
    Write-Host "Install the Windows aircrack-ng bundle and add it to PATH."
    Write-Host ""
}

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPath = Join-Path $RepoRoot ".venv"
$PythonExe = Join-Path $VenvPath "Scripts\python.exe"

if (-not (Test-Path $VenvPath)) {
    Write-Host "Creating virtual environment at $VenvPath"
    py -3.13 -m venv $VenvPath
}

Write-Host "Installing Python dependencies..."
& $PythonExe -m pip install --upgrade pip
& $PythonExe -m pip install -r (Join-Path $RepoRoot "requirements.txt")

Write-Host ""
Write-Host "Checking native tools on PATH..."
$ToolChecks = @(
    @{ Name = "dumpcap"; Required = $true; Help = "Install Wireshark with NPcap" },
    @{ Name = "tshark"; Required = $true; Help = "Install Wireshark with NPcap" },
    @{ Name = "ffplay"; Required = $false; Help = "Install FFmpeg" },
    @{ Name = "airdecap-ng"; Required = $false; Help = "Install aircrack-ng for Windows if needed" }
)

foreach ($Tool in $ToolChecks) {
    $Cmd = Get-Command $Tool.Name -ErrorAction SilentlyContinue
    if ($Cmd) {
        Write-Host ("  [ok] {0} -> {1}" -f $Tool.Name, $Cmd.Source)
    }
    elseif ($Tool.Required) {
        Write-Host ("  [missing] {0} ({1})" -f $Tool.Name, $Tool.Help)
    }
    else {
        Write-Host ("  [optional] {0} ({1})" -f $Tool.Name, $Tool.Help)
    }
}

Write-Host ""
Write-Host "Next steps:"
Write-Host ("  1. Activate the virtual environment:")
Write-Host ("     {0}" -f (Join-Path $VenvPath "Scripts\Activate.ps1"))
Write-Host ("  2. Configure the pipeline:")
Write-Host ("     python .\videopipeline.py config")
Write-Host ("  3. Check the environment:")
Write-Host ("     python .\videopipeline.py deps")
Write-Host ("  4. Run a stage or the full flow:")
Write-Host ("     python .\videopipeline.py capture")
Write-Host ("     python .\videopipeline.py extract --pcap .\pipeline_output\raw_capture.pcapng")
Write-Host ("     python .\videopipeline.py all")
