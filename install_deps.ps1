param(
    [switch]$InstallWingetPackages,
    [switch]$SkipSystemPackages,
    [switch]$SkipWifiTools,
    [switch]$SkipPythonInstall,
    [switch]$SkipSshSetup
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Write-Host "Setting up Wifi-Sniffer-And-Decoder for the supported Windows controller workflow..."
Write-Host ""
Write-Host "Official support target:"
Write-Host "  - Windows 10/11 as the controller and analysis machine"
Write-Host "  - Raspberry Pi OS or Ubuntu as the remote capture device"
Write-Host ""
Write-Host "This setup assumes:"
Write-Host "  - Native Windows Python"
Write-Host "  - Wireshark/NPcap tools on PATH"
Write-Host "  - FFmpeg/ffplay on PATH"
Write-Host "  - OpenSSH client for remote capture control"
Write-Host ""
Write-Host "The Windows helper scripts resolve the repo root automatically, so you can run them from any PowerShell location."
Write-Host ""
Write-Host "Explicit limits:"
Write-Host "  - This repo does not make Windows monitor mode adapter-independent"
Write-Host "  - The supported production path is remote capture on Raspberry Pi OS or Ubuntu"
Write-Host "  - Replay and decoding remain heuristic and are not guaranteed"
Write-Host ""

function Install-WingetPackage {
    param(
        [string]$Name,
        [string[]]$Ids,
        [bool]$Required = $false
    )
    foreach ($Id in $Ids) {
        Write-Host ("  - Trying {0} ({1})..." -f $Name, $Id)
        winget install --id $Id -e --accept-source-agreements --accept-package-agreements | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host ("  [ok] {0} installed via {1}" -f $Name, $Id)
            return $true
        }
    }
    if ($Required) {
        Write-Host ("  [missing] {0} (install manually if winget package not found)" -f $Name)
    } else {
        Write-Host ("  [optional] {0} (install manually if needed)" -f $Name)
    }
    return $false
}

function Ensure-OpenSSHClient {
    if (Get-Command ssh.exe -ErrorAction SilentlyContinue) {
        return $true
    }
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        Write-Host "OpenSSH client not found. Install Windows OpenSSH Client or enable it in Optional Features."
        return $false
    }
    Write-Host "OpenSSH client not found. Attempting install via winget..."
    $installed = Install-WingetPackage -Name "OpenSSH Client" -Ids @(
        "Microsoft.OpenSSH.Beta",
        "Microsoft.OpenSSH"
    ) -Required $false
    if ($installed -and (Get-Command ssh.exe -ErrorAction SilentlyContinue)) {
        return $true
    }
    Write-Host "OpenSSH client is still missing. Enable OpenSSH Client in Windows Optional Features."
    return $false
}

function Ensure-SshKey {
    if ($SkipSshSetup) {
        return
    }
    if (-not (Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue)) {
        Write-Host "ssh-keygen not found. Install OpenSSH Client to enable secure remote capture."
        return
    }
    $sshDir = Join-Path $env:USERPROFILE ".ssh"
    $keyPath = Join-Path $sshDir "id_ed25519"
    if (-not (Test-Path $keyPath)) {
        if (-not (Test-Path $sshDir)) {
            New-Item -ItemType Directory -Path $sshDir | Out-Null
        }
        Write-Host "Generating SSH key for secure remote capture..."
        ssh-keygen -t ed25519 -f $keyPath -N "" | Out-Null
        Write-Host ("  Public key: {0}" -f (Join-Path $sshDir "id_ed25519.pub"))
    }
}

$InstallSystemPackages = -not $SkipSystemPackages
if ($InstallWingetPackages) {
    $InstallSystemPackages = $true
}
$InstallWifiPackages = -not $SkipWifiTools

if (-not (Get-Command py.exe -ErrorAction SilentlyContinue)) {
    if ($InstallSystemPackages -and -not $SkipPythonInstall -and (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        Write-Host "Python not found. Attempting install via winget..."
        $installed = Install-WingetPackage -Name "Python" -Ids @(
            "Python.Python.3.13",
            "Python.Python.3.12"
        ) -Required $true
        if ($installed) {
            Write-Host "Python install completed. Please restart PowerShell and re-run this script."
            exit 0
        }
    }
    Write-Host "py.exe was not found. Install Python 3.12+ for Windows first."
    exit 1
}

if ($InstallSystemPackages) {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        Write-Host "winget was not found, so automatic tool installation is unavailable."
        Write-Host "Install Wireshark/NPcap and FFmpeg manually, then re-run this script."
    } else {
        Write-Host "Installing system tools via winget..."
        Install-WingetPackage -Name "Wireshark" -Ids @("WiresharkFoundation.Wireshark") -Required $true
        Install-WingetPackage -Name "Npcap" -Ids @("Npcap.Npcap") -Required $true
        Install-WingetPackage -Name "FFmpeg" -Ids @("Gyan.FFmpeg", "BtbN.FFmpeg") -Required $false

        if ($InstallWifiPackages) {
            Write-Host ""
            Write-Host "Installing optional Wi-Fi lab tools (best effort)..."
            Install-WingetPackage -Name "aircrack-ng" -Ids @("aircrack-ng.aircrack-ng", "Aircrack-ng") -Required $false
            Install-WingetPackage -Name "hashcat" -Ids @("hashcat.hashcat", "Hashcat") -Required $false
        }
        Write-Host ""
    }
}

if (-not $SkipSshSetup) {
    if (Ensure-OpenSSHClient) {
        Ensure-SshKey
    }
}

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPath = Join-Path $RepoRoot ".venv"
$PythonExe = Join-Path $VenvPath "Scripts\python.exe"

if (-not (Test-Path $VenvPath)) {
    Write-Host "Creating virtual environment at $VenvPath"
    py -3 -m venv $VenvPath
}

Write-Host "Installing Python dependencies..."
& $PythonExe -m pip install --upgrade pip
& $PythonExe -m pip install -r (Join-Path $RepoRoot "requirements.txt")

Write-Host ""
Write-Host "Checking native tools on PATH..."
$ToolChecks = @(
    @{ Name = "dumpcap"; Required = $true; Help = "Install Wireshark with NPcap" },
    @{ Name = "tshark"; Required = $true; Help = "Install Wireshark with NPcap" },
    @{ Name = "WlanHelper"; Required = $false; Help = "Install NPcap (WlanHelper.exe)" },
    @{ Name = "ffplay"; Required = $false; Help = "Install FFmpeg" },
    @{ Name = "ssh"; Required = $false; Help = "Install OpenSSH Client for remote capture" },
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
Write-Host ("  Preferred workflow:")
Write-Host ("     Windows controller -> Raspberry Pi OS / Ubuntu capture device")
Write-Host ("  1. Activate the virtual environment:")
Write-Host ("     {0}" -f (Join-Path $VenvPath "Scripts\Activate.ps1"))
Write-Host ("  2. Configure the pipeline:")
Write-Host ("     python .\videopipeline.py config")
Write-Host ("  3. Check the environment:")
Write-Host ("     python .\videopipeline.py deps")
Write-Host ("  4. Pair a Raspberry Pi or Linux laptop for remote pulls:")
Write-Host ("     python .\videopipeline.py pair-remote --host pi@raspberrypi")
Write-Host ("  5. Bootstrap the remote capture helper:")
Write-Host ("     python .\videopipeline.py bootstrap-remote --host pi@raspberrypi")
Write-Host ("     (This also tries to install the no-prompt privileged capture runner on the remote side.)")
Write-Host ("  6. Or use the Windows first-run wizard:")
Write-Host ("     .\setup_remote.ps1")
Write-Host ("     .\setup_remote.ps1 -InstallDeps -SmokeTest")
Write-Host ("  7. Run a remote capture end-to-end:")
Write-Host ("     python .\videopipeline.py start-remote --host pi@raspberrypi --interface wlan0 --duration 60 --run all")
Write-Host ("  8. Check the remote appliance service:")
Write-Host ("     python .\videopipeline.py remote-service status --host pi@raspberrypi")
Write-Host ("     (The managed service records state, completion markers, and SHA-256 metadata for remote captures.)")
Write-Host ("  9. Diagnose the full setup:")
Write-Host ("     python .\videopipeline.py doctor --host pi@raspberrypi --interface wlan0")
Write-Host ("  10. Run the supported hardware validation:")
Write-Host ("     .\validate_remote.ps1 -Host pi@raspberrypi -Interface wlan0")
Write-Host ("  11. Use the Windows shortcut helper:")
Write-Host ("     .\run_remote.ps1 -Host pi@raspberrypi -Interface wlan0 -Duration 60")
Write-Host ("  12. Run local checks:")
Write-Host ("     .\scripts\check.ps1")
Write-Host ("  13. Experimental local-only paths:")
Write-Host ("     python .\videopipeline.py capture")
Write-Host ("     python .\videopipeline.py extract --pcap .\pipeline_output\raw_capture.pcapng")
Write-Host ("     python .\videopipeline.py all")
Write-Host ("     (Use these for experimentation, not as the primary supported product path.)")
