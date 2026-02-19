param (
    # Optional: Path to a local Sysmon XML config file. Skips config download if provided.
    [string]$ConfigPath,

    # Optional: Directory where Sysmon binaries are placed.
    [string]$InstallDir = "C:\Sysmon"
)

# PowerShell script to install and configure Sysmon with Olaf Hartong's sysmon-modular config.
# Falls back to SwiftOnSecurity if the primary config is unavailable.
# Provide -ConfigPath to skip the download entirely and use your own XML.
#
# Samuel Brucker 2024 - 2026

$ErrorActionPreference = "Stop"

# -- Variables ----------------------------------------------------------------
$SysmonZipUrl    = "https://download.sysinternals.com/files/Sysmon.zip"
$SysmonZipPath   = Join-Path $InstallDir "Sysmon.zip"
$SysmonExe       = Join-Path $InstallDir "Sysmon64.exe"
$DefaultConfig   = Join-Path $InstallDir "sysmonconfig.xml"

$PrimaryConfigUrl  = "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml"
$FallbackConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"

# -- 1. Admin check -----------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] This script must be run as Administrator." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Running as Administrator." -ForegroundColor Green

# -- 2. Create install directory -----------------------------------------------
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Host "[OK] Created install directory: $InstallDir" -ForegroundColor Green
} else {
    Write-Host "[OK] Install directory exists: $InstallDir" -ForegroundColor Green
}

# -- 3. Download Sysmon --------------------------------------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

if (Test-Path $SysmonExe) {
    Write-Host "[OK] Sysmon64.exe already present at $SysmonExe" -ForegroundColor Green
} else {
    Write-Host "Downloading Sysmon from $SysmonZipUrl ..."
    try {
        Invoke-WebRequest -Uri $SysmonZipUrl -OutFile $SysmonZipPath -UseBasicParsing
    } catch {
        Write-Host "[ERROR] Failed to download Sysmon: $_" -ForegroundColor Red
        exit 1
    }

    Write-Host "Extracting Sysmon.zip ..."
    try {
        Expand-Archive -Path $SysmonZipPath -DestinationPath $InstallDir -Force
    } catch {
        Write-Host "[ERROR] Failed to extract Sysmon.zip: $_" -ForegroundColor Red
        exit 1
    }
    Remove-Item $SysmonZipPath -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $SysmonExe)) {
        Write-Host "[ERROR] Sysmon64.exe not found after extraction. Check $InstallDir contents." -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] Sysmon64.exe extracted to $InstallDir" -ForegroundColor Green
}

# -- 4. Download config --------------------------------------------------------
$ActiveConfig = ""

if ($ConfigPath) {
    if (-not (Test-Path $ConfigPath)) {
        Write-Host "[ERROR] Specified config not found: $ConfigPath" -ForegroundColor Red
        exit 1
    }
    $ActiveConfig = $ConfigPath
    Write-Host "[OK] Using provided config: $ActiveConfig" -ForegroundColor Green
} else {
    # Primary: Olaf Hartong sysmon-modular
    Write-Host "Downloading Olaf Hartong sysmon-modular config ..."
    try {
        Invoke-WebRequest -Uri $PrimaryConfigUrl -OutFile $DefaultConfig -UseBasicParsing
        $ActiveConfig = $DefaultConfig
        Write-Host "[OK] sysmon-modular config downloaded to $ActiveConfig" -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Failed to download sysmon-modular config: $_" -ForegroundColor Yellow
        # Fallback: SwiftOnSecurity
        Write-Host "Downloading SwiftOnSecurity fallback config ..."
        try {
            Invoke-WebRequest -Uri $FallbackConfigUrl -OutFile $DefaultConfig -UseBasicParsing
            $ActiveConfig = $DefaultConfig
            Write-Host "[OK] SwiftOnSecurity config downloaded to $ActiveConfig" -ForegroundColor Green
        } catch {
            Write-Host "[ERROR] Failed to download any config. Provide one with -ConfigPath." -ForegroundColor Red
            exit 1
        }
    }
}

# -- 5. Accept EULA ------------------------------------------------------------
Write-Host "Accepting Sysinternals EULA via registry ..."
$eulaKey = "HKCU:\Software\Sysinternals\Sysmon64"
if (-not (Test-Path $eulaKey)) {
    New-Item -Path $eulaKey -Force | Out-Null
}
Set-ItemProperty -Path $eulaKey -Name "EulaAccepted" -Value 1 -Type DWord
Write-Host "[OK] EULA accepted." -ForegroundColor Green

# -- 6. Install or update ------------------------------------------------------
$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

if ($svc) {
    Write-Host "Sysmon64 service exists - updating configuration ..."
    $ErrorActionPreference = "Continue"
    & $SysmonExe -c $ActiveConfig 2>&1 | ForEach-Object { Write-Host "    $_" }
    $sysmonExit = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    if ($sysmonExit -ne 0) {
        Write-Host "[ERROR] Sysmon config update returned exit code $sysmonExit" -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] Sysmon configuration updated." -ForegroundColor Green
} else {
    Write-Host "Installing Sysmon64 ..."
    $ErrorActionPreference = "Continue"
    & $SysmonExe -accepteula -i $ActiveConfig 2>&1 | ForEach-Object { Write-Host "    $_" }
    $sysmonExit = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    if ($sysmonExit -ne 0) {
        Write-Host "[ERROR] Sysmon installation returned exit code $sysmonExit" -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] Sysmon installed successfully." -ForegroundColor Green
}

# -- 7. Verify -----------------------------------------------------------------
Write-Host "Verifying Sysmon service ..."
$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne "Running") {
    Write-Host "[ERROR] Sysmon64 service is not running!" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Sysmon64 service is running." -ForegroundColor Green

Start-Sleep -Seconds 2
try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 -ErrorAction Stop
    Write-Host "[OK] Found $($events.Count) recent Sysmon event(s) in the log." -ForegroundColor Green
} catch {
    Write-Host "[WARN] No Sysmon events found yet (may take a moment): $_" -ForegroundColor Yellow
}

# -- 8. Restart Splunk UF (if installed) ----------------------------------------
# The Splunk UF must be restarted after Sysmon is installed so it picks up the
# new Microsoft-Windows-Sysmon/Operational event log channel.
$splunkSvc = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
if ($splunkSvc) {
    Write-Host "Restarting Splunk Universal Forwarder to pick up Sysmon event log ..."
    Restart-Service SplunkForwarder -Force
    Start-Sleep -Seconds 3
    $splunkSvc = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
    if ($splunkSvc.Status -eq "Running") {
        Write-Host "[OK] SplunkForwarder restarted - Sysmon events will begin forwarding." -ForegroundColor Green
    } else {
        Write-Host "[WARN] SplunkForwarder is not running after restart." -ForegroundColor Yellow
    }
} else {
    Write-Host "[INFO] Splunk Universal Forwarder not installed - skip UF restart." -ForegroundColor Yellow
}

# -- 9. Summary ----------------------------------------------------------------
Write-Host ""
Write-Host "=== Sysmon Installation Summary ===" -ForegroundColor Cyan
Write-Host "  Binary:  $SysmonExe"
Write-Host "  Config:  $ActiveConfig"
Write-Host "  Service: $($svc.Status)"
Write-Host "  Log:     Microsoft-Windows-Sysmon/Operational"
Write-Host "===================================" -ForegroundColor Cyan
