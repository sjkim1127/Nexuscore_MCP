<#
.SYNOPSIS
    NexusCore MCP Analysis Environment Setup Script (All-in-One)
    
.DESCRIPTION
    Automates the setup of a malware analysis environment on Windows.
    1. Installs Chocolatey (Package Manager).
    2. Installs base dependencies (Git, Python, Rust, LLVM, etc.).
    3. Downloads and configures specific analysis tools (DIE, Capa, PE-Sieve, Sysmon).
    4. Sets up PATH environment variables.

.NOTES
    Run as Administrator.
#>

$ErrorActionPreference = "Stop"
$toolsDir = Join-Path $PSScriptRoot "..\bin" # Target directory for tools

# Ensure tools directory exists
if (-not (Test-Path $toolsDir)) {
    New-Item -ItemType Directory -Path $toolsDir | Out-Null
    Write-Host "[+] Created tools directory: $toolsDir" -ForegroundColor Green
}

# 1. Install Chocolatey
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "[*] Installing Chocolatey..." -ForegroundColor Cyan
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}
else {
    Write-Host "[+] Chocolatey is already installed." -ForegroundColor Green
}

# 2. Install Base Utilities & Development Tools via Chocolatey
Write-Host "[*] Installing base utilities & Dev Tools..." -ForegroundColor Cyan
choco install -y git python 7zip.install wireshark rust visualcpp-build-tools llvm

# Set LIBCLANG_PATH for frida-sys
$llvmPath = "C:\Program Files\LLVM\bin"
if (Test-Path $llvmPath) {
    [Environment]::SetEnvironmentVariable("LIBCLANG_PATH", $llvmPath, "Machine")
    Write-Host "[+] Set LIBCLANG_PATH to $llvmPath" -ForegroundColor Green
}

# 3. Download & Install Analysis Tools function
function Install-AnalysisTool {
    param (
        [string]$Url,
        [string]$ZipName,
        [string]$DestName
    )
    $zipPath = Join-Path $toolsDir $ZipName
    $extractPath = Join-Path $toolsDir $DestName

    if (-not (Test-Path $extractPath)) {
        Write-Host "[*] Downloading $DestName..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $Url -OutFile $zipPath
        
        Write-Host "[*] Extracting $DestName..." -ForegroundColor Yellow
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
        Remove-Item $zipPath -Force
        Write-Host "[+] Installed $DestName" -ForegroundColor Green
    }
    else {
        Write-Host "[+] $DestName already exists." -ForegroundColor Green
    }
    return $extractPath
}

# --- Sysinternals Suite ---
Install-AnalysisTool "https://download.sysinternals.com/files/SysinternalsSuite.zip" "Sysinternals.zip" "Sysinternals"

# --- Detect It Easy (DIE) ---
$dieUrl = "https://github.com/horsicq/DIE-engine/releases/download/3.09/die_win64_portable_3.09.zip"
Install-AnalysisTool $dieUrl "die.zip" "DetectItEasy"

# --- Mandiant Capa ---
$capaUrl = "https://github.com/mandiant/capa/releases/download/v7.0.1/capa-v7.0.1-windows.zip"
Install-AnalysisTool $capaUrl "capa.zip" "Capa"

# --- Mandiant Floss ---
$flossUrl = "https://github.com/mandiant/flare-floss/releases/download/v3.0.1/floss-v3.0.1-windows.zip"
Install-AnalysisTool $flossUrl "floss.zip" "Floss"

# --- PE-Sieve (Injection Detection) ---
$pesieveUrl = "https://github.com/hasherezade/pe-sieve/releases/download/v0.3.9/pe-sieve64.zip"
Install-AnalysisTool $pesieveUrl "pesieve.zip" "PE-Sieve"

# --- Sysmon (Windows Event Logging) ---
Write-Host "[*] Checking Sysmon..." -ForegroundColor Cyan
$sysmonExe = Join-Path $toolsDir "Sysinternals\Sysmon64.exe"
if (Test-Path $sysmonExe) {
    # Check if Sysmon service is installed
    $sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $sysmonService) {
        Write-Host "[*] Installing Sysmon with default config..." -ForegroundColor Yellow
        # Download default config
        $configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
        $configPath = Join-Path $toolsDir "sysmon-config.xml"
        Invoke-WebRequest -Uri $configUrl -OutFile $configPath
        
        # Install Sysmon
        Start-Process -FilePath $sysmonExe -ArgumentList "-accepteula -i $configPath" -Wait -NoNewWindow
        Write-Host "[+] Sysmon installed and running." -ForegroundColor Green
    }
    else {
        Write-Host "[+] Sysmon is already installed." -ForegroundColor Green
    }
}
else {
    Write-Host "[!] Sysmon64.exe not found in Sysinternals folder." -ForegroundColor Red
}

# 4. Update PATH
$envPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$newPaths = @(
    (Join-Path $toolsDir "Sysinternals"),
    (Join-Path $toolsDir "DetectItEasy"),
    (Join-Path $toolsDir "Capa"),
    (Join-Path $toolsDir "Floss"),
    (Join-Path $toolsDir "PE-Sieve")
)

foreach ($p in $newPaths) {
    if ($envPath -notlike "*$p*") {
        Write-Host "[*] Adding to PATH: $p" -ForegroundColor Cyan
        [Environment]::SetEnvironmentVariable("Path", "$envPath;$p", "Machine")
        $envPath = "$envPath;$p"
    }
}

Write-Host "`n[SUCCESS] Environment Setup Complete!" -ForegroundColor Green
Write-Host "Please restart your terminal to apply PATH changes."

# Show setup summary
Write-Host "`n--- Installed Tools ---" -ForegroundColor Yellow
Write-Host "  - Sysinternals (handle.exe, procmon.exe, Sysmon64.exe)"
Write-Host "  - Detect It Easy (diec.exe)"
Write-Host "  - Capa (capa.exe)"
Write-Host "  - Floss (floss.exe)"
Write-Host "  - PE-Sieve (pe-sieve64.exe)"
Write-Host "  - Sysmon (Event Logging)"
