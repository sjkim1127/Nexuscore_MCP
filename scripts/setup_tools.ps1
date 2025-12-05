# Download External Tools Script
$toolsDir = "C:\Tools"
if (!(Test-Path $toolsDir)) { New-Item -ItemType Directory -Path $toolsDir }

Write-Host "Downloading Tools to $toolsDir..."

# 1. Capa
# URL needs to be latest release from github.com/mandiant/capa
$capaUrl = "https://github.com/mandiant/capa/releases/latest/download/capa-v7.0.1-windows.zip" # Example version
# (Real script would dynamically fetch latest tag)

# 2. FLOSS
# URL from github.com/mandiant/flare-floss
$flossUrl = "https://github.com/mandiant/flare-floss/releases/latest/download/floss-v2.3.0-windows.zip"

# 3. ProcDump (Sysinternals)
$procdumpUrl = "https://download.sysinternals.com/files/Procdump.zip"

Write-Host "Note: Accessing GitHub releases requires logic to resolve redirects or specific versions."
Write-Host "Please implement dynamic download or manually place executables in PATH."
Write-Host "For ProcDump:"
Invoke-WebRequest -Uri $procdumpUrl -OutFile "$toolsDir\procdump.zip"
Expand-Archive "$toolsDir\procdump.zip" -DestinationPath $toolsDir -Force

Write-Host "Done. Ensure $toolsDir is in your PATH environment variable."
