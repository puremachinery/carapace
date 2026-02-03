param(
  [Parameter(Mandatory = $true)]
  [string]$BinaryPath,
  [string]$InstallDir = "$env:LOCALAPPDATA\carapace\bin",
  [switch]$NoCara
)

if (-not (Test-Path -Path $BinaryPath -PathType Leaf)) {
  Write-Error "Binary not found: $BinaryPath"
  exit 1
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$targetExe = Join-Path $InstallDir "carapace.exe"
Copy-Item -Force $BinaryPath $targetExe

if (-not $NoCara) {
  $cmdPath = Join-Path $InstallDir "cara.cmd"
  '@echo off
"%~dp0carapace.exe" %*
' | Set-Content -Encoding ASCII -Path $cmdPath
}

Write-Host "Installed: $targetExe"
if (-not $NoCara) {
  Write-Host "Alias:     $(Join-Path $InstallDir 'cara.cmd')"
}
Write-Host "Ensure $InstallDir is on your PATH."
