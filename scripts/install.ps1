param(
  [Parameter(Mandatory = $true)]
  [string]$BinaryPath,
  [string]$InstallDir = "$env:LOCALAPPDATA\cara\bin"
)

if (-not (Test-Path -Path $BinaryPath -PathType Leaf)) {
  Write-Error "Binary not found: $BinaryPath"
  exit 1
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$targetExe = Join-Path $InstallDir "cara.exe"
Copy-Item -Force $BinaryPath $targetExe

Write-Host "Installed: $targetExe"
Write-Host "Ensure $InstallDir is on your PATH."
