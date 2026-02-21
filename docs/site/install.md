# Install Carapace

## Outcome

Install `cara`, optionally verify signatures/checksums, and confirm it runs.

## 1) Download a release binary

Use a direct download link for your platform (fastest path for most users):

- Linux x86_64: [cara-x86_64-linux](https://github.com/puremachinery/carapace/releases/latest/download/cara-x86_64-linux)
- Linux ARM64: [cara-aarch64-linux](https://github.com/puremachinery/carapace/releases/latest/download/cara-aarch64-linux)
- macOS Intel: [cara-x86_64-darwin](https://github.com/puremachinery/carapace/releases/latest/download/cara-x86_64-darwin)
- macOS Apple Silicon: [cara-aarch64-darwin](https://github.com/puremachinery/carapace/releases/latest/download/cara-aarch64-darwin)
- Windows x86_64: [cara-x86_64-windows.exe](https://github.com/puremachinery/carapace/releases/latest/download/cara-x86_64-windows.exe)

Release page: <https://github.com/puremachinery/carapace/releases/latest>

Use `releases/latest` for quick interactive installs. For automation, reproducible
rollouts, and preview-specific installs, use a pinned tag URL.

Note: `releases/latest` may not point at the newest pre-release preview.

Quick path for first-time setup:

1. Download your platform binary (above).
2. Make it executable and move it onto your PATH (see "Install on your PATH" below).
3. Run `cara version` to confirm.

Signature and checksum verification (next two sections) are recommended,
especially for production or automation.

## Optional (advanced): pinned version links (automation/ops)

```bash
VERSION="vX.Y.Z"
BASE_URL="https://github.com/puremachinery/carapace/releases/download/${VERSION}"
curl -LO "${BASE_URL}/cara-x86_64-linux"
```

```powershell
$Version = "vX.Y.Z"
$BaseUrl = "https://github.com/puremachinery/carapace/releases/download/$Version"
Invoke-WebRequest "$BaseUrl/cara-x86_64-windows.exe" -OutFile ".\cara-x86_64-windows.exe"
```

## 2) Verify signature (recommended)

Each release artifact has a matching `.sig` and `.pem` file.

Example for Linux x86_64:

```bash
curl -LO https://github.com/puremachinery/carapace/releases/latest/download/cara-x86_64-linux
curl -LO https://github.com/puremachinery/carapace/releases/latest/download/cara-x86_64-linux.sig
curl -LO https://github.com/puremachinery/carapace/releases/latest/download/cara-x86_64-linux.pem

cosign verify-blob \
  --certificate cara-x86_64-linux.pem \
  --signature cara-x86_64-linux.sig \
  --certificate-identity-regexp "https://github.com/puremachinery/carapace/.github/workflows/release.yml@refs/tags/v.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  cara-x86_64-linux
```

## 3) Verify checksum (optional)

Compute SHA-256 locally:

```bash
# macOS/Linux
shasum -a 256 cara-x86_64-linux
# Linux alternative
sha256sum cara-x86_64-linux
```

```powershell
# Windows PowerShell
Get-FileHash .\cara-x86_64-windows.exe -Algorithm SHA256
```

For pinned releases, compare against release-provided checksums:

```bash
VERSION="vX.Y.Z"
BASE_URL="https://github.com/puremachinery/carapace/releases/download/${VERSION}"
curl -LO "${BASE_URL}/cara-x86_64-linux"
curl -LO "${BASE_URL}/SHA256SUMS.txt"
curl -LO "${BASE_URL}/SHA256SUMS.txt.sig"
curl -LO "${BASE_URL}/SHA256SUMS.txt.pem"

cosign verify-blob \
  --certificate SHA256SUMS.txt.pem \
  --signature SHA256SUMS.txt.sig \
  --certificate-identity-regexp "https://github.com/puremachinery/carapace/.github/workflows/release.yml@refs/tags/v.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS.txt

grep "  cara-x86_64-linux$" SHA256SUMS.txt | sha256sum --check --strict
```

If you downloaded every artifact listed in `SHA256SUMS.txt`, you can also run:

```bash
sha256sum --check SHA256SUMS.txt
```

PowerShell example:

> **Prerequisite (Windows):** Install `cosign` if needed (for example:
> `winget install Sigstore.Cosign`).

```powershell
$Version = "vX.Y.Z"
$FileName = "cara-x86_64-windows.exe"
$BaseUrl = "https://github.com/puremachinery/carapace/releases/download/$Version"
$ErrorActionPreference = 'Stop'
Invoke-WebRequest "$BaseUrl/$FileName" -OutFile ".\$FileName"
Invoke-WebRequest "$BaseUrl/SHA256SUMS.txt" -OutFile ".\SHA256SUMS.txt"
Invoke-WebRequest "$BaseUrl/SHA256SUMS.txt.sig" -OutFile ".\SHA256SUMS.txt.sig"
Invoke-WebRequest "$BaseUrl/SHA256SUMS.txt.pem" -OutFile ".\SHA256SUMS.txt.pem"

cosign verify-blob `
  --certificate .\SHA256SUMS.txt.pem `
  --signature .\SHA256SUMS.txt.sig `
  --certificate-identity-regexp "https://github.com/puremachinery/carapace/.github/workflows/release.yml@refs/tags/v.*" `
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" `
  .\SHA256SUMS.txt
if ($LASTEXITCODE -ne 0) {
  throw "cosign verification failed for SHA256SUMS.txt"
}

$expectedLine = (Select-String -Path .\SHA256SUMS.txt -SimpleMatch "  $FileName").Line
if (-not $expectedLine) {
  throw "No checksum entry found for $FileName in SHA256SUMS.txt"
}
$expected = ($expectedLine -split '\s+')[0].ToLower()
$actual = (Get-FileHash ".\$FileName" -Algorithm SHA256).Hash.ToLower()
if ($expected -ne $actual) {
  throw "Checksum mismatch for $FileName"
}
Write-Host "Checksum verified for $FileName"
```

## 4) Install on your PATH

macOS/Linux:

```bash
FILE="cara-<your-platform>"   # example: cara-aarch64-darwin
chmod +x "./${FILE}"
sudo mv "./${FILE}" /usr/local/bin/cara
```

Windows (PowerShell):

```powershell
$installDir = "$env:LOCALAPPDATA\cara\bin"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item .\cara-x86_64-windows.exe (Join-Path $installDir "cara.exe")

# Add to PATH for the current user (persistent across sessions)
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$installDir", "User")
}
```

Restart your terminal after updating PATH.

## 5) Verify install

```bash
cara --help
cara version
```

## Next step

- Continue with [First run](first-run.md)
- Or jump to [Cookbook recipes](../cookbook/README.md)
