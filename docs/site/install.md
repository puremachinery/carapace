# Install Carapace

## Outcome

Install `cara` from release binaries, verify artifact integrity, and confirm the CLI works.

## 1) Download a release binary

Use a direct download link for your platform:

- Linux x86_64: [cara-x86_64-linux](https://github.com/puremachinery/carapace/releases/latest/download/cara-x86_64-linux)
- Linux ARM64: [cara-aarch64-linux](https://github.com/puremachinery/carapace/releases/latest/download/cara-aarch64-linux)
- macOS Intel: [cara-x86_64-darwin](https://github.com/puremachinery/carapace/releases/latest/download/cara-x86_64-darwin)
- macOS Apple Silicon: [cara-aarch64-darwin](https://github.com/puremachinery/carapace/releases/latest/download/cara-aarch64-darwin)
- Windows x86_64: [cara-x86_64-windows.exe](https://github.com/puremachinery/carapace/releases/latest/download/cara-x86_64-windows.exe)

Release page: <https://github.com/puremachinery/carapace/releases/latest>

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

## 4) Install on your PATH

macOS/Linux:

```bash
chmod +x ./cara-<your-platform>
sudo mv ./cara-<your-platform> /usr/local/bin/cara
```

Windows (PowerShell):

```powershell
$installDir = "$env:LOCALAPPDATA\cara\bin"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item .\cara-x86_64-windows.exe (Join-Path $installDir "cara.exe")
```

## 5) Verify install

```bash
cara --help
cara version
```

## Next step

- Continue with [First run](/carapace/first-run.html)
- Or jump to [Cookbook recipes](/carapace/cookbook/)
