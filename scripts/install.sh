#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: install.sh --binary <path> [--dir <install-dir>]

Installs the cara binary.

Examples:
  ./scripts/install.sh --binary ./cara-x86_64-linux
  sudo ./scripts/install.sh --binary ./cara-x86_64-linux --dir /usr/local/bin
USAGE
}

binary_path=""
install_dir="/usr/local/bin"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      binary_path="${2:-}"
      shift 2
      ;;
    --dir)
      install_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$binary_path" ]]; then
  echo "Missing --binary <path>" >&2
  usage
  exit 1
fi

if [[ ! -f "$binary_path" ]]; then
  echo "Binary not found: $binary_path" >&2
  exit 1
fi

mkdir -p "$install_dir"

cp "$binary_path" "$install_dir/cara"
chmod 0755 "$install_dir/cara"

echo "Installed: $install_dir/cara"
echo "Ensure $install_dir is on your PATH."
