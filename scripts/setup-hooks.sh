#!/bin/bash
# Install repository-managed Git hooks into .git/hooks.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
hooks_dir="${repo_root}/.git/hooks"

if [ ! -d "${hooks_dir}" ]; then
    echo "No .git/hooks directory found. Run this script from a cloned git repository."
    exit 1
fi

install -m 0755 "${repo_root}/scripts/hooks/pre-commit" "${hooks_dir}/pre-commit"
install -m 0755 "${repo_root}/scripts/hooks/pre-push" "${hooks_dir}/pre-push"

echo "Installed hooks:"
echo "  - ${hooks_dir}/pre-commit"
echo "  - ${hooks_dir}/pre-push"
