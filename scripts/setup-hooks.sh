#!/usr/bin/env bash
# Install repository-managed Git hooks into .git/hooks.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "${repo_root}" ]; then
    echo "Not a git repository. Run this script from within a cloned git repository."
    exit 1
fi

hooks_dir="$(git rev-parse --git-path hooks 2>/dev/null || true)"
if [ -z "${hooks_dir}" ]; then
    echo "Unable to determine git hooks directory. Ensure this is a git repository."
    exit 1
fi

if [[ "${hooks_dir}" != /* ]]; then
    hooks_dir="${repo_root}/${hooks_dir}"
fi

if [ ! -d "${hooks_dir}" ]; then
    echo "Git hooks directory '${hooks_dir}' not found. Run this script from within a cloned git repository."
    exit 1
fi

install -m 0755 "${script_dir}/hooks/pre-commit" "${hooks_dir}/pre-commit"
install -m 0755 "${script_dir}/hooks/pre-push" "${hooks_dir}/pre-push"

echo "Installed hooks:"
echo "  - ${hooks_dir}/pre-commit"
echo "  - ${hooks_dir}/pre-push"
