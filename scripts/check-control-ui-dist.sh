#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src_dir="${repo_root}/ui/control-ui"
dist_dir="${repo_root}/dist/control-ui"

if [[ ! -d "${src_dir}" ]]; then
  echo "Missing source directory: ${src_dir}" >&2
  exit 1
fi

if [[ ! -d "${dist_dir}" ]]; then
  echo "Missing dist directory: ${dist_dir}" >&2
  exit 1
fi

diff_file="$(mktemp)"
trap 'rm -f "${diff_file}"' EXIT

if ! diff -ru --exclude '.DS_Store' "${src_dir}" "${dist_dir}" >"${diff_file}"; then
  echo "Control UI source and dist assets are out of sync." >&2
  echo "Run: npm run ui:build" >&2
  echo >&2
  sed -n '1,200p' "${diff_file}" >&2
  exit 1
fi

echo "Control UI source and dist assets are in sync."
