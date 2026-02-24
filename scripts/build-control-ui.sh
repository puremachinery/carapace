#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

src_dir="${repo_root}/ui/control-ui"
out_dir="${repo_root}/dist/control-ui"

if [ ! -d "${src_dir}" ]; then
  echo "Error: missing control UI source directory: ${src_dir}" >&2
  exit 1
fi

rm -rf "${out_dir}"
mkdir -p "${out_dir}"
cp -R "${src_dir}"/. "${out_dir}"/

echo "Built control UI to ${out_dir}"
