#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

cd "${repo_root}"

scan_paths=(
  "README.md"
  "website"
  "docs"
)

stale_phrases=(
  "This project is in preview"
  "Carapace is preview software"
  "Current status: Carapace is still in preview"
  "Carapace is in preview"
  "Carapace is in active preview"
  "Preview release"
  "Stable (non-preview) release gate"
  "stable release gate"
  "non-preview release gate"
  "Up next: advanced Control UI flows and stable release gate"
  "Kicking the tires is welcome, but don't expect everything to work yet"
  "0.1.0-previewX"
)

failed=0

for phrase in "${stale_phrases[@]}"; do
  if rg -n --fixed-strings "${phrase}" "${scan_paths[@]}"; then
    echo >&2
    echo "Stale docs/site messaging found: ${phrase}" >&2
    failed=1
  fi
done

exit "${failed}"
