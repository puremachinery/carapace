#!/usr/bin/env bash
set -euo pipefail

# Public-facing copy should describe Carapace as a personal AI assistant.
# Reserve "gateway" wording for literal protocol/config identifiers only.
targets=(
    "website/index.html"
    "README.md"
    "docs/getting-started.md"
    "docs/cli.md"
    "docs/channels.md"
    "docs/security.md"
    "docs/security-comparison.md"
    "docs/architecture.md"
)

# Ensure all expected public-facing files are present.
for t in "${targets[@]}"; do
    if [ ! -e "$t" ]; then
        echo "Error: expected documentation file not found: $t" >&2
        exit 1
    fi
done

pattern="AI operations gateway|operational gateway|gateway server|gateway host|gateway authentication|single-user gateway|(^|[^[:alpha:]])(the|this|a|an)[[:space:]]+gateway([^[:alpha:]]|$)"

failed=0
if command -v rg >/dev/null 2>&1; then
    if rg -n --ignore-case "$pattern" "${targets[@]}"; then
        failed=1
    else
        status=$?
        if [ "$status" -ne 1 ]; then
            echo "Error: rg failed with exit status $status" >&2
            exit "$status"
        fi
    fi
else
    if grep -nEi "$pattern" "${targets[@]}"; then
        failed=1
    else
        status=$?
        if [ "$status" -ne 1 ]; then
            echo "Error: grep failed with exit status $status" >&2
            exit "$status"
        fi
    fi
fi

if [ "$failed" -ne 0 ]; then
    echo
    echo "Public copy terminology check failed."
    echo "Use personal-assistant wording in public docs and website copy."
    echo "Keep 'gateway' only for literal interface names (for example gateway.auth.*)."
    exit 1
fi

echo "Public copy terminology check passed"
