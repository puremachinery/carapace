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

failed=0
if command -v rg >/dev/null 2>&1; then
    if rg -n --ignore-case \
        "AI operations gateway|operational gateway|gateway server|gateway host|gateway authentication|single-user gateway|\\b(the|this|a|an)\\s+gateway\\b" \
        "${targets[@]}"; then
        failed=1
    fi
else
    if grep -nEi \
        "AI operations gateway|operational gateway|gateway server|gateway host|gateway authentication|single-user gateway|(^|[^[:alpha:]])(the|this|a|an)[[:space:]]+gateway([^[:alpha:]]|$)" \
        "${targets[@]}"; then
        failed=1
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
