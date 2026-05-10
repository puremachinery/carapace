#!/usr/bin/env bash
set -euo pipefail

# Fail the build if any cargo-deny or cargo-audit RustSec ignore lacks an
# exp:YYYY-MM-DD deadline or has passed its deadline. The deadline must live on
# the same line as the RustSec id so the suppression remains auditable when
# comments move during edits.

deny_file="${1:-deny.toml}"
audit_file="${2:-.cargo/audit.toml}"

today="$(date -u +%Y-%m-%d)"
checked=0
expired=0
missing=0

check_ignore_line() {
    local source="$1"
    local line="$2"
    local rustsec="$3"

    checked=$((checked + 1))
    if [[ "$line" =~ exp:([0-9]{4}-[0-9]{2}-[0-9]{2}) ]]; then
        deadline="${BASH_REMATCH[1]}"
        if [[ "$today" > "$deadline" ]]; then
            echo "EXPIRED: $source $rustsec had exp:$deadline (today is $today)" >&2
            expired=$((expired + 1))
        else
            echo "OK:      $source $rustsec exp:$deadline (today is $today)"
        fi
    else
        echo "MISSING: $source $rustsec has no exp:YYYY-MM-DD deadline" >&2
        missing=$((missing + 1))
    fi
}

if [[ -f "$deny_file" ]]; then
    while IFS= read -r line; do
        if [[ "$line" =~ id[[:space:]]*=[[:space:]]*\"(RUSTSEC-[0-9]{4}-[0-9]{4})\" ]]; then
            check_ignore_line "$deny_file" "$line" "${BASH_REMATCH[1]}"
        fi
    done < <(awk '{ print }' "$deny_file")
else
    echo "no $deny_file at $(pwd) -- skipping cargo-deny ignore check" >&2
fi

if [[ -f "$audit_file" ]]; then
    while IFS= read -r line; do
        if [[ ! "$line" =~ ^[[:space:]]*# ]] && [[ "$line" =~ \"(RUSTSEC-[0-9]{4}-[0-9]{4})\" ]]; then
            check_ignore_line "$audit_file" "$line" "${BASH_REMATCH[1]}"
        fi
    done < <(awk '{ print }' "$audit_file")
else
    echo "no $audit_file at $(pwd) -- skipping cargo-audit ignore check" >&2
fi

if [[ "$expired" -gt 0 || "$missing" -gt 0 ]]; then
    cat >&2 <<EOF

RustSec advisory ignore expiry check failed.

Every RUSTSEC ignore in deny.toml or .cargo/audit.toml must carry an
exp:YYYY-MM-DD deadline on the same line as its id. For each failed entry,
either drop the suppression because the dependency graph no longer needs it,
or renew the deadline with updated rationale.
EOF
    exit 1
fi

echo "checked $checked RustSec advisory ignore(s); none expired"
