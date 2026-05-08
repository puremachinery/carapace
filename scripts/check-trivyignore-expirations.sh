#!/usr/bin/env bash
# Fail the build if any `.trivyignore` line has a past `exp:YYYY-MM-DD`
# deadline. The deadline pattern is:
#
#     CVE-YYYY-NNNN exp:YYYY-MM-DD
#
# Optional whitespace, lines without `exp:` are skipped (treated as
# permanent suppressions — those should be very rare and discussed in
# the surrounding comment block).
#
# Self-enforcing alternative to a calendar reminder or a public-issue
# tracker: the deadline lives next to the suppression and breaks the
# build the moment it lapses, forcing the next contributor to either
# (a) bump the deadline with renewed justification, or
# (b) remove the suppression because the upstream fix is now available.
#
# Run: scripts/check-trivyignore-expirations.sh [path/to/.trivyignore]

set -euo pipefail

ignore_file="${1:-.trivyignore}"

if [[ ! -f "$ignore_file" ]]; then
    echo "no $ignore_file at $(pwd) — nothing to check" >&2
    exit 0
fi

today=$(date -u +%Y-%m-%d)
expired=0
total=0

# Process each non-comment, non-blank line. POSIX date math is portable;
# we compare YYYY-MM-DD strings lexicographically, which is correct for
# this format.
while IFS= read -r line; do
    # Strip trailing whitespace + comments after the entry.
    trimmed=${line%%#*}
    trimmed=${trimmed%"${trimmed##*[![:space:]]}"}
    [[ -z "$trimmed" ]] && continue

    total=$((total + 1))

    if [[ "$trimmed" =~ exp:([0-9]{4}-[0-9]{2}-[0-9]{2}) ]]; then
        deadline=${BASH_REMATCH[1]}
        cve=${trimmed%% *}
        if [[ "$today" > "$deadline" ]]; then
            echo "EXPIRED: $cve had exp:$deadline (today is $today)" >&2
            expired=$((expired + 1))
        else
            echo "OK:      $cve exp:$deadline (today is $today)"
        fi
    else
        # Permanent suppression. Allow but warn — operators should
        # almost always include a deadline.
        cve=${trimmed%% *}
        echo "WARN:    $cve has no exp: deadline (permanent suppression)" >&2
    fi
done < <(grep -v '^[[:space:]]*#' "$ignore_file" | grep -v '^[[:space:]]*$')

if [[ "$expired" -gt 0 ]]; then
    cat >&2 <<EOF

$expired of $total suppression(s) have passed their deadline.

For each expired entry:
  1. Check whether the upstream fix is now available — drop the line if so.
  2. If the suppression must continue, bump the exp:YYYY-MM-DD with a
     renewed rationale comment in the entry's preceding comment block.

Suppressions are not "set and forget"; the deadline is the contract.
EOF
    exit 1
fi

echo "checked $total suppression(s); none expired"
