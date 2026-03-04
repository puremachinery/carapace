#!/usr/bin/env bash
# Create a GitHub PR using a body file.
# This avoids shell command substitution issues from inline `--body` strings.

set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  ./scripts/create-pr.sh "<title>" <body-file> [base] [head]

Examples:
  ./scripts/create-pr.sh "Improve setup flow" /tmp/pr.md
  ./scripts/create-pr.sh "Improve setup flow" /tmp/pr.md master feat/setup-wizard-improvements
USAGE
}

if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then
    usage
    exit 1
fi

title="$1"
body_file="$2"
base="${3:-master}"
head="${4:-}"

if [ -z "$title" ]; then
    echo "Error: title must not be empty." >&2
    exit 1
fi

if [ ! -f "$body_file" ]; then
    echo "Error: body file not found: $body_file" >&2
    exit 1
fi

if [ ! -s "$body_file" ]; then
    echo "Error: body file is empty: $body_file" >&2
    exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
    echo "Error: gh CLI is required. See https://cli.github.com/" >&2
    exit 1
fi

args=(--base "$base" --title "$title" --body-file "$body_file")
if [ -n "$head" ]; then
    args+=(--head "$head")
fi
gh pr create "${args[@]}"
