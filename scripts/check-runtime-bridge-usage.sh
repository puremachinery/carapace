#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

violations="$(
  while IFS= read -r file; do
    if [[ "$file" == "src/runtime_bridge.rs" || "$file" == "src/plugins/runtime.rs" ]]; then
      continue
    fi

    awk -v file="$file" '
      function brace_delta(s,    tmp, opens, closes) {
        tmp = s
        gsub(/"([^"\\]|\\.)*"/, "\"\"", tmp)
        gsub(/'\''([^'\''\\]|\\.)*'\''/, "''", tmp)
        opens = gsub(/{/, "{", tmp)
        closes = gsub(/}/, "}", tmp)
        return opens - closes
      }

      BEGIN {
        in_tests = 0
        pending_cfg_test = 0
        test_brace_depth = 0
        saw_test_open_brace = 0
      }

      /^[[:space:]]*#\[cfg\(test\)\]/ {
        pending_cfg_test = 1
        next
      }

      {
        line = $0

        if (in_tests) {
          delta = brace_delta(line)
          test_brace_depth += delta
          if (delta > 0) {
            saw_test_open_brace = 1
          }
          if (saw_test_open_brace && test_brace_depth <= 0) {
            in_tests = 0
            test_brace_depth = 0
            saw_test_open_brace = 0
          }
          next
        }

        if (pending_cfg_test) {
          if (line ~ /^[[:space:]]*mod[[:space:]]+tests([[:space:]]*\{|[[:space:]]*$)/) {
            in_tests = 1
            pending_cfg_test = 0
            test_brace_depth = brace_delta(line)
            if (test_brace_depth > 0) {
              saw_test_open_brace = 1
            }
            next
          }
          pending_cfg_test = 0
        }

        if (line ~ /^[[:space:]]*\/\//) next
        if (line ~ /tokio::task::block_in_place[[:space:]]*\(/ || line ~ /\.block_on[[:space:]]*\(/) {
          printf "%s:%d:%s\n", file, NR, line
        }
      }
    ' "$file"
  done < <(git ls-files 'src/**/*.rs')
)"

if [[ -n "$violations" ]]; then
  echo "Direct runtime bridging is only allowed in approved runtime modules (or test code)." >&2
  echo "Found disallowed usage in production code:" >&2
  echo "$violations" >&2
  exit 1
fi

echo "Runtime bridge guard passed."
