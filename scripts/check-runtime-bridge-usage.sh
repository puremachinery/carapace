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
      function sanitize_line(s,    tmp, out, rest, start_block, start_line, end_block) {
        tmp = s
        # Drop one-line Rust raw strings (r"...", r#"..."#, r##"..."##, ...).
        gsub(/r[#]*"[^"]*"[#]*/, "\"\"", tmp)
        # Drop normal Rust string and char literals.
        gsub(/"([^"\\]|\\.)*"/, "\"\"", tmp)
        gsub(/'\''([^'\''\\]|\\.)*'\''/, "''", tmp)

        out = ""
        rest = tmp
        while (length(rest) > 0) {
          if (in_block_comment) {
            end_block = index(rest, "*/")
            if (end_block == 0) {
              return out
            }
            rest = substr(rest, end_block + 2)
            in_block_comment = 0
            continue
          }

          start_block = index(rest, "/*")
          start_line = index(rest, "//")

          if (start_line > 0 && (start_block == 0 || start_line < start_block)) {
            out = out substr(rest, 1, start_line - 1)
            return out
          }

          if (start_block == 0) {
            out = out rest
            return out
          }

          out = out substr(rest, 1, start_block - 1)
          rest = substr(rest, start_block + 2)
          in_block_comment = 1
        }

        return out
      }

      function brace_delta(s,    tmp, opens, closes) {
        tmp = s
        opens = gsub(/{/, "{", tmp)
        closes = gsub(/}/, "}", tmp)
        return opens - closes
      }

      BEGIN {
        in_block_comment = 0
        in_tests = 0
        pending_cfg_test = 0
        test_brace_depth = 0
        saw_test_open_brace = 0
      }

      {
        line = sanitize_line($0)
        if (line ~ /^[[:space:]]*$/) {
          next
        }

        if (line ~ /^[[:space:]]*#\[cfg\(test\)\]/) {
          pending_cfg_test = 1
          next
        }

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
