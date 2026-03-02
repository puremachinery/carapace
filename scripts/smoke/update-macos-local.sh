#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
report_dir="${repo_root}/.local/reports"
mkdir -p "${report_dir}"

timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
binary_path="${CARA_BIN:-${repo_root}/target/debug/cara}"
log_path="${report_dir}/update-smoke-macos-local-${timestamp}.log"
report_path="${report_dir}/update-smoke-macos-local-${timestamp}.json"

status="pass"
error_msg=""

run_step() {
  local label="$1"
  shift
  {
    echo "== ${label} =="
    echo "$ $*"
  } >>"${log_path}"
  if ! "$@" >>"${log_path}" 2>&1; then
    status="fail"
    error_msg="${label} failed"
    return 1
  fi
  return 0
}

if [[ ! -x "${binary_path}" ]]; then
  status="fail"
  error_msg="binary not executable: ${binary_path}"
else
  run_step "cara version" "${binary_path}" version || true
  if ! run_step "cara update --check" "${binary_path}" update --check; then
    if [[ "${STRICT_NETWORK:-0}" != "1" ]] && rg -q "failed to fetch release info|api.github.com" "${log_path}"; then
      status="skipped"
      error_msg="network unavailable for release API check"
    fi
  fi
fi

cat >"${report_path}" <<EOF
{
  "suite": "update-macos-local",
  "timestampUtc": "${timestamp}",
  "platform": "macos",
  "binaryPath": "${binary_path}",
  "logPath": "${log_path}",
  "status": "${status}",
  "error": "${error_msg}"
}
EOF

echo "Report: ${report_path}"
if [[ "${status}" != "pass" ]]; then
  if [[ "${status}" == "skipped" ]]; then
    exit 0
  fi
  exit 1
fi
