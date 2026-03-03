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

write_report() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "Warning: python3 not found; skipping JSON report generation for update-macos-local." >&2
    echo "Status: ${status}" >&2
    if [[ -n "${error_msg}" ]]; then
      echo "Error: ${error_msg}" >&2
    fi
    echo "Log: ${log_path}" >&2
    return 0
  fi
  python3 - "${report_path}" "${timestamp}" "${binary_path}" "${log_path}" "${status}" "${error_msg}" <<'PY'
import json
import sys

report_path, timestamp, binary_path, log_path, status, error_msg = sys.argv[1:7]
payload = {
    "suite": "update-macos-local",
    "timestampUtc": timestamp,
    "platform": "macos",
    "binaryPath": binary_path,
    "logPath": log_path,
    "status": status,
    "error": error_msg,
}
with open(report_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
    f.write("\n")
PY
  echo "Report: ${report_path}"
}

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

{
  echo "update-macos-local smoke test log"
  echo "timestamp=${timestamp}"
  echo "binary_path=${binary_path}"
  echo
} >"${log_path}"

if [[ ! -x "${binary_path}" ]]; then
  status="fail"
  error_msg="binary not executable: ${binary_path}"
  {
    echo "== preflight =="
    echo "binary not executable: ${binary_path}"
  } >>"${log_path}"
else
  if run_step "cara version" "${binary_path}" version; then
    if ! run_step "cara update --check" "${binary_path}" update --check; then
      if [[ "${STRICT_NETWORK:-0}" != "1" ]] && grep -Eq "failed to fetch release info|api.github.com" "${log_path}"; then
        status="skipped"
        error_msg="network unavailable for release API check"
      fi
    fi
  fi
fi

write_report
if [[ "${status}" != "pass" ]]; then
  if [[ "${status}" == "skipped" ]]; then
    exit 0
  fi
  exit 1
fi
