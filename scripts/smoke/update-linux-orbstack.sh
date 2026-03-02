#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
report_dir="${repo_root}/.local/reports"
mkdir -p "${report_dir}"

timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
binary_path="${CARA_BIN:-${repo_root}/target/debug/cara}"
log_path="${report_dir}/update-smoke-linux-orbstack-${timestamp}.log"
report_path="${report_dir}/update-smoke-linux-orbstack-${timestamp}.json"

status="pass"
error_msg=""
machine="${ORB_MACHINE:-}"
remote_dir=""
remote_bin=""

write_report() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "Warning: python3 not found; skipping JSON report generation for update-linux-orbstack." >&2
    echo "Status: ${status}" >&2
    if [[ -n "${error_msg}" ]]; then
      echo "Error: ${error_msg}" >&2
    fi
    echo "Log: ${log_path}" >&2
    return 0
  fi
  python3 - "${report_path}" "${timestamp}" "${machine}" "${binary_path}" "${log_path}" "${status}" "${error_msg}" <<'PY'
import json
import sys

report_path, timestamp, machine, binary_path, log_path, status, error_msg = sys.argv[1:8]
payload = {
    "suite": "update-linux-orbstack",
    "timestampUtc": timestamp,
    "platform": "linux-orbstack",
    "machine": machine,
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

cleanup_remote() {
  if [[ -n "${machine}" && -n "${remote_dir}" ]]; then
    orbctl run -m "${machine}" -- sh -lc "rm -rf '${remote_dir}'" >>"${log_path}" 2>&1 || true
  fi
}
trap cleanup_remote EXIT

{
  echo "update-linux-orbstack smoke test log"
  echo "timestamp=${timestamp}"
  echo "binary_path=${binary_path}"
  echo "machine=${machine:-<auto>}"
  echo
} >"${log_path}"

if ! command -v orbctl >/dev/null 2>&1; then
  status="skipped"
  error_msg="orbctl not installed"
  echo "${error_msg}" >>"${log_path}"
  write_report
  exit 0
fi

if [[ ! -x "${binary_path}" ]]; then
  status="fail"
  error_msg="binary not executable: ${binary_path}"
  echo "${error_msg}" >>"${log_path}"
  write_report
  exit 1
fi

if [[ -z "${machine}" ]]; then
  machine="$(orbctl default 2>/dev/null || orbctl list -q --running | head -n 1 || true)"
fi
if [[ -z "${machine}" ]]; then
  status="skipped"
  error_msg="no OrbStack machine configured/running"
  echo "${error_msg}" >>"${log_path}"
  write_report
  exit 0
fi
echo "Machine: ${machine}" >>"${log_path}"

if ! orbctl start "${machine}" >>"${log_path}" 2>&1; then
  status="fail"
  error_msg="failed to start machine ${machine}"
  write_report
  exit 1
fi

run_id="cara-update-smoke-${timestamp}"
remote_home="$(orbctl run -m "${machine}" -- sh -lc 'printf %s "$HOME"' 2>>"${log_path}" || true)"
if [[ -z "${remote_home}" ]]; then
  status="fail"
  error_msg="failed to determine remote home directory"
  write_report
  exit 1
fi
remote_dir="${remote_home}/${run_id}"
remote_bin="${remote_dir}/cara"

if ! orbctl run -m "${machine}" -- sh -lc "mkdir -p '${remote_dir}'" >>"${log_path}" 2>&1; then
  status="fail"
  error_msg="failed to create remote directory"
  write_report
  exit 1
fi

if ! orbctl push -m "${machine}" "${binary_path}" "${remote_bin}" >>"${log_path}" 2>&1; then
  status="fail"
  error_msg="failed to push binary to machine"
  write_report
  exit 1
fi

if ! orbctl run -m "${machine}" -- sh -lc "cd '${remote_dir}' && chmod +x ./cara && ./cara version && ./cara update --check" >>"${log_path}" 2>&1; then
  if [[ "${STRICT_NETWORK:-0}" != "1" ]] && grep -Eq "failed to fetch release info|api.github.com" "${log_path}"; then
    status="skipped"
    error_msg="network unavailable for release API check"
    write_report
    exit 0
  else
    status="fail"
    error_msg="remote update smoke commands failed"
    write_report
    exit 1
  fi
fi

write_report
