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

write_report() {
  cat >"${report_path}" <<EOF
{
  "suite": "update-linux-orbstack",
  "timestampUtc": "${timestamp}",
  "platform": "linux-orbstack",
  "machine": "${machine}",
  "binaryPath": "${binary_path}",
  "logPath": "${log_path}",
  "status": "${status}",
  "error": "${error_msg}"
}
EOF
  echo "Report: ${report_path}"
}

if ! command -v orbctl >/dev/null 2>&1; then
  status="skipped"
  error_msg="orbctl not installed"
  write_report
  exit 0
fi

if [[ ! -x "${binary_path}" ]]; then
  status="fail"
  error_msg="binary not executable: ${binary_path}"
  write_report
  exit 1
fi

if [[ -z "${machine}" ]]; then
  machine="$(orbctl default 2>/dev/null || true)"
fi
if [[ -z "${machine}" ]]; then
  machine="$(orbctl list -q --running | head -n 1 || true)"
fi
if [[ -z "${machine}" ]]; then
  status="skipped"
  error_msg="no OrbStack machine configured/running"
  write_report
  exit 0
fi

{
  echo "Machine: ${machine}"
  echo "Binary: ${binary_path}"
} >"${log_path}"

if ! orbctl start "${machine}" >>"${log_path}" 2>&1; then
  status="fail"
  error_msg="failed to start machine ${machine}"
  write_report
  exit 1
fi

run_id="cara-update-smoke-${timestamp}"
remote_dir="${run_id}"
remote_bin="${remote_dir}/cara"

if ! orbctl run -m "${machine}" -- sh -lc "mkdir -p \"\$HOME/${remote_dir}\"" >>"${log_path}" 2>&1; then
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

if ! orbctl run -m "${machine}" -- sh -lc "cd \"\$HOME/${remote_dir}\" && chmod +x ./cara && ./cara version && ./cara update --check" >>"${log_path}" 2>&1; then
  if [[ "${STRICT_NETWORK:-0}" != "1" ]] && rg -q "failed to fetch release info|api.github.com" "${log_path}"; then
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
