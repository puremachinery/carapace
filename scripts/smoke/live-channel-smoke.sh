#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
report_dir="${repo_root}/.local/reports"
mkdir -p "${report_dir}"

timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
binary_path="${CARA_BIN:-${repo_root}/target/debug/cara}"
port="${CARA_PORT:-18789}"
telegram_to="${TELEGRAM_TO:-}"
discord_to="${DISCORD_TO:-}"

log_path="${report_dir}/live-channel-smoke-${timestamp}.log"
report_path="${report_dir}/live-channel-smoke-${timestamp}.json"

status="pass"
error_msg=""
ran_any="false"

write_report() {
  cat >"${report_path}" <<EOF
{
  "suite": "live-channel-smoke",
  "timestampUtc": "${timestamp}",
  "binaryPath": "${binary_path}",
  "port": ${port},
  "telegramToSet": $([[ -n "${telegram_to}" ]] && echo "true" || echo "false"),
  "discordToSet": $([[ -n "${discord_to}" ]] && echo "true" || echo "false"),
  "ranAny": ${ran_any},
  "logPath": "${log_path}",
  "status": "${status}",
  "error": "${error_msg}"
}
EOF
  echo "Report: ${report_path}"
}

if [[ ! -x "${binary_path}" ]]; then
  status="fail"
  error_msg="binary not executable: ${binary_path}"
  write_report
  exit 1
fi

{
  echo "Binary: ${binary_path}"
  echo "Port: ${port}"
} >"${log_path}"

if [[ -n "${telegram_to}" ]]; then
  ran_any="true"
  {
    echo "== telegram verify =="
    echo "$ ${binary_path} verify --outcome telegram --telegram-to ${telegram_to} --port ${port}"
  } >>"${log_path}"
  if ! "${binary_path}" verify --outcome telegram --telegram-to "${telegram_to}" --port "${port}" >>"${log_path}" 2>&1; then
    status="fail"
    error_msg="telegram verify failed"
  fi
fi

if [[ -n "${discord_to}" ]]; then
  ran_any="true"
  {
    echo "== discord verify =="
    echo "$ ${binary_path} verify --outcome discord --discord-to ${discord_to} --port ${port}"
  } >>"${log_path}"
  if ! "${binary_path}" verify --outcome discord --discord-to "${discord_to}" --port "${port}" >>"${log_path}" 2>&1; then
    status="fail"
    if [[ -n "${error_msg}" ]]; then
      error_msg="${error_msg}; discord verify failed"
    else
      error_msg="discord verify failed"
    fi
  fi
fi

if [[ "${ran_any}" != "true" ]]; then
  status="skipped"
  error_msg="set TELEGRAM_TO and/or DISCORD_TO to run live channel smoke"
fi

write_report
if [[ "${status}" == "fail" ]]; then
  exit 1
fi
