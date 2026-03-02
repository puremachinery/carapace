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
  if ! command -v python3 >/dev/null 2>&1; then
    echo "Warning: python3 not found; skipping JSON report generation for live-channel-smoke." >&2
    echo "Status: ${status}" >&2
    if [[ -n "${error_msg}" ]]; then
      echo "Error: ${error_msg}" >&2
    fi
    echo "Log: ${log_path}" >&2
    return 0
  fi
  python3 - "${report_path}" "${timestamp}" "${binary_path}" "${port}" "${telegram_to}" "${discord_to}" "${ran_any}" "${log_path}" "${status}" "${error_msg}" <<'PY'
import json
import sys

(
    report_path,
    timestamp,
    binary_path,
    port,
    telegram_to,
    discord_to,
    ran_any,
    log_path,
    status,
    error_msg,
) = sys.argv[1:11]
payload = {
    "suite": "live-channel-smoke",
    "timestampUtc": timestamp,
    "binaryPath": binary_path,
    "port": port,
    "telegramToSet": bool(telegram_to),
    "discordToSet": bool(discord_to),
    "ranAny": ran_any == "true",
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

{
  echo "Binary: ${binary_path}"
  echo "Port: ${port}"
} >"${log_path}"

if [[ ! -x "${binary_path}" ]]; then
  status="fail"
  error_msg="binary not executable: ${binary_path}"
  {
    echo "== pre-check failure =="
    echo "${error_msg}"
  } >>"${log_path}"
  write_report
  exit 1
fi

if [[ -n "${telegram_to}" ]]; then
  ran_any="true"
  {
    echo "== telegram verify =="
    echo "$ ${binary_path} verify --outcome telegram --telegram-to <redacted> --port ${port}"
  } >>"${log_path}"
  if ! "${binary_path}" verify --outcome telegram --telegram-to "${telegram_to}" --port "${port}" >/dev/null 2>&1; then
    status="fail"
    error_msg="telegram verify failed"
  fi
fi

if [[ -n "${discord_to}" ]]; then
  ran_any="true"
  {
    echo "== discord verify =="
    echo "$ ${binary_path} verify --outcome discord --discord-to <redacted> --port ${port}"
  } >>"${log_path}"
  if ! "${binary_path}" verify --outcome discord --discord-to "${discord_to}" --port "${port}" >/dev/null 2>&1; then
    status="fail"
    [[ -n "${error_msg}" ]] && error_msg+="; "
    error_msg+="discord verify failed"
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
