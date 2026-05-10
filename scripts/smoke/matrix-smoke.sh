#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
report_dir="${MATRIX_SMOKE_REPORT_DIR:-${repo_root}/.local/reports/matrix-smoke-${timestamp}}"
cara_bin="${CARA_BIN:-${repo_root}/target/debug/cara}"
control_url="${CARAPACE_CONTROL_URL:-http://127.0.0.1:18789}"
control_token="${CARAPACE_GATEWAY_TOKEN:-${CARA_CONTROL_TOKEN:-}}"

required_vars=(
  MATRIX_SMOKE_HOMESERVER_URL
  MATRIX_SMOKE_USER_ID
  MATRIX_SMOKE_DEVICE_ID
  MATRIX_SMOKE_STORE_PASSPHRASE
  CARAPACE_CONFIG_PASSWORD
  MATRIX_SMOKE_ENCRYPTED_ROOM_ID
  MATRIX_SMOKE_UNENCRYPTED_ROOM_ID
  MATRIX_SMOKE_ALLOWLIST_USER
  MATRIX_SMOKE_VERIFICATION_USER_ID
  MATRIX_SMOKE_VERIFICATION_DEVICE_ID
)

missing=()
for name in "${required_vars[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    missing+=("${name}")
  fi
done

if [[ -z "${MATRIX_SMOKE_ACCESS_TOKEN:-}" && -z "${MATRIX_SMOKE_PASSWORD:-}" ]]; then
  missing+=("MATRIX_SMOKE_ACCESS_TOKEN or MATRIX_SMOKE_PASSWORD")
fi

if [[ ${#missing[@]} -gt 0 ]]; then
  printf 'matrix smoke skipped; missing required environment:\n' >&2
  printf '  - %s\n' "${missing[@]}" >&2
  exit 0
fi

mkdir -p "${report_dir}"

run_capture() {
  local name="$1"
  shift
  {
    printf '$'
    printf ' %q' "$@"
    printf '\n\n'
    "$@"
  } >"${report_dir}/${name}.out" 2>"${report_dir}/${name}.err" || {
    local status=$?
    printf '%s failed with exit %s; see %s.{out,err}\n' "$name" "$status" "${report_dir}/${name}" >&2
    return "$status"
  }
}

curl_capture() {
  local name="$1"
  local method="$2"
  local path="$3"
  shift 3
  if [[ -z "${control_token}" ]]; then
    printf 'skipped: CARAPACE_GATEWAY_TOKEN or CARA_CONTROL_TOKEN is required for control API capture\n' \
      >"${report_dir}/${name}.out"
    return 0
  fi
  run_capture "${name}" curl -fsS \
    -H "Authorization: Bearer ${control_token}" \
    -H "Content-Type: application/json" \
    -X "${method}" \
    "$@" \
    "${control_url}${path}"
}

{
  printf 'timestamp=%s\n' "${timestamp}"
  printf 'homeserver_url=%s\n' "${MATRIX_SMOKE_HOMESERVER_URL}"
  printf 'user_id=%s\n' "${MATRIX_SMOKE_USER_ID}"
  printf 'device_id=%s\n' "${MATRIX_SMOKE_DEVICE_ID}"
  printf 'encrypted_room_id=%s\n' "${MATRIX_SMOKE_ENCRYPTED_ROOM_ID}"
  printf 'unencrypted_room_id=%s\n' "${MATRIX_SMOKE_UNENCRYPTED_ROOM_ID}"
  printf 'allowlist_user=%s\n' "${MATRIX_SMOKE_ALLOWLIST_USER}"
  printf 'verification_user_id=%s\n' "${MATRIX_SMOKE_VERIFICATION_USER_ID}"
  printf 'verification_device_id=%s\n' "${MATRIX_SMOKE_VERIFICATION_DEVICE_ID}"
  printf 'auth_mode=%s\n' "$([[ -n "${MATRIX_SMOKE_ACCESS_TOKEN:-}" ]] && printf token || printf password)"
  printf 'store_passphrase=redacted\n'
  printf 'config_password=redacted\n'
  printf 'control_url=%s\n' "${control_url}"
} >"${report_dir}/env-redacted.txt"

if [[ ! -x "${cara_bin}" ]]; then
  printf 'cara binary not executable: %s\n' "${cara_bin}" >"${report_dir}/cara-status.err"
else
  run_capture cara-status "${cara_bin}" status --json || true
  run_capture matrix-send-unencrypted "${cara_bin}" verify --outcome matrix --matrix-to "${MATRIX_SMOKE_UNENCRYPTED_ROOM_ID}" || true
  run_capture matrix-send-encrypted "${cara_bin}" verify --outcome matrix --matrix-to "${MATRIX_SMOKE_ENCRYPTED_ROOM_ID}" || true
  run_capture matrix-devices "${cara_bin}" matrix devices || true
  run_capture matrix-verifications-cli "${cara_bin}" matrix verifications || true
fi

curl_capture control-channels GET /control/channels || true
curl_capture control-matrix-verifications GET /control/matrix/verifications || true
curl_capture control-matrix-send-test-unencrypted POST /control/matrix/send-test \
  --data "{\"roomId\":\"${MATRIX_SMOKE_UNENCRYPTED_ROOM_ID}\",\"text\":\"Carapace Matrix smoke ${timestamp} unencrypted\"}" || true
curl_capture control-matrix-send-test-encrypted POST /control/matrix/send-test \
  --data "{\"roomId\":\"${MATRIX_SMOKE_ENCRYPTED_ROOM_ID}\",\"text\":\"Carapace Matrix smoke ${timestamp} encrypted\"}" || true

if command -v journalctl >/dev/null 2>&1; then
  journalctl --user-unit carapace --since "30 minutes ago" --no-pager \
    >"${report_dir}/journal-user-carapace.log" 2>"${report_dir}/journal-user-carapace.err" || true
fi

{
  printf '{\n'
  printf '  "suite": "matrix-smoke",\n'
  printf '  "timestamp": "%s",\n' "${timestamp}"
  printf '  "reportDir": "%s",\n' "${report_dir}"
  printf '  "requiredEnvPresent": true,\n'
  printf '  "evidence": [\n'
  printf '    "env-redacted.txt",\n'
  printf '    "cara-status.out",\n'
  printf '    "control-channels.out",\n'
  printf '    "control-matrix-verifications.out",\n'
  printf '    "control-matrix-send-test-unencrypted.out",\n'
  printf '    "control-matrix-send-test-encrypted.out",\n'
  printf '    "matrix-send-unencrypted.out",\n'
  printf '    "matrix-send-encrypted.out",\n'
  printf '    "matrix-devices.out",\n'
  printf '    "matrix-verifications-cli.out",\n'
  printf '    "journal-user-carapace.log"\n'
  printf '  ]\n'
  printf '}\n'
} >"${report_dir}/summary.json"

printf 'matrix smoke evidence written to %s\n' "${report_dir}"
