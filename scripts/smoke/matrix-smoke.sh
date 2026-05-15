#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_report_dir="${repo_root}/.local/reports/matrix-smoke-${timestamp}-$$"
report_dir="${MATRIX_SMOKE_REPORT_DIR:-${default_report_dir}}"
cara_bin="${CARA_BIN:-${repo_root}/target/debug/cara}"
control_url="${CARAPACE_CONTROL_URL:-http://127.0.0.1:18789}"
control_token="${CARAPACE_GATEWAY_TOKEN:-${CARA_CONTROL_TOKEN:-}}"
status="running"
required_failures_file=""
curl_config_files=()

create_report_dir() {
  local parent
  parent="$(dirname "${report_dir}")"
  mkdir -p "${parent}"
  if ! mkdir "${report_dir}"; then
    printf 'matrix smoke report directory already exists or cannot be created atomically: %s\n' "${report_dir}" >&2
    exit 1
  fi
}

record_skip() {
  local step="$1"
  local reason="$2"
  jq -cn --arg step "${step}" --arg reason "${reason}" '{step:$step,reason:$reason}' \
    >>"${report_dir}/skipped-steps.jsonl"
}

record_required_failure() {
  local step="$1"
  local reason="$2"
  jq -cn --arg step "${step}" --arg reason "${reason}" '{step:$step,reason:$reason}' \
    >>"${required_failures_file}"
}

record_required_manual_step() {
  local step="$1"
  local reason="$2"
  record_skip "${step}" "${reason}"
  record_required_failure "${step}" "required manual evidence not captured by harness: ${reason}"
}

json_array_from_file() {
  local path="$1"
  if [[ -s "${path}" ]]; then
    jq -Rsc 'split("\n") | map(select(length > 0))' "${path}"
  else
    printf '[]'
  fi
}

json_lines_array_from_file() {
  local path="$1"
  if [[ -s "${path}" ]]; then
    jq -sc '.' "${path}"
  else
    printf '[]'
  fi
}

write_summary() {
  local evidence_file="${report_dir}/evidence-files.txt"
  find "${report_dir}" -type f -exec basename {} \; | sort >"${evidence_file}"
  if ! command -v jq >/dev/null 2>&1; then
    cat >"${report_dir}/summary.json" <<EOF
{"suite":"matrix-smoke","timestamp":"${timestamp}","reportDir":"${report_dir}","status":"${status}","evidence":["$(basename "${evidence_file}")"],"skippedSteps":[{"step":"harness","reason":"jq is required"}],"requiredFailures":[]}
EOF
    return 0
  fi
  jq -n \
    --arg suite "matrix-smoke" \
    --arg timestamp "${timestamp}" \
    --arg reportDir "${report_dir}" \
    --arg status "${status}" \
    --argjson evidence "$(json_array_from_file "${evidence_file}")" \
    --argjson skipped "$(json_lines_array_from_file "${report_dir}/skipped-steps.jsonl")" \
    --argjson requiredFailures "$(json_lines_array_from_file "${required_failures_file}")" \
    '{
      suite: $suite,
      timestamp: $timestamp,
      reportDir: $reportDir,
      status: $status,
      evidence: $evidence,
      skippedSteps: $skipped,
      requiredFailures: $requiredFailures
    }' >"${report_dir}/summary.json"
}

finalize() {
  local exit_code=$?
  cleanup_curl_configs
  if [[ "${status}" == "running" ]]; then
    if [[ ${exit_code} -eq 0 ]]; then
      status="completed"
    else
      status="aborted"
    fi
  fi
  write_summary || true
  if [[ ${exit_code} -ne 0 ]]; then
    printf 'matrix smoke %s; evidence written to %s\n' "${status}" "${report_dir}" >&2
  fi
  exit "${exit_code}"
}

cleanup_curl_configs() {
  local path
  for path in "${curl_config_files[@]:-}"; do
    rm -f "${path}"
  done
}

redacted_command_line() {
  local out=()
  local redact_next=0
  local arg
  for arg in "$@"; do
    if [[ ${redact_next} -eq 1 ]]; then
      out+=("[REDACTED]")
      redact_next=0
      continue
    fi
    case "${arg}" in
      Authorization:*)
        out+=("Authorization: Bearer [REDACTED]")
        ;;
      -H|--header)
        out+=("${arg}")
        redact_next=1
        ;;
      *)
        if [[ -n "${control_token}" && "${arg}" == *"${control_token}"* ]]; then
          out+=("${arg//${control_token}/[REDACTED]}")
        else
          out+=("${arg}")
        fi
        ;;
    esac
  done
  printf '$'
  printf ' %q' "${out[@]}"
  printf '\n\n'
}

run_capture() {
  local name="$1"
  shift
  {
    redacted_command_line "$@"
    "$@"
  } >"${report_dir}/${name}.out" 2>"${report_dir}/${name}.err" || {
    local status_code=$?
    printf '%s failed with exit %s; see %s.{out,err}\n' "$name" "$status_code" "${report_dir}/${name}" >&2
    return "${status_code}"
  }
}

run_required_capture() {
  local name="$1"
  shift
  if ! run_capture "${name}" "$@"; then
    record_required_failure "${name}" "required command failed"
    return 1
  fi
}

curl_capture() {
  local name="$1"
  local method="$2"
  local path="$3"
  shift 3
  if [[ -z "${control_token}" ]]; then
    record_skip "${name}" "CARAPACE_GATEWAY_TOKEN or CARA_CONTROL_TOKEN is required for control API capture"
    printf 'skipped: control token missing\n' >"${report_dir}/${name}.out"
    return 0
  fi
  local curl_config="${report_dir}/${name}.curlrc"
  umask 077
  {
    printf 'header = "Authorization: Bearer %s"\n' "${control_token}"
    printf 'header = "Content-Type: application/json"\n'
  } >"${curl_config}"
  curl_config_files+=("${curl_config}")
  local rc=0
  if run_capture "${name}" curl -fsS \
    --config "${curl_config}" \
    -X "${method}" \
    "$@" \
    "${control_url}${path}"; then
    rc=0
  else
    rc=$?
  fi
  rm -f "${curl_config}"
  return "${rc}"
}

curl_required_capture() {
  local name="$1"
  shift
  if ! curl_capture "${name}" "$@"; then
    record_required_failure "${name}" "required control API probe failed"
    return 1
  fi
}

capture_recovery_key_presence() {
  local name="matrix-recovery-key-presence"
  if "${cara_bin}" matrix recovery-key show --allow-non-terminal >/dev/null 2>"${report_dir}/${name}.err"; then
    jq -n --arg step "${name}" --arg present "true" '{step:$step,present:($present=="true")}' \
      >"${report_dir}/${name}.json"
  else
    record_skip "${name}" "recovery key is unavailable or CLI command failed"
  fi
}

create_report_dir
trap finalize EXIT
trap 'status="aborted"; exit 130' INT TERM
: >"${report_dir}/skipped-steps.jsonl"
required_failures_file="${report_dir}/required-failures.jsonl"
: >"${required_failures_file}"

if ! command -v jq >/dev/null 2>&1; then
  status="skipped"
  printf 'matrix smoke skipped; jq is required for structured JSON payloads\n' >&2
  printf '{"step":"harness","reason":"jq is required"}\n' >>"${report_dir}/skipped-steps.jsonl"
  exit 0
fi

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
  status="skipped"
  printf 'matrix smoke skipped; missing required environment:\n' >&2
  printf '  - %s\n' "${missing[@]}" >&2
  printf '%s\n' "${missing[@]}" >"${report_dir}/missing-env.txt"
  record_skip "live-homeserver-smoke" "missing required MATRIX_SMOKE_* or CARAPACE_CONFIG_PASSWORD environment"
  exit 0
fi

fixture_warning="false"
if [[ "${MATRIX_SMOKE_USER_ID}" != *smoke* && "${MATRIX_SMOKE_USER_ID}" != *test* ]]; then
  fixture_warning="true"
  record_skip "fixture-account-warning" "MATRIX_SMOKE_USER_ID does not look like a dedicated smoke/test account"
fi

jq -n \
  --arg timestamp "${timestamp}" \
  --arg homeserverUrl "${MATRIX_SMOKE_HOMESERVER_URL}" \
  --arg userId "${MATRIX_SMOKE_USER_ID}" \
  --arg deviceId "${MATRIX_SMOKE_DEVICE_ID}" \
  --arg encryptedRoomId "${MATRIX_SMOKE_ENCRYPTED_ROOM_ID}" \
  --arg unencryptedRoomId "${MATRIX_SMOKE_UNENCRYPTED_ROOM_ID}" \
  --arg allowlistUser "${MATRIX_SMOKE_ALLOWLIST_USER}" \
  --arg verificationUserId "${MATRIX_SMOKE_VERIFICATION_USER_ID}" \
  --arg verificationDeviceId "${MATRIX_SMOKE_VERIFICATION_DEVICE_ID}" \
  --arg authMode "$([[ -n "${MATRIX_SMOKE_ACCESS_TOKEN:-}" ]] && printf token || printf password)" \
  --arg controlUrl "${control_url}" \
  --argjson fixtureAccountWarning "${fixture_warning}" \
  '{
    timestamp: $timestamp,
    homeserverUrl: $homeserverUrl,
    userId: $userId,
    deviceId: $deviceId,
    encryptedRoomId: $encryptedRoomId,
    unencryptedRoomId: $unencryptedRoomId,
    allowlistUser: $allowlistUser,
    verificationUserId: $verificationUserId,
    verificationDeviceId: $verificationDeviceId,
    authMode: $authMode,
    storePassphrase: "redacted",
    configPassword: "redacted",
    accessToken: "redacted",
    controlUrl: $controlUrl,
    fixtureAccountWarning: $fixtureAccountWarning
  }' >"${report_dir}/env-redacted.json"

if curl -fsS "${control_url}/health" >"${report_dir}/daemon-health.out" 2>"${report_dir}/daemon-health.err"; then
  :
else
  record_required_failure "daemon-health" "daemon health preflight failed at ${control_url}/health"
fi

if [[ ! -x "${cara_bin}" ]]; then
  # The cara binary is the primary tool the harness needs. Missing
  # binary used to record a soft skip and continue, which allowed the
  # whole run to finish with `status=completed` even though none of
  # the matrix-send/cara-status probes were captured — directly
  # contradicting the required-evidence list in docs/channel-smoke.md.
  # Fail closed instead so a wrong binary path or unbuilt tree is
  # surfaced loudly.
  record_required_failure "cara-cli" "cara binary not executable at ${cara_bin}; rebuild the workspace or set MATRIX_SMOKE_CARA_BIN before retrying"
  printf 'cara binary not executable: %s\n' "${cara_bin}" >"${report_dir}/cara-status.err"
else
  run_required_capture cara-status "${cara_bin}" status --json || true
  run_required_capture matrix-send-unencrypted "${cara_bin}" verify --outcome matrix --matrix-to "${MATRIX_SMOKE_UNENCRYPTED_ROOM_ID}" || true
  run_required_capture matrix-send-encrypted "${cara_bin}" verify --outcome matrix --matrix-to "${MATRIX_SMOKE_ENCRYPTED_ROOM_ID}" || true
  run_capture matrix-devices "${cara_bin}" matrix devices || true
  run_capture matrix-verifications-cli "${cara_bin}" matrix verifications || true
  capture_recovery_key_presence || true
fi

curl_required_capture control-channels GET /control/channels || true
curl_required_capture control-matrix-verifications GET /control/matrix/verifications || true

unencrypted_body="$(jq -n \
  --arg roomId "${MATRIX_SMOKE_UNENCRYPTED_ROOM_ID}" \
  --arg text "Carapace Matrix smoke ${timestamp} unencrypted" \
  '{roomId:$roomId,text:$text}')"
encrypted_body="$(jq -n \
  --arg roomId "${MATRIX_SMOKE_ENCRYPTED_ROOM_ID}" \
  --arg text "Carapace Matrix smoke ${timestamp} encrypted" \
  '{roomId:$roomId,text:$text}')"

curl_required_capture control-matrix-send-test-unencrypted POST /control/matrix/send-test \
  --data "${unencrypted_body}" || true
curl_required_capture control-matrix-send-test-encrypted POST /control/matrix/send-test \
  --data "${encrypted_body}" || true

record_required_manual_step "allowlist-negative-invite" "manual fixture step; harness records account and expected artifact but does not invite from the homeserver"
record_required_manual_step "sas-confirmation" "manual operator comparison step; harness captures devices/verifications but does not auto-confirm SAS"
record_required_manual_step "rekey-store-rotation" "requires daemon stopped; run cara matrix rekey-store --new manually with captured report directory"
# docs/channel-smoke.md lists these as required sign-off evidence
# (#234). The harness cannot drive them automatically (they require a
# second test account / restart cycle / manual restore), but it MUST
# refuse to claim status=completed without operator confirmation that
# each was exercised. Without these markers the run could finish with
# `status=completed` and an empty required-failures.jsonl while the
# inbound-loop, restart-persistence, and recovery-restore evidence
# were never captured — exactly the silent-under-coverage hole the
# review flagged.
record_required_manual_step "token-reuse-across-restart" "operator must stop the daemon, restart it with the same MATRIX_ACCESS_TOKEN / matrix.accessToken + matrix.deviceId, and confirm the device pairing is preserved (no fresh device shows up in cara matrix devices) — pins token-restore session reuse (docs/channel-smoke.md step 2)"
record_required_manual_step "allowlist-positive-invite" "operator must invite the bot's user from an ALLOWED room/inviter (matrix.autoJoin.allowUsers or allowServerNames) and confirm the bot auto-joins — exercises the positive auto-join path, complementing allowlist-negative-invite (docs/channel-smoke.md step 6)"
record_required_manual_step "inbound-unencrypted-agent-run" "operator must send a message FROM the second test account TO the unencrypted room and confirm the agent acted on it (docs/channel-smoke.md step 3)"
record_required_manual_step "inbound-unencrypted-reply" "operator must capture the assistant reply event ID delivered back to the unencrypted room (docs/channel-smoke.md step 4)"
record_required_manual_step "inbound-encrypted-roundtrip" "operator must repeat steps 3-4 in the encrypted room and verify SAS/Olm framing (docs/channel-smoke.md step 5)"
record_required_manual_step "restart-persistent-store" "operator must restart the daemon and confirm session decrypts WITHOUT re-verification — pins persistent SQLite store integrity (docs/channel-smoke.md step 9)"
record_required_manual_step "recovery-key-restore" "operator must stop daemon, move {state_dir}/matrix/recovery_key aside, run cara matrix recovery-key restore --key-file <operator-held-file>, then restart and confirm cross-signing trust state preserved via cara matrix devices (docs/channel-smoke.md step 10)"

if command -v journalctl >/dev/null 2>&1; then
  journalctl --user-unit carapace --since "30 minutes ago" --no-pager \
    >"${report_dir}/journal-user-carapace.log" 2>"${report_dir}/journal-user-carapace.err" || true
else
  record_skip "journald" "journalctl is not available"
fi

if [[ -s "${required_failures_file}" ]]; then
  status="failed"
  printf 'matrix smoke failed required probes; evidence written to %s\n' "${report_dir}" >&2
  exit 1
fi

status="completed"
printf 'matrix smoke evidence written to %s\n' "${report_dir}"
