#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
report_dir="${repo_root}/.local/reports"
mkdir -p "${report_dir}"

timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
# Keep trust pin defaults fixed to upstream repo/workflow. For forks or alternate repos,
# callers must set EXPECTED_IDENTITY_REGEXP explicitly (enforced below).
default_repo="puremachinery/carapace"
repo="${GITHUB_REPO:-${default_repo}}"
requested_tag="${RELEASE_TAG:-latest}"
asset_name="${CARA_ASSET:-}"
default_identity_regexp="^https://github\\.com/puremachinery/carapace/\\.github/workflows/release\\.yml@refs/tags/v[0-9].*$"
default_oidc_issuer="https://token.actions.githubusercontent.com"
expected_identity_regexp="${EXPECTED_IDENTITY_REGEXP:-${default_identity_regexp}}"
expected_oidc_issuer="${EXPECTED_OIDC_ISSUER:-${default_oidc_issuer}}"
identity_policy_overridden="false"
oidc_policy_overridden="false"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/cara-release-verify-${timestamp}-XXXXXX")"
log_path="${report_dir}/release-artifact-verify-${timestamp}.log"
report_path="${report_dir}/release-artifact-verify-${timestamp}.json"

status="pass"
error_msg=""
resolved_tag=""
release_url=""
bundle_name=""
has_checksums="false"
checksums_file_present="false"
checksums_bundle_present="false"
binary_verified="false"
checksums_verified="false"
binary_sha256=""
report_written="false"

cleanup() {
  rm -rf "${work_dir}"
}

write_report() {
  if [[ "${report_written}" == "true" ]]; then
    return 0
  fi
  report_written="true"

  if ! command -v jq >/dev/null 2>&1; then
    echo "Warning: jq not found; skipping JSON report generation for verify-release-artifacts." >&2
    echo "Status: ${status}" >&2
    if [[ -n "${error_msg}" ]]; then
      echo "Error: ${error_msg}" >&2
    fi
    echo "Log: ${log_path}" >&2
    return 0
  fi
  local checksums_present_json=false
  local binary_verified_json=false
  local checksums_verified_json=false
  local identity_policy_overridden_json=false
  local oidc_policy_overridden_json=false

  if [[ "${has_checksums}" == "true" ]]; then
    checksums_present_json=true
  fi
  if [[ "${binary_verified}" == "true" ]]; then
    binary_verified_json=true
  fi
  if [[ "${checksums_verified}" == "true" ]]; then
    checksums_verified_json=true
  fi
  if [[ "${identity_policy_overridden}" == "true" ]]; then
    identity_policy_overridden_json=true
  fi
  if [[ "${oidc_policy_overridden}" == "true" ]]; then
    oidc_policy_overridden_json=true
  fi

  jq -n \
    --arg suite "release-artifact-verify" \
    --arg timestampUtc "${timestamp}" \
    --arg repo "${repo}" \
    --arg tagRequested "${requested_tag}" \
    --arg tagResolved "${resolved_tag}" \
    --arg releaseUrl "${release_url}" \
    --arg asset "${asset_name}" \
    --arg bundle "${bundle_name}" \
    --argjson checksumsPresent "${checksums_present_json}" \
    --argjson binaryVerified "${binary_verified_json}" \
    --argjson checksumsVerified "${checksums_verified_json}" \
    --arg expectedIdentityRegexp "${expected_identity_regexp}" \
    --arg expectedOidcIssuer "${expected_oidc_issuer}" \
    --argjson identityPolicyOverridden "${identity_policy_overridden_json}" \
    --argjson oidcPolicyOverridden "${oidc_policy_overridden_json}" \
    --arg binarySha256 "${binary_sha256}" \
    --arg logPath "${log_path}" \
    --arg status "${status}" \
    --arg error "${error_msg}" \
    '{
      "suite": $suite,
      "timestampUtc": $timestampUtc,
      "repo": $repo,
      "tagRequested": $tagRequested,
      "tagResolved": $tagResolved,
      "releaseUrl": $releaseUrl,
      "asset": $asset,
      "bundle": $bundle,
      "checksumsPresent": $checksumsPresent,
      "binaryVerified": $binaryVerified,
      "checksumsVerified": $checksumsVerified,
      "expectedIdentityRegexp": $expectedIdentityRegexp,
      "expectedOidcIssuer": $expectedOidcIssuer,
      "identityPolicyOverridden": $identityPolicyOverridden,
      "oidcPolicyOverridden": $oidcPolicyOverridden,
      "binarySha256": $binarySha256,
      "logPath": $logPath,
      "status": $status,
      "error": $error
    }' >"${report_path}"
  echo "Report: ${report_path}"
}

on_exit() {
  local exit_code=$?
  if [[ "${report_written}" != "true" ]]; then
    if [[ "${exit_code}" -ne 0 && "${status}" == "pass" ]]; then
      fail "unexpected script failure (exit ${exit_code})"
    fi
    write_report || true
  fi
  cleanup
}
trap on_exit EXIT

fail() {
  status="fail"
  error_msg="${error_msg:+${error_msg}; }$1"
  echo "ERROR: $1" >>"${log_path}"
}

compute_sha256() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file}" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file}" | awk '{print $1}'
  else
    return 1
  fi
}

default_asset_for_host() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "${os}/${arch}" in
    Darwin/arm64)
      echo "cara-aarch64-darwin"
      ;;
    Darwin/x86_64)
      echo "cara-x86_64-darwin"
      ;;
    Linux/x86_64)
      echo "cara-x86_64-linux"
      ;;
    Linux/aarch64)
      echo "cara-aarch64-linux"
      ;;
    *)
      return 1
      ;;
  esac
}

{
  echo "verify-release-artifacts smoke log"
  echo "timestamp=${timestamp}"
  echo "repo=${repo}"
  echo "requested_tag=${requested_tag}"
  echo "work_dir=${work_dir}"
  echo
} >"${log_path}"

if ! command -v gh >/dev/null 2>&1; then
  fail "gh CLI not installed"
  write_report
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  fail "jq not installed"
  write_report
  exit 1
fi

if ! command -v cosign >/dev/null 2>&1; then
  fail "cosign not installed"
  write_report
  exit 1
fi

if ! gh auth status >>"${log_path}" 2>&1; then
  fail "gh auth not configured"
  write_report
  exit 1
fi

if [[ -z "${asset_name}" ]]; then
  if ! asset_name="$(default_asset_for_host)"; then
    fail "unsupported host platform; set CARA_ASSET explicitly"
    write_report
    exit 1
  fi
fi
bundle_name="${asset_name}.bundle"

if [[ -n "${EXPECTED_IDENTITY_REGEXP:-}" && "${EXPECTED_IDENTITY_REGEXP}" != "${default_identity_regexp}" ]]; then
  identity_policy_overridden="true"
fi
if [[ -n "${EXPECTED_OIDC_ISSUER:-}" && "${EXPECTED_OIDC_ISSUER}" != "${default_oidc_issuer}" ]]; then
  oidc_policy_overridden="true"
fi

if [[ "${identity_policy_overridden}" == "true" ]]; then
  echo "WARNING: EXPECTED_IDENTITY_REGEXP overridden to: ${expected_identity_regexp}" >>"${log_path}"
fi
if [[ "${oidc_policy_overridden}" == "true" ]]; then
  echo "WARNING: EXPECTED_OIDC_ISSUER overridden to: ${expected_oidc_issuer}" >>"${log_path}"
fi

if [[ "${repo}" != "${default_repo}" && -z "${EXPECTED_IDENTITY_REGEXP:-}" ]]; then
  fail "GITHUB_REPO override (${repo}) requires EXPECTED_IDENTITY_REGEXP to keep trust policy explicit"
  write_report
  exit 1
fi

if [[ "${requested_tag}" == "latest" ]]; then
  if ! release_json="$(gh release view --repo "${repo}" --json tagName,url,assets 2>>"${log_path}")"; then
    fail "failed to query latest release metadata"
    write_report
    exit 1
  fi
else
  if ! release_json="$(gh release view "${requested_tag}" --repo "${repo}" --json tagName,url,assets 2>>"${log_path}")"; then
    fail "failed to query release metadata for tag ${requested_tag}"
    write_report
    exit 1
  fi
fi

resolved_tag="$(jq -r '.tagName' <<<"${release_json}")"
release_url="$(jq -r '.url' <<<"${release_json}")"
{
  echo "resolved_tag=${resolved_tag}"
  echo "release_url=${release_url}"
  echo "asset_name=${asset_name}"
  echo "bundle_name=${bundle_name}"
  echo "expected_identity_regexp=${expected_identity_regexp}"
  echo "expected_oidc_issuer=${expected_oidc_issuer}"
  echo "identity_policy_overridden=${identity_policy_overridden}"
  echo "oidc_policy_overridden=${oidc_policy_overridden}"
} >>"${log_path}"

if ! jq -e --arg n "${asset_name}" '.assets[] | select(.name == $n)' >/dev/null <<<"${release_json}"; then
  fail "release ${resolved_tag} does not contain asset ${asset_name}"
  write_report
  exit 1
fi

if ! jq -e --arg n "${bundle_name}" '.assets[] | select(.name == $n)' >/dev/null <<<"${release_json}"; then
  fail "release ${resolved_tag} does not contain required bundle ${bundle_name}"
  write_report
  exit 1
fi

if jq -e '.assets[] | select(.name == "SHA256SUMS.txt")' >/dev/null <<<"${release_json}"; then
  checksums_file_present="true"
fi
if jq -e '.assets[] | select(.name == "SHA256SUMS.txt.bundle")' >/dev/null <<<"${release_json}"; then
  checksums_bundle_present="true"
fi
if [[ "${checksums_file_present}" != "${checksums_bundle_present}" ]]; then
  fail "inconsistent checksum assets: SHA256SUMS.txt present=${checksums_file_present}, SHA256SUMS.txt.bundle present=${checksums_bundle_present}"
  write_report
  exit 1
fi
if [[ "${checksums_file_present}" == "true" && "${checksums_bundle_present}" == "true" ]]; then
  has_checksums="true"
fi
{
  echo "checksums_file_present=${checksums_file_present}"
  echo "checksums_bundle_present=${checksums_bundle_present}"
  echo "checksums_present=${has_checksums}"
} >>"${log_path}"

download_args=(
  release download "${resolved_tag}"
  --repo "${repo}"
  --dir "${work_dir}"
  --pattern "${asset_name}"
  --pattern "${bundle_name}"
)
if [[ "${has_checksums}" == "true" ]]; then
  download_args+=(--pattern "SHA256SUMS.txt" --pattern "SHA256SUMS.txt.bundle")
fi

{
  echo "== download =="
  printf '$ gh'
  printf ' %q' "${download_args[@]}"
  echo
} >>"${log_path}"

if ! gh "${download_args[@]}" >>"${log_path}" 2>&1; then
  fail "failed to download release artifacts"
  write_report
  exit 1
fi

asset_path="${work_dir}/${asset_name}"
bundle_path="${work_dir}/${bundle_name}"
checksums_path="${work_dir}/SHA256SUMS.txt"
checksums_bundle_path="${work_dir}/SHA256SUMS.txt.bundle"

chmod +x "${asset_path}"

{
  echo "== verify binary bundle =="
  echo "\$ cosign verify-blob --bundle ${bundle_path} --certificate-identity-regexp '${expected_identity_regexp}' --certificate-oidc-issuer '${expected_oidc_issuer}' ${asset_path}"
} >>"${log_path}"
if ! cosign verify-blob \
  --bundle "${bundle_path}" \
  --certificate-identity-regexp "${expected_identity_regexp}" \
  --certificate-oidc-issuer "${expected_oidc_issuer}" \
  "${asset_path}" >>"${log_path}" 2>&1; then
  fail "binary bundle verification failed"
  write_report
  exit 1
fi
binary_verified="true"

if [[ "${has_checksums}" == "true" ]]; then
  {
    echo "== verify checksums bundle =="
    echo "\$ cosign verify-blob --bundle ${checksums_bundle_path} --certificate-identity-regexp '${expected_identity_regexp}' --certificate-oidc-issuer '${expected_oidc_issuer}' ${checksums_path}"
  } >>"${log_path}"
  if ! cosign verify-blob \
    --bundle "${checksums_bundle_path}" \
    --certificate-identity-regexp "${expected_identity_regexp}" \
    --certificate-oidc-issuer "${expected_oidc_issuer}" \
    "${checksums_path}" >>"${log_path}" 2>&1; then
    fail "SHA256SUMS bundle verification failed"
    write_report
    exit 1
  fi

  checksum_status=0
  expected_sha256="$(
    awk -v asset="${asset_name}" '
      BEGIN { count = 0 }
      {
        filename = $2
        sub(/^\*/, "", filename)
        if (filename == asset) {
          print $1
          count++
        }
      }
      END {
        if (count == 0) exit 2
        if (count > 1) exit 3
      }
    ' "${checksums_path}"
  )" || checksum_status=$?
  if [[ "${checksum_status}" -eq 2 ]]; then
    fail "no checksum entry for ${asset_name} in SHA256SUMS.txt"
    write_report
    exit 1
  fi
  if [[ "${checksum_status}" -eq 3 ]]; then
    fail "multiple checksum entries for ${asset_name} in SHA256SUMS.txt"
    write_report
    exit 1
  fi
  if [[ "${checksum_status}" -ne 0 || -z "${expected_sha256}" ]]; then
    fail "failed to parse checksum entry for ${asset_name}"
    write_report
    exit 1
  fi
  if ! actual_sha256="$(compute_sha256 "${asset_path}")"; then
    fail "no local sha256 tool found (sha256sum/shasum)"
    write_report
    exit 1
  fi
  binary_sha256="${actual_sha256}"
  if [[ "${expected_sha256}" != "${actual_sha256}" ]]; then
    fail "checksum mismatch for ${asset_name}"
    write_report
    exit 1
  fi
  checksums_verified="true"
else
  if ! binary_sha256="$(compute_sha256 "${asset_path}")"; then
    binary_sha256=""
  fi
fi

{
  echo "== execute binary =="
  echo "\$ ${asset_path} version"
} >>"${log_path}"
if ! "${asset_path}" version >>"${log_path}" 2>&1; then
  fail "downloaded binary execution failed"
  write_report
  exit 1
fi

write_report
