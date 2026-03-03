#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
report_dir="${repo_root}/.local/reports"
mkdir -p "${report_dir}"

timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
repo="${GITHUB_REPO:-puremachinery/carapace}"
requested_tag="${RELEASE_TAG:-latest}"
asset_name="${CARA_ASSET:-}"
expected_identity_regexp="${EXPECTED_IDENTITY_REGEXP:-https://github.com/puremachinery/carapace/.github/workflows/release.yml@refs/tags/v.*}"
expected_oidc_issuer="${EXPECTED_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/cara-release-verify-${timestamp}-XXXXXX")"
log_path="${report_dir}/release-artifact-verify-${timestamp}.log"
report_path="${report_dir}/release-artifact-verify-${timestamp}.json"

status="pass"
error_msg=""
resolved_tag=""
release_url=""
bundle_name=""
has_checksums="false"
binary_verified="false"
checksums_verified="false"
binary_sha256=""

cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

write_report() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "Warning: python3 not found; skipping JSON report generation for verify-release-artifacts." >&2
    echo "Status: ${status}" >&2
    if [[ -n "${error_msg}" ]]; then
      echo "Error: ${error_msg}" >&2
    fi
    echo "Log: ${log_path}" >&2
    return 0
  fi
  python3 - "${report_path}" "${timestamp}" "${repo}" "${requested_tag}" "${resolved_tag}" "${release_url}" "${asset_name}" "${bundle_name}" "${has_checksums}" "${binary_verified}" "${checksums_verified}" "${binary_sha256}" "${log_path}" "${status}" "${error_msg}" <<'PY'
import json
import sys

(
    report_path,
    timestamp,
    repo,
    requested_tag,
    resolved_tag,
    release_url,
    asset_name,
    bundle_name,
    has_checksums,
    binary_verified,
    checksums_verified,
    binary_sha256,
    log_path,
    status,
    error_msg,
) = sys.argv[1:16]

payload = {
    "suite": "release-artifact-verify",
    "timestampUtc": timestamp,
    "repo": repo,
    "tagRequested": requested_tag,
    "tagResolved": resolved_tag,
    "releaseUrl": release_url,
    "asset": asset_name,
    "bundle": bundle_name,
    "checksumsPresent": has_checksums == "true",
    "binaryVerified": binary_verified == "true",
    "checksumsVerified": checksums_verified == "true",
    "binarySha256": binary_sha256,
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

fail() {
  status="fail"
  error_msg="$1"
  echo "ERROR: ${error_msg}" >>"${log_path}"
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

if jq -e '.assets[] | select(.name == "SHA256SUMS.txt")' >/dev/null <<<"${release_json}" &&
   jq -e '.assets[] | select(.name == "SHA256SUMS.txt.bundle")' >/dev/null <<<"${release_json}"; then
  has_checksums="true"
fi
echo "checksums_present=${has_checksums}" >>"${log_path}"

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

cd "${work_dir}"
chmod +x "./${asset_name}"

{
  echo "== verify binary bundle =="
  echo "\$ cosign verify-blob --bundle ${bundle_name} --certificate-identity-regexp '${expected_identity_regexp}' --certificate-oidc-issuer '${expected_oidc_issuer}' ${asset_name}"
} >>"${log_path}"
if ! cosign verify-blob \
  --bundle "./${bundle_name}" \
  --certificate-identity-regexp "${expected_identity_regexp}" \
  --certificate-oidc-issuer "${expected_oidc_issuer}" \
  "./${asset_name}" >>"${log_path}" 2>&1; then
  fail "binary bundle verification failed"
  write_report
  exit 1
fi
binary_verified="true"

if [[ "${has_checksums}" == "true" ]]; then
  {
    echo "== verify checksums bundle =="
    echo "\$ cosign verify-blob --bundle SHA256SUMS.txt.bundle --certificate-identity-regexp '${expected_identity_regexp}' --certificate-oidc-issuer '${expected_oidc_issuer}' SHA256SUMS.txt"
  } >>"${log_path}"
  if ! cosign verify-blob \
    --bundle "./SHA256SUMS.txt.bundle" \
    --certificate-identity-regexp "${expected_identity_regexp}" \
    --certificate-oidc-issuer "${expected_oidc_issuer}" \
    "./SHA256SUMS.txt" >>"${log_path}" 2>&1; then
    fail "SHA256SUMS bundle verification failed"
    write_report
    exit 1
  fi

  checksum_line="$(grep -E "[[:space:]][*]?${asset_name}$" "./SHA256SUMS.txt" | tail -n 1 || true)"
  if [[ -z "${checksum_line}" ]]; then
    fail "no checksum entry for ${asset_name} in SHA256SUMS.txt"
    write_report
    exit 1
  fi
  expected_sha256="$(awk '{print $1}' <<<"${checksum_line}")"
  if ! actual_sha256="$(compute_sha256 "./${asset_name}")"; then
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
  if ! binary_sha256="$(compute_sha256 "./${asset_name}")"; then
    binary_sha256=""
  fi
fi

{
  echo "== execute binary =="
  echo "\$ ./${asset_name} version"
} >>"${log_path}"
if ! "./${asset_name}" version >>"${log_path}" 2>&1; then
  fail "downloaded binary execution failed"
  write_report
  exit 1
fi

write_report
