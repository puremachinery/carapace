#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

python3 - <<'PY'
from pathlib import Path
import re
import sys

root = Path(".")
matrix_rs = (root / "src/channels/matrix.rs").read_text()
control_rs = (root / "src/server/control.rs").read_text()
ws_rs = (root / "src/server/ws/mod.rs").read_text()
cli_rs = (root / "src/cli/mod.rs").read_text()
http_docs = (root / "docs/protocol/http.md").read_text()

errors: list[str] = []

for struct_name in [
    "ConnectParams",
    "ClientInfo",
    "DeviceIdentity",
    "AuthParams",
]:
    pattern = rf"#\[serde\([^\]]*deny_unknown_fields[^\]]*\)\]\s*struct {struct_name}\b"
    if re.search(pattern, ws_rs):
        errors.append(
            f"{struct_name} is a released WS handshake DTO and must not use deny_unknown_fields"
        )

if re.search(
    r"#\[serde\([^\]]*deny_unknown_fields[^\]]*\)\]\s*pub struct MatrixSendTestRequest\b",
    control_rs,
):
    errors.append(
        "MatrixSendTestRequest is a released HTTP DTO and must not use deny_unknown_fields"
    )

if "MatrixError::Auth(format!" in matrix_rs:
    errors.append(
        "MatrixError::Auth(format!(...)) is forbidden; classify homeserver/auth results first"
    )

auth_helper = re.search(
    r"fn matrix_auth_error_from_sdk\(.*?\n\}",
    matrix_rs,
    flags=re.S,
)
if not auth_helper:
    errors.append("matrix_auth_error_from_sdk helper is missing")
else:
    helper_body = auth_helper.group(0)
    if "matrix_sync_terminal_error(err)" not in helper_body:
        errors.append("matrix_auth_error_from_sdk must peel through matrix_sync_terminal_error")
    if "MatrixError::Auth(err.to_string())" not in helper_body:
        errors.append("matrix_auth_error_from_sdk must own the direct MatrixError::Auth fallback")

outside_helper = matrix_rs.replace(auth_helper.group(0), "") if auth_helper else matrix_rs
if "MatrixError::Auth(err.to_string())" in outside_helper:
    errors.append(
        "direct MatrixError::Auth(err.to_string()) outside matrix_auth_error_from_sdk is forbidden"
    )

kind_fn = re.search(r"pub fn kind\(&self\).*?\n    \}", matrix_rs, flags=re.S)
if not kind_fn:
    errors.append("MatrixError::kind() body not found")
    kind_values: set[str] = set()
else:
    kind_values = set(re.findall(r'=>\s*"([a-z0-9-]+)"', kind_fn.group(0)))
    if not kind_values:
        errors.append("MatrixError::kind() exposes no wire values")

kind_test = re.search(
    r"fn test_matrix_error_kind_wire_stable_table\(.*?\n    \}",
    matrix_rs,
    flags=re.S,
)
if not kind_test:
    errors.append("test_matrix_error_kind_wire_stable_table is missing")
else:
    test_body = kind_test.group(0)
    for kind in sorted(kind_values):
        if f'"{kind}"' not in test_body:
            errors.append(f"MatrixError kind {kind!r} is missing from the stable table test")

for kind in sorted(kind_values):
    if kind not in http_docs:
        errors.append(f"MatrixError kind {kind!r} is missing from docs/protocol/http.md")

for kind in [
    "auth-token-revoked",
    "auth-probe",
    "encrypted-store-passphrase-mismatch",
    "interrupted-rekey",
    "missing-store-secret",
    "session-history-corrupt",
    "legacy-dlq-envelope-refused",
    "sync-loop-give-up",
]:
    if f'Some("{kind}")' not in cli_rs:
        errors.append(f"verify_matrix_outcome is missing an operator route for {kind!r}")

rekey_fn = re.search(
    r"fn reencode_matrix_inbound_dlq_lines_for_rekey\(.*?\n\}",
    matrix_rs,
    flags=re.S,
)
if not rekey_fn:
    errors.append("reencode_matrix_inbound_dlq_lines_for_rekey is missing")
else:
    rekey_body = rekey_fn.group(0)
    if (
        "Err(MatrixError::LegacyDlqEnvelopeRefused)" not in rekey_body
        or "return Err(MatrixError::LegacyDlqEnvelopeRefused)" not in rekey_body
    ):
        errors.append(
            "DLQ rekey must preserve typed LegacyDlqEnvelopeRefused instead of wrapping it"
        )

for test_name in [
    "test_rotate_matrix_inbound_dlq_for_rekey_honors_legacy_refuse_policy",
    "test_recover_matrix_inbound_dlq_rekey_honors_legacy_refuse_policy",
]:
    test = re.search(rf"fn {test_name}\(.*?\n    \}}", matrix_rs, flags=re.S)
    if not test:
        errors.append(f"{test_name} is missing")
    elif "matches!(err, MatrixError::LegacyDlqEnvelopeRefused)" not in test.group(0):
        errors.append(
            f"{test_name} must assert the typed LegacyDlqEnvelopeRefused variant"
        )

if errors:
    for error in errors:
        print(f"matrix wire guard: {error}", file=sys.stderr)
    sys.exit(1)
PY
