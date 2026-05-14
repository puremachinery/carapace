#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

python3 - "$@" <<'PY'
from dataclasses import dataclass, replace
from pathlib import Path
import re
import sys


CLI_VERIFIER_EXCEPTIONS = {
    "allowlist-too-large": "configuration resolver reports this before runtime status polling",
    "device-not-found": "verification subcommands surface this as request-scoped 404",
    "invalid-bool": "configuration resolver reports this before runtime status polling",
    "invalid-config-root": "configuration resolver reports this before runtime status polling",
    "invalid-length": "configuration resolver reports this before runtime status polling",
    "invalid-string": "configuration resolver reports this before runtime status polling",
    "invalid-string-array": "configuration resolver reports this before runtime status polling",
    "invalid-url": "configuration resolver reports this before runtime status polling",
    "invalid-user-id": "request DTO validation surfaces this before runtime readiness polling",
    "missing-credentials": "configuration resolver reports this before runtime status polling",
    "missing-device-id-for-token-restore": "configuration resolver reports this before runtime status polling",
    "missing-homeserver-url": "configuration resolver reports this before runtime status polling",
    "missing-user-id": "configuration resolver reports this before runtime status polling",
    "room-not-found": "send-test surfaces this as request-scoped 404",
    "send-terminal": "send-test surfaces this as request-scoped permanent 422",
    "unsupported-room": "send-test surfaces this as request-scoped 422",
    "user-identity-not-found": "verification subcommands surface this as request-scoped 404",
    "verification": "verification subcommands surface this at the action boundary",
    "verification-cancelled": "verification subcommands surface this as request-scoped 410",
    "verification-flow-not-found": "verification subcommands surface this as request-scoped 404",
    "verification-flow-not-ready": "verification subcommands surface this as request-scoped 409",
    "verification-timeout": "verification subcommands surface this as request-scoped 504",
}

CONTROL_NO_RETRY_AFTER_KINDS = {
    "allowlist-too-large",
    "auth",
    "auth-session-device-mismatch",
    "auth-session-missing-device-id",
    "auth-session-user-mismatch",
    "auth-token-revoked",
    "client-build",
    "clock",
    "device-not-found",
    "e2ee",
    "encrypted-store-passphrase-mismatch",
    "installation-id",
    "interrupted-rekey",
    "invalid-bool",
    "invalid-config-root",
    "invalid-length",
    "invalid-string",
    "invalid-string-array",
    "invalid-url",
    "invalid-user-id",
    "legacy-dlq-envelope-refused",
    "missing-credentials",
    "missing-device-id-for-token-restore",
    "missing-homeserver-url",
    "missing-store-secret",
    "missing-user-id",
    "room-not-found",
    "send-failed",
    "send-terminal",
    "session-history-corrupt",
    "startup-failed",
    "store-key-derivation",
    "sync-failed",
    "sync-loop-give-up",
    "token-persistence",
    "unsupported-room",
    "user-identity-not-found",
    "verification",
    "verification-cancelled",
    "verification-flow-not-found",
    "verification-flow-not-ready",
    "verification-timeout",
}


@dataclass(frozen=True)
class Sources:
    matrix_rs: str
    control_rs: str
    ws_rs: str
    cli_rs: str
    http_docs: str


def load_sources() -> Sources:
    root = Path(".")
    return Sources(
        matrix_rs=(root / "src/channels/matrix.rs").read_text(),
        control_rs=(root / "src/server/control.rs").read_text(),
        ws_rs=(root / "src/server/ws/mod.rs").read_text(),
        cli_rs=(root / "src/cli/mod.rs").read_text(),
        http_docs=(root / "docs/protocol/http.md").read_text(),
    )


def mask_comments_and_strings(text: str) -> str:
    chars = list(text)
    i = 0
    state = "normal"
    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""
        if state == "normal":
            if ch == "/" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "line_comment"
                continue
            if ch == "/" and nxt == "*":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "block_comment"
                continue
            if ch == '"':
                chars[i] = " "
                i += 1
                state = "string"
                continue
            i += 1
            continue
        if state == "line_comment":
            if ch == "\n":
                state = "normal"
            else:
                chars[i] = " "
            i += 1
            continue
        if state == "block_comment":
            if ch == "*" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "normal"
            else:
                chars[i] = " "
                i += 1
            continue
        if state == "string":
            if ch == "\\":
                chars[i] = " "
                if i + 1 < len(chars):
                    chars[i + 1] = " "
                i += 2
                continue
            if ch == '"':
                chars[i] = " "
                i += 1
                state = "normal"
                continue
            chars[i] = " "
            i += 1
            continue
    return "".join(chars)


def find_balanced_block(text: str, needle: str) -> str:
    start = text.find(needle)
    if start == -1:
        raise ValueError(f"{needle!r} not found")
    brace = text.find("{", start)
    if brace == -1:
        raise ValueError(f"{needle!r} has no opening brace")
    masked = mask_comments_and_strings(text)
    depth = 0
    for index in range(brace, len(text)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise ValueError(f"{needle!r} block is not balanced")


def production_matrix_source(matrix_rs: str) -> str:
    marker = "\n#[cfg(test)]\nmod tests"
    index = matrix_rs.find(marker)
    return matrix_rs[:index] if index != -1 else matrix_rs


def parse_kind_table(matrix_rs: str) -> tuple[dict[str, str], list[str]]:
    errors: list[str] = []
    try:
        body = find_balanced_block(matrix_rs, "pub fn kind(&self)")
    except ValueError as err:
        return {}, [f"MatrixError::kind() body not found: {err}"]

    pattern = re.compile(
        r"MatrixError::([A-Za-z0-9_]+)\s*(?:\([^)]*\)|\{[^{}]*\})?\s*=>\s*(?:\{\s*)?\"([a-z0-9-]+)\"",
        re.S,
    )
    by_variant = {variant: kind for variant, kind in pattern.findall(body)}
    if not by_variant:
        errors.append("MatrixError::kind() exposes no structured wire values")
    duplicate_kinds = sorted(
        kind for kind in set(by_variant.values()) if list(by_variant.values()).count(kind) > 1
    )
    for kind in duplicate_kinds:
        errors.append(f"MatrixError kind {kind!r} is returned by multiple variants")
    return by_variant, errors


def parse_docs_kinds(http_docs: str) -> set[str]:
    lines = http_docs.splitlines()
    start = None
    for idx, line in enumerate(lines):
        if line.strip().startswith("| `lastErrorKind` |"):
            start = idx + 2
            break
    if start is None:
        return set()
    kinds: set[str] = set()
    for line in lines[start:]:
        stripped = line.strip()
        if not stripped.startswith("|"):
            break
        cells = stripped.split("|")
        if len(cells) < 3:
            continue
        first_cell = cells[1]
        kinds.update(re.findall(r"`([a-z0-9-]+)`", first_cell))
    return kinds


def parse_cli_verifier_kinds(cli_rs: str) -> tuple[set[str], list[str]]:
    try:
        body = find_balanced_block(cli_rs, "async fn verify_matrix_outcome")
    except ValueError as err:
        return set(), [f"verify_matrix_outcome body not found: {err}"]
    return set(re.findall(r"Some\(\"([a-z0-9-]+)\"\)\s*=>", body)), []


def matrix_variants_in_block(block: str) -> set[str]:
    return set(re.findall(r"\bMatrixError::([A-Za-z0-9_]+)\b", block))


def find_auth_constructor_spans(matrix_rs: str) -> list[tuple[int, int]]:
    source = production_matrix_source(matrix_rs)
    masked = mask_comments_and_strings(source)
    return [
        match.span()
        for match in re.finditer(r"\bMatrixError::Auth\s*\((?!\s*_\s*\))", masked)
    ]


def allowed_auth_constructor_spans(matrix_rs: str) -> list[tuple[int, int]]:
    source = production_matrix_source(matrix_rs)
    spans: list[tuple[int, int]] = []
    for match in re.finditer(r"\bfn\s+[A-Za-z0-9_]+\s*\(", source):
        try:
            block = find_balanced_block(source, match.group(0))
        except ValueError:
            continue
        if (
            "matrix_sync_terminal_error(err)" in block
            and "err.client_api_error_kind().is_some()" in block
            and re.search(r"\bMatrixError::Auth\s*\((?!\s*_\s*\))", mask_comments_and_strings(block))
        ):
            block_start = match.start()
            spans.append((block_start, block_start + len(block)))
    return spans


def check_auth_construction(matrix_rs: str) -> list[str]:
    errors: list[str] = []
    constructors = find_auth_constructor_spans(matrix_rs)
    allowed = allowed_auth_constructor_spans(matrix_rs)
    if not allowed:
        errors.append(
            "classifier-owned MatrixError::Auth construction helper is missing"
        )
    for start, _end in constructors:
        if not any(allowed_start <= start < allowed_end for allowed_start, allowed_end in allowed):
            line = production_matrix_source(matrix_rs).count("\n", 0, start) + 1
            errors.append(
                f"direct MatrixError::Auth construction outside the classifier-owned helper at src/channels/matrix.rs:{line}"
            )
    return errors


def check_released_dtos(sources: Sources) -> list[str]:
    errors: list[str] = []
    for struct_name in [
        "ConnectParams",
        "ClientInfo",
        "DeviceIdentity",
        "AuthParams",
    ]:
        pattern = rf"#\[serde\([^\]]*deny_unknown_fields[^\]]*\)\]\s*struct {struct_name}\b"
        if re.search(pattern, sources.ws_rs):
            errors.append(
                f"{struct_name} is a released WS handshake DTO and must not use deny_unknown_fields"
            )

    if re.search(
        r"#\[serde\([^\]]*deny_unknown_fields[^\]]*\)\]\s*pub struct MatrixSendTestRequest\b",
        sources.control_rs,
    ):
        errors.append(
            "MatrixSendTestRequest is a released HTTP DTO and must not use deny_unknown_fields"
        )
    return errors


def check_kind_stable_table(matrix_rs: str, kinds: set[str]) -> list[str]:
    errors: list[str] = []
    try:
        body = find_balanced_block(matrix_rs, "fn test_matrix_error_kind_wire_stable_table")
    except ValueError as err:
        return [f"test_matrix_error_kind_wire_stable_table is missing: {err}"]
    for kind in sorted(kinds):
        if f'"{kind}"' not in body:
            errors.append(f"MatrixError kind {kind!r} is missing from the stable table test")
    return errors


def check_docs(http_docs: str, kinds: set[str]) -> list[str]:
    documented = parse_docs_kinds(http_docs)
    errors: list[str] = []
    if not documented:
        errors.append("docs/protocol/http.md lastErrorKind table was not found")
        return errors
    for kind in sorted(kinds - documented):
        errors.append(f"MatrixError kind {kind!r} is missing from the structured docs table")
    return errors


def check_cli_partition(cli_rs: str, kinds: set[str]) -> list[str]:
    routed, errors = parse_cli_verifier_kinds(cli_rs)
    exceptions = set(CLI_VERIFIER_EXCEPTIONS)
    for kind in sorted(routed - kinds):
        errors.append(f"verify_matrix_outcome routes unknown Matrix kind {kind!r}")
    for kind in sorted(exceptions - kinds):
        errors.append(f"CLI verifier exception table names unknown Matrix kind {kind!r}")
    for kind in sorted(routed & exceptions):
        errors.append(f"Matrix kind {kind!r} is both routed by CLI and excepted")
    for kind in sorted(kinds - routed - exceptions):
        errors.append(
            f"Matrix kind {kind!r} is missing from verify_matrix_outcome and the CLI exception table"
        )
    return errors


def check_http_projection(control_rs: str, by_variant: dict[str, str]) -> list[str]:
    errors: list[str] = []
    try:
        response = find_balanced_block(control_rs, "fn matrix_runtime_error_response")
    except ValueError as err:
        return [f"matrix_runtime_error_response body not found: {err}"]
    status_match = response.split("let body =", 1)[0]
    status_variants = matrix_variants_in_block(status_match)
    for variant in sorted(set(by_variant) - status_variants):
        errors.append(
            f"matrix_runtime_error_response is missing MatrixError::{variant} status coverage"
        )

    try:
        retry = find_balanced_block(control_rs, "fn matrix_control_retry_projection")
    except ValueError as err:
        errors.append(f"matrix_control_retry_projection body not found: {err}")
        return errors
    retry_variants = matrix_variants_in_block(retry)
    unknown_retry_variants = retry_variants - set(by_variant)
    for variant in sorted(unknown_retry_variants):
        errors.append(
            f"matrix_control_retry_projection references unknown MatrixError::{variant}"
        )
    retry_kinds = {by_variant[variant] for variant in retry_variants if variant in by_variant}
    no_retry_kinds = set(CONTROL_NO_RETRY_AFTER_KINDS)
    kinds = set(by_variant.values())
    for kind in sorted(no_retry_kinds - kinds):
        errors.append(f"control no-retry table names unknown Matrix kind {kind!r}")
    for kind in sorted(retry_kinds & no_retry_kinds):
        errors.append(f"Matrix kind {kind!r} is both retryable and no-retry in control projection")
    for kind in sorted(kinds - retry_kinds - no_retry_kinds):
        errors.append(
            f"Matrix kind {kind!r} is missing from matrix_control_retry_projection and the no-retry table"
        )
    return errors


def check_ws_runtime_projection(matrix_rs: str) -> list[str]:
    errors: list[str] = []
    try:
        metadata = find_balanced_block(matrix_rs, "pub struct MatrixStatusMetadata")
    except ValueError as err:
        return [f"MatrixStatusMetadata body not found: {err}"]
    if "pub last_error_kind: Option<String>" not in metadata:
        errors.append("MatrixStatusMetadata is missing last_error_kind")
    if '#[serde(rename_all = "camelCase")]' not in matrix_rs[: matrix_rs.find("pub struct MatrixStatusMetadata")]:
        errors.append("MatrixStatusMetadata must serialize last_error_kind as lastErrorKind")

    try:
        stamp = find_balanced_block(matrix_rs, "fn stamp_matrix_runtime_error")
    except ValueError as err:
        errors.append(f"stamp_matrix_runtime_error body not found: {err}")
    else:
        if "status.last_error_kind = Some(err.kind().to_string())" not in stamp:
            errors.append(
                "stamp_matrix_runtime_error must project MatrixError::kind() into runtime last_error_kind"
            )

    try:
        test = find_balanced_block(matrix_rs, "fn test_pinned_matrix_status_metadata_wire_shape")
    except ValueError as err:
        errors.append(f"test_pinned_matrix_status_metadata_wire_shape is missing: {err}")
    else:
        if '"lastErrorKind"' not in test or '"last_error_kind"' not in test:
            errors.append(
                "MatrixStatusMetadata wire-shape test must pin lastErrorKind and reject last_error_kind"
            )
    return errors


def check_dlq_policy_regressions(matrix_rs: str) -> list[str]:
    errors: list[str] = []
    try:
        body = find_balanced_block(matrix_rs, "fn reencode_matrix_inbound_dlq_lines_for_rekey")
    except ValueError as err:
        errors.append(f"reencode_matrix_inbound_dlq_lines_for_rekey is missing: {err}")
    else:
        if (
            "Err(MatrixError::LegacyDlqEnvelopeRefused)" not in body
            or "return Err(MatrixError::LegacyDlqEnvelopeRefused)" not in body
        ):
            errors.append(
                "DLQ rekey must preserve typed LegacyDlqEnvelopeRefused instead of wrapping it"
            )

    for test_name in [
        "test_rotate_matrix_inbound_dlq_for_rekey_honors_legacy_refuse_policy",
        "test_recover_matrix_inbound_dlq_rekey_honors_legacy_refuse_policy",
    ]:
        try:
            body = find_balanced_block(matrix_rs, f"fn {test_name}")
        except ValueError:
            errors.append(f"{test_name} is missing")
            continue
        if "matches!(err, MatrixError::LegacyDlqEnvelopeRefused)" not in body:
            errors.append(
                f"{test_name} must assert the typed LegacyDlqEnvelopeRefused variant"
            )
    return errors


def run_checks(sources: Sources) -> list[str]:
    errors: list[str] = []
    by_variant, kind_errors = parse_kind_table(sources.matrix_rs)
    errors.extend(kind_errors)
    kinds = set(by_variant.values())

    errors.extend(check_released_dtos(sources))
    errors.extend(check_auth_construction(sources.matrix_rs))
    errors.extend(check_kind_stable_table(sources.matrix_rs, kinds))
    errors.extend(check_docs(sources.http_docs, kinds))
    errors.extend(check_cli_partition(sources.cli_rs, kinds))
    errors.extend(check_http_projection(sources.control_rs, by_variant))
    errors.extend(check_ws_runtime_projection(sources.matrix_rs))
    errors.extend(check_dlq_policy_regressions(sources.matrix_rs))
    return errors


def assert_fixture_fails(name: str, sources: Sources, expected: str) -> list[str]:
    errors = run_checks(sources)
    if not errors:
        return [f"self-test fixture {name!r} unexpectedly passed"]
    if not any(expected in error for error in errors):
        joined = "; ".join(errors[:5])
        return [
            f"self-test fixture {name!r} failed for the wrong reason; expected {expected!r}; got {joined}"
        ]
    return []


def run_self_test() -> list[str]:
    sources = load_sources()
    baseline = run_checks(sources)
    if baseline:
        return ["self-test baseline guard run failed before mutation"] + baseline

    errors: list[str] = []
    errors.extend(
        assert_fixture_fails(
            "missing docs row",
            replace(
                sources,
                http_docs=sources.http_docs.replace("`auth-token-revoked`", "`auth-token-revoked-missing`", 1),
            ),
            "auth-token-revoked",
        )
    )
    errors.extend(
        assert_fixture_fails(
            "missing CLI verifier route",
            replace(
                sources,
                cli_rs=sources.cli_rs.replace('Some("auth-probe")', 'Some("auth-probe-missing")', 1),
            ),
            "auth-probe",
        )
    )
    errors.extend(
        assert_fixture_fails(
            "missing HTTP status projection",
            replace(
                sources,
                control_rs=sources.control_rs.replace("| MatrixError::AuthProbe(_)", "| MatrixError::AuthProbeMissing(_)", 1),
            ),
            "AuthProbe",
        )
    )
    errors.extend(
        assert_fixture_fails(
            "missing retry projection",
            replace(
                sources,
                control_rs=sources.control_rs.replace(
                    "| MatrixError::AuthProbe(_) => Some(default_matrix_control_retry_projection()),",
                    "=> Some(default_matrix_control_retry_projection()),",
                    1,
                ),
            ),
            "auth-probe",
        )
    )
    insertion = (
        "\nfn r56_illegal_auth_construction(err: &matrix_sdk::Error) -> MatrixError {\n"
        "    MatrixError::Auth ( err.to_string() )\n"
        "}\n"
    )
    errors.extend(
        assert_fixture_fails(
            "illegal Auth construction",
            replace(
                sources,
                matrix_rs=sources.matrix_rs.replace("\n#[cfg(test)]\nmod tests", insertion + "\n#[cfg(test)]\nmod tests", 1),
            ),
            "direct MatrixError::Auth construction outside",
        )
    )
    return errors


def main() -> int:
    args = sys.argv[1:]
    if args == ["--self-test"]:
        errors = run_self_test()
    elif not args:
        errors = run_checks(load_sources())
    else:
        print("usage: scripts/check-matrix-wire-guards.sh [--self-test]", file=sys.stderr)
        return 2

    if errors:
        for error in errors:
            print(f"matrix wire guard: {error}", file=sys.stderr)
        return 1
    return 0


raise SystemExit(main())
PY
