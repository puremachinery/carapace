#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

python3 - "$@" <<'PY'
from __future__ import annotations
from dataclasses import dataclass, replace
from pathlib import Path
import re
import sys


CONTROL_NO_RETRY_AFTER_KINDS = {
    "allowlist-too-large",
    "auth",
    "auth-session-device-mismatch",
    "auth-session-missing-device-id",
    "auth-session-user-mismatch",
    "auth-token-revoked",
    "client-build",
    "clock",
    "cross-signing-bootstrap-failed",
    "device-not-found",
    "dlq-cap-saturation",
    "dlq-decryption",
    "dlq-dispatch-failure",
    "dlq-io",
    "dlq-serialization",
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
    "recovery-key-restore-failed",
    "recovery-state-io",
    "recovery-state-probe-failed",
    "room-not-found",
    "send-terminal",
    "session-history-corrupt",
    "startup-failed",
    "store-passphrase-io",
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

CONTROL_CONDITIONAL_RETRY_AFTER_KINDS = {
    "send-failed",
}


@dataclass(frozen=True)
class MatrixSource:
    path: str
    source: str
    production_source: str


@dataclass(frozen=True)
class Sources:
    matrix_rs: str
    matrix_modules_rs: str
    matrix_sources: tuple[MatrixSource, ...]
    control_rs: str
    ws_rs: str
    cli_rs: str
    http_docs: str


def load_sources() -> Sources:
    root = Path(".")
    matrix_main_path = root / "src/channels/matrix.rs"
    if not matrix_main_path.is_file():
        raise FileNotFoundError(
            f"required Matrix source file not found: {matrix_main_path} "
            f"(run from the repository root; cwd={Path.cwd()})"
        )
    matrix_submodule_paths = [
        root / "src/channels/matrix/inbound_dlq.rs",
        root / "src/channels/matrix/recovery.rs",
        root / "src/channels/matrix/verification.rs",
    ]
    matrix_rs = matrix_main_path.read_text()
    matrix_sources = [
        MatrixSource(
            str(matrix_main_path),
            matrix_rs,
            production_matrix_source(matrix_rs),
        )
    ]
    for path in matrix_submodule_paths:
        if path.exists():
            if not path.is_file():
                raise FileNotFoundError(
                    f"Matrix source path exists but is not a file: {path} "
                    f"(run from the repository root; cwd={Path.cwd()})"
                )
            source = path.read_text()
            matrix_sources.append(
                MatrixSource(str(path), source, production_matrix_source(source))
            )
    return Sources(
        matrix_rs=matrix_rs,
        matrix_modules_rs="\n".join(source.source for source in matrix_sources),
        matrix_sources=tuple(matrix_sources),
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


def split_top_level_attributes(attr_block: str) -> list[str]:
    """Split a contiguous `#[...]` attribute block into individual
    `#[...]` attributes, returning each attribute's raw text. Bracket
    balancing uses the comment-and-string-masked source so a bracket
    inside a comment or string cannot derail the split."""
    masked = mask_comments_and_strings(attr_block)
    out: list[str] = []
    i = 0
    n = len(attr_block)
    while i < n:
        if masked[i].isspace():
            i += 1
            continue
        if attr_block[i] != "#" or attr_block[i:i + 2] != "#[":
            break
        depth = 1
        j = i + 2
        while j < n and depth > 0:
            ch = masked[j]
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
            j += 1
        out.append(attr_block[i:j])
        i = j
    return out


def serde_attribute_inner(attr: str) -> str | None:
    """Return the inner argument text of a top-level `#[serde(...)]`
    attribute, or None if the attribute is not a top-level serde
    attribute (`cfg_attr`, `doc`, `deprecated`, etc.).

    `cfg_attr(any(), serde(...))` is intentionally NOT treated as a
    serde attribute — wire-shape attributes that fire conditionally
    are not guaranteed to be active and must be reported as missing.
    """
    masked = mask_comments_and_strings(attr)
    m = re.match(r"#\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", masked)
    if not m or m.group(1) != "serde":
        return None
    open_paren = attr.index("(", m.start(1))
    depth = 1
    j = open_paren + 1
    while j < len(attr) and depth > 0:
        ch = masked[j]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return attr[open_paren + 1:j]
        j += 1
    return None


def has_serde_rename_all_camel_case(attr_block: str) -> bool:
    """True iff a top-level `#[serde(rename_all = "camelCase")]`
    attribute is present in the block. Substring `rename_all =
    "camelCase"` inside a `#[doc = ...]` payload, a `cfg_attr`
    wrapper, or a similar non-serde attribute is intentionally NOT
    accepted — the wire-shape must be unconditional."""
    for attr in split_top_level_attributes(attr_block):
        inner = serde_attribute_inner(attr)
        if inner is None:
            continue
        if 'rename_all = "camelCase"' in inner:
            return True
    return False


def has_serde_deny_unknown_fields(attr_block: str) -> bool:
    """True iff a top-level `#[serde(... deny_unknown_fields ...)]`
    attribute is present in the block. The check looks for the bare
    `deny_unknown_fields` ident inside any serde attribute (so a
    contributor cannot split `deny_unknown_fields` into a sibling
    `#[serde(...)]` to slip past the wire guard)."""
    for attr in split_top_level_attributes(attr_block):
        inner = serde_attribute_inner(attr)
        if inner is None:
            continue
        if re.search(r"\bdeny_unknown_fields\b", mask_comments_and_strings(inner)):
            return True
    return False


def attribute_block_before(text: str, anchor: str) -> str:
    """Return the contiguous `#[...]` attribute block (with original text
    contents) immediately above the first occurrence of ``anchor``.

    Walks backward over whitespace, then over balanced `[...]` brackets
    that are preceded by ``#``, repeating until a non-attribute token is
    encountered. Bracket walking uses the comment-and-string-masked
    source so a `]` inside a comment cannot close an attribute and so a
    commented-out attribute is not credited.
    """
    idx = text.find(anchor)
    if idx == -1:
        return ""
    masked = mask_comments_and_strings(text)
    end = idx
    while True:
        cursor = end - 1
        while cursor >= 0 and masked[cursor].isspace():
            cursor -= 1
        if cursor < 0 or masked[cursor] != "]":
            break
        depth = 1
        bracket = cursor - 1
        while bracket >= 0:
            ch = masked[bracket]
            if ch == "]":
                depth += 1
            elif ch == "[":
                depth -= 1
                if depth == 0:
                    break
            bracket -= 1
        if bracket <= 0 or masked[bracket - 1] != "#":
            break
        end = bracket - 1
    return text[end:idx]


def production_matrix_source(matrix_rs: str) -> str:
    marker = "\n#[cfg(test)]\nmod tests"
    index = matrix_rs.find(marker)
    return matrix_rs[:index] if index != -1 else matrix_rs


def line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def matrix_source_text(sources: Sources, path: str) -> str:
    for source in sources.matrix_sources:
        if source.path == path:
            return source.source
    raise ValueError(f"Matrix source {path!r} not loaded")


def replace_matrix_source(sources: Sources, path: str, source: str) -> Sources:
    updated = False
    matrix_sources: list[MatrixSource] = []
    for current in sources.matrix_sources:
        if current.path == path:
            updated = True
            matrix_sources.append(
                MatrixSource(path, source, production_matrix_source(source))
            )
        else:
            matrix_sources.append(current)
    if not updated:
        raise ValueError(f"Matrix source {path!r} not loaded")
    return replace(
        sources,
        matrix_rs=next(
            item.source
            for item in matrix_sources
            if item.path == "src/channels/matrix.rs"
        ),
        matrix_modules_rs="\n".join(item.source for item in matrix_sources),
        matrix_sources=tuple(matrix_sources),
    )


def insert_before_test_module(source: str, insertion: str) -> str:
    marker = "\n#[cfg(test)]\nmod tests"
    if marker in source:
        return source.replace(marker, insertion + marker, 1)
    return source + insertion


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


def parse_cli_verifier_exceptions(cli_rs: str) -> tuple[dict[str, str], list[str]]:
    """Parse the code-level Matrix CLI verifier exception table.

    The canonical source of truth is the
    ``MATRIX_CLI_VERIFIER_EXCEPTIONS`` const in ``src/cli/mod.rs``.
    Locate the const, walk balanced ``[ ... ]`` brackets over the
    comment-masked source so a stray ``]`` inside a comment cannot
    close the array, then scan the original array body for
    ``("kind", "justification")`` pairs.
    """
    errors: list[str] = []
    anchor = "const MATRIX_CLI_VERIFIER_EXCEPTIONS"
    start = cli_rs.find(anchor)
    if start == -1:
        return {}, [
            "MATRIX_CLI_VERIFIER_EXCEPTIONS const not found in src/cli/mod.rs"
        ]
    # The const has a `&[(&str, &str)]` type annotation that itself
    # contains a `&[` — skip past the `=` to find the array initializer.
    eq_idx = cli_rs.find("=", start)
    if eq_idx == -1:
        return {}, [
            "MATRIX_CLI_VERIFIER_EXCEPTIONS const has no `=` initializer"
        ]
    bracket = cli_rs.find("&[", eq_idx)
    if bracket == -1:
        return {}, [
            "MATRIX_CLI_VERIFIER_EXCEPTIONS const has no `&[` array opener"
        ]
    open_idx = bracket + 1
    masked = mask_comments_and_strings(cli_rs)
    depth = 0
    end = None
    for idx in range(open_idx, len(cli_rs)):
        if masked[idx] == "[":
            depth += 1
        elif masked[idx] == "]":
            depth -= 1
            if depth == 0:
                end = idx + 1
                break
    if end is None:
        return {}, [
            "MATRIX_CLI_VERIFIER_EXCEPTIONS array is unbalanced"
        ]
    body = cli_rs[open_idx:end]
    entries: dict[str, str] = {}
    for match in re.finditer(
        r'\(\s*"([a-z0-9-]+)"\s*,\s*"([^"]+)"\s*,?\s*\)',
        body,
    ):
        kind, justification = match.group(1), match.group(2)
        if not justification.strip():
            errors.append(
                f"MATRIX_CLI_VERIFIER_EXCEPTIONS entry for {kind!r} is missing a justification"
            )
            continue
        if kind in entries:
            errors.append(
                f"MATRIX_CLI_VERIFIER_EXCEPTIONS contains a duplicate entry for {kind!r}"
            )
            continue
        entries[kind] = justification
    if not entries and not errors:
        errors.append(
            "MATRIX_CLI_VERIFIER_EXCEPTIONS const was found but contained no parseable entries"
        )
    return entries, errors


def matrix_variants_in_block(block: str) -> set[str]:
    return set(re.findall(r"\bMatrixError::([A-Za-z0-9_]+)\b", block))


def find_auth_constructor_spans(production_source: str) -> list[tuple[int, int]]:
    masked = mask_comments_and_strings(production_source)
    return [
        match.span()
        for match in re.finditer(
            r"\bMatrixError::Auth\s*\((?!\s*_\s*\))", masked
        )
    ]


#: The single allowed direct-Auth-construction helper. Any other site
#: constructing `MatrixError::Auth(...)` directly must be classified
#: through this helper. Held as a one-element allowlist so a rename or
#: a "spiritual successor" function does not silently grant itself the
#: ability to bypass the classifier.
ALLOWED_AUTH_CONSTRUCTOR_FN = "matrix_auth_error_from_sdk"


def allowed_auth_constructor_spans(production_source: str) -> list[tuple[int, int]]:
    source = production_source
    needle = f"fn {ALLOWED_AUTH_CONSTRUCTOR_FN}("
    spans: list[tuple[int, int]] = []
    for match in re.finditer(rf"\b{re.escape(needle)}", source):
        try:
            block = find_balanced_block(source, match.group(0))
        except ValueError:
            continue
        # The helper must (a) be named exactly ALLOWED_AUTH_CONSTRUCTOR_FN,
        # (b) actually peel terminal-auth kinds via the classifier (these
        # substrings prove the body classifies before constructing
        # `Auth(_)`), and (c) construct `Auth(_)`. Mask comments and
        # string literals so a comment that mimics the classifier shape
        # cannot grant whitelist coverage to an unrelated helper.
        masked_block = mask_comments_and_strings(block)
        if (
            "matrix_sync_terminal_error(err)" in masked_block
            and "err.client_api_error_kind().is_some()" in masked_block
            and re.search(r"\bMatrixError::Auth\s*\((?!\s*_\s*\))", masked_block)
        ):
            block_start = match.start()
            spans.append((block_start, block_start + len(block)))
    return spans


def check_auth_construction(matrix_sources: tuple[MatrixSource, ...]) -> list[str]:
    errors: list[str] = []
    allowed: list[tuple[str, int, int]] = []
    for source in matrix_sources:
        for start, end in allowed_auth_constructor_spans(source.production_source):
            allowed.append((source.path, start, end))
    if not allowed:
        errors.append(
            "classifier-owned MatrixError::Auth construction helper is missing"
        )
    for source in matrix_sources:
        for start, _end in find_auth_constructor_spans(source.production_source):
            if not any(
                path == source.path and allowed_start <= start < allowed_end
                for path, allowed_start, allowed_end in allowed
            ):
                errors.append(
                    "direct MatrixError::Auth construction outside the "
                    f"classifier-owned helper at {source.path}:"
                    f"{line_number(source.production_source, start)}"
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
        anchor = f"struct {struct_name}"
        if anchor not in sources.ws_rs:
            continue
        if has_serde_deny_unknown_fields(attribute_block_before(sources.ws_rs, anchor)):
            errors.append(
                f"{struct_name} is a released WS handshake DTO and must not use deny_unknown_fields"
            )

    anchor = "pub struct MatrixSendTestRequest"
    if anchor in sources.control_rs and has_serde_deny_unknown_fields(
        attribute_block_before(sources.control_rs, anchor)
    ):
        errors.append(
            "MatrixSendTestRequest is a released HTTP DTO and must not use deny_unknown_fields"
        )
    return errors


def check_no_matrix_error_aliases(matrix_sources: tuple[MatrixSource, ...]) -> list[str]:
    """Reject `use ... MatrixError as ...` re-exports in production
    source. An alias bypasses the lexical Auth-construction guard:
    `M::Auth(_)` does not match `\\bMatrixError::Auth\\b`."""
    errors: list[str] = []
    for source in matrix_sources:
        masked = mask_comments_and_strings(source.production_source)
        for match in re.finditer(
            r"\buse\b[^;]*\bMatrixError\s+as\s+[A-Za-z_][A-Za-z0-9_]*\b",
            masked,
        ):
            errors.append(
                "`use ... MatrixError as ...;` alias at "
                f"{source.path}:{line_number(source.production_source, match.start())} "
                "bypasses the Auth-construction guard"
            )
    return errors


def check_no_macro_auth_construction(
    matrix_sources: tuple[MatrixSource, ...]
) -> list[str]:
    """Reject any `macro_rules!` definition whose body expands to
    `MatrixError::Auth(...)`. The Auth-construction guard inspects
    source text only — a macro that expands to the constructor
    silently routes around the classifier."""
    errors: list[str] = []
    for source in matrix_sources:
        masked = mask_comments_and_strings(source.production_source)
        for match in re.finditer(
            r"\bmacro_rules!\s+([A-Za-z_][A-Za-z0-9_]*)\b", masked
        ):
            macro_name = match.group(1)
            brace = source.production_source.find("{", match.end())
            if brace == -1:
                continue
            depth = 0
            end = None
            for index in range(brace, len(source.production_source)):
                ch = masked[index]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = index + 1
                        break
            if end is None:
                continue
            body_masked = mask_comments_and_strings(source.production_source[brace:end])
            if re.search(r"\bMatrixError::Auth\s*\(", body_masked):
                errors.append(
                    f"macro_rules! {macro_name} at {source.path}:"
                    f"{line_number(source.production_source, match.start())} "
                    "expands to MatrixError::Auth — must route through the "
                    "classifier helper"
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
    exceptions_map, exception_errors = parse_cli_verifier_exceptions(cli_rs)
    errors.extend(exception_errors)
    exceptions = set(exceptions_map)
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
    conditional_retry_kinds = set(CONTROL_CONDITIONAL_RETRY_AFTER_KINDS)
    kinds = set(by_variant.values())
    for kind in sorted(no_retry_kinds - kinds):
        errors.append(f"control no-retry table names unknown Matrix kind {kind!r}")
    for kind in sorted(conditional_retry_kinds - kinds):
        errors.append(f"control conditional-retry table names unknown Matrix kind {kind!r}")
    for kind in sorted(retry_kinds & no_retry_kinds):
        errors.append(f"Matrix kind {kind!r} is both retryable and no-retry in control projection")
    for kind in sorted(conditional_retry_kinds - retry_kinds):
        errors.append(
            f"Matrix kind {kind!r} must route through typed conditional retry projection"
        )
    if (
        "MatrixError::SendFailed { retry_after_ms, .. }" not in retry
        or "retry_projection_from_ms(*retry_after_ms)" not in retry
    ):
        errors.append(
            "matrix_control_retry_projection must derive send-failed Retry-After "
            "from MatrixError::SendFailed.retry_after_ms"
        )
    for kind in sorted(kinds - retry_kinds - no_retry_kinds - conditional_retry_kinds):
        errors.append(
            f"Matrix kind {kind!r} is missing from matrix_control_retry_projection and retry policy tables"
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
    metadata_attrs = attribute_block_before(matrix_rs, "pub struct MatrixStatusMetadata")
    if not has_serde_rename_all_camel_case(metadata_attrs):
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


def check_dlq_policy_regressions(matrix_modules_rs: str) -> list[str]:
    errors: list[str] = []
    try:
        body = find_balanced_block(
            matrix_modules_rs, "fn reencode_matrix_inbound_dlq_lines_for_rekey"
        )
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
            body = find_balanced_block(matrix_modules_rs, f"fn {test_name}")
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
    errors.extend(check_auth_construction(sources.matrix_sources))
    errors.extend(check_no_matrix_error_aliases(sources.matrix_sources))
    errors.extend(check_no_macro_auth_construction(sources.matrix_sources))
    errors.extend(check_kind_stable_table(sources.matrix_rs, kinds))
    errors.extend(check_docs(sources.http_docs, kinds))
    errors.extend(check_cli_partition(sources.cli_rs, kinds))
    errors.extend(check_http_projection(sources.control_rs, by_variant))
    errors.extend(check_ws_runtime_projection(sources.matrix_rs))
    errors.extend(check_dlq_policy_regressions(sources.matrix_modules_rs))
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
    matrix_path = "src/channels/matrix.rs"
    verification_path = "src/channels/matrix/verification.rs"
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
            replace_matrix_source(
                sources,
                matrix_path,
                insert_before_test_module(sources.matrix_rs, insertion),
            ),
            "direct MatrixError::Auth construction outside",
        )
    )
    submodule_auth_insertion = (
        "\nfn r58_submodule_illegal_auth_construction(err: &matrix_sdk::Error) -> MatrixError {\n"
        "    MatrixError::Auth(err.to_string())\n"
        "}\n"
    )
    errors.extend(
        assert_fixture_fails(
            "illegal Auth construction in Matrix submodule",
            replace_matrix_source(
                sources,
                verification_path,
                insert_before_test_module(
                    matrix_source_text(sources, verification_path),
                    submodule_auth_insertion,
                ),
            ),
            "src/channels/matrix/verification.rs",
        )
    )
    # Helper named differently from the classifier-owned helper but whose
    # body has the classifier-peel substrings embedded in comments. The
    # pre-R57 substring-on-raw-body whitelist would silently accept this
    # as classifier-owned; the masked-content + name-allowlist check must
    # reject it.
    comment_spoofed_helper = (
        "\nfn r57_comment_spoofed_auth_helper(err: &matrix_sdk::Error) -> MatrixError {\n"
        "    // pretends to peel via matrix_sync_terminal_error(err) and\n"
        "    // gates on err.client_api_error_kind().is_some() — but this\n"
        "    // helper does no such thing and is not the classifier owner.\n"
        "    MatrixError::Auth(err.to_string())\n"
        "}\n"
    )
    errors.extend(
        assert_fixture_fails(
            "comment-spoofed Auth helper",
            replace_matrix_source(
                sources,
                matrix_path,
                insert_before_test_module(sources.matrix_rs, comment_spoofed_helper),
            ),
            "direct MatrixError::Auth construction outside",
        )
    )
    # The 4th leg (WS/runtime `lastErrorKind` projection) must fail
    # cleanly when its three load-bearing surfaces drift. Without these
    # fixtures the leg's enforcement is asserted only by the baseline
    # green; a refactor that disables the check (e.g. relaxes the
    # required substring) would slip through CI silently. Each fixture
    # targets one of: (1) the projection write in
    # `stamp_matrix_runtime_error`, (2) the `last_error_kind` field on
    # `MatrixStatusMetadata`, and (3) the wire-shape pin test.
    projection_line = "status.last_error_kind = Some(err.kind().to_string())"
    if projection_line not in sources.matrix_rs:
        errors.append(
            "self-test: expected projection line missing from matrix.rs; "
            "self-test cannot exercise the 4th-leg check"
        )
    else:
        errors.extend(
            assert_fixture_fails(
                "missing lastErrorKind projection in stamp_matrix_runtime_error",
                replace(
                    sources,
                    matrix_rs=sources.matrix_rs.replace(
                        projection_line,
                        "status.last_error_kind = Some(err.kind().into())",
                        1,
                    ),
                ),
                "must project MatrixError::kind() into runtime last_error_kind",
            )
        )

    metadata_field = "pub last_error_kind: Option<String>"
    if metadata_field not in sources.matrix_rs:
        errors.append(
            "self-test: expected last_error_kind field missing from MatrixStatusMetadata; "
            "self-test cannot exercise the 4th-leg field-removal check"
        )
    else:
        errors.extend(
            assert_fixture_fails(
                "missing last_error_kind field on MatrixStatusMetadata",
                replace(
                    sources,
                    matrix_rs=sources.matrix_rs.replace(
                        metadata_field,
                        "pub last_error_kind_renamed: Option<String>",
                        1,
                    ),
                ),
                "MatrixStatusMetadata is missing last_error_kind",
            )
        )

    wire_pin_anchor = '"lastErrorKind"'
    if wire_pin_anchor not in sources.matrix_rs:
        errors.append(
            "self-test: wire-shape pin anchor missing from matrix.rs; "
            "self-test cannot exercise the wire-shape pin check"
        )
    else:
        errors.extend(
            assert_fixture_fails(
                "missing lastErrorKind pin in wire-shape test",
                replace(
                    sources,
                    matrix_rs=sources.matrix_rs.replace(
                        wire_pin_anchor,
                        '"lastErrorKindRenamed"',
                    ),
                ),
                "must pin lastErrorKind and reject last_error_kind",
            )
        )

    # Removing the `rename_all = "camelCase"` attribute from
    # MatrixStatusMetadata must fail the WS/runtime projection leg even
    # though plenty of sibling structs above the metadata still carry
    # the attribute. The pre-R57 "anywhere before struct" check passed
    # vacuously in that case.
    rename_attr = '#[serde(rename_all = "camelCase")]\npub struct MatrixStatusMetadata'
    if rename_attr not in sources.matrix_rs:
        errors.append(
            "self-test: MatrixStatusMetadata is not preceded by the expected rename_all attribute"
        )
    else:
        errors.extend(
            assert_fixture_fails(
                "missing rename_all on MatrixStatusMetadata",
                replace(
                    sources,
                    matrix_rs=sources.matrix_rs.replace(
                        rename_attr,
                        "pub struct MatrixStatusMetadata",
                        1,
                    ),
                ),
                "must serialize last_error_kind as lastErrorKind",
            )
        )
        # Substituting `#[doc = "uses rename_all = \"camelCase\""]`
        # for the real serde attribute must fail. The pre-fix substring
        # check passed vacuously because the doc payload contained the
        # phrase.
        errors.extend(
            assert_fixture_fails(
                "rename_all substring in doc-attribute payload only",
                replace(
                    sources,
                    matrix_rs=sources.matrix_rs.replace(
                        rename_attr,
                        '#[doc = "uses rename_all = \\"camelCase\\""]\npub struct MatrixStatusMetadata',
                        1,
                    ),
                ),
                "must serialize last_error_kind as lastErrorKind",
            )
        )
        # `cfg_attr` wrapping over a serde rename_all is conditional —
        # the wire shape must be unconditional, so the guard must
        # reject the cfg_attr form even when the cfg predicate would
        # never activate.
        errors.extend(
            assert_fixture_fails(
                "rename_all wrapped in cfg_attr is not unconditional",
                replace(
                    sources,
                    matrix_rs=sources.matrix_rs.replace(
                        rename_attr,
                        '#[cfg_attr(any(), serde(rename_all = "camelCase"))]\npub struct MatrixStatusMetadata',
                        1,
                    ),
                ),
                "must serialize last_error_kind as lastErrorKind",
            )
        )

    # `deny_unknown_fields` split into a sibling `#[serde(...)]`
    # attribute (so it is not on the same attribute as `struct`) must
    # still be detected. The pre-fix regex required the attribute to
    # sit on the line immediately before `struct`, so a split form
    # slipped through.
    connect_anchor = "pub struct ConnectParams"
    if connect_anchor in sources.ws_rs:
        errors.extend(
            assert_fixture_fails(
                "deny_unknown_fields split across sibling serde attributes on ConnectParams",
                replace(
                    sources,
                    ws_rs=sources.ws_rs.replace(
                        connect_anchor,
                        "#[serde(deny_unknown_fields)]\n#[serde(rename_all = \"camelCase\")]\n" + connect_anchor,
                        1,
                    ),
                ),
                "ConnectParams is a released WS handshake DTO and must not use deny_unknown_fields",
            )
        )

    # `use ... MatrixError as ...;` aliases bypass the lexical
    # Auth-construction guard. Adding one must fail.
    alias_insertion = (
        "\nuse crate::channels::matrix::MatrixError as MatrixErrorAlias;\n"
    )
    errors.extend(
        assert_fixture_fails(
            "use ... MatrixError as ... alias bypasses Auth guard",
            replace_matrix_source(
                sources,
                verification_path,
                insert_before_test_module(
                    matrix_source_text(sources, verification_path),
                    alias_insertion,
                ),
            ),
            "src/channels/matrix/verification.rs",
        )
    )

    # `macro_rules!` that expands to `MatrixError::Auth(...)` bypasses
    # the lexical guard. Adding one must fail.
    macro_insertion = (
        "\nmacro_rules! r58_illegal_auth_macro {\n"
        "    ($err:expr) => { MatrixError::Auth($err.to_string()) };\n"
        "}\n"
    )
    errors.extend(
        assert_fixture_fails(
            "macro_rules! expands to MatrixError::Auth",
            replace_matrix_source(
                sources,
                verification_path,
                insert_before_test_module(
                    matrix_source_text(sources, verification_path),
                    macro_insertion,
                ),
            ),
            "src/channels/matrix/verification.rs",
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
