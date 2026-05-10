#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

if ! grep -Eq '^matrix-sdk = \{ version = "[^"]+", default-features = false, features = \["e2e-encryption", "sqlite", "rustls-tls"\] \}$' Cargo.toml; then
  cat >&2 <<'EOF'
matrix-sdk feature contract changed.
Expected exactly: default-features = false, features = ["e2e-encryption", "sqlite", "rustls-tls"]
Matrix must stay on rustls and must not enable native-tls, openssl-tls, or bundled SQLite features implicitly.
EOF
  exit 1
fi

cargo_tree() {
  if [[ -x "${repo_root}/scripts/cargo-serial" ]]; then
    "${repo_root}/scripts/cargo-serial" tree --locked --all-features --all-targets -e features
  else
    cargo tree --locked --all-features --all-targets -e features
  fi
}

tree_output="$(cargo_tree)"
if printf '%s\n' "${tree_output}" \
    | grep -Ei '(^|[[:space:]])(openssl|openssl-sys|native-tls) v' \
    | grep -v openssl-probe; then
  cat >&2 <<'EOF'
OpenSSL / OpenSSL-sys / native-tls appeared in the Cargo feature graph.
Matrix must stay on rustls. openssl-probe is explicitly allowed because it
does not link OpenSSL; it only locates CA cert paths for rustls.
EOF
  exit 1
fi
