#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

if ! python3 - <<'PY'
import sys
import tomllib

with open("Cargo.toml", "rb") as fh:
    manifest = tomllib.load(fh)

dep = manifest.get("dependencies", {}).get("matrix-sdk")
required = {"e2e-encryption", "sqlite", "rustls-tls"}
if not isinstance(dep, dict):
    sys.exit(1)
features = set(dep.get("features", []))
if dep.get("default-features") is not False:
    sys.exit(1)
if not required.issubset(features):
    sys.exit(1)
PY
then
  cat >&2 <<'EOF'
matrix-sdk feature contract changed.
Expected default-features = false with features containing ["e2e-encryption", "sqlite", "rustls-tls"].
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
