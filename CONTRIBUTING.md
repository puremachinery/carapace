# Contributing to Carapace

Thank you for your interest in contributing to Carapace. This document covers
everything you need to get started, follow our conventions, and submit changes.

## Getting Started

### Prerequisites

- **Rust toolchain (stable):** Install via [rustup](https://rustup.rs/).
- **cargo-nextest (recommended):** Our preferred test runner.
  ```sh
  cargo install cargo-nextest
  ```
- **just (recommended):** Task runner used for local contributor workflows.
  ```sh
  cargo install just
  ```

### Clone, Build, and Test

```sh
git clone https://github.com/puremachinery/carapace.git
cd carapace
cargo build
just test-fast      # recommended inner-loop lane
just test-full      # broad local validation lane
just setup-hooks    # install repository-managed git hooks
```

### Development Mode

Run the server in development mode with relaxed defaults:

```sh
CARAPACE_DEV=1 cargo run
```

## Development Workflow

1. Branch from `master`.
2. Write tests first when possible.
3. Run `cargo fmt` before committing.
4. Run `cargo clippy -- -D warnings` before committing.
5. Run `just test-fast` for the normal inner loop.
6. Run `just test-golden` if you changed WebSocket protocol or golden surfaces.
7. Run `just test-full` before broad runtime changes or when you want parity with push-time validation.
8. If your PR changes workflows or docs, run `just workflow-lint` and/or `just docs-check`.
9. Push your branch and open a pull request.

Pre-commit hooks enforce formatting, lint checks, and staged secret scanning.
Pre-push hooks run shell checks for shell-script-only pushes, run
the `golden` or `full` test lanes for Rust-impacting pushes as appropriate, and skip checks
for docs/website/meta-only and non-shell script-only pushes.

## Code Style

- Follow `rustfmt` defaults. Do not override them.
- Use `parking_lot` mutexes and read-write locks, not `std::sync`.
- Prefer `tracing` macros (`tracing::info!`, `tracing::debug!`, etc.) over
  `println!` for all logging.
- Return `Result` types for fallible operations. Define error enums with
  `thiserror`.
- Perform atomic file writes using the temp file, fsync, rename pattern.
- Represent all timestamps as milliseconds since the Unix epoch.
- Config fields use camelCase in JSON/JSON5 and snake_case in Rust structs
  (use serde `rename` or `rename_all` as needed).
- Place unit tests in inline `#[cfg(test)] mod tests { }` blocks at the bottom
  of each source file.

## Testing

Carapace has 4,776+ tests. We use several testing strategies:

- **Unit tests:** Inline `#[cfg(test)]` modules alongside implementation code.
- **Integration tests:** Module-specific `tests.rs` files within the `src/`
  tree and the top-level `tests/` directory.
- **Golden trace tests:** Protocol parity tests using `insta` for snapshot
  assertions.
- **Feature-gated tests:** Platform-specific tests behind Cargo features:
  - `keychain-tests` -- macOS Keychain credential storage
  - `secret-service-tests` -- Linux Secret Service credential storage
- **File-system tests:** Use `tempfile::TempDir` for any test that touches the
  file system. Never write to fixed paths.

Carapace uses named test lanes:

- `just test-fast` — broad, fast Rust coverage for normal development and PRs
- `just test-golden` — WebSocket golden contract coverage
- `just test-integration` — slower top-level integration binaries plus expensive plugin activation positives
- `just test-full` — broad all-targets validation used for push-time coverage

Run the fast lane:

```sh
just test-fast
```

Run the full lane directly with cargo-nextest:

```sh
cargo nextest run --all-targets -P full
```

Run a single test by name:

```sh
just test-one my_test_name
```

## Pull Request Guidelines

- Keep each PR focused on a single feature, fix, or refactoring effort.
- Include tests for all new functionality.
- Use GitHub Issues for public contributor-facing work tracking.
- Link any related GitHub issue in the PR description and close it when appropriate.
- Treat roadmap documents as higher-level planning, not as a one-to-one checklist of GitHub issues.
- CI must pass before merge. The pipeline checks:
  - `cargo fmt --check`
  - `cargo clippy -- -D warnings`
  - `fast` + `golden` lanes on PRs, plus Windows `fast` when the change is Windows-sensitive
  - `full` lane on push to `master` across Linux, macOS, and Windows
  - Security audit

## Architecture Overview

The codebase is organized into focused modules under `src/`:

| Module | Purpose |
|---|---|
| `src/agent/` | LLM provider abstraction (Anthropic, OpenAI, Ollama, Gemini, Bedrock), built-in tools, tool allowlist policy |
| `src/auth/` | Authentication backends: token, password, Tailscale, OAuth profiles |
| `src/server/` | HTTP and WebSocket servers, middleware, rate limiting, security headers |
| `src/config/` | JSON5 config loading with `$include`, env var substitution, hot reload, defaults pipeline |
| `src/sessions/` | Session management, per-sender/global/channel-peer scoping, retention, GDPR export/purge |
| `src/plugins/` | WASM plugin runtime (wasmtime), capability enforcement, sandbox |
| `src/channels/` | Channel abstraction for console, Telegram, Discord, and Slack |
| `src/cron/` | Scheduled job execution with real cron expression parsing |
| `src/credentials/` | Platform-specific secure credential storage (Keychain, Secret Service, Windows Credential Manager) |

## Reporting Issues

Please use [GitHub Issues](https://github.com/puremachinery/carapace/issues) to
report bugs or request features. When filing a bug report, include:

- **Rust version:** output of `rustc --version`
- **Operating system:** name and version
- **Steps to reproduce:** minimal sequence of actions that triggers the issue
- **Expected behavior:** what you expected to happen
- **Actual behavior:** what actually happened, including any error output

## License

By contributing to Carapace, you agree that your contributions will be licensed
under the [Apache License 2.0](LICENSE).
