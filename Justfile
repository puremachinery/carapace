# Justfile for carapace
# Install just: cargo install just
# Run: just <recipe>

# Default recipe - show available commands
default:
    @just --list

# Build the project
build:
    cargo build

# Build in release mode
build-release:
    cargo build --release

# Run all tests with nextest (faster, better output)
test:
    cargo nextest run --all-targets

# Run all tests with standard cargo test
test-cargo:
    cargo test

# Run library tests only
test-lib:
    cargo nextest run --lib

# Run tests with verbose output
test-verbose:
    cargo nextest run --no-capture

# Run a specific test by name
test-one NAME:
    cargo nextest run {{NAME}}

# Run tests and show coverage summary
test-coverage:
    cargo tarpaulin --out Html --output-dir target/coverage

# Run clippy linter
lint:
    cargo clippy

# Run clippy with warnings as errors
lint-strict:
    cargo clippy -- -D warnings

# Format code
fmt:
    cargo fmt

# Check formatting without making changes
fmt-check:
    cargo fmt --check

# Run all checks (lint + fmt + test)
check: lint fmt-check test

# Build documentation
doc:
    cargo doc --no-deps

# Build and open documentation
doc-open:
    cargo doc --no-deps --open

# Clean build artifacts
clean:
    cargo clean

# Watch for changes and run tests
watch:
    cargo watch -x 'nextest run'

# Watch for changes and run clippy
watch-lint:
    cargo watch -x clippy

# Run the same markdown tab check used in CI docs-check.
docs-check:
    @echo "Checking Markdown files for hard tabs"
    @tab="$$(printf '\t')"; \
      if grep -RIn "$$tab" --include='*.md' --exclude-dir=.git --exclude-dir=target .; then \
        echo "Found tab characters in Markdown files; please use spaces."; \
        exit 1; \
      fi
    @bash scripts/check-public-copy.sh

# Run the same workflow lint used in CI (requires actionlint).
workflow-lint:
    @if command -v actionlint >/dev/null 2>&1; then \
      actionlint -color -shellcheck=; \
    else \
      echo "actionlint not found. Install from https://github.com/rhysd/actionlint"; \
      exit 1; \
    fi

# Setup git hooks for pre-commit and pre-push checks.
setup-hooks:
    ./scripts/setup-hooks.sh

# Run pre-commit hook checks manually.
pre-commit:
    ./scripts/hooks/pre-commit

# Run pre-push hook checks manually.
pre-push:
    ./scripts/hooks/pre-push origin </dev/null
