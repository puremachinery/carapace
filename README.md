# carapace

Rust implementation of the Moltbot gateway.

## Status

Work in progress. See [docs/refactor/implementation-plan.md](docs/refactor/implementation-plan.md) for current status.

## Requirements

- Rust 1.75+ (2021 edition)
- For WASM plugins: wasmtime 18+

### Recommended Tools

```bash
# Task runner (like make, but better)
cargo install just

# Faster test runner with better output
cargo install cargo-nextest

# File watcher for development (optional)
cargo install cargo-watch

# Code coverage (optional)
cargo install cargo-tarpaulin
```

## Development

This project uses [just](https://github.com/casey/just) as a task runner. Run `just` to see available commands:

```bash
just          # Show all available recipes
just build    # Build the project
just test     # Run tests with nextest
just lint     # Run clippy
just check    # Run lint + fmt-check + test
just watch    # Watch for changes and run tests
```

## Building

```bash
cargo build
# or
just build
```

## Testing

Using [cargo-nextest](https://nexte.st/) (recommended - faster, better output):
```bash
cargo nextest run
# or
just test
```

Using standard cargo test:
```bash
cargo test
# or
just test-cargo
```

Run specific tests:
```bash
just test-one test_name
```

With coverage:
```bash
just test-coverage
# or
cargo tarpaulin --out Html
```

## Linting

```bash
cargo clippy
cargo fmt --check
# or
just lint
just fmt-check
```

## Project Structure

```
src/
├── auth/           # Authentication (tokens, passwords, loopback)
├── channels/       # Channel registry
├── credentials/    # Credential storage
├── devices/        # Device pairing
├── hooks/          # Webhook mappings
├── logging/        # Structured logging
├── media/          # Media fetch/store
├── messages/       # Outbound messages
├── nodes/          # Node pairing
├── plugins/        # WASM plugin runtime
├── server/         # HTTP + WebSocket server
└── sessions/       # Session storage

docs/
├── architecture.md # Component diagrams
├── security.md     # Threat model
└── protocol/       # Protocol specifications

tests/
├── golden/         # Golden test traces
└── *.rs            # Integration tests
```

## Documentation

See [docs/README.md](docs/README.md) for full documentation index.

## License

MIT - see [LICENSE](LICENSE)
