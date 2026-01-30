# Rust Migration Plan (Historical)

> **Status: Complete.** The migration from Node.js to Rust is finished. This
> document is retained as historical reference. For current architecture, see
> [architecture.md](../architecture.md).

## Goals
- Eliminate npm supply chain exposure entirely.
- Isolate plugin execution via WASM capability-based sandboxing.
- Preserve current external behavior for gateway WS and HTTP APIs.
- Single binary deployment with no Node.js runtime.

## Architecture Decision
- Build a Rust core gateway that owns config loading, auth, routing, and core services.
- Plugins compile to WASM and run in wasmtime with explicit capabilities.
- Define plugin interface using WIT (WebAssembly Interface Types).
- Rewrite existing JS plugins in Rust (compile to WASM).
- No Node.js sidecar - full Rust stack.

## Phased Plan

### Phase 1 Contract Freeze
- Lock the gateway WS protocol and HTTP endpoints as compatibility targets.
- Capture golden traces for connect, auth errors, hooks, tools, and status calls.
- Define the WASM plugin WIT interface and capability model.
- Define a strict compatibility checklist for parity verification.

### Phase 2 Rust Core Skeleton
- Implement config parsing, auth, bind modes, and basic logging in Rust.
- Serve the existing WS and HTTP endpoints with real handlers.
- Pass the golden trace tests (schema validation).
- Validate macOS and iOS apps against the Rust gateway using the existing WS protocol.
- Implement credential storage in Rust using OS keychain/Secret Service (no JSON creds store).

### Phase 3 WASM Plugin System
- Implement wasmtime-based plugin host with capability enforcement.
- Define WIT interfaces for plugin capabilities:
  - Channel adapters (outbound messaging)
  - Webhook handlers
  - Tools
  - Services
- Load and execute WASM plugins with sandboxed capabilities.

### Phase 4 High Risk Surface Migration
- Port media fetch/store, webhook handling, and outbound message pipeline to Rust.
- Implement SSRF protection, rate limiting, CSRF in Rust.

### Phase 5 Plugin Rewrites
- Rewrite existing JS plugins in Rust:
  - extensions/msteams
  - extensions/matrix
  - extensions/zalo
  - extensions/zalouser
  - extensions/voice-call
  - (others as needed)
- Compile all plugins to WASM.
- Validate feature parity with original plugins.

### Phase 6 Cutover
- Run Rust gateway in parallel with the current gateway in staging.
- Verify parity with the golden traces and operational metrics.
- Flip production once parity and performance targets are met.

## Repo Strategy
- Create a new repo for the Rust core gateway.
- Keep the current repo unchanged and treat it as the legacy runtime.
- Do not move the current folder structure under a legacy folder.
- Keep a read only clone of this repo available for reference.

## Compatibility Notes
- Keep the config file format, env vars, and defaults aligned.
- Preserve CLI entry points and exit codes where possible.
- Plugin behavior preserved through WASM rewrites (same capabilities, new runtime).

## Security Benefits
- No npm in production - zero npm supply chain risk.
- WASM plugins sandboxed by default - only granted capabilities are accessible.
- Single static binary - easier to audit and deploy.
- Memory safety guaranteed by Rust + WASM.
