# Rust Migration Plan

## Goals
- Reduce npm supply chain exposure by moving the core runtime to Rust.
- Isolate plugin execution behind an explicit capability boundary.
- Preserve current external behavior for gateway WS and HTTP APIs.
- Migrate incrementally without breaking existing plugins.

## Architecture Decision
- Build a Rust core gateway that owns config loading, auth, routing, and core services.
- Introduce a sidecar plugin protocol first (JSON-RPC over stdio or local socket).
- Run existing JS plugins in a Node plugin host that speaks the sidecar protocol.
- Add optional WASM plugin support later using the same protocol surface.

## Phased Plan

### Phase 1 Contract Freeze
- Lock the gateway WS protocol and HTTP endpoints as compatibility targets.
- Capture golden traces for connect, auth errors, hooks, tools, and status calls.
- Define a strict compatibility checklist for parity verification.

### Phase 2 Rust Core Skeleton
- Implement config parsing, auth, bind modes, and basic logging in Rust.
- Serve the existing WS and HTTP endpoints with stub handlers.
- Pass the golden trace tests with placeholder responses.

### Phase 3 Plugin Sidecar Boundary
- Define the minimal RPC surface for one plugin capability:
  - Start with outbound adapter or webhook handler.
- Implement a Node sidecar host that loads current JS plugins and exports the RPC.
- Wire the Rust core to the sidecar for that capability only.

### Phase 4 High Risk Surface Migration
- Port media fetch/store, webhook handling, and outbound message pipeline to Rust.
- Keep JS plugins running unchanged through the sidecar host.
- Expand the RPC surface only as needed to keep parity.

### Phase 5 Expand Capabilities
- Add gateway handlers, tools, hooks, and services to the sidecar protocol.
- Move selected capabilities from sidecar to native Rust modules as they stabilize.
- Keep the protocol stable and versioned to avoid churn.

### Phase 6 Cutover
- Run Rust gateway in parallel with the current gateway in staging.
- Verify parity with the golden traces and operational metrics.
- Flip production once parity and performance targets are met.

## Repo Strategy
- Create a new repo for the Rust core gateway and sidecar protocol.
- Keep the current repo unchanged and treat it as the legacy runtime.
- Do not move the current folder structure under a legacy folder.
- Keep a read only clone of this repo available for reference.

## Compatibility Notes
- Keep the config file format, env vars, and defaults aligned.
- Preserve CLI entry points and exit codes where possible.
- Maintain existing plugin behavior through the Node sidecar host during transition.
