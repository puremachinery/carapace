# Implementation Plan (Historical)

> **Status: Complete.** All six phases are finished. This document is retained
> as historical reference for how the migration was planned and executed. For
> current architecture, see [architecture.md](../architecture.md).

## Agent Allocation
- **Agents 1-6**: Parallel workers, assigned dynamically

---

## Phase 1: Contract Freeze (Day 1)

All tasks run in parallel.

| Task | Agent | Output | Dependencies |
|------|-------|--------|--------------|
| Capture WS protocol golden traces (schema + field presence) | 1 | `tests/golden/ws/*.json` | None |
| Capture HTTP endpoint golden traces (schema + field presence) | 2 | `tests/golden/http/*.json` | None |
| Document WS protocol spec | 3 | `docs/protocol/websocket.md` | None |
| Document HTTP API spec | 4 | `docs/protocol/http.md` | None |
| Define WASM plugin WIT interface | 5 | `wit/plugin.wit` | None |
| Define compatibility checklist | 6 | `docs/refactor/compatibility-checklist.md` | None |
| Scaffold Rust workspace | 1 | `Cargo.toml`, `src/` structure | None |

**End of Day 1 Gate**: All golden traces captured, protocol docs complete, Rust workspace compiles.

---

## Phase 2: Rust Core Skeleton (Days 2-3)

### Day 2 - Parallel Implementation

| Task | Agent | Output | Dependencies |
|------|-------|--------|--------------|
| Config parsing (JSON with includes) | 1 | `src/config/` | Scaffold |
| Auth module (token, password, timing-safe) | 2 | `src/auth/` | Scaffold |
| Auth module (Tailscale whois) | 3 | `src/auth/tailscale.rs` | Scaffold |
| Logging subsystem | 4 | `src/logging/` | Scaffold |
| Credential storage (macOS Keychain) | 5 | `src/credentials/macos.rs` | Scaffold |
| Credential storage (Linux Secret Service) | 6 | `src/credentials/linux.rs` | Scaffold |
| Credential storage (Windows Credential Manager) | 1 | `src/credentials/windows.rs` | Scaffold |

### Day 3 - Server Implementation

| Task | Agent | Output | Dependencies |
|------|-------|--------|--------------|
| HTTP server with real handlers | 1 | `src/server/http.rs` | Config, Auth, Logging |
| WebSocket server with real handlers | 2 | `src/server/ws.rs` | Config, Auth, Logging |
| Bind mode resolution | 3 | `src/server/bind.rs` | Config |
| Golden trace test runner | 4 | `tests/golden_test.rs` | HTTP, WS handlers |
| macOS app integration test | 5 | Manual validation | WS server |
| iOS app integration test | 6 | Manual validation | WS server |

**End of Day 3 Gate**: `cargo test` passes golden traces (schema + field presence, not exact bytes). macOS/iOS apps connect successfully.

---

## Phase 3: WASM Plugin System (Days 4-5)

### Day 4 - Plugin Host

| Task | Agent | Output | Dependencies |
|------|-------|--------|--------------|
| Wasmtime plugin host | 1 | `src/plugins/host.rs` | Scaffold |
| WIT bindgen integration | 2 | `src/plugins/bindings.rs` | WIT from Phase 1 |
| Capability enforcement | 3 | `src/plugins/capabilities.rs` | Host |
| Plugin loader (discover + instantiate) | 4 | `src/plugins/loader.rs` | Host, Bindings |

### Day 5 - Plugin Interface Implementation

| Task | Agent | Output | Dependencies |
|------|-------|--------|--------------|
| Channel adapter capability | 1 | `src/plugins/caps/channel.rs` | Capabilities |
| Webhook handler capability | 2 | `src/plugins/caps/webhook.rs` | Capabilities |
| Tool capability | 3 | `src/plugins/caps/tool.rs` | Capabilities |
| Service capability | 4 | `src/plugins/caps/service.rs` | Capabilities |
| Plugin system integration test | 5 | `tests/plugin_e2e.rs` | All above |

**End of Day 5 Gate**: WASM plugin host loads and executes a test plugin with capability enforcement.

---

## Phase 4: High Risk Surface Migration (Days 6-8)

### Day 6 - Media Pipeline

| Task | Agent | Output | Dependencies |
|------|-------|--------|--------------|
| Media fetch with SSRF protection | 1 | `src/media/fetch.rs` | None |
| Media store with cleanup | 2 | `src/media/store.rs` | None |
| Port SSRF tests | 3 | `tests/ssrf_test.rs` | Fetch module |

### Day 7 - Webhook and Message Pipeline

| Task | Agent | Output | Dependencies |
|------|-------|--------|--------------|
| Webhook handler | 1 | `src/hooks/handler.rs` | HTTP server |
| Hook token auth (Bearer + header) | 2 | `src/hooks/auth.rs` | Auth module |
| Outbound message pipeline | 3 | `src/messages/outbound.rs` | Plugin system |
| Expand golden trace coverage | 4 | Additional `tests/golden/` | All new endpoints |

**End of Day 7 Gate**: Media, webhooks, and message pipeline work through Rust with parity to Node.

### Day 8 - Security Hardening (New Behaviors)

These are improvements over the Node gateway, not compatibility requirements.

| Task | Agent | Output | Dependencies |
|------|-------|--------|--------------|
| Rate limiting middleware | 1 | `src/server/ratelimit.rs` | HTTP server |
| CSRF protection | 2 | `src/server/csrf.rs` | HTTP server |
| CSP headers | 3 | `src/server/headers.rs` | HTTP server |
| Security review of new Rust code | 4 | `docs/security-review-phase4.md` | All above |

**End of Day 8 Gate**: Security hardening complete. Rate limiting and CSRF active.

---

## Phase 5: Plugin Rewrites (Days 9-11)

### Day 9 - Core Channel Plugins

| Task | Agent | Output | Dependencies |
|------|-------|--------|--------------|
| Rewrite msteams plugin | 1 | `plugins/msteams/` | Plugin system |
| Rewrite matrix plugin | 2 | `plugins/matrix/` | Plugin system |
| Rewrite zalo plugin | 3 | `plugins/zalo/` | Plugin system |
| Rewrite zalouser plugin | 4 | `plugins/zalouser/` | Plugin system |

### Day 10 - Additional Plugins + Validation

| Task | Agent | Output | Dependencies |
|------|-------|--------|--------------|
| Rewrite voice-call plugin | 1 | `plugins/voice-call/` | Plugin system |
| Compile all plugins to WASM | 2 | `plugins/*/target/*.wasm` | All rewrites |
| Integration test: msteams | 3 | Validate feature parity | WASM build |
| Integration test: matrix | 4 | Validate feature parity | WASM build |

### Day 11 - Full Plugin Validation

| Task | Agent | Output | Dependencies |
|------|-------|--------|--------------|
| Integration test: all plugins | 1-4 | Full test suite | All WASM plugins |
| Performance benchmark | 5 | Benchmark results | All plugins |
| Plugin documentation | 6 | `docs/plugins/` | All plugins |

**End of Day 11 Gate**: All plugins rewritten, compiled to WASM, and validated for feature parity.

---

## Phase 6: Cutover (Days 12-14)

### Day 12 - Parallel Deployment Setup

| Task | Agent | Output | Dependencies |
|------|-------|--------|--------------|
| Docker image for Rust gateway | 1 | `Dockerfile` | All phases |
| CI/CD pipeline | 2 | `.github/workflows/` | Dockerfile |
| Staging environment config | 3 | `deploy/staging/` | CI/CD |
| Metrics and logging integration | 4 | Prometheus/Grafana setup | Staging |

### Day 13 - Parallel Run

| Task | Agent | Output | Dependencies |
|------|-------|--------|--------------|
| Deploy to staging alongside Node gateway | 1 | Running parallel gateways | Staging setup |
| Traffic mirroring setup | 2 | Mirror prod traffic to staging | Parallel deployment |
| Parity verification automation | 3 | Compare responses | Traffic mirror |
| Monitor and fix discrepancies | 4-6 | Bug fixes | Parity checks |

### Day 14 - Cutover

| Task | Agent | Output | Dependencies |
|------|-------|--------|--------------|
| Final parity sign-off | 1-6 | Checklist complete | Day 13 |
| Production deployment | 1 | Rust gateway live | Sign-off |
| Rollback procedure documented | 2 | `docs/operations/rollback.md` | None |
| Post-cutover monitoring | 1-6 | 24h watch | Deployment |

**End of Day 14 Gate**: Rust gateway serving production traffic.

---

## Directory Structure

```
carapace/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── config/
│   ├── auth/
│   ├── credentials/
│   ├── logging/
│   ├── server/
│   │   ├── http.rs
│   │   ├── ws.rs
│   │   ├── bind.rs
│   │   ├── ratelimit.rs
│   │   ├── csrf.rs
│   │   └── headers.rs
│   ├── plugins/
│   │   ├── host.rs
│   │   ├── bindings.rs
│   │   ├── capabilities.rs
│   │   ├── loader.rs
│   │   └── caps/
│   │       ├── channel.rs
│   │       ├── webhook.rs
│   │       ├── tool.rs
│   │       └── service.rs
│   ├── hooks/
│   ├── media/
│   ├── messages/
│   └── channels/
├── plugins/                    # WASM plugins (Rust source)
│   ├── msteams/
│   ├── matrix/
│   ├── zalo/
│   ├── zalouser/
│   └── voice-call/
├── wit/
│   └── plugin.wit              # WIT interface definition
├── tests/
│   ├── golden/
│   │   ├── ws/
│   │   └── http/
│   ├── golden_test.rs
│   ├── ssrf_test.rs
│   └── plugin_e2e.rs
├── docs/
│   ├── protocol/
│   ├── refactor/
│   ├── plugins/
│   └── operations/
└── deploy/
    └── staging/
```

---

## Crate Dependencies

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
axum = "0.7"
tokio-tungstenite = "0.21"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = "0.3"
keyring = "2"                    # Cross-platform credential storage
tower = "0.4"
tower-http = "0.5"
wasmtime = "18"                  # WASM runtime
wit-bindgen = "0.22"             # WIT bindings generation

[dev-dependencies]
insta = "1"                      # Snapshot testing for golden traces
```

---

## Success Metrics

- All golden traces pass
- All plugins rewritten and running as WASM
- macOS and iOS apps connect without modification
- No plaintext credentials on disk
- No npm dependencies in production
- Rate limiting active on all HTTP endpoints
- CSRF protection on state-changing endpoints
- < 10ms latency overhead vs Node gateway
