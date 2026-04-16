# Carapace Documentation

A security-focused, open-source personal AI assistant.

## Start Here

- [Website](https://getcara.io) — install, first run, security, ops, cookbook, and troubleshooting
- [Getting Started](getting-started.md) — install, first run, and ops
- [Install](site/install.md) — binary downloads and verification
- [First Run](site/first-run.md) — secure local startup and smoke checks
- [Get Unstuck](site/get-unstuck.md) — troubleshooting and report paths
- [Docs Hubs](site/docs.md) — getting started/channels/providers/cli/security-ops/reference hubs
- [Providers Hub](site/providers.md) — provider setup and decision guidance
- [Capability Matrix](site/capability-matrix.md) — channels/providers/platform support + caveats
- [CLI Tasks Index](site/cli-tasks.md) — task-oriented command index
- [CLI Reference Hub](site/cli-reference.md) — task index + full reference + troubleshooting routes
- [Security & Ops Hub](site/security-ops.md) — day-2 security/ops paths
- [Reference Hub](site/reference.md) — protocol/architecture reference routing
- [Cookbook](cookbook/README.md) — task-focused walkthroughs
- [Release & Upgrade Policy](release.md) — compatibility, migration, rollback, release checklist
- [Channel Setup](channels.md) — Signal, Telegram, Discord, Slack, webhooks
- [Channel Smoke Validation](channel-smoke.md) — reproducible live channel checks + evidence capture
- [CLI Guide](cli.md) — subcommands, flags, and device identity
- [Migrating from another tool](getting-started.md#migrating-from-another-tool) — import config from OpenClaw, OpenCode, Aider, or NemoClaw
- [Security Policy](../SECURITY.md) — vulnerability reporting and response expectations

## Architecture & Security

- [Architecture](architecture.md) — Component diagrams, request flows, design decisions
- [Security](security.md) — Threat model, trust boundaries, implementation checklist
- [Plugin Development](plugin-development.md) — WASM plugin authoring, local dev loading, and managed plugin distribution rules

## Protocol Reference

- [WebSocket Protocol](protocol/websocket.md) — JSON-RPC over WebSocket, methods, events
- [HTTP API](protocol/http.md) — REST endpoints, hooks, OpenAI compatibility
- [Pairing](protocol/pairing.md) — Node and device pairing flows
- [Configuration](protocol/config.md) — Config file format, environment variables
- [Credentials](protocol/credentials.md) — Secret storage

## Quick Links

| Topic | File | Description |
|-------|------|-------------|
| Trust boundaries | [security.md](security.md#security-layers) | 4-layer defense model |
| WS handshake | [websocket.md](protocol/websocket.md#connection-lifecycle) | Connect flow, auth methods |
| Cookbook recipes | [cookbook/README.md](cookbook/README.md) | Goal-oriented setup walkthroughs |
| HTTP hooks | [http.md](protocol/http.md#hooks) | Webhook configuration |
| Token security | [pairing.md](protocol/pairing.md#token-security) | SHA-256 hashing, constant-time comparison |
| Rate limiting | [security.md](security.md#rate-limiting) | Default limits per endpoint |
| Inbound classifier | [security.md](security.md#prompt-injection-considerations) | LLM-based attack classification |
| Venice AI provider | [architecture.md](architecture.md#key-files) | OpenAI-compatible composition wrapper |
| Session storage | [architecture.md](architecture.md#key-files) | JSONL history, compaction, encryption at rest |
| Named routes | [config-reference.md](protocol/config-reference.md#2a-named-routes-optional) | Reusable backend route definitions |
| Import / migrate | [getting-started.md](getting-started.md#migrating-from-another-tool) | Import from OpenClaw, OpenCode, Aider, NemoClaw |
