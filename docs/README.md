# carapace Documentation

Rust implementation of the Moltbot gateway.

## Overview

- [Architecture](architecture.md) - Component diagrams, request flows, design decisions
- [Security](security.md) - Threat model, implementation checklist, anti-patterns

## Protocol Reference

- [WebSocket Protocol](protocol/websocket.md) - JSON-RPC over WebSocket, methods, events
- [HTTP API](protocol/http.md) - REST endpoints, hooks, OpenAI compatibility
- [Pairing](protocol/pairing.md) - Node and device pairing flows
- [Configuration](protocol/config.md) - Config file format, environment variables
- [Credentials](protocol/credentials.md) - Secret storage, migration from Node gateway

## Refactor Notes

- [Migration Plan](refactor/rust-migration.md) - Migration strategy overview
- [Implementation Plan](refactor/implementation-plan.md) - Phased implementation details
- [Compatibility Checklist](refactor/compatibility-checklist.md) - Node gateway compatibility tracking

## Quick Links

| Topic | File | Description |
|-------|------|-------------|
| WS handshake | [websocket.md](protocol/websocket.md#connection-lifecycle) | Connect flow, auth methods |
| HTTP hooks | [http.md](protocol/http.md#hooks) | Webhook configuration |
| Token security | [pairing.md](protocol/pairing.md#token-security) | SHA-256 hashing, constant-time comparison |
| Rate limiting | [security.md](security.md#rate-limiting) | Default limits per endpoint |
| Session storage | [architecture.md](architecture.md#key-files) | JSONL history, compaction |
