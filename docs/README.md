# carapace Documentation

A security-focused, open-source personal AI assistant.

## Start Here

- [Getting Started](getting-started.md) — install, first run, and ops
- [Channel Setup](channels.md) — Signal, Telegram, Discord, Slack, webhooks
- [CLI Guide](cli.md) — subcommands, flags, and device identity

## Architecture & Security

- [Architecture](architecture.md) — Component diagrams, request flows, design decisions
- [Security](security.md) — Threat model, trust boundaries, implementation checklist

## Protocol Reference

- [WebSocket Protocol](protocol/websocket.md) — JSON-RPC over WebSocket, methods, events
- [HTTP API](protocol/http.md) — REST endpoints, hooks, OpenAI compatibility
- [Pairing](protocol/pairing.md) — Node and device pairing flows
- [Configuration](protocol/config.md) — Config file format, environment variables
- [Credentials](protocol/credentials.md) — Secret storage
- [CLI Guide](cli.md) — Subcommands, flags, and device identity notes

## Quick Links

| Topic | File | Description |
|-------|------|-------------|
| Trust boundaries | [security.md](security.md#security-layers) | 4-layer defense model |
| WS handshake | [websocket.md](protocol/websocket.md#connection-lifecycle) | Connect flow, auth methods |
| HTTP hooks | [http.md](protocol/http.md#hooks) | Webhook configuration |
| Token security | [pairing.md](protocol/pairing.md#token-security) | SHA-256 hashing, constant-time comparison |
| Rate limiting | [security.md](security.md#rate-limiting) | Default limits per endpoint |
| Inbound classifier | [security.md](security.md#prompt-injection-considerations) | LLM-based attack classification |
| Venice AI provider | [architecture.md](architecture.md#key-files) | OpenAI-compatible composition wrapper |
| Session storage | [architecture.md](architecture.md#key-files) | JSONL history, compaction |
