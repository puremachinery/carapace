# Capability Matrix

## Outcome

See what works today across channels, providers, and platforms, including caveats.

## Channels

| Area | Support level | Notes / caveats |
|---|---|---|
| Telegram | Verified | Webhook mode + long-polling fallback supported. |
| Discord | Verified | Gateway + outbound flows supported. |
| Slack | Implemented (smoke pending) | Runtime wiring present; live smoke evidence pending. |
| Signal | Implemented (smoke pending) | Inbound polling, typing indicators, and after-response read receipts are implemented; live smoke evidence pending. |
| Hooks (automation) | Verified | Token-authenticated wake/agent/mapping endpoints. |

## Providers

| Provider | Support level | Notes / caveats |
|---|---|---|
| Anthropic | Verified | Streaming + tools + cancellation. |
| OpenAI | Verified | Streaming + tools + cancellation. |
| Gemini | Verified | Streaming + tools + cancellation. |
| Vertex AI | Verified | Google-published Gemini models on Vertex AI are supported. |
| Ollama | Verified | Local serving path supported. |
| Bedrock | Verified | SigV4 + streaming/event path wired. |
| Venice AI | Verified | OpenAI-compatible wrapper/provider wiring. |

## Tools / local workspace

| Area | Support level | Notes / caveats |
|---|---|---|
| Filesystem tools | Verified | `file_read`, `directory_list`, `file_stat`, and `file_search` register when `filesystem.enabled = true`. `file_write` and `file_move` require `filesystem.writeAccess = true`. Access stays inside configured roots and excludes, and config changes require restart. |

## Platform/runtime

| Area | Support level | Notes / caveats |
|---|---|---|
| Control UI (`/ui`) | Foundation shipped | Auth/session handling, status/channels, redacted config read + safe patch path, task operator actions, pairing flow. |
| macOS sandboxing | Verified | Seatbelt + limits for sandbox-required subprocess paths. |
| Linux sandboxing | Verified | Landlock + limits for sandbox-required subprocess paths. |
| Windows sandboxing | Partial | Job Objects + AppContainer paths; unsupported deny-network spawn paths fail closed. |
| Unsupported targets | Verified fail-closed | Sandbox-required subprocess flows are rejected rather than unsandboxed. |

## Source of truth

- [Feature status inventory](../feature-status.yaml)
- [Feature evidence inventory](../feature-evidence.yaml)
- [Channel smoke playbook](../channel-smoke.md)
