# Route requests to different models

## Outcome

Define named execution routes so different agents or requests use different
backends — for example, a fast/cheap model for quick lookups and a strong
model for complex reasoning — without repeating `provider:model` strings
everywhere.

## Prerequisites

- `cara` installed.
- API keys for at least two providers (or two models from the same provider).

## 1) Create config

Generate a gateway token:

```bash
export CARAPACE_GATEWAY_TOKEN="$(openssl rand -hex 32)"
```

Windows (PowerShell) alternative:

```powershell
$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$env:CARAPACE_GATEWAY_TOKEN = [System.BitConverter]::ToString($bytes).Replace('-', '').ToLower()
```

```json5
{
  "gateway": {
    "bind": "loopback",
    "port": 18789,
    "auth": {
      "mode": "token",
      "token": "${CARAPACE_GATEWAY_TOKEN}"
    }
  },
  // Define routes once, reference by name
  "routes": {
    "fast":   { "model": "gemini:gemini-2.5-flash" },
    "strong": { "model": "anthropic:claude-opus-4-6" }
  },
  // Default all agents to the fast route
  "agents": {
    "defaults": {
      "route": "fast"
    }
  },
  "anthropic": {
    "apiKey": "${ANTHROPIC_API_KEY}"
  },
  "google": {
    "apiKey": "${GOOGLE_API_KEY}"
  }
}
```

Key points:
- `routes` defines named backends. Each route has a `model` string using
  `provider:model` syntax.
- `agents.defaults.route` sets the default for all agents.
- Individual agents can override with their own `route` or `model` field.
- `route` takes precedence over `model` when both are set.

## 2) Run commands

```bash
CARAPACE_CONFIG_PATH=./carapace.json5 cara
```

In another terminal:

```bash
cara status --port 18789
cara chat
```

## 3) Verify

- `cara chat` uses the fast route (Gemini) by default.
- Check logs to confirm the expected provider is called:
  ```bash
  cara logs -n 50
  ```
- To test the strong route, set it on a per-agent or per-session basis via
  config or the Control API.

## Variations

**Single provider, multiple models:**

```json5
"routes": {
  // Date-suffixed IDs pin a specific stable snapshot; non-dated aliases
  // (e.g. `claude-opus-4-6`) track the latest snapshot for that family.
  "fast":   { "model": "anthropic:claude-haiku-4-5-20251001" },
  "strong": { "model": "anthropic:claude-opus-4-6" }
}
```

**Local + cloud hybrid:**

```json5
"routes": {
  "local":  { "model": "ollama:llama3" },
  "cloud":  { "model": "anthropic:claude-sonnet-4-6" }
}
```

## Next step

- [5-minute secure local setup](secure-local-first-reply.md)
- [Config reference — named routes](../protocol/config-reference.md#2a-named-routes-optional)
- [Day-2 ops](../site/ops.md)

## Common failures and fixes

- Symptom: `unknown route` error at startup.
  - Fix: Confirm the route name in `agents.defaults.route` matches a key in
    the `routes` map exactly.
- Symptom: `bare model name rejected` validation error.
  - Fix: Every `model` string requires a `provider:` prefix. Use
    `anthropic:claude-opus-4-6`, not just `claude-opus-4-6`.
- Symptom: Requests use the wrong model.
  - Fix: `route` takes precedence over `model`. If an agent has both, the
    route wins. Remove the `route` field to use `model` directly.
