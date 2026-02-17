# First Run

## Outcome

Start Carapace in secure local mode, verify health, and get your first response in `cara chat`.

## Prerequisites

- `cara` installed: [/carapace/install.html](/carapace/install.html)
- One provider key set in your shell:
  - `ANTHROPIC_API_KEY` or
  - `OPENAI_API_KEY`

## 1) Generate service token

```bash
export CARAPACE_GATEWAY_TOKEN="$(openssl rand -hex 32)"
```

## 2) Create minimal config (`carapace.json5`)

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
  "anthropic": {
    "apiKey": "${ANTHROPIC_API_KEY}"
  }
}
```

If using OpenAI instead:

```json5
"openai": {
  "apiKey": "${OPENAI_API_KEY}"
}
```

## 3) Start Carapace

```bash
CARAPACE_CONFIG_PATH=./carapace.json5 cara
```

## 4) Smoke checks (expected checkpoints)

In a second terminal:

```bash
cara status --host 127.0.0.1 --port 18789
curl -H "Authorization: Bearer ${CARAPACE_GATEWAY_TOKEN}" http://127.0.0.1:18789/health
cara chat
```

Expected:

- `cara status` shows service healthy.
- `/health` returns JSON with `"status":"ok"`.
- `cara chat` opens REPL and returns a model response.

## 5) Continue

- Need channel setup? Go to [Cookbook](/carapace/cookbook/)
- Just want Discord first? Use [Add Carapace to Discord](/carapace/cookbook/discord-assistant.html)
- Stuck? Use [/carapace/get-unstuck.html](/carapace/get-unstuck.html)
