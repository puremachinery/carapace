# First Run

## Outcome

Start Carapace in secure local mode, verify health, and get your first response in `cara chat`.

## Prerequisites

- `cara` installed: [Install guide](install.md)
- One provider key set in your shell:
  - `ANTHROPIC_API_KEY` or
  - `OPENAI_API_KEY`

## macOS/Linux

### 1) Generate service token

```bash
export CARAPACE_GATEWAY_TOKEN="$(openssl rand -hex 32)"
```

### 2) Create minimal config (`carapace.json5`)

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

### 3) Start Carapace

```bash
CARAPACE_CONFIG_PATH=./carapace.json5 cara
```

### 4) Smoke checks (expected checkpoints)

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

## Windows (PowerShell)

### 1) Generate service token

```powershell
$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$env:CARAPACE_GATEWAY_TOKEN = [System.BitConverter]::ToString($bytes).Replace('-', '').ToLower()
```

### 2) Create minimal config (`carapace.json5`)

Use the same config shown in the macOS/Linux path above.

### 3) Start Carapace

```powershell
$env:CARAPACE_CONFIG_PATH = ".\\carapace.json5"
cara
```

### 4) Smoke checks (expected checkpoints)

In a second PowerShell terminal:

```powershell
cara status --host 127.0.0.1 --port 18789
curl.exe -H "Authorization: Bearer $env:CARAPACE_GATEWAY_TOKEN" http://127.0.0.1:18789/health
cara chat
```

Expected:

- `cara status` shows service healthy.
- `/health` returns JSON with `"status":"ok"`.
- `cara chat` opens REPL and returns a model response.

## Continue

- Need channel setup? Go to [Cookbook](../cookbook/README.md)
- Just want Discord first? Use [Add Carapace to Discord](../cookbook/discord-assistant.md)
- Stuck? Use [Get Unstuck](get-unstuck.md)
