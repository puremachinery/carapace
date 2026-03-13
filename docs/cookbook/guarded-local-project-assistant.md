# Use Cara as a guarded local project assistant

## Outcome

Run Cara against one explicit workspace root so it can inspect and search local
project files without getting unrestricted disk access.

## Prerequisites

- `cara` installed and on your PATH.
- Ollama running locally with `llama3` available (`ollama pull llama3` if needed).
- One project directory you want Cara to inspect.

Export these shell variables first:

```bash
export CARAPACE_GATEWAY_TOKEN="$(openssl rand -hex 32)"
export OLLAMA_BASE_URL="http://127.0.0.1:11434"
export WORKSPACE_ROOT="$PWD"
```

Windows (PowerShell) alternative:

```powershell
$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$env:CARAPACE_GATEWAY_TOKEN = [System.BitConverter]::ToString($bytes).Replace('-', '').ToLower()
$env:OLLAMA_BASE_URL = "http://127.0.0.1:11434"
$env:WORKSPACE_ROOT = (Get-Location).Path
```

## 1) Create config

Create `carapace.json5`:

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
  "providers": {
    "ollama": {
      "baseUrl": "${OLLAMA_BASE_URL}"
    }
  },
  "agents": {
    "defaults": {
      "model": "ollama:llama3"
    }
  },
  "filesystem": {
    "enabled": true,
    "roots": ["${WORKSPACE_ROOT}"],
    "excludePatterns": [".git", "node_modules", "target", "*.env"]
  }
}
```

This recipe keeps filesystem access read-only. Cara can read, list, stat, and
search inside `WORKSPACE_ROOT`, but it cannot write or move files until you opt
into `filesystem.writeAccess`.

## 2) Run commands

Start Cara:

```bash
CARAPACE_CONFIG_PATH=./carapace.json5 cara
```

In another terminal:

```bash
export CARAPACE_CONFIG_PATH="$PWD/carapace.json5"
# Reuse the same gateway token value you exported before starting Cara.
export CARAPACE_GATEWAY_TOKEN="paste-the-same-token-here"

cara verify --outcome local-chat --port 18789
cara chat --port 18789
```

If you open a fresh shell instead of reusing the one where you exported the
variables above, re-export `CARAPACE_GATEWAY_TOKEN` there first. The CLI needs
the same config path and gateway token context as the running server.

Then try prompts that exercise the guarded workspace tools:

- `List the top-level files in this workspace and point out the main entry points.`
- `Search this workspace for TODO or FIXME comments and summarize the results.`
- `Read README.md and summarize the setup steps in five bullets.`

## 3) Verify

- `cara verify --outcome local-chat` reports PASS.
- `cara chat` returns model output that refers to files inside your workspace.
- Requests aimed outside the configured root fail instead of reading arbitrary files.
- Files matching `.git`, `node_modules`, `target`, or `*.env` are skipped by the tool layer.

## Next step

- If you want controlled edits, set `"writeAccess": true` under `filesystem`,
  restart Cara, and keep the same narrow root/exclude set.
- If you want editors or other clients to connect through Cara, use the
  [OpenAI-compatible endpoint recipe](openai-compatible-endpoint.md).

## Common failures and fixes

- Symptom: `No provider is currently available`.
  - Fix: Confirm Ollama is running and `OLLAMA_BASE_URL` is correct in the same shell that starts Cara.
- Symptom: Filesystem requests are denied for files you expected to be readable.
  - Fix: Confirm `filesystem.enabled` is `true`, `WORKSPACE_ROOT` is an absolute path, and the target is inside that root.
- Symptom: Changes to `filesystem.roots` or `excludePatterns` do not take effect.
  - Fix: Restart Cara. Filesystem tool registration happens at startup.
- Symptom: Cara cannot inspect files under a nested build or dependency directory.
  - Fix: Check whether your `excludePatterns` intentionally deny that directory (for example `node_modules` or `target`).
