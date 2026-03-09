# First Run

## Outcome

Run `cara setup`, start Carapace, and complete your first useful assistant workflow.

## Prerequisites

- `cara` installed: [Install guide](install.md)
- One supported provider configured:
  - `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`, or `VENICE_API_KEY`, or
  - local Ollama (`OLLAMA_BASE_URL`)

## 0) Pick the simplest first path

If you are not sure where to start:

- choose `local-chat` as your first outcome
- start with one provider only
- use Anthropic/OpenAI for the fastest cloud path, or Ollama for the fastest fully local path
- add Discord, Telegram, or hooks only after `cara verify --outcome auto` passes

If provider choice is the blocker, use the [Providers hub](providers.md).
If you want a maintainer to help you pick the shortest path, use [Help](help.md).

## 1) Run the setup wizard

```bash
cara setup
```

The wizard walks you through:
- provider selection (or use `cara setup --provider <provider>` to skip the menu),
- provider credentials and first-run model defaults,
- gateway auth mode (`token`/`password`) and strong-secret generation,
- bind + port,
- first-run outcome:
  - `local-chat`
  - `discord`
  - `telegram`
  - `hooks`
- optional hooks token and Control UI toggle.

Recommended explicit examples (pick one, based on your provider):

```bash
# Pick ONE of these commands:
cara setup --provider anthropic
cara setup --provider ollama
cara setup --provider gemini
```

## 2) Start Carapace

```bash
cara
```

## 3) Run smoke checks

In a second terminal:

```bash
cara verify --outcome auto --port 18789
cara verify --outcome autonomy --port 18789
cara status --port 18789
cara chat --port 18789
```

Expected:

- `cara verify` prints a pass/fail summary for your selected outcome.
- `cara verify --outcome autonomy` proves task start (`attempts > 0`) and
  terminal state (`done` or `blocked`).
- `cara status` shows the service healthy.
- `cara chat` opens the REPL and returns a model response.

If you set a custom port during setup, use that instead of `18789`.
If your selected outcome is `discord` or `telegram`, `cara verify` may also
require destination flags (`--discord-to` / `--telegram-to`) for send-path checks.

## 4) Complete your chosen first outcome

- `local-chat`:
  - Continue in `cara chat`, or try the [local first-reply recipe](../cookbook/secure-local-first-reply.md).
- `discord`:
  - Continue with [Add Carapace to Discord](../cookbook/discord-assistant.md)
- `telegram`:
  - Continue with [Add Carapace to Telegram](../cookbook/telegram-webhook-assistant.md)
- `hooks`:
  - Continue with [Trigger Cara from other apps](../cookbook/hooks-safe-automation.md)

## Continue

- Need a specific task flow? Go to [Cookbook](../cookbook/README.md)
- Want guided help or a team evaluation path? Use [Help](help.md)
- Stuck? Use [Get Unstuck](get-unstuck.md)
