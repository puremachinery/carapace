# First Run

## Outcome

Run `cara setup`, start Carapace, and complete your first useful assistant workflow.

## Prerequisites

- `cara` installed: [Install guide](install.md)
- One provider key available in your shell:
  - `ANTHROPIC_API_KEY`, or
  - `OPENAI_API_KEY`

## 1) Run the setup wizard

```bash
cara setup
```

The wizard walks you through:
- provider + API key (with optional credential validation),
- gateway auth mode (`token`/`password`) and strong-secret generation,
- bind + port,
- first-run outcome:
  - `local-chat`
  - `discord`
  - `telegram`
  - `hooks`
- optional hooks token and Control UI toggle.

## 2) Start Carapace

```bash
cara
```

## 3) Run smoke checks

In a second terminal:

```bash
cara status --host 127.0.0.1 --port 18789
cara chat --port 18789
```

Expected:

- `cara status` shows the service healthy.
- `cara chat` opens the REPL and returns a model response.

If you set a custom port during setup, use that instead of `18789`.

## 4) Complete your chosen first outcome

- `local-chat`:
  - You can continue in `cara chat`.
- `discord`:
  - Continue with [Add Carapace to Discord](../cookbook/discord-assistant.md)
- `telegram`:
  - Continue with [Set up Telegram inbound + reply flow](../cookbook/telegram-webhook-assistant.md)
- `hooks`:
  - Continue with [Expose hooks safely with token auth](../cookbook/hooks-safe-automation.md)

## Continue

- Need a specific task flow? Go to [Cookbook](../cookbook/README.md)
- Stuck? Use [Get Unstuck](get-unstuck.md)
