# Providers Hub

## Outcome

Pick a first provider with the shortest path to a verified useful outcome.

## Recommended first choices

- **Fastest cloud start**: Anthropic or OpenAI
  - One API key, common setup path, best fit if your immediate goal is "get to first reply quickly."
- **Fastest local-only start**: Ollama
  - Best fit if your immediate goal is "keep everything local and verify the basic loop first."
- **Existing cloud standardization**: Gemini or Bedrock
  - Good if your environment is already centered on Google Cloud or AWS.
- **OpenAI-compatible alternative path**: Venice
  - Good if you specifically want Venice's endpoint and API shape.

If you are undecided, do not optimize for the perfect long-term setup yet.
Optimize for the shortest verified first run, then change providers later if needed.

## Start with one provider only

Run `cara setup` after configuring exactly one provider path. If you are unsure,
choose `local-chat` as the first outcome and add channels only after
`cara verify --outcome auto` passes.

### Anthropic / OpenAI (fastest cloud path)

```bash
export ANTHROPIC_API_KEY='...'
cara setup
```

```bash
export OPENAI_API_KEY='...'
cara setup
```

### Ollama (fastest fully local path)

```bash
export OLLAMA_BASE_URL='http://127.0.0.1:11434'
cara setup
```

### Gemini / Bedrock / Venice

These are fully supported, but only choose them first if they already match your environment or provider preference.

```bash
export GOOGLE_API_KEY='...'
cara setup
```

```bash
export AWS_REGION='us-east-1'
export AWS_ACCESS_KEY_ID='...'
export AWS_SECRET_ACCESS_KEY='...'
cara setup
```

```bash
export VENICE_API_KEY='...'
cara setup
```

Supported env vars:

- `ANTHROPIC_API_KEY`
- `OPENAI_API_KEY`
- `GOOGLE_API_KEY`
- `OLLAMA_BASE_URL` (if non-default)
- `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (Bedrock)
- `VENICE_API_KEY`

## Common first-run mistakes

- Multiple provider env vars are set, but you are not sure which one the setup path should use.
- The API key is exported in a different shell than the one running `cara setup` or `cara`.
- You start with a remote channel before local chat and provider verification work.
- You try to solve network exposure, channels, and provider choice all at once.

When in doubt:

1. choose one provider
2. choose `local-chat`
3. run `cara setup`
4. start `cara`
5. run `cara verify --outcome auto --port 18789`

## Capability matrix

Use the full support matrix for channels/providers/platforms:

- [Capability matrix](capability-matrix.md)

## Need help choosing?

- [Guided setup help](help.md#guided-setup-help)
- [Team setup / pilot request](help.md#team-setup-and-pilot-request)

## Next paths

- [Getting Started](../getting-started.md)
- [First Run](first-run.md)
- [Help](help.md)
- [CLI tasks index](cli-tasks.md)
- [Reference hub](reference.md)
