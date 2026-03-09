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

Pick one of these, not both:

```bash
export ANTHROPIC_API_KEY='...'
cara setup
```

Or:

```bash
export OPENAI_API_KEY='...'
cara setup
```

### Ollama (fastest fully local path)

The runtime supports Ollama today, but the interactive `cara setup` wizard
still writes Anthropic/OpenAI first-run config. If `OLLAMA_BASE_URL` is set
and neither `ANTHROPIC_API_KEY` nor `OPENAI_API_KEY` is set, `cara setup` will
stop and ask whether you want to continue with that wizard anyway.

```bash
export OLLAMA_BASE_URL='http://127.0.0.1:11434'
```

If you are staying on Ollama first, skip the Anthropic/OpenAI wizard, copy the
`ollama` section from `config.example.json5`, and use
[Guided setup help](help.md#guided-setup-help) if you want help getting to a
verified local-chat first run.

### Gemini / Bedrock / Venice

These are fully supported at runtime, but the interactive `cara setup` wizard
still writes Anthropic/OpenAI first-run config. If neither
`ANTHROPIC_API_KEY` nor `OPENAI_API_KEY` is set and the matching env vars are
present, `cara setup` will stop and ask whether you want to continue with that
wizard anyway. For Bedrock, that means a region plus both
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
If `GOOGLE_API_KEY` is only for other Google APIs and not for Gemini, unset it
before running `cara setup`.

```bash
export GOOGLE_API_KEY='...'
```

```bash
export AWS_REGION='us-east-1'
export AWS_ACCESS_KEY_ID='...'
export AWS_SECRET_ACCESS_KEY='...'
```

```bash
export VENICE_API_KEY='...'
```

If you are staying on Gemini, Bedrock, or Venice first, skip the
Anthropic/OpenAI wizard, copy the relevant provider section from
`config.example.json5`, and use [Guided setup help](help.md#guided-setup-help)
if you want a shorter path to a verified first run.

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
