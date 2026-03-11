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

Run `cara setup --provider <provider>` when you already know which provider you
want, or plain `cara setup` if you want the wizard to ask. If you are unsure,
choose `local-chat` as the first outcome and add channels only after
`cara verify --outcome auto` passes.
In headless or scripted environments, pass `--provider`; non-interactive
`cara setup` now errors instead of writing a providerless config.

### Anthropic / OpenAI (fastest cloud path)

Pick one of these, not both:

```bash
export ANTHROPIC_API_KEY='...'
cara setup --provider anthropic
```

Or:

```bash
export OPENAI_API_KEY='...'
cara setup --provider openai
```

### Ollama (fastest fully local path)

```bash
export OLLAMA_BASE_URL='http://127.0.0.1:11434'
cara setup --provider ollama
```

If your Ollama endpoint requires auth, the wizard will also offer an optional
API key prompt and can write `providers.ollama.apiKey` from either direct input
or `${OLLAMA_API_KEY}`.

### Gemini / Bedrock / Venice

These providers are supported directly by the setup wizard now. If multiple
provider env vars are already set, prefer the explicit provider flag so setup
does not rely on the interactive default.

```bash
export GOOGLE_API_KEY='...'
cara setup --provider gemini --auth-mode api-key
```

Gemini also supports Google sign-in:

```bash
export GOOGLE_OAUTH_CLIENT_ID='...'
export GOOGLE_OAUTH_CLIENT_SECRET='...'
cara setup --provider gemini --auth-mode oauth
```

Notes:

- Gemini OAuth is interactive-only in the CLI because it completes through a loopback callback.
- Control UI also supports Gemini onboarding with either Google sign-in or API key.
- Gemini onboarding stores the Google OAuth client secret with the auth profile; it is not written into `config.json5`.
- Gemini Google sign-in requires `CARAPACE_CONFIG_PASSWORD` so the stored auth profile is encrypted at rest.

```bash
export AWS_REGION='us-east-1'
export AWS_ACCESS_KEY_ID='...'
export AWS_SECRET_ACCESS_KEY='...'
cara setup --provider bedrock
```

```bash
export VENICE_API_KEY='...'
cara setup --provider venice
```

If `GOOGLE_API_KEY` is only for other Google APIs and not for Gemini, unset it
before running `cara setup`. If you need to override the default Gemini or
Venice endpoint, the wizard will offer an optional base URL override.

Supported env vars:

- `ANTHROPIC_API_KEY`
- `OPENAI_API_KEY`
- `GOOGLE_API_KEY`
- `GOOGLE_API_BASE_URL` (Gemini override)
- `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET` (Gemini Google sign-in)
- `OLLAMA_API_KEY` (optional Ollama auth)
- `OLLAMA_BASE_URL` (if non-default)
- `AWS_REGION` or `AWS_DEFAULT_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (Bedrock)
- `AWS_SESSION_TOKEN` (optional Bedrock session token)
- `VENICE_API_KEY`
- `VENICE_BASE_URL` (Venice override)

## Common first-run mistakes

- Multiple provider env vars are set, but you are not sure which one the setup path should use.
- The API key is exported in a different shell than the one running `cara setup` or `cara`.
- You start with a remote channel before local chat and provider verification work.
- You try to solve network exposure, channels, and provider choice all at once.

When in doubt:

1. choose one provider
2. choose `local-chat`
3. run `cara setup --provider <provider>`
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
