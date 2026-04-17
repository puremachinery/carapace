# Providers Hub

## Outcome

Pick a first provider with the shortest path to a verified useful outcome.

## Recommended first choices

- **Fastest cloud start**: Anthropic or OpenAI
  - One API key, common setup path, best fit if your immediate goal is "get to first reply quickly."
- **Subscription-login path**: Codex
  - Best fit if you want OpenAI subscription-backed usage separated cleanly from API-key OpenAI.
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

### Anthropic / OpenAI API key (fastest cloud path)

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

Anthropic also supports a setup-token-backed auth profile:

```bash
export CARAPACE_CONFIG_PASSWORD='...'
export ANTHROPIC_SETUP_TOKEN='...'
cara setup --provider anthropic --auth-mode setup-token
```

Notes:

- This keeps the Anthropic setup-token out of config and stores it in the encrypted auth-profile store.
- The resulting config uses `anthropic.authProfile`.
- `cara setup --provider anthropic --auth-mode api-key` keeps the existing direct API-key path.

### Codex (OpenAI subscription login)

```bash
export CARAPACE_CONFIG_PASSWORD='...'
export OPENAI_OAUTH_CLIENT_ID='...'
export OPENAI_OAUTH_CLIENT_SECRET='...'
cara setup --provider codex
```

Notes:

- Codex is separate from API-key `openai`.
- Codex sign-in is interactive-only in the CLI because it completes through a loopback callback on a local port.
- Control UI also supports Codex sign-in.
- The resulting config uses `codex.authProfile` and defaults the agent model to `codex:default`.
- `CARAPACE_CONFIG_PASSWORD` is required so the stored auth profile is encrypted at rest.

### Ollama (fastest fully local path)

```bash
export OLLAMA_BASE_URL='http://127.0.0.1:11434'
cara setup --provider ollama
```

If your Ollama endpoint requires auth, the wizard will also offer an optional
API key prompt and can write `providers.ollama.apiKey` from either direct input
or `${OLLAMA_API_KEY}`.

### Vertex AI

Vertex AI supports Google Gemini models and third-party models from
Anthropic, Meta, Mistral, and Nvidia. Authentication uses `gcloud` CLI
credentials or the GCE metadata server.

Prerequisite: authenticate with `gcloud auth application-default login` so
Carapace can obtain access tokens.

```bash
export VERTEX_PROJECT_ID='my-gcp-project'
export VERTEX_LOCATION='us-central1'   # optional, defaults to us-central1
cara setup --provider vertex
```

Gemini models use the short form in agent config:

```json5
// agents.defaults.model or agents.list[].model
{ "model": "vertex:gemini-2.5-flash" }
```

Third-party models use the full publisher path from the Vertex AI Model
Garden. You must enable the model's API in your GCP project first.

```text
// agents.defaults.model or agents.list[].model
vertex:publishers/anthropic/models/claude-sonnet-4-6
vertex:publishers/meta/models/llama-3.1-405b-instruct-maas
vertex:publishers/mistral/models/mistral-large-2411
vertex:publishers/nvidia/models/llama-3.1-nemotron-70b-instruct
```

Vertex AI accepts both short aliases (e.g. `claude-sonnet-4-6`) and
dated snapshot IDs (e.g. `claude-sonnet-4-20250514`) for Anthropic
publisher models. Use the aliased form to follow the latest snapshot,
or pin to a dated ID when you need a specific stable snapshot. Check
the [Vertex AI Model Garden](https://console.cloud.google.com/vertex-ai/model-garden)
for the currently published model IDs per publisher.

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

- Gemini OAuth is interactive-only in the CLI because it completes through a loopback callback on a local port.
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

- `VERTEX_PROJECT_ID`, `VERTEX_LOCATION`, `VERTEX_MODEL` (Vertex AI)
- `ANTHROPIC_API_KEY`
- `OPENAI_API_KEY`
- `OPENAI_OAUTH_CLIENT_ID` / `OPENAI_OAUTH_CLIENT_SECRET` (Codex OpenAI sign-in)
- `GOOGLE_API_KEY`
- `GOOGLE_API_BASE_URL` (Gemini override)
- `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET` (Gemini Google sign-in)
- `OLLAMA_API_KEY` (optional Ollama auth)
- `OLLAMA_BASE_URL` (if non-default)
- `AWS_REGION` or `AWS_DEFAULT_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (Bedrock)
- `AWS_SESSION_TOKEN` (optional Bedrock session token)
- `VENICE_API_KEY`
- `VENICE_BASE_URL` (Venice override)

## Provider Routing

Carapace automatically routes your requests to the correct AI provider based on the `model` string configured in your agent (see [agent.model](../protocol/config-reference.md)).

- **Canonical Provider Prefix**: Every model requires an explicit `provider:model` colon prefix: `anthropic:claude-sonnet-4-6`, `openai:gpt-5.4`, `gemini:gemini-2.5-flash`, `vertex:gemini-2.5-flash`, `vertex:publishers/anthropic/models/claude-sonnet-4-6`, `bedrock:anthropic.claude-3-sonnet`, `ollama:llama3`, `codex:default`, `venice:llama-3.3-70b`, `claude-cli:opus`.
- **No implicit routing**: Bare model names (without a `provider:` prefix) are rejected with a clear error. Always specify the provider.

Here is an example `carapace.json5` snippet locking agents onto specific providers using prefixes:

```json5
{
  "agents": {
    "list": [
      {
        "id": "researcher",
        "model": "vertex:gemini-2.5-flash",
        "system": "You are a specialized research assistant."
      },
      {
        "id": "local-coder",
        "model": "ollama:qwen2.5-coder",
        "system": "You are a local coding assistant."
      }
    ]
  }
}
```

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
