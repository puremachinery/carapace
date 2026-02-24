# Providers Hub

## Outcome

Pick and operate an LLM provider configuration with clear defaults and caveats.

## Provider quick picks

- **Anthropic**: strong default for assistant workflows.
- **OpenAI**: broad ecosystem compatibility.
- **Gemini**: Google provider path.
- **Ollama**: local model hosting.
- **Bedrock**: AWS-managed model access.
- **Venice**: OpenAI-compatible Venice endpoint.

## Configure one provider first

Set one provider key, then run setup:

```bash
export ANTHROPIC_API_KEY='...'
cara setup
```

Other supported env vars:

- `OPENAI_API_KEY`
- `GOOGLE_API_KEY`
- `OLLAMA_BASE_URL` (if non-default)
- `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (Bedrock)
- `VENICE_API_KEY`

## Capability matrix

Use the full support matrix for channels/providers/platforms:

- [Capability matrix](capability-matrix.md)

## Next paths

- [Getting Started](../getting-started.md)
- [CLI tasks index](cli-tasks.md)
- [Reference hub](reference.md)
