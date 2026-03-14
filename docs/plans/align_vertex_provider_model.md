# Align Vertex Provider Model Selection

Currently, specifically for Vertex AI, the default model can be configured at the provider level in `carapace.json5` and via environment variables (`VERTEX_MODEL`). This is inconsistent with how other providers are managed, where the model is always supplied on a per-request basis or via prefix routing.

This plan details the changes necessary to remove this provider-level model configuration for Vertex AI, aligning it exactly with the other providers in the system.

## Proposed Changes

### Configuration and Schema

- Update `config.example.json5` (or equivalent schema references) to remove the `model` key from the `vertex` provider block.

### Vertex AI Specific Refactoring

#### [MODIFY] src/agent/factory.rs

- Remove `model` from `VertexConfig` and stop reading it from `std::env::var("VERTEX_MODEL")` and the `vertex` block of `cfg`.
- Call `VertexProvider::new(project_id, location)` without the third `default_model` argument.
- Update the `fingerprint_providers` hash for Vertex to no longer include the `vertex_config.model`.

#### [MODIFY] src/agent/vertex.rs

- Remove `default_model: Option<String>` from the `VertexProvider` struct.
- In `VertexProvider::resolve_request_config`, remove the fallback to `default_model`. If the `effective_model` is `"default"` or empty, immediately return an error `AgentError::Provider("Model name must be provided")`.

## Verification Plan

### Automated Tests

- Run `cargo fmt` and `cargo clippy -- -D warnings` to ensure code style and linting guidelines are met.
- Run `cargo nextest run` to ensure all existing tests pass. We will have to update the unit tests in `src/agent/provider.rs`, `src/agent/factory.rs`, and `src/agent/vertex.rs`:
  - `test_multi_provider_default_model_routes_to_vertex_when_anthropic_missing` in `provider.rs` uses `default_model`, which we will need to adjust.
  - `test_resolve_request_config` in `vertex.rs` tests the generic fallback to `default_model` which will be removed.

### Manual Verification

1. Start the carapace gateway with `CARAPACE_CONFIG_PATH` pointed to a local config that tests Vertex provider actions.
2. We will verify that running Carapace with a completion request with an empty/default model specified for Vertex AI correctly errors out.
3. Establish a WebSocket session or CLI operation requesting a completion from Vertex AI using an explicit model prefix, and monitor gateway logs to ensure the behavior completely aligns with standard parameters as seen in Anthropic or OpenAI handlers.
