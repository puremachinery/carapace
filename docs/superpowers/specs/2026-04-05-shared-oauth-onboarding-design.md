# Shared OAuth Onboarding Flow

Issue #201, Slice 1: Extract shared OAuth onboarding lifecycle from Codex and Gemini.

## Problem

Codex (`onboarding/codex.rs`, ~1,128 lines) and Gemini (`onboarding/gemini.rs`, ~1,589 lines) implement nearly identical OAuth onboarding flows. The browser flow state machine, CLI fallback server, Control UI handlers, and OAuth-profile persistence are structurally identical, differing only in provider enum, env var names, config paths, and error messages. ~1,500 lines of duplication.

## Owning Abstraction

The shared OAuth onboarding lifecycle (`src/onboarding/oauth.rs`) owns browser flow initiation, CLI fallback, Control flow status/apply, and OAuth-profile persistence. Provider-specific config resolution, profile construction, and config mutation live in typed `fn` hooks on a static spec struct.

**Invariant**: These mechanics stay behaviorally aligned across providers. Adding a new OAuth provider means defining a new `OAuthOnboardingSpec` instance, not duplicating flow logic.

## Non-Goals

- Changing external onboarding API shape (Control UI endpoints stay the same)
- Merging provider-specific config semantics
- Touching `setup.rs` assessment logic
- Modifying the Gemini API-key onboarding path
- Broad onboarding redesign

## Design

### OAuthOnboardingSpec

A plain struct with static data and `fn` pointers. One `static` instance per provider.

```rust
pub(crate) struct OAuthOnboardingSpec {
    // --- Identity ---
    pub oauth_provider: OAuthProvider,
    pub display_name: &'static str,       // "Codex" / "Gemini"
    pub idp_display_name: &'static str,   // "OpenAI" / "Google" — for "sign in with X for Y"
    pub provider_label: &'static str,     // "codex" / "gemini" — derives callback_path

    // --- Env var names ---
    pub client_id_env: &'static str,
    pub client_secret_env: &'static str,

    // --- Per-provider flow limits ---
    pub max_pending_flows: usize,         // 20 per provider (preserves current per-provider quota)
    pub flow_ttl_secs: u64,              // 1800 (30 min)

    // --- Provider hooks (fn pointers) ---

    /// Resolve OAuth provider config from config, env vars, overrides, and stored state.
    pub resolve_provider_config: fn(
        cfg: &Value,
        client_id_override: Option<String>,
        client_secret_override: Option<String>,
        redirect_uri: String,
        state_dir: &Path,
    ) -> Result<OAuthProviderConfig, String>,

    /// Build an AuthProfile from completed OAuth tokens, provider config, and user info.
    /// Takes owned values — current builders consume both tokens and user info.
    pub build_auth_profile: fn(
        tokens: OAuthTokens,
        provider_config: &OAuthProviderConfig,
        user_info: OAuthUserInfo,
    ) -> AuthProfile,

    /// Write provider-specific config keys after profile persistence.
    /// Called with the profile_id and client_id after the shared engine
    /// completes the match-and-upsert cycle.
    pub write_provider_config: fn(
        cfg: &mut Value,
        profile_id: &str,
        client_id: &str,
    ),
}
```

The `callback_path` is derived from `provider_label` (e.g., `/control/onboarding/{provider_label}/callback`), not carried as a separate string.

### Shared Flow Engine (oauth.rs)

Generic functions parameterized by `&'static OAuthOnboardingSpec`:

- **`start_oauth_flow(spec, cfg, overrides, redirect_uri, state_dir)`** — calls `spec.resolve_provider_config`, creates `PendingOAuthFlow`, generates auth URL, stores in per-spec flow map. Returns flow ID + auth URL.
- **`complete_oauth_callback(spec, state, code, error)`** — looks up the pending flow by OAuth `state` parameter (not flow ID — Control callbacks arrive with state/code/error, not flow_id). Exchanges authorization code for tokens, fetches user info, transitions flow to `Completed` or `Failed`.
- **`oauth_flow_status(spec, flow_id)`** — returns typed status enum (Pending/InProgress/Completed/Failed).
- **`apply_oauth_flow(spec, flow_id, state_dir, cfg)`** — calls `spec.build_auth_profile` to construct the profile, resolves the env-backed `ProfileStore` from `state_dir`, performs the full match-and-upsert cycle, then calls `spec.write_provider_config`. Returns a typed `OAuthApplyResult`. The shared engine owns store construction and loading — callers pass `state_dir`, not a prebuilt store.
- **`run_cli_oauth(spec, cfg, state_dir)`** — spawns localhost callback server, opens browser, waits with timeout. Resolves `ProfileStore` from `state_dir` internally. CLI fallback path.
- **`persist_cli_oauth(spec, tokens, provider_config, user_info, state_dir, cfg)`** — CLI-side: builds profile via hook, resolves store from `state_dir`, match-and-upsert, writes config via hook.

### Flow State

Single generic enum and struct replacing the duplicated variants:

```rust
pub(crate) enum OAuthFlowState {
    Pending,
    InProgress,
    Completed(Box<OAuthCompletion>),
    Failed(String),
}

pub(crate) struct PendingOAuthFlow {
    pub id: String,
    pub state: String,
    pub code_verifier: String,
    pub provider_config: OAuthProviderConfig,
    pub created_at_ms: u64,
    pub flow_state: OAuthFlowState,
    pub spec: &'static OAuthOnboardingSpec,
}
```

### Flow Storage

One global `LazyLock<RwLock<HashMap<String, PendingOAuthFlow>>>` replaces the two separate maps. Per-provider limits are enforced by counting flows matching `flow.spec.provider_label` before inserting, preserving the current "20 per provider" quota (not "20 total"). Flow expiry TTL and user-facing error text are parameterized by spec to prevent cross-provider coupling from creeping back in.

### Typed Results

The shared engine returns typed results, not `serde_json::Value`:

```rust
pub(crate) struct OAuthStartResult {
    pub flow_id: String,
    pub auth_url: String,
}

pub(crate) enum OAuthStatusResult {
    InProgress,  // Pending and InProgress are collapsed — callers see "pending" for both
    Completed {
        profile_name: String,
        email: Option<String>,
    },
    Failed { error: String },
    NotFound,
}

pub(crate) struct OAuthApplyResult {
    pub profile_id: String,
}
```

Control handlers map these into their existing provider-specific HTTP response payloads. Codex and Gemini do not currently return the same apply shape — the thin provider wrappers in `control.rs` preserve each provider's distinct response format.

### Control UI Handlers

Explicit routes stay — no dynamic routing by prefix. Each provider keeps thin handler wrappers in `control.rs` that look up the provider's `&'static OAuthOnboardingSpec` and delegate to the shared engine:

```rust
// Explicit routes (unchanged URLs):
POST /control/onboarding/codex/oauth/start  -> codex_oauth_start_handler()
GET  /control/onboarding/codex/oauth/{id}   -> codex_oauth_status_handler()
POST /control/onboarding/codex/oauth/{id}/apply -> codex_oauth_apply_handler()
GET  /control/onboarding/codex/callback     -> codex_oauth_callback_handler()

POST /control/onboarding/gemini/oauth/start  -> gemini_oauth_start_handler()
GET  /control/onboarding/gemini/oauth/{id}   -> gemini_oauth_status_handler()
POST /control/onboarding/gemini/oauth/{id}/apply -> gemini_oauth_apply_handler()
GET  /control/onboarding/gemini/callback     -> gemini_oauth_callback_handler()
```

Each handler shrinks to ~5 lines: extract params, call `oauth::start_oauth_flow(&CODEX_SPEC, ...)`, map result to HTTP response.

### Profile-Store Persistence

The shared engine owns the full match-and-upsert cycle, not just a raw `ProfileStore::upsert`. Current `upsert_openai_profile()` and `upsert_google_profile()` both load the store, call `find_matching(provider, user_id, email)` to preserve existing profile IDs and `created_at_ms`, then upsert. That whole sequence is the shared invariant.

The persistence sequence:

1. `spec.build_auth_profile(tokens, provider_config, user_info)` — provider hook builds the `AuthProfile`
2. Shared engine loads the profile store, calls `find_matching` by provider/user_id/email to detect existing profiles, preserves `id` and `created_at_ms` if found, then upserts — this is the structurally shared match-and-upsert behavior
3. `spec.write_provider_config(cfg, &profile_id, &client_id)` — provider hook writes config keys

This keeps the full persistence lifecycle in one place while provider-specific config mutation stays in hooks.

## File Layout

| File | Change | Approximate size after |
|------|--------|----------------------|
| `src/onboarding/oauth.rs` | **New** — shared flow engine + types | ~600 lines |
| `src/onboarding/codex.rs` | Shrinks — spec definition + 3 hook fns | ~150 lines |
| `src/onboarding/gemini.rs` | Shrinks — spec + hooks + API-key path | ~400 lines |
| `src/onboarding/mod.rs` | Add `pub mod oauth;` | trivial |
| `src/server/control.rs` | OAuth handlers delegate to shared engine | net reduction ~200 lines |
| `src/cli/mod.rs` | CLI OAuth calls use shared engine | net reduction ~100 lines |

**Net elimination**: ~1,200-1,400 lines of duplicated code.

## Testing

- Existing Codex/Gemini onboarding tests migrate to call through the shared engine.
- Provider hook functions are independently unit-testable (they're plain `fn` pointers).
- The shared engine gets its own tests for flow lifecycle (start/status/apply/expire/per-provider limits).
- Control handler tests verify the thin wrappers produce correct HTTP responses.

## What This Does Not Touch

- `setup.rs` — assessment logic reads persisted config, doesn't interact with OAuth flows
- `anthropic.rs` — different auth mechanism (setup tokens, not OAuth)
- `vertex.rs` — no auth flow (uses ADC)
- `bedrock.rs` — different auth mechanism (static AWS credentials)
- Gemini API-key onboarding path — stays in `gemini.rs`
