# Capability-Aware Routing for Multimodal Workflows — Deferred

**Status: Deferred.** No concrete user-driven workflow currently justifies
building this. Carapace's canonical answer to "use a different model for
this thing" is **tool-based multimodality** (the agent writes programs or
calls APIs/CLI tools), not capability-based agent/model swapping. This
document records the design space considered so a future contributor does
not have to redo the analysis if a real workflow surfaces.

Issue: [#189](https://github.com/puremachinery/carapace/issues/189).

## Why deferred

- The closest concrete request came from @j-cray on
  [#207](https://github.com/puremachinery/carapace/issues/207) /
  [PR #322](https://github.com/puremachinery/carapace/pull/322) ("ask the
  bot to generate an image and get an output without manually switching
  models"). After discussion, j-cray acknowledged that the tool-based
  framing — exposing image generation as a tool the agent can choose —
  fits Carapace's model better than capability-aware routing, and has not
  followed up with a workflow that doesn't fit that framing.
- Agent identity is already separable from the underlying model
  ([#188](https://github.com/puremachinery/carapace/issues/188)). An
  operator who genuinely wants a different backend for a different agent
  can do that today by configuring two agents and pointing each at the
  intended model.
- The "skills/onboarding UX and multi-agent routing" gap noted in the
  README is more directly served by skills onboarding (separate work) and
  by named routes (already shipped). Capability-aware routing is a
  speculative extension, not a foundation piece.
- Pre-launch product. Adding speculative complexity to a
  security-sensitive resolver path costs review/maintenance time without a
  user it serves.

## Conditions to revisit

Reopen this design (or supersede it with a fresh proposal) when **any** of
the following lands:

1. A concrete user workflow that does not fit the tool-based multimodal
   approach — for example, a request shape where the *same logical agent*
   needs to transparently switch backend providers between turns based on
   declared intent, not based on tool selection.
2. Cost-aware routing requirements (move "expensive" turns to a cheaper
   backend) that demand an automatic mechanism beyond per-agent config.
3. A multi-agent dispatcher feature that needs a typed capability
   declaration as a sub-primitive.
4. Provider-side capability negotiation that the gateway needs to surface
   to callers in a uniform way.

If only the **resolver-shape** improvements are wanted (typed capability
on the request boundary, no auto-routing), prefer adding a tool-policy or
exec-approval surface that lets the operator constrain which tools an
agent may invoke for a given turn — that addresses the same operator
control problem with the existing tool layer.

## Design space considered

The rest of this document records what was considered, what would need to
change in the codebase, and what was left unresolved. None of it is
committed work.

### Capability buckets

If implemented, the candidate initial set would be:

| Capability (camelCase wire form) | Backed by today |
|---|---|
| `vision` | `src/media/` Claude Vision + GPT-4 Vision |
| `imageGeneration` | `src/agent/venice.rs` |
| `audioTranscription` | Whisper via `src/media/` |
| `reasoning` | n/a today |

Excluded for the first slice: `tts` (orthogonal abstraction in
`src/server/ws/handlers/tts.rs`, doesn't flow through `LlmProvider`),
`embeddings` (no shipped surface), `code_execution` / `web_browsing` /
`function_calling` (already covered by tool dispatch and prompt-guard
layers).

The wire form would be camelCase consistently to match the rest of the
JSON-RPC surface (e.g. `imageGeneration`).

### Where capability routes would live

A new optional sub-key under the existing `routes` object:

```json5
routes: {
  fast: { model: "anthropic:claude-sonnet-4-20250514" },
  smart: { model: "anthropic:claude-opus-4-20250514" },
  byCapability: {
    vision:             { route: "smart" },
    imageGeneration:    { model: "venice:flux-1.1-pro" },
    audioTranscription: { model: "openai:whisper-1" },
    reasoning:          { route: "smart" },
  },
},
```

This is the design as drafted. It carries the **open questions** below
that would need resolution before this could ship.

### Resolution order (as drafted)

Highest to lowest precedence:

1. Request override (`route` / `model` directly on the request).
2. Session override (session-pinned `route` / `model`).
3. Per-agent capability override (`agent.capabilityRoutes.<bucket>`) —
   would not exist today, would need to be added.
4. Default capability route (`routes.byCapability.<bucket>`) — would not
   exist today, would need to be added.
5. Agent default (`agent.route` / `agent.model`).
6. Defaults (`agents.defaults.route` / `agents.defaults.model`).

If the caller declared a capability and no level 3 or 4 entry was
configured, the as-drafted design would hard-error rather than fall
through to levels 5–6 — see Open Question O3.

### Detection

If implemented, the first slice would require **explicit caller
declaration** of capability via a typed field on the request. No
MIME-sniffing, no inference from message content. Reasons: predictability
(billing-relevant decision), security (capability is not steerable by
attacker-controlled content), and test surface (typed enum is enforceable
at the boundary).

## Open questions (would need resolution before any implementation)

Several review findings on the original draft of this document
([PR #395](https://github.com/puremachinery/carapace/pull/395)) point at
real correctness gaps. They are **left unresolved** here because a
deferred design is more honest as a record of what was considered than as
a polished spec for unbuilt work. Anyone reopening this should resolve
these first.

### O1. The `RouteConfig` shape would need to change (high)

Today `src/config/routes.rs` defines `RouteConfig` as `{ model: String,
label: Option<String> }` with `model` required. The example above uses
`{ route: "smart" }` (no `model`) for capability entries that delegate to
a named route. That is **not** the existing `RouteConfig` — implementing
this would require either:

- making `model` optional and adding `route: Option<String>`, plus
  validation that exactly one of `model` / `route` is set; or
- introducing a purpose-built capability pointer type and clarifying that
  `routes.byCapability` parsing must not go through the current
  `load_routes` deserialize-each-key-as-`RouteConfig` loop (which would
  warn-skip `byCapability` today and / or reject `{ route: ... }` entries
  as malformed).

The original draft claimed `RouteConfig` was reused unchanged. That claim
was incorrect.

### O2. The default-capability fallback was inconsistent (high)

The draft listed `agents.defaults.capabilityRoutes` as a low-priority
fallback in §2 ("Where capability routes would live") but the §3
pseudocode hard-errored before consulting it. The two surfaces must be
reconciled — either the lookup is genuinely added as a checked level
before the hard error, or `agents.defaults.capabilityRoutes` is dropped
from the proposal and capability routing is documented as always
hard-fail when `routes.byCapability` is absent.

This is the choice point that determines whether the system is "strict"
(hard-fail when nothing matches) or "graceful" (fall through to a
documented default). Both are defensible; pick one and reflect it in
both the prose and the resolver pseudocode.

### O3. Configuration error must not surface as `AgentError::Provider` (medium)

`AgentError::Provider` messages flow to external callers via
`src/server/openai.rs` and the WS layer. Including a literal config-key
path like `routes.byCapability.<bucket>` in the surfaced message leaks
internal configuration topology to anyone who can probe the API — a
low-value but real information leak in a security-first gateway.

If this design is revived, the error must be a distinct variant (e.g. a
`ConfigError::CapabilityNotConfigured { capability }` or similar) that
the server layer maps to a generic, stable code (e.g.
`"capability_not_configured"`) for external callers. The remediation
hint with the exact config key belongs in server logs and the Control
UI, not in the wire-format error string.

### O4. `#[non_exhaustive]` vs "closed enum" (low)

The draft simultaneously called the `Capability` enum "closed" and
proposed `#[non_exhaustive]` on it. Pick one:

- Closed and fixed: drop `#[non_exhaustive]`, accept that adding a
  variant is a breaking change for any future external consumer (likely
  fine for a gateway-internal type).
- Open and forward-compatible: keep `#[non_exhaustive]` but drop the
  "closed" framing, and document that downstream consumers must use a
  wildcard arm.

### O5. Test matrix for the precedence chain

A 6-level resolution chain with a hard-error terminator deserves an
explicit truth-table-style test matrix before the first implementation
PR — capability routing being a billing-relevant decision means that a
precedence bug could silently route production traffic to an unintended
backend. The existing `src/config/routes.rs` tests cover the current
4-level chain and provide a reference shape.

## Typed boundary discipline

Independent of whether this design is ever built, the principle holds:
any capability declaration that crosses the request boundary should be a
closed, typed enum at the API edge, not a free-form string blob or
`serde_json::Value`. Unknown values are rejected at deserialization time;
adding a new value is an explicit enum + schema change. This matches the
typed-boundary discipline documented in
[`AGENTS.md`](../../AGENTS.md) ("Typed Boundary Discipline" section) and
[`.claude/rules/rust-patterns.md`](../../.claude/rules/rust-patterns.md).

## References

- Issue: [#189](https://github.com/puremachinery/carapace/issues/189)
- Walk-back conversation: [#207](https://github.com/puremachinery/carapace/issues/207),
  [PR #322](https://github.com/puremachinery/carapace/pull/322)
- Agent identity separation (already shipped): [#188](https://github.com/puremachinery/carapace/issues/188)
- Existing resolver: `src/config/routes.rs` (named-routes, `SelectorLevel`)
- Provider abstraction: `src/agent/provider.rs`
- Provider construction: `src/agent/factory.rs`
- Multimodal-adjacent surfaces shipped today: `src/media/` (Vision,
  Whisper), `src/agent/venice.rs` (Venice provider, image-capable models)
- Architecture overview: [`docs/architecture.md`](../architecture.md)
- Feature inventory: [`docs/feature-status.yaml`](../feature-status.yaml)
- Repository conventions: [`AGENTS.md`](../../AGENTS.md),
  [`.claude/rules/rust-patterns.md`](../../.claude/rules/rust-patterns.md)
