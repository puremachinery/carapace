# Roadmap

This roadmap is directional, not a date-based promise. Priorities may shift as
we get real user feedback.

For what is already shipped and verified, see:

- [Feature status](feature-status.yaml)
- [Feature evidence](feature-evidence.yaml)

## Recently shipped

- Cross-platform subprocess sandbox hardening — macOS, Linux, and Windows
  enforce OS-level isolation for sandbox-required paths; unsupported platforms
  fail closed.
- Control UI foundation — local browser UI for status/channels, safe
  `gateway.controlUi.*` config patching, device pairing, and task queue
  operator actions.
- Long-running assistant MVP — durable task queue with restart recovery,
  operator task controls (`create/list/get/patch/cancel/retry/resume`),
  continuation policy budgets, blocked-state handling, and autonomy verification
  (`cara verify --outcome autonomy`).
- Outcome-driven setup flow (`cara setup`) with provider credential validation.
- First-run verifier (`cara verify`) with pass/fail outcome checks.
- Gemini onboarding — Google sign-in or API-key setup via `cara setup` and the
  Control UI, backed by shared onboarding flow state and `google.authProfile`
  runtime support.
- Codex onboarding — OpenAI subscription-login setup via `cara setup` and the
  Control UI, backed by `codex.authProfile` runtime support.
- Managed and local WASM plugins — startup/runtime loading, `plugins.*` API
  surface, `cara plugins` CLI workflows, and plugin development guidance.
  Local `cara plugins install/update --file` staging assumes a trusted,
  single-user state directory. Do not use that workflow where other users can
  write to the same state directory.
  Issue: [#250](https://github.com/puremachinery/carapace/issues/250)
- Filesystem tools — guarded local workspace read/search/stat/list plus opt-in
  write/move within explicit roots, with config-gated registration and
  fail-closed validation.
- Multi-page docs site with install/first-run/security/ops plus docs hubs,
  capability matrix, and task-oriented CLI index.

## Next

These items are listed in priority order. The top item is the current focus.
This replaces the older `Now` bucket:
- subscription onboarding, guided provider onboarding, and migration/import
  work are absorbed into the onboarding and migration groups below
- model/provider routing clarity is absorbed into the routing group below
- provider-status parity remains part of [#185](https://github.com/puremachinery/carapace/issues/185),
  while broader Control UI depth is not part of the current near-term
  product-priority list
- test-infra hardening remains tracked separately in
  [#190](https://github.com/puremachinery/carapace/issues/190)

- Make onboarding excellent — provider setup should be fast, guided, and
  understandable without requiring users to edit config by hand.
  Issues: [#185](https://github.com/puremachinery/carapace/issues/185),
  [#178](https://github.com/puremachinery/carapace/issues/178),
  [#183](https://github.com/puremachinery/carapace/issues/183),
  [#184](https://github.com/puremachinery/carapace/issues/184)
- Add import and migration from tools people already use — reduce switching
  cost for users coming from adjacent assistants.
  Issues: [#180](https://github.com/puremachinery/carapace/issues/180),
  [#181](https://github.com/puremachinery/carapace/issues/181),
  [#182](https://github.com/puremachinery/carapace/issues/182)
- Add Matrix / Element — best-fit next channel for privacy-focused,
  self-hosted users.
  Issue: [#234](https://github.com/puremachinery/carapace/issues/234)
- Make model routing explicit, capability-aware, and sane — users should be
  able to choose cheap/fast, stronger reasoning, or multimodal routes
  intentionally.
  Issues: [#203](https://github.com/puremachinery/carapace/issues/203),
  [#188](https://github.com/puremachinery/carapace/issues/188),
  [#189](https://github.com/puremachinery/carapace/issues/189),
  [#207](https://github.com/puremachinery/carapace/issues/207)
- Make managed plugin install/update operations truly transactional
  server-side — plugin distribution needs stronger trust and recovery
  guarantees.
  Issue: [#243](https://github.com/puremachinery/carapace/issues/243)

## Later

- Audit dead-code allowances on plugin and channel entrypoints.
  Issue: [#241](https://github.com/puremachinery/carapace/issues/241)
- Harden plugin CLI local staging against local symlink-swap races.
  Issue: [#250](https://github.com/puremachinery/carapace/issues/250)
- Evaluate Microsoft Teams as an additional channel.
  Issue: [#236](https://github.com/puremachinery/carapace/issues/236)
- Evaluate Session integration feasibility.
  Issue: [#237](https://github.com/puremachinery/carapace/issues/237)

## Give feedback

- Issues: <https://github.com/puremachinery/carapace/issues/new/choose>
- Discussions: <https://github.com/puremachinery/carapace/discussions>
