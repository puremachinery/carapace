# Roadmap

This roadmap is directional, not a date-based promise. Priorities may shift as
we get real user feedback.

For what is already shipped and verified, see:

- [Feature status](feature-status.yaml)
- [Feature evidence](feature-evidence.yaml)

## Recently shipped

- Stable release line established (`v0.1.0`, `v0.2.0`) — stable compatibility
  policy and verified update/release paths are now in effect for the stable
  channel.
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
- Filesystem tools — guarded local workspace read/search/stat/list plus opt-in
  write/move within explicit roots, with config-gated registration and
  fail-closed validation.
- Multi-page docs site with install/first-run/security/ops plus docs hubs,
  capability matrix, and task-oriented CLI index.
- Docs architecture polish — tighter day-1/day-2 routing and clearer task-first
  command ladders across operational docs.

## Now

- Test-infra hardening for env-sensitive flows — reduce order-dependent flake in
  config/setup/WebSocket test coverage before expanding onboarding further.
- Subscription onboarding expansion — add Codex/OpenAI and Anthropic
  subscription-oriented flows while keeping provider/auth boundaries explicit.
- Guided provider onboarding and migration paths — strengthen setup
  verification/remediation, add Bedrock and Vertex guided onboarding, and make
  migration/import easier for users coming from adjacent assistants.
- Control UI depth — richer in-browser runbook/operator workflows and stronger
  day-2 remediation UX, including onboarding and provider-status parity.
- Model/provider routing clarity — improve docs for current routing behavior and
  evaluate clearer route-vs-agent and multimodal routing UX.

## Next

- Additional channels (WhatsApp, iMessage, Teams, Matrix, WebChat).
- Companion apps — native macOS, iOS, and Android clients.

## Later

- Browser control and live canvas / A2UI experiences.
- Multi-agent routing and automatic model/provider failover.

## Give feedback

- Issues: <https://github.com/puremachinery/carapace/issues/new/choose>
- Discussions: <https://github.com/puremachinery/carapace/discussions>
