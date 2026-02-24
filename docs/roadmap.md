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
- Multi-page docs site with install/first-run/security/ops plus docs hubs,
  capability matrix, and task-oriented CLI index.

## Now

- Stable (non-preview) release gate:
  - migration/compatibility statement,
  - backup/restore and update-path validation,
  - cross-platform smoke evidence current.
- Security follow-up: restore per-client hooks sender identity without
  reintroducing uncontrolled-allocation risk.

## Next

- Subscription-style provider onboarding — OAuth/device-code style flows that
  reduce manual API-key setup friction while staying provider ToS-compliant.
- Control UI depth — richer in-browser runbook/operator workflows and stronger
  day-2 remediation UX.
- Docs architecture polish — tighter day-1/day-2 routing and clearer task-first
  command ladders across operational docs.

## Later

- Additional channels (WhatsApp, iMessage, Teams, Matrix, WebChat).
- Companion apps — native macOS, iOS, and Android clients.
- Browser control and live canvas / A2UI experiences.
- Multi-agent routing and automatic model/provider failover.

## Give feedback

- Issues: <https://github.com/puremachinery/carapace/issues/new/choose>
- Discussions: <https://github.com/puremachinery/carapace/discussions>
