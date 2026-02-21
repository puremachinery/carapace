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
- Outcome-driven setup flow (`cara setup`) with provider credential validation.
- First-run verifier (`cara verify`) with pass/fail outcome checks.
- Multi-page docs site with install, first-run, security, and ops guides.

## Now

- Long-running assistant MVP:
  - durable task queue with retry/recovery state,
  - operator surface for objective/task create/list/get/cancel/retry,
  - continuation budgets and blocked-state handling,
  - close remaining trigger wiring gaps.
- Stable (non-preview) release gate:
  - migration/compatibility statement,
  - backup/restore and update-path validation,
  - cross-platform smoke evidence current.
- Security follow-up: restore per-client hooks sender identity without
  reintroducing uncontrolled-allocation risk.

## Next

- Control UI — a local web frontend so users can configure and manage Cara
  without JSON edits or CLI-only workflows.
- Cloud-provider onboarding — provider-sanctioned auth flows that avoid manual
  API-key setup where possible.
- Docs and navigation upgrades: docs hubs in nav, channel/provider/platform
  capability matrix, task-oriented CLI index.

## Later

- Additional channels (WhatsApp, iMessage, Teams, Matrix, WebChat).
- Companion apps — native macOS, iOS, and Android clients.
- Browser control and live canvas / A2UI experiences.
- Multi-agent routing and automatic model/provider failover.

## Give feedback

- Issues: <https://github.com/puremachinery/carapace/issues/new/choose>
- Discussions: <https://github.com/puremachinery/carapace/discussions>
