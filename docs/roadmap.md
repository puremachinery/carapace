# Roadmap

This roadmap is directional, not a date-based promise. Priorities may shift as
we get real user feedback.

For what is already shipped and verified, see:

- [Feature status](feature-status.yaml)
- [Feature evidence](feature-evidence.yaml)

## Next

These items are listed in priority order. The top item is the current focus.

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
