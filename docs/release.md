# Release & Upgrade Policy

This document is for maintainers and operators preparing or consuming releases.
It defines compatibility expectations, migration and rollback behavior, and a
repeatable release checklist.

## Security Contact

- Private security reports: <https://github.com/puremachinery/carapace/security/advisories/new>
- Full policy and response expectations: [../SECURITY.md](../SECURITY.md)

Do not post vulnerability details in public issues.

## Compatibility Statement

Current status: Carapace is still in preview.

- Preview tags (`vX.Y.Z-previewN`) are best-effort compatibility.
- Before upgrading between preview tags, take a backup.
- If an upgrade is not compatible with existing local state, release notes must
  call this out with explicit migration/rollback steps.

Stable-release compatibility policy (effective at first non-preview release):

- Compatibility target is **N-1 -> N** for stable releases only.
  - Example: `v0.2.0` must support data/config from `v0.1.x` stable releases.
  - Preview tags are explicitly out of contract.
- Every stable release note must include migration + rollback sections.
- Any incompatible change must be explicitly called out in `Breaking Changes`.

### Versioned N-1 Contract (stable channel)

| Surface | N-1 -> N expectation | Breaking-change requirement |
| --- | --- | --- |
| Config format (`config.json5`) | New stable versions load prior stable config and preserve behavior unless explicitly deprecated. | If a key/shape is removed or semantics change, provide migration steps and at least one stable deprecation window. |
| State files (`state_dir`) | New stable versions read prior stable state and perform safe migrations where needed. | If migration is not automatic, ship operator migration steps and rollback steps. |
| Session/task persistence (`sessions/`, `tasks/`) | New stable versions can read prior stable persisted session/task data or fail closed with actionable remediation. | If format changes are incompatible, provide conversion path and recovery procedure from backup. |

Contract boundary:

- Guaranteed: previous stable minor line (N-1) to current stable line (N).
- Not guaranteed: preview-to-preview, preview-to-stable, or skipping multiple
  stable lines without intermediate migration steps.

## Migration Behavior

General migration rules:

1. Prefer automatic migration only when behavior is deterministic and reversible
   from backup.
2. Any migration that can change persisted state must be documented in release
   notes.
3. If migration fails, fail closed with an actionable error instead of silently
   continuing in a mixed state.

Operator expectation:

- Run `cara backup --output ./carapace-backup.tar.gz` before upgrading.
- Upgrade using a pinned release tag in production environments.
- Run `cara verify --outcome auto` after upgrade.
- Run `cara verify --outcome autonomy` after upgrade to confirm durable task
  start + terminal behavior.

## Rollback Runbook

Use this when an upgrade causes a regression.

1. Stop Cara.
2. Reinstall the previous known-good binary (pinned tag URL).
3. Restore backup created before the upgrade:
   - `cara restore --path ./carapace-backup.tar.gz`
4. Start Cara.
5. Verify:
   - `cara status --port 18789`
   - `cara verify --outcome auto --port 18789`
   - `cara verify --outcome autonomy --port 18789`

Recovery-time target:

- Single-node/local deployments should target under 15 minutes from stop to
  verified recovery. Validate this in your own environment.

## Updater Authenticity and Resume Contract

Updater behavior is fail-closed by policy:

1. `cara update` and WS `update.install` both require Sigstore bundle
   verification for the target binary (`<asset>.bundle`).
2. Verification policy is strict:
   - OIDC issuer must be `https://token.actions.githubusercontent.com`
   - certificate identity must match this repo release workflow for the target
     tag.
3. Missing/invalid bundle, trust-chain failure, issuer mismatch, or identity
   mismatch must stop install before apply.
4. `SHA256SUMS.txt` verification is a secondary integrity check when present,
   not a substitute for authenticity verification.

Resume behavior:

1. Update transactions persist at `{state_dir}/updates/transaction.json`.
2. Transaction phases are persisted across restarts (`created`,
   `downloading`, `downloaded`, `verified`, `applying`, `failed`, `applied`).
3. Startup performs bounded auto-resume for retryable interrupted updates.
4. Non-retryable failures stay terminal and require operator intervention.

## Release Notes Template

Every release should include these sections:

```markdown
## Summary
- High-level changes in this release.

## Breaking Changes
- What changed incompatibly, who is affected, and impact.

## Migration Steps
- Exact commands or file changes required after upgrade.

## Rollback Steps
- Exact steps to return to previous known-good version.

## Security
- Security fixes, hardening changes, and advisory references.

## Verification
- Links or commands for signature/checksum verification.

## Known Caveats
- Remaining limitations or partial areas relevant to operators.
```

## Reproducible Release Checklist

1. Confirm `master` is green (CI + CodeQL + required checks).
2. Confirm no open critical/high security findings on `master`.
3. Confirm docs are current for install, ops, and security behavior.
4. Create annotated tag from `master`:
   - `git tag -a vX.Y.Z-previewN -m "vX.Y.Z-previewN"`
5. Push tag:
   - `git push origin vX.Y.Z-previewN`
6. Wait for `.github/workflows/release.yml` to complete.
7. Verify release artifacts are published (all target binaries + signatures +
   checksums).
8. Verify published artifact authenticity/checksum workflow against the release.
   - `scripts/smoke/verify-release-artifacts.sh`
   - Optional overrides:
     - `RELEASE_TAG=vX.Y.Z scripts/smoke/verify-release-artifacts.sh`
     - `CARA_ASSET=cara-x86_64-linux scripts/smoke/verify-release-artifacts.sh`
9. Smoke-check the published binary on at least one Linux and one macOS path.
   - Suggested scripts:
     - `scripts/smoke/update-macos-local.sh`
     - `scripts/smoke/update-linux-orbstack.sh`
   - Optional live channel smoke:
     - `scripts/smoke/live-channel-smoke.sh`
10. Confirm release notes contain all required sections above.

## Distribution Notes

- Interactive installs may use `releases/latest`.
- Automation and production rollouts should use pinned tag URLs.
- Signature/checksum verification steps are documented in
  [site/install.md](site/install.md).
