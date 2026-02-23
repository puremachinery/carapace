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

Target policy before first non-preview release:

- Define and enforce an explicit N-1 compatibility contract for config/state.
- Require migration and rollback sections in every stable release note.

## Migration Behavior

General migration rules:

1. Prefer automatic migration only when behavior is deterministic and reversible
   from backup.
2. Any migration that can change persisted state must be documented in release
   notes.
3. If migration fails, fail closed with an actionable error instead of silently
   continuing in a mixed state.

Operator expectation:

- Run `cara backup` before upgrading.
- Upgrade using a pinned release tag in production environments.
- Run `cara verify --outcome auto` after upgrade.

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

Recovery-time target:

- Single-node/local deployments should target under 15 minutes from stop to
  verified recovery. Validate this in your own environment.

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
8. Smoke-check the published binary on at least one Linux and one macOS path.
9. Confirm release notes contain all required sections above.

## Distribution Notes

- Interactive installs may use `releases/latest`.
- Automation and production rollouts should use pinned tag URLs.
- Signature/checksum verification steps are documented in
  [site/install.md](site/install.md).
