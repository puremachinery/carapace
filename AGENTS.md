# carapace Agent Guidelines

## Project Context

carapace is a secure, stable Rust alternative to moltbot - for when your molt needs a hard shell.

## Code Review Cadence

### Review Triggers

| Trigger | Review Depth | Blocker? |
|---------|--------------|----------|
| Phase gate | Full review of all new code | Yes - wait for approval |
| Security-critical module complete | Immediate review | Yes - do not integrate until reviewed |
| Integration point | Review when components connect | Yes |
| Boilerplate/scaffolding | Light spot-check | No |
| Documentation | Spot-check at gate | No |

### Security-Critical Modules

These require immediate review before integration. Flag completion to the operator:

- `src/auth/` - all authentication code
- `src/credentials/` - OS keychain integration
- `src/plugins/` - plugin capability boundary
- `src/server/ratelimit.rs` - rate limiting
- `src/server/csrf.rs` - CSRF protection
- `src/hooks/auth.rs` - hook token handling
- Any code handling secrets, tokens, or credentials

When completing a security-critical module:
1. Stop and notify: "Security-critical module complete: [path]. Awaiting review."
2. Do not proceed to dependent work until review approved.

### Light Review (Spot-Check)

These can proceed without blocking:
- Directory scaffolding
- Type definitions (`types.rs`)
- Documentation (`.md` files)
- Test fixtures (`tests/golden/`)
- CI/CD configuration

### Phase Gates

Before starting a new phase:
1. All prior phase work must be complete
2. Operator reviews all outputs
3. Gate checklist verified
4. Explicit approval to proceed

## Output Standards

### Rust Code
- `cargo fmt` before committing
- `cargo clippy` must pass
- Security-critical code includes comments explaining the security property
- Keep files under ~500 lines; split when beneficial

### Testing
- Use `just test` or `cargo nextest run` (NOT `cargo test`)
- nextest has better parallelism and output
- `just test-one NAME` for specific tests
- `just test-verbose` for full output

### Documentation
- Use code blocks for examples
- Reference source files when documenting existing behavior
- Keep schemas in sync with implementation

### Golden Traces
- Schema validation, not exact byte matching
- Include `notes` field explaining what's validated
- Use `{{placeholder}}` for dynamic values

## Coordination

### File Ownership
- One agent per file at a time
- Claim files by starting work, release on completion
- If blocked on another agent's file, wait or notify operator

### Dependencies
- Check `docs/refactor/implementation-plan.md` for task dependencies
- Do not start dependent tasks until dependencies complete
- If a dependency is blocked, notify operator

### Multi-Agent Safety
- Do not create/apply/drop `git stash` entries
- Do not switch branches unless explicitly requested
- When committing, scope to your changes only
- When you see unrecognized files, keep going; focus on your changes

## Notifications

Flag these to the operator immediately:
- Security-critical module complete
- Blocker encountered
- Dependency not available
- Significant deviation from plan needed
- Tests failing
- Phase gate reached

## Reference Files

- Protocol specs: `docs/protocol/*.md`
- Golden traces: `tests/golden/`
- Architecture: `docs/architecture.md`

## Response Style

- Give a single recommendation, commit to it
- Do not hedge; pick the most likely answer
- 2-3 concrete reasons only
- Assume effort is planned and funded
