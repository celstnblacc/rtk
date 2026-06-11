# RTK Improvements Summary

Based on a quick product and integration review, the best improvements for `rtk` are:

## Role Under Token-Diet

- If `token-diet` is the primary installer for new users, `rtk` should not be the main owner of cross-tool onboarding.
- `rtk` should instead expose a strong runtime contract: stable CLI behavior, machine-readable health/status, accurate hook diagnostics, and safe execution boundaries.
- `token-diet` can then orchestrate install, repair, and compatibility checks on top of those primitives.

- Automate adoption. Strengthen hooks and post-install checks so users do not have to remember `rtk <cmd>` manually.
- Improve command routing. Make `rtk` the default for noisy shell commands, while keeping file navigation and symbol work with tools like `tilth` and Serena.
- Add `rtk doctor` and machine-readable self-checks so `token-diet` can detect broken hooks, stale registrations, PATH issues, and config drift.
- Add `--json` output for health, gain, and diagnostics so dashboards and other tools can consume RTK state.
- Improve tracking. Add per-project views, better cost attribution, and clearer “you should have used RTK here” feedback.
- Improve idempotency. Re-running setup should converge cleanly without duplicate hook/config mutations.
- Add stronger post-install smoke checks for each supported agent so the user knows the rewrite path is actually active.

## Security Improvements

- Keep the rewrite boundary strict. Never fall back to shell interpretation for rewritten commands.
- Validate environment inputs such as `PATH`, pager/editor variables, and any hook-controlled command strings before execution.
- Preserve child exit codes and signal semantics on every wrapper path so failures are never reported as success.
- Add atomic writes and backups for all config and hook mutations.
- Verify install sources with pinned versions, checksums, or signed artifacts where possible.
- Harden tracking storage with safer file permissions, WAL/concurrency strategy, and corruption recovery paths.
- Add regression tests for shell metacharacters, hostile environment variables, malformed command output, signal exits, and concurrent database writes.
- Add an audit/debug mode that shows raw command, rewritten command, applied filter, and trust boundary for troubleshooting.

## Highest-Leverage Next Steps

1. Build `rtk doctor`.
2. Add `--json` health and rewrite-state diagnostics for `token-diet` to consume.
3. Harden hook rewrite and environment validation.
4. Add per-project tracking and exportable metrics.
5. Expand install and runtime smoke tests across supported agents.
