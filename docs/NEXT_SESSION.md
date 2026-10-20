# Piko: resume checkpoint

Updated: 2026-10-20. Read with root AGENTS.md; verify live state before mutation.

## Current outcome
- Account lifecycle monitoring added: Security 4720/4722/4725/4726 version 0,
  affected account vs requester, filters, five-row pages, details and raw evidence.
  ADR 0033; this does not enforce account creation/deletion policy.
- CI fixes prepared: two new Clippy warnings, explicit internal dependency versions,
  SBOM package discovery from cargo metadata. Audit gates were not disabled.
- Packaging no longer embeds the packager's Windows SID in installer instructions.

## Evidence from last development run
- Workspace fmt/Clippy passed; Rust workspace tests: 147 passed, two ignored.
- Frontend check clean; 89 unit tests passed; identity Playwright scenario passed.
- Runtime workspace + native desktop release builds passed.
- `scripts/package.ps1 -Profile release` succeeded; four executable hashes verified.
- Package: `artifacts/piko-0.2.0-windows-x64-release` (ignored, local only).
- Long Rust test evidence: `.build/account-workspace-tests.txt` (ignored/local;
  may be absent on another checkout). Summary in docs/VALIDATION.md.

## Outstanding delivery state
- Development checkpoint is being published for DEV-01. Verify git status for follow-up edits.
- Prior baseline main commit: 90e6d30. Read git log for the current checkpoint.
- Last inspected CI run 39390516235 failed; the local corrections above have not
  been verified by a subsequent remote run. Local cargo-deny audit was not run.
- Local Rust/Clippy was 1.93; remote run used 1.99. Matching-toolchain verification
  can find new diagnostics that the local linter misses.
- The compiled package has been refreshed; the active installed service has NOT
  been updated/qualified for these changes. Do not report it as deployed.

## Next action
Work queue DEV-01 first: inspect pending changes and verify remote CI at a reviewed
checkpoint using existing publication authorization where applicable. Resolve
remaining build/audit failures, then DEV-02 installation qualification and APP-01/02.
Check authorization scope for persistent OS changes; do not re-ask for granted scope.

## Permanent product constraints (details in linked docs)
- MIT; no personal identifiers, runtime DBs, secrets or logs in public source.
- Minimal UI, grouped alerts, application names, detail/raw on demand.
- 12 months of all retained security events within 2 GiB; suspend collection on
  capacity exhaustion rather than silently discard unexpired evidence.
- Existing noise policy/aggregation is contextual, not a universal trust allowlist.

Replace this checkpoint after a completed milestone or interruption. Keep it short;
do not duplicate the 116 requirements, old chat or full test output.
