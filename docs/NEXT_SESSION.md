# Piko: resume checkpoint

Updated: 2026-10-20. Start with root AGENTS.md and docs/WORK_QUEUE.md.
Verify git status and live state before mutation; read only task-relevant files.

## Delivered checkpoint
- Public development commit: 6b8293f. Account lifecycle monitoring (ADR 0033),
  pinned Rust 1.99.0, native CI portability and installed hash preflight.
- Same-version installer refresh with protected staging, binary backup and rollback
  (ADR 0034). Cross-version migration and signed updates remain unsupported.
- Dependency audits repaired, Vitest 5.0.5, exact-version MPL reviews and five
  verified upstream source archives included in development packages.
- AGENTS.md defines continuation/delegation/checks; WORK_QUEUE.md orders remaining
  work. These files replace repeated chat-history reconstruction.

## Verification
- Full local scripts/ci-sbom.ps1 passed: both Rust dependency graphs, npm audit
  (zero vulnerabilities), 14 Rust SBOMs plus frontend SBOM, unchanged lockfiles.
- Frontend: 89 tests, check/build pass. Earlier account Playwright scenario passed.
- Native ETW/process targeted tests pass; remote Windows job for 5acb14a passed
  full tests, desktop build and IPC smoke (run 39427136418).
- Read-only service preflight: nine fixtures per shell. Refresh/rollback: ten
  fixtures per shell. Both Windows PowerShell 5.1 and PowerShell 7 pass locally.
- Local release package refreshed: artifacts/piko-0.2.0-windows-x64-release.
  Four executable checksums, updater and five source archives verified.
- Remote CI for 6b8293f: run 39429554940, Windows and dependency jobs both passed.
  DEV-01 complete. Ignored .build/ evidence is local and not portable.

## Installed-runtime boundary / next action
- Installed service remains running and was NOT updated or restarted.
- Its piko-service.exe differs from its installed manifest; updater correctly
  refuses this inconsistency. Do not rewrite the manifest or uninstall to bypass it.
- Read-only comparison: one historical installed backup matches that manifest;
  no scanned historical backup or four local build/package candidates matches the
  current installed service. This suggests a stale manifest, not proven provenance
  of the current executable. Do not restore old binaries against newer evidence.
- Next, DEV-02: establish
  provenance of installed binaries and design verified recovery from the mismatch,
  preserving configuration, evidence and original binaries before any live change.
  Installation/reboot/uninstall qualification remains open; APP-01 follows.
- Use existing authorization for publication and approved OS changes. Request only
  genuinely missing scope; don't repeat already granted permission requests.

## Permanent product constraints
- MIT; keep personal identifiers, runtime databases, secrets and logs out of source.
- Minimal UI, grouped alerts, application names, details/raw on demand.
- Preserve retained security events for 12 months within 2 GiB; stop collection on
  capacity exhaustion rather than silently discard unexpired evidence.
- Contextual noise filtering is not a universal trusted-loader allowlist.

Replace this checkpoint at the next milestone; don't append a chat transcript.
