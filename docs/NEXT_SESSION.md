# Piko: resume checkpoint

Updated: 2026-10-21. Read AGENTS.md and WORK_QUEUE.md; check git status first.
Only inspect sources relevant to the next item. Preserve existing work.

## Current development checkpoint
- ADR0036: explicit Recover-Piko.cmd / updater recovery switch, strict replacement
  validation, exact original manifest/hash/ACL backup, stopped-service archive copy
  and trusted replacement read-only verification before replacing binaries.
  Default installer/update still refuses inconsistency. Rollback restores files
  and prior SCM state; unknown old CLI is not executed for health qualification.
  Known prior storage quota failure can remain with an explicit warning, never
  labelled active; a new quota failure causes rollback.
- ADR0037: AppContainer network None(default)/InternetClient selection wired through
  UI/Tauri/stored plan to exact enabled token capability verification before resume.
  Real benign native processes passed both modes + cleanup; no network I/O.
- ADR0038: effective SQLite page limit is measured, not assumed. UI distinguishes
  internal database saturation from aggregate budget. Reserve policy unchanged.
- Local checks: Rust workspace 156 passed / 5 ignored; separately invoked native trial
  qualification passed; changed-crate Clippy/fmt; PS5.1/7 recovery fixtures 20 each;
  frontend check, 24 affected contract tests, 7 trial + 2 archive browser tests pass.
- Runtime and native desktop release rebuilds passed. Local package is refreshed
  with scripts/package.ps1 -Profile release; artifacts/logs are ignored.
- Prior remotely green source: e0b6217 / run 39441703542 (both jobs passed). This
  reviewed development checkpoint is being published once; inspect matching CI
  before claiming remote verification. git log identifies its exact commit.

## Live installation / limitations
- UAC was CANCELLED before the recovery helper executed. No live replacement,
  stop/restart or recovery archive copy occurred. Do not reopen the UAC prompt
  without renewed user direction after cancellation; continue independent code.
- Installed service remains running with binary/manifest mismatch. Earlier private
  six-original-file copy remains in ProgramData/piko-recovery-*/originals.
- Trusted packaged CLI health observed 273668 events, dropped 0; storage degraded:
  SQLite FULL, effective DB 1 GiB, active DB 1 GiB,total ~1.0005 GiB,budget 2 GiB,retention 12 months.
  Actual event archive was not deleted or modified by this development work.
- Live recovery/reboot/rollback, outbound AppContainer connectivity and persistent
  installed-app file/system/update mediation remain unqualified/unsupported.

## Next task
- STORE-02: measure pinned-reader WAL/checkpoint peaks and bound every writer before
  reducing reserves. Current half reserve is deliberate; journal_size_limit and
  auto-checkpoint are soft bounds. Never increase the user's 2 GiB budget or discard
  unexpired evidence to make tests pass. Review ADR0038 before changes.
- Publish the reviewed development checkpoint once, inspect its CI when useful,
  and continue independent ready work rather than idle polling. GRAPH-01 follows
  if storage policy requires a separate bounded design milestone.

Permanent constraints: MIT; no personal paths/SIDs/secrets/runtime data in source;
minimal grouped UI with details/raw; retain security events 12 months within 2 GiB and
suspend on capacity. Use existing authorization; don't re-ask granted permissions.
Replace this checkpoint at the next milestone; no append-only chat transcript.
