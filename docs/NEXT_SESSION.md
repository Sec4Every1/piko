# Piko: resume checkpoint

Updated: 2026-10-20. Read AGENTS.md, git status, then WORK_QUEUE.md.
Read only the active item's relevant sources; preserve existing work.

## Latest delivery: APP-01 (ADR 0035)
- Grid: outbound/inbound/both batches, selected verified-rule removal, explicit
  preview/confirmation, 32-plan bound, direction-specific partial outcomes.
- Helper lifetime: terminal wait, global nonqueued mutex, origin PID + creation
  FILETIME validation before mutation. A delayed old helper rejects a closed
  desktop; an already-started change may finish while excluding new helpers.
- Desktop/helper must be rebuilt together; legacy plans fail closed. Hung helpers
  keep the caller pending; automatic cancellation is not implemented.
- Local checks passed: workspace Rust 151 tests, 4 ignored (two are child fixtures
  invoked by parent tests); targeted app-control 26, lifecycle 4; Clippy/fmt.
  Browser network suite 22 scenarios plus one additional plan-limit scenario pass.
  Frontend check/build and runtime/desktop release builds pass.
- Refresh local package with scripts/package.ps1 -Profile release if absent:
  artifacts/piko-0.2.0-windows-x64-release (ignored, never commit).
- Publish this reviewed checkpoint once. Full CI runs automatically; inspect the
  matching commit under GitHub Actions before claiming remote qualification.
  Last prior green baseline: 6b8293f / run 39429554940. Current source changes
  have local evidence; no result from the new remote pipeline is claimed yet.

## Next action / installed boundary
- DEV-02 still blocks live qualification. Installed service remains running and
  was NOT updated/restarted. Its service executable differs from its manifest.
- One historical protected backup matches that manifest; no scanned backup or
  four local build/package candidates matches the current service. A stale
  development manifest is plausible, but current binary provenance is unproven.
- Design verified recovery that retains originals/config/evidence before any
  replacement. Do not overwrite the manifest to bypass validation or restore old
  executables against newer evidence. Existing same-version updater (ADR 0034)
  correctly refuses inconsistent installations.
- Then qualify real packet blocking, undo, desktop/service restart and alternate
  administrator credentials. APP-01 remains VERIFIED-LOCAL, not complete endpoint
  protection. APP-02 file/system/update capabilities remain separate queued work.

## Permanent constraints
MIT, no personal identifiers/secrets/runtime data in source. Minimal grouped UI,
application names, details/raw on demand. Retain security events 12 months within
2 GiB; suspend collection on capacity rather than discard unexpired evidence.
Use existing authorization; do not repeat granted permission requests.
Replace this checkpoint at milestones; don't append chat history.
