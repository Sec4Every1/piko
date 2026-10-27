# Bounded archive maintenance: worker to desktop

Base: 16bbeb5. Consolidates the maintenance source path through the original
storage writer, cached status, read-only IPC command, Tauri and archive panel.
Runtime configuration archive_maintenance defaults true; legacy configurations
use that default on a future deployment. No installed configuration or runtime
was changed here. Protection defaults and retention/quota remain unchanged.

Maintenance is requested on flush ticks, coalesced into one queue entry and
yields when other storage work is queued. Each pass uses the existing bounded
storage API and original writer identity. Full/closed queues allow retry;
worker loss invalidates cached success metrics. The UI distinguishes waiting,
running, completed, blocked and unavailable outcomes. Logical data reduction
is explicitly not a claim of physical disk space freed.

Included: service storage_worker and maintenance_tests, runtime configuration/
scheduling/status hunks, IPC command/data, CLI response serialization, native
status function/registration, ArchiveUsage maintenance integration, new
ArchiveMaintenance.svelte/maintenance.ts and scoped frontend tests. Evidence
keys, provider adapters, activation, APP-03, manifests and lockfiles are excluded.

Validation used an archived 16bbeb5 plus exactly those files/hunks:

- Service: 20 tests passed, including 5 new queue/watch/real-worker cases.
  The synthetic real worker scans normally compressed evidence, reports zero
  new savings, completes its next cycle and preserves raw data/integrity.
  Legacy recompression itself remains covered in the storage suite.
- IPC: 2 tests passed. Service/IPC/CLI all-target Clippy with -D warnings passed.
- Targeted worker/IPC/CLI rustfmt checks and changed native-function formatting
  check passed; no whole-runtime/workspace formatting claim.
- Frontend Svelte/TypeScript check passed with zero errors/warnings; 25 targeted
  maintenance/API unit tests and 4 archive Chromium scenarios passed.
- Frontend production build and offline locked Tauri cargo check passed.

An initial test attempted to import transitive rusqlite from the service; it
was corrected to use the existing storage API rather than adding a dependency.
The first browser run found an ambiguous capacity-status selector after adding
the maintenance status. Existing capacity assertions were narrowed and passed,
along with completed-to-blocked refresh and unavailable/retry scenarios.

Snapshot/logs: .build/consolidation-maintenance-20261027,
maintenance-tests.log, maintenance-clippy.log, desktop-check.log,
desktop-tests.log, desktop-playwright.log, desktop-build.log, desktop-tauri.log.
Existing dependencies/browser/build artifacts were reused; nothing installed
or updated. All fixtures are synthetic. No installed service-to-UI session,
Windows qualification, remote green CI or physical peak-space proof is claimed.
