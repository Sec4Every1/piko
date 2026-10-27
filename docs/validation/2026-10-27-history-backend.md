# Observation history backend checkpoint

Base: f1b665d. Adds read-only GetInvestigationWindow/GetInvestigationPage IPC
commands and production storage-worker dispatch/query functions. Existing
service dispatch already forwards these read commands to the worker; no new
runtime module, dependency, lockfile, native bridge or desktop UI is included.
Older clients retain GetInvestigation. Existing request deadlines and bounded
worker queues continue to apply.

Window bounds and cursor timestamps are validated before querying. A page
admits 128 queried rows and uses the actual last queried row for continuation,
independently of ascending display order or rejected attribution. It never
skips the 129th sentinel. Parent/child evidence and UDP bind semantics come
from the core model; no causality or remote UDP activity is inferred.

Validation used an archived f1b665d plus exactly the IPC/worker hunks and new
storage_worker/history_tests.rs. Other uncommitted evidence-key, maintenance
and APP-03 work was excluded. Existing compact formatting in the affected
worker was normalized with rustfmt; no behavior was changed by those hunks.

- cargo test --offline --locked -p piko-security-service -p piko-ipc:
  service 15 tests and IPC 2 tests passed, no failures. Four new worker tests
  cover invalid bounds/cursors, real keyset continuation across 130 events,
  child attribution within an inclusive/exclusive window and UDP bind limits.
- Affected all-target Clippy with -D warnings passed after replacing an
  initially rejected test unwrap with an explicit missing-node error.
- Targeted rustfmt --edition 2021 --check passed after normalizing the
  affected worker's pre-existing compact formatting.

Logs/snapshot: .build/consolidation-history-backend-20261027,
service-tests.log and backend-clippy.log. Test paths, process names and IDs are
synthetic. No real IPC endpoint, service installation or protection changed.
No end-to-end desktop, remote CI or installed Windows qualification is claimed.
