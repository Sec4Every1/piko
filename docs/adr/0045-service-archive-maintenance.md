# ADR 0045: bounded archive maintenance under the runtime identity

## Validation update, 2026-10-27

Relevant selected source has now passed the local checks recorded in [2026-10-27-maintenance-vertical.md](../validation/2026-10-27-maintenance-vertical.md), [2026-10-27-storage-foundation.md](../validation/2026-10-27-storage-foundation.md).
The original decision below records its source-only state at the earlier date;
its deferred-check and missing-integration statements are historical, not the
current execution instruction. See [NEXT_SESSION](../NEXT_SESSION.md) for
remaining gates. Installed Windows behavior, UAC/SCM/DPAPI recovery and security
qualification remain open. Protection defaults remain off; no current host
configuration was changed. Local checks do not imply a completed dependency
security audit, portable archive import or release qualification.

## Original decision and limitations


2026-10-22. Development source only; all execution checks deferred by the user.

Historical raw-evidence compression now runs on the existing storage writer,
under the identity that opened the archive. No offline administrator process,
impersonation, key export, dependency or native boundary is added. The service
configuration archive_maintenance defaults true for future builds. No installed
configuration or executable was changed.

Each flush tick may enqueue one coalesced internal maintenance job. Already
queued append/read work takes priority: maintenance skips its turn when the
queue is not empty. A pass examines at most32 rows and processes at most4MiB of
plaintext input, reusing conservative compression admission and atomic commit.
Protected/already-compressed blobs are skipped without rewriting or decrypting
the blob. Owner-policy/probe validation still runs under the original identity.
It does not repeat the archive-wide startup orphan-envelope scan every batch.
The original writer was validated at startup; local metadata is not an external
anti-tampering anchor. No event expiry, deletion, quota increase, retention
shortening or encryption migration is introduced by this job.

The cursor advances only after success; errors preserve it. An empty scan ends
the cycle and resets its cursor; restarting safely rescans old rows. Compression
uses a single writer, so there is no concurrent append/maintenance transaction.
A pass already running can delay newly arriving work; row/input bounds are not
a proven wall-time or peak-disk guarantee. Continuous collection may postpone
maintenance. A full archive may lack the transient space needed to compress.

Cached watch status reports waiting/running/completed_batch/blocked, sample time,
scanned/changed counts, logical bytes saved and cycle completion. Errors are
bounded to2048 UTF8 bytes. A stopped writer reports blocked rather than returning
its prior success as current. Read-only GetArchiveMaintenance IPC, a Tauri bridge,
CLI maintenance command and compact archive panel expose this status. The panel
loads when connected and refreshes on request; old runtimes/unavailable IPC fail
visibly. This is not an externally writable maintenance command. Logical savings
do not mean physical database-file shrinkage or a verified integrity result.

This closes the source path for routine compression under the service identity.
It does not implement portable key backup/recovery, protected archive replacement,
cross-account upgrade verification or whole-database encryption. Raw encryption
remains default off until these flows and Windows service profiles are qualified.

Deferred checks: writer queue/coalescing/closed-channel cases; priority and cursor
progress/restart; corruption/quota rollback; original/wrong DPAPI identity;
plaintext/compressed/protected mixtures; UTF8 error bounds; IPC/parser/native UI
integration, stale/disconnected responses; live service identity and concurrency.
No tests, lint, formatting checks, builds, CI, installation or live maintenance
were executed for this change.
