# ADR 0046: archive compatibility gate under the existing service identity

## Validation update, 2026-10-27

Relevant selected source has now passed the local checks recorded in [2026-10-27-key-backend.md](../validation/2026-10-27-key-backend.md), [2026-10-27-recovery-package.md](../validation/2026-10-27-recovery-package.md).
The original decision below records its source-only state at the earlier date;
its deferred-check and missing-integration statements are historical, not the
current execution instruction. See [NEXT_SESSION](../NEXT_SESSION.md) for
remaining gates. Installed Windows behavior, UAC/SCM/DPAPI recovery and security
qualification remain open. Protection defaults remain off; no current host
configuration was changed. Local checks do not imply a completed dependency
security audit, portable archive import or release qualification.

## Original decision and limitations


2026-10-22. Development source only; no tests, builds, script execution or live
installation changes. This is not a portable recovery-key implementation.

The administrator performing a refresh cannot decrypt user-scoped DPAPI evidence
owned by the virtual service account. Do not export Windows master keys, change
the owner account, weaken protection to machine scope or skip raw verification.

The updater now requires the replacement's bounded --archive-capabilities probe
before stopping the original. Unsupported candidates refuse before that point.
The probe advertises service_read_only_verification, report_version and a normal
startup guard; key_recovery_portable is explicitly false. Checksums describe
package consistency; neither capability negotiation nor hashes authenticate a
publisher. PreflightOnly reports static_preflight_passed/archive_verified=false.
It runs a candidate capability subprocess but never starts the SCM service.

For every refresh, preserve a private hash-checked copy of the existing database,
WAL/SHM when present, exact original binaries/manifest/configuration and ACL
diagnostics. Copies require extra free disk space outside the live archive quota;
the live2GiB budget and12-month retention are unchanged. Do not overwrite these
copies with later evidence or restore an archive automatically.

While stopped, create an exclusive, flushed archive-verification.pending marker
with protocol1 and a unique canonical nonce. Install strictly checked candidate
binaries and start the existing SCM service with ephemeral --verify-archive/nonce
arguments. No new service, impersonation, permanent binPath change or account/
profile/key replacement occurs. The existing Windows service adapter passes SCM
arguments into ServiceContext; unknown arguments refuse without collecting.

The data directory must have administrator/SYSTEM ownership and no additional
writers beyond administrators, SYSTEM and the service SID. Archive files also
allow service ownership. Otherwise another local writer could forge a guard or
receipt. Preserve exact validated ACLs; never silently repair permissions.

The candidate accepts only the existing --service --config command line and a
matching, bounded guard in its configured absolute data directory. It opens a
read-only event store, validates the owner probe, decrypts/verifies raw records
and checks the existing chain. No writer, migration, collector or IPC listener
is created. SQLite cancellation checks a90-second deadline and SCM stop requests
cooperatively. Native calls/individual hashing steps are not forcibly preempted.
SQLite may use transient shared-memory sidecars even with a read-only connection.

An exclusive create_new report, <=4096 bytes, records protocol/nonce, PASS or
FAIL, read_only, scope, integrity counters/head and a bounded generic error code.
It contains no raw content or keys. Flush it before the service exits. A diagnostic
refusal exits SCM successfully, preventing configured non-crash recovery actions
from interpreting a completed refusal as a request to start normal collection.
The updater requires a clean stopped SCM status, exact report shape/nonce and
PASS, and verifies database/WAL bytes and presence against the protected copy.
WAL lifecycle differences conservatively refuse; this has not been qualified.

Normal runtime startup refuses any pending guard before opening the writer or
starting sensors. This covers verification crashes followed by SCM automatic
restart without the original transient arguments. Remove only the updater's own
matching marker, while fully stopped, after verification and before normal start.
Offline compression/noise rewrites also refuse a pending guarded transaction.
Do not delete pre-existing/malformed markers or silently treat them as obsolete.

Ordinary refusals retain exact binary rollback and restore the prior service
state, preserving the archive. A crashed verifier can leave a queued SCM restart
that Stop cannot cancel. If a clean diagnostic completion cannot be established,
do not restore an older unguarded binary or clear the guard: retain the checked
candidate, guard and backup, report the guarded recovery blocker. No recovery
policy/start-mode changes are introduced. Interrupted guarded transactions still
need a resumable recovery interface; source alone is not failure qualification.

No new dependency, custom cryptography or FFI is added. The service adapter adds
SCM argument plumbing; existing Windows wrappers provide report handle creation
and DPAPI. The updater retains its existing administrator requirement. New code
preserves owner continuity during same-version refresh, not portability after
profile/key loss. Raw encryption therefore remains default off.

Deferred verification: Windows PowerShell5.1/PowerShell7 fixtures; absent/wrong
capabilities, nonce/report shapes, missing or swapped marker; empty/plain/
compressed/protected archives, correct and wrong DPAPI owner; cancellation and
deadline; byte/ACL/config continuity; full archive refusal; SCM crash/restart
races, rollback and interrupted resume; native service/profile availability.
Prior green CI does not cover any ADR0046 source changes.

Primary API references: [SCM arguments](https://learn.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicecontroller.start)
and [queued recovery restart behavior](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w).
