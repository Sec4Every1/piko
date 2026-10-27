# ADR0053: maintenance admission after releasing readers

## Validation update, 2026-10-27

Relevant selected source has now passed the local checks recorded in [2026-10-27-storage-foundation.md](../validation/2026-10-27-storage-foundation.md), [2026-10-27-maintenance-vertical.md](../validation/2026-10-27-maintenance-vertical.md).
The original decision below records its source-only state at the earlier date;
its deferred-check and missing-integration statements are historical, not the
current execution instruction. See [NEXT_SESSION](../NEXT_SESSION.md) for
remaining gates. Installed Windows behavior, UAC/SCM/DPAPI recovery and security
qualification remain open. Protection defaults remain off; no current host
configuration was changed. Local checks do not imply a completed dependency
security audit, portable archive import or release qualification.

## Original decision and limitations


Status: SOURCE UNVERIFIED, 2026-10-23. Progress/remaining work: NEXT_SESSION.md.
Safe Rust in event-storage; no public configuration, dependency, FFI or privilege
change. No tests, builds or other checks executed.

Compression stages at most 32 rows/4 MiB, verifies digests, closes its reader,
then uses the existing bounded nonblocking checkpoint/admission path. Under
BEGIN IMMEDIATE, shared accounting re-samples DB/WAL/SHM and pending main-file
growth before mutation. Updates compare original payload/digest/rowid; any changed
or removed row rolls back the whole pass. No-op passes avoid a writer transaction.
Admission never counts anticipated compression savings as freed physical space.

Retention computes the existing conservative reserve while verifying its prefix
under the writer lock. Admission refusal occurs before DELETE/metadata changes.
It then drops transaction/readers, tries the existing bounded checkpoint path,
and re-reads/re-verifies once. A second refusal returns; cutoff, contiguous-prefix
policy and retained evidence are unchanged. Later errors never trigger that retry.

The same writer-locked accounting now covers append and protection-policy metadata
as well as offline-copy host identity, detection annotations and provenance.
Noise-copy targets privately carry a companion source path. Target bootstrap
retains the existing half-budget reserve; later admission/checkpoint checks count
source + destination physical files against one configured quota. Source loss
fails closed. Ordinary stores carry no companion; no persistent policy is added.
Copy callers must keep source writers stopped. Missing/partial target artifacts
are retained on failure, never removed to make room.

These are conservative admission estimates, not proven SQLite amplification or
physical peak bounds. Source+destination accounting excludes external backups,
other retained maintenance outputs and filesystem allocation overhead. Existing
maintenance status/IPC/UI propagates compression refusal and integrity errors;
offline copy still reports through the existing CLI/manual maintenance workflow.

Deferred checks: reclaimable WAL, pinned readers, budget refusal without mutation,
conditional-update mismatch rollback, cursor retry, unchanged expired-prefix
behavior, concurrent commits between admission/BEGIN, source loss, combined copy
refusal, identity/annotation/provenance refusal and destination bootstrap residue.
