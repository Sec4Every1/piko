# ADR 0047: resume a known guarded update forward

## Validation update, 2026-10-27

Relevant selected source has now passed the local checks recorded in [2026-10-27-recovery-package.md](../validation/2026-10-27-recovery-package.md).
The original decision below records its source-only state at the earlier date;
its deferred-check and missing-integration statements are historical, not the
current execution instruction. See [NEXT_SESSION](../NEXT_SESSION.md) for
remaining gates. Installed Windows behavior, UAC/SCM/DPAPI recovery and security
qualification remain open. Protection defaults remain off; no current host
configuration was changed. Local checks do not imply a completed dependency
security audit, portable archive import or release qualification.

## Original decision and limitations


2026-10-22. Development source only; no tests, parser checks, builds, packaging,
CI, installation or live service actions performed.

Update-Piko.ps1 -ResumeInterruptedUpdate loads an internal continuation, reusing
the existing identity, snapshot, archive and verification gates. The public
Resume-PikoUpdate.cmd uses the existing interactive UAC wrapper; it discovers
the transaction without asking a novice for paths, SIDs or nonces. No UAC was
opened during development. Packaging source includes both new files.

New updates durably flush a resume_protocol1 journal before creating the guard.
The journal binds the candidate manifest digest, prior state, original binary
hashes/ACLs, configuration digest/ACL, directory ACLs and verification nonce.
Older journals without this contract are not silently upgraded or trusted.

Resume requires an existing private guard and one matching protected journal
among at most64 canonical .upgrade directories. Metadata is bounded (journal
256KiB, archive inventory4KiB, guard1KiB). Validate staged candidate consistency,
capabilities, original backups, unchanged configuration/directory/file ACLs and
all archive backup hashes. Paths in the archive inventory are fixed names, not
arbitrary journal-supplied destinations. Unknown/ambiguous state refuses.

The installed service executable must already match the guarded candidate.
Other installed files may match either the preserved original or the staged
replacement. Unrecognized bytes, including a half-written executable, refuse
automatic repair. This deliberately does not execute an old unguarded service
to recover from a verifier crash with a potentially queued SCM restart.

Static preflight does not stop services or verify the live archive. Mutation
uses the existing exclusive upgrade lock; failing to acquire it never stops a
different updater's service. Recheck owned marker, installed files and preserved
configuration after the lock/stop. Database/WAL bytes must still match the
pre-update archive snapshot; shared-memory sidecars remain transient. This gate
does not restore a backup over newer or changed evidence.

Retain an existing bounded verification report privately before retrying its
fixed nonce report path. Complete the checked candidate copy, re-run read-only
verification under the original service identity, then release only the owned
guard and start normally. Restore the journal's prior Running/Stopped state.
Failure keeps the candidate and backups; while owning the lock, attempt to stop
and retain/recreate the guard. Never roll back to an unguarded binary or restore
an archive automatically. Missing/changed data or failed guard retention remain
explicit errors, not successful recovery.

Limits: only new journals, an intact staged package, an already installed guarded
service and unchanged pre-start evidence are supported. Post-start failures that
already wrote new events, partial service-image writes, malformed/legacy journals
and ambiguous transactions still need a separate recovery path. Crash windows
around guard release and SCM delayed restarts are not qualified. Repeated human
retries retain diagnostics and require adequate disk space; no automatic retry
loop, cleanup, key export, custom crypto, new FFI or new privilege is introduced.
Portable recovery after loss of Windows profile/DPAPI keys remains unimplemented;
raw encryption stays default off.

Deferred evidence: PowerShell5.1/7 parser/fixtures, compatible journal generation,
unique/ambiguous/legacy discovery and bounds, ACL/reparse/hash drift, lock failure,
mixed/partial binary sets, stale/partial reports, repeated interruptions, clean
verification/guard release/health failure, SCM races, packet/runtime integrity.
Existing updater fixtures need adaptation to this new protocol before qualification.
