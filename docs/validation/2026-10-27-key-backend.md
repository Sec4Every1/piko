# Recoverable evidence key backend integration

Base: 9770b16. Consolidates the actual provider/key bundle, bounded key worker,
backup/activation-purpose tickets, guarded recovery and archive-verification
service modes, their IPC types, runtime wiring and CLI secret refusal. Both
protection flags remain false by default. APP-03 modules/commands are excluded.
No manifest, dependency or lockfile change belongs to this checkpoint.

Key operations use a separate single-slot queue. Read disclosure requires the
backup authorization; receipt confirmation follows delivery. Activation uses
a distinct ticket purpose and a matching confirmed key. Pending recovery or
verification blocks ordinary collection/key operations and is not auto-cleared.
An activation journal permits forward completion only with both required flags.
Receipts bind the exact bundle hash, archive, recipient and proof purpose.

Native changes reuse existing boundaries: Windows-service start arguments are
passed to fixed maintenance modes; LockedFile gains an existing-file-only
writable inspected handle for flush/recovery; the existing DPAPI wrapper wipes
its bounded native plaintext allocation before LocalFree. No new FFI function,
dependency, account/ACL grant or live privileged operation was introduced.
IPC frame buffers are zeroizing and malformed frame errors do not echo input.
This is not a claim that every library/allocator copy is erased.

## Exact-source validation

An archived baseline plus only the selected backend hunks/files was checked.
No uncommitted guard/UI/installer source was used to make this slice compile.

- Service: 30 tests passed, including 5 new production-worker refusal/grant tests,
  3 receipt/recovery-artifact tests and 2 pending-state collection-guard tests.
- IPC: 5 tests passed, including 3 new secret bounds/redaction, authorization
  classification and injected-field tests.
- win-platform: 42 unit and 1 new writable-lock integration test passed;
  3 pre-existing cases remained ignored. The new test uses temporary plain
  files and checks no create/truncate, exclusive ownership, flush and release.
- Affected service/IPC/platform/CLI all-target Clippy with -D warnings passed;
  targeted Rust formatting checks passed. Whole-runtime formatting is not claimed.
- Service/CLI offline locked debug build passed. The built service's read-only
  --key-recovery-capabilities and --archive-capabilities commands returned the
  expected protocol-1 metadata without starting collection or installed SCM.

A new regression reproduced expired requests occupying the key queue and
refusing an immediately following valid request. KeyClient now checks expiry
before creating/enqueueing the job; the worker retains its own expiry check.
Recovery primitive tests execute real inspected file/sync/readback functions
with synthetic artifacts, including exact idempotent retry, mismatch refusal,
empty-original preservation and retained partial-installation residue.

Snapshot/logs: .build/consolidation-key-backend-20261027, backend-tests.log,
service-tests.log, backend-clippy.log, backend-build.log and
locked-update-tests.log. Test keys/data are synthetic; no secret is printed.
DPAPI under the installed service identity, elevated IPC authorization, SCM
maintenance/recovery execution, full interrupted replacement/power-loss behavior
and installed activation remain unqualified. No installed service, real evidence,
active-protection state, driver, release or manual remote CI dispatch changed.
