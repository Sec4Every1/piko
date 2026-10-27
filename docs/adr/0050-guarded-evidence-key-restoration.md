# ADR 0050: guarded recovery after service-profile key loss

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


2026-10-23. SOURCE UNVERIFIED, not built, installed or executed. Tests, builds,
format/parser checks, dependency resolution and CI remain deferred by the user.

## Workflow

Restore-PikoEvidenceKey.cmd enters the existing installer UAC wrapper in STA
mode. A Windows file picker selects the exported plaintext recovery backup.
No code or selected path appears in process arguments. Inputs are bounded and
failure messages do not echo parser or OS exceptions. Managed PowerShell/GUI
strings and OS caches cannot be guaranteed erased.

The launcher requires the existing virtual-account service, exact installed
binary/configuration paths, a consistent four-executable manifest and protected
installation/private data ACLs. It probes a separate bounded key-recovery
capability protocol. Existing update capabilities remain unchanged and do not
claim general cross-machine migration. An inconsistent installation is refused.

The existing upgrade lock serializes maintenance. Lock failure causes no service
action. After the service stops, an immutable private baseline records DB/WAL
hashes and configuration/manifest hashes. The fixed private pending request
contains the nonce, archive identity, recipient and secret code. It doubles as
the normal-start guard. Baseline and request are synced before SCM launch and
reflushed on retries. Update paths refuse pending key recovery and vice versa.

SCM receives only --recover-evidence-key plus a nonce. The service creates no
writer, IPC listener or collectors. A bounded read-only scan requires v2 policy,
matching archive UUID/key identity/owner probe and complete chain/raw integrity.
Only then may local wrapping change. Legacy DPAPI-only or plaintext archives
are refused. Recovery code does not repair tampering, missing data or v1 keys.

Key rebind preserves the original bundle/receipt, stages the same recovered key
under the current service DPAPI profile, confirms the new pair and journals
exact hashes. Matching nonce artifacts are reused and flushed through inspected
exclusive writable handles. Both installing copies/destinations are preflighted
before either replacement. Corrupt/partial/unrelated files are retained and
refused. No new FFI: open_for_update extends the existing inspected Windows file
boundary, without create/truncate. No new privilege or dependency for this slice
beyond using zeroize already introduced by ADR0048/0049.

A second full read-only scan uses the newly installed local bundle. Report
creation/readback is bounded; reports have no secret. The launcher requires a
clean SCM stop, nonce-bound PASS, complete key replacement, valid integrity
fields, preserved installation and byte-identical DB/WAL before guard removal
and normal restart. Failed reports are retained, up to64 attempts per nonce.
Retries require the same backup and immutable baseline. A clean FAIL before any
key change releases only its own guard, allowing selection of the correct backup.
Other failures retain the guard and copies. Normal-start failure restores the
request if possible; later changed evidence refuses automatic resume.

## Limits and next work

This is same-installation profile-loss recovery source, not a qualified portable
archive importer. User supplies their external backup; no automatic archive
restore, data deletion, policy weakening or quota expansion. Temporary private
request contains the plaintext secret until completed; logical deletion is not
secure erasure. Old wrapping/stages/reports remain private for diagnosis.

Per-file replacement is not pair-atomic; the durable startup guard is mandatory.
File flushes do not prove directory-entry durability through sudden power loss.
Partial request/state/stage files, missing baseline, a second DPAPI-profile loss
mid-transaction, inconsistent install and post-restart archive changes refuse
automatic recovery. A complete signed installer/cross-machine import, key
rotation/revocation/TPM, full-log encryption, independent anchors and guided
encryption activation remain separate work. Existing flags remain off.

Deferred evidence: build/lockfile/MSRV/dependency checks; wrong key/archive and
metadata tamper; missing/partial/reparse/hardlink/ACL artifacts; every interrupted
commit/flush; fail/noop retry; SCM crash/timeout/restart; concurrent update;
full/large archives; power-loss/profile-loss drills; UAC picker and packaging.
No earlier successful checks qualify these source changes.
