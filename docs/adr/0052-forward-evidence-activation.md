# ADR0052: recoverable activation and forward-only interruption recovery

## Validation update, 2026-10-27

Relevant selected source has now passed the local checks recorded in [2026-10-27-key-backend.md](../validation/2026-10-27-key-backend.md), [2026-10-27-key-desktop.md](../validation/2026-10-27-key-desktop.md), [2026-10-27-recovery-package.md](../validation/2026-10-27-recovery-package.md).
The original decision below records its source-only state at the earlier date;
its deferred-check and missing-integration statements are historical, not the
current execution instruction. See [NEXT_SESSION](../NEXT_SESSION.md) for
remaining gates. Installed Windows behavior, UAC/SCM/DPAPI recovery and security
qualification remain open. Protection defaults remain off; no current host
configuration was changed. Local checks do not imply a completed dependency
security audit, portable archive import or release qualification.

## Original decision and limitations


Status: SOURCE UNVERIFIED, 2026-10-23. No tests, builds, parser/format checks,
installation, live changes, dependency resolution, CI or push executed.
Current progress and remaining work live in NEXT_SESSION.md.

The fresh activation flow is desktop -> Tauri -> dedicated IPC key ticket ->
elevated helper -> embedded PowerShell procedure -> protected storage startup ->
runtime IPC confirmation. Backup confirmation and explicit user opt-in remain
prerequisites; defaults remain disabled. The helper embeds the procedure using
include_str!, so existing executable manifest/snapshot/update rollback/resume
also delivers matching activation code. Loose installed/package activation
scripts are no longer used. Constant source travels through stdin to a fixed
PowerShell command, with 64 KiB source bound, null output, hidden window and
150-second child deadline. No secrets enter argv, no new FFI or dependency.

Disconnected desktop resume uses the existing validated-hex/UAC launcher and
origin-bound operation serialization. Its purpose-specific authorization has
an expiry and carries no recovery code. No unavailable service ticket is needed:
the elevated operation instead requires an exact existing journal. CMD fallback
invokes the installed helper after Windows consent. Neither resume entry may
start a fresh activation.

Protocol-2 journals bind the original configuration hash, key bundle hash,
confirmation receipt hash and installed manifest hash. The original backup and
journal staging file are flushed; the journal is published by same-directory
move before configuration replacement. Retained attempts are bounded to 16;
none is automatically deleted. Unsupported/partial journals refuse rather than
being silently migrated. Existing v1 development journals need explicit review.

Once prepared, recovery moves forward. A service may have committed protected
raw evidence even if SCM/IPC confirmation failed, so disabled flags are never
restored. Exact original configuration may proceed; exact deterministically
enabled bytes may complete only after the real key worker confirms ready,
backup-confirmed, both flags enabled and pending. Baseline hashes are rechecked
before journal removal. Disabled startup with a pending guard refuses collection;
enabled startup can open protected storage and provide the required IPC proof.

Matching configuration stages are reflushed. Explicit resume with exact original
configuration and unchanged identity can privately retain one partial stage
(up to 16 KiB) and regenerate it; a second partial residue refuses. Missing or
changed original config, baseline, key or installation refuses with copies kept.
A private retained stage gets its ACL before moving. No arbitrary archive restore,
configuration repair, guard removal, key rotation or profile-loss bypass occurs.

Trusted ACL/owner, null-DACL/reparse refusal, bounded inputs, installed executable
manifest consistency, fixed paths and upgrade lock gate the operation. Existing
update/key-recovery markers exclude activation; their paths exclude activation
markers. Administrator-tampered state is outside this transaction's trust boundary.
The helper's fixed process creation uses the existing std Windows extension and
PowerShell boundary. End-to-end packaging and interruption behavior are unqualified.

Deferred checks: crash at backup/journal-stage/publication/config-stage/replace/
start/IPC/journal-removal boundaries; partial stage preservation and repeat refusal;
changed baseline/manifest/ACL; UAC cancellation; disconnect during activation and
resume; first v2 write then confirmation failure; stopped-service resume; full
storage; helper upgrade/rollback/resume; key recovery. No check was executed.
