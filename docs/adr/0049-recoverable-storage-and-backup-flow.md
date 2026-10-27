# ADR 0049: connect recoverable storage and an authorized backup flow

## Validation update, 2026-10-27

Relevant selected source has now passed the local checks recorded in [2026-10-27-storage-foundation.md](../validation/2026-10-27-storage-foundation.md), [2026-10-27-key-backend.md](../validation/2026-10-27-key-backend.md), [2026-10-27-key-desktop.md](../validation/2026-10-27-key-desktop.md).
The original decision below records its source-only state at the earlier date;
its deferred-check and missing-integration statements are historical, not the
current execution instruction. See [NEXT_SESSION](../NEXT_SESSION.md) for
remaining gates. Installed Windows behavior, UAC/SCM/DPAPI recovery and security
qualification remain open. Protection defaults remain off; no current host
configuration was changed. Local checks do not imply a completed dependency
security audit, portable archive import or release qualification.

## Original decision and limitations


2026-10-22. SOURCE UNVERIFIED. User defers all tests, format checks, builds, CI,
dependency resolution/audit and live changes. Lockfiles remain unresolved.

## Storage and key files

PIKOENC-v1/dpapi-user-v1 remains supported. PIKOENC-v2/age-x25519-v1 uses the
recoverable core and its authenticated Piko domain/archive UUID. Codec expected
length and digest still describe original encoded/raw content. A7-byte prefix
recognizes protected envelopes, including unknown versions, which fail closed.
Ciphertext keeps the existing4MiB+64KiB+12 bound. Compression skips protected
records. No old evidence is re-encrypted or migrated automatically.

Provider scheme and public key identity (archive UUID:age recipient) are stored
atomically with the encrypted owner probe, admitted before metadata writes.
Readers and writers reject wrong schemes/keys, orphan metadata and downgrade.
Portable protected writes require validated backup confirmation before opening
the writer/DDL. Existing plaintext history can remain plaintext; v1 archives
cannot silently switch to v2. Normalized events/indexes remain unencrypted.

Runtime recoverable_raw_evidence defaults false, as does protect_raw_evidence.
The former chooses the provider; it never enables the latter. Provider load
failures never fall back to DPAPI/plaintext. Readers can use a loaded key without
backup confirmation, but new writers require it. No current installed archive
or configuration was changed, and no activation UI is supplied yet.

key_bundle uses fixed evidence-key.json and evidence-key.confirmed.json files.
Existing private directory/ancestor ACLs are a prerequisite; the installed
installer provides that boundary, console key operations are refused. Creation
uses inspected exclusive create_new handles, sync, exact readback and DPAPI
unwrap. Size limits64KiB/16KiB. No path-based cleanup of unrelated files.
The embedded bundle boolean does not authorize protection. An immutable receipt
binds exact bundle SHA256, archive UUID, public recipient and an encrypted fixed
proof. Code re-entry plus local-key decryption proves consistency, not physical
off-device custody. Corrupt receipts and existing keys are never overwritten.

## Backup authorization and UI

A dedicated service thread has a one-job queue, one5-minute monotonic ticket,
no long-lived plaintext code cache and no secret diagnostics. Installed-service
mode only. Status requests sample actual key files through that thread, not a
stale success cache. Closed/full queues and failures remain unavailable.

BeginKeyBackup creates a random bearer ticket but no key/file. The desktop then
invokes the existing adjacent elevated helper with a new narrow authorization
payload: purpose, ticket UUID, original desktop PID/creation time and expiry.
No secret or arbitrary command/path enters the helper command line. Existing
native runas, parent/file locking and origin-liveness checks are reused; no new
FFI or generic shell capability. The helper still supports prior network plans.
It now depends on IPC/Tokio for this purpose; it does not apply Firewall rules
when processing a key authorization request. Existing operation mutex serializes
the helper with network operations. UAC remains an explicit human action.

AuthorizeKeyBackup requires the named-pipe elevated-administrator authorization.
Other key operations require the current random ticket and its grant (plus the
endpoint's existing OS DACL); they cannot mint that grant. Installed endpoint
permissions allow the enrolled viewer, administrators and SYSTEM. The ticket is
a short-lived bearer capability, not a new process/session isolation boundary;
it must never enter logs or URLs. This does not protect a compromised viewer
process from its own memory. Cancel invalidates only the matching ticket and
keeps durable keys/receipts. A delayed helper cannot authorize a replacement ID.

After authorization, ReadKeyBackup prepares a key once or exports the same
locally unwrapped key. It checks the archive identity. Confirmation rechecks that
identity before writing an immutable receipt, verifies the re-entered code and
consumes the grant. Retries after an ambiguous response preserve the same key;
another export requires a new ticket/UAC approval. File operations already
executing are not forcibly cancelled on client timeout; no encryption activation
or key overwrite can follow such a timeout.

IPC SecretText has bounded owned zeroizing memory and redacted Debug. Request,
response and size-check JSON buffers are zeroizing; parse errors are generic.
No CLI command exports keys and CLI refuses unexpected secret reply types.
Tauri exposes status, begin, authorization, read, confirmation and cancellation.
UI is collapsed by default; it requires explicit consent before UAC/reveal,
explicit download of a plaintext backup, independent password-field re-entry
and a custody declaration. Expiry/disconnect/cancel/collapse/teardown/success
clear volatile state and Blob URLs; stale replies cannot restore it. Browser JS,
Tauri internals, OS caches and user-downloaded files are not securely erasable
by this flow. Downloading locally does not constitute an external backup.

## Remaining work and deferred evidence

This delivers source paths core -> provider/storage and service -> authenticated
helper/IPC -> desktop backup confirmation. It does NOT yet deliver full profile-
loss restoration/bootstrap, replacement-key transactions, durable recovery resume,
key rotation/revocation, live crypto activation, signed external anchors or full
database encryption. Existing service capability key_recovery_portable stays
false until complete restoration exists. An export alone cannot recover legacy
DPAPI-only raw blobs. No production protection claim is added.

Deferred checks: lockfile resolution/MSRV/audit, v1/v2/plain/compressed mixes,
unknown headers/oversize/domain/key mismatches, full quotas and copy/expiry,
private ACL/hardlink/reparse/partial-file cases, native profile availability,
nonce guessing/cross-session/cancel/replay/expiry/queue cases, UAC identity/origin,
wrong-code confirmation, transport redaction, stale UI replies/download cleanup,
restart/backup restore and complete loss-of-profile drills. No existing green
CI/check result qualifies this source.
