# ADR 0048: recoverable evidence-key core, not an activated archive format

## Validation update, 2026-10-27

Relevant selected source has now passed the local checks recorded in [2026-10-27-recoverable-key-core.md](../validation/2026-10-27-recoverable-key-core.md), [2026-10-27-key-backend.md](../validation/2026-10-27-key-backend.md).
The original decision below records its source-only state at the earlier date;
its deferred-check and missing-integration statements are historical, not the
current execution instruction. See [NEXT_SESSION](../NEXT_SESSION.md) for
remaining gates. Installed Windows behavior, UAC/SCM/DPAPI recovery and security
qualification remain open. Protection defaults remain off; no current host
configuration was changed. Local checks do not imply a completed dependency
security audit, portable archive import or release qualification.

## Original decision and limitations


2026-10-22. Development source only; no tests, format checks, builds, CI, package
creation, dependency resolution/audit or installed changes. Cargo lockfiles do
not yet describe the new dependencies; resolve both workspace/desktop lockfiles
and qualify MSRV, licenses/advisories and dependency closure before any build.

DPAPI-only evidence is tied to the original Windows profile and keys. Copying
its ciphertext or exporting a new Piko recovery code cannot repair that loss.
Do not export Windows master keys or silently broaden the DPAPI protection scope.
Instead introduce an application evidence key with a separate portable recovery
code for a future versioned raw-evidence format.

The new safe-Rust piko-crypto crate uses age=0.12.1 (pinned, default features off)
for X25519 recipient-based authenticated encryption and key serialization. No
custom primitive, password KDF or nonce construction is implemented. zeroize
handles managed secret buffers. This is a new dependency graph, not qualified
cryptography or a post-quantum implementation. The core intentionally has no
filesystem, IPC, service, UI or automatic activation capability.

EvidenceKey generates an identity/public recipient and a RecoveryCode without
Serialize/Display/Clone and with a redacted Debug implementation. Disclosure is
an explicit method intended only for a future protected backup flow. The code is
the private key: possessing it enables decryption; it must never enter logs,
command-line arguments, Git, ordinary configuration or automatic telemetry.

LocalKeyEnvelope holds a version, public recipient and bounded wrapped secret.
KeyProtector wraps only the local secret-key copy. The service's existing Windows
adapter implements it through the current user-scoped DPAPI wrappers. Native
DPAPI plaintext output is now zeroized before LocalFree (bounded writable slice
inside win-platform's existing native boundary); no new Windows FFI or privilege.
This is distinct from the existing active DPAPI evidence-provider interface.

Core paths implemented: generate key/code; wrap and unwrap local key; recover the
same key from a code plus expected public recipient; decrypt a preserved proof
bound to the expected archive UUID before wrapping under a replacement profile.
No key-file overwrite, account/profile modification, raw rewrite or key rotation
occurs. Callers must supply the expected identity/UUID from trusted preserved
metadata; a proof is not a full archive integrity check or external authenticity.
Recovery requires a code saved before loss and new-format evidence made with
that key. It cannot recover existing PIKOENC-v1 DPAPI raw blobs.

Encrypted evidence binds a Piko domain and non-nil archive UUID inside age's
authenticated payload. Input/output limits:4MiB payload,4MiB+64KiB ciphertext,
16KiB wrapped secret,128-byte recovery-code/recipient text. Decrypt rejects
passphrase/scrypt envelopes before running a KDF, consumes/authenticates the final
stream chunk, checks domain/archive and releases only bounded plaintext. Buffers
holding decoded secret keys or evidence are zeroizing; the decode allocation is
fixed to avoid growth leaving previous plaintext allocations behind. Underlying
crypto/library/runtime memory behavior still requires security review.

Not implemented here: new raw codec/storage policy and migration, durable key
bundle files with private ACLs and create/replace transactions, backup export and
read-back confirmation, authenticated IPC, nontechnical recovery UI, full archive
verification before owner reassignment, key rotation/revocation and restoring
after an interrupted key import. Do not label this as complete KEY STORAGE or
RECOVERY. Existing service capability key_recovery_portable remains false and
protect_raw_evidence remains false by default. No current archive uses this key.

Next: connect the key bundle and versioned storage mode, then controlled backup/
confirmation and recovery IPC/UI; keep activation gated until all exist. Deferred
coverage: generation/import roundtrip, wrong code/recipient/archive, corruption,
truncation/trailing data, size/KDF limits, error/Debug redaction, unavailable DPAPI,
native-memory wiping, Windows profile loss/rebind, durable writes and rollback.

Primary API references: [age Encryptor](https://docs.rs/age/latest/age/struct.Encryptor.html)
and [age Decryptor](https://docs.rs/age/latest/age/struct.Decryptor.html).
