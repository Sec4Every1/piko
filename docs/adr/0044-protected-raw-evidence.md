# ADR 0044: opt-in protection of newly stored raw evidence

## Validation update, 2026-10-27

Relevant selected source has now passed the local checks recorded in [2026-10-27-storage-foundation.md](../validation/2026-10-27-storage-foundation.md), [2026-10-27-key-backend.md](../validation/2026-10-27-key-backend.md).
The original decision below records its source-only state at the earlier date;
its deferred-check and missing-integration statements are historical, not the
current execution instruction. See [NEXT_SESSION](../NEXT_SESSION.md) for
remaining gates. Installed Windows behavior, UAC/SCM/DPAPI recovery and security
qualification remain open. Protection defaults remain off; no current host
configuration was changed. Local checks do not imply a completed dependency
security audit, portable archive import or release qualification.

## Original decision and limitations


2026-10-22. Development source only; tests, lint, builds and CI deferred by user.

Scope: encrypt new raw-evidence blobs with the runtime account's existing Windows
DPAPI boundary. This is not encryption of the entire SQLite database: normalized
events, searchable indexes, derived detections and metadata remain plaintext.
Old raw blobs remain readable and unchanged. No archive migration or live change.

Storage exposes an injected Debug/Send/Sync EvidenceProtection interface so safe
core code has no new native dependency. The Windows service adapter delegates
to existing user-scoped CryptProtectData/CryptUnprotectData wrappers; no new FFI,
cryptographic dependency or application-managed secret key. All production
storage configurations, including integrity readers and offline maintenance,
receive the adapter. Configuration protect_raw_evidence defaults false.

The write path serializes/digests original raw JSON, compresses it when useful,
then seals a versioned domain-tagged payload. The outer PIKOENC-v1 envelope binds
the expected inner length; DPAPI protects the inner domain/encoded bytes. Stored
blobs have a4MiB+64KiB+12 bound; decoded/compressed content keeps the prior4MiB
limit. Provider failure has no plaintext fallback. Reads, raw API, integrity,
retention and copy paths unwrap/decompress before checking original digest and
evidence identity. Ciphertext overhead counts toward admission/batch budgets.
Already protected blobs are not rewritten by offline compression.

Writer activation atomically persists an encrypted fixed-domain owner probe and
raw_evidence_protection=dpapi-user-v1 only after archive
integrity/startup work succeeds and metadata admission passes. Subsequent writers
with protection disabled or no provider refuse the marked archive before DDL.
Readers need a provider but may use protection-disabled configuration. Owner
probe decryption must succeed even when there are no protected raw rows yet,
preventing a different maintenance account from silently becoming the writer.
Missing/orphan probes or unknown policies refuse. Protected blobs with a missing
marker also prevent a plaintext writer. Copy requires the source writer policy
before destination creation. Compression does not encrypt historical plaintext.
This local metadata is not a signed anti-tampering anchor.

Key lifecycle is owned by the Windows account/profile, not a portable Piko key.
Account/profile/DPAPI-key loss can make encrypted evidence unrecoverable. Merely
elevating another administrator does not grant that identity the service account's
keys. In particular, existing offline administrator recovery/upgrade verification
cannot be claimed compatible with encrypted service-owned archives. Keep default
off and do not change installed configuration until service-identity maintenance,
key backup/recovery and relevant installer workflows are implemented/qualified.
This source option is not an end-user-ready whole-log encryption release.

Deferred verification: plaintext/legacy/compressed/encrypted mixes, exact digest
continuity, malformed envelope/length/domain, wrong account/unavailable keys,
quota with ciphertext overhead, downgrade refusal, restarts, maintenance/upgrade
rollback and true service profile availability. No old green result covers it.
ADR0045 adds source for routine compression on the original storage writer with
cached IPC/UI status; it is also unverified. Next: key recovery and protected
installer/upgrade workflows, then encrypted normalized-event design without
breaking searchable schema/integrity semantics.
