# Protected evidence and maintenance storage foundation

Base: 4e00996. Consolidates the storage-side provider interface and v1/v2 raw
evidence envelopes, owner/key metadata checks, bounded maintenance, conditional
compression updates, retention admission retry and writer-locked accounting.
Offline copy accounts for source and destination DB/WAL/SHM under one quota;
external backups and worst-case physical allocation remain outside that bound.

Source boundary: event-storage lib.rs, evidence_codec.rs, noise.rs, retention.rs,
maintenance.rs, protected_evidence.rs and tests/protected_storage.rs. The only
consumer adaptation is the service storage_error mapping for ProtectionPolicy.
No manifests, lockfiles, crypto dependencies, Windows provider, activation,
key lifecycle, installer or UI changes are included. Defaults remain protection
off/provider absent; no installed configuration is changed.

## Corrected refusal case

A new regression reproduced implicit metadata reconstruction: after all policy
metadata was removed from an archive containing protected raw rows, reopening
with the original provider and protection enabled recreated policy metadata.
Writer validation now refuses orphan protected rows regardless of the requested
new-write flag. Explicit recovery remains separate; failed attempts preserve
raw rows and do not recreate the policy marker. Requesting protection without
a provider also now returns ProtectionPolicy instead of generic Configuration.

## Local evidence

Checks ran on an archived 4e00996 plus exactly the selected source. Existing
locked offline dependencies were used; neither lockfile was rewritten.

- Storage: 54 tests passed, including 7 new integration tests for both envelope
  versions, original evidence/digest continuity, disabled/missing/wrong providers,
  reader versus writer maintenance/copy, failed writes without plaintext fallback,
  missing metadata, damaged envelopes and prerequisites before archive creation.
- Service: 15 tests passed.
- cargo check --offline --locked --workspace --all-targets passed on the selected
  snapshot after the public StorageConfig/StorageError changes were included.
- Affected storage/service all-target Clippy with -D warnings passed.
- Targeted rustfmt --edition 2021 --check on the changed Rust files passed.
- Staged source is compared to the tested snapshot before committing.

The injected tagged-XOR provider is deliberately noncryptographic. These tests
execute production storage/envelope logic, but do not qualify DPAPI, age, key
backup/recovery, Windows identities or installed runtime protection.

Snapshot/logs: .build/consolidation-storage-foundation-20261027,
storage-service-tests.log, storage-clippy.log and workspace-check.log. The
reproduced pre-fix failure is in missing-policy-before-fix.log. Data and names
are synthetic; generated artifacts are excluded. No host installation,
driver load, active-protection change or manual remote CI dispatch occurred.
