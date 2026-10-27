//! Immutable, bounded local key material for the original Windows identity.
//!
//! The installed data directory must already have its private ACL. Console mode
//! has the same prerequisite: callers must provide an existing private directory
//! whose ancestors cannot be replaced by an untrusted account. These checks do
//! not provision ACLs or lock parent directory handles. No directories are made.
use super::evidence_protection::WindowsEvidenceProtection;
use piko_crypto::{EvidenceKey, LocalKeyEnvelope, RecoveryCode};
use piko_win_platform::file_response::LockedFile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::fs::MetadataExt,
    path::{Component, Path},
    sync::Arc,
};
use uuid::Uuid;

const BUNDLE_NAME: &str = "evidence-key.json";
#[cfg(test)]
mod tests;
const CONFIRMATION_NAME: &str = "evidence-key.confirmed.json";
const MAX_BUNDLE_BYTES: usize = 64 * 1024;
const MAX_CONFIRMATION_BYTES: usize = 16 * 1024;
const CONFIRMATION_PROOF: &[u8] = b"piko.evidence-key.backup-confirmed.v1\0";
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    version: u16,
    archive_id: Uuid,
    local_key: LocalKeyEnvelope,
    // Reserved legacy field. Only a validated separate confirmation grants use.
    backup_confirmed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirmation {
    version: u16,
    archive_id: Uuid,
    recipient: String,
    bundle_sha256: [u8; 32],
    proof: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct LoadedKey {
    pub(super) archive_id: Uuid,
    pub(super) key: Arc<EvidenceKey>,
    pub(super) backup_confirmed: bool,
    pub(super) recipient: String,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid evidence key material")
}

fn private_error(error: io::Error) -> io::Error {
    // Preserve operational kinds (especially NotFound/AlreadyExists) without
    // publishing paths, DPAPI diagnostics or supplied recovery material.
    io::Error::new(error.kind(), "evidence key operation failed")
}

fn existing_private_directory(data_dir: &Path) -> io::Result<()> {
    if !data_dir.is_absolute()
        || data_dir
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid());
    }
    for ancestor in data_dir.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid());
        }
    }
    Ok(())
}

fn read_handle(input: &mut LockedFile, bound: usize) -> io::Result<Vec<u8>> {
    let bytes = read_raw_handle(input, bound)?;
    if bytes.is_empty() {
        return Err(invalid());
    }
    Ok(bytes)
}

// Recovery preserves malformed/empty original files too; interpreting them is
// separate from retaining their exact bounded bytes as rollback evidence.
fn read_raw_handle(input: &mut LockedFile, bound: usize) -> io::Result<Vec<u8>> {
    if input.file.metadata()?.len() > bound as u64 {
        return Err(invalid());
    }
    input.file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(bound + 1);
    (&mut input.file)
        .take((bound + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > bound {
        return Err(invalid());
    }
    Ok(bytes)
}

fn read_fixed(data_dir: &Path, name: &str, bound: usize) -> io::Result<Vec<u8>> {
    existing_private_directory(data_dir)?;
    // This helper requires DELETE access and exclusive sharing even for reads.
    // Refuse unavailable access; never fall back to an uninspected File::open.
    let mut input = LockedFile::open(&data_dir.join(name))?;
    existing_private_directory(data_dir)?;
    read_handle(&mut input, bound)
}

fn decode_bundle(bytes: &[u8]) -> io::Result<LoadedKey> {
    let bundle: Bundle = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if bundle.version != 1 || bundle.archive_id.is_nil() {
        return Err(invalid());
    }
    let key = EvidenceKey::unwrap_local(&bundle.local_key, &WindowsEvidenceProtection)
        .map_err(|_| invalid())?;
    Ok(LoadedKey {
        archive_id: bundle.archive_id,
        recipient: key.recipient(),
        key: Arc::new(key),
        backup_confirmed: false,
    })
}

fn validate_confirmation(bytes: &[u8], bundle: &[u8], loaded: &LoadedKey) -> io::Result<()> {
    let confirmation: Confirmation = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let digest: [u8; 32] = Sha256::digest(bundle).into();
    if confirmation.version != 1
        || confirmation.archive_id != loaded.archive_id
        || confirmation.recipient != loaded.recipient
        || confirmation.bundle_sha256 != digest
        || confirmation.proof.is_empty()
        || confirmation.proof.len() > MAX_CONFIRMATION_BYTES
    {
        return Err(invalid());
    }
    let proof = loaded
        .key
        .decrypt(loaded.archive_id, &confirmation.proof)
        .map_err(|_| invalid())?;
    if proof.as_slice() != CONFIRMATION_PROOF {
        return Err(invalid());
    }
    Ok(())
}

fn load_inner(data_dir: &Path) -> io::Result<(LoadedKey, Vec<u8>)> {
    let bytes = read_fixed(data_dir, BUNDLE_NAME, MAX_BUNDLE_BYTES)?;
    let mut loaded = decode_bundle(&bytes)?;
    match read_fixed(data_dir, CONFIRMATION_NAME, MAX_CONFIRMATION_BYTES) {
        Ok(confirmation) => {
            validate_confirmation(&confirmation, &bytes, &loaded)?;
            loaded.backup_confirmed = true;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok((loaded, bytes))
}

pub(super) fn load(data_dir: &Path) -> io::Result<LoadedKey> {
    load_inner(data_dir)
        .map(|(loaded, _)| loaded)
        .map_err(private_error)
}

// Retain the new create_new handle for write, sync, readback and cleanup. Never
// remove a path on failure: cleanup deletes only this exact inspected object.
fn write_new_verified<T>(
    data_dir: &Path,
    name: &str,
    bytes: &[u8],
    bound: usize,
    verify: impl FnOnce(&[u8]) -> io::Result<T>,
) -> io::Result<T> {
    if bytes.is_empty() || bytes.len() > bound {
        return Err(invalid());
    }
    existing_private_directory(data_dir)?;
    let mut output = LockedFile::create(&data_dir.join(name))?;
    let result = (|| {
        existing_private_directory(data_dir)?;
        output.file.write_all(bytes)?;
        output.file.sync_all()?;
        let persisted = read_handle(&mut output, bound)?;
        if persisted != bytes {
            return Err(invalid());
        }
        verify(&persisted)
    })();
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            if output.delete().is_err() {
                return Err(io::Error::other("incomplete evidence key cleanup failed"));
            }
            Err(error)
        }
    }
}

pub(super) fn prepare(data_dir: &Path, archive_id: Uuid) -> io::Result<(LoadedKey, RecoveryCode)> {
    (|| {
        if archive_id.is_nil() {
            return Err(invalid());
        }
        existing_private_directory(data_dir)?;
        // A stale marker must not silently confirm a newly prepared key.
        match read_fixed(data_dir, CONFIRMATION_NAME, MAX_CONFIRMATION_BYTES) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "evidence key confirmation already exists",
                ))
            }
        }
        let (key, recovery) = EvidenceKey::generate();
        let expected_recipient = key.recipient();
        let bundle = Bundle {
            version: 1,
            archive_id,
            local_key: key
                .wrap_local(&WindowsEvidenceProtection)
                .map_err(|_| invalid())?,
            backup_confirmed: false,
        };
        let bytes = serde_json::to_vec(&bundle).map_err(|_| invalid())?;
        let loaded = write_new_verified(
            data_dir,
            BUNDLE_NAME,
            &bytes,
            MAX_BUNDLE_BYTES,
            |persisted| {
                let loaded = decode_bundle(persisted)?;
                if loaded.archive_id != archive_id || loaded.recipient != expected_recipient {
                    return Err(invalid());
                }
                Ok(loaded)
            },
        )?;
        Ok((loaded, recovery))
    })()
    .map_err(private_error)
}

/// Re-entry proves that the caller possesses the matching recovery code. The
/// caller owns the secret input buffer and must erase it after this operation.
/// This creates an immutable receipt; it never replaces the bundle or a marker.
pub(super) fn confirm_backup(data_dir: &Path, code: &str) -> io::Result<LoadedKey> {
    (|| {
        let (mut loaded, bundle) = load_inner(data_dir)?;
        let recovered = EvidenceKey::recover(code, &loaded.recipient).map_err(|_| invalid())?;
        if loaded.backup_confirmed {
            return Ok(loaded);
        }
        let confirmation = Confirmation {
            version: 1,
            archive_id: loaded.archive_id,
            recipient: loaded.recipient.clone(),
            bundle_sha256: Sha256::digest(&bundle).into(),
            proof: recovered
                .encrypt(loaded.archive_id, CONFIRMATION_PROOF)
                .map_err(|_| invalid())?,
        };
        let bytes = serde_json::to_vec(&confirmation).map_err(|_| invalid())?;
        // Verify recovery proof against the locally unwrapped key before any write.
        validate_confirmation(&bytes, &bundle, &loaded)?;
        let result = write_new_verified(
            data_dir,
            CONFIRMATION_NAME,
            &bytes,
            MAX_CONFIRMATION_BYTES,
            |persisted| validate_confirmation(persisted, &bundle, &loaded),
        );
        match result {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                // Another serialized caller may already have confirmed the same
                // immutable bundle. An invalid existing marker is never replaced.
                let existing = read_fixed(data_dir, CONFIRMATION_NAME, MAX_CONFIRMATION_BYTES)?;
                validate_confirmation(&existing, &bundle, &loaded)?;
            }
            Err(error) => return Err(error),
        }
        loaded.backup_confirmed = true;
        Ok(loaded)
    })()
    .map_err(private_error)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RebindJournal {
    version: u16,
    nonce: Uuid,
    archive_id: Uuid,
    recipient: String,
    bundle_sha256: [u8; 32],
    confirmation_sha256: [u8; 32],
    original_bundle_sha256: Option<[u8; 32]>,
    original_confirmation_sha256: Option<[u8; 32]>,
}

struct RebindNames {
    original_bundle: String,
    original_confirmation: String,
    staged_bundle: String,
    staged_confirmation: String,
    installing_bundle: String,
    installing_confirmation: String,
    journal: String,
}

impl RebindNames {
    fn for_nonce(nonce: Uuid) -> Self {
        // Only typed, non-nil UUIDs reach here; filenames are never IPC input.
        let prefix = format!("evidence-key.rebind-{nonce}");
        Self {
            original_bundle: format!("{prefix}.original.json"),
            original_confirmation: format!("{prefix}.original-confirmed.json"),
            staged_bundle: format!("{prefix}.stage.json"),
            staged_confirmation: format!("{prefix}.stage-confirmed.json"),
            installing_bundle: format!("{prefix}.installing.json"),
            installing_confirmation: format!("{prefix}.installing-confirmed.json"),
            journal: format!("{prefix}.journal.json"),
        }
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn read_optional_raw(data_dir: &Path, name: &str, bound: usize) -> io::Result<Option<Vec<u8>>> {
    existing_private_directory(data_dir)?;
    let mut input = match LockedFile::open(&data_dir.join(name)) {
        Ok(input) => input,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    existing_private_directory(data_dir)?;
    read_raw_handle(&mut input, bound).map(Some)
}

fn resync_matching(data_dir: &Path, name: &str, expected: &[u8], bound: usize) -> io::Result<()> {
    existing_private_directory(data_dir)?;
    // A previous attempt may have written all bytes but failed its flush. A
    // matching read alone does not establish durability on an idempotent retry.
    let mut input = LockedFile::open_for_update(&data_dir.join(name))?;
    existing_private_directory(data_dir)?;
    if read_raw_handle(&mut input, bound)? != expected {
        return Err(invalid());
    }
    input.file.sync_all()?;
    if read_raw_handle(&mut input, bound)? != expected {
        return Err(invalid());
    }
    Ok(())
}

/// Recovery artifacts are never deleted on error. A partial file causes the
/// same nonce to refuse rather than replacing material that may be significant.
fn preserve_immutable(data_dir: &Path, name: &str, bytes: &[u8], bound: usize) -> io::Result<()> {
    if bytes.len() > bound {
        return Err(invalid());
    }
    existing_private_directory(data_dir)?;
    let mut output = match LockedFile::create(&data_dir.join(name)) {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return resync_matching(data_dir, name, bytes, bound);
        }
        Err(error) => return Err(error),
    };
    existing_private_directory(data_dir)?;
    output.file.write_all(bytes)?;
    output.file.sync_all()?;
    if read_raw_handle(&mut output, bound)? != bytes {
        return Err(invalid());
    }
    Ok(())
}

fn preserve_optional(
    data_dir: &Path,
    name: &str,
    bytes: Option<&[u8]>,
    bound: usize,
) -> io::Result<()> {
    match bytes {
        Some(bytes) => preserve_immutable(data_dir, name, bytes, bound),
        None => {
            if read_optional_raw(data_dir, name, bound)?.is_some() {
                return Err(invalid());
            }
            Ok(())
        }
    }
}

fn checked_original(
    data_dir: &Path,
    name: &str,
    expected: Option<[u8; 32]>,
    bound: usize,
) -> io::Result<Option<Vec<u8>>> {
    let bytes = read_optional_raw(data_dir, name, bound)?;
    if bytes.as_deref().map(digest) != expected {
        return Err(invalid());
    }
    if let Some(existing) = bytes.as_deref() {
        resync_matching(data_dir, name, existing, bound)?;
    }
    Ok(bytes)
}

fn check_destination(
    data_dir: &Path,
    name: &str,
    original: Option<&[u8]>,
    staged: &[u8],
    bound: usize,
) -> io::Result<bool> {
    let current = read_optional_raw(data_dir, name, bound)?;
    if current.as_deref() == Some(staged) {
        // A matching destination can be the residue of an interrupted commit.
        // Complete its writable-handle flush before accepting it as installed.
        resync_matching(data_dir, name, staged, bound)?;
        return Ok(true);
    }
    if current.as_deref() != original {
        return Err(invalid());
    }
    Ok(false)
}

fn check_installing(data_dir: &Path, name: &str, staged: &[u8], bound: usize) -> io::Result<()> {
    // Preserve partial or unrelated copies and refuse this nonce. A matching
    // leftover must be flushed again before any fixed destination can change.
    if let Some(existing) = read_optional_raw(data_dir, name, bound)? {
        if existing != staged {
            return Err(invalid());
        }
        resync_matching(data_dir, name, staged, bound)?;
    }
    Ok(())
}

fn install_staged(
    data_dir: &Path,
    name: &str,
    installing_name: &str,
    original: Option<&[u8]>,
    staged: &[u8],
    bound: usize,
) -> io::Result<()> {
    // Even a leftover installing copy must match; never reuse a nonce to hide
    // differing material. The canonical stage itself is never renamed away.
    check_installing(data_dir, installing_name, staged, bound)?;
    if check_destination(data_dir, name, original, staged, bound)? {
        return Ok(());
    }
    preserve_immutable(data_dir, installing_name, staged, bound)?;
    existing_private_directory(data_dir)?;
    // Handles above have closed before Windows rename. The caller's private ACL
    // and exclusive maintenance guard serialize path changes over this interval.
    std::fs::rename(data_dir.join(installing_name), data_dir.join(name))?;
    existing_private_directory(data_dir)?;
    resync_matching(data_dir, name, staged, bound)
}

/// Rebind only after the caller has verified the entire preserved archive with
/// this recovery key. The caller must keep its durable startup guard active and
/// serialize all key operations until post-rebind archive verification succeeds.
///
/// Backups, stages and the journal survive every outcome. Per-file renames do
/// not make the pair atomic; this function cannot safely run without that guard.
/// File sync/readback does not prove directory-entry durability through sudden
/// power loss. If the DPAPI profile changes again, existing staged envelopes may
/// be unreadable and the same nonce refuses rather than silently rewrapping them.
pub(super) fn rebind_after_verified_archive(
    data_dir: &Path,
    nonce: Uuid,
    archive_id: Uuid,
    key: &EvidenceKey,
) -> io::Result<LoadedKey> {
    (|| {
        if nonce.is_nil() || archive_id.is_nil() {
            return Err(invalid());
        }
        existing_private_directory(data_dir)?;
        let names = RebindNames::for_nonce(nonce);
        let recipient = key.recipient();
        let existing_journal = read_optional_raw(data_dir, &names.journal, MAX_CONFIRMATION_BYTES)?;
        let (journal, journal_bytes): (RebindJournal, Vec<u8>) = if let Some(bytes) =
            existing_journal
        {
            let journal = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            (journal, bytes)
        } else {
            // Preserve originals without attempting DPAPI unwrap: profile loss
            // is precisely why this operation may be needed. Missing originals
            // remain explicitly missing in the journal, never empty stand-ins.
            let original_bundle = read_optional_raw(data_dir, BUNDLE_NAME, MAX_BUNDLE_BYTES)?;
            let original_confirmation =
                read_optional_raw(data_dir, CONFIRMATION_NAME, MAX_CONFIRMATION_BYTES)?;
            preserve_optional(
                data_dir,
                &names.original_bundle,
                original_bundle.as_deref(),
                MAX_BUNDLE_BYTES,
            )?;
            preserve_optional(
                data_dir,
                &names.original_confirmation,
                original_confirmation.as_deref(),
                MAX_CONFIRMATION_BYTES,
            )?;

            let bundle = match read_optional_raw(data_dir, &names.staged_bundle, MAX_BUNDLE_BYTES)?
            {
                Some(bytes) => bytes,
                None => {
                    let candidate = Bundle {
                        version: 1,
                        archive_id,
                        local_key: key
                            .wrap_local(&WindowsEvidenceProtection)
                            .map_err(|_| invalid())?,
                        backup_confirmed: false,
                    };
                    let bytes = serde_json::to_vec(&candidate).map_err(|_| invalid())?;
                    preserve_immutable(data_dir, &names.staged_bundle, &bytes, MAX_BUNDLE_BYTES)?;
                    bytes
                }
            };
            let loaded = decode_bundle(&bundle)?;
            if loaded.archive_id != archive_id || loaded.recipient != recipient {
                return Err(invalid());
            }
            let confirmation = match read_optional_raw(
                data_dir,
                &names.staged_confirmation,
                MAX_CONFIRMATION_BYTES,
            )? {
                Some(bytes) => bytes,
                None => {
                    let candidate = Confirmation {
                        version: 1,
                        archive_id,
                        recipient: recipient.clone(),
                        bundle_sha256: digest(&bundle),
                        proof: key
                            .encrypt(archive_id, CONFIRMATION_PROOF)
                            .map_err(|_| invalid())?,
                    };
                    let bytes = serde_json::to_vec(&candidate).map_err(|_| invalid())?;
                    preserve_immutable(
                        data_dir,
                        &names.staged_confirmation,
                        &bytes,
                        MAX_CONFIRMATION_BYTES,
                    )?;
                    bytes
                }
            };
            validate_confirmation(&confirmation, &bundle, &loaded)?;
            let journal = RebindJournal {
                version: 1,
                nonce,
                archive_id,
                recipient: recipient.clone(),
                bundle_sha256: digest(&bundle),
                confirmation_sha256: digest(&confirmation),
                original_bundle_sha256: original_bundle.as_deref().map(digest),
                original_confirmation_sha256: original_confirmation.as_deref().map(digest),
            };
            let bytes = serde_json::to_vec(&journal).map_err(|_| invalid())?;
            // No fixed destination changes until both originals, both stages
            // and this binding journal have been synced and read back.
            preserve_immutable(data_dir, &names.journal, &bytes, MAX_CONFIRMATION_BYTES)?;
            (journal, bytes)
        };
        if journal.version != 1
            || journal.nonce != nonce
            || journal.archive_id != archive_id
            || journal.recipient != recipient
        {
            return Err(invalid());
        }
        let original_bundle = checked_original(
            data_dir,
            &names.original_bundle,
            journal.original_bundle_sha256,
            MAX_BUNDLE_BYTES,
        )?;
        let original_confirmation = checked_original(
            data_dir,
            &names.original_confirmation,
            journal.original_confirmation_sha256,
            MAX_CONFIRMATION_BYTES,
        )?;
        let bundle = read_optional_raw(data_dir, &names.staged_bundle, MAX_BUNDLE_BYTES)?
            .ok_or_else(invalid)?;
        let confirmation =
            read_optional_raw(data_dir, &names.staged_confirmation, MAX_CONFIRMATION_BYTES)?
                .ok_or_else(invalid)?;
        if digest(&bundle) != journal.bundle_sha256
            || digest(&confirmation) != journal.confirmation_sha256
        {
            return Err(invalid());
        }
        let staged_key = decode_bundle(&bundle)?;
        if staged_key.archive_id != archive_id || staged_key.recipient != recipient {
            return Err(invalid());
        }
        validate_confirmation(&confirmation, &bundle, &staged_key)?;
        // Re-flush all resume inputs, even when an earlier invocation already
        // created their complete bytes but did not finish syncing them. Original
        // backups were re-flushed by checked_original above. No replacement is
        // allowed until every required writable inspected handle has succeeded.
        resync_matching(data_dir, &names.staged_bundle, &bundle, MAX_BUNDLE_BYTES)?;
        resync_matching(
            data_dir,
            &names.staged_confirmation,
            &confirmation,
            MAX_CONFIRMATION_BYTES,
        )?;
        resync_matching(
            data_dir,
            &names.journal,
            &journal_bytes,
            MAX_CONFIRMATION_BYTES,
        )?;
        // Check both leftover installation copies before changing either fixed
        // destination: a partial second copy must not allow the first commit.
        check_installing(
            data_dir,
            &names.installing_bundle,
            &bundle,
            MAX_BUNDLE_BYTES,
        )?;
        check_installing(
            data_dir,
            &names.installing_confirmation,
            &confirmation,
            MAX_CONFIRMATION_BYTES,
        )?;
        // Validate both destinations before the first replacement. A retry may
        // see any original/staged pair, but unrelated bytes always refuse. Flush
        // destinations already holding staged bytes before either replacement.
        check_destination(
            data_dir,
            BUNDLE_NAME,
            original_bundle.as_deref(),
            &bundle,
            MAX_BUNDLE_BYTES,
        )?;
        check_destination(
            data_dir,
            CONFIRMATION_NAME,
            original_confirmation.as_deref(),
            &confirmation,
            MAX_CONFIRMATION_BYTES,
        )?;
        install_staged(
            data_dir,
            BUNDLE_NAME,
            &names.installing_bundle,
            original_bundle.as_deref(),
            &bundle,
            MAX_BUNDLE_BYTES,
        )?;
        install_staged(
            data_dir,
            CONFIRMATION_NAME,
            &names.installing_confirmation,
            original_confirmation.as_deref(),
            &confirmation,
            MAX_CONFIRMATION_BYTES,
        )?;
        let loaded = load(data_dir)?;
        if loaded.archive_id != archive_id
            || loaded.recipient != recipient
            || !loaded.backup_confirmed
        {
            return Err(invalid());
        }
        Ok(loaded)
    })()
    .map_err(private_error)
}
