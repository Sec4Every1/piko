//! Receipt validation executes production code with synthetic keys only.
use super::*;
use std::error::Error;

struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!("piko-key-artifact-test-{}", Uuid::new_v4()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn preserved_artifact_retries_require_exact_bytes_and_never_overwrite() -> Result<(), Box<dyn Error>>
{
    let directory = Directory::new()?;
    let bytes = b"synthetic preserved original";
    preserve_immutable(&directory.0, "original.bin", bytes, 64)?;
    preserve_immutable(&directory.0, "original.bin", bytes, 64)?;
    assert!(preserve_immutable(&directory.0, "original.bin", b"different", 64).is_err());
    assert_eq!(std::fs::read(directory.0.join("original.bin"))?, bytes);
    assert!(checked_original(&directory.0, "original.bin", Some(digest(b"wrong")), 64).is_err());
    assert_eq!(
        checked_original(&directory.0, "original.bin", Some(digest(bytes)), 64)?,
        Some(bytes.to_vec())
    );
    assert_eq!(std::fs::read(directory.0.join("original.bin"))?, bytes);
    Ok(())
}

#[test]
fn empty_originals_and_partial_installation_residue_remain_distinct_and_preserved(
) -> Result<(), Box<dyn Error>> {
    let directory = Directory::new()?;
    assert!(read_optional_raw(&directory.0, "original.bin", 64)?.is_none());
    preserve_optional(&directory.0, "original.bin", Some(b""), 64)?;
    assert_eq!(
        read_optional_raw(&directory.0, "original.bin", 64)?,
        Some(Vec::new())
    );
    assert!(preserve_optional(&directory.0, "original.bin", None, 64).is_err());
    assert_eq!(
        checked_original(&directory.0, "original.bin", Some(digest(b"")), 64)?,
        Some(Vec::new())
    );

    let residue = directory.0.join("installing.bin");
    std::fs::write(&residue, b"partial")?;
    assert!(check_installing(&directory.0, "installing.bin", b"complete", 64).is_err());
    assert_eq!(std::fs::read(residue)?, b"partial");
    Ok(())
}

#[test]
fn backup_receipt_binds_exact_bundle_archive_recipient_and_proof() -> Result<(), Box<dyn Error>> {
    let (key, _) = EvidenceKey::generate();
    let loaded = LoadedKey {
        archive_id: Uuid::from_u128(1),
        recipient: key.recipient(),
        key: Arc::new(key),
        backup_confirmed: false,
    };
    let bundle = b"synthetic wrapped bundle commitment";
    let receipt = || -> io::Result<Confirmation> {
        Ok(Confirmation {
            version: 1,
            archive_id: loaded.archive_id,
            recipient: loaded.recipient.clone(),
            bundle_sha256: Sha256::digest(bundle).into(),
            proof: loaded.key.encrypt(loaded.archive_id, CONFIRMATION_PROOF)?,
        })
    };
    assert!(validate_confirmation(&serde_json::to_vec(&receipt()?)?, bundle, &loaded).is_ok());
    for fault in 0..7 {
        let mut altered = receipt()?;
        match fault {
            0 => altered.version = 2,
            1 => altered.archive_id = Uuid::from_u128(2),
            2 => altered.recipient = EvidenceKey::generate().0.recipient(),
            3 => altered.bundle_sha256[0] ^= 1,
            4 => {
                altered.proof = loaded
                    .key
                    .encrypt(loaded.archive_id, b"different proof purpose")?
            }
            5 => {
                altered.proof.pop();
            }
            _ => altered.proof = vec![0; MAX_CONFIRMATION_BYTES + 1],
        }
        assert!(validate_confirmation(&serde_json::to_vec(&altered)?, bundle, &loaded).is_err());
    }
    let bytes = serde_json::to_vec(&receipt()?)?;
    assert!(validate_confirmation(&bytes, b"changed wrapped bundle", &loaded).is_err());
    let mut injected = serde_json::to_value(receipt()?)?;
    injected
        .as_object_mut()
        .ok_or("receipt must be an object")?
        .insert("activate".into(), true.into());
    assert!(validate_confirmation(&serde_json::to_vec(&injected)?, bundle, &loaded).is_err());
    Ok(())
}
