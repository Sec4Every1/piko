//! Versioned envelope; cryptographic operations belong to the platform adapter.
use crate::{StorageConfig, StorageError};

pub trait EvidenceProtection: std::fmt::Debug + Send + Sync {
    fn scheme(&self) -> &'static str {
        "dpapi-user-v1"
    }
    fn key_identity(&self) -> Option<String> {
        None
    }
    fn validate_new_writes(&self) -> std::io::Result<()> {
        Ok(())
    }
    fn protect(&self, bytes: &[u8]) -> std::io::Result<Vec<u8>>;
    fn unprotect(&self, bytes: &[u8]) -> std::io::Result<Vec<u8>>;
}

pub(crate) const MAGIC: &[u8; 8] = b"PIKOENC\x01";
pub(crate) const PREFIX: &[u8; 7] = b"PIKOENC";
const RECOVERABLE_MAGIC: &[u8; 8] = b"PIKOENC\x02";
const DOMAIN: &[u8] = b"piko.raw.evidence.user-dpapi.v1\0";
const MAX_ENCODED: usize = 4 * 1024 * 1024;
const PROBE: &[u8] = b"piko.raw.evidence.owner-probe.v1\0";
pub const MAX_STORED_EVIDENCE_BYTES: usize = MAX_ENCODED + 65_536 + 12;

pub(crate) fn is_protected(bytes: &[u8]) -> bool {
    bytes.starts_with(PREFIX)
}

pub(crate) fn create_owner_probe(config: &StorageConfig) -> Result<String, StorageError> {
    let provider = config
        .evidence_protection
        .as_ref()
        .ok_or(StorageError::Configuration)?;
    let bytes = provider.protect(PROBE).map_err(|_| {
        StorageError::ProtectionPolicy("cannot establish evidence protection identity".into())
    })?;
    if bytes.is_empty() || bytes.len() > 65_536 {
        return Err(StorageError::Configuration);
    }
    Ok(crate::hex(&bytes))
}

pub(crate) fn verify_owner_probe(value: &str, config: &StorageConfig) -> Result<(), StorageError> {
    let invalid = || {
        StorageError::ProtectionPolicy(
            "original evidence key is required; owner probe unavailable or invalid".into(),
        )
    };
    if value.is_empty()
        || value.len() > 131_072
        || !value.len().is_multiple_of(2)
        || !value.is_ascii()
    {
        return Err(invalid());
    }
    let bytes: Vec<u8> = (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|_| invalid()))
        .collect::<Result<_, _>>()?;
    let provider = config.evidence_protection.as_ref().ok_or_else(invalid)?;
    let plaintext = provider.unprotect(&bytes).map_err(|_| invalid())?;
    if plaintext != PROBE {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn seal(encoded: Vec<u8>, config: &StorageConfig) -> Result<Vec<u8>, StorageError> {
    if !config.protect_new_evidence {
        return Ok(encoded);
    }
    let provider = config
        .evidence_protection
        .as_ref()
        .ok_or(StorageError::Configuration)?;
    if encoded.len() > MAX_ENCODED {
        return Err(StorageError::InvalidRawEvidence);
    }
    let mut plaintext = Vec::with_capacity(DOMAIN.len() + encoded.len());
    let magic = match provider.scheme() {
        "dpapi-user-v1" => {
            plaintext.extend_from_slice(DOMAIN);
            MAGIC
        }
        "age-x25519-v1" => RECOVERABLE_MAGIC,
        _ => {
            return Err(StorageError::ProtectionPolicy(
                "unsupported evidence provider".into(),
            ))
        }
    };
    plaintext.extend_from_slice(&encoded);
    let ciphertext = provider.protect(&plaintext).map_err(|_| {
        StorageError::ProtectionPolicy(
            "Windows evidence protection failed; plaintext storage is refused".into(),
        )
    })?;
    if ciphertext.is_empty() || ciphertext.len() > MAX_STORED_EVIDENCE_BYTES - 12 {
        return Err(StorageError::InvalidRawEvidence);
    }
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(magic);
    result.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub(crate) fn open(bytes: &[u8], config: &StorageConfig) -> Result<Vec<u8>, StorageError> {
    let invalid = || StorageError::Corrupt("invalid protected evidence envelope".into());
    if bytes.len() <= 12 || bytes.len() > MAX_STORED_EVIDENCE_BYTES || !is_protected(bytes) {
        return Err(invalid());
    }
    let expected = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| invalid())?) as usize;
    if expected == 0 || expected > MAX_ENCODED {
        return Err(invalid());
    }
    let provider = config.evidence_protection.as_ref().ok_or_else(|| {
        StorageError::ProtectionPolicy(
            "protected evidence requires its runtime identity and protection provider".into(),
        )
    })?;
    let domain = if bytes.starts_with(MAGIC) && provider.scheme() == "dpapi-user-v1" {
        DOMAIN
    } else if bytes.starts_with(RECOVERABLE_MAGIC) && provider.scheme() == "age-x25519-v1" {
        &[][..]
    } else {
        return Err(StorageError::ProtectionPolicy(
            "evidence envelope/provider mismatch; automatic migration is refused".into(),
        ));
    };
    let plaintext = provider.unprotect(&bytes[12..]).map_err(|_| StorageError::ProtectionPolicy("cannot decrypt protected evidence; runtime identity, key availability or ciphertext integrity must be checked".into()))?;
    if plaintext.len() != domain.len() + expected || !plaintext.starts_with(domain) {
        return Err(invalid());
    }
    Ok(plaintext[domain.len()..].to_vec())
}
