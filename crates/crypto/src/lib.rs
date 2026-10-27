//! Experimental recoverable evidence keys. No persistence or activation here.
#![forbid(unsafe_code)]

use age::secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    io::{self, Read, Write},
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const MAX_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CIPHERTEXT_BYTES: usize = MAX_PLAINTEXT_BYTES + 65_536;
pub const MAX_WRAPPED_KEY_BYTES: usize = 16 * 1024;
const KEY_DOMAIN: &[u8] = b"piko.recoverable-key.age-x25519.v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"piko.evidence.age-x25519.v1\0";

fn refused() -> io::Error {
    // Never forward library errors containing user-supplied key material.
    io::Error::new(
        io::ErrorKind::InvalidData,
        "recoverable evidence key or envelope is invalid",
    )
}

/// Platform boundary protects only the local secret-key copy, not the evidence.
/// Implementations must not silently fall back to plaintext or a broader scope.
pub trait KeyProtector {
    fn protect_key(&self, plaintext: &[u8]) -> io::Result<Vec<u8>>;
    fn unprotect_key(&self, ciphertext: &[u8]) -> io::Result<Vec<u8>>;
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalKeyEnvelope {
    pub version: u16,
    pub recipient: String,
    pub wrapped_secret: Vec<u8>,
}
impl fmt::Debug for LocalKeyEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalKeyEnvelope")
            .field("version", &self.version)
            .field("recipient", &self.recipient)
            .finish_non_exhaustive()
    }
}

/// No Serialize/Display/Clone. The future explicit export flow owns disclosure.
pub struct RecoveryCode(age::secrecy::SecretString);
impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCode([REDACTED])")
    }
}
impl RecoveryCode {
    pub fn expose_for_backup(&self) -> &str {
        self.0.expose_secret()
    }
}

pub struct EvidenceKey(age::x25519::Identity);
impl fmt::Debug for EvidenceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EvidenceKey([REDACTED])")
    }
}

impl EvidenceKey {
    /// A candidate key; issuance alone never authorizes archive encryption.
    pub fn generate() -> (Self, RecoveryCode) {
        let identity = age::x25519::Identity::generate();
        let recovery = RecoveryCode(identity.to_string());
        (Self(identity), recovery)
    }

    pub fn recipient(&self) -> String {
        self.0.to_public().to_string()
    }
    pub fn recovery_code_for_authorized_backup(&self) -> RecoveryCode {
        RecoveryCode(self.0.to_string())
    }

    /// Import requires the expected public identity from the preserved archive.
    /// The borrowed code must be kept in a secret/zeroizing buffer by the caller.
    pub fn recover(code: &str, expected_recipient: &str) -> io::Result<Self> {
        if code.len() > 128
            || !code.is_ascii()
            || !code.starts_with("AGE-SECRET-KEY-1")
            || expected_recipient.len() > 128
        {
            return Err(refused());
        }
        let identity: age::x25519::Identity = code.parse().map_err(|_| refused())?;
        let key = Self(identity);
        if key.recipient() != expected_recipient {
            return Err(refused());
        }
        Ok(key)
    }

    pub fn wrap_local(&self, protector: &impl KeyProtector) -> io::Result<LocalKeyEnvelope> {
        let code = self.0.to_string();
        let mut plaintext = Zeroizing::new(Vec::with_capacity(KEY_DOMAIN.len() + 128));
        plaintext.extend_from_slice(KEY_DOMAIN);
        plaintext.extend_from_slice(code.expose_secret().as_bytes());
        let wrapped_secret = protector.protect_key(&plaintext).map_err(|_| refused())?;
        if wrapped_secret.is_empty() || wrapped_secret.len() > MAX_WRAPPED_KEY_BYTES {
            return Err(refused());
        }
        Ok(LocalKeyEnvelope {
            version: 1,
            recipient: self.recipient(),
            wrapped_secret,
        })
    }

    pub fn unwrap_local(
        envelope: &LocalKeyEnvelope,
        protector: &impl KeyProtector,
    ) -> io::Result<Self> {
        if envelope.version != 1
            || envelope.recipient.len() > 128
            || envelope.wrapped_secret.is_empty()
            || envelope.wrapped_secret.len() > MAX_WRAPPED_KEY_BYTES
        {
            return Err(refused());
        }
        let plaintext = Zeroizing::new(
            protector
                .unprotect_key(&envelope.wrapped_secret)
                .map_err(|_| refused())?,
        );
        if plaintext.len() > KEY_DOMAIN.len() + 128 || !plaintext.starts_with(KEY_DOMAIN) {
            return Err(refused());
        }
        let code = std::str::from_utf8(&plaintext[KEY_DOMAIN.len()..]).map_err(|_| refused())?;
        Self::recover(code, &envelope.recipient)
    }

    /// Rebind only after proof that the preserved archive belongs to this key.
    /// Does not overwrite the old key or rewrite any evidence.
    pub fn recover_and_wrap(
        code: &str,
        expected_recipient: &str,
        archive: Uuid,
        proof: &[u8],
        protector: &impl KeyProtector,
    ) -> io::Result<(Self, LocalKeyEnvelope)> {
        let key = Self::recover(code, expected_recipient)?;
        let _verified = key.decrypt(archive, proof)?;
        let local = key.wrap_local(protector)?;
        let rebound = Self::unwrap_local(&local, protector)?;
        let _rechecked = rebound.decrypt(archive, proof)?;
        Ok((key, local))
    }

    pub fn encrypt(&self, archive: Uuid, bytes: &[u8]) -> io::Result<Vec<u8>> {
        if archive.is_nil() || bytes.len() > MAX_PLAINTEXT_BYTES {
            return Err(refused());
        }
        let recipient = self.0.to_public();
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .map_err(|_| refused())?;
        let mut writer = encryptor.wrap_output(Vec::new()).map_err(|_| refused())?;
        writer.write_all(EVIDENCE_DOMAIN)?;
        writer.write_all(archive.as_bytes())?;
        writer.write_all(bytes)?;
        let ciphertext = writer.finish().map_err(|_| refused())?;
        if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(refused());
        }
        Ok(ciphertext)
    }

    pub fn decrypt(&self, archive: Uuid, bytes: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        if archive.is_nil() || bytes.is_empty() || bytes.len() > MAX_CIPHERTEXT_BYTES {
            return Err(refused());
        }
        let decryptor = age::Decryptor::new_buffered(bytes).map_err(|_| refused())?;
        // Recovery accepts X25519 only: never run attacker-supplied passphrase KDFs.
        if decryptor.is_scrypt() {
            return Err(refused());
        }
        let reader = decryptor
            .decrypt(std::iter::once(&self.0 as &dyn age::Identity))
            .map_err(|_| refused())?;
        let header = EVIDENCE_DOMAIN.len() + 16;
        // Fixed upper allocation avoids leaving old plaintext allocations behind
        // if Vec grows during streaming. One extra byte detects an oversized body.
        // age does not compress: decoded bytes cannot exceed ciphertext length.
        // Small owner/backup probes therefore do not allocate a full 4 MiB.
        let decoded_limit = bytes.len().min(MAX_PLAINTEXT_BYTES + header);
        let mut plaintext = Zeroizing::new(Vec::with_capacity(decoded_limit + 2));
        reader
            .take((decoded_limit + 1) as u64)
            .read_to_end(&mut plaintext)
            .map_err(|_| refused())?;
        if plaintext.len() < header
            || plaintext.len() > decoded_limit
            || !plaintext.starts_with(EVIDENCE_DOMAIN)
            || &plaintext[EVIDENCE_DOMAIN.len()..header] != archive.as_bytes()
        {
            return Err(refused());
        }
        // read_to_end above consumes the authenticated final chunk before release.
        let payload = Zeroizing::new(plaintext[header..].to_vec());
        Ok(payload)
    }
}
