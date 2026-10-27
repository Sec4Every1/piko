//! Real age operations; the local wrapping adapter is deliberately fake.
use piko_crypto::{
    EvidenceKey, KeyProtector, MAX_CIPHERTEXT_BYTES, MAX_PLAINTEXT_BYTES, MAX_WRAPPED_KEY_BYTES,
};
use std::{cell::Cell, error::Error, io};
use uuid::Uuid;

type TestResult = Result<(), Box<dyn Error>>;
const ARCHIVE: Uuid = Uuid::from_u128(1);
const OTHER_ARCHIVE: Uuid = Uuid::from_u128(2);

#[derive(Default)]
struct FakeProtector {
    protects: Cell<usize>,
    fail_protect: Cell<bool>,
    fail_unprotect: Cell<bool>,
    output_length: Cell<Option<usize>>,
}

impl KeyProtector for FakeProtector {
    fn protect_key(&self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        self.protects.set(self.protects.get() + 1);
        if self.fail_protect.get() {
            return Err(io::Error::other("sensitive adapter failure"));
        }
        Ok(match self.output_length.get() {
            Some(length) => vec![0; length],
            None => plaintext.to_vec(),
        })
    }

    fn unprotect_key(&self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        if self.fail_unprotect.get() {
            return Err(io::Error::other("sensitive adapter failure"));
        }
        Ok(ciphertext.to_vec())
    }
}

#[test]
fn authenticated_evidence_is_bound_to_the_archive_and_key() -> TestResult {
    let (key, _) = EvidenceKey::generate();
    let (other, _) = EvidenceKey::generate();
    let encrypted = key.encrypt(ARCHIVE, b"synthetic evidence")?;
    assert_eq!(&**key.decrypt(ARCHIVE, &encrypted)?, b"synthetic evidence");
    assert!(key.decrypt(OTHER_ARCHIVE, &encrypted).is_err());
    assert!(other.decrypt(ARCHIVE, &encrypted).is_err());
    Ok(())
}

#[test]
fn authenticated_evidence_rejects_tampering_and_truncated_final_chunks() -> TestResult {
    let (key, _) = EvidenceKey::generate();
    let ciphertext = key.encrypt(ARCHIVE, &vec![42; 70_000])?;
    for offset in [0, ciphertext.len() / 2, ciphertext.len() - 1] {
        let mut corrupt = ciphertext.clone();
        corrupt[offset] ^= 1;
        assert!(key.decrypt(ARCHIVE, &corrupt).is_err());
    }
    for length in [0, 1, ciphertext.len() / 2, ciphertext.len() - 1] {
        assert!(key.decrypt(ARCHIVE, &ciphertext[..length]).is_err());
    }
    Ok(())
}

#[test]
fn recovery_requires_the_expected_public_identity() -> TestResult {
    let (key, code) = EvidenceKey::generate();
    let (other, _) = EvidenceKey::generate();
    assert_eq!(
        EvidenceKey::recover(code.expose_for_backup(), &key.recipient())?.recipient(),
        key.recipient()
    );
    assert!(EvidenceKey::recover(code.expose_for_backup(), &other.recipient()).is_err());
    for invalid in [
        String::new(),
        "AGE-SECRET-KEY-1invalid".into(),
        "x".repeat(129),
        "\u{00e9}".into(),
    ] {
        assert!(EvidenceKey::recover(&invalid, &key.recipient()).is_err());
    }
    assert!(EvidenceKey::recover(code.expose_for_backup(), &"x".repeat(129)).is_err());
    Ok(())
}

#[test]
fn local_wrapping_checks_domain_version_identity_and_provider_failures() -> TestResult {
    let (key, _) = EvidenceKey::generate();
    let (other, _) = EvidenceKey::generate();
    let protector = FakeProtector::default();
    let envelope = key.wrap_local(&protector)?;
    assert_eq!(
        EvidenceKey::unwrap_local(&envelope, &protector)?.recipient(),
        key.recipient()
    );
    let mut invalid = envelope.clone();
    invalid.version = 2;
    assert!(EvidenceKey::unwrap_local(&invalid, &protector).is_err());
    invalid = envelope.clone();
    invalid.recipient = other.recipient();
    assert!(EvidenceKey::unwrap_local(&invalid, &protector).is_err());
    invalid = envelope.clone();
    invalid.wrapped_secret[0] ^= 1;
    assert!(EvidenceKey::unwrap_local(&invalid, &protector).is_err());
    invalid = envelope.clone();
    invalid.wrapped_secret.pop();
    assert!(EvidenceKey::unwrap_local(&invalid, &protector).is_err());
    protector.fail_unprotect.set(true);
    let error = EvidenceKey::unwrap_local(&envelope, &protector)
        .err()
        .ok_or("provider failure unexpectedly succeeded")?;
    assert!(!error.to_string().contains("sensitive adapter"));
    protector.fail_protect.set(true);
    assert!(key.wrap_local(&protector).is_err());
    Ok(())
}

#[test]
fn failed_recovery_proof_never_calls_local_protection() -> TestResult {
    let (key, code) = EvidenceKey::generate();
    let (other, _) = EvidenceKey::generate();
    let proof = key.encrypt(ARCHIVE, b"owner proof")?;
    let mut corrupt = proof.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    let protector = FakeProtector::default();
    for (recipient, archive, bytes) in [
        (other.recipient(), ARCHIVE, proof.as_slice()),
        (key.recipient(), OTHER_ARCHIVE, proof.as_slice()),
        (key.recipient(), ARCHIVE, corrupt.as_slice()),
        (key.recipient(), ARCHIVE, &[][..]),
    ] {
        assert!(EvidenceKey::recover_and_wrap(
            code.expose_for_backup(),
            &recipient,
            archive,
            bytes,
            &protector
        )
        .is_err());
        assert_eq!(protector.protects.get(), 0);
    }
    Ok(())
}

#[test]
fn successful_recovery_rebinds_only_after_verifiable_proof() -> TestResult {
    let (key, code) = EvidenceKey::generate();
    let proof = key.encrypt(ARCHIVE, b"preserved archive proof")?;
    let protector = FakeProtector::default();
    let (recovered, envelope) = EvidenceKey::recover_and_wrap(
        code.expose_for_backup(),
        &key.recipient(),
        ARCHIVE,
        &proof,
        &protector,
    )?;
    assert_eq!(protector.protects.get(), 1);
    assert_eq!(recovered.recipient(), key.recipient());
    let rebound = EvidenceKey::unwrap_local(&envelope, &protector)?;
    assert_eq!(
        &**rebound.decrypt(ARCHIVE, &proof)?,
        b"preserved archive proof"
    );
    let next = rebound.encrypt(ARCHIVE, b"new synthetic evidence")?;
    assert_eq!(&**key.decrypt(ARCHIVE, &next)?, b"new synthetic evidence");
    Ok(())
}

#[test]
fn evidence_and_wrapped_key_bounds_refuse_oversized_or_empty_envelopes() -> TestResult {
    let (key, _) = EvidenceKey::generate();
    assert!(key.encrypt(Uuid::nil(), b"evidence").is_err());
    assert!(key
        .encrypt(ARCHIVE, &vec![0; MAX_PLAINTEXT_BYTES + 1])
        .is_err());
    assert!(key
        .decrypt(ARCHIVE, &vec![0; MAX_CIPHERTEXT_BYTES + 1])
        .is_err());
    let empty = key.encrypt(ARCHIVE, b"")?;
    assert!(key.decrypt(ARCHIVE, &empty)?.is_empty());
    assert!(key.decrypt(Uuid::nil(), &empty).is_err());
    let protector = FakeProtector::default();
    let envelope = key.wrap_local(&protector)?;
    for length in [0, MAX_WRAPPED_KEY_BYTES + 1] {
        protector.output_length.set(Some(length));
        assert!(key.wrap_local(&protector).is_err());
        let mut invalid = envelope.clone();
        invalid.wrapped_secret = vec![0; length];
        assert!(EvidenceKey::unwrap_local(&invalid, &protector).is_err());
    }
    let mut invalid = envelope;
    invalid.recipient = "x".repeat(129);
    assert!(EvidenceKey::unwrap_local(&invalid, &protector).is_err());
    Ok(())
}

#[test]
fn debug_output_redacts_secret_keys_and_wrapped_bytes() -> TestResult {
    let (key, code) = EvidenceKey::generate();
    let envelope = key.wrap_local(&FakeProtector::default())?;
    let debug = format!("{key:?} {code:?} {envelope:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(code.expose_for_backup()));
    assert!(!debug.contains("AGE-SECRET-KEY-1"));
    assert!(!debug.contains("wrapped_secret"));
    assert!(debug.contains(&key.recipient()));
    let authorized = key.recovery_code_for_authorized_backup();
    assert!(authorized.expose_for_backup() == code.expose_for_backup());
    Ok(())
}
