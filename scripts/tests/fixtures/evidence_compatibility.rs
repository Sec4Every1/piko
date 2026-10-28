//! Run only in isolated source snapshots; all generated keys/data are synthetic.
//! Copy to crates/crypto/examples/evidence_compatibility.rs in each snapshot,
//! then run `cargo run -p piko-crypto --example evidence_compatibility --
//! generate <new-directory>` and `... verify <other-version-directory>`.
//! Keep fixture directories under ignored .build; never use real evidence/keys.
use piko_crypto::{EvidenceKey, KeyProtector, LocalKeyEnvelope, MAX_PLAINTEXT_BYTES};
use std::{error::Error, fs, io, path::Path};
use uuid::Uuid;

const ARCHIVE: Uuid = Uuid::from_u128(0x70696b6f);
const LENGTHS: [usize; 8] = [
    0,
    1,
    31,
    65_493,
    65_535,
    65_536,
    70_000,
    MAX_PLAINTEXT_BYTES,
];

// Deliberately fake: tests serialized wrapping bytes, never Windows DPAPI.
struct SyntheticProtector;
impl KeyProtector for SyntheticProtector {
    fn protect_key(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        Ok(bytes.iter().map(|byte| byte ^ 0x5a).collect())
    }
    fn unprotect_key(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        self.protect_key(bytes)
    }
}

fn payload(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}

fn generate(directory: &Path) -> Result<(), Box<dyn Error>> {
    // Refuse existing destinations, including partial earlier runs.
    fs::create_dir(directory)?;
    let (key, code) = EvidenceKey::generate();
    let envelope = key.wrap_local(&SyntheticProtector)?;
    fs::write(
        directory.join("SYNTHETIC-ONLY.txt"),
        "Generated interoperability fixtures; never production keys.\n",
    )?;
    fs::write(directory.join("recovery.txt"), code.expose_for_backup())?;
    fs::write(directory.join("recipient.txt"), key.recipient())?;
    fs::write(directory.join("wrapped.bin"), envelope.wrapped_secret)?;
    for length in LENGTHS {
        fs::write(
            directory.join(format!("{length}.age")),
            key.encrypt(ARCHIVE, &payload(length))?,
        )?;
    }
    println!("Generated 8 synthetic envelopes and one local/recovery key fixture");
    Ok(())
}

fn verify(directory: &Path) -> Result<(), Box<dyn Error>> {
    let code = fs::read_to_string(directory.join("recovery.txt"))?;
    let recipient = fs::read_to_string(directory.join("recipient.txt"))?;
    let key = EvidenceKey::recover(&code, &recipient)?;
    let wrapped = LocalKeyEnvelope {
        version: 1,
        recipient: recipient.clone(),
        wrapped_secret: fs::read(directory.join("wrapped.bin"))?,
    };
    let local_key = EvidenceKey::unwrap_local(&wrapped, &SyntheticProtector)?;
    let (wrong_key, _) = EvidenceKey::generate();
    assert!(EvidenceKey::recover(&code, &wrong_key.recipient()).is_err());
    for length in LENGTHS {
        let ciphertext = fs::read(directory.join(format!("{length}.age")))?;
        let expected = payload(length);
        assert_eq!(&**key.decrypt(ARCHIVE, &ciphertext)?, &expected);
        assert_eq!(&**local_key.decrypt(ARCHIVE, &ciphertext)?, &expected);
        assert!(key.decrypt(Uuid::from_u128(1), &ciphertext).is_err());
        assert!(wrong_key.decrypt(ARCHIVE, &ciphertext).is_err());
        let (recovered, rebound) = EvidenceKey::recover_and_wrap(
            &code,
            &recipient,
            ARCHIVE,
            &ciphertext,
            &SyntheticProtector,
        )?;
        assert_eq!(recovered.recipient(), recipient);
        assert_eq!(
            EvidenceKey::unwrap_local(&rebound, &SyntheticProtector)?.recipient(),
            recipient
        );
        for index in [0, ciphertext.len() / 2, ciphertext.len() - 1] {
            let mut corrupt = ciphertext.clone();
            corrupt[index] ^= 1;
            assert!(key.decrypt(ARCHIVE, &corrupt).is_err());
        }
        for end in [0, 1, ciphertext.len() / 2, ciphertext.len() - 1] {
            assert!(key.decrypt(ARCHIVE, &ciphertext[..end]).is_err());
        }
    }
    println!("Verified 8 cross-version envelopes: payloads, keys, recovery, archive binding, tampering and truncation");
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err("expected generate|verify and an isolated fixture directory".into());
    }
    if args[1] == "generate" {
        generate(Path::new(&args[2]))
    } else if args[1] == "verify" {
        verify(Path::new(&args[2]))
    } else {
        Err("unknown fixture operation".into())
    }
}
