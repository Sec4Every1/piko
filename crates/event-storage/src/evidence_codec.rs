//! Bounded, lossless storage encoding. Digests always cover the original JSON.
use crate::StorageError;
use flate2::{bufread::GzDecoder, write::GzEncoder, Compression};
use std::io::{Read, Write};
const MAGIC: &[u8; 7] = b"PIKOEV\x01";
const HEADER: usize = 11;
const MAX_BYTES: usize = 4 * 1024 * 1024;

pub fn encode_stored(bytes: &[u8], config: &crate::StorageConfig) -> Result<Vec<u8>, StorageError> {
    crate::protected_evidence::seal(encode(bytes)?, config)
}

pub fn decode_stored(bytes: &[u8], config: &crate::StorageConfig) -> Result<Vec<u8>, StorageError> {
    if crate::protected_evidence::is_protected(bytes) {
        decode(&crate::protected_evidence::open(bytes, config)?)
    } else {
        decode(bytes)
    }
}

pub fn encode(bytes: &[u8]) -> Result<Vec<u8>, StorageError> {
    if bytes.len() > MAX_BYTES {
        return Err(StorageError::InvalidRawEvidence);
    }
    if bytes.len() < 512 {
        return Ok(bytes.to_vec());
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes)?;
    let compressed = encoder.finish()?;
    if compressed.len() + HEADER + 64 >= bytes.len() {
        return Ok(bytes.to_vec());
    }
    let mut stored = Vec::with_capacity(HEADER + compressed.len());
    stored.extend_from_slice(MAGIC);
    stored.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    stored.extend(compressed);
    Ok(stored)
}

pub fn decode(bytes: &[u8]) -> Result<Vec<u8>, StorageError> {
    let invalid = || StorageError::Corrupt("invalid or oversized evidence encoding".into());
    if bytes.len() > MAX_BYTES {
        return Err(invalid());
    }
    if !bytes.starts_with(MAGIC) {
        // Previously written serde JSON has no leading whitespace.
        return if bytes.first() == Some(&b'{') {
            Ok(bytes.to_vec())
        } else {
            Err(invalid())
        };
    }
    if bytes.len() <= HEADER {
        return Err(invalid());
    }
    let length = u32::from_le_bytes(bytes[7..11].try_into().map_err(|_| invalid())?) as usize;
    if length == 0 || length > MAX_BYTES {
        return Err(invalid());
    }
    let mut decoder = GzDecoder::new(&bytes[HEADER..]);
    let mut decoded = Vec::with_capacity(length.min(64 * 1024));
    (&mut decoder)
        .take(length as u64 + 1)
        .read_to_end(&mut decoded)
        .map_err(|_| invalid())?;
    if decoded.len() != length || !decoder.into_inner().is_empty() {
        return Err(invalid());
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_legacy_and_compressed_and_reject_tampering_or_bombs() {
        assert_eq!(decode(br#"{"old":true}"#).unwrap(), br#"{"old":true}"#);
        let raw = format!("{{\"bytes\":\"{}\"}}", "repeated XML field ".repeat(4096));
        let encoded = encode(raw.as_bytes()).unwrap();
        assert!(encoded.len() < raw.len() / 4);
        assert_eq!(decode(&encoded).unwrap(), raw.as_bytes());
        for end in [0, 7, 10, encoded.len() - 1] {
            assert!(decode(&encoded[..end]).is_err());
        }
        let mut damaged = encoded.clone();
        let last = damaged.len() - 5;
        damaged[last] ^= 1;
        assert!(decode(&damaged).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        let mut oversized = encoded.clone();
        oversized[7..11].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&oversized).is_err());
        let mut lying = encoded;
        lying[7..11].copy_from_slice(&10u32.to_le_bytes());
        assert!(decode(&lying).is_err());
    }
}
