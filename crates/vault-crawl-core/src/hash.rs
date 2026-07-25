//! Small cryptographic-hash helpers used by Phase 0 integrity proofs.

use sha2::{Digest, Sha256};

/// Returns the lowercase hexadecimal SHA-256 digest of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

/// Validates the canonical lowercase, 64-character SHA-256 representation.
#[must_use]
pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{is_sha256_hex, sha256_hex};

    #[test]
    fn hashes_and_validates_known_vector() {
        let digest = sha256_hex(b"abc");
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(is_sha256_hex(&digest));
        assert!(!is_sha256_hex(&digest.to_uppercase()));
        assert!(!is_sha256_hex("fixture"));
    }
}
