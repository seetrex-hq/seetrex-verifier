// SPDX-License-Identifier: Apache-2.0
//! `sha256_hex` — the one raw-bytes → lowercase-hex SHA-256 primitive of
//! the pure verification core.
//!
//! Distinct from [`crate::evidence::canonicalize`]: that routine first
//! canonicalizes a `Serialize` payload through the shared JCS RFC 8785
//! primitive and hashes the canonical bytes. `sha256_hex` hashes the bytes
//! it is given VERBATIM — no canonicalization. That is exactly the
//! evidence-integrity semantics of the package format (§5 of
//! `docs/SPEC_VERDICT_PACKAGE_V1.md`): the evidence `content_hash` covers
//! the STORED bytes of `canonical_inline`, and re-canonicalizing them at
//! verification time would mask non-canonical storage.
//!
//! Single source of truth: both [`crate::package::verify_package`] (step
//! 3) and `compliance-cli replay --full`'s inline evidence-hash site use
//! this function, so the two paths hash byte-for-byte identically.

use sha2::{Digest, Sha256};

/// SHA-256 of `bytes`, encoded as 64 lowercase hex characters.
///
/// Pure and deterministic: the same input always yields the same output.
/// The bytes are hashed verbatim — the caller is responsible for having
/// already produced the exact byte string it means to commit to.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_vector() {
        // NIST FIPS 180-4 example: SHA-256("abc").
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_hex_empty_input() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hex_is_lowercase_hex_64_chars() {
        let h = sha256_hex(b"some evidence payload bytes");
        assert_eq!(h.len(), 64);
        assert!(h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }

    /// The whole point of the helper: it hashes bytes VERBATIM, so a
    /// trailing-space tamper of the stored payload changes the digest
    /// (the property that lets step 3 detect non-canonical / tampered
    /// storage without re-canonicalizing).
    #[test]
    fn sha256_hex_is_byte_sensitive() {
        assert_ne!(sha256_hex(b"payload"), sha256_hex(b"payload "));
    }
}
