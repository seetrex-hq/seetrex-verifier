// SPDX-License-Identifier: Apache-2.0
//! Evidence content-hash canonicalization — the pure `canonicalize`
//! primitive extracted from `compliance::evidence::canonical`.
//!
//! `canonicalize` produces `(canonical_string, sha256_hex)` for any
//! `Serialize` payload, routing its canonical-string production through the
//! shared platform JCS RFC 8785 primitive
//! (`seetrex_format::hashing::canonicalize` — moved there VERBATIM from the
//! engine crate; the engine re-exports it on its historical path) so there
//! is exactly ONE definition of "JSON → canonical bytes" across the
//! platform. The convergence on that primitive is asserted by the
//! compliance intent test
//! `test_intent_evidence_canonicalization_uses_shared_motor_primitive`,
//! which greps THIS file's source for the import below — do NOT re-inline
//! `serde_jcs::to_string` here.
//!
//! The routing/size-cap policy (`CanonicalPayload::try_inline`,
//! `INLINE_MAX_BYTES`, the per-category caps) and the DB-coupled
//! `EvidenceError` stay in `compliance::evidence`; this crate carries only
//! the pure hashing step and its own small error type.

use serde::Serialize;
use seetrex_format::hashing::{
    canonicalize as motor_canonicalize, CanonicalizationError as MotorCanonicalizationError,
};
use sha2::{Digest, Sha256};

/// Error from [`canonicalize`]. Pure by construction — the only failure is
/// a JCS/serde canonicalization error. `compliance::evidence` maps this
/// into its own DB-entangled `EvidenceError::CanonicalizationFailed` so the
/// existing PII-redaction `Display` discipline and call sites are preserved
/// unchanged.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceCanonicalError {
    /// `serde_jcs` (via the shared platform primitive) failed to canonicalize
    /// the payload. The underlying `serde_json::Error` is carried as
    /// `#[source]`; the `Display` is intentionally short (its message can
    /// echo input fragments, which for PII-carrying payloads must not
    /// surface through logs/API responses).
    #[error("canonicalization failed (cause hidden — payload may carry PII)")]
    CanonicalizationFailed {
        #[source]
        source: serde_json::Error,
    },
}

/// Canonicalize `payload` to JCS RFC 8785 and return
/// `(canonical_string, sha256_hex_lowercase)`.
///
/// The hash is SHA-256 of the canonical UTF-8 bytes, hex lowercase
/// 64 chars. **Never fails on payload size** — routing inline vs
/// blob_ref is the caller's responsibility via the
/// `CanonicalPayload::try_inline` / `blob_ref` constructors (which live in
/// `compliance::evidence`).
///
/// Determinism: any two payloads that serialize to the same JCS
/// canonical produce the same hash; this is what powers the
/// reproducibility property of the Evidence chain.
pub fn canonicalize<T: Serialize>(payload: &T) -> Result<(String, String), EvidenceCanonicalError> {
    // Route through the shared platform primitive (JCS RFC 8785) instead
    // of calling `serde_jcs::to_string` directly. Same algorithm, same
    // bytes → evidence hashes unchanged; one canonicalization definition
    // for the whole platform. The primitive's error wraps the same
    // `serde_json::Error`, mapped into `EvidenceCanonicalError`.
    let canonical = motor_canonicalize(payload).map_err(|e| match e {
        MotorCanonicalizationError::Jcs(source) => {
            EvidenceCanonicalError::CanonicalizationFailed { source }
        }
    })?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    Ok((canonical, hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Stable across key order: two payloads that differ only in key
    /// order produce the same content hash.
    #[test]
    fn canonicalize_is_stable_across_keys_order() {
        let a = json!({"alpha": 1, "beta": 2, "gamma": 3});
        let b = json!({"gamma": 3, "beta": 2, "alpha": 1});
        let (_, hash_a) = canonicalize(&a).unwrap();
        let (_, hash_b) = canonicalize(&b).unwrap();
        assert_eq!(hash_a, hash_b);
    }

    /// The hash is always lowercase hex, exactly 64 chars.
    #[test]
    fn canonicalize_produces_lowercase_hex_hash_64_chars() {
        let (_, hash) = canonicalize(&json!({"x": 1})).unwrap();
        assert_eq!(hash.len(), 64, "SHA-256 hex length");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "all chars must be lowercase hex"
        );
    }
}
