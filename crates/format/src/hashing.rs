// SPDX-License-Identifier: Apache-2.0
// src/hashing.rs — the platform's SHARED canonicalization primitive:
// strict JCS (RFC 8785). A single definition of "JSON → canonical bytes"
// for every producer and verifier, so the audit chain is auditable with
// exactly one canonicalization.
//
// Domain-level structuring (e.g. ordering facts/rules) is NOT
// canonicalization and does not live here; anything that needs it is
// built ON TOP of this primitive.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Error type of the canonicalization primitive.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalizationError {
    /// JCS serialization failed (e.g. a non-finite `f64`, which JSON
    /// cannot represent). Fail-loud: never a silent hash over input
    /// that cannot be canonicalized.
    #[error("JCS (RFC 8785) serialization failed: {0}")]
    Jcs(#[from] serde_json::Error),
}

/// JCS RFC 8785 canonical form of a serializable value: object keys
/// sorted by UTF-16 code units, no whitespace, numbers in ECMA-262
/// shortest round-trip form.
pub fn canonicalize<T: Serialize + ?Sized>(value: &T) -> Result<String, CanonicalizationError> {
    Ok(serde_jcs::to_string(value)?)
}

/// SHA-256 (lowercase hex, 64 chars via `format!("{:x}")`) of the JCS
/// canonical form.
pub fn canonical_hash<T: Serialize + ?Sized>(
    value: &T,
) -> Result<String, CanonicalizationError> {
    let canon = canonicalize(value)?;
    let mut hasher = Sha256::new();
    hasher.update(canon.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}
