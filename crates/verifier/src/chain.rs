// SPDX-License-Identifier: Apache-2.0
//! Audit-chain link primitive — the pure hash that chains one verdict to
//! the previous one in a tenant's append-only `compliance_audit_chain`.
//!
//! Extracted from `compliance::persistence::audit_chain` (the DB-coupled
//! append path stays there and re-exports this function). An auditor
//! walking the public chain from the tail recomputes, for each row,
//! `chain_hash[N] == compute_chain_hash(chain_hash[N-1], verdict_hash[N])`
//! — end-to-end cryptographic integrity with no database access.

use sha2::{Digest, Sha256};

/// Computes the `chain_hash` linking a verdict into the append-only
/// audit chain.
///
/// **Genesis case** (`prev = None`): `chain_hash = SHA256(verdict_hash_bytes)`.
/// Hash of the verdict_hash alone — a genesis row has no `prev` to
/// chain, but its `chain_hash` must be deterministic so the next row
/// can reference it in its `chain_prev_hash`.
///
/// **Non-genesis case** (`prev = Some(prev_hash)`):
/// `chain_hash = SHA256(prev_hash_bytes || verdict_hash_bytes)`.
/// **RAW bytes** of the hex string (NOT hex-decoded). This is not an
/// arbitrary decision: the hex string as ASCII bytes is the
/// representation the row persists; hashing it this way guarantees an
/// auditor can recompute the hash with no intermediate hex-decode (a
/// badly implemented decoder in another language cannot break the
/// hash).
///
/// **Visibility `pub`**: the `compliance-cli` `verify-chain` command
/// must use EXACTLY the same algorithm as the write path. An in-line
/// re-implementation in the CLI would be latent drift if a refactor
/// touches one and not the other. Single source of truth (same pattern
/// as `compute_verdict_hash`, also pub).
pub fn compute_chain_hash(prev: Option<&str>, verdict_hash: &str) -> String {
    let mut hasher = Sha256::new();
    if let Some(prev_hash) = prev {
        hasher.update(prev_hash.as_bytes());
    }
    hasher.update(verdict_hash.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// INTENT: the `compute_chain_hash` genesis case (prev = None)
    ///         hashes ONLY the verdict_hash, prepending nothing — a
    ///         genesis row has no prev to chain, but its chain_hash
    ///         must be deterministic so the next row can reference it.
    /// CONTEXT: the genesis scheme is part of the chain contract every
    ///          external verifier reimplements.
    /// EXPIRES IF: the genesis scheme is deliberately changed.
    #[test]
    fn test_intent_compute_chain_hash_genesis_case_hashes_verdict_alone() {
        let verdict_hash = "a".repeat(64);
        let chain_hash = compute_chain_hash(None, &verdict_hash);

        // Recompute manually to verify the algorithm.
        let mut hasher = Sha256::new();
        hasher.update(verdict_hash.as_bytes());
        let expected = hex::encode(hasher.finalize());

        assert_eq!(chain_hash, expected);
        assert_eq!(chain_hash.len(), 64, "hex64 lowercase output");
        assert!(
            chain_hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "hex lowercase only"
        );
    }

    /// INTENT: the `compute_chain_hash` non-genesis case concatenates
    ///         prev_hash_bytes || verdict_hash_bytes (in that order)
    ///         before hashing. If the order is inverted (verdict ||
    ///         prev) or one part is omitted, the hash diverges.
    /// CONTEXT: the concatenation order is part of the chain contract.
    /// EXPIRES IF: a refactor deliberately changes the concatenation
    ///             order.
    #[test]
    fn test_intent_compute_chain_hash_non_genesis_concatenates_prev_then_verdict_bytes() {
        let prev_hash = "b".repeat(64);
        let verdict_hash = "c".repeat(64);
        let chain_hash = compute_chain_hash(Some(&prev_hash), &verdict_hash);

        // Recompute: prev || verdict, in that order, raw ASCII bytes.
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(verdict_hash.as_bytes());
        let expected = hex::encode(hasher.finalize());

        assert_eq!(chain_hash, expected);

        // Sanity: the inverted order produces a DIFFERENT hash.
        let mut inverted = Sha256::new();
        inverted.update(verdict_hash.as_bytes());
        inverted.update(prev_hash.as_bytes());
        let inverted_hex = hex::encode(inverted.finalize());
        assert_ne!(
            chain_hash, inverted_hex,
            "order matters — prev || verdict ≠ verdict || prev"
        );

        // Sanity: omitting the prev also produces a different hash
        // (= genesis case over the same verdict).
        let genesis = compute_chain_hash(None, &verdict_hash);
        assert_ne!(
            chain_hash, genesis,
            "non-genesis must differ from genesis on same verdict"
        );
    }

    /// INTENT: `compute_chain_hash` is byte-for-byte deterministic —
    ///         repeated invocations with the same input produce
    ///         identical output. Without this, two auditors
    ///         recomputing the hash from the same row could see
    ///         "tampering" where there is only non-determinism.
    /// CONTEXT: determinism is the central falsifiability property of
    ///          the chain.
    /// EXPIRES IF: the impl introduces deliberate non-determinism
    ///             (impossible — sha2 is deterministic by spec).
    #[test]
    fn test_intent_compute_chain_hash_is_deterministic_byte_by_byte() {
        let prev = "d".repeat(64);
        let verdict = "e".repeat(64);
        let first = compute_chain_hash(Some(&prev), &verdict);
        let second = compute_chain_hash(Some(&prev), &verdict);
        let third = compute_chain_hash(Some(&prev), &verdict);
        assert_eq!(first, second);
        assert_eq!(second, third);
    }
}
