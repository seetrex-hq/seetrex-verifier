// SPDX-License-Identifier: Apache-2.0
//! RFC 6962 Merkle proof verification (PURE, offline) — two sibling primitives:
//! `verify_inclusion` (RFC 9162 §2.1.3.2) and `verify_consistency`
//! (RFC 9162 §2.1.4.2). `verify_inclusion` is the offline half of the anchor
//! consistency check: every inclusion proof must validate against its
//! cosigned checkpoint. `verify_consistency` is the append-only-extension
//! check that UNDERPINS `C_audit` freshness (a fresh `C_audit` must extend
//! the package checkpoint) — it is only the FALSIFICATION half (it rejects a
//! rewritten/forked `C_audit`); wall-clock recency needs a live monitor, and
//! neither primitive ALONE constitutes an auditor-facing verdict. See each
//! function's doc for its precise, narrow claim.
//!
//! This module proves ONE thing: given a `leaf_hash`, its `index` in a tree
//! of a stated `size`, an audit `proof`, and an EXPECTED `root`, the leaf is
//! included in a tree with that root. It does NOT authenticate the root —
//! that is the cosigned-checkpoint half ([`crate::checkpoint`],
//! `ed25519-dalek`), which supplies the `root` argument from a
//! witness-quorum-cosigned checkpoint validated against the pinned witness
//! policy. On its own, `verify_inclusion` is a building block, not a full
//! anchor gate: a forged package could pass a self-chosen root here. The
//! gate closes when the checkpoint half binds `root` to the pinned witness
//! quorum — those call sites live in [`crate::checkpoint`] and the
//! completeness half of the anchor check.
//!
//! Algorithm source (NOT reconstructed from memory): **RFC 9162 §2.1.3.2**
//! "Verifying an Inclusion Proof" — the tree is identical to RFC 6962, which
//! Sigsum uses (leaf hash `SHA256(0x00 || d)`, node `SHA256(0x01 || l || r)`,
//! SHA-256). Independent oracle / anti-tautology guard: the test vectors
//! below are the output of a control implementation written separately and
//! directly from the RFC 6962 text, so the code under test never generates
//! its own expected answers.

use sha2::{Digest, Sha256};

/// RFC 6962 leaf hash of a leaf's data bytes: `SHA256(0x00 || d)`. The `0x00`
/// domain-separation prefix is what distinguishes a leaf from an interior
/// node (`0x01`), so a leaf hash can never be confused for a node hash.
pub fn leaf_hash(leaf_data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(leaf_data);
    h.finalize().into()
}

/// RFC 6962 interior node hash: `SHA256(0x01 || left || right)`. Order
/// matters — `(left, right)` is not `(right, left)`; the caller decides the
/// order from the audit-path position bit.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Verify a Merkle inclusion proof, RFC 9162 §2.1.3.2 (verbatim). Returns
/// `true` iff `leaf` at `index` in a tree of `size` leaves, combined with the
/// `proof` audit path (bottom-up), recomputes exactly `root`.
///
/// Correctness of REJECTION (why no separate length check is needed): the
/// final `sn == 0` test rejects a proof that is too short (`sn` never reaches
/// 0) or too long (an extra entry is consumed while `sn == 0`, caught by the
/// in-loop guard). An `index >= size` is rejected up front.
pub fn verify_inclusion(
    index: u64,
    size: u64,
    leaf: [u8; 32],
    proof: &[[u8; 32]],
    root: [u8; 32],
) -> bool {
    // RFC 9162 §2.1.3.2 step 1: leaf_index must be within the tree.
    if index >= size {
        return false;
    }
    // step 2/3: fn = leaf_index, sn = tree_size - 1, r = hash.
    let mut fnn = index;
    let mut sn = size - 1;
    let mut r = leaf;
    // step 4: fold each audit-path entry.
    for p in proof {
        // "If sn is 0, stop and fail." — an over-long proof.
        if sn == 0 {
            return false;
        }
        if (fnn & 1) == 1 || fnn == sn {
            // r is a right child (or the right edge of an unbalanced tree):
            // the sibling p sits to its LEFT.
            r = node_hash(p, &r);
            // "If LSB(fn) is not set: loop fn,sn >>= 1 until LSB(fn) set or fn == 0."
            if (fnn & 1) == 0 {
                loop {
                    fnn >>= 1;
                    sn >>= 1;
                    if (fnn & 1) == 1 || fnn == 0 {
                        break;
                    }
                }
            }
        } else {
            // r is a left child: the sibling p sits to its RIGHT.
            r = node_hash(&r, p);
        }
        // step 4 final: right-shift both once.
        fnn >>= 1;
        sn >>= 1;
    }
    // step 5: all path entries consumed exactly (sn == 0) and root matches.
    sn == 0 && r == root
}

/// Verify a Merkle CONSISTENCY proof, RFC 9162 §2.1.4.2 (verbatim). Returns
/// `true` iff the tree of `second_size` leaves with root `second_root` is an
/// APPEND-ONLY extension of the tree of `first_size` leaves with root
/// `first_root` — i.e. the first `first_size` leaves of the second tree are
/// exactly the first tree, unrewritten — as attested by the `proof` node path.
///
/// PURE/offline. Like [`verify_inclusion`], it does NOT authenticate either
/// root (that is the cosigned-checkpoint half, [`crate::checkpoint`]). It also
/// does NOT establish wall-clock freshness: a consistency proof shows MONOTONIC
/// append-only growth between two checkpoints, NOT that `second` is RECENT in
/// time — that needs a live monitor / a recently-pinned checkpoint.
/// **Consistency ≠ recency.**
///
/// The caller in [`crate::anchor_completitud`] uses this as the freshness
/// PROOF: it replaces a bare integer floor (`S(C_audit) ≥ pkg_size` on
/// DECLARED scalars) with this cryptographic root binding, so a package can
/// no longer claim a larger `C_audit` size behind a forked/inconsistent root.
///
/// Degenerate cases (the RFC algorithm assumes `0 < first < second`; handling
/// them is this wrapper's responsibility, fail-closed):
///   * `first_size > second_size` → `false` (cannot extend "backwards").
///   * `first_size == second_size` → `true` iff `proof` empty AND roots equal.
///   * `first_size == 0` → the empty tree is a prefix of any tree; `true` iff
///     `proof` empty. This ignores `second_root` entirely, so it is VACUOUS for
///     freshness — the caller MUST hard-reject `first_size == 0` (the package's
///     own authenticated checkpoint size, which is always `≥ 1`) BEFORE
///     delegating, never rely on the invariant holding. The wired caller in
///     [`crate::anchor_completitud`] does exactly that.
///
/// Algorithm source (NOT reconstructed from memory): RFC 9162 §2.1.4.2. The
/// proof CONSTRUCTION (RFC 6962 §2.1.2 SUBPROOF) is cross-checked by an
/// INDEPENDENT control implementation, and a REAL Sigsum consistency proof
/// captured from the live log anchors the vectors against non-synthetic
/// data, so the code under test never generates its own expected answers.
pub fn verify_consistency(
    first_size: u64,
    second_size: u64,
    first_root: &[u8; 32],
    second_root: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    // Degenerate cases outside the RFC precondition `0 < first < second`.
    if first_size > second_size {
        return false;
    }
    if first_size == second_size {
        return proof.is_empty() && first_root == second_root;
    }
    if first_size == 0 {
        return proof.is_empty();
    }
    // Now `0 < first_size < second_size`; follow RFC 9162 §2.1.4.2 verbatim.
    // step 1: an empty consistency_path fails.
    if proof.is_empty() {
        return false;
    }
    // step 2: if `first` is an exact power of 2, prepend `first_hash` to the
    // path. Modelled without allocation: `first_elem` is "the first value in
    // the consistency_path array" (step 5) and `rest` is everything after it.
    let (first_elem, rest): (&[u8; 32], &[[u8; 32]]) = if first_size.is_power_of_two() {
        (first_root, proof) // prepended: first value = first_hash, rest = whole proof
    } else {
        (&proof[0], &proof[1..]) // first value = proof[0], rest = the tail
    };
    // step 3.
    let mut fnn = first_size - 1;
    let mut sn = second_size - 1;
    // step 4: if LSB(fn) is set, right-shift both equally until it is not.
    while (fnn & 1) == 1 {
        fnn >>= 1;
        sn >>= 1;
    }
    // step 5.
    let mut fr = *first_elem;
    let mut sr = *first_elem;
    // step 6: fold each subsequent value `c`.
    for c in rest {
        // 6a.
        if sn == 0 {
            return false;
        }
        // 6b: LSB(fn) set, or fn == sn.
        if (fnn & 1) == 1 || fnn == sn {
            fr = node_hash(c, &fr); // 6b.i
            sr = node_hash(c, &sr); // 6b.ii
            // 6b.iii: if LSB(fn) not set, right-shift both until LSB set or fn == 0.
            if (fnn & 1) == 0 {
                while (fnn & 1) == 0 && fnn != 0 {
                    fnn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            // 6b (otherwise).i.
            sr = node_hash(&sr, c);
        }
        // 6c: right-shift both once.
        fnn >>= 1;
        sn >>= 1;
    }
    // step 7 (RFC-mandated, verbatim): both recomputed roots match AND the path
    // was consumed exactly. The `sn == 0` clause is defense-in-depth here — a
    // too-short proof leaves `sn != 0` but also fails the root match, and a
    // too-long proof is caught earlier by the 6a guard — so no non-collision
    // input can reach step 7 with matching roots yet `sn != 0`. It is kept
    // because RFC 9162 §2.1.4.2 requires it and it costs nothing.
    fr == *first_root && sr == *second_root && sn == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a 64-char lowercase-hex string into a 32-byte hash. Panics on
    /// malformed input — these are hardcoded test vectors.
    fn h(hex_str: &str) -> [u8; 32] {
        let bytes = hex::decode(hex_str).expect("valid hex");
        bytes.try_into().expect("32 bytes")
    }

    // ---- REAL oracles from an independent control implementation ----------
    //
    // An INDEPENDENT RFC 6962 implementation built these trees and audit
    // paths (top-down `mth`/`path` tree CONSTRUCTION — a different algorithm
    // from the Rust bottom-up fold under test) and self-checked each with
    // RFC 9162 §2.1.3.2. The vectors are deterministic (SHA-256 over the
    // fixed leaf inputs quoted below), so the control reproduces these bytes
    // exactly. The Rust code under test NEVER computes a root here — it only
    // VERIFIES against the control's root — so a bug in the Rust FOLD cannot
    // hide behind its own output. The one thing a shared misreading of the
    // RFC 6962 hashing (0x00/0x01 prefixes) would NOT catch is pinned
    // separately: the published CT primitive vectors
    // `SHA256(0x00) = 6e340b9c…` and the domain-separated leaf hash below.

    // Leaf hashes (SHA256(0x00 || "seetrex-merkle-control::leaf-N")).
    const LH0: &str = "3803c86c9256fbe52726b787acb90a02570f96aa2e742d94d49438da6f684185";
    const LH1: &str = "144b9b18dfab030751745dac96e0947c05ed438f9962adcb8aaca8f834aafa79";
    const LH2: &str = "aa16c2b0bdbf3f4e9844533b193e2407326ef041ddf3d3e86cf028c7dd41c474";
    const LH3: &str = "3d2390c612074b7725ce713fda7810728791990de2833442d531701039a5515a";
    const LH4: &str = "6ba4472e8116fea9061db75a18d0eea4d06ad1649a2fd9d4312affbe2b682c31";
    const LH6: &str = "f64402b9050fce7565c0b76b5c9991ac2d9d85b41504935aeeff012d39f03d76";

    #[test]
    fn leaf_hash_matches_rfc6962_domain_separation() {
        // The control's leaf-0 input, hashed with the 0x00 prefix.
        assert_eq!(hex::encode(leaf_hash(b"seetrex-merkle-control::leaf-0")), LH0);
    }

    #[test]
    fn size1_single_leaf_empty_proof() {
        // tree_size=1: root == leaf_hash, empty audit path.
        let root = h("3803c86c9256fbe52726b787acb90a02570f96aa2e742d94d49438da6f684185");
        assert!(verify_inclusion(0, 1, h(LH0), &[], root));
    }

    #[test]
    fn size2_both_indices() {
        let root = h("9d7001da51a48c638d3781518f19775a6680ab97184a9f4d836cf353dbad75b3");
        assert!(verify_inclusion(0, 2, h(LH0), &[h(LH1)], root));
        assert!(verify_inclusion(1, 2, h(LH1), &[h(LH0)], root));
    }

    #[test]
    fn size3_unbalanced_right_leaf() {
        // The lone right leaf (index 2) proves against the size-2 subtree root.
        let root = h("0a515d9a4552f02eb7db1ad69852cbf645992fd982c82b929f8a74f728f3ce18");
        let l01 = "9d7001da51a48c638d3781518f19775a6680ab97184a9f4d836cf353dbad75b3";
        assert!(verify_inclusion(2, 3, h(LH2), &[h(l01)], root));
        // And a left leaf (index 0) in the same odd tree (proof length 2).
        let r2 = "aa16c2b0bdbf3f4e9844533b193e2407326ef041ddf3d3e86cf028c7dd41c474";
        assert!(verify_inclusion(0, 3, h(LH0), &[h(LH1), h(r2)], root));
    }

    #[test]
    fn size4_balanced() {
        let root = h("d016137767242f024e725557b5051dab80491413071240495cd88035436b4a83");
        // index 0 folds up with: sibling leaf-1, then the (2,3) subtree root.
        let subtree_23 = "c1875cafa6d53c8bf9c346eab93b398d09df3dfe11dec67ed4b7278902ad4315";
        assert!(verify_inclusion(0, 4, h(LH0), &[h(LH1), h(subtree_23)], root));
        // index 3 folds up with: sibling leaf-2 (== LH2), then the (0,1) subtree root.
        let subtree_01 = "9d7001da51a48c638d3781518f19775a6680ab97184a9f4d836cf353dbad75b3";
        assert!(verify_inclusion(3, 4, h(LH3), &[h(LH2), h(subtree_01)], root));
    }

    #[test]
    fn size5_lone_fifth_leaf_exercises_fn_eq_sn_shift() {
        // index 4 in a 5-leaf tree: the `fn == sn` + while-shift branch.
        let root = h("41d238ac4b1dd0be94e9bc7410ea26c94ccb2089bec2c4e1b61945810e1b52e3");
        let subtree4 = "d016137767242f024e725557b5051dab80491413071240495cd88035436b4a83";
        assert!(verify_inclusion(4, 5, h(LH4), &[h(subtree4)], root));
    }

    #[test]
    fn size7_rightmost_unbalanced() {
        // index 6 (rightmost) in a 7-leaf tree — deepest unbalanced path.
        let root = h("14ad6a7369b84b35e2d920ad0acc0b494520b05e3d8fdb084cfed0c7c4d1e1e7");
        let p0 = "f368ecfc0f7903eeb2889217e5e67100c18c4311a85f25c4506fd593f57f9a36";
        let p1 = "d016137767242f024e725557b5051dab80491413071240495cd88035436b4a83";
        assert!(verify_inclusion(6, 7, h(LH6), &[h(p0), h(p1)], root));
    }

    // ---- REJECTION: forged / malformed proofs (falsifiers) ---------------

    #[test]
    fn rejects_index_out_of_range() {
        let root = h("9d7001da51a48c638d3781518f19775a6680ab97184a9f4d836cf353dbad75b3");
        assert!(!verify_inclusion(2, 2, h(LH0), &[h(LH1)], root)); // index == size
        assert!(!verify_inclusion(9, 2, h(LH0), &[h(LH1)], root)); // index > size
    }

    #[test]
    fn rejects_empty_tree() {
        assert!(!verify_inclusion(0, 0, h(LH0), &[], h(LH0)));
    }

    #[test]
    fn rejects_tampered_proof_node() {
        // Real proof for size-2 index-0, but the sibling is zeroed (forged).
        let root = h("9d7001da51a48c638d3781518f19775a6680ab97184a9f4d836cf353dbad75b3");
        assert!(!verify_inclusion(0, 2, h(LH0), &[[0u8; 32]], root));
    }

    #[test]
    fn rejects_forged_leaf() {
        // A leaf that is not in the tree, with an otherwise-real path.
        let root = h("9d7001da51a48c638d3781518f19775a6680ab97184a9f4d836cf353dbad75b3");
        assert!(!verify_inclusion(0, 2, leaf_hash(b"forged"), &[h(LH1)], root));
    }

    #[test]
    fn rejects_wrong_root() {
        let wrong = [0xabu8; 32];
        assert!(!verify_inclusion(0, 2, h(LH0), &[h(LH1)], wrong));
    }

    #[test]
    fn rejects_proof_too_short() {
        // size-4 index-0 needs a 2-node path; give it 1 → sn never reaches 0.
        let root = h("d016137767242f024e725557b5051dab80491413071240495cd88035436b4a83");
        assert!(!verify_inclusion(0, 4, h(LH0), &[h(LH1)], root));
    }

    #[test]
    fn rejects_proof_too_long() {
        // size-2 index-0 needs a 1-node path; give it 2 → extra entry hits the
        // in-loop `sn == 0` guard.
        let root = h("9d7001da51a48c638d3781518f19775a6680ab97184a9f4d836cf353dbad75b3");
        assert!(!verify_inclusion(0, 2, h(LH0), &[h(LH1), h(LH2)], root));
    }

    // ---- intent test (COMPLEX discipline) --------------------------------

    /// INTENT: `verify_inclusion` implements RFC 9162 §2.1.3.2 with RFC 6962
    ///   hashing (leaf `0x00`, node `0x01`), and the node hash is
    ///   ORDER-SENSITIVE — the position bit of the audit path decides
    ///   `(sibling, r)` vs `(r, sibling)`. Swapping the order breaks every
    ///   multi-leaf proof (the whole point of the domain-separated,
    ///   position-dependent hashing).
    /// CONTEXT: an inclusion proof is only sound if the recomputation matches
    ///   the producer's tree hashing byte-for-byte; a left/right swap or a
    ///   missing domain-separation prefix silently accepts forged trees.
    /// EXPIRES IF: Sigsum/RFC 6962 changes its tree-hash construction (a v2
    ///   epoch), in which case this module and these vectors change together.
    #[test]
    fn test_intent_rfc6962_hashing_is_order_and_domain_sensitive() {
        // Domain separation: a leaf hash is NOT a bare SHA-256 of the data.
        let bare = {
            let mut hh = Sha256::new();
            hh.update(b"x");
            let out: [u8; 32] = hh.finalize().into();
            out
        };
        assert_ne!(leaf_hash(b"x"), bare, "leaf hash must carry the 0x00 prefix");
        // Order sensitivity: for size-2, index 0 (sibling on the right) and
        // index 1 (sibling on the left) use the SAME two hashes in OPPOSITE
        // order and both must verify against the SAME root — proving the
        // position bit, not a symmetric combine, drives the fold.
        let root = h("9d7001da51a48c638d3781518f19775a6680ab97184a9f4d836cf353dbad75b3");
        assert!(verify_inclusion(0, 2, h(LH0), &[h(LH1)], root));
        assert!(verify_inclusion(1, 2, h(LH1), &[h(LH0)], root));
        // But feeding index 0's leaf with index 1's position must NOT verify
        // (order matters): leaf LH0 as if it were the RIGHT child.
        assert!(!verify_inclusion(1, 2, h(LH0), &[h(LH1)], root));
    }

    // ---- consistency-proof oracles ----------------------------------------
    //
    // Same provenance as the inclusion oracles: the INDEPENDENT control
    // implementation builds each consistency proof via the
    // RFC 6962 §2.1.2 SUBPROOF recursion (top-down CONSTRUCTION — a DIFFERENT
    // algorithm from the RFC 9162 §2.1.4.2 fold under test) and self-checks it.
    // Re-running the script reproduces these bytes exactly. Roots are the
    // `mth` of the first `m` / all `n` synthetic leaves.

    // Subtree roots reused across sizes (from the control's `mth`).
    const R1: &str = "3803c86c9256fbe52726b787acb90a02570f96aa2e742d94d49438da6f684185"; // tree[0:1] == LH0
    const R2: &str = "9d7001da51a48c638d3781518f19775a6680ab97184a9f4d836cf353dbad75b3"; // tree[0:2]
    const R3: &str = "0a515d9a4552f02eb7db1ad69852cbf645992fd982c82b929f8a74f728f3ce18"; // tree[0:3]
    const R4: &str = "d016137767242f024e725557b5051dab80491413071240495cd88035436b4a83"; // tree[0:4]
    const R5: &str = "41d238ac4b1dd0be94e9bc7410ea26c94ccb2089bec2c4e1b61945810e1b52e3"; // tree[0:5]
    const R6: &str = "74309e6fcc1522f91bc5642991f282ec7240e1ca798865a0299cda29d3ce0346"; // tree[0:6]
    const R7: &str = "14ad6a7369b84b35e2d920ad0acc0b494520b05e3d8fdb084cfed0c7c4d1e1e7"; // tree[0:7]
    const R8: &str = "166de2c2db9125aa0809126f1036ba111fdf10194b6a6c3d0993a089d9b16283"; // tree[0:8]

    #[test]
    fn consistency_power_of_two_first() {
        // first == 1 (pow2): first_hash is prepended to the path (step 2).
        assert!(verify_consistency(1, 2, &h(R1), &h(R2), &[h(LH1)]));
        // first == 2 (pow2), one-node proof.
        assert!(verify_consistency(2, 3, &h(R2), &h(R3), &[h(LH2)]));
        assert!(verify_consistency(
            2, 4, &h(R2), &h(R4),
            &[h("c1875cafa6d53c8bf9c346eab93b398d09df3dfe11dec67ed4b7278902ad4315")],
        ));
        // first == 4 (pow2), boundary into an 8-leaf tree.
        assert!(verify_consistency(
            4, 8, &h(R4), &h(R8),
            &[h("3a79447899eda508a2a2f3245753a2876f2b87bac19567a8e0994af30026dbda")],
        ));
    }

    #[test]
    fn consistency_odd_first() {
        // first == 3 (NOT pow2): the first proof node is the "first value".
        assert!(verify_consistency(
            3, 4, &h(R3), &h(R4),
            &[h(LH2), h(LH3), h(R2)],
        ));
        assert!(verify_consistency(
            3, 7, &h(R3), &h(R7),
            &[
                h(LH2), h(LH3), h(R2),
                h("4d39603800e1977a0f58287e0a42763cc3807b1ce92a8b817a1e7b713997707c"),
            ],
        ));
        // first == 5 (NOT pow2), four-node proof.
        assert!(verify_consistency(
            5, 7, &h(R5), &h(R7),
            &[
                h(LH4),
                h("a56e1511a57fb2266c56a14559141c385c0f2fc00f257308dd181d22c4bc3d92"),
                h(LH6), h(R4),
            ],
        ));
    }

    #[test]
    fn consistency_fn_equals_sn_edge() {
        // first == 6, second == 7: exercises the `fn == sn` branch of step 6b.
        assert!(verify_consistency(
            6, 7, &h(R6), &h(R7),
            &[
                h("f368ecfc0f7903eeb2889217e5e67100c18c4311a85f25c4506fd593f57f9a36"),
                h(LH6), h(R4),
            ],
        ));
        // first == 7 (odd), second == 8.
        assert!(verify_consistency(
            7, 8, &h(R7), &h(R8),
            &[
                h(LH6),
                h("993d4cea1768f0aff2117053f4eed09435cb870c4215dad6aa77d225ca72d4d8"),
                h("f368ecfc0f7903eeb2889217e5e67100c18c4311a85f25c4506fd593f57f9a36"),
                h(R4),
            ],
        ));
    }

    #[test]
    fn consistency_degenerate_cases() {
        // first == second, equal roots, empty proof → trivially consistent.
        assert!(verify_consistency(3, 3, &h(R3), &h(R3), &[]));
        // first == second but roots differ → false (different trees).
        assert!(!verify_consistency(3, 3, &h(R3), &h(R4), &[]));
        // first == second with a non-empty proof → false.
        assert!(!verify_consistency(3, 3, &h(R3), &h(R3), &[h(LH0)]));
        // first == 0: empty tree is a prefix of any tree, but only with an
        // empty proof; a non-empty proof for first == 0 is malformed.
        assert!(verify_consistency(0, 4, &h(R4), &h(R4), &[]));
        assert!(!verify_consistency(0, 4, &h(R4), &h(R4), &[h(LH0)]));
        // first > second: cannot extend "backwards".
        assert!(!verify_consistency(4, 3, &h(R4), &h(R3), &[h(LH0)]));
    }

    #[test]
    fn consistency_rejects_empty_proof_when_growing() {
        // 0 < first < second REQUIRES a non-empty path (step 1).
        assert!(!verify_consistency(2, 4, &h(R2), &h(R4), &[]));
    }

    #[test]
    fn consistency_rejects_tampered_node() {
        // Real (3,4) proof with its last node zeroed.
        assert!(!verify_consistency(3, 4, &h(R3), &h(R4), &[h(LH2), h(LH3), [0u8; 32]]));
    }

    #[test]
    fn consistency_rejects_forked_second_tree() {
        // THE capital case: a real (3,4) proof, real first_root, but a
        // second_root that does NOT extend the first tree (a rewrite) →
        // false. This is what the primitive exists to catch, and what a bare
        // `S(C_audit) >= pkg_size` integer comparison could NOT catch.
        let forked = [0x11u8; 32];
        assert!(!verify_consistency(3, 4, &h(R3), &forked, &[h(LH2), h(LH3), h(R2)]));
    }

    #[test]
    fn consistency_rejects_swapped_roots() {
        // Passing the roots in the wrong order must not verify.
        assert!(!verify_consistency(3, 4, &h(R4), &h(R3), &[h(LH2), h(LH3), h(R2)]));
    }

    #[test]
    fn consistency_rejects_proof_wrong_length() {
        // Too short: drop the last node of the (3,4) proof → sn never reaches 0.
        assert!(!verify_consistency(3, 4, &h(R3), &h(R4), &[h(LH2), h(LH3)]));
        // Too long: append an extra node → hits the in-loop `sn == 0` guard.
        assert!(!verify_consistency(
            3, 4, &h(R3), &h(R4), &[h(LH2), h(LH3), h(R2), h(LH0)],
        ));
    }

    // ---- REAL Sigsum consistency oracle (anti-tautology) -------------------
    //
    // Captured from the live log: the test.sigsum.org barreleye log BUILT
    // this consistency proof between the already-frozen, already-authenticated
    // checkpoint (size 196372) and a later cosigned head (size 196698). The
    // log made the proof, so Rust-verifying-a-log-built-proof cannot be
    // tautological — this anchors the algorithm against non-synthetic data.
    // Root authentication by cosignature quorum is the checkpoint module's
    // job (orthogonal to this test).
    const SIGSUM_FIRST: &str =
        "848aff0ecb7315a0fc1cc4a00c1065b51b4c269ff871dc2f048711892739a06e";
    const SIGSUM_SECOND: &str =
        "8ed945e8e985fa955a241d629741652799b17d1e7509555b3ceb34530bfd414e";

    fn sigsum_proof() -> Vec<[u8; 32]> {
        [
            "83dfb887c08aaf41d2a00353503832f75af3024ecae61d09c2768de96d2ce2ce",
            "e5b48fd17b69f71aa62b9ce8fe20574a23afac4feee3a65acac8ca2ccbc9c77a",
            "fdab4aae5aa70ea61beb0d5cc136fe68127deac0ad264af5f33c63ea4d671860",
            "6fde5da41e30dcf36aeb80be3a067a0d71f109906e452f2e7a58cc86a0be79df",
            "ca908cfaf00047a1fef39cec68f933f775ddbbbe8320b980aed0a59baa988ab3",
            "46200d2db2017dc9aea157d38926c27e81977815a75aac5af3317d1516b07f37",
            "0be3a720c479cf25673c21ea84db809b0bc8f3f2767cab85560878fbb42b30a1",
            "5a3b158db3c207b6841f00c782e96d17b88a19cabb5cd7fb213ef6984457b88e",
            "5a20a489847488e7f7b2b2cd70de536c91fb27a0a960f7d04d2e7dc3f98a1f47",
            "ce7d3d60bddef51351c90ed469c5140030a6e8f87a87d6b4f20cd8eaf6c55081",
            "425bdfab555c08a4ca2f753da727ffc34f01c568eb0bd7cf27603bd8a29d55f3",
            "2ebbadd1c82f077533f2904f4cc3e89fa9112d97ac982115b4f92d08e759b5ce",
            "2f22287841aca348a0e5e38650bfc1506744dc6acc06b5812bdce30c399ead98",
            "84b0f8a1d9c6e04ab627cde4506c9a7105683a935e8a3d988176d12b191e3f28",
            "20065aca59c5b73c0fd5cf20ddeecc66b5f054b6bcf13c6a05bc0e374ab8423c",
            "39f6ea6a47c49627fa9bc74ff55ccb283612d9267365ba0c95acd8e3122c241f",
            "43bd28c79dec46786a85bdf0fe72eac3985a8fa172979cdbf7dc04d6c506d43d",
        ]
        .iter()
        .map(|s| h(s))
        .collect()
    }

    #[test]
    fn consistency_real_sigsum_vector() {
        assert!(verify_consistency(
            196372, 196698, &h(SIGSUM_FIRST), &h(SIGSUM_SECOND), &sigsum_proof(),
        ));
    }

    #[test]
    fn consistency_real_sigsum_falsifiers() {
        let proof = sigsum_proof();
        // A forged second root over the real proof must not verify.
        assert!(!verify_consistency(
            196372, 196698, &h(SIGSUM_FIRST), &[0u8; 32], &proof,
        ));
        // The real proof with its last node tampered must not verify.
        let mut bad = proof.clone();
        *bad.last_mut().unwrap() = [0u8; 32];
        assert!(!verify_consistency(
            196372, 196698, &h(SIGSUM_FIRST), &h(SIGSUM_SECOND), &bad,
        ));
    }

    // ---- intent test (COMPLEX discipline) --------------------------------

    /// INTENT: `verify_consistency` proves APPEND-ONLY extension by binding BOTH
    ///   roots, so it rejects a `second` tree that rewrites history under
    ///   `first` even when `second_size > first_size` — the case a bare
    ///   integer size comparison (`S(C_audit) >= pkg_size`) accepts. This is
    ///   the whole reason the freshness FLOOR was upgraded from an integer
    ///   comparison to this cryptographic binding.
    /// CONTEXT: a malicious producer could present a `C_audit` with a larger
    ///   DECLARED size but a forked root; only recomputing both roots from the
    ///   consistency proof and matching them catches it.
    /// EXPIRES IF: Sigsum/RFC 6962 changes its tree-hash construction (a v2
    ///   epoch), in which case this module and its vectors change together.
    #[test]
    fn test_intent_consistency_rejects_rewrite_despite_larger_size() {
        // A genuine (3,4) extension verifies.
        assert!(verify_consistency(3, 4, &h(R3), &h(R4), &[h(LH2), h(LH3), h(R2)]));
        // Same first tree, a STRICTLY larger second_size, but a second_root
        // that is not an append-only extension → rejected, despite 4 > 3. The
        // integer floor the primitive replaces (`second_size >= first_size`,
        // 4 >= 3) WOULD have accepted this rewrite as "fresh" — that weakness
        // is exactly what this cryptographic binding closes.
        let rewritten = [0x22u8; 32];
        assert!(!verify_consistency(3, 4, &h(R3), &rewritten, &[h(LH2), h(LH3), h(R2)]));
    }
}
