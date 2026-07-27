// SPDX-License-Identifier: Apache-2.0
//! Cosigned-checkpoint verification — the WITNESS-QUORUM half of the anchor
//! consistency line. This is what AUTHENTICATES the Merkle `root` that
//! [`crate::merkle::verify_inclusion`] consumes.
//!
//! On its own, `verify_inclusion` trusts a caller-supplied `root` (its doc
//! says so explicitly). Here that root is proven to be the head of a tree the
//! LOG signed and an INDEPENDENT witness QUORUM cosigned: a split-view attack
//! then requires compromising the pinned quorum, not just the log.
//! [`verify_anchored_inclusion`] composes the two halves plus the
//! producer-identity and tenant-slug bindings into the single-leaf INCLUSION
//! COMPONENT of the anchor gate — NOT the whole gate (the package JOIN and
//! the completeness/freshness half live in [`crate::anchor_package`] and
//! [`crate::anchor_completitud`], which are the callers that wire this in).
//!
//! The acceptance rule is deliberate: durable trust = the pinned witness
//! quorum, and the verifier applies the CURRENT pinned policy, never a
//! historical one.
//!
//! Serializations — NOT reconstructed from memory. Each was VERIFIED against
//! REAL `test.sigsum.org` signatures with a spike driven by the live log (a
//! wrong byte fails the Ed25519 verify); the test `const`s below are
//! TRANSCRIBED from the frozen oracle that spike produced. The
//! serializations:
//!
//! * Signed tree head (the LOG signs, Ed25519, directly):
//!   `"sigsum.org/v1/tree/<log-key-hash-hex>\n<size>\n<root-b64>\n"`
//! * Cosignature (a WITNESS signs, Ed25519 — c2sp `tlog-cosignature`):
//!   `"cosignature/v1\ntime <unix>\nsigsum.org/v1/tree/<log-key-hash-hex>\n<size>\n<root-b64>\n"`
//! * Tree-leaf hash (RFC 6962 leaf of a Sigsum leaf, 128 preimage bytes):
//!   `SHA256(0x00 || checksum(32) || signature(64) || key_hash(32))`
//! * A Sigsum key hash is `SHA256(raw 32-byte Ed25519 public key)`; the
//!   `<root-b64>` is standard base64 (RFC 4648 §4) of the 32-byte root.
//!
//! `ed25519-dalek` is VERIFY-ONLY here (`VerifyingKey::verify_strict`); this
//! crate never signs — a deliberate, standing design decision.

use crate::anchor::{is_valid_slug, leaf_checksum, serialize_preimage, Lane, RotationRecord, Verdict};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// A pinned witness policy: the log public key, the set of
/// accepted witness public keys, and the quorum threshold `k`. The verifier
/// applies the CURRENT pinned policy — never a historical one — rejecting any
/// checkpoint that does not reach `quorum_k` cosignatures from THESE
/// witnesses. Rotation (adding/removing a witness) is a NEW policy version,
/// append-only; this struct is one version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessPolicy {
    /// Raw 32-byte Ed25519 public key of the log.
    pub log_pubkey: [u8; 32],
    /// Raw 32-byte Ed25519 public keys of the accepted witnesses.
    pub witnesses: Vec<[u8; 32]>,
    /// Minimum number of DISTINCT policy witnesses that must cosign. A pinned
    /// policy MUST have `quorum_k >= 1` (a 0 threshold would accept the log's
    /// signature alone, defeating the split-view protection) — a
    /// pinned-artifact invariant, not something an attacker supplies.
    pub quorum_k: usize,
}

/// One witness cosignature line from a Sigsum tree head:
/// `cosignature=<key_hash> <timestamp> <signature>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cosignature {
    /// `SHA256(witness public key)` — identifies which witness signed.
    pub key_hash: [u8; 32],
    /// Unix seconds the witness stamped into the cosignature message.
    pub timestamp: u64,
    /// The witness's 64-byte Ed25519 signature.
    pub signature: [u8; 64],
}

/// A cosigned tree head (checkpoint): the log's signed `(size, root)` plus the
/// witness cosignatures over the same head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub size: u64,
    pub root: [u8; 32],
    /// The log's 64-byte Ed25519 signature over the signed-tree-head bytes.
    pub log_signature: [u8; 64],
    pub cosignatures: Vec<Cosignature>,
}

/// Why a checkpoint failed to authenticate. Every variant means "do NOT trust
/// this root".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    /// The log's own signature over the tree head did not verify (or the log
    /// key is not a valid Ed25519 point).
    LogSignature,
    /// Fewer than `need` distinct policy witnesses produced a valid
    /// cosignature over this head.
    QuorumNotMet { have: usize, need: usize },
}

/// A Sigsum key hash: `SHA256(raw 32-byte Ed25519 public key)`.
fn key_hash(pubkey: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(pubkey).into()
}

/// Standard base64 (RFC 4648 §4, `=`-padded) of arbitrary bytes. Hand-rolled
/// to keep the PUBLIC crate's dependency set minimal (`ed25519-dalek` is the
/// one deliberately-approved addition). A bug here is SELF-REVEALING: the
/// encoded root feeds the Ed25519 message that must verify against a real log
/// and witness signature — a wrong encoding fails [`verify_checkpoint`] against
/// the frozen real oracle.
fn base64_standard(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// The exact bytes the LOG signs (the signed tree head).
fn treehead_signed_bytes(log_key_hash: &[u8; 32], size: u64, root: &[u8; 32]) -> Vec<u8> {
    format!(
        "sigsum.org/v1/tree/{}\n{}\n{}\n",
        hex::encode(log_key_hash),
        size,
        base64_standard(root)
    )
    .into_bytes()
}

/// The exact bytes a WITNESS signs (c2sp `tlog-cosignature`).
fn cosignature_signed_bytes(
    log_key_hash: &[u8; 32],
    timestamp: u64,
    size: u64,
    root: &[u8; 32],
) -> Vec<u8> {
    format!(
        "cosignature/v1\ntime {}\nsigsum.org/v1/tree/{}\n{}\n{}\n",
        timestamp,
        hex::encode(log_key_hash),
        size,
        base64_standard(root)
    )
    .into_bytes()
}

/// Verify an Ed25519 signature. Returns `false` (never panics) if the public
/// key is not a valid curve point or the signature does not verify.
/// `verify_strict` rejects the small-order / non-canonical edge cases.
fn ed25519_verify(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(pubkey) {
        Ok(vk) => vk.verify_strict(message, &Signature::from_bytes(signature)).is_ok(),
        Err(_) => false,
    }
}

/// The RFC 6962 leaf hash of a Sigsum leaf — what BINDS an anchor submission
/// to a Merkle leaf: `SHA256(0x00 || checksum || signature || key_hash)` over
/// the 128-byte Sigsum leaf (`checksum(32) || signature(64) || key_hash(32)`).
/// Reuses [`crate::merkle::leaf_hash`] (one RFC 6962 primitive, not a second
/// copy). CONFIRMED against real `test.sigsum.org` leaf 196053.
pub fn tree_leaf_hash(checksum: &[u8; 32], signature: &[u8; 64], key_hash: &[u8; 32]) -> [u8; 32] {
    let mut leaf_data = Vec::with_capacity(128);
    leaf_data.extend_from_slice(checksum);
    leaf_data.extend_from_slice(signature);
    leaf_data.extend_from_slice(key_hash);
    crate::merkle::leaf_hash(&leaf_data)
}

/// Verify a cosigned checkpoint against a PINNED policy. Returns the
/// AUTHENTICATED `root` iff BOTH:
///   (a) the LOG's signature over the signed-tree-head verifies, AND
///   (b) at least `policy.quorum_k` DISTINCT policy witnesses each have a valid
///       cosignature over this head.
///
/// Counting is by DISTINCT policy witness (a witness cosigning twice counts
/// once; a duplicate `key_hash` cannot inflate the quorum). Cosignatures from
/// witnesses OUTSIDE the pinned policy are ignored (acceptance rule: the
/// CURRENT pinned policy, not whoever happened to cosign).
pub fn verify_checkpoint(
    policy: &WitnessPolicy,
    checkpoint: &Checkpoint,
) -> Result<[u8; 32], CheckpointError> {
    let log_kh = key_hash(&policy.log_pubkey);

    // (a) The log must have signed this head.
    let th_msg = treehead_signed_bytes(&log_kh, checkpoint.size, &checkpoint.root);
    if !ed25519_verify(&policy.log_pubkey, &th_msg, &checkpoint.log_signature) {
        return Err(CheckpointError::LogSignature);
    }

    // (b) Count DISTINCT policy witnesses with a valid cosignature over this
    // head. A witness cosigning twice counts once (we search per policy
    // witness); a duplicate ENTRY in the pinned policy also counts once (we
    // skip a policy key already counted). `quorum_k >= 1` and distinct
    // witnesses are pinned-artifact invariants; the dedup here is
    // defensive so a malformed pinned policy cannot inflate the quorum.
    let mut counted: Vec<[u8; 32]> = Vec::new();
    for witness in &policy.witnesses {
        if counted.contains(witness) {
            continue;
        }
        let wkh = key_hash(witness);
        let ok = checkpoint
            .cosignatures
            .iter()
            .filter(|c| c.key_hash == wkh)
            .any(|c| {
                let msg =
                    cosignature_signed_bytes(&log_kh, c.timestamp, checkpoint.size, &checkpoint.root);
                ed25519_verify(witness, &msg, &c.signature)
            });
        if ok {
            counted.push(*witness);
        }
    }
    let have = counted.len();
    if have < policy.quorum_k {
        return Err(CheckpointError::QuorumNotMet {
            have,
            need: policy.quorum_k,
        });
    }

    Ok(checkpoint.root)
}

/// A single anchored leaf's inclusion evidence: the anchor FACT (a [`Lane`],
/// which re-serializes to the canonical preimage and hence the checksum) plus
/// the Sigsum SUBMISSION bytes (the submitter's signature over the checksum
/// and the submitter key hash) and the inclusion PROOF. Fields are carried
/// STRUCTURED — the `anchor.json` serde that transports them lives in
/// [`crate::anchor_package`] (the producer contract), deliberately not
/// frozen here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredLeaf {
    /// The anchor fact; re-serialized to the canonical preimage → checksum.
    pub lane: Lane,
    /// The submitter's 64-byte Ed25519 signature stored in the Sigsum leaf.
    pub submitter_signature: [u8; 64],
    /// `SHA256(submitter public key)` stored in the Sigsum leaf.
    pub submitter_key_hash: [u8; 32],
    /// The leaf's 0-based index in the tree.
    pub index: u64,
    /// The RFC 6962 inclusion (audit) path, bottom-up.
    pub inclusion_proof: Vec<[u8; 32]>,
}

/// The single-leaf INCLUSION COMPONENT of the anchor consistency line — NOT
/// the whole anchor gate. The full gate is this (per-leaf inclusion +
/// producer identity + tenant slug) PLUS the package-level JOIN
/// ([`crate::anchor::verify_consistencia`]) PLUS completeness/enumeration and
/// `C_audit` freshness ([`crate::anchor_completitud`]). This function does
/// NOT prove completeness or recency; [`crate::anchor_package`] is the
/// caller that composes all the pieces behind the CLI.
///
/// Composes the AUTHENTICATED root ([`verify_checkpoint`]) with the leaf
/// binding ([`tree_leaf_hash`]) and the inclusion proof
/// ([`crate::merkle::verify_inclusion`]). Returns `Verdict::Verified` iff ALL
/// hold:
///   (0) slug↔tenant binding — the leaf belongs to `tenant_slug` (so an
///       attacker cannot pass off ANOTHER tenant's leaf from the SHARED log —
///       a dual-review finding). `rotate` leaves have no slug and are out of
///       scope for this single-tenant gate.
///   (0b) producer-identity binding — `leaf.submitter_key_hash` is in
///       `accepted_submitter_key_hashes`, the PINNED producer key set (the
///       vendor's Sigsum submitter identity, followed from the genesis key via
///       the `rotate` lane). Inclusion ALONE does not make a leaf the
///       vendor's: a provider could anchor a FABRICATED fact under a fresh key
///       on the shared log and get a real proof. DERIVING this set from
///       genesis+rotate is [`crate::anchor::derive_producer_identity_set`]'s
///       job; here the caller supplies it.
///   (1) the checkpoint authenticates a root under the pinned quorum;
///   (2) the fact re-serializes to a canonical `v1` preimage (else it is an
///       unexplained leaf ⇒ `FAILED` — omission or ambiguity never verifies);
///   (3) the fact's checksum, bound via `tree_leaf_hash` to the submission, is
///       included in the tree at the AUTHENTICATED root.
///
/// Note: the submitter SIGNATURE is folded into the leaf hash (it is part of
/// the Sigsum leaf) but is NOT verified against a producer key here — identity
/// is bound by the `submitter_key_hash` set-membership check (0b), not by
/// re-verifying the submission signature.
///
/// What it turns [`crate::merkle::verify_inclusion`] into: a leaf whose root is
/// authenticated by the pinned quorum AND that is bound to our producer
/// identity and the audited tenant — a NECESSARY component of the anchor gate,
/// not the gate on its own.
pub fn verify_anchored_inclusion(
    tenant_slug: &str,
    accepted_submitter_key_hashes: &[[u8; 32]],
    policy: &WitnessPolicy,
    checkpoint: &Checkpoint,
    leaf: &AnchoredLeaf,
) -> Verdict {
    // (0) slug↔tenant binding. The audited slug must itself be well-formed, and
    // the leaf's slug must equal it. A `rotate` leaf (no slug) is not a
    // per-tenant fact and is rejected by this single-tenant gate.
    if !is_valid_slug(tenant_slug) {
        return Verdict::Failed {
            reason: format!("audited tenant slug is not a valid slug: {tenant_slug:?}"),
        };
    }
    match leaf.lane.slug() {
        Some(slug) if slug == tenant_slug => {}
        Some(other) => {
            return Verdict::Failed {
                reason: format!(
                    "leaf slug {other:?} does not match the audited tenant {tenant_slug:?} — \
                     a leaf from the shared log belonging to a different tenant"
                ),
            }
        }
        None => {
            return Verdict::Failed {
                reason: "leaf has no tenant slug (rotate lane) — not a per-tenant anchored fact"
                    .to_string(),
            }
        }
    }

    // (0b) producer-identity binding. Inclusion in the shared cosigned log does
    // NOT make a leaf ours: a provider could submit a fabricated fact's checksum
    // under a FRESH key and get a real inclusion proof. The leaf's submitter
    // must be in the PINNED producer key set (the genesis key and its `rotate`
    // rotations). Deriving that set by following the rotate lane from the
    // pinned genesis is [`crate::anchor::derive_producer_identity_set`]'s job;
    // the caller supplies it.
    if !accepted_submitter_key_hashes.contains(&leaf.submitter_key_hash) {
        return Verdict::Failed {
            reason: "leaf submitter key is not in the pinned producer identity set — \
                     inclusion in the shared log does not make the leaf ours"
                .to_string(),
        };
    }

    // (1) Authenticate the root under the pinned witness quorum.
    let root = match verify_checkpoint(policy, checkpoint) {
        Ok(root) => root,
        Err(e) => {
            return Verdict::Failed {
                reason: format!("checkpoint not authenticated by pinned quorum: {e:?}"),
            }
        }
    };

    // (2) Re-derive the anchor checksum from the fact (Lane → preimage →
    // SHA256(SHA256(preimage))). An unexplained leaf FAILS here.
    let preimage = match serialize_preimage(&leaf.lane) {
        Ok(preimage) => preimage,
        Err(e) => {
            return Verdict::Failed {
                reason: format!("unexplained leaf (does not serialize to v1): {e:?}"),
            }
        }
    };
    let checksum = leaf_checksum(&preimage);

    // (3) Bind fact → Sigsum leaf → Merkle leaf, then prove inclusion against
    // the AUTHENTICATED root.
    let merkle_leaf = tree_leaf_hash(&checksum, &leaf.submitter_signature, &leaf.submitter_key_hash);
    if crate::merkle::verify_inclusion(
        leaf.index,
        checkpoint.size,
        merkle_leaf,
        &leaf.inclusion_proof,
        root,
    ) {
        Verdict::Verified
    } else {
        Verdict::Failed {
            reason: "leaf is not included in the authenticated tree — the anchored fact is not \
                     in the cosigned log"
                .to_string(),
        }
    }
}

/// The rotate-inclusion GATE — verify a `rotate` leaf's inclusion under the
/// cosigned checkpoint and, ONLY on success, yield the [`RotationRecord`] the
/// identity derivation ([`crate::anchor::derive_producer_identity_set`])
/// consumes. This is what discharges the HARD precondition the derivation's
/// module note pins: `submitter_key_hash` is trustworthy ONLY because the
/// inclusion of THIS leaf under the cosigned checkpoint was verified first.
///
/// It does NOT bind the leaf to a tenant slug (a `rotate` has none) nor to the
/// producer identity set (that would be circular — the set is being DERIVED from
/// these very leaves). Its ONLY job is: authenticate the root, re-derive the
/// checksum from the fact, bind it to the Sigsum leaf via [`tree_leaf_hash`], and
/// prove inclusion. Sigsum binds the leaf's submitter `key_hash` to that same
/// checksum (= SHA256 of the rotate PAYLOAD), so a verified inclusion
/// cryptographically ties submitter↔payload — which is exactly what makes the
/// derivation's `submitter_key_hash == key_hash_old` authorization test
/// sound.
///
/// Returns the [`RotationRecord`] on a fully verified inclusion, or a
/// `Verdict::Failed` (with a reason) otherwise. A non-`rotate` lane is a usage
/// error and fails: per-tenant leaves go through [`verify_anchored_inclusion`].
pub fn verify_rotate_inclusion(
    policy: &WitnessPolicy,
    checkpoint: &Checkpoint,
    leaf: &AnchoredLeaf,
) -> Result<RotationRecord, Verdict> {
    // The gate is for the identity lane only. A per-tenant leaf here is misuse.
    let (rot_ordinal, key_hash_old, key_hash_new) = match &leaf.lane {
        Lane::Rotate {
            rot_ordinal,
            key_hash_old,
            key_hash_new,
        } => (*rot_ordinal, key_hash_old.clone(), key_hash_new.clone()),
        other => {
            return Err(Verdict::Failed {
                reason: format!(
                    "verify_rotate_inclusion called on a non-rotate lane: {other:?}"
                ),
            })
        }
    };

    // (1) Authenticate the root under the pinned witness quorum.
    let root = match verify_checkpoint(policy, checkpoint) {
        Ok(root) => root,
        Err(e) => {
            return Err(Verdict::Failed {
                reason: format!("checkpoint not authenticated by pinned quorum: {e:?}"),
            })
        }
    };

    // (2) Re-derive the anchor checksum from the fact. An unexplained rotate
    // preimage FAILS here (defense in depth; the payload hex is also revalidated
    // by the derivation).
    let preimage = match serialize_preimage(&leaf.lane) {
        Ok(preimage) => preimage,
        Err(e) => {
            return Err(Verdict::Failed {
                reason: format!("unexplained rotate leaf (does not serialize to v1): {e:?}"),
            })
        }
    };
    let checksum = leaf_checksum(&preimage);

    // (3) Bind fact → Sigsum leaf → Merkle leaf, then prove inclusion against the
    // AUTHENTICATED root. Only if this holds is `submitter_key_hash` trustworthy.
    let merkle_leaf = tree_leaf_hash(&checksum, &leaf.submitter_signature, &leaf.submitter_key_hash);
    if !crate::merkle::verify_inclusion(
        leaf.index,
        checkpoint.size,
        merkle_leaf,
        &leaf.inclusion_proof,
        root,
    ) {
        return Err(Verdict::Failed {
            reason: "rotate leaf is not included in the authenticated tree — its \
                     submitter identity is not attested by the cosigned log"
                .to_string(),
        });
    }

    // Verified inclusion ⇒ the log attested this submitter for THIS payload. Build
    // the record from the SAME leaf: submitter from the log, payload from the fact.
    Ok(RotationRecord {
        submitter_key_hash: leaf.submitter_key_hash,
        key_hash_old,
        key_hash_new,
        rot_ordinal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- helpers -----------------------------------------------------------

    /// Parse a 64-char lowercase-hex string into 32 bytes (test vectors).
    fn h32(hex_str: &str) -> [u8; 32] {
        hex::decode(hex_str).expect("valid hex").try_into().expect("32 bytes")
    }

    /// Parse a 128-char lowercase-hex string into a 64-byte signature.
    fn h64(hex_str: &str) -> [u8; 64] {
        hex::decode(hex_str).expect("valid hex").try_into().expect("64 bytes")
    }

    // ---- FROZEN REAL oracle ------------------------------------------------
    //
    // Captured from test.sigsum.org/barreleye and self-verified end-to-end
    // (log signature + 3 witness cosignatures + a 17-node inclusion proof for
    // real leaf 196053). These bytes are REAL — no synthetic signing — so a
    // tautology (Rust verifying Rust) is impossible: the log and the
    // witnesses made these signatures. The pinned policy is Glasklar's named
    // policy `sigsum-test1-2025` (barreleye + 3 witnesses, quorum 2-of-3). The
    // key set is CROSS-READ from two independent sources (the trust anchor);
    // verification here only rules out a transcription typo — it does not by
    // itself prove these are the canonical witnesses. The production quorum
    // is a separately pinned operator artifact.

    const LOG_PK: &str = "4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6";
    const WIT_NISSE: &str = "1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c";
    const WIT_RGDD: &str = "28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806";
    const WIT_SMARTIT: &str = "f4855a0f46e8a3e23bb40faf260ee57ab8a18249fa402f2ca2d28a60e1a3130e";

    const KH_NISSE: &str = "1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c";
    const KH_RGDD: &str = "70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc";
    const KH_SMARTIT: &str = "42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8";

    const CP_SIZE: u64 = 196372;
    const CP_ROOT: &str = "848aff0ecb7315a0fc1cc4a00c1065b51b4c269ff871dc2f048711892739a06e";
    const CP_LOG_SIG: &str = "c551769caf05b2cf2358d6b93f9582e1e878e2eb3ac65b06d20315dbf7ef78b0f9b956e82a215e61abe2f06d2b30d407e81e2f4247f3e0d03daa4436434c0503";
    const CP_TS: u64 = 1784740225;
    const COSIG_SMARTIT: &str = "e8859da78c26b746a2a0c3350fe0e9984c0b99233887d50dff9f2738a8b88b77026b7022e0fc73d690c450fd5affad18db2d535178e2773e3e8d7738813b740d";
    const COSIG_NISSE: &str = "da97cf997439732bbee15c4cf32d5a1040ff393e2a0fa05e14586f59ab6a387fd85f235014ccd2c9eee033b098cb5cfabd1a2c45f095deac08174c715c079b02";
    const COSIG_RGDD: &str = "b2fa95af7a17239fe2ea4a8bada2dcf36c480ee8eda4e3061fe8fb7c299825f6650bbd606cbd6ba6a7a40f92fbca20db4dd40f6063bb9432d3a55c9147a9090b";

    // Real anchored leaf 196053 = the head@42 example-tenant fact (the
    // pinned head-leaf preimage layout).
    const LEAF_INDEX: u64 = 196053;
    const LEAF_CHECKSUM: &str =
        "7980a962d631ff148d741308a9853a63a165de056ca1255fe3a9bfc7b277c792";
    const LEAF_SUBMITTER_SIG: &str = "9bb51335303c5c0a6cc7917ea97fbc5490b25b7f5bf320bdb8d678c688cc04a706d2c57e31824d6f80e6e1616666b7d871d7453c4830fc4440ab478a42015507";
    const LEAF_SUBMITTER_KH: &str =
        "b112398d0e531a2a1e49ac5a7e2d8d7cd80ab69485e7c97f36ad893ca543717d";
    const LEAF_HASH: &str = "604708b5ef48e42450e9711532a3a0c757ffcfb383c4d06c27b55412e67d46a4";
    const PROOF: &[&str] = &[
        "57954ec27540bec161ffebe796ad23ca9d3769cc131245e395fb0a3a397d130e",
        "771576ed460260a46ab3737e206f54beff92230ca8811f278deac631447e0470",
        "c5b5a29c5c1b4c04a558f70e40bc9577d2324cbea66e1c859bc3d4f26c58d83e",
        "1f86b8529603e401c6e43f17dd0d3c4ab1b6699052c9b04ffb9267b0836fb26f",
        "6d341bc07fafaf60392044e64cf9eaa12bdd97b589a645c860f2d2c9c2925aac",
        "86e3e828b940919b1fe34cbf238eaae3d4561dcaf974e828a855175d8b65fdeb",
        "e8678a6c7e857d489d6fcefd4bbfcf6c9168b2b4e29395d7aa5f8371ae610737",
        "e029a3edb1e91b2f65f569627fd19a592fe3a9221ce01819f58dc7bd31ae98ad",
        "60f3a15100b723cb4b37c79e1b39b0f3bf39326fbb810c59e13fe32d14105fe0",
        "7f45ba88ef99f21b0fd081a401fa0a8782954be5458ef916f7e9e46cfb49c9e4",
        "ce7d3d60bddef51351c90ed469c5140030a6e8f87a87d6b4f20cd8eaf6c55081",
        "425bdfab555c08a4ca2f753da727ffc34f01c568eb0bd7cf27603bd8a29d55f3",
        "2ebbadd1c82f077533f2904f4cc3e89fa9112d97ac982115b4f92d08e759b5ce",
        "2f22287841aca348a0e5e38650bfc1506744dc6acc06b5812bdce30c399ead98",
        "84b0f8a1d9c6e04ab627cde4506c9a7105683a935e8a3d988176d12b191e3f28",
        "20065aca59c5b73c0fd5cf20ddeecc66b5f054b6bcf13c6a05bc0e374ab8423c",
        "43bd28c79dec46786a85bdf0fe72eac3985a8fa172979cdbf7dc04d6c506d43d",
    ];

    /// The pinned test policy (Glasklar `sigsum-test1-2025`): barreleye + 3
    /// witnesses, quorum 2-of-3. This is the pinned witness-policy artifact
    /// for the TEST tier; the production quorum is a separately pinned,
    /// operator-controlled artifact.
    fn test_policy() -> WitnessPolicy {
        WitnessPolicy {
            log_pubkey: h32(LOG_PK),
            witnesses: vec![h32(WIT_NISSE), h32(WIT_RGDD), h32(WIT_SMARTIT)],
            quorum_k: 2,
        }
    }

    fn cosig(kh: &str, sig: &str) -> Cosignature {
        Cosignature {
            key_hash: h32(kh),
            timestamp: CP_TS,
            signature: h64(sig),
        }
    }

    /// The frozen real checkpoint with all 3 policy cosignatures.
    fn real_checkpoint() -> Checkpoint {
        Checkpoint {
            size: CP_SIZE,
            root: h32(CP_ROOT),
            log_signature: h64(CP_LOG_SIG),
            cosignatures: vec![
                cosig(KH_SMARTIT, COSIG_SMARTIT),
                cosig(KH_NISSE, COSIG_NISSE),
                cosig(KH_RGDD, COSIG_RGDD),
            ],
        }
    }

    fn real_leaf() -> AnchoredLeaf {
        AnchoredLeaf {
            lane: Lane::Head {
                slug: "example-tenant".to_string(),
                ordinal: 42,
                chain_hash: "5fe66186d8e2100608f5b914fe260f08c57cc894087966a637f452a0f606c689"
                    .to_string(),
            },
            submitter_signature: h64(LEAF_SUBMITTER_SIG),
            submitter_key_hash: h32(LEAF_SUBMITTER_KH),
            index: LEAF_INDEX,
            inclusion_proof: PROOF.iter().map(|p| h32(p)).collect(),
        }
    }

    // ---- base64 (self-check + known vectors) -------------------------------

    #[test]
    fn base64_known_vectors() {
        // RFC 4648 §10 test vectors.
        assert_eq!(base64_standard(b""), "");
        assert_eq!(base64_standard(b"f"), "Zg==");
        assert_eq!(base64_standard(b"fo"), "Zm8=");
        assert_eq!(base64_standard(b"foo"), "Zm9v");
        assert_eq!(base64_standard(b"foob"), "Zm9vYg==");
        assert_eq!(base64_standard(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_standard(b"foobar"), "Zm9vYmFy");
    }

    // ---- tree_leaf_hash: REAL binding --------------------------------------

    #[test]
    fn tree_leaf_hash_matches_real_sigsum_leaf() {
        // The binding that ties the real submission to its real Merkle leaf.
        let lh = tree_leaf_hash(
            &h32(LEAF_CHECKSUM),
            &h64(LEAF_SUBMITTER_SIG),
            &h32(LEAF_SUBMITTER_KH),
        );
        assert_eq!(hex::encode(lh), LEAF_HASH);
    }

    // ---- verify_checkpoint: REAL positive ----------------------------------

    #[test]
    fn checkpoint_real_verifies_and_returns_root() {
        let got = verify_checkpoint(&test_policy(), &real_checkpoint());
        assert_eq!(got, Ok(h32(CP_ROOT)));
    }

    #[test]
    fn checkpoint_verifies_with_exactly_quorum() {
        // Drop one cosignature: 2 of 3 remain — exactly the quorum.
        let mut cp = real_checkpoint();
        cp.cosignatures.remove(0);
        assert_eq!(verify_checkpoint(&test_policy(), &cp), Ok(h32(CP_ROOT)));
    }

    // ---- verify_checkpoint: falsifiers -------------------------------------

    #[test]
    fn checkpoint_rejects_tampered_log_signature() {
        let mut cp = real_checkpoint();
        cp.log_signature[0] ^= 0x01;
        assert_eq!(
            verify_checkpoint(&test_policy(), &cp),
            Err(CheckpointError::LogSignature)
        );
    }

    #[test]
    fn checkpoint_rejects_tampered_root() {
        // A different root breaks the LOG signature first (it signs the root).
        let mut cp = real_checkpoint();
        cp.root[0] ^= 0x01;
        assert!(matches!(
            verify_checkpoint(&test_policy(), &cp),
            Err(CheckpointError::LogSignature)
        ));
    }

    #[test]
    fn checkpoint_rejects_when_below_quorum() {
        // Only one valid policy cosignature present ⇒ 1 < 2.
        let mut cp = real_checkpoint();
        cp.cosignatures.truncate(1);
        assert_eq!(
            verify_checkpoint(&test_policy(), &cp),
            Err(CheckpointError::QuorumNotMet { have: 1, need: 2 })
        );
    }

    #[test]
    fn checkpoint_ignores_cosignatures_outside_policy() {
        // A policy that lists only ONE witness, quorum 2: the head has 3 valid
        // cosignatures but only one is in-policy ⇒ 1 < 2 ⇒ FAIL. Proves the
        // acceptance rule counts POLICY witnesses, not whoever cosigned.
        let policy = WitnessPolicy {
            log_pubkey: h32(LOG_PK),
            witnesses: vec![h32(WIT_NISSE)],
            quorum_k: 2,
        };
        assert_eq!(
            verify_checkpoint(&policy, &real_checkpoint()),
            Err(CheckpointError::QuorumNotMet { have: 1, need: 2 })
        );
    }

    #[test]
    fn checkpoint_counts_duplicate_witness_once() {
        // A witness cosigning twice must NOT inflate the quorum. Policy lists
        // one witness (nisse), quorum 2; the head carries nisse's real
        // cosignature DUPLICATED ⇒ still only 1 distinct policy witness ⇒ FAIL.
        let policy = WitnessPolicy {
            log_pubkey: h32(LOG_PK),
            witnesses: vec![h32(WIT_NISSE)],
            quorum_k: 2,
        };
        let cp = Checkpoint {
            size: CP_SIZE,
            root: h32(CP_ROOT),
            log_signature: h64(CP_LOG_SIG),
            cosignatures: vec![cosig(KH_NISSE, COSIG_NISSE), cosig(KH_NISSE, COSIG_NISSE)],
        };
        assert_eq!(
            verify_checkpoint(&policy, &cp),
            Err(CheckpointError::QuorumNotMet { have: 1, need: 2 })
        );
    }

    #[test]
    fn checkpoint_rejects_forged_cosignature_for_policy_witness() {
        // A cosignature CLAIMING a policy witness's key_hash but with a signature
        // that does not verify ⇒ that witness does not count.
        let mut cp = real_checkpoint();
        // Corrupt smartit's cosignature bytes but keep its key_hash.
        cp.cosignatures[0].signature[0] ^= 0x01;
        // nisse + rgdd still valid = 2 ⇒ still passes; drop them to isolate.
        cp.cosignatures.retain(|c| c.key_hash == h32(KH_SMARTIT));
        assert_eq!(
            verify_checkpoint(&test_policy(), &cp),
            Err(CheckpointError::QuorumNotMet { have: 0, need: 2 })
        );
    }

    /// The pinned producer identity set for the TEST tier: the single key
    /// real leaf 196053 was submitted under. The real production genesis key
    /// and its rotations are pinned operator artifacts; deriving the set from
    /// the `rotate` lane is [`crate::anchor::derive_producer_identity_set`].
    /// This exercises the MECHANISM — set membership — with the real leaf's
    /// real submitter key.
    fn accepted_keys() -> [[u8; 32]; 1] {
        [h32(LEAF_SUBMITTER_KH)]
    }

    // ---- verify_anchored_inclusion: REAL end-to-end ------------------------

    #[test]
    fn anchored_inclusion_real_leaf_verifies() {
        let verdict = verify_anchored_inclusion(
            "example-tenant",
            &accepted_keys(),
            &test_policy(),
            &real_checkpoint(),
            &real_leaf(),
        );
        assert_eq!(verdict, Verdict::Verified);
    }

    #[test]
    fn anchored_inclusion_rejects_wrong_tenant() {
        // The crypto is ALL valid, but the leaf belongs to a DIFFERENT tenant
        // than the one being audited ⇒ FAILED. This is the shared-log
        // enumeration attack an adversarial review flagged.
        let verdict = verify_anchored_inclusion(
            "other-tenant",
            &accepted_keys(),
            &test_policy(),
            &real_checkpoint(),
            &real_leaf(),
        );
        assert!(matches!(verdict, Verdict::Failed { .. }));
    }

    #[test]
    fn anchored_inclusion_rejects_submitter_not_in_pinned_set() {
        // The crypto, slug and inclusion are ALL valid, but the leaf was
        // submitted under a key NOT in the pinned producer identity set ⇒
        // FAILED. This is the provider-forgery attack: anchoring a fabricated
        // fact under a FRESH key on the shared log. Empty set ⇒ nothing ours.
        let verdict = verify_anchored_inclusion(
            "example-tenant",
            &[],
            &test_policy(),
            &real_checkpoint(),
            &real_leaf(),
        );
        assert!(matches!(verdict, Verdict::Failed { .. }));
    }

    #[test]
    fn anchored_inclusion_rejects_unauthenticated_checkpoint() {
        let mut cp = real_checkpoint();
        cp.cosignatures.truncate(1); // below quorum
        let verdict = verify_anchored_inclusion(
            "example-tenant",
            &accepted_keys(),
            &test_policy(),
            &cp,
            &real_leaf(),
        );
        assert!(matches!(verdict, Verdict::Failed { .. }));
    }

    #[test]
    fn anchored_inclusion_rejects_tampered_proof() {
        let mut leaf = real_leaf();
        leaf.inclusion_proof[0][0] ^= 0x01;
        let verdict = verify_anchored_inclusion(
            "example-tenant",
            &accepted_keys(),
            &test_policy(),
            &real_checkpoint(),
            &leaf,
        );
        assert!(matches!(verdict, Verdict::Failed { .. }));
    }

    #[test]
    fn anchored_inclusion_rejects_tampered_submitter_signature() {
        // Changing the submitter signature changes the tree_leaf_hash ⇒ the
        // leaf is no longer in the tree at the authenticated root. (The
        // submitter key_hash is unchanged, so it still passes the identity set;
        // this isolates the inclusion binding.)
        let mut leaf = real_leaf();
        leaf.submitter_signature[0] ^= 0x01;
        let verdict = verify_anchored_inclusion(
            "example-tenant",
            &accepted_keys(),
            &test_policy(),
            &real_checkpoint(),
            &leaf,
        );
        assert!(matches!(verdict, Verdict::Failed { .. }));
    }

    #[test]
    fn anchored_inclusion_rejects_rotate_leaf_without_slug() {
        let leaf = AnchoredLeaf {
            lane: Lane::Rotate {
                rot_ordinal: 7,
                key_hash_old: "fa3580190786e1de2c17600bc6ce2e2785656b6b7c20154f14de9f39927bde77"
                    .to_string(),
                key_hash_new: "b1a5b27125d5774fa89405492bab3ef3b2a941f0307e21b0b0116668a161d2c4"
                    .to_string(),
            },
            ..real_leaf()
        };
        let verdict = verify_anchored_inclusion(
            "example-tenant",
            &accepted_keys(),
            &test_policy(),
            &real_checkpoint(),
            &leaf,
        );
        assert!(matches!(verdict, Verdict::Failed { .. }));
    }

    // ---- verify_rotate_inclusion: REAL rotate leaf 196056 ------------------
    //
    // A REAL rotate leaf (the pinned rotate-leaf preimage layout), anchored
    // under the SAME throwaway key as leaf 196053, inclusion-proven against
    // THIS frozen checkpoint — captured from the live log. NON-TAUTOLOGICAL:
    // the log made these signatures. The rotate PAYLOAD (old=fa358019…,
    // new=b1a5b271…) is DISTINCT from the log submitter (b112398d…) — the
    // submitter≠payload distinction.

    const ROTATE_INDEX: u64 = 196056;
    const ROTATE_SUBMITTER_SIG: &str = "bf93e2454755ad71d54c2b31d93199907a18a87baeb27cf56ff7cf458d7f372826592c4fde26a787d486520ee6245795112f5aef36b6c22e039e68ec75f57403";
    // Same submitter key hash as the HEAD leaf (one throwaway key for all 4).
    const ROTATE_SUBMITTER_KH: &str =
        "b112398d0e531a2a1e49ac5a7e2d8d7cd80ab69485e7c97f36ad893ca543717d";
    // Rotate payload (pinned rotate-leaf preimage layout) — NOT the submitter.
    const ROTATE_ORDINAL: u64 = 7;
    const ROTATE_OLD: &str = "fa3580190786e1de2c17600bc6ce2e2785656b6b7c20154f14de9f39927bde77";
    const ROTATE_NEW: &str = "b1a5b27125d5774fa89405492bab3ef3b2a941f0307e21b0b0116668a161d2c4";
    const ROTATE_PROOF: &[&str] = &[
        "14020122279afd01f4ae7e54bd8482453cc5a8b1d6c91ef26e6721076a1be0c8",
        "aa069aabd8ec74fff7edc10388706f1f8dd6b5f5093cf8cda0840c07adfb7c4c",
        "a99f3c8c69c4842f0f117aeef8638f512c6aaf9f2a6b318532e96f1351c0bd5a",
        "30e0bba48fe634f6815ae77c2d457e78f6593a983225957efb10373d16263c98",
        "6d341bc07fafaf60392044e64cf9eaa12bdd97b589a645c860f2d2c9c2925aac",
        "86e3e828b940919b1fe34cbf238eaae3d4561dcaf974e828a855175d8b65fdeb",
        "e8678a6c7e857d489d6fcefd4bbfcf6c9168b2b4e29395d7aa5f8371ae610737",
        "e029a3edb1e91b2f65f569627fd19a592fe3a9221ce01819f58dc7bd31ae98ad",
        "60f3a15100b723cb4b37c79e1b39b0f3bf39326fbb810c59e13fe32d14105fe0",
        "7f45ba88ef99f21b0fd081a401fa0a8782954be5458ef916f7e9e46cfb49c9e4",
        "ce7d3d60bddef51351c90ed469c5140030a6e8f87a87d6b4f20cd8eaf6c55081",
        "425bdfab555c08a4ca2f753da727ffc34f01c568eb0bd7cf27603bd8a29d55f3",
        "2ebbadd1c82f077533f2904f4cc3e89fa9112d97ac982115b4f92d08e759b5ce",
        "2f22287841aca348a0e5e38650bfc1506744dc6acc06b5812bdce30c399ead98",
        "84b0f8a1d9c6e04ab627cde4506c9a7105683a935e8a3d988176d12b191e3f28",
        "20065aca59c5b73c0fd5cf20ddeecc66b5f054b6bcf13c6a05bc0e374ab8423c",
        "43bd28c79dec46786a85bdf0fe72eac3985a8fa172979cdbf7dc04d6c506d43d",
    ];

    fn real_rotate_leaf() -> AnchoredLeaf {
        AnchoredLeaf {
            lane: Lane::Rotate {
                rot_ordinal: ROTATE_ORDINAL,
                key_hash_old: ROTATE_OLD.to_string(),
                key_hash_new: ROTATE_NEW.to_string(),
            },
            submitter_signature: h64(ROTATE_SUBMITTER_SIG),
            submitter_key_hash: h32(ROTATE_SUBMITTER_KH),
            index: ROTATE_INDEX,
            inclusion_proof: ROTATE_PROOF.iter().map(|p| h32(p)).collect(),
        }
    }

    #[test]
    fn rotate_inclusion_real_leaf_yields_record() {
        // Real crypto: the log included this rotate leaf under the cosigned
        // checkpoint ⇒ the gate yields a RotationRecord carrying the LOG-ATTESTED
        // submitter and the leaf's own payload.
        let got = verify_rotate_inclusion(&test_policy(), &real_checkpoint(), &real_rotate_leaf());
        assert_eq!(
            got,
            Ok(RotationRecord {
                submitter_key_hash: h32(ROTATE_SUBMITTER_KH),
                key_hash_old: ROTATE_OLD.to_string(),
                key_hash_new: ROTATE_NEW.to_string(),
                rot_ordinal: ROTATE_ORDINAL,
            })
        );
    }

    #[test]
    fn rotate_inclusion_rejects_non_rotate_lane() {
        // A HEAD leaf is not a rotate — the gate is for the identity lane only.
        let got = verify_rotate_inclusion(&test_policy(), &real_checkpoint(), &real_leaf());
        assert!(matches!(got, Err(Verdict::Failed { .. })));
    }

    #[test]
    fn rotate_inclusion_rejects_tampered_proof() {
        // Real negative: flip one proof node ⇒ the leaf is NOT in the tree at the
        // authenticated root ⇒ no record. This is the load-bearing inclusion
        // binding (mutation target for the RED proof).
        let mut leaf = real_rotate_leaf();
        leaf.inclusion_proof[0][0] ^= 0x01;
        let got = verify_rotate_inclusion(&test_policy(), &real_checkpoint(), &leaf);
        assert!(matches!(got, Err(Verdict::Failed { .. })));
    }

    #[test]
    fn rotate_inclusion_rejects_unauthenticated_checkpoint() {
        let mut cp = real_checkpoint();
        cp.cosignatures.truncate(1); // below quorum
        let got = verify_rotate_inclusion(&test_policy(), &cp, &real_rotate_leaf());
        assert!(matches!(got, Err(Verdict::Failed { .. })));
    }

    /// INTENT: the `RotationRecord` the gate yields carries the leaf's LOG-ATTESTED
    ///   `submitter_key_hash` (bound to the payload by the VERIFIED inclusion),
    ///   NEVER the payload `key_hash_old`. This is the submitter≠payload
    ///   distinction made structural: only a leaf whose inclusion under the
    ///   cosigned checkpoint is verified yields a record, and its submitter is
    ///   the one the log attested — which is what makes the derivation's
    ///   `submitter==old` authorization test meaningful (the caller obligation
    ///   the module note pins).
    /// CONTEXT: without verifying inclusion first, `submitter_key_hash` is
    ///   attacker-controlled and the whole identity derivation is unsound
    ///   (caught by a blind adversarial review).
    /// EXPIRES IF: the rotate leaf format or the Sigsum submitter binding changes.
    #[test]
    fn test_intent_rotate_record_carries_log_attested_submitter() {
        let rec = verify_rotate_inclusion(&test_policy(), &real_checkpoint(), &real_rotate_leaf())
            .expect("real included rotate leaf yields a record");
        // The record's submitter is the log-attested one, DISTINCT from the payload.
        assert_eq!(rec.submitter_key_hash, h32(ROTATE_SUBMITTER_KH));
        assert_ne!(
            hex::encode(rec.submitter_key_hash),
            rec.key_hash_old,
            "submitter must not be confused with the payload old key"
        );
        // A leaf whose inclusion does NOT verify yields NO record at all.
        let mut broken = real_rotate_leaf();
        broken.inclusion_proof[0][0] ^= 0x01;
        assert!(verify_rotate_inclusion(&test_policy(), &real_checkpoint(), &broken).is_err());
    }

    // ---- intent tests (COMPLEX discipline) ---------------------------------

    /// INTENT: `verify_checkpoint` authenticates the root ONLY when the log
    ///   signed it AND a QUORUM of PINNED-POLICY witnesses cosigned it — the
    ///   whole point of the pinned-quorum design (a split-view then needs the
    ///   quorum, not just the log). The acceptance rule counts DISTINCT policy witnesses
    ///   under the CURRENT policy; cosignatures from non-policy witnesses do
    ///   not count and duplicates do not inflate.
    /// CONTEXT: without a witness quorum, a compromised (or coerced) log could
    ///   sign a split-view tree head; the pinned quorum is what makes the root
    ///   trustworthy enough to feed `merkle::verify_inclusion`.
    /// EXPIRES IF: the anchor moves off a cosigned-transparency-log model, or
    ///   the Sigsum tree-head/cosignature serialization changes (a v2 epoch),
    ///   in which case this module and the frozen oracle change together.
    #[test]
    fn test_intent_checkpoint_requires_log_and_witness_quorum() {
        let policy = test_policy();
        // Real, fully-cosigned head authenticates.
        assert!(verify_checkpoint(&policy, &real_checkpoint()).is_ok());
        // Remove the log's authorship ⇒ no root, regardless of witnesses.
        let mut no_log = real_checkpoint();
        no_log.log_signature = [0u8; 64];
        assert_eq!(
            verify_checkpoint(&policy, &no_log),
            Err(CheckpointError::LogSignature)
        );
        // Remove the quorum (strip witnesses) ⇒ no root, even with a valid log.
        let mut no_quorum = real_checkpoint();
        no_quorum.cosignatures.clear();
        assert_eq!(
            verify_checkpoint(&policy, &no_quorum),
            Err(CheckpointError::QuorumNotMet { have: 0, need: 2 })
        );
    }

    /// INTENT: the anchor gate binds a leaf to the AUDITED tenant. The offline
    ///   consistency checks and the crypto can all pass, yet a leaf that
    ///   belongs to ANOTHER tenant in the SHARED log must FAIL — otherwise an
    ///   attacker enumerates a victim tenant's leaves and presents them as the
    ///   audited tenant's anchor.
    /// CONTEXT: the design uses one SHARED Sigsum log for all tenants; a dual
    ///   adversarial review flagged (both reviewers, independently) that a
    ///   leaf's slug must be tied to the tenant under audit.
    /// EXPIRES IF: the anchor moves to a per-tenant log (no shared enumeration),
    ///   in which case the slug binding is redundant, not wrong.
    #[test]
    fn test_intent_leaf_bound_to_audited_tenant() {
        // Same real, fully-valid evidence; only the audited slug differs.
        assert_eq!(
            verify_anchored_inclusion(
                "example-tenant",
                &accepted_keys(),
                &test_policy(),
                &real_checkpoint(),
                &real_leaf()
            ),
            Verdict::Verified,
            "the leaf's own tenant verifies"
        );
        assert!(
            matches!(
                verify_anchored_inclusion(
                    "other-tenant",
                    &accepted_keys(),
                    &test_policy(),
                    &real_checkpoint(),
                    &real_leaf()
                ),
                Verdict::Failed { .. }
            ),
            "another tenant's audit must NOT accept this leaf from the shared log"
        );
    }

    /// INTENT: an accepted leaf must be bound to OUR pinned producer identity.
    ///   Inclusion in the SHARED cosigned log does NOT make a leaf ours: a
    ///   provider (the adversary in this audit model) can anchor a FABRICATED
    ///   fact under a fresh key and get a real inclusion proof against the real
    ///   cosigned checkpoint. Only membership of `submitter_key_hash` in the
    ///   pinned producer key set makes the leaf attributable to us.
    /// CONTEXT: the design uses ONE shared Sigsum log; the checkpoint and
    ///   proof are public, so without the identity binding any party could
    ///   mint a "valid" anchor for the audited tenant (two independent
    ///   adversarial reviews flagged this).
    /// EXPIRES IF: the anchor moves to a per-producer dedicated log whose
    ///   submitter identity is implied by the log key itself, making the
    ///   set-membership check redundant.
    #[test]
    fn test_intent_leaf_bound_to_pinned_producer_identity() {
        // Identical real evidence; only the accepted producer key set differs.
        assert_eq!(
            verify_anchored_inclusion(
                "example-tenant",
                &accepted_keys(), // the real leaf's submitter is in the set
                &test_policy(),
                &real_checkpoint(),
                &real_leaf()
            ),
            Verdict::Verified,
            "a leaf submitted by our pinned producer key verifies"
        );
        // A different pinned identity set (a fresh key that is NOT ours): the
        // same included, cosigned leaf must NOT be accepted as our anchor.
        let not_ours = [[0xABu8; 32]];
        assert!(
            matches!(
                verify_anchored_inclusion(
                    "example-tenant",
                    &not_ours,
                    &test_policy(),
                    &real_checkpoint(),
                    &real_leaf()
                ),
                Verdict::Failed { .. }
            ),
            "a leaf submitted under a key outside the pinned producer set must FAIL — \
             inclusion alone does not make it ours"
        );
    }
}
