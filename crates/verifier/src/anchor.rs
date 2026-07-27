// SPDX-License-Identifier: Apache-2.0
//! External-anchor verification — the `seetrex/anchor/v1` preimage
//! convention and the OFFLINE anchor-consistency verdict.
//!
//! The preimage convention is NORMATIVE and pinned here: the exact layouts
//! are implemented by [`serialize_preimage`] and frozen by REAL round-trip
//! test vectors against `test.sigsum.org` (the design went through a
//! 6-round dual adversarial review before freezing).
//!
//! This module is the PURE, offline core of the consistency line — preimage
//! re-serialization, the JOIN invariant (`M ≤ N`, head-leaf ↔ row equality)
//! and the intra-package `RETIRED` cross-check. The enumeration-dependent
//! completeness line (monitor, `C_audit` freshness, lane rules) lives in
//! [`crate::anchor_completitud`]; the inclusion-proof / cosigned checkpoint
//! crypto lives in [`crate::merkle`] and [`crate::checkpoint`].
//!
//! Dependency purity (`test_intent_verifier_crate_dependency_purity`): the
//! slug charset is validated by a hand-rolled full-string scan — NOT the
//! `regex` crate — which is both dependency-free and inherently ANCHORED
//! (an unanchored `is_match` over a substring would reintroduce the
//! `\0`-smuggling hole a full-string scan closes).

/// The tenant anchor mode. Closed set; any other `<mode>`
/// byte string in an `enroll` preimage is an unexplained leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Attested,
    Revocable,
}

impl Mode {
    /// The literal ASCII bytes serialized into the `enroll` preimage.
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Mode::Attested => b"attested",
            Mode::Revocable => b"revocable",
        }
    }
}

/// One anchored fact, typed by lane. The lane set is CLOSED:
/// `{head, enroll, retired, rotate}`. Fields are carried
/// STRUCTURED (not raw preimage bytes) so the verifier RE-SERIALIZES the
/// canonical preimage and re-derives the checksum — a leaf
/// that does not re-serialize byte-identical is FAILED.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lane {
    /// `seetrex/anchor/v1/head \0 <slug> \0 <ordinal> \0 <chain_hash>`
    Head {
        slug: String,
        ordinal: u64,
        chain_hash: String,
    },
    /// `seetrex/anchor/v1/enroll \0 <slug> \0 <mode>`
    Enroll { slug: String, mode: Mode },
    /// `seetrex/anchor/v1/retired \0 <slug> \0 <ordinal_final> \0 <chain_hash_final>`
    Retired {
        slug: String,
        ordinal_final: u64,
        chain_hash_final: String,
    },
    /// `seetrex/anchor/v1/rotate \0 <rot_ordinal> \0 <key_hash_old> \0 <key_hash_new>`
    Rotate {
        rot_ordinal: u64,
        key_hash_old: String,
        key_hash_new: String,
    },
}

impl Lane {
    /// The tenant slug this lane is about, if any. `head`/`enroll`/`retired`
    /// carry a slug; `rotate` is a log-signer key rotation with no tenant slug
    /// (it is bound to the genesis chain, not a tenant). Used by
    /// the anchor gate to bind a leaf to the AUDITED tenant, so an attacker
    /// cannot pass off another tenant's leaf from the SHARED log (a dual
    /// adversarial-review finding).
    pub fn slug(&self) -> Option<&str> {
        match self {
            Lane::Head { slug, .. }
            | Lane::Enroll { slug, .. }
            | Lane::Retired { slug, .. } => Some(slug),
            Lane::Rotate { .. } => None,
        }
    }
}

/// Why a lane could not be canonically serialized — every variant maps to
/// an "unexplained leaf ⇒ FAILED": a preimage the honest
/// producer could never have emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreimageError {
    /// Slug fails the pinned charset `^[a-z0-9][a-z0-9-]{7,31}$`.
    InvalidSlug { slug: String },
    /// A hash field is not exactly 64 lowercase hex digits.
    InvalidHashHex { field: &'static str, value: String },
    /// An ordinal is 0 (the canonical form is `[1-9][0-9]*`; genesis = 1).
    ZeroOrdinal { field: &'static str },
}

/// Anchored, full-string slug validation against the charset the producer's
/// storage layer already imposes as a DB CHECK constraint:
/// `^[a-z0-9][a-z0-9-]{7,31}$` (8–32 chars, lowercase alnum + hyphen, no
/// leading hyphen). The rule is DERIVED from that constraint, not invented.
///
/// Hand-rolled on purpose (dependency purity + anchoring): this scans
/// EVERY byte, so a `\0` or uppercase byte ANYWHERE fails — there is no
/// substring/anchoring hole a `regex::is_match` could leave open.
pub fn is_valid_slug(slug: &str) -> bool {
    let len = slug.len();
    if !(8..=32).contains(&len) {
        return false;
    }
    let mut chars = slug.chars();
    // First char: lowercase alnum, NO leading hyphen.
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    // Remaining chars: lowercase alnum or hyphen. Every byte is scanned, so a
    // `\0`, uppercase or any other byte ANYWHERE fails.
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// A hash field is EXACTLY 64 lowercase hex digits (`[0-9a-f]{64}`).
/// Uppercase, wrong length or non-hex ⇒ not a hash the honest producer
/// could have emitted.
fn is_valid_hash_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Serialize a lane into its canonical `seetrex/anchor/v1` preimage bytes,
/// validating every field against the pinned charset rules first.
/// NUL-separated; no field may contain `0x00` (guaranteed by the charsets),
/// so the separator is unambiguous.
pub fn serialize_preimage(lane: &Lane) -> Result<Vec<u8>, PreimageError> {
    // Validate every field against the pinned rules FIRST, then concatenate the
    // NUL-separated fields. Because no valid field can contain `0x00`, the
    // separator is unambiguous and the byte sequence is canonical.
    let check_slug = |slug: &str| -> Result<(), PreimageError> {
        if is_valid_slug(slug) {
            Ok(())
        } else {
            Err(PreimageError::InvalidSlug {
                slug: slug.to_string(),
            })
        }
    };
    let check_hash = |field: &'static str, value: &str| -> Result<(), PreimageError> {
        if is_valid_hash_hex(value) {
            Ok(())
        } else {
            Err(PreimageError::InvalidHashHex {
                field,
                value: value.to_string(),
            })
        }
    };
    let check_ordinal = |field: &'static str, ordinal: u64| -> Result<(), PreimageError> {
        if ordinal == 0 {
            Err(PreimageError::ZeroOrdinal { field })
        } else {
            Ok(())
        }
    };

    // Assemble from field byte-slices joined by a single `0x00`.
    let fields: Vec<Vec<u8>> = match lane {
        Lane::Head {
            slug,
            ordinal,
            chain_hash,
        } => {
            check_slug(slug)?;
            check_ordinal("ordinal", *ordinal)?;
            check_hash("chain_hash", chain_hash)?;
            vec![
                b"seetrex/anchor/v1/head".to_vec(),
                slug.as_bytes().to_vec(),
                ordinal.to_string().into_bytes(),
                chain_hash.as_bytes().to_vec(),
            ]
        }
        Lane::Enroll { slug, mode } => {
            check_slug(slug)?;
            vec![
                b"seetrex/anchor/v1/enroll".to_vec(),
                slug.as_bytes().to_vec(),
                mode.as_bytes().to_vec(),
            ]
        }
        Lane::Retired {
            slug,
            ordinal_final,
            chain_hash_final,
        } => {
            check_slug(slug)?;
            check_ordinal("ordinal_final", *ordinal_final)?;
            check_hash("chain_hash_final", chain_hash_final)?;
            vec![
                b"seetrex/anchor/v1/retired".to_vec(),
                slug.as_bytes().to_vec(),
                ordinal_final.to_string().into_bytes(),
                chain_hash_final.as_bytes().to_vec(),
            ]
        }
        Lane::Rotate {
            rot_ordinal,
            key_hash_old,
            key_hash_new,
        } => {
            check_ordinal("rot_ordinal", *rot_ordinal)?;
            check_hash("key_hash_old", key_hash_old)?;
            check_hash("key_hash_new", key_hash_new)?;
            vec![
                b"seetrex/anchor/v1/rotate".to_vec(),
                rot_ordinal.to_string().into_bytes(),
                key_hash_old.as_bytes().to_vec(),
                key_hash_new.as_bytes().to_vec(),
            ]
        }
    };

    Ok(fields.join(&0u8))
}

/// The value the Sigsum leaf carries: `SHA256(SHA256(preimage))`
/// (the pinned double-hash convention, verified empirically against
/// `test.sigsum.org`).
pub fn leaf_checksum(preimage: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let message = Sha256::digest(preimage);
    let checksum = Sha256::digest(message);
    checksum.into()
}

/// One of the two verdicts. `INCONCLUSO` is a first-class outcome, never a
/// collapse into either pole: `VERIFIED` must never depend
/// on a monitor being absent, and a missing monitor must never be read as
/// a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Verified,
    Failed { reason: String },
    Inconclusive { reason: String },
}

/// The two verdicts that NEVER collapse: `CONSISTENCIA`
/// (offline, over published material) and `COMPLETITUD`
/// (enumeration-dependent — `INCONCLUSO` by default until a monitor
/// enumeration is supplied to [`crate::anchor_completitud`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorReport {
    pub consistencia: Verdict,
    pub completitud: Verdict,
}

/// The OFFLINE `CONSISTENCIA` line — the pure JOIN half; the
/// inclusion-proof / cosigned-checkpoint crypto lives in
/// [`crate::checkpoint`] and is composed by [`crate::anchor_package`].
/// Given the published
/// chain rows and the anchor leaves, check
/// (1) the chain is well-formed (delegated to [`crate::chain_export::verify_public_chain`]);
/// (2) every leaf re-serializes to a canonical `v1` preimage (else it is an
///     "unexplained leaf" ⇒ `FAILED`);
/// (3) the JOIN: `M` = max HEAD ordinal in the package; `M ≤ N` and every
///     HEAD@k carries the byte-identical `chain_hash` of row k (a HEAD of
///     ordinal `> N` ⇒ `FAILED`, WITHOUT a monitor);
/// (4) the intra-package RETIRED cross-check: with a
///     RETIRED for the slug, require `ordinal_final = M` ∧
///     `chain_hash_final = head@M` ∧ no HEAD with ordinal `> ordinal_final`.
///
/// Returns `VERIFIED` / `FAILED`. It does NOT prove completeness (truncating
/// rows AND omitting their tail leaves passes here — `COMPLETITUD` catches it).
pub fn verify_consistencia(
    rows: &[crate::chain_export::PublicChainRow],
    leaves: &[Lane],
) -> Verdict {
    // (1) The chain is well-formed — delegated to the single source of truth
    // (genesis, contiguous ordinals 1..=N, link, per-row self-consistency).
    let head = match crate::chain_export::verify_public_chain(rows) {
        Ok(head) => head,
        Err(e) => {
            return Verdict::Failed {
                reason: format!("chain not well-formed: {e}"),
            }
        }
    };
    let n = u64::from(head.verdict_count); // = rows.len()

    // (2) Every leaf must re-serialize to a canonical `v1` preimage. A leaf
    // that cannot is an "unexplained leaf" — a preimage the honest producer
    // could never have emitted. This also guarantees every
    // HEAD/RETIRED ordinal is ≥ 1 below (serialize rejects 0), so the
    // `k - 1` row indexing is safe.
    for lane in leaves {
        if let Err(e) = serialize_preimage(lane) {
            return Verdict::Failed {
                reason: format!("unexplained leaf (does not serialize to v1): {e:?}"),
            };
        }
    }

    // (3) JOIN — HEAD leaves ↔ rows. M = max HEAD ordinal in the package.
    let mut max_head: Option<u64> = None;
    for lane in leaves {
        if let Lane::Head {
            ordinal,
            chain_hash,
            ..
        } = lane
        {
            let k = *ordinal;
            if k > n {
                // Truncation with a published tail leaf: the log proves a row
                // that the shortened export omits. FAILED without a monitor.
                return Verdict::Failed {
                    reason: format!(
                        "HEAD@{k} is anchored but beyond chain length N={n} — \
                         rows were truncated while their tail leaf stays published"
                    ),
                };
            }
            let row = &rows[(k - 1) as usize];
            if &row.chain_hash != chain_hash {
                // History rewritten under a fixed anchor: the anchored HEAD@k
                // carries a chain_hash the current row no longer reproduces.
                return Verdict::Failed {
                    reason: format!(
                        "HEAD@{k} chain_hash does not match row {k} — \
                         published history was rewritten under a fixed anchor"
                    ),
                };
            }
            max_head = Some(max_head.map_or(k, |m| m.max(k)));
        }
    }

    // (4) Intra-package RETIRED cross-check: a RETIRED
    // must sit exactly at the anchored tail — `ordinal_final = M` ∧
    // `chain_hash_final = head@M` ∧ (implied) no HEAD past it. A
    // self-contradictory package fails offline, without waiting for a monitor.
    for lane in leaves {
        if let Lane::Retired {
            ordinal_final,
            chain_hash_final,
            ..
        } = lane
        {
            let Some(m) = max_head else {
                return Verdict::Failed {
                    reason: "RETIRED present but no HEAD leaf to cross-check against"
                        .to_string(),
                };
            };
            if *ordinal_final != m {
                return Verdict::Failed {
                    reason: format!(
                        "RETIRED ordinal_final={ordinal_final} != max anchored HEAD M={m} — \
                         resurrection after retirement or a truncated wind-down"
                    ),
                };
            }
            let row_m = &rows[(m - 1) as usize];
            if chain_hash_final != &row_m.chain_hash {
                return Verdict::Failed {
                    reason: format!(
                        "RETIRED chain_hash_final does not match head@M (M={m}) — forged RETIRED"
                    ),
                };
            }
        }
    }

    Verdict::Verified
}

/// Top-level two-verdict entry for the OFFLINE case: no monitor enumeration
/// is consumed here (the enumeration-aware gate is
/// [`crate::anchor_completitud`]). `CONSISTENCIA`
/// being `VERIFIED` here never implies completeness.
pub fn verify_anchored(
    rows: &[crate::chain_export::PublicChainRow],
    leaves: &[Lane],
) -> AnchorReport {
    AnchorReport {
        consistencia: verify_consistencia(rows, leaves),
        completitud: Verdict::Inconclusive {
            reason: "no monitor enumeration supplied — COMPLETITUD is \
                     enumeration-dependent"
                .to_string(),
        },
    }
}

// ---- producer identity-set derivation --------------------------------
//
// The set of `key_hash`es the anchor gate accepts as the producer's is
// followed from a PINNED genesis key via the `rotate` lane. A rotation is only
// followed if it is AUTHORIZED by the old key it claims to rotate from —
// encoded structurally as `submitter_key_hash == key_hash_old` (a rotate must
// be signed by the old key; the leaf's SUBMISSION key hash and the rotate
// PAYLOAD key hashes are different things — confusing them opens an identity
// fork, so the derivation REQUIRES they agree for the old key).
//
// This layer is pure and offline: it does NO cryptography. It relies on a HARD
// PRECONDITION its caller MUST enforce: each `RotationRecord`'s
// `submitter_key_hash` AND its payload (`key_hash_old`/`key_hash_new`/
// `rot_ordinal`) are read from ONE AND THE SAME rotate leaf whose inclusion
// under the cosigned checkpoint has been verified. Sigsum checks the submission
// signature at add-leaf time and binds the leaf's `key_hash` (submitter) to its
// `checksum` = SHA256 of the preimage (the payload), so a verified inclusion
// cryptographically binds submitter↔payload — which is what makes the
// "submitter_key_hash == key_hash_old ⇒ authorized" test meaningful. WITHOUT
// that inclusion check upstream, `submitter_key_hash` is attacker-controlled and
// this derivation is NOT sound. (That obligation is ENFORCED by the caller
// [`crate::checkpoint::verify_rotate_inclusion`]: the derived set is only
// trustworthy over inclusion-verified rotations whose submitter and payload come
// from the same leaf. BOTH branches — authorized-extends and unauthorized-anomaly
// — have real-vector round-trip coverage.)

/// Why a `rotate` was NOT followed into the identity chain — surfaced, never
/// silently dropped (a published rotation nobody accounts for is where
/// tampering hides). The design does not pin, for the OFFLINE
/// case, whether such a rotation maps to `FAILED` or `INCONCLUSO`; that
/// enumeration-aware mapping is the wiring's call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyReason {
    /// `submitter_key_hash != key_hash_old`: the rotation was not submitted by
    /// the old key it claims to rotate from, so the old-key holder did not
    /// authorize it. A forged rotation naming a public key (e.g.
    /// the pinned genesis) as `key_hash_old` lands here and never extends the set.
    Unauthorized,
    /// Authorized (`submitter_key_hash == key_hash_old`) but the old key does not
    /// chain from the pinned genesis — a real rotation of a key outside our
    /// identity chain, irrelevant to our set but surfaced for the caller.
    OffChain,
}

/// A `rotate` that was not followed into the identity chain, with the reason.
/// Carries the log-attested `submitter_key_hash` so the wiring
/// can ATTRIBUTE the rotation: two distinct forgeries with the same payload but
/// different submitters are separate events, and must not collapse into one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnomalousRotation {
    /// The log-attested submitter of the rotate leaf.
    pub submitter_key_hash: [u8; 32],
    pub key_hash_old: [u8; 32],
    pub key_hash_new: [u8; 32],
    pub rot_ordinal: u64,
    pub reason: AnomalyReason,
}

/// The producer identity set derived from the pinned genesis key. `keys` is the
/// accepted-submitter set the anchor gate
/// ([`crate::checkpoint::verify_anchored_inclusion`]) filters against;
/// `anomalous_rotations` are rotations that were NOT followed (unauthorized or
/// off-chain), surfaced for the enumeration-aware wiring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySet {
    /// The identity chain, genesis first, then each rotation's new key in order.
    pub keys: Vec<[u8; 32]>,
    /// Rotations not followed into the chain, each with its [`AnomalyReason`].
    pub anomalous_rotations: Vec<AnomalousRotation>,
}

/// Why deriving the identity chain FAILED — a structural impossibility of the
/// ON-CHAIN history, not mere incompleteness. `Fork`/`Cycle` are enumeration-
/// INDEPENDENT structural reports; the `FAILED`-vs-`INCONCLUSO` verdict
/// mapping (two rotations from the same key ⇒ FAILED under enumeration;
/// without a monitor they merely coexist ⇒ INCONCLUSO) is the wiring's call,
/// not this pure derivation's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// A `rotate` payload key_hash is not exactly 64 lowercase hex digits — a
    /// malformed-input guard (NOT a structural chain fault). `serialize_preimage`
    /// also enforces this; the derivation validates independently (defense in
    /// depth — the payloads are `String`s the caller supplies).
    InvalidKeyHashHex { field: &'static str, value: String },
    /// The ON-CHAIN key `key_hash_old` sources ≥2 DISTINCT authorized rotations —
    /// the identity chain bifurcates at a key we actually reach, so no successor
    /// can be chosen (successor uniqueness). Only forks on the reachable
    /// chain error; off-chain forks are surfaced as [`AnomalyReason::OffChain`],
    /// never aborting our derivation.
    Fork { key_hash_old: [u8; 32] },
    /// Following the chain from genesis revisits a key already in the set — a
    /// cycle no honest append-only rotation can produce.
    Cycle { key_hash: [u8; 32] },
}

/// One `rotate` leaf as the identity derivation consumes it: the log-attested
/// SUBMITTER key hash plus the rotate PAYLOAD (`key_hash_old`/`key_hash_new` as
/// 64-lowercase-hex, `rot_ordinal`). The derivation follows a rotation only if
/// `submitter_key_hash == key_hash_old` — the structural encoding of "a
/// rotate must be signed by the old key". See the module note: the
/// caller MUST have verified this leaf's inclusion under the
/// cosigned checkpoint, which is what makes `submitter_key_hash` trustworthy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationRecord {
    /// `SHA256(submission public key)` the log recorded for this rotate leaf.
    pub submitter_key_hash: [u8; 32],
    /// The rotate payload's old key hash (64 lowercase hex).
    pub key_hash_old: String,
    /// The rotate payload's new key hash (64 lowercase hex).
    pub key_hash_new: String,
    /// The rotate payload's ordinal.
    pub rot_ordinal: u64,
}

/// Parse a 64-lowercase-hex `key_hash` payload string into raw bytes. The
/// charset+length check ([`is_valid_hash_hex`]) makes the subsequent decode
/// total: it cannot fail on charset, and the fixed length yields exactly 32
/// bytes.
fn parse_key_hash(field: &'static str, value: &str) -> Result<[u8; 32], IdentityError> {
    if !is_valid_hash_hex(value) {
        return Err(IdentityError::InvalidKeyHashHex {
            field,
            value: value.to_string(),
        });
    }
    let bytes = hex::decode(value).map_err(|_| IdentityError::InvalidKeyHashHex {
        field,
        value: value.to_string(),
    })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Derive the producer identity set (the accepted-submitter `key_hash` set) by
/// following AUTHORIZED `rotate`s from the PINNED genesis key.
/// Pure and offline — it does NO cryptography (see the
/// module note on the inclusion precondition the caller must have met).
///
/// Semantics:
/// - Start from `genesis_key_hash` (pinned out-of-band; the production pin is
///   an operator artifact).
/// - A rotation is AUTHORIZED iff `submitter_key_hash == key_hash_old` — only
///   the holder of the old key can rotate FROM it (a rotate must be signed by
///   the old key). Unauthorized rotations never extend the set and are surfaced
///   as [`AnomalyReason::Unauthorized`]. This is what stops an attacker who
///   forges a rotate PAYLOAD naming the public genesis as `key_hash_old` but
///   submits under their OWN key.
/// - Byte-identical authorized facts (same old/new/rot_ordinal) are ONE fact.
/// - Follow the unique authorized rotation whose `key_hash_old` equals the
///   current key, appending its `key_hash_new`.
/// - **Fork**: a key REACHED on the chain that sources ≥2 distinct authorized
///   rotations ⇒ [`IdentityError::Fork`] (bifurcation on our chain). Off-chain
///   forks do NOT abort — each surfaces as [`AnomalyReason::OffChain`].
/// - **Cycle**: revisiting a key ⇒ [`IdentityError::Cycle`].
/// - Authorized rotations whose old key never chains from genesis go to
///   `anomalous_rotations` as [`AnomalyReason::OffChain`], surfaced not dropped.
///
/// It decides no anchor verdict and verifies no signatures: it is the offline
/// identity-chain derivation whose result feeds
/// [`crate::checkpoint::verify_anchored_inclusion`] as its accepted-submitter set.
pub fn derive_producer_identity_set(
    genesis_key_hash: [u8; 32],
    rotations: &[RotationRecord],
) -> Result<IdentitySet, IdentityError> {
    use std::collections::{BTreeMap, BTreeSet};

    // Parse+classify each rotation. AUTHORIZED (submitter == old) facts are
    // deduped by the full (old, new, rot_ordinal) tuple (the same fact
    // republished is one fact; for authorized facts submitter == old, so the
    // submitter is redundant in the key). Unauthorized rotations are surfaced,
    // never followed, and keyed WITH the submitter so two distinct forgeries
    // sharing a payload do not collapse. Tag: 0 = Unauthorized, 1 = OffChain.
    // BTree* for DETERMINISTIC ordering: which fork/anomaly is reported must not
    // depend on hash iteration order.
    // Ordered anomaly key: derived `Ord` gives deterministic output ordering
    // (payload first, then submitter, then tag), and a named struct keeps the
    // BTreeSet element from being a clippy `type_complexity` tuple.
    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    struct AnomalyKey {
        key_hash_old: [u8; 32],
        key_hash_new: [u8; 32],
        rot_ordinal: u64,
        submitter: [u8; 32],
        /// 0 = Unauthorized, 1 = OffChain.
        tag: u8,
    }

    let mut authorized: BTreeSet<([u8; 32], [u8; 32], u64)> = BTreeSet::new();
    let mut anomalies: BTreeSet<AnomalyKey> = BTreeSet::new();
    for r in rotations {
        let old = parse_key_hash("key_hash_old", &r.key_hash_old)?;
        let new = parse_key_hash("key_hash_new", &r.key_hash_new)?;
        if r.submitter_key_hash == old {
            authorized.insert((old, new, r.rot_ordinal));
        } else {
            anomalies.insert(AnomalyKey {
                key_hash_old: old,
                key_hash_new: new,
                rot_ordinal: r.rot_ordinal,
                submitter: r.submitter_key_hash,
                tag: 0, // Unauthorized
            });
        }
    }

    // Group authorized facts by old key. A key REACHED on the chain with ≥2
    // distinct facts is a fork; off-chain forks stay grouped and surface later.
    let mut by_old: BTreeMap<[u8; 32], Vec<([u8; 32], u64)>> = BTreeMap::new();
    for (old, new, ord) in &authorized {
        by_old.entry(*old).or_default().push((*new, *ord));
    }

    // Walk the linear chain from genesis. Fork is detected only for keys we
    // actually reach (an off-chain fork must not abort our derivation).
    let mut keys = vec![genesis_key_hash];
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    seen.insert(genesis_key_hash);
    let mut current = genesis_key_hash;
    while let Some(succs) = by_old.get(&current) {
        if succs.len() >= 2 {
            return Err(IdentityError::Fork {
                key_hash_old: current,
            });
        }
        let new = succs[0].0;
        if !seen.insert(new) {
            return Err(IdentityError::Cycle { key_hash: new });
        }
        keys.push(new);
        current = new;
    }

    // Authorized facts whose old key is not on the derived chain are off-chain.
    // For an authorized fact submitter == old, so the submitter is `old`.
    // Deterministic order: `authorized`/`anomalies` are BTreeSets.
    let on_chain: BTreeSet<[u8; 32]> = keys.iter().copied().collect();
    for (old, new, ord) in &authorized {
        if !on_chain.contains(old) {
            anomalies.insert(AnomalyKey {
                key_hash_old: *old,
                key_hash_new: *new,
                rot_ordinal: *ord,
                submitter: *old, // authorized ⇒ submitter == old
                tag: 1,          // OffChain
            });
        }
    }
    let anomalous_rotations = anomalies
        .into_iter()
        .map(|k| AnomalousRotation {
            submitter_key_hash: k.submitter,
            key_hash_old: k.key_hash_old,
            key_hash_new: k.key_hash_new,
            rot_ordinal: k.rot_ordinal,
            reason: if k.tag == 0 {
                AnomalyReason::Unauthorized
            } else {
                AnomalyReason::OffChain
            },
        })
        .collect();

    Ok(IdentitySet {
        keys,
        anomalous_rotations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- slug charset (pinned rule, mirrors the storage constraint) --

    #[test]
    fn slug_accepts_the_canonical_example() {
        assert!(is_valid_slug("example-tenant"));
    }

    #[test]
    fn slug_accepts_boundary_lengths() {
        assert!(is_valid_slug("abcdefgh")); // exactly 8
        assert!(is_valid_slug(&"a".repeat(32))); // exactly 32
    }

    #[test]
    fn slug_rejects_too_short_and_too_long() {
        assert!(!is_valid_slug("abcdefg")); // 7
        assert!(!is_valid_slug(&"a".repeat(33))); // 33
    }

    #[test]
    fn slug_rejects_leading_hyphen() {
        assert!(!is_valid_slug("-bcdefgh"));
    }

    #[test]
    fn slug_rejects_uppercase_and_underscore() {
        assert!(!is_valid_slug("Abcdefgh"));
        assert!(!is_valid_slug("abc_defg"));
    }

    #[test]
    fn slug_rejects_embedded_nul_anywhere() {
        // The exact hole an unanchored is_match leaves open.
        assert!(!is_valid_slug("abcd\0fgh"));
        assert!(!is_valid_slug("\0xample-tenant"));
    }

    // ---- preimage re-serialization: REAL vectors ---------------------
    //
    // Transcription-safe oracle: the leaf CHECKSUM is what round-tripped into
    // real `test.sigsum.org` leaves (indices 196053-196056) at
    // submission time. `checksum = SHA256(SHA256(
    // preimage))` is collision-resistant, so a matching checksum proves the
    // serialization is byte-exact. We ALSO assert the preimage BYTE LENGTH
    // the ADR states (105/48/109/156) — a cheap structural check that
    // localizes a length drift without hand-copying 100+ hex digits.

    #[test]
    fn head_preimage_matches_real_vector() {
        let lane = Lane::Head {
            slug: "example-tenant".to_string(),
            ordinal: 42,
            chain_hash: "5fe66186d8e2100608f5b914fe260f08c57cc894087966a637f452a0f606c689"
                .to_string(),
        };
        let preimage = serialize_preimage(&lane).unwrap();
        assert_eq!(preimage.len(), 105, "the pinned head-leaf layout is 105 bytes");
        assert_eq!(
            hex::encode(leaf_checksum(&preimage)),
            "7980a962d631ff148d741308a9853a63a165de056ca1255fe3a9bfc7b277c792"
        );
    }

    #[test]
    fn enroll_preimage_matches_real_vector() {
        let lane = Lane::Enroll {
            slug: "example-tenant".to_string(),
            mode: Mode::Attested,
        };
        let preimage = serialize_preimage(&lane).unwrap();
        assert_eq!(preimage.len(), 48, "the pinned enroll-leaf layout is 48 bytes");
        assert_eq!(
            hex::encode(leaf_checksum(&preimage)),
            "c2f0d3a22b6181b7d9a92e03cfe9a68b551f77a2855d73193b4d0278f0f4f580"
        );
    }

    #[test]
    fn retired_preimage_matches_real_vector() {
        let lane = Lane::Retired {
            slug: "example-tenant".to_string(),
            ordinal_final: 128,
            chain_hash_final: "bdb9175e8d400bcbb455f95046eaad430f7129a779b9b0a60fa2bb3641a6083c"
                .to_string(),
        };
        let preimage = serialize_preimage(&lane).unwrap();
        assert_eq!(preimage.len(), 109, "the pinned retired-leaf layout is 109 bytes");
        assert_eq!(
            hex::encode(leaf_checksum(&preimage)),
            "b7e7916e58718b45a97f97973b72137cd9b63a7767f411fc26dc94185c939b8e"
        );
    }

    #[test]
    fn rotate_preimage_matches_real_vector() {
        let lane = Lane::Rotate {
            rot_ordinal: 7,
            key_hash_old: "fa3580190786e1de2c17600bc6ce2e2785656b6b7c20154f14de9f39927bde77"
                .to_string(),
            key_hash_new: "b1a5b27125d5774fa89405492bab3ef3b2a941f0307e21b0b0116668a161d2c4"
                .to_string(),
        };
        let preimage = serialize_preimage(&lane).unwrap();
        assert_eq!(preimage.len(), 156, "the pinned rotate-leaf layout is 156 bytes");
        assert_eq!(
            hex::encode(leaf_checksum(&preimage)),
            "bd33a1669f4c71bb7fff2c3a35907c7c3f0c656524eafa9fde38d155b954fd2b"
        );
    }

    #[test]
    fn preimage_rejects_bad_slug() {
        let lane = Lane::Head {
            slug: "BAD".to_string(),
            ordinal: 1,
            chain_hash: "a".repeat(64),
        };
        assert!(matches!(
            serialize_preimage(&lane),
            Err(PreimageError::InvalidSlug { .. })
        ));
    }

    #[test]
    fn preimage_rejects_uppercase_hex() {
        let lane = Lane::Head {
            slug: "example-tenant".to_string(),
            ordinal: 1,
            chain_hash: "A".repeat(64),
        };
        assert!(matches!(
            serialize_preimage(&lane),
            Err(PreimageError::InvalidHashHex { .. })
        ));
    }

    #[test]
    fn preimage_rejects_zero_ordinal() {
        let lane = Lane::Head {
            slug: "example-tenant".to_string(),
            ordinal: 0,
            chain_hash: "a".repeat(64),
        };
        assert!(matches!(
            serialize_preimage(&lane),
            Err(PreimageError::ZeroOrdinal { .. })
        ));
    }

    // ---- CONSISTENCIA (offline) — JOIN + RETIRED cross-check --------

    use crate::chain::compute_chain_hash;
    use crate::chain_export::PublicChainRow;
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    /// A VALID n-row chain built with the production hash algorithm.
    fn valid_rows(n: u32) -> Vec<PublicChainRow> {
        let mut rows = Vec::with_capacity(n as usize);
        let mut prev: Option<String> = None;
        for ordinal in 1..=n {
            let verdict_hash = format!("{ordinal:064x}");
            let chain_hash = compute_chain_hash(prev.as_deref(), &verdict_hash);
            rows.push(PublicChainRow {
                ordinal,
                verdict_id: Uuid::nil(),
                verdict_hash,
                chain_prev_hash: prev.clone(),
                chain_hash: chain_hash.clone(),
                appended_at: Utc.with_ymd_and_hms(2026, 7, 22, 12, 0, 0).unwrap(),
                ruleset_id: "demo-sbom-presence".to_string(),
                verdict_outcome: "SATISFIED".to_string(),
            });
            prev = Some(chain_hash);
        }
        rows
    }

    /// The honest HEAD leaf for row k (1-based): carries row k's chain_hash.
    fn head_at(rows: &[PublicChainRow], k: u32) -> Lane {
        Lane::Head {
            slug: "example-tenant".to_string(),
            ordinal: k as u64,
            chain_hash: rows[(k - 1) as usize].chain_hash.clone(),
        }
    }

    #[test]
    fn consistencia_honest_head_at_tail_verifies() {
        let rows = valid_rows(5);
        let leaves = vec![head_at(&rows, 5)];
        assert_eq!(verify_consistencia(&rows, &leaves), Verdict::Verified);
    }

    #[test]
    fn verify_anchored_defaults_completitud_to_inconclusive() {
        let rows = valid_rows(3);
        let leaves = vec![head_at(&rows, 3)];
        let report = verify_anchored(&rows, &leaves);
        assert_eq!(report.consistencia, Verdict::Verified);
        assert!(matches!(report.completitud, Verdict::Inconclusive { .. }));
    }

    /// G-v6-1: rows truncated to N=3 but a tail HEAD@4 leaf published ⇒
    /// ordinal 4 > N=3 ⇒ CONSISTENCIA FAILED, WITHOUT a monitor.
    #[test]
    fn consistencia_head_ordinal_beyond_n_fails() {
        let rows = valid_rows(3);
        let leaves = vec![Lane::Head {
            slug: "example-tenant".to_string(),
            ordinal: 4,
            chain_hash: "a".repeat(64),
        }];
        assert!(matches!(
            verify_consistencia(&rows, &leaves),
            Verdict::Failed { .. }
        ));
    }

    /// G-v6-10: a row rewritten while its previously-anchored HEAD@k leaf
    /// still carries the OLD chain_hash ⇒ head@k.chain_hash != row k ⇒
    /// CONSISTENCIA FAILED offline.
    #[test]
    fn consistencia_head_chain_hash_mismatch_fails() {
        let rows = valid_rows(5);
        let leaves = vec![Lane::Head {
            slug: "example-tenant".to_string(),
            ordinal: 3,
            chain_hash: "b".repeat(64), // != rows[2].chain_hash
        }];
        assert!(matches!(
            verify_consistencia(&rows, &leaves),
            Verdict::Failed { .. }
        ));
    }

    /// An "unexplained leaf" (a preimage that cannot canonically serialize —
    /// here a bad slug) ⇒ CONSISTENCIA FAILED.
    #[test]
    fn consistencia_unexplained_leaf_fails() {
        let rows = valid_rows(2);
        let leaves = vec![
            head_at(&rows, 2),
            Lane::Enroll {
                slug: "BAD".to_string(),
                mode: Mode::Attested,
            },
        ];
        assert!(matches!(
            verify_consistencia(&rows, &leaves),
            Verdict::Failed { .. }
        ));
    }

    /// A malformed chain (delegated well-formedness check) ⇒ FAILED.
    #[test]
    fn consistencia_malformed_chain_fails() {
        let leaves: Vec<Lane> = vec![];
        assert!(matches!(
            verify_consistencia(&[], &leaves),
            Verdict::Failed { .. }
        ));
    }

    /// Honest wind-down: RETIRED at the tail (ordinal_final = M = N,
    /// chain_hash_final = head@M) with no later HEAD ⇒ VERIFIED.
    #[test]
    fn consistencia_honest_retired_verifies() {
        let rows = valid_rows(5);
        let leaves = vec![
            head_at(&rows, 5),
            Lane::Retired {
                slug: "example-tenant".to_string(),
                ordinal_final: 5,
                chain_hash_final: rows[4].chain_hash.clone(),
            },
        ];
        assert_eq!(verify_consistencia(&rows, &leaves), Verdict::Verified);
    }

    /// G-v6-11: resurrection — RETIRED at ordinal_final=3 but a HEAD@5 also
    /// anchored ⇒ M=5 ≠ ordinal_final ⇒ CONSISTENCIA FAILED.
    #[test]
    fn consistencia_retired_then_later_head_fails() {
        let rows = valid_rows(5);
        let leaves = vec![
            head_at(&rows, 5),
            Lane::Retired {
                slug: "example-tenant".to_string(),
                ordinal_final: 3,
                chain_hash_final: rows[2].chain_hash.clone(),
            },
        ];
        assert!(matches!(
            verify_consistencia(&rows, &leaves),
            Verdict::Failed { .. }
        ));
    }

    /// A forged RETIRED whose chain_hash_final does not match head@M ⇒ FAILED.
    #[test]
    fn consistencia_retired_forged_final_hash_fails() {
        let rows = valid_rows(5);
        let leaves = vec![
            head_at(&rows, 5),
            Lane::Retired {
                slug: "example-tenant".to_string(),
                ordinal_final: 5,
                chain_hash_final: "f".repeat(64),
            },
        ];
        assert!(matches!(
            verify_consistencia(&rows, &leaves),
            Verdict::Failed { .. }
        ));
    }

    // ---- intent + scenario tests (COMPLEX discipline) ---------------

    /// INTENT: the slug charset is DERIVED from the producer's storage
    ///         DB CHECK `^[a-z0-9][a-z0-9-]{7,31}$`, not a parallel
    ///         charset that can drift from it, and the match is ANCHORED
    ///         (full-string) — an embedded `\0` or uppercase byte ANYWHERE
    ///         fails, closing the hole an unanchored `is_match` leaves.
    /// CONTEXT: the "unexplained leaf" boundary is only
    ///          well-defined if there is exactly one canonical slug encoding;
    ///          an ambiguous charset gives a forger a free grade of freedom.
    /// EXPIRES IF: migration 017 deliberately changes the slug CHECK (this
    ///             test and the charset are revised in the same PR).
    #[test]
    fn test_intent_slug_charset_matches_migration_017_and_is_anchored() {
        // Boundaries of the DB regex, checked directly.
        assert!(is_valid_slug("abcdefgh")); // min length 8
        assert!(is_valid_slug(&"z9".repeat(16))); // max length 32
        assert!(!is_valid_slug("abcdefg")); // 7 — too short
        assert!(!is_valid_slug(&"a".repeat(33))); // 33 — too long
        assert!(!is_valid_slug("-bcdefgh")); // leading hyphen
        assert!(!is_valid_slug("Abcdefgh")); // uppercase
        // Anchored: a valid substring does NOT make the whole string valid.
        assert!(!is_valid_slug("example-tenant\0evil"));
        assert!(!is_valid_slug("evil\0example-tenant"));
    }

    /// INTENT: the two verdicts NEVER collapse. `VERIFIED`
    ///         CONSISTENCIA must never leak into COMPLETITUD, and a run with
    ///         no monitor enumeration yields `INCONCLUSO` COMPLETITUD — never
    ///         `VERIFIED` — even when the offline half fully verifies. A
    ///         `VERIFIED` verdict cannot depend on an artifact of the
    ///         producer's being absent.
    /// CONTEXT: the whole point of the v6 redesign — the pre-v6 verifier
    ///          returned a single `VERIFIED OFFLINE` that an evaluator read
    ///          as completeness it never proved.
    /// EXPIRES IF: COMPLETITUD is deliberately re-scoped (the enumeration-
    ///             aware gate consumes a monitor enumeration — a supplied,
    ///             fresh monitor CAN raise COMPLETITUD to VERIFIED; the
    ///             DEFAULT stays INCONCLUSO).
    #[test]
    fn test_intent_two_verdicts_never_collapse() {
        let rows = valid_rows(4);
        let leaves = vec![head_at(&rows, 4)];
        let report = verify_anchored(&rows, &leaves);
        assert_eq!(
            report.consistencia,
            Verdict::Verified,
            "offline half verifies for an honest package"
        );
        assert!(
            matches!(report.completitud, Verdict::Inconclusive { .. }),
            "COMPLETITUD must be INCONCLUSO without a monitor — never VERIFIED, \
             never collapsed into the offline verdict"
        );
    }

    /// SCENARIO (G-v6-1): truncate the published rows to N but keep the
    ///   anchored tail HEAD leaf (ordinal > N). The JOIN sees a leaf the
    ///   shortened export cannot account for ⇒ CONSISTENCIA FAILED, offline,
    ///   WITHOUT a monitor. Falsifier: a VERIFIED here.
    #[test]
    fn test_scenario_g_v6_1_truncation_with_published_tail_leaf() {
        let full = valid_rows(6);
        let tail_leaf = head_at(&full, 6); // anchored head@6, chain_hash of row 6
        let truncated = full[..4].to_vec(); // export shortened to N=4
        let verdict = verify_consistencia(&truncated, &[tail_leaf]);
        assert!(
            matches!(verdict, Verdict::Failed { .. }),
            "a tail leaf beyond the truncated export must FAIL consistencia, got {verdict:?}"
        );
    }

    /// SCENARIO (G-v6-10): rewrite a published row while its previously
    ///   anchored HEAD@k leaf still carries the pre-rewrite chain_hash. The
    ///   anchor is fixed; the row no longer reproduces it ⇒ CONSISTENCIA
    ///   FAILED offline. Falsifier: a VERIFIED here.
    #[test]
    fn test_scenario_g_v6_10_rewrite_under_fixed_anchor() {
        let original = valid_rows(5);
        let anchored_head_3 = head_at(&original, 3); // carries ORIGINAL row-3 hash
        // Rewrite row 3's verdict_hash (and re-link forward so the chain is
        // still well-formed — the rewrite is otherwise undetectable offline).
        let mut rewritten = valid_rows(5);
        rewritten[2].verdict_hash = "deadbeef".repeat(8);
        rewritten[2].chain_hash =
            compute_chain_hash(rewritten[2].chain_prev_hash.as_deref(), &rewritten[2].verdict_hash);
        for i in 3..5 {
            rewritten[i].chain_prev_hash = Some(rewritten[i - 1].chain_hash.clone());
            rewritten[i].chain_hash =
                compute_chain_hash(rewritten[i].chain_prev_hash.as_deref(), &rewritten[i].verdict_hash);
        }
        // The rewritten chain is internally well-formed...
        assert_eq!(
            verify_consistencia(&rewritten, &[]),
            Verdict::Verified,
            "sanity: without the anchor, the rewrite is undetectable offline"
        );
        // ...but the fixed anchored HEAD@3 exposes it.
        let verdict = verify_consistencia(&rewritten, &[anchored_head_3]);
        assert!(
            matches!(verdict, Verdict::Failed { .. }),
            "the anchored HEAD@3 must expose the rewrite, got {verdict:?}"
        );
    }

    /// SCENARIO (G-v6-11, offline half): a RETIRED at ordinal_final followed
    ///   by a later anchored HEAD is a resurrection ⇒ CONSISTENCIA FAILED
    ///   offline (no monitor needed). Falsifier: the resurrection explained.
    #[test]
    fn test_scenario_g_v6_11_resurrection_after_retired() {
        let rows = valid_rows(7);
        let leaves = vec![
            head_at(&rows, 7), // a HEAD past the RETIRED
            Lane::Retired {
                slug: "example-tenant".to_string(),
                ordinal_final: 4,
                chain_hash_final: rows[3].chain_hash.clone(),
            },
        ];
        let verdict = verify_consistencia(&rows, &leaves);
        assert!(
            matches!(verdict, Verdict::Failed { .. }),
            "a HEAD anchored after RETIRED must FAIL (resurrection), got {verdict:?}"
        );
    }

    // ---- producer identity-set derivation ----------------------------
    //
    // Pure, offline, NO crypto: a `RotationRecord` carries hex payload STRINGS
    // (the identity payload, not the submission signature) plus the
    // log-attested `submitter_key_hash`, so the whole derivation is exercised
    // against structured records. No synthetic crypto ⇒ no tautology.

    /// A synthetic key_hash: 32 bytes all equal to `seed`. Distinct seeds ⇒
    /// distinct keys, and `kh_hex` is the payload form.
    fn kh(seed: u8) -> [u8; 32] {
        [seed; 32]
    }
    fn kh_hex(seed: u8) -> String {
        hex::encode(kh(seed))
    }
    /// An AUTHORIZED rotation: submitted by the old key it rotates from
    /// (`submitter_key_hash == key_hash_old`).
    fn rot(rot_ordinal: u64, old: u8, new: u8) -> RotationRecord {
        RotationRecord {
            submitter_key_hash: kh(old),
            key_hash_old: kh_hex(old),
            key_hash_new: kh_hex(new),
            rot_ordinal,
        }
    }

    #[test]
    fn identity_genesis_only_when_no_rotations() {
        let set = derive_producer_identity_set(kh(1), &[]).unwrap();
        assert_eq!(set.keys, vec![kh(1)]);
        assert!(set.anomalous_rotations.is_empty());
    }

    #[test]
    fn identity_follows_linear_chain() {
        let rots = vec![rot(1, 1, 2), rot(2, 2, 3), rot(3, 3, 4)];
        let set = derive_producer_identity_set(kh(1), &rots).unwrap();
        assert_eq!(set.keys, vec![kh(1), kh(2), kh(3), kh(4)]);
        assert!(set.anomalous_rotations.is_empty());
    }

    #[test]
    fn identity_dedups_identical_rotation() {
        // The SAME authorized fact republished (byte-identical) is one fact.
        let rots = vec![rot(1, 1, 2), rot(1, 1, 2)];
        let set = derive_producer_identity_set(kh(1), &rots).unwrap();
        assert_eq!(set.keys, vec![kh(1), kh(2)]);
    }

    #[test]
    fn identity_fork_two_rotations_from_same_on_chain_key() {
        // Two DISTINCT authorized rotations from genesis (reached) ⇒ Fork
        // (successor uniqueness). Falsifier: an Ok here.
        let rots = vec![rot(1, 1, 2), rot(2, 1, 3)];
        assert_eq!(
            derive_producer_identity_set(kh(1), &rots),
            Err(IdentityError::Fork {
                key_hash_old: kh(1)
            })
        );
    }

    #[test]
    fn identity_fork_same_destination_different_ordinal_is_still_fork() {
        // Conservative reading of "dos ROTATE desde la misma clave ⇒ FAILED":
        // two distinct authorized facts (differing rot_ordinal) from the reached
        // key 1, even to the same destination, forks. Falsifier: an Ok here.
        let rots = vec![rot(1, 1, 2), rot(2, 1, 2)];
        assert_eq!(
            derive_producer_identity_set(kh(1), &rots),
            Err(IdentityError::Fork {
                key_hash_old: kh(1)
            })
        );
    }

    #[test]
    fn identity_offchain_fork_does_not_abort() {
        // Two authorized rotations from key 5 (never chains from genesis 1) must
        // NOT abort our derivation — they surface as OffChain. A shared-log
        // attacker who forks a junk key they own cannot DoS our set (review H1).
        // Falsifier: an Err(Fork) here.
        let rots = vec![rot(1, 5, 6), rot(2, 5, 7)];
        let set = derive_producer_identity_set(kh(1), &rots).unwrap();
        assert_eq!(set.keys, vec![kh(1)]);
        assert_eq!(set.anomalous_rotations.len(), 2);
        assert!(set
            .anomalous_rotations
            .iter()
            .all(|a| a.reason == AnomalyReason::OffChain));
    }

    #[test]
    fn identity_cycle_is_rejected() {
        // genesis 1 → 2 → 1 revisits a key already in the set. Falsifier: an Ok.
        let rots = vec![rot(1, 1, 2), rot(2, 2, 1)];
        assert_eq!(
            derive_producer_identity_set(kh(1), &rots),
            Err(IdentityError::Cycle { key_hash: kh(1) })
        );
    }

    #[test]
    fn identity_surfaces_offchain_rotation() {
        // An authorized rotation whose old key does NOT chain from genesis is
        // surfaced (OffChain), never silently dropped. The set is the genesis
        // chain only.
        let rots = vec![rot(1, 1, 2), rot(9, 5, 6)];
        let set = derive_producer_identity_set(kh(1), &rots).unwrap();
        assert_eq!(set.keys, vec![kh(1), kh(2)]);
        assert_eq!(
            set.anomalous_rotations,
            vec![AnomalousRotation {
                submitter_key_hash: kh(5), // authorized off-chain ⇒ submitter == old
                key_hash_old: kh(5),
                key_hash_new: kh(6),
                rot_ordinal: 9,
                reason: AnomalyReason::OffChain,
            }]
        );
    }

    #[test]
    fn identity_distinct_forgeries_same_payload_do_not_collapse() {
        // Two DIFFERENT attackers forge the same payload (old=genesis, new=9).
        // They are distinct events and must both surface, attributed to their
        // own submitter — not merged into one (an adversarial-review finding).
        let forgeries = vec![
            RotationRecord {
                submitter_key_hash: kh(200),
                key_hash_old: kh_hex(1),
                key_hash_new: kh_hex(9),
                rot_ordinal: 1,
            },
            RotationRecord {
                submitter_key_hash: kh(201),
                key_hash_old: kh_hex(1),
                key_hash_new: kh_hex(9),
                rot_ordinal: 1,
            },
        ];
        let set = derive_producer_identity_set(kh(1), &forgeries).unwrap();
        assert_eq!(set.keys, vec![kh(1)]);
        assert_eq!(set.anomalous_rotations.len(), 2, "distinct submitters must not collapse");
        let submitters: Vec<_> = set
            .anomalous_rotations
            .iter()
            .map(|a| a.submitter_key_hash)
            .collect();
        assert!(submitters.contains(&kh(200)) && submitters.contains(&kh(201)));
    }

    #[test]
    fn identity_rejects_invalid_payload_hex() {
        // Defense in depth: the derivation validates the payload hex itself.
        let rots = vec![RotationRecord {
            submitter_key_hash: kh(1),
            key_hash_old: "not-hex".to_string(),
            key_hash_new: kh_hex(2),
            rot_ordinal: 1,
        }];
        assert!(matches!(
            derive_producer_identity_set(kh(1), &rots),
            Err(IdentityError::InvalidKeyHashHex { .. })
        ));
    }

    /// INTENT: a rotation extends the set ONLY if it is AUTHORIZED by the old
    ///   key it claims to rotate from (`submitter_key_hash == key_hash_old` —
    ///   the structural encoding of "a rotate must be signed by the old key").
    ///   An attacker who forges a rotate PAYLOAD naming the
    ///   PUBLIC pinned genesis as `key_hash_old` but submits it under their OWN
    ///   key does NOT get their key admitted.
    /// CONTEXT: genesis is public; the anchor gate accepts a leaf only if its
    ///   submitter is in this set, so without the submitter==old binding anyone
    ///   could publish `rotate(old=genesis, new=theirs)` and inject their key —
    ///   then anchor a fabricated fact under it (a blind dual-review finding).
    /// EXPIRES IF: the rotate authorization model changes (multi-sig rotations,
    ///   or the old-key binding moves to an explicit submission-signature
    ///   re-verification layer instead of the log-attested submitter_key_hash).
    #[test]
    fn test_intent_rotation_requires_old_key_authorization() {
        // Attacker: payload claims genesis(1) as old, but the leaf was submitted
        // under the attacker's OWN key (200) — the log-attested submitter.
        let forged = RotationRecord {
            submitter_key_hash: kh(200),
            key_hash_old: kh_hex(1),
            key_hash_new: kh_hex(201),
            rot_ordinal: 5,
        };
        let set = derive_producer_identity_set(kh(1), &[forged]).unwrap();
        assert_eq!(set.keys, vec![kh(1)], "attacker key must not be admitted");
        assert!(!set.keys.contains(&kh(201)));
        assert_eq!(set.anomalous_rotations.len(), 1);
        assert_eq!(
            set.anomalous_rotations[0].reason,
            AnomalyReason::Unauthorized,
            "a rotation not signed by the old key it names is unauthorized"
        );
    }
}
