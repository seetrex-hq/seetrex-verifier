// SPDX-License-Identifier: Apache-2.0
//! The OFFLINE `COMPLETITUD` rules engine: the enumeration-dependent verdict,
//! the lane + tenant-mode rules, and the falsifiable gates (the `G-v6-*` rule
//! tags cited throughout and in error reasons).
//!
//! ## What COMPLETITUD is, and why it needs a monitor
//!
//! `CONSISTENCIA` ([`crate::anchor`]) is pure and offline: it detects REWRITING of
//! published history. It is structurally blind to OMISSION — a producer who
//! truncates rows AND omits their tail leaves publishes an internally coherent
//! package that passes `CONSISTENCIA`. Catching omission requires an INDEPENDENT
//! enumeration of the whole log filtered by our `key_hash` (a monitor), compared
//! against a FROZEN freshness reference `C_audit`. Sigsum proves neither absence
//! nor completeness; completeness lives in COMPARING the log to what we published.
//!
//! ## The trust boundary (a signed, deliberate design decision)
//!
//! This layer VERIFIES (reusing the checkpoint/merkle primitives): each
//! enumerated leaf's
//! inclusion under the `C_audit` checkpoint, `C_audit`'s cosignature quorum, the
//! producer identity-set derivation, AND that `C_audit` is
//! a consistency-proven APPEND-ONLY extension of the package's own cosigned
//! checkpoint (R8 calls [`crate::merkle::verify_consistency`] against the two
//! AUTHENTICATED roots, replacing an earlier `S(C_audit) ≥ pkg_size` integer
//! floor). It still TRUSTS as input that the enumeration is COMPLETE (really
//! all the producer's leaves under `0..S(C_audit)-1`) — that is an independent
//! live monitor's job — and that `C_audit` is RECENT in wall-clock time
//! (**consistency ≠ recency**: R8 binds monotonic append-only growth by
//! roots, NOT recency).
//!
//! Consequently a `Verified` COMPLETITUD from THIS layer means "given a COMPLETE,
//! RECENT enumeration, no omission/fork was found" — freshness-of-history is
//! cryptographic (R8), but completeness + recency remain TRUSTED inputs
//! (the live monitor's job).
//!
//! ## Wired to the auditor-facing top level
//!
//! [`verify_completitud`] is `pub` and called from
//! [`crate::anchor_package::verify_anchored_package`] when the auditor supplies a
//! monitor: `None` ⇒ the top-level COMPLETITUD field stays `INCONCLUSO` (the
//! DEFAULT);
//! `Some` ⇒ this layer's real verdict (or `INCONCLUSO` if the package checkpoint
//! itself does not authenticate). A supplied monitor's `Verified` is
//! CONDITIONAL on the enumeration being COMPLETE *and* RECENT — both still
//! TRUSTED inputs deferred to the live monitor; it is NOT an
//! unconditional completeness proof. The conditionality is stated here so the
//! reachable
//! `Verified` is not misread as unconditional (an over-claim class two
//! adversarial reviews caught).
//!
//! ## Verdict ordering (sound under a possibly-stale monitor)
//!
//! POSITIVE-evidence FAILED rules (identity fork, a leaf under an alien key, an
//! enumerated leaf that contradicts the package, a RETIRED violation) use ONLY
//! what the monitor actually SAW, so they are valid even if the monitor is stale.
//! They run FIRST. Then the freshness floor (R8): a stale monitor yields
//! `INCONCLUSO`, never a false `FAILED` from ABSENCE. Only with a fresh-enough
//! monitor do the ABSENCE-based rules run (coverage, mode/404 resolution) and a
//! `Verified` become reachable.

use crate::anchor::{
    is_valid_slug, leaf_checksum, serialize_preimage, IdentityError, IdentitySet, Lane, Mode,
    RotationRecord, Verdict,
};
use crate::chain_export::PublicChainRow;
use crate::checkpoint::{
    tree_leaf_hash, verify_checkpoint, AnchoredLeaf, Checkpoint, WitnessPolicy,
};

/// The monitor's enumeration: the leaves observed under our historic `key_hash`
/// set at `tree_size = S(C_audit)`, each with an inclusion proof under `c_audit`.
/// Its COMPLETENESS and FRESHNESS are TRUST-INPUT in this layer (see the module
/// note); this layer authenticates each leaf's INCLUSION and `c_audit`'s cosig.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorEnumeration {
    /// The FROZEN audit reference checkpoint (`C_audit`). Its cosignature is
    /// verified here; that `C_audit` is an APPEND-ONLY extension of the package's
    /// own cosigned checkpoint (freshness) is the merkle CONSISTENCY proof below,
    /// checked at R8.
    pub c_audit: Checkpoint,
    /// Every leaf the monitor enumerated under our identity, with its inclusion
    /// proof under `c_audit`.
    pub leaves: Vec<AnchoredLeaf>,
    /// The monitor-supplied merkle CONSISTENCY proof binding the package's OWN
    /// cosigned checkpoint (`first`) to `c_audit` (`second`), RFC 9162 §2.1.4.2.
    /// R8 verifies it against the two AUTHENTICATED roots so `S(C_audit) ≥` the
    /// package tree size is bound by roots, not by a declared scalar. NB: it
    /// proves append-only growth, NOT wall-clock recency.
    pub consistency_proof: Vec<[u8; 32]>,
}

/// The cryptographic freshness evidence R8 checks: `C_audit` must
/// be a consistency-proven APPEND-ONLY extension of the package's OWN cosigned
/// checkpoint. Grouped into a NAMED struct (not five positional args) on purpose:
/// transposing the two roots is exactly the failure `verify_consistency`'s
/// swap-roots falsador exists to catch — naming the fields removes that call-site
/// footgun in a crypto-critical path.
pub(crate) struct FreshnessProof<'a> {
    /// `first_size`: the package's AUTHENTICATED cosigned checkpoint size. A HARD
    /// CALLER OBLIGATION: the CONSISTENCIA-verified cosigned size, never a
    /// producer-declared scalar. MUST be `>= 1` (R8 hard-rejects 0 before
    /// delegating — `verify_consistency` treats `first_size==0` as vacuous).
    pub package_checkpoint_size: u64,
    /// `first_root`: the AUTHENTICATED package checkpoint root (same caller
    /// obligation as the size).
    pub package_checkpoint_root: &'a [u8; 32],
    /// `second_size`: `S(C_audit)`.
    pub c_audit_size: u64,
    /// `second_root`: the cosig-verified `C_audit` root.
    pub c_audit_root: &'a [u8; 32],
    /// The monitor-supplied consistency proof binding the package checkpoint to
    /// `C_audit`.
    pub consistency_proof: &'a [[u8; 32]],
}

/// The auditor's per-slug liveness observation: does the slug's published export
/// currently serve (`served = true`) or return 404 (`served = false`)? A 404 is
/// absolved ONLY here (never offline — G-v6-4ter), and only under
/// the mode the enumeration determines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlugObservation {
    pub slug: String,
    pub served: bool,
}

/// One enumerated leaf after inclusion+identity authentication: the fact and its
/// log-attested submitter. The pure rules engine operates on these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthLane {
    pub lane: Lane,
    pub submitter_key_hash: [u8; 32],
}

fn failed(reason: impl Into<String>) -> Verdict {
    Verdict::Failed {
        reason: reason.into(),
    }
}

fn inconclusive(reason: impl Into<String>) -> Verdict {
    Verdict::Inconclusive {
        reason: reason.into(),
    }
}

/// The PURE COMPLETITUD rules over an ALREADY-AUTHENTICATED enumeration
/// (`enumerated`: inclusion + identity checked upstream). This is the epistemic
/// core (the "degradation → undeserved-green" surface): every degraded /
/// ambiguous / omitted signal maps to `FAILED`, `attested-strict`, or
/// `INCONCLUSO` — never a silent `VERIFIED`.
///
/// `identity` is the identity set derived over the enumeration's `rotate` leaves
/// (`Err` ⇒ a structural fork/cycle under enumeration).
///
/// `fresh` is the R8 freshness evidence (see [`FreshnessProof`]): `C_audit` must
/// be a consistency-proven append-only extension of the package's OWN cosigned
/// checkpoint. Its `package_checkpoint_{size,root}` are HARD CALLER OBLIGATIONS
/// (the CONSISTENCIA-verified cosigned checkpoint, never producer-declared) —
/// otherwise R8 (the only offline freshness defense) can be neutered.
///
/// `slug_liveness` is the audited slug's export liveness: `Some(true)` = served,
/// `Some(false)` = 404, `None` = NOT probed. A slug with an anchored head whose
/// liveness is `None` is UNRESOLVED (`INCONCLUSO`) — an omitted liveness signal
/// is fail-closed, never a silent `VERIFIED`.
pub(crate) fn apply_completitud_rules(
    audited_slug: &str,
    rows: &[PublicChainRow],
    published_slug_lanes: &[Lane],
    enumerated: &[AuthLane],
    identity: &Result<IdentitySet, IdentityError>,
    fresh: &FreshnessProof,
    slug_liveness: Option<bool>,
) -> Verdict {
    let n = rows.len() as u64;

    // ===================================================================
    // PHASE 1 — POSITIVE-evidence FAILED rules (valid even if stale)
    // ===================================================================

    // R7 (G-v6-8): identity fork/cycle under enumeration. Two authorized
    // rotations from the same ON-CHAIN key (fork), a cycle, or a malformed
    // rotate payload the monitor enumerated ⇒ FAILED. Uses only seen rotates.
    let identity = match identity {
        Ok(set) => set,
        Err(IdentityError::Fork { .. }) => {
            return failed(
                "two authorized rotations from the same on-chain key (identity fork) \
                 under enumeration (G-v6-8)",
            )
        }
        Err(IdentityError::Cycle { .. }) => {
            return failed("identity chain cycle under enumeration")
        }
        Err(IdentityError::InvalidKeyHashHex { field, .. }) => {
            return failed(format!(
                "malformed rotate key hash ({field}) in enumerated rotation"
            ))
        }
    };
    let our_keys = &identity.keys;

    // R7 (G-v6-7): an enumerated leaf submitted under a key that does NOT chain
    // from the pinned genesis via an authorized rotate — a "key_hash nuevo sin
    // ROTATE de la vieja". The enumeration is "under our key_hash", so every
    // enumerated leaf's submitter MUST be in the derived set; one that is not is
    // a leaf minted under an unrotated key ⇒ FAILED. Seen evidence ⇒ freshness-
    // independent.
    //
    // NB (dependency on the deferred enumeration contract): this gate
    // is only NON-VACUOUS if the monitor's enumeration filter is BROADER than the
    // verifier's derived identity chain (e.g. enumerates by a submitter set the
    // monitor tracks independently, or all leaves). If the monitor enumerated
    // EXACTLY "leaves whose submitter ∈ derived set", every leaf passes by
    // construction and G-v6-7 catches nothing. The enumeration contract that
    // makes this gate live is pinned by the monitor contract, not here.
    for a in enumerated {
        if !our_keys.contains(&a.submitter_key_hash) {
            return failed(
                "enumerated leaf under a key not in the producer identity set — \
                 a key without an authorized rotate (G-v6-7)",
            );
        }
    }

    // Slug-scoped views. The audited slug's enumerated head/enroll/retired lanes,
    // and the max HEAD ordinal the MONITOR sees for this slug (M).
    let enum_slug: Vec<&Lane> = enumerated
        .iter()
        .map(|a| &a.lane)
        .filter(|l| l.slug() == Some(audited_slug))
        .collect();
    let m_enum: Option<u64> = enum_slug
        .iter()
        .filter_map(|l| match l {
            Lane::Head { ordinal, .. } => Some(*ordinal),
            _ => None,
        })
        .max();

    // R1 + R2 (G-v6-2, G-v6-3): every ENUMERATED head for this slug must be
    // EXPLAINED by a published row — `k ≤ N` (else a truncated tail the log
    // still proves) and `chain_hash` byte-identical to row k (else a forged /
    // rewritten leaf). Uses seen leaves ⇒ freshness-independent.
    for l in &enum_slug {
        if let Lane::Head {
            ordinal,
            chain_hash,
            ..
        } = l
        {
            let k = *ordinal;
            if k > n {
                return failed(format!(
                    "monitor enumerates HEAD@{k} but the published chain is only N={n} rows — \
                     rows were truncated while their tail leaf stays in the log (G-v6-2)"
                ));
            }
            if &rows[(k - 1) as usize].chain_hash != chain_hash {
                return failed(format!(
                    "enumerated HEAD@{k} chain_hash does not match published row {k} — \
                     a forged or rewritten leaf (G-v6-3)"
                ));
            }
        }
    }

    // R6 (G-v6-11): RETIRED cross-check against the monitor's view. An enumerated
    // RETIRED must sit exactly at the anchored tail M — `ordinal_final = M` ∧
    // `chain_hash_final = head@M` ∧ no enumerated HEAD past it — else forged
    // RETIRED or resurrection. Seen evidence ⇒ freshness-independent.
    for l in &enum_slug {
        if let Lane::Retired {
            ordinal_final,
            chain_hash_final,
            ..
        } = l
        {
            let Some(m) = m_enum else {
                return failed(
                    "enumerated RETIRED with no enumerated HEAD to cross-check against — \
                     forged RETIRED (G-v6-11)",
                );
            };
            if *ordinal_final != m {
                return failed(format!(
                    "enumerated RETIRED ordinal_final={ordinal_final} != max enumerated HEAD M={m} \
                     — resurrection after retirement (G-v6-11)"
                ));
            }
            if m > n || &rows[(m - 1) as usize].chain_hash != chain_hash_final {
                return failed(
                    "enumerated RETIRED chain_hash_final does not match head@M — forged RETIRED \
                     (G-v6-11)",
                );
            }
        }
    }

    // ===================================================================
    // PHASE 2 — freshness PROOF (R8, G-v6-6)
    // ===================================================================
    // C_audit must be a consistency-proven APPEND-ONLY extension of the package's
    // OWN cosigned checkpoint. This replaces the earlier integer floor
    // (`c_audit_size >= package_checkpoint_size` on DECLARED scalars) with a
    // cryptographic root binding: a package can no longer claim a larger C_audit
    // size behind a forked / inconsistent root. A proof that does not verify —
    // a stale monitor (`S(C_audit) < pkg size`), a missing / malformed proof, or a
    // forked C_audit root — ⇒ INCONCLUSO (freshness UNPROVEN), never a false
    // FAILED from this gate (the positive-evidence FAILED rules already ran in
    // Phase 1). Consistency ≠ recency: this binds monotonic append-only growth,
    // NOT wall-clock recency (that is the live monitor's job).

    // Hard-reject `first_size == 0` BEFORE delegating: verify_consistency treats
    // first_size==0 as VACUOUS (it ignores second_root and returns true on an
    // empty proof), so a 0 package checkpoint size would let ANY C_audit pass. A
    // real authenticated cosigned checkpoint size is always >= 1; reject 0
    // fail-closed (the verify_consistency module note pins this caller obligation).
    if fresh.package_checkpoint_size == 0 {
        return inconclusive(
            "package checkpoint size is 0 — no authenticated checkpoint to prove \
             C_audit freshness against (fail-closed; a real cosigned checkpoint is \
             never empty)",
        );
    }
    if !crate::merkle::verify_consistency(
        fresh.package_checkpoint_size,
        fresh.c_audit_size,
        fresh.package_checkpoint_root,
        fresh.c_audit_root,
        fresh.consistency_proof,
    ) {
        return inconclusive(format!(
            "C_audit (size {}) is not a consistency-proven append-only extension \
             of the package checkpoint (size {}) — freshness not cryptographically \
             established (G-v6-6); a stale or forked reference cannot certify \
             completeness",
            fresh.c_audit_size, fresh.package_checkpoint_size
        ));
    }

    // ===================================================================
    // PHASE 3 — ABSENCE-based rules (need a fresh-enough monitor)
    // ===================================================================

    // R3 (G-v6-2): coverage — every HEAD the PACKAGE published must appear in the
    // floor-fresh enumeration (completeness ASSUMED, deferred to the monitor). A
    // published head the enumeration does not show is a contradiction (the
    // package claims an anchoring the independent monitor cannot corroborate).
    for pl in published_slug_lanes {
        if let Lane::Head { ordinal, .. } = pl {
            let seen = enum_slug
                .iter()
                .any(|l| matches!(l, Lane::Head { ordinal: e, .. } if e == ordinal));
            if !seen {
                return failed(format!(
                    "package published HEAD@{ordinal} but the floor-fresh monitor enumeration \
                     omits it — unattested anchoring (G-v6-2 coverage; enumeration completeness \
                     is a TRUSTED input)"
                ));
            }
        }
    }

    // R4 (G-v6-4, G-v6-4bis): mode determination, FAIL-CLOSED. A slug with ≥1
    // anchored head must have EXACTLY ONE enumerated ENROLL; zero or ≥2 ⇒ mode =
    // `attested` STRICT (omission/ambiguity never buys the revocable treatment).
    let has_anchored_head = m_enum.is_some()
        || published_slug_lanes
            .iter()
            .any(|l| matches!(l, Lane::Head { .. }));
    let enroll_modes: Vec<Mode> = enum_slug
        .iter()
        .filter_map(|l| match l {
            Lane::Enroll { mode, .. } => Some(*mode),
            _ => None,
        })
        .collect();
    let mode = if has_anchored_head && enroll_modes.len() == 1 {
        enroll_modes[0]
    } else {
        // Zero or ≥2 ENROLL with heads ⇒ attested strict. Also the no-head case
        // defaults to attested (no revocable treatment without a single ENROLL).
        Mode::Attested
    };

    // R5 (G-v6-4bis, G-v6-4ter, G-v6-5, G-v6-5b): 404 resolution. Absolution of a
    // 404 lives ONLY here, and only under the determined mode. A missing liveness
    // probe for a slug with an anchored head is UNRESOLVED (fail-closed): an
    // omitted signal can never green-light (degradation→undeserved-green).
    match slug_liveness {
        Some(false) => {
            // Is there a valid crossing RETIRED (already cross-checked in Phase 1)?
            let has_crossing_retired = enum_slug
                .iter()
                .any(|l| matches!(l, Lane::Retired { .. }));
            match mode {
                Mode::Attested => {
                    if has_crossing_retired {
                        // Honest attested wind-down: RETIRED durable → 404. NO RED.
                        return Verdict::Verified;
                    }
                    return failed(
                        "attested slug returns 404 with no crossing RETIRED — an unattested \
                         disappearance (G-v6-4bis)",
                    );
                }
                Mode::Revocable => {
                    // A single revocable ENROLL + a FULL 404 is honest deletion, no
                    // tampering provable ⇒ INCONCLUSO. (Partial truncation would have
                    // FAILED in Phase 1/R3, never reaching here — G-v6-5.)
                    return inconclusive(
                        "revocable slug returns a full 404 — honest deletion, no tampering \
                         provable (G-v6-5)",
                    );
                }
            }
        }
        None if has_anchored_head => {
            // Liveness NOT probed for a slug with an anchored head: we cannot
            // certify the export is served, and cannot conclude a 404 either.
            return inconclusive(
                "slug has an anchored head but its liveness was not probed — cannot certify \
                 the export is served (fail-closed; supply a SlugObservation)",
            );
        }
        // Some(true) = served, or None with no anchored head (a legacy prefix
        // whose pre-anchor rows are inatestiguable, 6S.8·5): liveness irrelevant.
        _ => {}
    }

    // Served (or a legacy no-head prefix, 6S.5c/6S.8·5 — the fall-through IS the
    // "prefijo sin head anclado NO ROJO" case, enforced by absence of any FAILED
    // rule), floor-fresh, and every rule passed.
    Verdict::Verified
}

/// Authenticate the enumeration and apply the COMPLETITUD rules.
///
/// Reuses the checkpoint/merkle primitives: [`verify_checkpoint`] (cosignature quorum) for
/// `C_audit`, and per-leaf inclusion under the AUTHENTICATED `C_audit` root. The
/// identity set is derived over the enumeration's `rotate` leaves. Then the pure
/// [`apply_completitud_rules`] runs.
///
/// **A returned `Verified` is CONDITIONAL** — it means "given a COMPLETE, RECENT
/// enumeration, no omission/fork was found", and completeness + recency are
/// TRUSTED inputs deferred to the live monitor (see the module note). It carries no in-band
/// marker distinguishing it from an unconditional verdict, so its caller
/// ([`crate::anchor_package::verify_anchored_package`]) surfaces it ONLY when the
/// auditor explicitly supplies a monitor; with no monitor the top-level
/// COMPLETITUD stays `INCONCLUSO`.
///
/// `package_checkpoint_size`/`package_checkpoint_root` MUST be the
/// CONSISTENCIA-verified COSIGNED checkpoint size and root (a hard caller
/// obligation, see [`FreshnessProof`]); R8 proves `C_audit` extends this
/// checkpoint via the monitor's `enumeration.consistency_proof`.
/// `published_slug_lanes` are the audited tenant's anchored lanes from the
/// producer's package (HEAD/ENROLL/RETIRED). `rows` is the audited chain.
#[allow(clippy::too_many_arguments)]
pub fn verify_completitud(
    audited_slug: &str,
    rows: &[PublicChainRow],
    published_slug_lanes: &[Lane],
    package_checkpoint_size: u64,
    package_checkpoint_root: [u8; 32],
    genesis_key_hash: [u8; 32],
    enumeration: &MonitorEnumeration,
    policy: &WitnessPolicy,
    observations: &[SlugObservation],
) -> Verdict {
    if !is_valid_slug(audited_slug) {
        return failed(format!("audited slug is not a valid slug: {audited_slug:?}"));
    }

    // (1) Authenticate C_audit's root under the pinned witness quorum.
    let root = match verify_checkpoint(policy, &enumeration.c_audit) {
        Ok(root) => root,
        Err(e) => return failed(format!("C_audit not authenticated by pinned quorum: {e:?}")),
    };

    // (2) Authenticate every enumerated leaf's inclusion under the AUTHENTICATED
    // C_audit root, and split rotate leaves from tenant leaves. A leaf that does
    // not include, or does not serialize to a canonical v1 preimage, is FAILED.
    let mut auth_lanes: Vec<AuthLane> = Vec::with_capacity(enumeration.leaves.len());
    let mut rotate_records: Vec<RotationRecord> = Vec::new();
    for leaf in &enumeration.leaves {
        if let Err(v) = authenticate_leaf_inclusion(&enumeration.c_audit, root, leaf) {
            return v;
        }
        match &leaf.lane {
            Lane::Rotate {
                rot_ordinal,
                key_hash_old,
                key_hash_new,
            } => {
                rotate_records.push(RotationRecord {
                    submitter_key_hash: leaf.submitter_key_hash,
                    key_hash_old: key_hash_old.clone(),
                    key_hash_new: key_hash_new.clone(),
                    rot_ordinal: *rot_ordinal,
                });
            }
            _ => auth_lanes.push(AuthLane {
                lane: leaf.lane.clone(),
                submitter_key_hash: leaf.submitter_key_hash,
            }),
        }
    }

    // (3) Derive the producer identity set over the AUTHENTICATED rotate leaves
    // (the inclusion precondition is met: each rotate's submitter is log-attested by the
    // inclusion check above).
    let identity =
        crate::anchor::derive_producer_identity_set(genesis_key_hash, &rotate_records);

    // (4) The audited slug's liveness: Some(served) if probed, None if the
    // auditor supplied no observation. An absent probe is NOT treated as served
    // (fail-closed in the rules: None + anchored head ⇒ INCONCLUSO).
    let slug_liveness = observations
        .iter()
        .find(|o| o.slug == audited_slug)
        .map(|o| o.served);

    let fresh = FreshnessProof {
        package_checkpoint_size,
        package_checkpoint_root: &package_checkpoint_root,
        c_audit_size: enumeration.c_audit.size,
        c_audit_root: &enumeration.c_audit.root,
        consistency_proof: &enumeration.consistency_proof,
    };
    apply_completitud_rules(
        audited_slug,
        rows,
        published_slug_lanes,
        &auth_lanes,
        &identity,
        &fresh,
        slug_liveness,
    )
}

/// Verify one enumerated leaf's inclusion under the AUTHENTICATED `C_audit` root.
/// Lighter than [`crate::checkpoint::verify_anchored_inclusion`]: it does NOT bind
/// to a single tenant slug (the enumeration spans slugs and includes `rotate`
/// lanes) and does NOT filter identity here (that is the rules engine's R7). It
/// binds fact → checksum → Sigsum leaf → inclusion, exactly as
/// [`crate::checkpoint::verify_anchored_inclusion`] does.
fn authenticate_leaf_inclusion(
    c_audit: &Checkpoint,
    root: [u8; 32],
    leaf: &AnchoredLeaf,
) -> Result<(), Verdict> {
    let preimage = serialize_preimage(&leaf.lane)
        .map_err(|e| failed(format!("unexplained enumerated leaf (does not serialize to v1): {e:?}")))?;
    let checksum = leaf_checksum(&preimage);
    let merkle_leaf =
        tree_leaf_hash(&checksum, &leaf.submitter_signature, &leaf.submitter_key_hash);
    if crate::merkle::verify_inclusion(leaf.index, c_audit.size, merkle_leaf, &leaf.inclusion_proof, root)
    {
        Ok(())
    } else {
        Err(failed(format!(
            "enumerated leaf at index {} does not include under C_audit root",
            leaf.index
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::Cosignature;
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    // ---- synthetic fixtures for the PURE rules engine ---------------------
    // The falsadores are inherently synthetic: `test.sigsum.org` has no real
    // fork/omission/forged-RETIRED. Positive honest cases use controlled lanes
    // whose chain_hash matches the rows (the crypto/inclusion path is tested
    // SEPARATELY with real vectors below — the anti-tautology split).

    const GEN: [u8; 32] = [1u8; 32]; // the producer (genesis) submitter key
    const ALIEN: [u8; 32] = [9u8; 32];
    const SLUG: &str = "example-tenant";

    /// A row whose only fields the rules read are `ordinal` and `chain_hash`.
    fn row(ordinal: u32, chain_hash: &str) -> PublicChainRow {
        PublicChainRow {
            ordinal,
            verdict_id: Uuid::nil(),
            verdict_hash: format!("{ordinal:064x}"),
            chain_prev_hash: None,
            chain_hash: chain_hash.to_string(),
            appended_at: Utc.with_ymd_and_hms(2026, 7, 23, 12, 0, 0).unwrap(),
            ruleset_id: "demo".to_string(),
            verdict_outcome: "SATISFIED".to_string(),
        }
    }

    /// N rows with chain_hash = the 64-hex of the ordinal (deterministic, so a
    /// HEAD@k built with `ch(k)` matches row k).
    fn rows(n: u32) -> Vec<PublicChainRow> {
        (1..=n).map(|o| row(o, &ch(o))).collect()
    }
    fn ch(ordinal: u32) -> String {
        format!("{ordinal:064x}")
    }

    fn head(ordinal: u64, chain_hash: &str, submitter: [u8; 32]) -> AuthLane {
        AuthLane {
            lane: Lane::Head {
                slug: SLUG.to_string(),
                ordinal,
                chain_hash: chain_hash.to_string(),
            },
            submitter_key_hash: submitter,
        }
    }
    fn enroll(mode: Mode) -> AuthLane {
        AuthLane {
            lane: Lane::Enroll {
                slug: SLUG.to_string(),
                mode,
            },
            submitter_key_hash: GEN,
        }
    }
    fn retired(ordinal_final: u64, chain_hash_final: &str) -> AuthLane {
        AuthLane {
            lane: Lane::Retired {
                slug: SLUG.to_string(),
                ordinal_final,
                chain_hash_final: chain_hash_final.to_string(),
            },
            submitter_key_hash: GEN,
        }
    }
    fn ok_identity() -> Result<IdentitySet, IdentityError> {
        Ok(IdentitySet {
            keys: vec![GEN],
            anomalous_rotations: vec![],
        })
    }

    static ZR: [u8; 32] = [0u8; 32];

    /// A "fresh" R8 proof at EQUAL sizes: the degenerate consistency case (empty
    /// proof + equal roots ⇒ `verify_consistency` true). Size 100 as the pre-crypto
    /// rules tests used; the non-degenerate crypto binding is exercised separately
    /// by the REAL Sigsum vectors below (the anti-tautology split).
    fn fresh() -> FreshnessProof<'static> {
        FreshnessProof {
            package_checkpoint_size: 100,
            package_checkpoint_root: &ZR,
            c_audit_size: 100,
            c_audit_root: &ZR,
            consistency_proof: &[],
        }
    }

    /// A STALE monitor: `S(C_audit)=50 < package size=100` ⇒ `verify_consistency`
    /// false (`first_size > second_size`) ⇒ INCONCLUSO. Preserves the old
    /// integer-floor stale semantics under the crypto gate.
    fn stale() -> FreshnessProof<'static> {
        FreshnessProof {
            package_checkpoint_size: 100,
            package_checkpoint_root: &ZR,
            c_audit_size: 50,
            c_audit_root: &ZR,
            consistency_proof: &[],
        }
    }

    /// Honest served baseline: HEAD@3 published + enumerated (matching), one
    /// revocable ENROLL, fresh, served ⇒ VERIFIED.
    fn honest_verified() -> Verdict {
        apply_completitud_rules(
            SLUG,
            &rows(3),
            &[Lane::Head {
                slug: SLUG.to_string(),
                ordinal: 3,
                chain_hash: ch(3),
            }],
            &[head(3, &ch(3), GEN), enroll(Mode::Revocable)],
            &ok_identity(),
            &fresh(),
            /*slug_liveness*/ Some(true),
        )
    }

    #[test]
    fn honest_served_package_verifies() {
        assert_eq!(honest_verified(), Verdict::Verified);
    }

    #[test]
    fn g_v6_2_tail_omission_fails() {
        // Monitor enumerates HEAD@5 but the published chain is only N=3.
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            &[],
            &[head(5, &ch(5), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        assert!(matches!(v, Verdict::Failed { .. }), "got {v:?}");
    }

    #[test]
    fn g_v6_3_forged_head_fails() {
        // Enumerated HEAD@3 whose chain_hash does not match published row 3.
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            &[],
            &[head(3, &ch(999), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        assert!(matches!(v, Verdict::Failed { .. }), "got {v:?}");
    }

    #[test]
    fn g_v6_2_coverage_published_head_missing_from_fresh_monitor_fails() {
        // Package published HEAD@3 but the FRESH monitor omits it.
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            &[Lane::Head {
                slug: SLUG.to_string(),
                ordinal: 3,
                chain_hash: ch(3),
            }],
            &[head(2, &ch(2), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        assert!(matches!(v, Verdict::Failed { .. }), "got {v:?}");
    }

    #[test]
    fn g_v6_4bis_attested_404_no_retired_fails() {
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            &[],
            &[head(3, &ch(3), GEN), enroll(Mode::Attested)],
            &ok_identity(),
            &fresh(),
            /*liveness*/ Some(false),
        );
        assert!(matches!(v, Verdict::Failed { .. }), "got {v:?}");
    }

    #[test]
    fn g_v6_4_zero_enroll_with_head_is_attested_strict_404_fails() {
        // No ENROLL at all + a head + 404 ⇒ attested strict ⇒ FAILED.
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            &[],
            &[head(3, &ch(3), GEN)],
            &ok_identity(),
            &fresh(),
            Some(false),
        );
        assert!(matches!(v, Verdict::Failed { .. }), "got {v:?}");
    }

    #[test]
    fn g_v6_4_two_enroll_is_attested_strict_404_fails() {
        // ≥2 ENROLL (even revocable) ⇒ attested strict ⇒ 404 FAILED (ambiguity
        // never buys revocable).
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            &[],
            &[
                head(3, &ch(3), GEN),
                enroll(Mode::Revocable),
                enroll(Mode::Revocable),
            ],
            &ok_identity(),
            &fresh(),
            Some(false),
        );
        assert!(matches!(v, Verdict::Failed { .. }), "got {v:?}");
    }

    #[test]
    fn g_v6_5_revocable_full_404_is_inconclusive_not_red() {
        // Single revocable ENROLL + full 404 ⇒ honest deletion ⇒ INCONCLUSO.
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            &[],
            &[head(3, &ch(3), GEN), enroll(Mode::Revocable)],
            &ok_identity(),
            &fresh(),
            Some(false),
        );
        assert!(matches!(v, Verdict::Inconclusive { .. }), "got {v:?}");
    }

    #[test]
    fn g_v6_5b_attested_retired_wind_down_verifies() {
        // Attested ENROLL, RETIRED@3 crossing head@3, 404 ⇒ honest wind-down ⇒
        // VERIFIED (NOT red).
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            &[],
            &[
                head(3, &ch(3), GEN),
                enroll(Mode::Attested),
                retired(3, &ch(3)),
            ],
            &ok_identity(),
            &fresh(),
            Some(false),
        );
        assert_eq!(v, Verdict::Verified, "honest attested wind-down must not be red");
    }

    #[test]
    fn g_v6_6_stale_monitor_is_inconclusive_not_red() {
        // Even a "missing published head" gives INCONCLUSO when the monitor is
        // stale (S(C_audit) < package checkpoint size) — never a false FAILED.
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            &[Lane::Head {
                slug: SLUG.to_string(),
                ordinal: 3,
                chain_hash: ch(3),
            }],
            &[], // monitor saw nothing for the slug
            &ok_identity(),
            &stale(),
            Some(true),
        );
        assert!(matches!(v, Verdict::Inconclusive { .. }), "got {v:?}");
    }

    #[test]
    fn g_v6_7_leaf_under_alien_key_fails() {
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            &[],
            &[head(3, &ch(3), ALIEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        assert!(matches!(v, Verdict::Failed { .. }), "got {v:?}");
    }

    #[test]
    fn g_v6_8_identity_fork_fails() {
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            &[],
            &[head(3, &ch(3), GEN)],
            &Err(IdentityError::Fork { key_hash_old: GEN }),
            &fresh(),
            Some(true),
        );
        assert!(matches!(v, Verdict::Failed { .. }), "got {v:?}");
    }

    #[test]
    fn g_v6_11_forged_retired_resurrection_fails() {
        // RETIRED ordinal_final=2 but the monitor's max HEAD is 3 (a head past
        // the claimed retirement) ⇒ resurrection ⇒ FAILED.
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            &[],
            &[head(3, &ch(3), GEN), retired(2, &ch(2))],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        assert!(matches!(v, Verdict::Failed { .. }), "got {v:?}");
    }

    #[test]
    fn g_v6_5c_legacy_prefix_without_anchored_head_not_red() {
        // Legacy rows, NO anchored head (published or enumerated), served ⇒ does
        // not fire ⇒ VERIFIED (6S.8·5: prefix pre-anchor is inatestiguable).
        let v = apply_completitud_rules(
            SLUG, &rows(3), &[], &[], &ok_identity(), &fresh(), Some(true),
        );
        assert_eq!(v, Verdict::Verified);
    }

    /// INTENT: mode determination is FAIL-CLOSED — zero or ≥2 ENROLL for a slug
    ///         with an anchored head is `attested` STRICT, so a 404 without a
    ///         crossing RETIRED can NEVER be absolved by an omitted/duplicated
    ///         ENROLL. CONTEXT: omission or ambiguity must never buy the
    ///         revocable treatment; the degradation→undeserved-green
    ///         class (an ambiguous mode silently buying revocable = the reigning
    ///         bug of this product class). EXPIRES IF: the lane rules are
    ///         re-scoped to allow a
    ///         mid-life mode transition (then the single-ENROLL invariant lifts).
    #[test]
    fn test_intent_mode_determination_is_fail_closed() {
        let attacker_tries_zero_enroll = apply_completitud_rules(
            SLUG, &rows(3), &[], &[head(3, &ch(3), GEN)], &ok_identity(), &fresh(), Some(false),
        );
        let attacker_tries_two_enroll = apply_completitud_rules(
            SLUG, &rows(3), &[],
            &[head(3, &ch(3), GEN), enroll(Mode::Revocable), enroll(Mode::Revocable)],
            &ok_identity(), &fresh(), Some(false),
        );
        assert!(matches!(attacker_tries_zero_enroll, Verdict::Failed { .. }));
        assert!(matches!(attacker_tries_two_enroll, Verdict::Failed { .. }));
    }

    /// INTENT: a stale monitor never produces a false FAILED from ABSENCE — the
    ///         freshness floor (R8) gates absence-based rules. CONTEXT: G-v6-6
    ///         ("monitor < C_audit ⇒ INCONCLUSO, no FAILED") + the sound
    ///         ordering (positive-evidence FAILED before R8 before absence).
    ///         EXPIRES IF: the verdict ordering stops gating absence-based
    ///         rules behind the freshness proof (R8).
    #[test]
    fn test_intent_stale_monitor_never_false_fails_on_absence() {
        // Missing published head under a stale monitor ⇒ INCONCLUSO, not FAILED.
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            &[Lane::Head { slug: SLUG.to_string(), ordinal: 3, chain_hash: ch(3) }],
            &[],
            &ok_identity(),
            &stale(),
            Some(true),
        );
        assert!(matches!(v, Verdict::Inconclusive { .. }));
        // …but a SEEN contradiction (forged head) still FAILS even when stale.
        let seen = apply_completitud_rules(
            SLUG, &rows(3), &[], &[head(3, &ch(999), GEN)], &ok_identity(), &stale(), Some(true),
        );
        assert!(matches!(seen, Verdict::Failed { .. }));
    }

    #[test]
    fn g_v6_5c_legacy_no_enroll_404_fails() {
        // The OTHER half of G-v6-5c: a legacy slug with no ENROLL (⇒ attested
        // strict) that returns 404 must FAIL — "el 404 no escapa" (6S.5c).
        let v = apply_completitud_rules(
            SLUG, &rows(3), &[], &[], &ok_identity(), &fresh(), Some(false),
        );
        assert!(matches!(v, Verdict::Failed { .. }), "got {v:?}");
    }

    /// A-MED-1 (dual review): a missing liveness observation for a slug with an
    /// anchored head must NOT green-light — an omitted signal is fail-closed.
    #[test]
    fn liveness_not_probed_with_anchored_head_is_inconclusive() {
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            &[Lane::Head { slug: SLUG.to_string(), ordinal: 3, chain_hash: ch(3) }],
            &[head(3, &ch(3), GEN), enroll(Mode::Revocable)],
            &ok_identity(),
            &fresh(),
            /*liveness NOT probed*/ None,
        );
        assert!(matches!(v, Verdict::Inconclusive { .. }), "got {v:?}");
    }

    /// A legacy prefix (no anchored head) with liveness NOT probed still passes:
    /// liveness is irrelevant when nothing is anchored (6S.8·5).
    #[test]
    fn liveness_not_probed_without_anchored_head_verifies() {
        let v = apply_completitud_rules(
            SLUG, &rows(3), &[], &[], &ok_identity(), &fresh(), None,
        );
        assert_eq!(v, Verdict::Verified);
    }

    // ---- REAL-vector authentication (crypto reuse, anti-tautology) ---------
    // The C_audit checkpoint + HEAD leaf are the frozen F-A vectors from
    // `test.sigsum.org` (leaf 196053 under checkpoint size 196372). Their
    // signatures were made by the real log + witnesses, not by Rust.

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }
    fn h64(s: &str) -> [u8; 64] {
        hex::decode(s).unwrap().try_into().unwrap()
    }
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
    const SUBMITTER_KH: &str = "b112398d0e531a2a1e49ac5a7e2d8d7cd80ab69485e7c97f36ad893ca543717d";
    const HEAD_INDEX: u64 = 196053;
    const HEAD_CHAIN_HASH: &str =
        "5fe66186d8e2100608f5b914fe260f08c57cc894087966a637f452a0f606c689";
    const HEAD_SIG: &str = "9bb51335303c5c0a6cc7917ea97fbc5490b25b7f5bf320bdb8d678c688cc04a706d2c57e31824d6f80e6e1616666b7d871d7453c4830fc4440ab478a42015507";
    const HEAD_PROOF: &[&str] = &[
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

    fn real_policy() -> WitnessPolicy {
        WitnessPolicy {
            log_pubkey: h32(LOG_PK),
            witnesses: vec![h32(WIT_NISSE), h32(WIT_RGDD), h32(WIT_SMARTIT)],
            quorum_k: 2,
        }
    }
    fn real_c_audit() -> Checkpoint {
        Checkpoint {
            size: CP_SIZE,
            root: h32(CP_ROOT),
            log_signature: h64(CP_LOG_SIG),
            cosignatures: vec![
                Cosignature { key_hash: h32(KH_SMARTIT), timestamp: CP_TS, signature: h64(COSIG_SMARTIT) },
                Cosignature { key_hash: h32(KH_NISSE), timestamp: CP_TS, signature: h64(COSIG_NISSE) },
                Cosignature { key_hash: h32(KH_RGDD), timestamp: CP_TS, signature: h64(COSIG_RGDD) },
            ],
        }
    }
    fn real_head_leaf() -> AnchoredLeaf {
        AnchoredLeaf {
            lane: Lane::Head {
                slug: SLUG.to_string(),
                ordinal: 42,
                chain_hash: HEAD_CHAIN_HASH.to_string(),
            },
            submitter_signature: h64(HEAD_SIG),
            submitter_key_hash: h32(SUBMITTER_KH),
            index: HEAD_INDEX,
            inclusion_proof: HEAD_PROOF.iter().map(|p| h32(p)).collect(),
        }
    }

    #[test]
    fn real_leaf_authenticates_under_c_audit() {
        let cp = real_c_audit();
        let root = verify_checkpoint(&real_policy(), &cp).expect("real C_audit cosig verifies");
        assert!(authenticate_leaf_inclusion(&cp, root, &real_head_leaf()).is_ok());
    }

    #[test]
    fn tampered_real_leaf_fails_authentication() {
        let cp = real_c_audit();
        let root = verify_checkpoint(&real_policy(), &cp).unwrap();
        let mut bad = real_head_leaf();
        bad.index += 1; // wrong index ⇒ inclusion must not verify
        assert!(authenticate_leaf_inclusion(&cp, root, &bad).is_err());
    }

    #[test]
    fn verify_completitud_end_to_end_real_crypto_served_verifies() {
        // Real C_audit + real HEAD@42 leaf (index 196053). Build a 42-row chain
        // whose row 42 carries the leaf's chain_hash so the JOIN cross-check
        // passes. Genesis = the leaf's real submitter (no rotate ⇒ set = genesis).
        let mut r = rows(42);
        r[41] = row(42, HEAD_CHAIN_HASH);
        let enumeration = MonitorEnumeration {
            c_audit: real_c_audit(),
            leaves: vec![real_head_leaf()],
            // Package checkpoint == C_audit (both 196372): the degenerate
            // consistency case (first==second ⇒ empty proof + equal roots ⇒ true).
            // The NON-degenerate real vector (196372→196698) is exercised at the
            // pure-rules level below (split: this level authenticates cosig).
            consistency_proof: vec![],
        };
        let published = vec![Lane::Head {
            slug: SLUG.to_string(),
            ordinal: 42,
            chain_hash: HEAD_CHAIN_HASH.to_string(),
        }];
        let v = verify_completitud(
            SLUG,
            &r,
            &published,
            /*package_checkpoint_size*/ CP_SIZE,
            /*package_checkpoint_root*/ h32(CP_ROOT),
            /*genesis*/ h32(SUBMITTER_KH),
            &enumeration,
            &real_policy(),
            &[SlugObservation { slug: SLUG.to_string(), served: true }],
        );
        assert_eq!(v, Verdict::Verified, "got {v:?}");
    }

    // ---- R8 crypto binding — REAL Sigsum consistency vector ----------------
    //
    // The same live-log-captured vector merkle.rs
    // uses: the test.sigsum.org barreleye log BUILT this consistency proof between
    // the authenticated checkpoint 196372 and the later head 196698. The log made
    // the proof, so Rust-verifying-a-log-built-proof is non-tautological.
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
        .map(|s| h32(s))
        .collect()
    }

    /// An otherwise-honest served enumeration + a `fresh` proof ⇒ VERIFIED. Used
    /// to isolate the R8 gate: everything else passes, so the verdict turns on the
    /// freshness proof alone.
    fn honest_with(fresh: &FreshnessProof) -> Verdict {
        apply_completitud_rules(
            SLUG,
            &rows(3),
            &[Lane::Head {
                slug: SLUG.to_string(),
                ordinal: 3,
                chain_hash: ch(3),
            }],
            &[head(3, &ch(3), GEN), enroll(Mode::Revocable)],
            &ok_identity(),
            fresh,
            Some(true),
        )
    }

    #[test]
    fn r8_real_sigsum_consistency_proof_is_fresh_verifies() {
        // The REAL 196372→196698 consistency proof binds C_audit as an append-only
        // extension of the package checkpoint ⇒ R8 passes ⇒ VERIFIED.
        let first = h32(SIGSUM_FIRST);
        let second = h32(SIGSUM_SECOND);
        let proof = sigsum_proof();
        let fresh = FreshnessProof {
            package_checkpoint_size: 196372,
            package_checkpoint_root: &first,
            c_audit_size: 196698,
            c_audit_root: &second,
            consistency_proof: &proof,
        };
        assert_eq!(honest_with(&fresh), Verdict::Verified, "real proof must pass R8");
    }

    /// INTENT: R8 is a CRYPTOGRAPHIC root binding, not an integer-size floor — a
    ///   C_audit that DECLARES a larger size (196698 > 196372) but whose root is
    ///   FORKED (does not append-only-extend the package checkpoint) must NOT pass
    ///   the freshness gate. The integer floor it replaces WOULD have passed this
    ///   (196698 >= 196372); `verify_consistency` catches the fork ⇒ INCONCLUSO.
    /// CONTEXT: the exact gap the design review named ("a C_audit with a
    ///   larger DECLARED size behind a forked/inconsistent root"). false ⇒
    ///   INCONCLUSO (freshness UNPROVEN), never a false FAILED (the positive-
    ///   evidence FAILED rules already ran in Phase 1).
    /// EXPIRES IF: R8 stops being a freshness gate (a live monitor proves wall-clock
    ///   recency, changing what "fresh enough" means).
    #[test]
    fn test_intent_r8_forked_c_audit_declaring_larger_size_is_not_fresh() {
        let first = h32(SIGSUM_FIRST);
        let proof = sigsum_proof();
        // A forged C_audit root: it still DECLARES size 196698 > 196372, but the
        // root does not extend the package checkpoint under the real proof.
        let mut forked = h32(SIGSUM_SECOND);
        forked[0] ^= 0x01;
        let fresh = FreshnessProof {
            package_checkpoint_size: 196372,
            package_checkpoint_root: &first,
            c_audit_size: 196698,
            c_audit_root: &forked,
            consistency_proof: &proof,
        };
        assert!(
            matches!(honest_with(&fresh), Verdict::Inconclusive { .. }),
            "a forked C_audit declaring a larger size must NOT pass R8"
        );
    }

    #[test]
    fn r8_missing_proof_with_unequal_sizes_is_inconclusive() {
        // Sizes say C_audit (196698) > package (196372) but NO proof is supplied ⇒
        // freshness cannot be established ⇒ INCONCLUSO (an integer floor would have
        // passed on the sizes alone).
        let first = h32(SIGSUM_FIRST);
        let second = h32(SIGSUM_SECOND);
        let fresh = FreshnessProof {
            package_checkpoint_size: 196372,
            package_checkpoint_root: &first,
            c_audit_size: 196698,
            c_audit_root: &second,
            consistency_proof: &[],
        };
        assert!(matches!(honest_with(&fresh), Verdict::Inconclusive { .. }));
    }

    #[test]
    fn r8_swapped_roots_is_inconclusive() {
        // first_root/second_root transposed under the real proof ⇒ false ⇒
        // INCONCLUSO (the swap-roots falsador at the rules layer).
        let first = h32(SIGSUM_FIRST);
        let second = h32(SIGSUM_SECOND);
        let proof = sigsum_proof();
        let fresh = FreshnessProof {
            package_checkpoint_size: 196372,
            package_checkpoint_root: &second, // swapped
            c_audit_size: 196698,
            c_audit_root: &first, // swapped
            consistency_proof: &proof,
        };
        assert!(matches!(honest_with(&fresh), Verdict::Inconclusive { .. }));
    }

    /// INTENT: R8 hard-rejects `package_checkpoint_size == 0` BEFORE delegating —
    ///   `verify_consistency` treats `first_size==0` as VACUOUS (it ignores
    ///   second_root and returns true on an empty proof), so a 0 package size
    ///   would let ANY C_audit pass the freshness gate. The hard-reject is the
    ///   fail-closed defense the primitive's module note pins as a caller
    ///   obligation.
    /// CONTEXT: a real authenticated cosigned checkpoint size is always >= 1;
    ///   0 is a malformed/degenerate package. Without the guard the gate is
    ///   silently defeated (an omitted-defense → undeserved-green).
    /// EXPIRES IF: `verify_consistency` changes its `first_size==0` contract.
    #[test]
    fn test_intent_r8_zero_package_checkpoint_size_is_hard_rejected() {
        let second = h32(SIGSUM_SECOND);
        // package size 0, empty proof: verify_consistency(0, .., &[]) would return
        // TRUE (vacuous). The R8 hard-reject must override that to INCONCLUSO.
        let fresh = FreshnessProof {
            package_checkpoint_size: 0,
            package_checkpoint_root: &ZR,
            c_audit_size: 196698,
            c_audit_root: &second,
            consistency_proof: &[],
        };
        assert!(
            matches!(honest_with(&fresh), Verdict::Inconclusive { .. }),
            "size-0 package checkpoint must be hard-rejected, not vacuously fresh"
        );
    }
}
