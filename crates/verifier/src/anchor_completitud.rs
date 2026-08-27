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
//! ## Lag is not truncation (the export input)
//!
//! The package a producer publishes is a SNAPSHOT of its chain, emitted on its own
//! cadence; heads reach the log on a faster one. A package is therefore routinely
//! BEHIND the log by up to a packaging period, and an enumerated `HEAD@k` past the
//! package's `N` rows is then perfectly honest. From the package ALONE that is
//! byte-for-byte the same observation as a producer who DELETED rows k..N while
//! their tail leaf stayed in the log - so this layer refuses to choose: without the
//! producer's published CHAIN EXPORT the case is a NAMED `INCONCLUSO` that says
//! which input decides it, never a `FAILED`. With the export supplied the question
//! is decided: only a head that NO published producer artefact reaches can have
//! vanished, and a real truncation is still `FAILED` under the same discriminant
//! `G-v6-2` ([`verify_completitud_with_chain`]).
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

/// What COMPLETITUD's truncation rule (`G-v6-2`) ACTUALLY judged against.
///
/// It exists because the number is not derivable from the inputs a caller holds. A
/// supplied export can be DECLINED (it does not verify as a chain, or it contradicts
/// the package), and a declined export contributes NOTHING to the reference - so a
/// caller that recomputes `max(package, supplied_export)` to tell the auditor what
/// happened prints a number the rule never used. Measured on a live run: a 41-row
/// export diverging from the package at row 3 was declined, the rule judged against
/// N=12, and the banner said `reference N=41`.
///
/// The rule that produces it: `G-v6-2` asserts a row VANISHED from the producer's
/// publication, and both the package and the export ARE producer publications, so
/// `reference_rows = max(package_rows, admitted export rows)` and can only ever RISE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruncationReference {
    /// Rows the anchor package itself publishes.
    pub package_rows: u64,
    /// Rows in the chain export the caller SUPPLIED. `None` = none was supplied.
    /// Non-`None` with `declined` set means the file was read but not used.
    pub supplied_export_rows: Option<u64>,
    /// Why a supplied export was DECLINED, if it was. `None` = admitted, or none
    /// supplied. A declined export never raises `reference_rows`.
    pub declined: Option<String>,
    /// The `N` the rule judged against: `max` of the package and any ADMITTED export.
    pub reference_rows: u64,
}

impl TruncationReference {
    /// `true` when a supplied export was actually used as published evidence.
    pub fn export_admitted(&self) -> bool {
        self.supplied_export_rows.is_some() && self.declined.is_none()
    }
}

/// The export as ADMITTED (or not), the reason if not, and the reference the rule
/// will use - resolved ONCE so no caller can disagree with the rule.
pub(crate) struct ResolvedChain<'a> {
    /// The export ONLY if admitted. `None` = absent or declined; the rules then see
    /// no export at all, which is exactly what "nothing is concluded from it" means.
    pub admitted: Option<&'a [PublicChainRow]>,
    pub reference: TruncationReference,
}

/// Apply the admission gates and compute the reference. See [`admit_chain_export`]
/// for the gates and [`TruncationReference`] for the arithmetic.
pub(crate) fn resolve_chain<'a>(
    rows: &[PublicChainRow],
    supplied: Option<&'a [PublicChainRow]>,
) -> ResolvedChain<'a> {
    let package_rows = rows.len() as u64;
    let Some(export) = supplied else {
        return ResolvedChain {
            admitted: None,
            reference: TruncationReference {
                package_rows,
                supplied_export_rows: None,
                declined: None,
                reference_rows: package_rows,
            },
        };
    };
    let supplied_export_rows = Some(export.len() as u64);
    match admit_chain_export(rows, export) {
        Ok(()) => ResolvedChain {
            admitted: Some(export),
            reference: TruncationReference {
                package_rows,
                supplied_export_rows,
                declined: None,
                reference_rows: package_rows.max(export.len() as u64),
            },
        },
        Err(why) => ResolvedChain {
            // DECLINED contributes nothing: not to the rules, not to the reference.
            admitted: None,
            reference: TruncationReference {
                package_rows,
                supplied_export_rows,
                declined: Some(why),
                reference_rows: package_rows,
            },
        },
    }
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

/// One finding a precedence arm produced, BEFORE the precedence chose between them.
///
/// The arms do not report where they are computed: each yields a candidate, and one
/// ordered array in [`completitud_rules`] decides which candidate reaches the auditor.
/// That is what makes the precedence a VALUE - reorderable in one place, pinnable by
/// one guard - instead of an emergent property of the order several `return`
/// statements happen to be written in. Distributed over `return`s it was mutable in
/// three places, and a review found a reordering that ran fully green while replacing
/// a hash-forgery accusation with a truncation one.
enum ArmFinding {
    /// This arm ACCUSES: the run is `FAILED` with this reason.
    Failed(String),
    /// This arm cannot conclude: a NAMED undecided note, which accumulates.
    Undecided(String),
}

/// How many arms the R1/R2/R3 finding precedence has.
///
/// Load-bearing twice. The array in [`completitud_rules`] is declared with this
/// length, so an arm cannot be added there without changing this number; and the
/// guard's table `DECLARED_PRECEDENCE` is declared with the SAME length, so changing
/// this number without registering the new arm does not compile. A seventh arm is
/// therefore covered by construction: it cannot be added silently, and once
/// registered its pairwise fixtures are demanded by name.
const PRECEDENCE_ARMS: usize = 3;

/// How the undecided ledger joins its notes.
///
/// The single source: [`mask_ledger_joiner`] DERIVES what it looks for from this
/// string rather than repeating it, so the two cannot drift apart by construction. A
/// second hardcoded literal would have been a coupling only two unrelated assertions
/// could catch.
const UNDECIDED_JOINER: &str = ". ALSO UNDECIDED: ";

/// Neutralise the ledger's own joiner inside an UNTRUSTED string.
///
/// The gate-1 decline reason embeds `Debug` of a [`crate::chain_export::ChainPackageError`],
/// whose `declared` / `persisted` / `expected` fields are PRODUCER-CONTROLLED text.
/// `Debug` escapes quotes and control bytes but not ordinary printable text, so a
/// hostile export could carry the joiner and forge a note boundary - splitting one
/// note into two, or attributing its own text to a rule that never fired. Not
/// reachable from this crate's CLI (which applies gate 1 itself and exits before the
/// library sees such an export) but reachable through the public entry points, which
/// is exactly the audience that cannot see the CLI's precautions.
///
/// Matching is over the joiner's WORDS, case-insensitively, with any run of
/// SEPARATOR characters between them. Anything narrower is a near-miss a skimming
/// reader still takes for a note boundary: the exact literal alone leaves
/// `also undecided`, case-folding alone still leaves `ALSO  UNDECIDED`, and
/// whitespace-only tolerance still leaves `ALSO. UNDECIDED:` and `ALSO-UNDECIDED:`.
///
/// A SEPARATOR is anything that is not an IDENTIFIER character (`[A-Za-z0-9_]`), and
/// the match must begin and end on an identifier boundary. It was measured buying
/// real accuracy: while `_` counted as a separator,
/// `unknown ruleset id: also_undecided` lost the identifier the auditor needs, and
/// `also` inside a longer word could open a match.
///
/// THAT BOUND IS A TRADE, NOT A FREE ONE, and the price is paid in the
/// false-negative direction: EIGHT near-miss forms this paragraph's own reasoning
/// calls forged boundaries are now left INTACT. The one that stings is the array's
/// `". ALSO_UNDECIDED: injected"`: its boundary differs from the masked
/// `ALSO-UNDECIDED:` by one character and reads to a skimmer as the same thing.
///
/// THE AUTHORITATIVE LIST IS THE ARRAY in `ledger_joiner_mask_spares_innocent_text`,
/// never this comment: a second copy here would be a list to keep in step, and the
/// whole reason this paragraph needed rewriting is that a sentence here drifted from
/// what the code did. Two kinds of quotation appear below and they are not the same:
/// a full string in double quotes is an array ENTRY, verbatim; a bare fragment like
/// `ALSO_UNDECIDED:` names a SHAPE, not an entry. Neither is the whole list. The test
/// asserts all eight UNCHANGED, so if the bound ever moves back ONTO them the trade
/// gets re-decided in the open instead of silently.
///
/// It is accepted because the two cases are NOT DISTINGUISHABLE by identifier rules:
/// `also_undecided` as a legitimate ruleset id and `. ALSO_UNDECIDED:` as a forged
/// boundary have the same shape, so any rule that masks the second corrupts the
/// first. The direction chosen protects the identifier the auditor needs to act on.
///
/// The bound is ASCII-only, so the rule is ASYMMETRIC ACROSS SCRIPTS, from this one
/// predicate. Under-masking on one side: an ASCII identifier character on EITHER
/// flank blocks the mask, so `". ALSO UNDECIDED2:"` (right flank) and
/// `"1also undecided"` (left flank) both survive whole - that half is PINNED, and
/// those two are the array's last entries verbatim. Over-masking on the other: a
/// non-ASCII flank does not block it: with a non-ASCII letter on each outer flank of
/// the run (an o-acute, an e-acute), the inner words still mask - measured when this
/// was written, but carried by NO test, so treat it as today's code, not a guarantee.
///
/// Widening `is_ident` to `char::is_alphanumeric` would square the two halves, at the
/// cost of the byte indexing below being re-derived over chars; it has not been done,
/// and this sentence is the record that it is known rather than overlooked.
///
/// The replacement covers the WORDS, not the run between them. Replacing the whole
/// span with one token swallowed structure the surrounding text needed: measured,
/// `keys not recognised: also, undecided` collapsed to a single `[masked]`, so two
/// unrecognised keys read as one.
///
/// Over-masking remains the deliberate direction of error, and what it costs is now
/// bounded rather than waved away. The only text this touches is an UNTRUSTED
/// producer string inside a decline reason, which is diagnostic and never
/// load-bearing - an auditor who wants the detail runs `verify-chain` on the export.
/// What must survive is pinned by `ledger_joiner_mask_spares_innocent_text`,
/// including the one case deliberately NOT spared: prose in which the two words
/// really are adjacent (`is also undecided by`) is still masked, because sparing it
/// would mean demanding the full literal - the very near-miss the paragraph above
/// forbids.
fn mask_ledger_joiner(untrusted: &str) -> String {
    // DERIVED from the joiner, never a second literal: its words, lowercased.
    let needle: Vec<String> = UNDECIDED_JOINER
        .split_whitespace()
        .map(|word| word.trim_matches(|c: char| !c.is_ascii_alphanumeric()).to_ascii_lowercase())
        .filter(|word| !word.is_empty())
        .collect();
    if needle.is_empty() {
        return untrusted.to_string();
    }
    // An IDENTIFIER byte: what a ruleset id, a key name or a symbol is made of. The
    // mask never begins on one, ends on one, or steps across one. UTF-8 continuation
    // bytes are not identifier bytes, so every index derived below lands on a char
    // boundary.
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let lower = untrusted.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut out = String::with_capacity(untrusted.len());
    let mut cut = 0usize;
    while cut < bytes.len() {
        let Some(rel) = lower[cut..].find(needle[0].as_str()) else {
            break;
        };
        let start = cut + rel;
        let after_first = start + needle[0].len();
        // Where each word landed, so the run BETWEEN them survives verbatim.
        let mut words: Vec<(usize, usize)> = vec![(start, after_first)];
        let mut end = after_first;
        // Boundary at the START: `also` inside a longer word is not the joiner.
        let mut matched = start == 0 || !is_ident(bytes[start - 1]);
        if matched {
            // Walk the remaining words over any run of separator characters.
            matched = needle[1..].iter().all(|word| {
                let mut probe = end;
                while probe < bytes.len() && !is_ident(bytes[probe]) {
                    probe += 1;
                }
                if lower[probe..].starts_with(word.as_str()) {
                    words.push((probe, probe + word.len()));
                    end = probe + word.len();
                    true
                } else {
                    false
                }
            });
        }
        // Boundary at the END: the last word inside a longer identifier is not it.
        if matched && end < bytes.len() && is_ident(bytes[end]) {
            matched = false;
        }
        if matched {
            out.push_str(&untrusted[cut..start]);
            let mut kept = start;
            for (word_start, word_end) in words {
                out.push_str(&untrusted[kept..word_start]);
                out.push_str("[masked]");
                kept = word_end;
            }
            cut = end;
        } else {
            out.push_str(&untrusted[cut..after_first]);
            cut = after_first;
        }
    }
    out.push_str(&untrusted[cut..]);
    out
}

/// `INCONCLUSO` for `reason`, KEEPING any rule that was already undecided.
///
/// A later rule that cannot conclude (R8 freshness, a revocable 404, an unprobed
/// liveness) must not silently drop an earlier `G-v6-2 UNDECIDED`: the verdict CLASS
/// would survive, but the auditor would lose the one line telling them which extra
/// input turns the run into an answer. Both reasons are carried.
fn inconclusive_keeping(pending: &Option<String>, reason: impl Into<String>) -> Verdict {
    let reason = reason.into();
    match pending {
        None => inconclusive(reason),
        Some(earlier) => inconclusive(format!("{reason}{UNDECIDED_JOINER}{earlier}")),
    }
}

/// The PURE COMPLETITUD rules over an ALREADY-AUTHENTICATED enumeration
/// (`enumerated`: inclusion + identity checked upstream). This is the epistemic
/// core (the "degradation → undeserved-green" surface): every degraded /
/// ambiguous / omitted signal maps to `FAILED`, `attested-strict`, or
/// `INCONCLUSO` — never a silent `VERIFIED`.
///
/// `published_chain` is the producer's CURRENT published chain export when the
/// auditor supplied one, `None` when the run holds only the package. It is the input
/// that DECIDES the truncation rule (R1/G-v6-2): `rows` is the package's own SNAPSHOT
/// of that same chain, and a producer that submits heads to the log more often than
/// it emits packages legitimately publishes a package that LAGS the log. Against the
/// package alone "the producer deleted rows" and "this package is older than the log"
/// are the SAME observation, so R1 reports a NAMED `INCONCLUSO` pointing at this input
/// instead of accusing; with the export supplied the question is decided by the UNION
/// of what the two artefacts publish - see THE PRINCIPLE in the body.
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
// The Verdict-only shape the rules tests use. Production callers go through
// `apply_completitud_rules_reported`, which also yields the reference it judged
// against, so this exists only for the tests that predate that value.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_completitud_rules(
    audited_slug: &str,
    rows: &[PublicChainRow],
    published_chain: Option<&[PublicChainRow]>,
    published_slug_lanes: &[Lane],
    enumerated: &[AuthLane],
    identity: &Result<IdentitySet, IdentityError>,
    fresh: &FreshnessProof,
    slug_liveness: Option<bool>,
) -> Verdict {
    apply_completitud_rules_reported(
        audited_slug,
        rows,
        published_chain,
        published_slug_lanes,
        enumerated,
        identity,
        fresh,
        slug_liveness,
    )
    .0
}

/// [`apply_completitud_rules`], additionally returning the [`TruncationReference`]
/// the rule ACTUALLY judged against, so no caller has to (or may) recompute it.
///
/// The single place the export is resolved: the rules below receive the RESOLVED
/// value, never the raw input, so the reference the auditor is shown and the
/// reference the rules used are the same object by construction.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_completitud_rules_reported(
    audited_slug: &str,
    rows: &[PublicChainRow],
    published_chain: Option<&[PublicChainRow]>,
    published_slug_lanes: &[Lane],
    enumerated: &[AuthLane],
    identity: &Result<IdentitySet, IdentityError>,
    fresh: &FreshnessProof,
    slug_liveness: Option<bool>,
) -> (Verdict, TruncationReference) {
    let resolved = resolve_chain(rows, published_chain);
    let verdict = completitud_rules(
        audited_slug,
        rows,
        &resolved,
        published_slug_lanes,
        enumerated,
        identity,
        fresh,
        slug_liveness,
    );
    (verdict, resolved.reference)
}

#[allow(clippy::too_many_arguments)]
fn completitud_rules(
    audited_slug: &str,
    rows: &[PublicChainRow],
    resolved: &ResolvedChain,
    published_slug_lanes: &[Lane],
    enumerated: &[AuthLane],
    identity: &Result<IdentitySet, IdentityError>,
    fresh: &FreshnessProof,
    slug_liveness: Option<bool>,
) -> Verdict {
    let n = rows.len() as u64;

    // ---- THE TRUNCATION REFERENCE ------------------------------------------
    //
    // THE PRINCIPLE (the whole rule follows from it): G-v6-2's premise is that a row
    // VANISHED FROM THE PRODUCER'S PUBLICATION while its tail leaf stayed in the log.
    // If ANY published producer artefact this run holds still carries row k, that
    // premise is FALSE and NO ACCUSATION IS AVAILABLE - whatever the other artefact
    // says. Both inputs here are producer publications: `rows` is the anchor
    // package's snapshot of the chain, and `published_chain` is the export the
    // producer serves. So the reference can only ever RISE:
    //
    //     n_ref = max(package rows, export rows)
    //
    // Each artefact is emitted on its own cadence and downloaded at its own instant,
    // so EITHER can be the stale one. A package emitted daily lags an hourly export
    // (the case this input exists for); an export can equally lag the package - a CDN
    // copy, a reused file, or two downloads straddling a publication. `min`, or
    // taking the export alone, accuses on
    // exactly that skew: it reports "row k was truncated" while holding, in the same
    // run, a package that publishes row k, self-consistent, anchored, and whose
    // CONSISTENCIA it just confirmed. That is the same class of error as accusing a
    // lagging package - installed one artefact over.
    //
    // RESIDUAL, stated because it is real: `max` NARROWS the staleness window to
    // "both artefacts behind the enumeration", it does not close it. Nothing in a
    // chain export binds it to the log's clock - it carries no checkpoint - so an
    // export AND a package that both predate a head the monitor saw still produce a
    // FAILED that a fresh fetch would clear. The verdict text says so, and the fix
    // is procedural (fetch the export and the enumeration together, export first),
    // not available inside these formats.
    //
    // `max` does NOT weaken the real detection. A producer that truncates its chain
    // regenerates BOTH artefacts from that same shortened chain, so on the next tick
    // the package is short too and `k > max(...)` FAILS. The only window `max` gives
    // up is the one where the auditor's own package still explains the head - i.e.
    // where the auditor holds the evidence that refutes the accusation. `max` defers
    // the finding to a fetch of both artefacts taken together; it does not lose it.
    // NB: that recovery is a property of THIS rule, not of anything the auditor kit
    // currently prescribes - as of 2026-08-26 the published kit documents neither
    // `--chain` nor a re-fetch for it, so the run's own INCONCLUSO text is what has
    // to carry the instruction, and it does.
    //
    // ---- What the export IS gated on ---------------------------------------
    //
    // Length is not the only thing checked, and must not be: raising the reference
    // opens one evasion - delete rows, republish an export of the ORIGINAL length
    // with other content - so every enumerated head is ALSO compared against the
    // export's own row k (R1 arm (b)). An export is admitted only if it VERIFIES
    // OFFLINE as a chain (every SHA-256 link recomputed, the same gate `verify-chain`
    // applies) and AGREES with the package byte for byte over the rows both reach.
    //
    // DECLARED LIMIT (not papered over): declining a contradictory export is a mute
    // button the PRODUCER can press - publishing an export that disagrees with its
    // own package at any overlap row turns a would-be FAILED into INCONCLUSO. It is
    // accepted because the alternative is worse in the direction that matters: the
    // verifier cannot tell a producer's contradiction from the auditor's wrong
    // download, and it must not accuse on the latter. The floor is real: a pressed
    // mute button is never WORSE than supplying no export at all, which is always
    // available to a producer anyway, and it leaves a loud named INCONCLUSO in the
    // auditor's hands.
    // Resolved ONCE by the caller, in `resolve_chain`, and READ here - never
    // recomputed. A DECLINED export contributes nothing: not to the rules, not to
    // the reference. The reference can only RISE - see THE PRINCIPLE above.
    let chain = resolved.admitted;

    // ---- the UNDECIDED ledger ----------------------------------------------
    //
    // Every rule that cannot conclude appends here, and ALL of them reach the
    // auditor. Keeping only the FIRST note was a producer-controlled mute button:
    // the decline note is installed before any rule runs, so a producer that
    // published an export contradicting its own package suppressed the enumeration
    // finding underneath it (measured: `HEAD@42` vanished from the verdict). That
    // made supplying a contradictory export strictly WORSE for the auditor than
    // supplying none, refuting the floor the DECLARED LIMIT rests on. It is the
    // same defect class `inconclusive_keeping` exists to fix, in the other
    // direction, and it is fixed the same way: accumulate.
    let mut lag_note: Option<String> = None;
    let mut retired_note: Option<String> = None;

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
    //
    // ORDINAL STABILITY (all three rules that name one — see the intent test
    // `test_intent_every_named_ordinal_is_order_independent`): the ordinal a finding
    // names must be a property of the EVIDENCE, never of the order an artefact
    // happened to serialize its array in. Two conventions, each following what its
    // rule ASSERTS:
    //
    //   * a DIVERGENCE rule names the LOWEST offending ordinal - arms (a) and (b)
    //     here, and R3 coverage below. The earliest divergence is where the two
    //     histories part company and everything after it is downstream of that
    //     break, so it is both the most diagnostic ordinal and the one this crate
    //     already reports elsewhere for the same shape (`verify_public_chain` names
    //     the first severed link by position, `admit_chain_export` the first
    //     disagreeing row).
    //   * a REACH rule names the MAXIMUM - arm (c). Its claim is "no published
    //     artefact reaches this far", and the maximum is the strongest true form of
    //     it.
    //
    // NO COUNT is reported, and that is deliberate rather than an omission: three
    // forged heads read exactly like one. A count here would be a number the auditor
    // cannot rely on, because the enumeration is a TRUSTED input that may be
    // INCOMPLETE - so any count is a floor, not a total, and printing it beside a
    // deterministic ordinal would lend it the same standing. The ordinal is an
    // ANCHOR into the evidence, not a summary of it: the auditor's next step (re-fetch
    // both artefacts, or re-run the enumeration) is the same for one offender or
    // twenty, and the bundle in their hand answers "how many" exactly.
    //
    // Collect, then report: returning inside the loop is what made the answer
    // depend on iteration order.
    let mut forged_vs_package: Option<u64> = None;
    let mut forged_vs_export: Option<u64> = None;
    for l in &enum_slug {
        if let Lane::Head {
            ordinal,
            chain_hash,
            ..
        } = l
        {
            let k = *ordinal;
            // (a) Against the PACKAGE's own rows, where they reach. A head the package
            // DOES cover whose chain_hash differs is a forged or rewritten leaf
            // whatever any export says.
            if k <= n && &rows[(k - 1) as usize].chain_hash != chain_hash {
                forged_vs_package = Some(forged_vs_package.map_or(k, |lowest: u64| lowest.min(k)));
            }
            // (b) Against the EXPORT's own rows, where they reach. This is what stops
            // the evasion a rising reference opens: a producer who deletes rows and
            // republishes an export of the ORIGINAL length with other content is
            // caught by the hash, not by the length.
            if let Some(c) = chain {
                if k <= c.len() as u64 && &c[(k - 1) as usize].chain_hash != chain_hash {
                    forged_vs_export = Some(forged_vs_export.map_or(k, |lowest: u64| lowest.min(k)));
                }
            }
        }
    }
    // (c) The LENGTH rule, computed ONCE against M - the MAXIMUM enumerated head for
    // this slug - and not inside the loop above. Which head is "the" offending one
    // must be a property of the EVIDENCE, not of the order the monitor happened to
    // serialize its leaves in: keyed on the first head past `n_ref`, two auditors
    // holding the same leaves in different order read different ordinals for the same
    // finding. `m_enum` is the max, so `m > n_ref` is equivalent as a CONDITION and
    // stable as a VALUE. Arms (a) and (b) already judged every head either artefact
    // reaches, so computing this after the loop skips nothing.
    //
    // Read from the REPORTED value at the point of use, with no local copy to drift
    // from it. A shadow `let n_ref = ...` is a second place the reference can be
    // changed, and a change there is invisible to every test that asserts on what the
    // run REPORTS - the rules would then judge against one number while telling the
    // auditor another, which is the whole defect class this value exists to remove.
    // With no copy, the only way to alter what the rules use is to alter
    // `resolve_chain`, which the reported line pins.
    let length_reach: Option<ArmFinding> = m_enum
        .filter(|m| *m > resolved.reference.reference_rows)
        .map(|m| {
            if let Some(c) = chain {
                let nc = c.len();
                return ArmFinding::Failed(format!(
                    "monitor enumerates HEAD@{m} (the highest head it saw for this slug) \
                     but no published artefact of this run reaches row {m} (chain export \
                     N={nc}, anchor package N={n}) — rows were truncated while their tail \
                     leaf stays in the log (G-v6-2). Before acting, re-fetch BOTH artifacts \
                     and re-run: this finding is only as fresh as the older of them, and an \
                     export and a package that BOTH predate the enumeration can lack a row \
                     the log already carries"
                ));
            }
            // Package-only: LAG and TRUNCATION are the same observation here. Name what
            // would decide it; never accuse. The remedy depends on whether an export
            // was supplied at all - telling an auditor to supply the export they DID
            // supply, and which was DECLINED, sends them in a circle.
            let remedy = if resolved.reference.supplied_export_rows.is_none() {
                "Supply the producer's published chain export (--chain <chain.json>) \
                 to decide it: a head no published artefact reaches is truncation, one \
                 either artefact carries is lag"
            } else {
                "The chain export you supplied was DECLINED as evidence (the reason \
                 follows), so it decided nothing: re-fetch it from the producer and \
                 re-run"
            };
            ArmFinding::Undecided(format!(
                "monitor enumerates HEAD@{m} (the highest head it saw for this slug), \
                 beyond the anchor package's N={n} rows. The package alone cannot tell a \
                 producer that TRUNCATED rows from a package that merely LAGS the log \
                 (packages are emitted less often than heads are submitted), so nothing is \
                 concluded. {remedy} (G-v6-2 UNDECIDED)"
            ))
        });

    // THE PRECEDENCE, AS DATA. Every arm that fired, HIGHEST first; the first one
    // present is the finding the auditor gets. The order of THIS array is the whole
    // precedence - it is not spread over the order three `return` statements are
    // written in, which is what let a reordering of the source blocks silently swap
    // one accusation for another while every test stayed green.
    //
    //   * (a) before (b): both compare the same enumerated head against a published
    //     row, and the package is the artefact under audit. `admit_chain_export`
    //     forces byte-equal rows over the overlap, so where both fire they fire on the
    //     same `k` and only the ARTEFACT named changes.
    //   * (a) and (b) before (c): positive hash evidence outranks a reach rule. These
    //     are different gates with different accusations, so ordering them wrongly
    //     does not reword a finding, it REPLACES it - the forgery vanishes from the
    //     report and is announced as a truncation.
    //
    // `test_intent_declared_precedence_holds_for_every_ordered_pair` drives every
    // ordered pair of this array, so no permutation of it passes.
    //
    // INDEX, NOT SEVERITY: the selection below is `.next()`, so the first arm PRESENT
    // wins even when a later one is `Failed` and it is only `Undecided`. An
    // `Undecided` candidate above a `Failed` one SILENCES the accusation: the note
    // becomes the `lag_note`, the `Failed` arm below it is never read, and its
    // accusation never reaches the auditor at all. That is inert today, and only by
    // accident of layout: `length_reach` is the sole arm that can be `Undecided` and
    // it is last, so nothing can sit below it. It goes LIVE the moment a fourth arm
    // is inserted above it, which is exactly when someone will be reading this array
    // and not this sentence. A severity-aware selection would be the fix; the pairwise
    // guard does not cover it, because it drives `Failed`-against-`Failed` pairs only.
    let fired: [Option<ArmFinding>; PRECEDENCE_ARMS] = [
        forged_vs_package.map(|k| {
            ArmFinding::Failed(format!(
                "enumerated HEAD@{k} (the lowest head whose chain_hash diverges) does not \
                 match published row {k} — a forged or rewritten leaf (G-v6-3)"
            ))
        }),
        forged_vs_export.map(|k| {
            ArmFinding::Failed(format!(
                "enumerated HEAD@{k} (the lowest head whose chain_hash diverges) does not \
                 match the producer's published chain export at row {k} — a forged or \
                 rewritten leaf (G-v6-3)"
            ))
        }),
        length_reach,
    ];
    match fired.into_iter().flatten().next() {
        Some(ArmFinding::Failed(reason)) => return failed(reason),
        Some(ArmFinding::Undecided(note)) => lag_note = Some(note),
        None => {}
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
            // Cross-checked against the SAME reference R1 used. `m` is an enumerated
            // HEAD ordinal, so with an export supplied `m > n_ref` already returned
            // FAILED in R1; reaching it here means the package alone cannot place
            // head@M, so the RETIRED is UNDECIDED - not forged.
            match published_row_chain_hash(rows, chain, m) {
                Some(published) if published == chain_hash_final => {}
                Some(_) => {
                    return failed(
                        "enumerated RETIRED chain_hash_final does not match head@M — forged \
                         RETIRED (G-v6-11)",
                    )
                }
                // No published artefact reaches head@M. With an export supplied R1 arm
                // (c) already returned FAILED for that same ordinal (M IS an enumerated
                // head), so this is the package-only case: unplaceable, not forged.
                None => {
                    retired_note.get_or_insert(format!(
                        "enumerated RETIRED sits at head@{m} (the highest head the monitor \
                         saw for this slug), beyond the anchor package's \
                         N={n} rows: the package alone cannot place that head, so the \
                         RETIRED can be neither cross-checked nor called forged. Supply \
                         the producer's published chain export (--chain <chain.json>) \
                         (G-v6-11 UNDECIDED)"
                    ));
                }
            }
        }
    }

    // Phase 1 is over, so every undecided rule has spoken. Joined ENUMERATION
    // FIRST: what the monitor saw is the substantive observation, and a refused
    // export is the EXPLANATION of why it could not be resolved - never a
    // replacement for it.
    let undecided: Option<String> = {
        let notes: Vec<&str> = [
            lag_note.as_deref(),
            retired_note.as_deref(),
            resolved.reference.declined.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect();
        if notes.is_empty() {
            None
        } else {
            Some(notes.join(UNDECIDED_JOINER))
        }
    };

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
        return inconclusive_keeping(&undecided, 
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
        return inconclusive_keeping(&undecided, format!(
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
    //
    // Names the LOWEST omitted ordinal, per the ORDINAL STABILITY note above. The
    // stability argument IS weaker here than for the monitor rules - this order comes
    // from the package file, so two auditors holding the same artefact already read
    // the same ordinal - but it is not absent: the PRODUCER chooses the order of its
    // own array, and so would choose which of its omissions the finding names. One
    // convention across all three rules also lets the intent test state the invariant
    // generally instead of for the cases that happened to be covered.
    let omitted_head = published_slug_lanes
        .iter()
        .filter_map(|pl| match pl {
            Lane::Head { ordinal, .. } => Some(*ordinal),
            _ => None,
        })
        .filter(|ordinal| {
            !enum_slug
                .iter()
                .any(|l| matches!(l, Lane::Head { ordinal: e, .. } if e == ordinal))
        })
        .min();
    if let Some(ordinal) = omitted_head {
        return failed(format!(
            "package published HEAD@{ordinal} (the lowest it published that is missing) \
             but the floor-fresh monitor enumeration omits it — unattested anchoring \
             (G-v6-2 coverage; enumeration completeness is a TRUSTED input)"
        ));
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
                        return verified_unless_undecided(undecided);
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
                    return inconclusive_keeping(&undecided, 
                        "revocable slug returns a full 404 — honest deletion, no tampering \
                         provable (G-v6-5)",
                    );
                }
            }
        }
        None if has_anchored_head => {
            // Liveness NOT probed for a slug with an anchored head: we cannot
            // certify the export is served, and cannot conclude a 404 either.
            return inconclusive_keeping(&undecided, 
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
    verified_unless_undecided(undecided)
}

/// `Verified`, UNLESS a rule could not be DECIDED on the inputs supplied.
///
/// The verdict lattice this enforces is `FAILED > INCONCLUSO > Verified`: an
/// undecidable rule never suppresses a `FAILED` (those `return` from their own rule,
/// above, and never reach here) and never buys a `Verified` either. Deferring the
/// undecided note to the exits instead of returning it where it is noticed is what
/// keeps the rest of the engine running: a package that both LAGS the log and carries
/// a forged RETIRED must still be reported FAILED, not INCONCLUSO.
fn verified_unless_undecided(undecided: Option<String>) -> Verdict {
    match undecided {
        Some(reason) => inconclusive(reason),
        None => Verdict::Verified,
    }
}

/// Decide whether an auditor-supplied chain export may serve as published evidence,
/// or return the reason it is DECLINED.
///
/// TWO gates, both inside the library rather than left to the caller: this is a
/// PUBLIC entry point of a published crate and the export is UNTRUSTED producer
/// material, so an obligation stated only in prose would be an obligation the next
/// caller silently breaks (measured: a 6-row export with fabricated `chain_hash` on
/// rows 2..6 raised the reference from 1 to 6 in complete silence).
///
/// 1. It must VERIFY OFFLINE as a chain - every SHA-256 link recomputed, the same
///    [`crate::chain_export::verify_public_chain`] gate the `verify-chain` surface
///    applies. An export whose own links do not hold is not evidence of anything.
/// 2. It must AGREE with the package over the rows BOTH reach - the WHOLE row, all
///    eight fields, not just the two the chain commits to. `chain_hash` is
///    `SHA256(chain_prev_hash || verdict_hash)`, so with both artefacts link-verified
///    it binds `ordinal`, `chain_prev_hash` and `verdict_hash` and nothing else:
///    `verdict_id`, `appended_at`, `ruleset_id` and `verdict_outcome` are outside it,
///    and an export whose row 2 reads `VIOLATED` against a package row reading
///    `SATISFIED` was admitted in silence while that was the gate. The package is a
///    snapshot of the same chain, so a disagreement in ANY field means the wrong
///    export or a producer contradiction, and we cannot tell which from here.
///
///    Comparing the whole row cannot become a false DECLINE through two honest
///    renderers disagreeing, and the reason is STRUCTURAL and in this tree, not a
///    measurement someone has to re-take: a package's `rows` ARE the parsed published
///    export. `seetrex_witness::enumerate` builds each tenant's rows by running the
///    served `<slug>-chain.json` through `parse_and_verify_package_rows`, and
///    `seetrex_witness::anchor_emit` clones exactly those rows into the package it
///    emits. One parse, one clone - there is no second renderer to diverge from.
///    (Corroborated, not established, by the live artefacts: the rows a package and
///    the published export shared were byte-identical in all eight fields.) And a
///    spurious DECLINE costs only the `--chain` benefit - never a finding, since
///    every undecided note accumulates.
///
/// An export that is merely SHORTER passes gate 2 (it agrees over its overlap) and is
/// admitted: a shorter export never accuses on its own - see THE PRINCIPLE in
/// [`apply_completitud_rules`] - but its rows still judge the heads it does reach.
fn admit_chain_export(rows: &[PublicChainRow], chain: &[PublicChainRow]) -> Result<(), String> {
    if let Err(e) = crate::chain_export::verify_public_chain(chain) {
        // `e` carries PRODUCER-CONTROLLED text; mask the ledger's joiner in it.
        let detail = mask_ledger_joiner(&format!("{e:?}"));
        return Err(format!(
            "the supplied chain export does not verify offline as a chain ({detail}): it is \
             DECLINED as published evidence and nothing is concluded from it - re-fetch it \
             from the producer and re-run (G-v6-2 UNDECIDED)"
        ));
    }
    if let Some(k) = rows
        .iter()
        .zip(chain.iter())
        .position(|(a, b)| a != b)
        .map(|i| i + 1)
    {
        return Err(format!(
            "the supplied chain export contradicts the anchor package at row {k}: the \
             package is a snapshot of that same chain, so a disagreement means the wrong \
             export or a producer contradiction - it is DECLINED as published evidence and \
             nothing is concluded from it; re-fetch both artifacts from the producer and \
             re-run (G-v6-2 UNDECIDED)"
        ));
    }
    Ok(())
}

/// The `chain_hash` the producer PUBLISHES for row `k` (1-based), read from whichever
/// artefact reaches it, or `None` when NEITHER does.
///
/// The two artefacts are admitted only if they agree over their overlap
/// ([`admit_chain_export`]), so where both reach row `k` the answer is the same and
/// the preference between them is immaterial.
fn published_row_chain_hash<'a>(
    rows: &'a [PublicChainRow],
    chain: Option<&'a [PublicChainRow]>,
    k: u64,
) -> Option<&'a str> {
    if k == 0 {
        return None;
    }
    if let Some(c) = chain {
        if k <= c.len() as u64 {
            return Some(c[(k - 1) as usize].chain_hash.as_str());
        }
    }
    if k <= rows.len() as u64 {
        return Some(rows[(k - 1) as usize].chain_hash.as_str());
    }
    None
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
/// Takes NO chain export, so the TRUNCATION rule is always UNDECIDABLE here and
/// always reports a named `INCONCLUSO` rather than accusing. That is a statement
/// about that rule, NOT about its `G-v6-2` tag: R3 coverage carries the same tag and
/// can return `Failed` from this entry point, because it judges an ABSENCE from the
/// enumeration and needs no export to do so. See
/// [`verify_completitud_with_chain`] to supply one, and
/// [`verify_completitud_reported`] to also learn what the rule judged against.
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
    verify_completitud_with_chain(
        audited_slug,
        rows,
        None,
        published_slug_lanes,
        package_checkpoint_size,
        package_checkpoint_root,
        genesis_key_hash,
        enumeration,
        policy,
        observations,
    )
}

/// [`verify_completitud`] plus the one input that makes the truncation rule DECIDABLE:
/// `published_chain`, the producer's CURRENT published chain export.
///
/// Everything else is identical - same authentication, same rules, same verdicts. The
/// difference is what R1 (G-v6-2) does with an enumerated `HEAD@k` that the package's
/// own `rows` do not reach:
///
/// * `published_chain = None` (what [`verify_completitud`] passes) - `k > N(package)`
///   is UNDECIDABLE. A producer that deleted rows and a package that merely LAGS the
///   log (packages are emitted less often than heads are submitted) produce the very
///   same observation, so the verdict is a NAMED `INCONCLUSO` that says which input
///   decides it. It is NEVER a `FAILED`: accusing on an ambiguity is the one error a
///   verifier cannot take back.
/// * `published_chain = Some(export)` - decided. `k` beyond BOTH artefacts is a real
///   truncation and stays `FAILED` under the same discriminant `G-v6-2`; `k` that
///   EITHER artefact reaches is lag, and its `chain_hash` is checked against every
///   artefact that does reach it (which is what stops a producer from re-publishing
///   an export of the original length with different content).
///
/// THE PRINCIPLE the rule follows from: `G-v6-2` asserts that a row VANISHED from the
/// producer's publication. Both `rows` and `published_chain` ARE producer
/// publications, so if EITHER still carries row `k` that premise is false and no
/// accusation is available. The reference is therefore
/// `max(package rows, export rows)` and can only ever RISE. In particular an export
/// SHORTER than the package - a CDN copy, a reused file, two downloads straddling a
/// publication - never accuses: the package in the auditor's own hand publishes the
/// row, self-consistent and anchored. This does not weaken the real detection,
/// because a producer that truncates its chain regenerates BOTH artefacts from it;
/// `max` defers such a finding to a fetch of both taken together rather than losing
/// it. The verdict text says so itself, which is what the auditor actually reads.
///
/// GATES on the export, applied INSIDE this function rather than left to the caller:
/// it must verify offline as a chain ([`crate::chain_export::verify_public_chain`] -
/// every SHA-256 link recomputed) AND agree with the package over the rows both
/// reach. An export failing either is DECLINED - the run degrades to the
/// package-only, `INCONCLUSO` reading and NOTHING is concluded from it.
///
/// DECLARED LIMIT 2: a truncation finding is only as fresh as the OLDER of the two
/// artefacts. An export carries no checkpoint, so nothing dates it against the log;
/// a package and an export that BOTH predate a head the monitor enumerated yield a
/// `FAILED` a fresh fetch would clear. `max` narrows that window to "both behind",
/// it does not close it, and the verdict text tells the auditor to re-fetch both
/// before acting.
///
/// DECLARED LIMIT 1: that DECLINED path is a mute button the PRODUCER can press. An
/// export contradicting its own package at any overlap row turns a would-be `FAILED`
/// into `INCONCLUSO`. It is accepted because the verifier cannot tell a producer's
/// contradiction from the auditor's wrong download and must not accuse on the latter;
/// the floor is that pressing it is never worse than supplying no export at all,
/// which the producer can always achieve anyway, and it leaves a named `INCONCLUSO`.
///
/// Returns the VERDICT only. If you will report what the rule judged against, call
/// [`verify_completitud_reported`] instead and render the [`TruncationReference`] it
/// returns - do NOT recompute `max(package, export)` at the call site, because a
/// DECLINED export makes that a different number (see [`TruncationReference`]). Of
/// the three public entry points to this layer, that one is the only one that yields
/// the reference; [`verify_completitud`] takes no export at all, so there is no
/// reference to report and nothing to recompute.
///
/// ADDITIVE by construction: [`verify_completitud`] keeps its `0.3.3` signature and
/// behaviour, so no existing caller changes.
#[allow(clippy::too_many_arguments)]
pub fn verify_completitud_with_chain(
    audited_slug: &str,
    rows: &[PublicChainRow],
    published_chain: Option<&[PublicChainRow]>,
    published_slug_lanes: &[Lane],
    package_checkpoint_size: u64,
    package_checkpoint_root: [u8; 32],
    genesis_key_hash: [u8; 32],
    enumeration: &MonitorEnumeration,
    policy: &WitnessPolicy,
    observations: &[SlugObservation],
) -> Verdict {
    verify_completitud_reported(
        audited_slug,
        rows,
        published_chain,
        published_slug_lanes,
        package_checkpoint_size,
        package_checkpoint_root,
        genesis_key_hash,
        enumeration,
        policy,
        observations,
    )
    .0
}

/// [`verify_completitud_with_chain`], additionally returning the
/// [`TruncationReference`] the rule judged against.
///
/// **This is the entry point to use when you intend to TELL anyone what the
/// truncation rule judged against.** The number is NOT derivable from the inputs you
/// hold: a supplied export can be DECLINED (it does not verify as a chain, or it
/// contradicts the package), and a declined export contributes nothing - so
/// `max(package.len(), export.len())` computed at a call site is a different, wrong
/// number whenever that happens. It was wrong in this crate's own CLI, twice, in
/// both directions, before the value was reported.
///
/// `None` means the rules never ran - the honest answer for the early refusals above
/// them (an invalid slug, a `C_audit` the pinned quorum does not authenticate, a leaf
/// whose inclusion does not verify). Render it as "not evaluated"; never fill it in.
#[allow(clippy::too_many_arguments)]
pub fn verify_completitud_reported(
    audited_slug: &str,
    rows: &[PublicChainRow],
    published_chain: Option<&[PublicChainRow]>,
    published_slug_lanes: &[Lane],
    package_checkpoint_size: u64,
    package_checkpoint_root: [u8; 32],
    genesis_key_hash: [u8; 32],
    enumeration: &MonitorEnumeration,
    policy: &WitnessPolicy,
    observations: &[SlugObservation],
) -> (Verdict, Option<TruncationReference>) {
    if !is_valid_slug(audited_slug) {
        return (
            failed(format!("audited slug is not a valid slug: {audited_slug:?}")),
            None,
        );
    }

    // (1) Authenticate C_audit's root under the pinned witness quorum.
    let root = match verify_checkpoint(policy, &enumeration.c_audit) {
        Ok(root) => root,
        Err(e) => {
            return (
                failed(format!("C_audit not authenticated by pinned quorum: {e:?}")),
                None,
            )
        }
    };

    // (2) Authenticate every enumerated leaf's inclusion under the AUTHENTICATED
    // C_audit root, and split rotate leaves from tenant leaves. A leaf that does
    // not include, or does not serialize to a canonical v1 preimage, is FAILED.
    let mut auth_lanes: Vec<AuthLane> = Vec::with_capacity(enumeration.leaves.len());
    let mut rotate_records: Vec<RotationRecord> = Vec::new();
    for leaf in &enumeration.leaves {
        if let Err(v) = authenticate_leaf_inclusion(&enumeration.c_audit, root, leaf) {
            return (v, None);
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
    let (verdict, reference) = apply_completitud_rules_reported(
        audited_slug,
        rows,
        published_chain,
        published_slug_lanes,
        &auth_lanes,
        &identity,
        &fresh,
        slug_liveness,
    );
    (verdict, Some(reference))
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
    use crate::chain::compute_chain_hash;
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

    /// One row of a REAL chain: `chain_hash` is `compute_chain_hash(prev, verdict)`,
    /// so a run of these passes `verify_public_chain`.
    ///
    /// That matters now: a supplied chain export is ADMITTED only if it verifies
    /// offline as a chain, so a fixture that is merely a bag of rows is DECLINED and
    /// tests nothing about the rules. (The pre-`--chain` fixtures were link-severed -
    /// every `chain_prev_hash` was `None` - because nothing had ever asked them to be
    /// chains; they only ever fed `rows`, which the rules read by `chain_hash` alone.)
    fn row(ordinal: u32, prev: Option<&str>, verdict_hash: String) -> PublicChainRow {
        PublicChainRow {
            ordinal,
            verdict_id: Uuid::nil(),
            chain_hash: compute_chain_hash(prev, &verdict_hash),
            verdict_hash,
            chain_prev_hash: prev.map(str::to_string),
            appended_at: Utc.with_ymd_and_hms(2026, 7, 23, 12, 0, 0).unwrap(),
            ruleset_id: "demo".to_string(),
            verdict_outcome: "SATISFIED".to_string(),
        }
    }

    /// `n` rows of the chain whose row `o` carries `verdict_hash = 64-hex(o + seed)`.
    fn chain_rows(n: u32, seed: u32) -> Vec<PublicChainRow> {
        let mut out: Vec<PublicChainRow> = Vec::new();
        let mut prev: Option<String> = None;
        for o in 1..=n {
            let r = row(o, prev.as_deref(), format!("{:064x}", o + seed));
            prev = Some(r.chain_hash.clone());
            out.push(r);
        }
        out
    }

    /// THE canonical chain, `n` rows. `rows(a)` is a byte-identical PREFIX of
    /// `rows(b)` for `a <= b`, which is what makes a package and an export of
    /// different lengths agree over their overlap.
    fn rows(n: u32) -> Vec<PublicChainRow> {
        chain_rows(n, 0)
    }

    /// A VALID chain of `n` rows that agrees with [`rows`] up to `k - 1` and diverges
    /// from row `k` on. Divergence by CONTENT, not by broken links: a producer
    /// republishing a different history publishes a well-formed chain, and that is the
    /// case the admission gate must pass through to the rules.
    fn rows_diverging_at(n: u32, k: u32) -> Vec<PublicChainRow> {
        let mut out = rows(k - 1);
        let mut prev: Option<String> = out.last().map(|r| r.chain_hash.clone());
        for o in k..=n {
            let r = row(o, prev.as_deref(), format!("{:064x}", o + 1_000_000));
            prev = Some(r.chain_hash.clone());
            out.push(r);
        }
        out
    }

    /// The `chain_hash` of row `ordinal` of the canonical chain, so a `HEAD@k` built
    /// with `ch(k)` matches row `k` of any `rows(n >= k)`.
    fn ch(ordinal: u32) -> String {
        chain_rows(ordinal, 0).pop().expect("ordinal >= 1").chain_hash
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
            None,
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
        // Monitor enumerates HEAD@5 but the producer's PUBLISHED CHAIN EXPORT is
        // only N=3 rows. The export is what makes this a finding rather than a
        // question: against the package alone the same enumeration is a lag
        // (test_intent_package_only_lag_is_inconclusive_never_failed).
        let published_chain = rows(3);
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            Some(&published_chain),
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
            None,
            &[],
            &[head(3, &ch(999), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        assert!(matches!(v, Verdict::Failed { .. }), "got {v:?}");
    }

    // ---- LAG vs TRUNCATION: what the package alone cannot decide -----------
    //
    // R1's reference is the producer's PUBLISHED CHAIN EXPORT when the auditor
    // supplied one, and the package's own snapshot otherwise. The tests below pin
    // both readings of the SAME enumeration, so a change that collapses them (in
    // either direction) turns one of them red.

    /// INTENT: a package that merely LAGS the log is NEVER accused of truncation.
    /// A verdict may only accuse on evidence that distinguishes the accusation from
    /// its innocent twin; against the package alone "the producer deleted rows k..N"
    /// and "this package was emitted before head@k reached the log" are the SAME
    /// observation, so the honest outcome is a NAMED INCONCLUSO that says which
    /// input decides it.
    ///
    /// CONTEXT: measured 2026-08-26 against the producer's own live public
    /// artifacts. The published anchor package carried N=12 rows (a witness on a
    /// DAILY timer) while the log held head@14 ... head@40 and the published chain
    /// export carried 40 rows (submissions and the export run HOURLY). The tool
    /// printed `COMPLETITUD: FAILED ... rows were truncated`, exit 1 - a false
    /// accusation against an honest producer, produced by feeding `pkg.rows` to the
    /// rule.
    ///
    /// EXPIRES IF: anchor packages stop being SNAPSHOTS - i.e. a package is emitted
    /// in the same act as every head submission, so it can no longer lag the log.
    /// Then `k > N(package)` is decidable from the package again.
    #[test]
    fn test_intent_package_only_lag_is_inconclusive_never_failed() {
        // The live shape, minified: the monitor sees a head the package does not.
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            /*published_chain*/ None,
            &[],
            &[head(5, &ch(5), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        let Verdict::Inconclusive { reason } = &v else {
            panic!("a lag the package cannot decide must never be a verdict: {v:?}")
        };
        // The FULL sentence, byte for byte. A `contains("--chain")` prefix check is
        // what let two runs of 18 literal spaces - the source indentation of a
        // single-line string - ship inside the one sentence the auditor acts on.
        assert!(
            reason.contains(
                "Supply the producer's published chain export (--chain <chain.json>) to \
                 decide it: a head no published artefact reaches is truncation, one either \
                 artefact carries is lag"
            ),
            "the remedy sentence must reach the auditor intact: {reason}"
        );
        assert!(
            !reason.contains("  "),
            "no run of double spaces may reach the auditor: {reason}"
        );
        assert!(
            reason.contains("G-v6-2 UNDECIDED"),
            "the undecided case must be NAMED, not anonymous: {reason}"
        );
    }

    /// INTENT: with the producer's published chain export supplied, a head WITHIN
    /// that export is decided - it is lag, and the verdict is clean.
    /// CONTEXT: same 2026-08-26 measurement; supplying the 40-row export turned the
    /// false FAILED into CONFIRMED on the very same package and enumeration.
    /// EXPIRES IF: the export stops being a superset-in-time of the package (they
    /// would no longer be snapshots of one chain).
    #[test]
    fn test_intent_head_within_the_published_chain_is_lag_not_truncation() {
        let chain = rows(5);
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            Some(&chain),
            &[],
            &[head(5, &ch(5), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        assert_eq!(v, Verdict::Verified, "head@5 is row 5 of the published export");
    }

    /// INTENT: THE PRINCIPLE. `G-v6-2` asserts that a row VANISHED from the
    /// producer's publication; if ANY published producer artefact this run holds
    /// still carries row k, that premise is FALSE and no accusation is available -
    /// whatever the other artefact says. The reference is therefore
    /// `max(package rows, export rows)` and can only ever RISE.
    ///
    /// CONTEXT: measured 2026-08-26 on the live public artefacts, and the reason this
    /// test replaces its own predecessor. The first cut of the lag fix took the
    /// export as THE reference, so an export SHORTER than the package lowered it
    /// BELOW the package's own N: with the real package (N=12) and the real export
    /// truncated to its first 11 rows - an ordinary stale download, a CDN copy or two
    /// downloads straddling a publication - the tool accused `HEAD@12` of truncation,
    /// exit 1, in the same run that printed `CONSISTENCIA CONFIRMED OFFLINE` over the
    /// package publishing row 12. That is the lag error installed one artefact over.
    /// The predecessor test PINNED the inverted behaviour, so the tree froze it.
    ///
    /// EXPIRES IF: the anchor package stops being a producer PUBLICATION (e.g. it
    /// becomes an auditor-side artefact), so its rows are no longer evidence of what
    /// the producer publishes.
    #[test]
    fn test_intent_export_shorter_than_the_package_never_accuses() {
        // The live shape, minified: the package publishes 3 rows and the enumerated
        // head@3 matches row 3; the export in hand only reaches row 2.
        let chain = rows(2);
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            Some(&chain),
            &[],
            &[head(3, &ch(3), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        assert_eq!(
            v,
            Verdict::Verified,
            "row 3 is published by the package in this very run: no accusation is available"
        );
    }

    /// INTENT: the REAL detection survives `max`. A head that NEITHER artefact
    /// reaches did vanish from the producer's publication, and is still caught loudly
    /// under the same discriminant `G-v6-2`.
    /// CONTEXT: the guard on the fix for THE PRINCIPLE - a reference that rises must
    /// not rise past the point where the finding disappears.
    /// EXPIRES IF: `G-v6-2` is retired from the rule set.
    #[test]
    fn test_intent_head_no_published_artefact_reaches_still_fails() {
        // Package 3 rows, export cut back to 2, and the log holds head@5: no
        // published artefact of this run explains row 5.
        let chain = rows(2);
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            Some(&chain),
            &[],
            &[head(5, &ch(5), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        let Verdict::Failed { reason } = &v else {
            panic!("a deleted row must stay a FAILED: {v:?}")
        };
        assert!(
            reason.contains("rows were truncated while their tail leaf stays in the log")
                && reason.contains("G-v6-2"),
            "the truncation finding must keep its discriminant and its words: {reason}"
        );
        assert!(
            reason.contains("chain export N=2") && reason.contains("anchor package N=3"),
            "the finding must show BOTH counts it judged against: {reason}"
        );
    }

    /// INTENT: which ordinal a finding NAMES must be a property of the EVIDENCE, not
    /// of the order an artefact happened to serialize its array in. Two auditors
    /// holding the same leaves in a different order must read the same ordinal.
    /// ENFORCED ON ALL THREE rules that name one, by
    /// `test_intent_every_named_ordinal_is_order_independent`: arms (a)/(b) forgery
    /// and R3 coverage name the LOWEST offending ordinal (a divergence is most
    /// diagnostic where the histories part), arm (c) names the MAXIMUM (its claim is
    /// about REACH). This test covers arm (c).
    /// CONTEXT: the rule used to fire on the FIRST head past `n_ref` in bundle order,
    /// and the same defect survived a round in arms (a)/(b) and R3 because the
    /// invariant was stated generally and enforced on one case. Every enumeration
    /// fixture had a single `head` lane, so reversing a loop changed nothing.
    /// EXPIRES IF: the findings stop naming an ordinal at all.
    #[test]
    fn test_intent_truncation_names_the_maximum_head_not_the_first_seen() {
        let chain = rows(4);
        // Two heads past the reference, in BOTH serialization orders.
        let ascending = [head(6, &ch(6), GEN), head(9, &ch(9), GEN)];
        let descending = [head(9, &ch(9), GEN), head(6, &ch(6), GEN)];
        let mut reasons = Vec::new();
        for enumerated in [&ascending, &descending] {
            let v = apply_completitud_rules(
                SLUG,
                &rows(3),
                Some(&chain),
                &[],
                enumerated,
                &ok_identity(),
                &fresh(),
                Some(true),
            );
            let Verdict::Failed { reason } = v else {
                panic!("both heads are past N=4: expected FAILED")
            };
            assert!(
                reason.contains("HEAD@9") && !reason.contains("HEAD@6"),
                "the finding must name the MAXIMUM head: {reason}"
            );
            reasons.push(reason);
        }
        assert_eq!(
            reasons[0], reasons[1],
            "the same leaves in a different order must yield the same finding"
        );
    }

    // ---- the whitespace sweep ----------------------------------------------

    /// Reconstruct what `rustc` emits for a string literal's BODY: a backslash at
    /// end-of-line eats the newline AND the next line's leading whitespace.
    fn emitted_text(literal: &str) -> String {
        let mut out = String::new();
        let mut chars = literal.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.peek() {
                Some('\n') | Some('\r') => {
                    while matches!(chars.peek(), Some('\r') | Some('\n')) {
                        chars.next();
                    }
                    while matches!(chars.peek(), Some(' ') | Some('\t')) {
                        chars.next();
                    }
                }
                Some(_) => {
                    let escaped = chars.next().expect("peeked");
                    out.push('\\');
                    out.push(escaped);
                }
                None => out.push('\\'),
            }
        }
        out
    }

    /// Every string literal in `src`, with the 1-based line it opens on. Skips line
    /// and block comments (doc comments carry prose and `"` freely) and char
    /// literals, and does not confuse a lifetime for one.
    fn string_literals(src: &str) -> Vec<(String, usize)> {
        let c: Vec<char> = src.chars().collect();
        let mut found = Vec::new();
        let (mut i, mut line) = (0usize, 1usize);
        while i < c.len() {
            if c[i] == '\n' {
                line += 1;
                i += 1;
            } else if c[i] == '/' && c.get(i + 1) == Some(&'/') {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            } else if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                i += 2;
                let mut depth = 1usize;
                while i < c.len() && depth > 0 {
                    if c[i] == '\n' {
                        line += 1;
                    }
                    if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                        depth += 1;
                        i += 2;
                    } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            } else if c[i] == '\'' {
                // `'a` is a lifetime; `'x'` and `'\\n'` are char literals.
                let is_char = c.get(i + 2) == Some(&'\'') || c.get(i + 1) == Some(&'\\');
                if is_char {
                    i += 1;
                    while i < c.len() && c[i] != '\'' {
                        i += if c[i] == '\\' { 2 } else { 1 };
                    }
                }
                i += 1;
            } else if c[i] == '"' {
                let opened = line;
                i += 1;
                let mut lit = String::new();
                while i < c.len() && c[i] != '"' {
                    if c[i] == '\\' && i + 1 < c.len() {
                        if c[i + 1] == '\n' {
                            line += 1;
                        }
                        lit.push(c[i]);
                        lit.push(c[i + 1]);
                        i += 2;
                        continue;
                    }
                    if c[i] == '\n' {
                        line += 1;
                    }
                    lit.push(c[i]);
                    i += 1;
                }
                i += 1;
                found.push((lit, opened));
            } else {
                i += 1;
            }
        }
        found
    }

    /// INTENT: no sentence this module can EMIT may carry a run of two spaces.
    ///
    /// A run of spaces mid-sentence means source indentation was baked into a
    /// single-line literal, and nothing downstream removes it: the reasons flow
    /// through `completitud_display` into `sanitize_reserved_token`, which is a
    /// byte-for-byte token replacer and normalises no whitespace. The auditor reads
    /// the result.
    ///
    /// A SWEEP over every literal the production half of this module contains, NOT a
    /// per-sentence assertion. That is the point: two remedies were caught by hand
    /// and four more FAILED reasons could have shipped the identical defect green,
    /// three of them in the very commit that fixed the first two. A hand-written
    /// check covers the sentences someone thought of; this covers the one added next
    /// month. The test module is excluded deliberately - it contains fixtures whose
    /// double spaces are the thing under test.
    ///
    /// CONTEXT: `anchor_completitud.rs` shipped
    /// `"Supply the producer's published chain export (--chain <chain.json>) to<18
    /// spaces>decide it: ..."` to stdout, in the one sentence the `--chain` work
    /// exists to deliver.
    /// EXPIRES IF: the reasons stop being human sentences (e.g. structured fields).
    #[test]
    fn test_intent_no_emitted_sentence_carries_baked_source_indentation() {
        const SOURCE: &str = include_str!("anchor_completitud.rs");
        // The MODULE marker, not the first `#[cfg(test)]` attribute: there is a
        // `#[cfg(test)]` fn above the test module, and anchoring on the bare
        // attribute truncated this sweep to 3 literals. The floor below is what
        // caught that.
        let cut = SOURCE
            .find("#[cfg(test)]\nmod tests {")
            .or_else(|| SOURCE.find("#[cfg(test)]\r\nmod tests {"))
            .expect("the test-module marker moved; a sweep must know where to stop");
        let production = &SOURCE[..cut];
        let literals = string_literals(production);
        assert!(
            literals.len() > 20,
            "only {} literals were read; the scanner broke and a sweep that reads \
             nothing certifies nothing",
            literals.len()
        );
        for (literal, line) in literals {
            let emitted = emitted_text(&literal);
            assert!(
                !emitted.contains("  "),
                "anchor_completitud.rs:{line} emits a run of two spaces - source \
                 indentation baked into a literal: {emitted:?}"
            );
        }
    }

    // ---- rule precedence ----------------------------------------------------

    // WHAT THIS SECTION'S GUARD VERIFIES, AND WHAT IT TRUSTS. Read before adding to
    // it; do not widen any sentence below past this list.
    //
    // VERIFIED AT RUN TIME, by comparing DATA with DATA:
    //
    //   * the arms' accusation signatures are pairwise non-containing, so a pair that
    //     passes really did tell its two arms apart.
    //   * the sweep visits EVERY ordered pair of arms - checked against an `expected`
    //     set derived from the DEFINITION of the upper triangle, and again against
    //     the closed form n(n-1)/2, neither of which reads the loop's own bounds.
    //   * for each pair the RULES ARE RUN on real evidence and the returned reasons
    //     are compared: the lower arm speaks alone once the higher arm's ingredient
    //     is removed, the higher arm is then silent, and with both present the higher
    //     arm's accusation is the one reported and the lower one's is absent.
    //   * each pair's INDEX TUPLE is compared against the FIELD its removal writes -
    //     read off `RemoveHigher::writes`, not off the variant's NAME - so a removal
    //     that writes a field the lower arm reads cannot spread to a pair it was
    //     never reasoned about, and a variant added under a different name is scoped
    //     the same as the one it copies (`removal_is_registered_for_pair`).
    //
    // ENFORCED BY THE COMPILER, not by comparison - a fact about the source, and it
    // reddens as a build failure rather than as a failed assertion:
    //
    //   * `DECLARED_PRECEDENCE` carries one row per arm of the production `fired`
    //     array, because both are declared with `PRECEDENCE_ARMS`. An arm added to
    //     the rules cannot reach this table by accident and cannot avoid it either:
    //     bumping the constant without registering the arm does not compile.
    //   * `RemoveHigher::writes` is exhaustive over its variants (`E0004`) and names
    //     the field each one overwrites. `apply` is written over ITS result, and
    //     passes every field it does not name THROUGH by `..e.clone()`, so a field
    //     added to `Evidence` cannot be dropped between `both` and the lower-arm
    //     case, and a variant cannot overwrite one field while being scoped as if it
    //     wrote another - there is ONE match over the variants, not two. The scope
    //     check reads that same result and is exhaustive over the FIELDS (`E0004`
    //     again), so a removal added tomorrow must DECLARE which field it writes, and
    //     a field added to `Written` must be given a scope before any pair can use it.
    //     What no `E0004` forces is a decision PER VARIANT - see the residual below.
    //
    // TRUSTED, stated rather than simulated: the fixtures in `pair_fixture` - the
    // evidence sets, and which ingredient each pair removes - are HUMAN-REVIEWED
    // CODE. Nothing here verifies that a fixture is the evidence its comment says it
    // is. Nor does anything DERIVE which fields an arm reads: the guard derives which
    // field a removal WRITES, never which fields an arm READS. That a removal only
    // ever REMOVES its arm's ingredient and never ENABLES the lower one is reasoned
    // by eye, per variant, and the scope check is what pins that reasoning to the
    // pairs it was actually done for. Keeping the removal down to two data variants
    // and one `apply`, rather than a closure per fixture, is what keeps it checkable.
    //
    // DECLARED RESIDUAL, measured rather than argued - the price of keying the scope
    // on the FIELD: a removal variant added tomorrow that writes an ALREADY-SCOPED
    // field inherits that field's scope with nobody deciding anything. For
    // `Written::Lanes` that inherited scope is "unscoped", so a lanes-writing variant
    // that ENABLES an arm goes through the sweep green. Measured on this tree: a
    // variant `UnforgeAndExtend(u64)` whose `writes` returns `Written::Lanes(..)`
    // after APPENDING a head beyond both artefacts compiles, switches arm (c) on by
    // the removal itself, and the suite still reports `351 passed`; on `b980354e` -
    // before the scope check was moved onto `writes` - that same mutant did NOT
    // compile, because the scope `match` was over the VARIANTS and `E0004` there
    // forced a pair decision for every new one. What bounds this now is review of
    // each variant's BODY, per variant, and not the compiler. It is the same eye that
    // decides a removal only ever REMOVES its arm's ingredient, stated once more
    // because moving the scope to the field widened what that eye is responsible for.
    //
    // WHAT WAS REMOVED HERE, so nobody rebuilds it: an earlier revision tried to
    // PROVE that each pair's removal read its input, by perturbing that input at two
    // points and checking the output noticed. Measured, on the pristine tree: a
    // straight closure - `export_rows = 2 * lanes.len() + 3 * package_rows - 2` -
    // satisfies BOTH probes and lets this branch's headline defect through green.
    // Two probes plus the unprobed real call are three conditions, and an affine
    // derivation of three terms has three free coefficients, so the family is
    // generically solvable; a third, non-coplanar probe closes that family and opens
    // the next. A universally quantified property - "for every input, the output
    // depends on it" - is not established by a FINITE number of examples against a
    // closure that can recognise them. Examples refute; they do not prove. So the
    // probes are gone and the property is STRUCTURAL instead: the removal is data the
    // guard applies, and there is no closure left to sample.

    /// One arm of the R1/R2/R3 precedence as the GUARD sees it: what it is called
    /// where the rules are written, and the fragment of its accusation that belongs
    /// to it and to no other arm.
    struct DeclaredArm {
        name: &'static str,
        signature: &'static str,
    }

    /// The DECLARED precedence, highest first - the same order as the `fired` array
    /// in `completitud_rules`, and the same order the module comment states.
    ///
    /// Its length is `PRECEDENCE_ARMS`, the production constant the `fired` array is
    /// declared with. An arm added to the rules therefore cannot reach this table by
    /// accident and cannot avoid it either: bumping the constant without adding a row
    /// here does not compile.
    const DECLARED_PRECEDENCE: [DeclaredArm; PRECEDENCE_ARMS] = [
        DeclaredArm {
            name: "(a) forged against the PACKAGE's rows",
            signature: "does not match published row",
        },
        DeclaredArm {
            name: "(b) forged against the EXPORT's rows",
            signature: "does not match the producer's published chain export at row",
        },
        DeclaredArm {
            name: "(c) the LENGTH rule - no artefact reaches M",
            signature: "rows were truncated",
        },
    ];

    /// One evidence set the pairwise guard runs.
    #[derive(Clone)]
    struct Evidence {
        package_rows: u32,
        export_rows: u32,
        lanes: Vec<AuthLane>,
    }

    /// Make the enumerated head at `ordinal` agree with the canonical rows again -
    /// the edit that removes a FORGERY arm's ingredient without touching anything
    /// else the evidence carries.
    ///
    /// It MAPS over the lanes it is given rather than rebuilding a lane list from
    /// literals, and that is the load-bearing part: a lane deleted from the `both`
    /// evidence is deleted here too, so the liveness check below runs on the same
    /// lanes. A version that returned `vec![head(3, ..), head(9, ..)]` would silently
    /// restore whatever `both` had lost, which is the hole this whole derivation
    /// exists to close.
    fn unforge_head_at(lanes: &[AuthLane], ordinal: u64) -> Vec<AuthLane> {
        lanes
            .iter()
            .map(|l| match &l.lane {
                Lane::Head {
                    slug, ordinal: k, ..
                } if *k == ordinal => AuthLane {
                    lane: Lane::Head {
                        slug: slug.clone(),
                        ordinal,
                        chain_hash: ch(ordinal as u32),
                    },
                    ..l.clone()
                },
                _ => l.clone(),
            })
            .collect()
    }

    fn run_evidence(e: &Evidence) -> Verdict {
        let package = rows(e.package_rows);
        let export = rows(e.export_rows);
        apply_completitud_rules(
            SLUG,
            &package,
            Some(&export),
            &[],
            &e.lanes,
            &ok_identity(),
            &fresh(),
            Some(true),
        )
    }

    /// The evidence for ONE ordered pair of arms: ONE evidence set, plus the edit
    /// that removes the HIGHER arm's ingredient from it.
    ///
    /// `both` fires the two arms together. The lower-arm case is DERIVED from it -
    /// `both` with one ingredient removed - rather than written beside it, and the
    /// derivation is the whole point.
    ///
    /// A fixture in which the LOWER arm is mute shows only the higher arm firing
    /// alone and certifies nothing about precedence - that is exactly how the shipped
    /// guard missed the `acb` permutation, reusing a fixture that had arm (c) silent.
    /// The first repair gave each pair a SECOND, independently written evidence set
    /// and checked the lower arm spoke THERE. That checked the wrong object: the two
    /// sets were unrelated literals, so deleting one lane from `both` left the
    /// liveness half untouched and reopened the same hole at green. Measured: with
    /// `head(9, ..)` gone from the (b)/(c) `both` fixture, arm (c) never fired, the
    /// pair certified nothing, and the `acb` permutation passed 351/351 (`--lib`).
    ///
    /// So the removal is not a closure. [`RemoveHigher`] is DATA - WHICH ingredient
    /// to remove - and the single [`RemoveHigher::apply`] that interprets it starts
    /// from the evidence it is handed and passes every field it does not name through
    /// by `..e.clone()`. What that buys, exactly: a fixture cannot DROP a field
    /// between `both` and the lower-arm case, and it cannot rebuild the LANES from
    /// literals - `UnforgeHeadAt` carries an ordinal, not a lane list, and
    /// `unforge_head_at` maps over the lanes it is handed. It does not make the
    /// removal literal-free in general: `ShortenPackageTo(u32)` writes `package_rows`
    /// verbatim, which is why that variant's scope is checked against the pair it was
    /// reasoned for. The revision this replaces held a `fn(&Evidence) -> Evidence`
    /// pointer, where rebuilding the whole evidence WAS expressible, and spent two
    /// rounds failing to detect it by perturbing the input - see the note at the head
    /// of this section for why that could not work.
    ///
    /// WHAT THIS STILL DOES NOT PROVE, stated rather than glossed: the guard observes
    /// the lower arm speaking in `both` MINUS the higher arm's ingredient, never in
    /// `both` itself - a `Verdict` carries one reason, the winning arm's, so the
    /// loser's firing is not observable while the winner is present and no assertion
    /// on the returned `Verdict` can reach it. Going from the one to the other rests
    /// on a removal only ever REMOVING an arm's ingredient, never enabling one. THAT
    /// is not asserted; it is kept checkable by eye, and keeping the removal down to
    /// two data variants with one `apply` is what keeps it so.
    struct PairFixture {
        both: Evidence,
        /// `both` with the HIGHER arm's ingredient removed and nothing else changed.
        remove_higher: RemoveHigher,
    }

    /// The edit that removes ONE arm's ingredient from a piece of evidence, as DATA.
    ///
    /// Each variant names a whole field of the evidence, or a part of one.
    /// [`RemoveHigher::writes`] is the one `match` over the variants, and it is
    /// exhaustive, so a new kind of removal cannot be added without deciding there
    /// which field it overwrites and with what (`E0004`).
    /// [`RemoveHigher::apply`] is the only thing that interprets it INTO EVIDENCE, and
    /// it reads that result rather than the variants; `removal_is_registered_for_pair`
    /// reads the same result, to decide which pairs may use it.
    #[derive(Clone, Copy)]
    enum RemoveHigher {
        /// Shorten the package to this row count, below the offending row. That
        /// silences arm (a), which reads the package's rows; the export still covers
        /// the row, so arm (b) keeps exactly the evidence it had. Arm (c) DOES reach
        /// `package_rows`, through the resolved reference - which is why this variant
        /// is registered for the (a) over (b) pair alone, and why that scoping is
        /// ASSERTED in `removal_is_registered_for_pair` rather than left to this
        /// sentence. What moving it to the (a) over (c) pair actually does, measured
        /// by running the rules on that pair's evidence with each removal in turn:
        /// AS THAT FIXTURE IS WRITTEN (`package_rows: 5`) this variant is a SOUND
        /// alternative - it silences (a) and the reported reason becomes arm (c)'s
        /// truncation, and (c) was already speaking there, since the registered
        /// `UnforgeHeadAt(3)` reports that same truncation from that same `both`. It
        /// is rejected by REGISTRATION, not because that evidence caught it enabling
        /// anything. ENABLING takes a SECOND value: widen that fixture's package to 9
        /// rows and `UnforgeHeadAt(3)` returns `Verified` - with (a) silenced nothing
        /// accuses, so arm (c) is not firing on that evidence - while
        /// `ShortenPackageTo(1)` still reports the truncation. There the edit switched
        /// (c) ON, and liveness would be satisfied by an arm the edit created.
        ShortenPackageTo(u32),
        /// Un-forge the enumerated head at this ordinal. That silences whichever
        /// forgery arm was comparing that head's `chain_hash` against an artefact;
        /// the ordinal SET is untouched and both artefacts are passed through, so arm
        /// (c) - computed from the MAXIMUM enumerated ordinal against the resolved
        /// reference - keeps its evidence.
        UnforgeHeadAt(u64),
    }

    /// WHICH field of the evidence a removal overwrites, and the value it writes
    /// there.
    ///
    /// ONE `match` over `RemoveHigher` produces it - [`RemoveHigher::writes`] - and
    /// both the evidence [`RemoveHigher::apply`] returns and the scope
    /// `removal_is_registered_for_pair` enforces are read off THAT. So a variant
    /// cannot overwrite one field while being scoped as if it wrote another, and it
    /// cannot leave a scope by being given a new NAME: the scope keys on this enum,
    /// which the variant's own body picks.
    enum Written {
        PackageRows(u32),
        Lanes(Vec<AuthLane>),
    }

    impl RemoveHigher {
        /// The field this removal overwrites, and with what.
        ///
        /// Exhaustive over the variants (`E0004`): a removal added tomorrow cannot be
        /// written at all without naming the field it touches.
        fn writes(self, e: &Evidence) -> Written {
            match self {
                RemoveHigher::ShortenPackageTo(rows) => Written::PackageRows(rows),
                RemoveHigher::UnforgeHeadAt(ordinal) => {
                    Written::Lanes(unforge_head_at(&e.lanes, ordinal))
                }
            }
        }

        /// `e` with ONE ingredient removed and every other field passed THROUGH.
        ///
        /// The `..e.clone()` is the load-bearing part, and the reason this is a method
        /// over data instead of a closure per fixture: it is written ONCE, it starts
        /// from the evidence it was handed, and a field added to `Evidence` tomorrow
        /// travels through it without anyone having to remember to carry it.
        ///
        /// It interprets `writes`, not the variants, so the field it overwrites is the
        /// one the scope check was applied to.
        fn apply(self, e: &Evidence) -> Evidence {
            match self.writes(e) {
                Written::PackageRows(package_rows) => Evidence {
                    package_rows,
                    ..e.clone()
                },
                Written::Lanes(lanes) => Evidence { lanes, ..e.clone() },
            }
        }
    }

    /// Which ordered pairs a removal is registered for, compared as DATA (the pair's
    /// index tuple) against DATA (the FIELD the removal `pair_fixture` returned
    /// writes, read off `RemoveHigher::writes`).
    ///
    /// It keys on the FIELD, never on the variant's NAME. A second variant with the
    /// same body under a different name therefore lands in the same arm here, instead
    /// of falling through the unscoped one.
    ///
    /// WHY THIS EXISTS. The liveness assertion in the sweep reads "the lower arm
    /// speaks in `both` MINUS the higher arm's ingredient". It certifies precedence
    /// only if the minus really was a REMOVAL: an edit that ENABLES the lower arm
    /// makes the same assertion pass while the lower arm is mute in the `both` the
    /// precedence half actually runs. Nothing here derives which fields an arm reads
    /// - that is reasoned by eye, per variant, in the `RemoveHigher` doc comments.
    /// What this DOES is stop that reasoning from being silently extended to a pair
    /// it was never done for.
    ///
    /// measured, which is why it is code and not a sentence. Both measurements are on
    /// the (a) over (c) fixture, by running the rules on its evidence with each
    /// removal in turn:
    ///
    ///   * retyping its `UnforgeHeadAt(3)` as `ShortenPackageTo(1)` - ONE token, the
    ///     package left at 5 rows - is SOUND: the edit silences (a) and the reason
    ///     reported becomes arm (c)'s truncation, which the registered
    ///     `UnforgeHeadAt(3)` also reports from that same `both`. Arm (c) was speaking
    ///     there either way. This function rejects that edit anyway, and for what it
    ///     IS - a removal that writes `package_rows` on a pair nobody reasoned it for
    ///     - not because the evidence caught it enabling anything.
    ///   * the ENABLING edit needs a SECOND value. Widen that fixture's package to 9
    ///     rows: `UnforgeHeadAt(3)` then returns `Verified` - with (a) silenced,
    ///     nothing accuses, so arm (c) is not firing on that evidence - while
    ///     `ShortenPackageTo(1)` still reports the truncation. The sweep's liveness
    ///     assertion asks only that the lower arm speak in `both` MINUS the removal,
    ///     so without this function it would pass on an arm the removal switched ON.
    ///
    /// The `match` is exhaustive over `Written` (`E0004`), and `writes` is exhaustive
    /// over `RemoveHigher`, so a removal added tomorrow must declare WHICH field it
    /// writes, and a field added to `Written` must be given a scope here before any
    /// pair can use it. Neither `E0004` forces a decision PER VARIANT, though: a new
    /// variant that writes an ALREADY-SCOPED field inherits that field's scope
    /// untouched. For `Written::Lanes` that is "unscoped", so a lanes-writing variant
    /// that ENABLES an arm passes this function - a declared residual, written up in
    /// full in the section comment above `DeclaredArm`, bounded by review of each
    /// variant's body rather than by the compiler.
    fn removal_is_registered_for_pair(
        higher: usize,
        lower: usize,
        removal: RemoveHigher,
        both: &Evidence,
    ) {
        match removal.writes(both) {
            // Writes `package_rows`, which arm (c) reads through the resolved
            // reference. Registered for (a) over (b) alone.
            Written::PackageRows(_) => assert_eq!(
                (higher, lower),
                (0, 1),
                "a removal that writes `package_rows` is registered for the ({} over \
                 {}) pair alone, but ({} over {}) uses one. It EDITS `package_rows`, \
                 and an arm that READS `package_rows` - arm (c) does, through the \
                 resolved reference - can be \
                 switched ON by it rather than left alone, which turns the liveness \
                 assertion below into a check on an arm the edit created. Register a \
                 removal whose field this pair's lower arm does not read, or widen this \
                 scope only with the reasoning for the new pair written down",
                DECLARED_PRECEDENCE[0].name,
                DECLARED_PRECEDENCE[1].name,
                DECLARED_PRECEDENCE[higher].name,
                DECLARED_PRECEDENCE[lower].name
            ),
            // Writes the LANES. Unscoped on purpose, and the reason is a property of
            // the ONE variant registered today, not of the field: `UnforgeHeadAt`
            // rewrites the `chain_hash` of a head that is ALREADY enumerated, leaving
            // the ordinal SET and both artefacts' row counts alone, so no arm's
            // ingredient is created by it. This arm does NOT vouch for a lanes-writing
            // variant added tomorrow - one that APPENDS a head beyond both artefacts
            // would land here unscoped and switch arm (c) on. See the DECLARED
            // RESIDUAL in the section comment above `DeclaredArm`; what covers a new
            // variant is reading its body, not reaching this line.
            Written::Lanes(_) => {}
        }
    }

    /// Registered evidence per ordered pair. A pair with no entry PANICS by name:
    /// that is how an added arm is prevented from being silently uncovered.
    fn pair_fixture(higher: usize, lower: usize) -> PairFixture {
        match (higher, lower) {
            // (a) vs (b): an export identical to the package (so gate 2 admits it)
            // and a head whose chain_hash matches NEITHER.
            //
            // EDITS `package_rows`. THIS pair's lower arm does not read it: (b) is
            // computed from `chain` and the lanes, both passed through. (Arm (c) DOES
            // reach it, through the resolved reference - which is why this is scoped
            // to the pair and not claimed of the field, and why
            // `removal_is_registered_for_pair` asserts that scope rather than leaving
            // it to this comment.) Shortening the package below
            // the offending row is what silences (a); the export still covers that
            // row, so (b) keeps exactly the evidence it had.
            (0, 1) => PairFixture {
                both: Evidence {
                    package_rows: 5,
                    export_rows: 5,
                    lanes: vec![head(2, &ch(999), GEN)],
                },
                remove_higher: RemoveHigher::ShortenPackageTo(1),
            },
            // (a) vs (c): a forged head the PACKAGE covers but the (shorter) export
            // does not, plus a head past the reference.
            //
            // EDITS one lane's `chain_hash`. THIS pair's lower arm does not read it:
            // arm (c) is computed from the MAXIMUM enumerated ORDINAL against the
            // resolved reference, and un-forging a head changes neither - the ordinal
            // set is untouched and both artefacts are passed through.
            (0, 2) => PairFixture {
                both: Evidence {
                    package_rows: 5,
                    export_rows: 1,
                    lanes: vec![head(3, &ch(903), GEN), head(9, &ch(9), GEN)],
                },
                remove_higher: RemoveHigher::UnforgeHeadAt(3),
            },
            // (b) vs (c): a forged head only the EXPORT covers, plus a head past the
            // reference. Same edit and same reasoning as (a) vs (c).
            (1, 2) => PairFixture {
                both: Evidence {
                    package_rows: 1,
                    export_rows: 5,
                    lanes: vec![head(3, &ch(903), GEN), head(9, &ch(9), GEN)],
                },
                remove_higher: RemoveHigher::UnforgeHeadAt(3),
            },
            _ => panic!(
                "no evidence registered for the ordered pair ({} over {}): a precedence \
                 arm was added and its pairs were not, so nothing certifies which of the \
                 two reaches the auditor. Register evidence that fires BOTH, plus the \
                 edit that removes the higher arm's ingredient FROM THAT SAME evidence - \
                 a second, independently written evidence set does not certify that the \
                 lower arm was ever alive in the first one",
                DECLARED_PRECEDENCE[higher].name, DECLARED_PRECEDENCE[lower].name
            ),
        }
    }

    /// INTENT: when more than one finding rule fires, WHICH accusation reaches the
    /// auditor is a DECLARED order, and the declaration is enforced over EVERY
    /// ordered pair of arms - not over the one pair somebody wrote a case for.
    ///
    /// CONTEXT: the guard this replaces drove a single fixture and pinned (a) before
    /// (c). Its own docstring narrowed to "(a) before (c) is the one with teeth"
    /// while the module comment declared the relation over (a) AND (b), and the
    /// commit installing it claimed both were pinned. Measured: the permutation
    /// `acb` - the length arm moved between the two forgery arms - ran 407/407 GREEN
    /// and replaced a hash-forgery finding with a truncation accusation. Pinning
    /// sentences one at a time is what left the property open.
    ///
    /// WHY PAIRS SUFFICE: the precedence is a strict total order, and a strict total
    /// order is determined by its ordered pairs - a wrong permutation is wrong on at
    /// least one pair, and that pair's case reddens. So the guard is complete for the
    /// arms it knows, and `PRECEDENCE_ARMS` plus the unregistered-pair panic are what
    /// stop it from not knowing one.
    ///
    /// That argument carries only while each pair's evidence fires BOTH its arms: a
    /// lower arm absent because it never fired is indistinguishable, in the reported
    /// reason, from one absent because it was outranked, and a pair whose lower arm
    /// is mute reddens for no permutation at all. Two DISTINCT things are needed for
    /// that premise, and they are held by two distinct mechanisms:
    ///
    ///   * the lower-arm case must be the SAME evidence as `both`, so a lane deleted
    ///     from `both` is deleted from it too. That is structural: each pair's
    ///     lower-arm case IS `both` with one ingredient removed, the removal is data
    ///     the guard applies, and `apply` passes through every field it does not name,
    ///     so the two cases cannot be edited apart.
    ///   * the removal must SUBTRACT and not ADD, or the lower arm can be speaking in
    ///     the derived case only because the edit switched it on. Nothing here derives
    ///     that; it is reasoned by eye per removal variant, and
    ///     `removal_is_registered_for_pair` asserts that the reasoning is not reused
    ///     on a pair it was never done for - keyed on the FIELD the removal writes, so
    ///     a variant under a new name is scoped like the one it copies. measured, on
    ///     the (a) over (c) fixture with its package widened to 9 rows: a removal that
    ///     shortens the package - the field arm (c) READS - has the truncation
    ///     reported, while the registered `UnforgeHeadAt(3)` returns `Verified` on
    ///     that same widened `both`. The removal had switched arm (c) ON. See
    ///     `removal_is_registered_for_pair` for both measurements, including the
    ///     one-token edit that is SOUND and out of scope anyway.
    ///
    /// See `PairFixture` for what the derivation buys and, precisely, what it does
    /// not.
    ///
    /// The bound on the (a)/(b) pair, so its red is not over-read: arms (a) and (b)
    /// can never name DIFFERENT ordinals, because `admit_chain_export` forces
    /// byte-equal rows over the overlap - below the overlap they fire on the same
    /// `k`, above it only one range is non-empty. Swapping them changes which
    /// ARTEFACT the auditor is pointed at, never the ordinal. (a)/(b) against (c) is
    /// the pair with teeth: different gates, different accusations, so a wrong order
    /// REPLACES the finding instead of rewording it.
    ///
    /// EXPIRES IF: the precedence stops being a strict total order - e.g. two arms
    /// are declared incomparable because they can never fire together.
    #[test]
    fn test_intent_declared_precedence_holds_for_every_ordered_pair() {
        assert!(
            PRECEDENCE_ARMS >= 2,
            "a precedence over fewer than two arms is not a precedence"
        );
        // A signature contained in another arm's signature would let a pair pass
        // without either arm having been distinguished.
        for (i, a) in DECLARED_PRECEDENCE.iter().enumerate() {
            for (j, b) in DECLARED_PRECEDENCE.iter().enumerate() {
                assert!(
                    i == j || !a.signature.contains(b.signature),
                    "{} and {} do not have distinguishable signatures, so no pair \
                     involving them measures anything",
                    a.name,
                    b.name
                );
            }
        }

        // WHICH PAIRS THE SWEEP ACTUALLY VISITED, collected as it goes.
        //
        // This was once deleted as "a tautology": the loops have no `continue` and no
        // early exit, so the count held unconditionally and could only fail by not
        // being reached. That read "cannot fail today by construction" as "is worth
        // nothing", when its whole value is catching TOMORROW's change of
        // construction. Measured after the deletion: `(higher + 1)` -> `(higher + 2)`,
        // ONE character, cut the sweep from three pairs to one and ran 408/408
        // GREEN (the aggregate over the crate's targets; `--lib` alone reports 351);
        // with the `acb` permutation on top, also 408/408 - the branch's headline
        // defect, a G-v6-3 forgery swapped for a G-v6-2 truncation, fully reopened.
        // Before the deletion that same mutant reddened `left: 1 right: 3`.
        //
        // Nothing else covers it. The loop bounds are what such a mutant EDITS;
        // `PRECEDENCE_ARMS >= 2` counts no pairs; and `pair_fixture` panics only when
        // it is CALLED - a pair the loop never visits calls nothing, so the
        // unregistered-pair panic is silent for exactly the pairs that went missing.
        //
        // The `EXPIRES IF` above names the change that would put a `continue` here:
        // two arms declared incomparable because they can never fire together. That is
        // why the push sits at the BOTTOM of the body rather than the top - see the
        // note beside it, and the measurement that forced the move.
        let mut visited: Vec<(usize, usize)> = Vec::new();
        (0..PRECEDENCE_ARMS)
            .flat_map(|higher| {
                ((higher + 1)..PRECEDENCE_ARMS).map(move |lower| (higher, lower))
            })
            .for_each(|(higher, lower)| {
                let hi = &DECLARED_PRECEDENCE[higher];
                let lo = &DECLARED_PRECEDENCE[lower];
                let fixture = pair_fixture(higher, lower);

                // SCOPE: the removal this pair registered must be one that was
                // reasoned about FOR THIS PAIR. Data against data - the pair's index
                // tuple against the FIELD the removal writes - and severable from
                // everything below it.
                removal_is_registered_for_pair(
                    higher,
                    lower,
                    fixture.remove_higher,
                    &fixture.both,
                );

                // LIVENESS: the lower arm must be able to speak in this shape, or the
                // pair proves nothing about which of the two the precedence picked.
                //
                // DERIVED, not written beside `both`: `remove_higher` is DATA, and the
                // `apply` that interprets it starts from `both` and passes every field
                // it does not name through. A lane deleted from `both` is therefore
                // deleted here too, instead of being quietly restored by a second set
                // of literals - the hole that ran 351/351 GREEN (`--lib`) with arm (c)
                // mute in the (b)/(c) fixture and the `acb` permutation on top.
                let lower_alone = fixture.remove_higher.apply(&fixture.both);

                let alone = run_evidence(&lower_alone);
                let Verdict::Failed { reason: alone } = &alone else {
                    panic!("{} alone must FAIL in its own fixture: {alone:?}", lo.name)
                };
                assert!(
                    alone.contains(lo.signature),
                    "the fixture for ({} over {}) leaves {} MUTE, so it cannot show which \
                     arm the precedence chose: {alone}",
                    hi.name,
                    lo.name,
                    lo.name
                );
                assert!(
                    !alone.contains(hi.signature),
                    "removing {}'s ingredient did not silence it, so the pair is not \
                     isolating the two arms: {alone}",
                    hi.name
                );

                // PRECEDENCE: both fire, the higher arm's accusation is the one
                // reported, and the lower one's is ABSENT - replaced, not reworded.
                let both = run_evidence(&fixture.both);
                let Verdict::Failed { reason: both } = &both else {
                    panic!(
                        "{} and {} must both fire and FAIL: {both:?}",
                        hi.name, lo.name
                    )
                };
                assert!(
                    both.contains(hi.signature),
                    "{} must outrank {}, but its accusation is not the one reported: {both}",
                    hi.name,
                    lo.name
                );
                assert!(
                    !both.contains(lo.signature),
                    "{} must not replace {} in the report: {both}",
                    lo.name,
                    hi.name
                );

                // RECORDED LAST, inside a CLOSURE, and both halves are load-bearing.
                //
                // The rule: a coverage collector records where the work is DONE, never
                // where it BEGINS. At entry it certifies only that a case was stepped
                // on; at exit, that the case was checked. An exit path between the
                // record and the checks makes the collector measure a larger set than
                // the one verified, and the green grows with the hole.
                //
                // Recording last is not enough on its own, because `return` leaves the
                // FUNCTION: the post-loop assertion never runs and cannot fail. That is
                // why the sweep is a `for_each` over a pair iterator rather than nested
                // `for` loops - an early exit now leaves the CLOSURE, the iteration
                // continues, and the missing pair still reaches the assertion.
                //
                // The exit paths out of THIS closure, each measured rather than
                // listed. An earlier version named five from intuition and the one
                // that mattered was among the two nobody had run:
                //
                //   * `continue`       -> `error[E0267]`
                //   * `break`          -> `error[E0267]`
                //   * `return;`        -> compiles (the closure owes `()`) and leaves
                //                         only the closure. The pair never reaches
                //                         `visited`: RED naming it, `left:
                //                         [(0,1),(0,2)] right: [(0,1),(0,2),(1,2)]`.
                //   * `return (h, l);` -> `error[E0308]`, the closure owes `()`
                //
                // What the shape does NOT close, said plainly rather than generalised:
                // a `for` loop written INSIDE this closure has its own `continue` and
                // `break` again, and a measured earlier revision shipped exactly that.
                // The shape is a CONVENTION that must be repeated at every nesting
                // level; nothing here enforces it one level down.
                //
                // Two earlier layouts are the reason for both halves. With the push at
                // the TOP of a `for` body, a `continue` behind it ran 408/408 GREEN
                // (aggregate) and, with the array permuted to `acb`, also 408/408. With
                // the push at the BOTTOM of a `for` body, `continue` and `break` were
                // caught but `return;` still ran 408/408 GREEN, `acb` included. Pair
                // (1,2) is the only pair separating the (b) forgery accusation from the
                // (c) truncation one, so either hole reopened the headline defect.
                visited.push((higher, lower));
            });
        // The upper triangle, derived from the DEFINITION of "ordered pair of distinct
        // arms" - a filtered full product - and NOT from the loop's own bounds. That
        // independence is the point: editing the bounds moves `visited` and leaves
        // `expected` exactly where it was, so the two cannot be walked off together by
        // one edit.
        let expected: Vec<(usize, usize)> = (0..PRECEDENCE_ARMS)
            .flat_map(|h| (0..PRECEDENCE_ARMS).map(move |l| (h, l)))
            .filter(|(h, l)| h < l)
            .collect();
        assert_eq!(
            visited, expected,
            "the guard did not drive every ordered pair of the declared precedence. A \
             pair it never visits is a pair no fixture is ever demanded for, and the \
             unregistered-pair panic cannot fire for a call that never happens"
        );
        // The closed form, independently: a THIRD expression of the same fact, so no
        // single edit moves the sweep and its expectation together.
        assert_eq!(
            visited.len(),
            PRECEDENCE_ARMS * (PRECEDENCE_ARMS - 1) / 2,
            "a strict total order over {PRECEDENCE_ARMS} arms has {} ordered pairs, \
             and the sweep drove {}",
            PRECEDENCE_ARMS * (PRECEDENCE_ARMS - 1) / 2,
            visited.len()
        );
    }

    /// The invariant on the OTHER two rules that name an ordinal, so the general
    /// claim above is enforced generally: the forgery rules (arms a/b) and R3
    /// coverage. Each is driven with two offending ordinals in BOTH serialization
    /// orders; the reason must be byte-identical and must name the LOWEST.
    #[test]
    fn test_intent_every_named_ordinal_is_order_independent() {
        // --- arm (a): two forged heads against the PACKAGE's rows ---------------
        // ONE evidence set, serialized two ways. Building the lanes inside the
        // closure varied the chain_hash payload with the ordinal, so the two runs
        // compared different evidence rather than one enumeration REORDERED - which
        // is the only thing the invariant is about.
        let (low, high) = (head(2, &ch(902), GEN), head(4, &ch(904), GEN));
        let forged_a = |lanes: &[AuthLane]| {
            apply_completitud_rules(
                SLUG,
                &rows(5),
                None,
                &[],
                lanes,
                &ok_identity(),
                &fresh(),
                Some(true),
            )
        };
        let (up, down) = (
            forged_a(&[low.clone(), high.clone()]),
            forged_a(&[high.clone(), low.clone()]),
        );
        let (Verdict::Failed { reason: up }, Verdict::Failed { reason: down }) = (up, down) else {
            panic!("two forged heads must FAIL")
        };
        assert_eq!(up, down, "arm (a) must not depend on bundle order");
        assert!(
            up.contains("HEAD@2") && !up.contains("HEAD@4"),
            "arm (a) must name the LOWEST forged ordinal: {up}"
        );

        // --- arm (b): forged against the EXPORT's rows, package silent ----------
        // The package reaches 1 row, so arm (a) cannot fire; the 5-row export can.
        let export = rows(5);
        let (low, high) = (head(3, &ch(903), GEN), head(5, &ch(905), GEN));
        let forged_b = |lanes: &[AuthLane]| {
            apply_completitud_rules(
                SLUG,
                &rows(1),
                Some(&export),
                &[],
                lanes,
                &ok_identity(),
                &fresh(),
                Some(true),
            )
        };
        let (up, down) = (
            forged_b(&[low.clone(), high.clone()]),
            forged_b(&[high.clone(), low.clone()]),
        );
        let (Verdict::Failed { reason: up }, Verdict::Failed { reason: down }) = (up, down) else {
            panic!("two forged heads must FAIL")
        };
        assert_eq!(up, down, "arm (b) must not depend on bundle order");
        assert!(
            up.contains("chain export at row 3") && !up.contains("HEAD@5"),
            "arm (b) must name the LOWEST forged ordinal: {up}"
        );

        // --- R3 coverage: two published heads the enumeration omits -------------
        let published = |first: u64, second: u64| {
            [
                Lane::Head {
                    slug: SLUG.to_string(),
                    ordinal: first,
                    chain_hash: ch(first as u32),
                },
                Lane::Head {
                    slug: SLUG.to_string(),
                    ordinal: second,
                    chain_hash: ch(second as u32),
                },
            ]
        };
        let coverage = |first: u64, second: u64| {
            apply_completitud_rules(
                SLUG,
                &rows(5),
                None,
                &published(first, second),
                // The monitor shows only head@1, so 2 and 4 are both omitted.
                &[head(1, &ch(1), GEN)],
                &ok_identity(),
                &fresh(),
                Some(true),
            )
        };
        let (up, down) = (coverage(2, 4), coverage(4, 2));
        let (Verdict::Failed { reason: up }, Verdict::Failed { reason: down }) = (up, down) else {
            panic!("two omitted heads must FAIL")
        };
        assert_eq!(up, down, "R3 must not depend on the package's array order");
        assert!(
            up.contains("HEAD@2") && !up.contains("HEAD@4"),
            "R3 must name the LOWEST omitted ordinal: {up}"
        );
    }

    /// A whitespace near-miss of the ledger joiner is masked too: case-folding alone
    /// still let `ALSO  UNDECIDED` through to a skimming reader.
    #[test]
    fn ledger_joiner_mask_is_whitespace_insensitive() {
        for near_miss in [
            "x. also  UNDECIDED: injected",   // whitespace run
            "x. ALSO. UNDECIDED: injected",   // punctuation between the words
            "x. ALSO-UNDECIDED: injected",    // no space at all
        ] {
            assert!(
                !mask_ledger_joiner(near_miss).to_ascii_lowercase().contains("undecided"),
                "near-miss survived the mask: {near_miss}"
            );
        }
        let mut chain = rows(3);
        chain[1].chain_prev_hash = Some("x. also  UNDECIDED: injected".to_string());
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            Some(&chain),
            &[],
            &[head(3, &ch(3), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        let Verdict::Inconclusive { reason } = &v else {
            panic!("got {v:?}")
        };
        assert!(reason.contains("[masked]"), "{reason}");
        assert!(
            !reason.to_ascii_lowercase().contains("undecided: injected"),
            "a whitespace near-miss survived: {reason}"
        );
    }

    /// The mask's NEGATIVE control: what innocent text must SURVIVE it.
    ///
    /// The three assertions above are all in the false-negative direction (no
    /// near-miss may slip through). Nothing asserted the other side, and the
    /// unbounded separator class was measured corrupting text no forger wrote:
    /// `unknown ruleset id: also_undecided` lost the identifier whole, and
    /// `keys not recognised: also, undecided` collapsed to one token, so two
    /// unrecognised keys read as one.
    ///
    /// Two things answer that. The narrowing bounds the match - it may not begin,
    /// end, or step across an identifier character - and the replacement covers the
    /// WORDS rather than the whole span, so punctuation the surrounding text needs
    /// survives. The near-miss cases in the whitespace test are re-run unchanged and
    /// stay green.
    ///
    /// IT DOES HAVE A FALSE-NEGATIVE COST, and this test is where that cost is
    /// PINNED. It was once written here as "the narrowing with NO false-negative
    /// cost"; that was false and nothing here could catch it, because the near-miss
    /// coverage carried no underscore case at all. Eight forms that `cb0746aa`'s mask
    /// MASKED - measured by running that mask verbatim, all eight - survive this one,
    /// and they are the array below. This array is their single source: the module
    /// comment on `mask_ledger_joiner` describes the trade and deliberately does not
    /// re-list them.
    ///
    /// What that pin does and does not do, since the sentence it replaces got exactly
    /// this wrong: asserting the eight UNCHANGED reddens when the bound moves back ONTO
    /// them (a re-widening), which is the change that would silently restore the
    /// identifier corruption the paragraph above measured. It does NOT catch a further
    /// narrowing - these eight are already untouched, so letting a NINTH form through
    /// does not move them. That direction is covered by the assertions that demand
    /// masking: `ledger_joiner_mask_is_whitespace_insensitive` and the forged loop at
    /// the end of this test, and only for the forms they actually name.
    ///
    /// NOT narrowed, deliberately: prose in which the two words really are adjacent
    /// is still masked. Sparing that would mean demanding the full literal, which is
    /// exactly the near-miss the whitespace test forbids, so over-masking stays the
    /// declared direction of error - it is pinned here, not denied.
    #[test]
    fn ledger_joiner_mask_spares_innocent_text() {
        for intact in [
            "unknown ruleset id: also_undecided",
            "unknown ruleset id: also_undecided_v2",
            "x. also undecided_key: y",
            "recalso undecided",
            "undecided also",
            "no needle here at all",
            "",
        ] {
            assert_eq!(
                mask_ledger_joiner(intact),
                intact,
                "innocent text was corrupted: {intact}"
            );
        }

        // A list keeps its separator, so two unrecognised keys still read as two.
        assert_eq!(
            mask_ledger_joiner("keys not recognised: also, undecided"),
            "keys not recognised: [masked], [masked]"
        );

        // DECLARED over-masking, pinned rather than denied: the words go, the
        // sentence around them stays.
        assert_eq!(
            mask_ledger_joiner("row 4 is also undecided by the local policy"),
            "row 4 is [masked] [masked] by the local policy"
        );

        // THE COST OF THE NARROWING, measured and pinned rather than claimed to be
        // zero. Each is a near-miss of the joiner that `cb0746aa`'s mask MASKED -
        // measured by running that mask verbatim, all eight - and that this one
        // leaves WHOLE. They are accepted because `also_undecided` as a legitimate
        // ruleset id has the same shape and must survive; not because they are
        // harmless.
        //
        // These assert the mask does NOTHING, so they redden when the bound moves
        // back ONTO these forms - not when it moves further off them. Measured on
        // both halves of `is_ident`, which different inputs cover:
        //
        //   * dropping `_` (what `cb0746aa` did) flips the first SIX;
        //   * dropping ASCII DIGITS flips the last two - and that one is caught
        //     HERE and nowhere else in the file, because no innocent-text case has
        //     a digit against the boundary.
        //
        // So the two tail entries are not padding: they are the only cover the digit
        // half of the identifier class has.
        for surviving_near_miss in [
            ". ALSO_UNDECIDED: injected",
            "ALSO_UNDECIDED: injected",
            "x. also_undecided: injected",
            "also_ undecided",
            "also _undecided",
            "also__undecided",
            ". ALSO UNDECIDED2:",
            "1also undecided",
        ] {
            assert_eq!(
                mask_ledger_joiner(surviving_near_miss),
                surviving_near_miss,
                "the identifier bound's declared cost changed and nobody re-decided \
                 it: {surviving_near_miss}"
            );
        }

        // The other direction, re-measured. This asserted absence of the EXACT
        // literal `". ALSO UNDECIDED: "`, which two of its three inputs could not
        // have produced whatever the mask did: substituting a DEAD (identity) mask
        // left them passing, so two thirds of the "re-measurement" measured nothing.
        // Case-insensitive absence of the WORD is what the whitespace test already
        // asserts, and it is what actually fails when the mask stops working.
        //
        // The underscore form that used to sit in this loop has moved UP, to the
        // block that pins it as the narrowing's cost: it is not masked, so it cannot
        // be evidence that masking works.
        for forged in [
            ". ALSO UNDECIDED: injected",
            "x. also  undecided: injected",
            "x. ALSO-UNDECIDED: injected",
        ] {
            let masked = mask_ledger_joiner(forged);
            assert!(
                !masked.to_ascii_lowercase().contains("undecided"),
                "a forged note boundary survived the mask: {masked}"
            );
        }
    }

    /// The same property on the package-only UNDECIDED note.
    #[test]
    fn g_v6_2_undecided_note_names_the_maximum_head() {
        let ascending = [head(6, &ch(6), GEN), head(9, &ch(9), GEN)];
        let descending = [head(9, &ch(9), GEN), head(6, &ch(6), GEN)];
        let mut reasons = Vec::new();
        for enumerated in [&ascending, &descending] {
            let v = apply_completitud_rules(
                SLUG,
                &rows(3),
                None,
                &[],
                enumerated,
                &ok_identity(),
                &fresh(),
                Some(true),
            );
            let Verdict::Inconclusive { reason } = v else {
                panic!("package-only: expected INCONCLUSO")
            };
            assert!(reason.contains("HEAD@9") && !reason.contains("HEAD@6"), "{reason}");
            reasons.push(reason);
        }
        assert_eq!(reasons[0], reasons[1]);
    }

    /// M-1: the remedy must not send an auditor to supply the export they already
    /// supplied and which was DECLINED.
    #[test]
    fn undecided_note_does_not_ask_for_an_export_already_supplied() {
        let chain = rows_diverging_at(5, 2);
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            Some(&chain),
            &[],
            &[head(9, &ch(9), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        let Verdict::Inconclusive { reason } = &v else {
            panic!("got {v:?}")
        };
        assert!(
            reason.contains(
                "The chain export you supplied was DECLINED as evidence (the reason \
                 follows), so it decided nothing: re-fetch it from the producer and re-run"
            ),
            "the remedy sentence must reach the auditor intact: {reason}"
        );
        assert!(
            !reason.contains("  "),
            "no run of double spaces may reach the auditor: {reason}"
        );
        assert!(
            !reason.contains("Supply the producer's published chain export"),
            "must not ask for an export the auditor already supplied: {reason}"
        );
    }

    /// M-4: a PRODUCER-CONTROLLED string reaches the ledger through the gate-1
    /// decline reason (`Debug` escapes control bytes, not printable text), so it can
    /// carry the ledger's own joiner and forge a note boundary - splitting one note
    /// into two, or attributing its text to a rule that never fired. Not reachable
    /// through this crate's CLI, which applies gate 1 itself and exits first; fully
    /// reachable through the public entry points.
    #[test]
    fn test_intent_ledger_joiner_cannot_be_forged_from_an_export() {
        let mut chain = rows(3);
        // A link-severing edit puts this producer-controlled text into `Debug`.
        chain[1].chain_prev_hash = Some("x. ALSO UNDECIDED: injected finding".to_string());
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            Some(&chain),
            &[],
            &[head(3, &ch(3), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        let Verdict::Inconclusive { reason } = &v else {
            panic!("a link-severed export must be DECLINED: {v:?}")
        };
        assert!(
            reason.contains("does not verify offline as a chain"),
            "gate 1 must be what refused it: {reason}"
        );
        assert!(
            !reason.contains("ALSO UNDECIDED: injected finding"),
            "the export forged a ledger note boundary: {reason}"
        );
        assert!(reason.contains("[masked]"), "the joiner must be masked: {reason}");
        // Exactly ONE note here, so the real joiner must not appear at all.
        assert_eq!(
            reason.matches(UNDECIDED_JOINER).count(),
            0,
            "one note must carry no joiner: {reason}"
        );
    }

    /// A truncation FAILED must carry the one check that could falsify it: both
    /// artefacts being older than the enumeration produces the same observation, and
    /// nothing in an export dates it against the log.
    #[test]
    fn g_v6_2_truncation_finding_names_its_own_alternative_cause() {
        let chain = rows(2);
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            Some(&chain),
            &[],
            &[head(5, &ch(5), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        let Verdict::Failed { reason } = &v else {
            panic!("got {v:?}")
        };
        assert!(
            reason.contains("re-fetch BOTH artifacts and re-run"),
            "the finding must name the check that falsifies it: {reason}"
        );
    }

    /// The C-1 shape at the exact ordinal the live run accused: an export one row
    /// short of the package, and the enumerated head sitting on that very row.
    #[test]
    fn g_v6_2_export_one_row_stale_does_not_accuse_the_packages_own_tail() {
        let chain = rows(11);
        let v = apply_completitud_rules(
            SLUG,
            &rows(12),
            Some(&chain),
            &[],
            &[head(12, &ch(12), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        assert_eq!(v, Verdict::Verified, "got {v:?}");
    }

    /// INTENT: the export gate compares the WHOLE row, not only what the chain
    /// commits to. `chain_hash = SHA256(chain_prev_hash || verdict_hash)`, so with
    /// both artefacts link-verified it binds `ordinal`, `chain_prev_hash` and
    /// `verdict_hash` - and nothing else. `verdict_id`, `appended_at`, `ruleset_id`
    /// and `verdict_outcome` sit outside it.
    /// CONTEXT: measured - an export whose row 2 read `VIOLATED` where the package
    /// read `SATISFIED`, with a different `ruleset_id`, `verdict_id` and an
    /// `appended_at` of 1999, was ADMITTED in silence while the gate compared two
    /// fields, and the doc-comment claimed "byte for byte".
    /// EXPIRES IF: `PublicChainRow` gains a field the two emitters legitimately
    /// render differently (then the gate must name the fields it skips and why).
    #[test]
    fn test_intent_export_gate_compares_the_whole_row_not_only_the_hash() {
        let mut chain = rows(3);
        chain[1].verdict_outcome = "VIOLATED".to_string();
        chain[1].ruleset_id = "other".to_string();
        chain[1].appended_at = Utc.with_ymd_and_hms(1999, 1, 1, 0, 0, 0).unwrap();
        // The links still recompute: nothing above is inside `chain_hash`.
        assert!(
            crate::chain_export::verify_public_chain(&chain).is_ok(),
            "the fixture must pass gate 1, or it tests the wrong gate"
        );
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            Some(&chain),
            &[],
            &[head(3, &ch(3), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        let Verdict::Inconclusive { reason } = &v else {
            panic!("a contradicting export must not be admitted: {v:?}")
        };
        assert!(
            reason.contains("contradicts the anchor package at row 2")
                && reason.contains("DECLINED"),
            "must name the row and the refusal: {reason}"
        );
    }

    /// INTENT: a DECLINED export must never SUPPRESS the enumeration finding.
    /// Supplying a contradictory export has to stay no worse for the auditor than
    /// supplying none - the floor the DECLARED LIMIT rests on. The producer controls
    /// the published export, so a decline that swallowed the note would hand the
    /// producer control of whether the auditor ever sees it.
    /// CONTEXT: measured - same package, kit and enumeration, only the export
    /// differing: without it the verdict named `HEAD@42`; with a contradictory export
    /// that line was GONE, because the decline note was installed before any rule ran
    /// and `get_or_insert` keeps the first.
    /// EXPIRES IF: undecided rules stop accumulating.
    #[test]
    fn test_intent_declined_export_does_not_suppress_the_enumeration_note() {
        let chain = rows_diverging_at(5, 2);
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            Some(&chain),
            &[],
            &[head(9, &ch(9), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        let Verdict::Inconclusive { reason } = &v else {
            panic!("got {v:?}")
        };
        assert!(
            reason.contains("HEAD@9") && reason.contains("G-v6-2 UNDECIDED"),
            "the enumeration finding must survive the decline: {reason}"
        );
        assert!(
            reason.contains("DECLINED") && reason.contains("ALSO UNDECIDED"),
            "the decline must be reported ALONGSIDE it, not instead of it: {reason}"
        );
    }

    /// The reference the rules used is REPORTED, and a DECLINED export contributes
    /// nothing to it - the number a caller would get by recomputing
    /// `max(package, supplied)` is a different, wrong number.
    #[test]
    fn test_intent_reported_reference_excludes_a_declined_export() {
        let chain = rows_diverging_at(9, 2);
        let (_, reference) = apply_completitud_rules_reported(
            SLUG,
            &rows(3),
            Some(&chain),
            &[],
            &[head(3, &ch(3), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        assert_eq!(reference.package_rows, 3);
        assert_eq!(reference.supplied_export_rows, Some(9));
        assert!(reference.declined.is_some(), "the export contradicts the package");
        assert!(!reference.export_admitted());
        assert_eq!(
            reference.reference_rows, 3,
            "a declined export must not raise the reference; recomputing max(3, 9) \
             would report 9"
        );
    }

    /// ...and an ADMITTED export does raise it.
    #[test]
    fn reported_reference_rises_with_an_admitted_export() {
        let chain = rows(9);
        let (_, reference) = apply_completitud_rules_reported(
            SLUG,
            &rows(3),
            Some(&chain),
            &[],
            &[head(3, &ch(3), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        assert!(reference.export_admitted());
        assert_eq!(reference.reference_rows, 9);
    }

    /// INTENT: an export is EVIDENCE only if it verifies as a chain. A published
    /// crate's public entry point must not take an unverified producer artefact on
    /// trust and let it raise the reference.
    /// CONTEXT: measured - a 6-row export with fabricated `chain_hash` on rows 2..6
    /// raised the reference from 1 to 6 in complete silence when the obligation was
    /// only stated in prose for the caller.
    /// EXPIRES IF: the type system carries the verification (a `VerifiedChain`
    /// newtype that cannot be constructed without the gate).
    #[test]
    fn test_intent_unverified_export_is_declined_not_trusted() {
        let mut chain = rows(6);
        for row in chain.iter_mut().skip(1) {
            row.chain_hash = ch(900 + row.ordinal); // links no longer recompute
        }
        let v = apply_completitud_rules(
            SLUG,
            &rows(1),
            Some(&chain),
            &[],
            &[head(1, &ch(1), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        let Verdict::Inconclusive { reason } = &v else {
            panic!("an export that does not verify must not be evidence: {v:?}")
        };
        assert!(
            reason.contains("does not verify offline as a chain") && reason.contains("DECLINED"),
            "must name what was refused and why: {reason}"
        );
    }

    /// A pending `G-v6-2 UNDECIDED` survives a LATER rule that also cannot conclude:
    /// the auditor must not lose the line naming the input that decides the run.
    #[test]
    fn undecided_note_survives_a_later_inconclusive_rule() {
        // head@5 beyond the package's N=3 (undecided), and the liveness of a slug
        // with an anchored head was never probed (a later INCONCLUSO).
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            None,
            &[],
            &[head(5, &ch(5), GEN)],
            &ok_identity(),
            &fresh(),
            /*slug_liveness*/ None,
        );
        let Verdict::Inconclusive { reason } = &v else {
            panic!("got {v:?}")
        };
        assert!(
            reason.contains("liveness was not probed") && reason.contains("G-v6-2 UNDECIDED"),
            "both undecided rules must reach the auditor: {reason}"
        );
    }

    /// A head beyond BOTH the package and the export: the plain truncation shape.
    #[test]
    fn g_v6_2_head_beyond_every_published_artefact_fails() {
        let chain = rows(4);
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            Some(&chain),
            &[],
            &[head(7, &ch(7), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        assert!(matches!(v, Verdict::Failed { .. }), "got {v:?}");
    }

    /// INTENT: the export can never BUY silence. Raising the reference row count
    /// opens exactly one evasion - delete rows, then republish an export of the
    /// ORIGINAL length with different content - and the chain_hash arm of R1 closes
    /// it: every enumerated head is checked against the export's row k, not just
    /// against its length.
    /// CONTEXT: introduced with `--chain`; without this arm the flag would be a
    /// producer-controlled mute button on G-v6-2.
    /// EXPIRES IF: the export stops carrying per-row `chain_hash`.
    #[test]
    fn test_intent_relengthened_export_cannot_absolve_a_rewritten_row() {
        // A VALID 5-row chain that agrees with the package's 3 rows and carries a
        // DIFFERENT row 5 - what a producer republishing a rewritten tail emits.
        let chain = rows_diverging_at(5, 4);
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            Some(&chain),
            &[],
            &[head(5, &ch(5), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        let Verdict::Failed { reason } = &v else {
            panic!("a rewritten export row must stay a FAILED: {v:?}")
        };
        assert!(reason.contains("G-v6-3"), "wrong discriminant: {reason}");
    }

    /// INTENT: an export that contradicts the package over the rows BOTH reach is
    /// DECLINED as the reference, never accused on. The auditor supplies the file;
    /// a mismatch is as likely their wrong download as a producer contradiction,
    /// and the verifier cannot tell which - so it says so and concludes nothing.
    /// CONTEXT: `--chain` is the first input the AUDITOR chooses that can reach an
    /// accusation; a false FAILED from a mis-typed path would be the same class of
    /// error this whole change exists to remove.
    /// EXPIRES IF: the export becomes cryptographically bound to the package, so a
    /// mismatch can only be the producer's.
    #[test]
    fn test_intent_export_contradicting_the_package_is_declined_not_accused() {
        // A VALID 5-row chain that disagrees with the package from row 2 on.
        let chain = rows_diverging_at(5, 2);
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            Some(&chain),
            &[],
            &[head(3, &ch(3), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        let Verdict::Inconclusive { reason } = &v else {
            panic!("a contradictory export must not produce a verdict: {v:?}")
        };
        assert!(
            reason.contains("DECLINED") && reason.contains("row 2"),
            "must name what was declined and where it broke: {reason}"
        );
    }

    /// INTENT: deferring the undecided note to the exits must not SUPPRESS a real
    /// finding. `FAILED > INCONCLUSO > Verified` - a package that both lags the log
    /// and violates a rule is reported FAILED.
    /// CONTEXT: R1 no longer returns where it notices the lag; if the note short
    /// -circuited the engine, every later rule (coverage, forged RETIRED, identity)
    /// would go unevaluated the moment a producer lagged by one head - which is
    /// most of the time.
    /// EXPIRES IF: the verdict lattice changes.
    #[test]
    fn test_intent_a_failed_rule_outranks_an_undecided_lag() {
        // head@5 is beyond N=3 (undecided) AND the monitor omits the package's own
        // published head@3 (R3 coverage, a real finding).
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            None,
            &[Lane::Head {
                slug: SLUG.to_string(),
                ordinal: 3,
                chain_hash: ch(3),
            }],
            &[head(5, &ch(5), GEN)],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        assert!(
            matches!(v, Verdict::Failed { .. }),
            "an undecided lag must not mute a real finding: {v:?}"
        );
    }

    /// The same false-accusation class in R6: a RETIRED sitting at a head the
    /// package cannot place is UNDECIDED, not "forged RETIRED".
    #[test]
    fn g_v6_11_retired_beyond_the_package_is_undecided_not_forged() {
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            None,
            &[],
            &[head(5, &ch(5), GEN), retired(5, &ch(5))],
            &ok_identity(),
            &fresh(),
            Some(true),
        );
        assert!(
            matches!(v, Verdict::Inconclusive { .. }),
            "a RETIRED past the package's rows is unplaceable, not forged: {v:?}"
        );
    }

    #[test]
    fn g_v6_2_coverage_published_head_missing_from_fresh_monitor_fails() {
        // Package published HEAD@3 but the FRESH monitor omits it.
        let v = apply_completitud_rules(
            SLUG,
            &rows(3),
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            SLUG, &rows(3), None, &[], &[], &ok_identity(), &fresh(), Some(true),
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
            SLUG, &rows(3), None, &[], &[head(3, &ch(3), GEN)], &ok_identity(), &fresh(), Some(false),
        );
        let attacker_tries_two_enroll = apply_completitud_rules(
            SLUG, &rows(3), None, &[],
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
            None,
            &[Lane::Head { slug: SLUG.to_string(), ordinal: 3, chain_hash: ch(3) }],
            &[],
            &ok_identity(),
            &stale(),
            Some(true),
        );
        assert!(matches!(v, Verdict::Inconclusive { .. }));
        // …but a SEEN contradiction (forged head) still FAILS even when stale.
        let seen = apply_completitud_rules(
            SLUG, &rows(3), None, &[], &[head(3, &ch(999), GEN)], &ok_identity(), &stale(), Some(true),
        );
        assert!(matches!(seen, Verdict::Failed { .. }));
    }

    #[test]
    fn g_v6_5c_legacy_no_enroll_404_fails() {
        // The OTHER half of G-v6-5c: a legacy slug with no ENROLL (⇒ attested
        // strict) that returns 404 must FAIL — "el 404 no escapa" (6S.5c).
        let v = apply_completitud_rules(
            SLUG, &rows(3), None, &[], &[], &ok_identity(), &fresh(), Some(false),
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
            None,
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
            SLUG, &rows(3), None, &[], &[], &ok_identity(), &fresh(), None,
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
        // Only `chain_hash` is retargeted: the rules read rows by that field, and no
        // chain EXPORT is supplied here, so nothing applies `verify_public_chain` to
        // these rows (that gate exists for the untrusted `published_chain` input).
        let mut r = rows(42);
        r[41].chain_hash = HEAD_CHAIN_HASH.to_string();
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
            None,
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
