// SPDX-License-Identifier: Apache-2.0
//! Scope statements shared, verbatim, by the two auditor-facing surfaces that
//! print the result of an OFFLINE `verify-chain`: the public
//! `seetrex-verifier` binary and the `compliance-cli`.
//!
//! A prior release carried a LIVE 18-byte divergence between the two: the
//! CLI's "NOT covered by this check" block omitted the `` (`verify-package`) ``
//! pointer the public binary carried, while a comment on the CLI side asserted
//! "the two surfaces must never disagree". Promoting the text to shared
//! constants here turns that from a claim a reader must trust into a fact the
//! compiler enforces — the divergence stops being *detectable* and becomes
//! *impossible* (a parity test in the compliance crate guards that neither
//! binary reintroduces a rival literal).
//!
//! What can and cannot be shared:
//! - [`SCOPE_NOT_COVERED`] is printed VERBATIM by both binaries. Byte equality
//!   is achievable because the block names only what the check omits, which is
//!   the same on both surfaces. The canonical wording KEEPS the
//!   `` (`verify-package`) `` pointer: both binaries expose that subcommand, so
//!   it is accurate on both — the private CLI merely dropped it.
//! - [`SCOPE_LINK_CLAIM`] is the shared scope-of-comparison claim that
//!   follows the "compare these two values" line on both surfaces. Byte
//!   equality of the WHOLE line is impossible by construction — the leading
//!   URL sentence differs and the public binary must not name the internal
//!   `seetrex.com/trust/` alias (`intent_trust_public_pages`) — so each
//!   binary prints its own URL sentence and then interpolates this shared
//!   claim verbatim.

/// F3 — the full "NOT covered by this check" scope block, printed verbatim by
/// both the public `seetrex-verifier` and the private `compliance-cli` after a
/// successful offline chain verification.
pub const SCOPE_NOT_COVERED: &str = "NOT covered by this check: the \
    human-readable columns of each row (verdict_outcome, ruleset_id, \
    appended_at, verdict_id). They are not inputs to the chain link, so \
    altering them keeps every link — and the hash above — valid. Two of \
    them — verdict_outcome and ruleset_id — are committed inside that row's \
    verdict_hash, recomputable only from that verdict's package \
    (`verify-package`). The other two — appended_at and verdict_id — are \
    committed NOWHERE: they are inputs neither to the chain link nor to \
    verdict_hash, and no artifact we publish binds them. Treat all four as \
    unverified metadata; the last two you cannot verify at all.";

/// F2 — the shared scope-of-comparison claim common to both surfaces' "compare
/// these two values" line. Each binary prints its own leading URL sentence
/// (the private CLI's naming the permanent `seetrex.com/trust/` alias) and then
/// interpolates this claim verbatim, so the shared invariant is this
/// sub-phrase, not the full line.
pub const SCOPE_LINK_CLAIM: &str = "A match proves this file agrees with what \
    the vendor publishes RIGHT NOW — nothing more. It does NOT prove rows were \
    not removed: a vendor who republishes a truncated chain also republishes \
    its shorter head, so both sides of this comparison move together. What \
    catches removal is material you kept earlier — a copy of this export, or a \
    verdict package whose verdict_hash (recompute it with `verify-package`) \
    still appears in a row of the published chain. Each export you fetch \
    should extend the prefix you already hold, not rewrite it; keeping and \
    comparing that material is your step. This tool has no command for either \
    comparison; you must keep the material and make it yourself.";

/// The scope statement printed by `seetrex-verifier verify-anchor` on EVERY
/// terminal outcome — CONSISTENCIA confirmed OR failed, monitor supplied or
/// not. An OFFLINE anchor verification confirms CONSISTENCIA (non-contradiction
/// of the PRESENTED material); the second verdict, COMPLETITUD, is INCONCLUSIVE
/// UNLESS an independent monitor enumeration is supplied (`--monitor`), in
/// which case it carries a REAL verdict shown on the COMPLETITUD line above.
/// Stated at the same volume as the result so a confirmed CONSISTENCIA WITHOUT
/// a monitor can never be misread as completeness — the exact overclaim the v6
/// redesign removed. Deliberately free of the reserved token `VERIFIED`:
/// `verify-anchor` is not (yet) a §9.6-blessed strong surface, so no terminal
/// outcome here is a blanket strong pass. The wording is honest on BOTH paths:
/// it does not assert a fixed "INCONCLUSIVE here", it states the CONDITION
/// (monitor present or absent) that decides COMPLETITUD.
pub const SCOPE_ANCHOR: &str = "CONSISTENCIA (offline) confirms only that the \
    PRESENTED material does not contradict itself: every anchored leaf's \
    inclusion under the cosigned checkpoint verifies, the producer identity \
    chain derives from the PINNED genesis without a fork, and the chain JOIN \
    holds. It does NOT prove COMPLETITUD: a vendor who OMITS a contradictory \
    log leaf republishes a shorter, self-consistent history that still passes \
    CONSISTENCIA — catching omission needs an INDEPENDENT monitor enumeration \
    of the log. That second verdict, COMPLETITUD, is INCONCLUSIVE unless you \
    supply such an enumeration (--monitor <bundle>); with one it becomes a \
    REAL verdict (CONFIRMED / INCONCLUSIVE / FAILED) shown on the COMPLETITUD \
    line above, and WITHOUT one a confirmed CONSISTENCIA is NOT a statement \
    that the vendor anchored everything. A confirmed verdict over ZERO anchored \
    leaves is VACUOUS — it asserts nothing about anchoring; read the 'anchored \
    leaves checked' count. Surfaced anomalous rotations (e.g. unauthorized) do \
    NOT lower CONSISTENCIA — their fatal mapping is enumeration-dependent \
    (COMPLETITUD); investigate them separately. The witness policy and \
    genesis key used here are PINNED inputs from your auditor kit, never from \
    the package.";

#[cfg(test)]
mod tests {
    use super::*;

    /// The anchor scope statement must (a) carry no reserved `VERIFIED` token
    /// (the shell tooling reads it as a strong pass), and (b) actually state
    /// the two-verdict honesty — that COMPLETITUD is INCONCLUSIVE and that a
    /// confirmed CONSISTENCIA is not completeness.
    #[test]
    fn scope_anchor_is_honest_and_carries_no_reserved_token() {
        assert!(
            !SCOPE_ANCHOR.to_ascii_uppercase().contains("VERIFIED"),
            "SCOPE_ANCHOR must not contain the reserved strong token"
        );
        assert!(SCOPE_ANCHOR.contains("INCONCLUSIVE"));
        assert!(SCOPE_ANCHOR.contains("COMPLETITUD"));
        assert!(SCOPE_ANCHOR.contains("does NOT prove"));
        // The vacuous-pass and surfaced-anomaly caveats must be present (both
        // blind reviewers flagged the silent-vacuous hazard).
        assert!(SCOPE_ANCHOR.contains("VACUOUS"));
        assert!(SCOPE_ANCHOR.contains("anchored leaves checked"));
        assert!(SCOPE_ANCHOR.contains("anomalous rotations"));
    }
}
