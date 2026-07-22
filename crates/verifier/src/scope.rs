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
