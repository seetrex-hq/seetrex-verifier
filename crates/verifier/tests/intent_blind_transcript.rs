// SPDX-License-Identifier: Apache-2.0
//! The blindness claim, made checkable.
//!
//! `reference/seetrex_verifier.py` is published as an implementation written
//! from `docs/SPEC_VERDICT_PACKAGE_V1.md` alone. The only part of that claim
//! an auditor can verify mechanically is WHICH BYTES the implementer received,
//! and `reference/BLIND_TRANSCRIPT.md` is where those bytes are named. This
//! file recomputes the hash so the transcript cannot drift behind the
//! document it names.
//!
//! This test TRAVELS: it ships in the public repository and inside the
//! `.crate`, and it has to be honest in all three trees `tests/common/mod.rs`
//! describes. Its two document-dependent obligations therefore ask whether
//! their input is present -- with POSITIVE evidence, never with an
//! environment variable -- and the half that a published tree cannot carry
//! (the producer's git history) has an unconditional counterpart in
//! `crates/witness/tests/intent_blind_transcript_history.rs`, a crate the
//! export does not ship.

mod common;

use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use common::Tree;

/// The specification under test. Same escape as `corpus_equivalence.rs`, and
/// on the same allowlist of `intent_public_crate_is_self_contained.rs`.
///
/// It resolves in the private workspace and in a clone of the public
/// repository (the export ships `docs/` on its allowlist); it does NOT
/// resolve inside an unpacked `.crate`, because `cargo package` cannot carry
/// a file from outside the package directory.
const SPEC_REL: &str = "../../docs/SPEC_VERDICT_PACKAGE_V1.md";

const TRANSCRIPT_REL: &str = "reference/BLIND_TRANSCRIPT.md";

/// The reason the GIT leg announces when it cannot run, hoisted into a
/// constant because it is PUBLISHED.
///
/// `docs/AUDITOR_KIT.md` §2.2 reproduces the whole line an auditor will see
/// in a clone of the public repository — `skipped [SourceWithoutHistory]: `
/// followed by this text — as the one skip that tree prints. That makes the
/// document and this string a pair that has to stay identical, and
/// `crates/witness/tests/kit_doc.rs` keeps them so by reading this literal out
/// of this file and comparing it with the document, exactly as it already
/// reads the anchor commit out of `tests/common/mod.rs`. Written twice, they
/// drift and the auditor greps for a line nobody prints any more.
const GIT_LEG_SKIP_REASON: &str = "transcript rows are not resolved against git blobs: anchor \
                                   commit is unreachable here, so this tree does not carry the \
                                   producer's history (the public repository is an export \
                                   snapshot). The unconditional resolution lives in \
                                   crates/witness/tests/intent_blind_transcript_history.rs";

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The `(date, sha256, commit)` rows of the transcript's hash table, in file
/// order.
///
/// A row is a table line whose first cell is a date and whose second cell is
/// a backticked 64-character lowercase hex string. The third cell, when
/// present, is the COMMIT whose `docs/SPEC_VERDICT_PACKAGE_V1.md` hashes to
/// it (or the literal `HEAD` for the row that names this tree). Anything else
/// in the document — the prose, the verbatim task text, the fenced listing —
/// is ignored, so the table can gain columns without breaking the parse.
fn hash_rows(text: &str) -> Vec<(String, String, String)> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() < 2 {
            continue;
        }
        let date = cells[0];
        if date.len() != 10 || !date.starts_with("20") {
            continue;
        }
        let hash = cells[1].trim_matches('`');
        if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()) {
            let commit = cells.get(2).map(|c| c.trim_matches('`')).unwrap_or("");
            rows.push((date.to_string(), hash.to_string(), commit.to_string()));
        }
    }
    rows
}

/// INTENCION: «written blind» is a claim an auditor must be able to check,
///     and the checkable part is which bytes the implementer received. This
///     test travels with the crate, so it states, per tree, exactly how much
///     of that claim the tree in hand can answer:
///       * PRIVATE workspace — everything: the SHAPE of the transcript (at
///         least two rows, `HEAD` only on the last, no empty commit cell,
///         first row ≠ last row, the task text verbatim), the sha256 of the
///         LAST row against the working-tree specification, AND every row
///         resolved against the git blob its commit names.
///       * clone of the PUBLIC repository — the shape and the last-row hash
///         (the export ships `docs/`), but not the row-by-row resolution:
///         the export is a snapshot and the producer's commits are not in it.
///         That leg SKIPS, out loud, on the authority of the anchor commit of
///         `tests/common/mod.rs` — never on the authority of a row.
///       * unpacked `.crate` — the shape only. Neither the specification nor
///         a repository travels in the tarball; the test PROVES it is
///         packaged (`Cargo.toml.orig`) before it excuses the hash, so a
///         source tree with the document missing stays red.
///     The other half of the claim — the resolution, unconditional and
///     fail-closed on a shallow checkout — lives in
///     `crates/witness/tests/intent_blind_transcript_history.rs`, in a crate
///     the export does not ship, so the skip above is a door with a lock on
///     the other side.
/// CONTEXTO: the kit publishes the claim (§7); an unpinned claim is prose.
///     0.3.6 shipped this test RED in both public routes (`AUDITOR_KIT.md`
///     §2.2): one unconditional `git show` written in the tree that has
///     everything, and a specification path that leaves the tarball.
/// EXPIRA SI: the Python stops being presented as an independent
///     implementation, or the crate stops being published as source an
///     auditor tests in place.
#[test]
fn test_intent_blind_transcript_names_the_spec_it_saw() {
    let tree = common::classify();

    let transcript_path = crate_root().join(TRANSCRIPT_REL);
    let transcript = fs::read_to_string(&transcript_path).unwrap_or_else(|e| {
        panic!(
            "the blindness claim has no transcript at {} ({e}). The Python \
             reference implementation is published as written from the \
             specification alone; without this file that claim is prose an \
             auditor cannot check.",
            transcript_path.display()
        )
    });

    // ─── Unconditional: the SHAPE of the record. Every tree carries the
    // transcript, so every tree owes these. ───

    let rows = hash_rows(&transcript);
    assert!(
        rows.len() >= 2,
        "{TRANSCRIPT_REL} carries {} dated hash row(s). It must carry at \
         least two: the copy handed to the implementer, and the document as \
         it stands now — the difference between them IS the record of what \
         changed after the implementation was frozen.",
        rows.len()
    );

    // R3-B I-4 / M-2: an EMPTY commit cell used to be skipped exactly like
    // `HEAD`, so a forged row with its commit blanked out was pinned by
    // nothing at all. Only the LAST row may name no commit, and only by
    // spelling it `HEAD`: it is the row about this working tree, which
    // cannot carry the hash of the commit that contains it, and it IS pinned
    // -- against the working-tree bytes, by the last-row assertion below.
    //
    // These two live OUTSIDE the git loop deliberately. They are the part of
    // the row-by-row discipline that needs no history, so a published tree
    // still enforces it; folding them back into the loop would let a tree
    // without history accept a table of empty cells.
    let last_index = rows.len() - 1;
    for (index, (date, _hash, commit)) in rows.iter().enumerate() {
        assert!(
            !commit.is_empty(),
            "{TRANSCRIPT_REL} row {date} names NO commit. Every row resolves \
             against a git blob except the last, which says `HEAD`; an empty \
             cell is a row that pins nothing and is forgeable by construction."
        );
        if commit == "HEAD" {
            assert_eq!(
                index,
                last_index,
                "{TRANSCRIPT_REL} row {date} says `HEAD`, and it is row {} of \
                 {}. Only the LAST row may say `HEAD` -- an earlier one would \
                 exempt itself from the git resolution while claiming to \
                 record a document nobody can recover.",
                index + 1,
                rows.len()
            );
        }
    }

    // Non-vacuity: the first row must NOT be the current document, or the
    // test would be satisfied by a transcript that simply restated today's
    // hash twice and recorded no history at all. If a future spec edit ever
    // makes this true again by coincidence, that is a real signal — the
    // document came back to the exact bytes the implementer saw.
    let (first_date, first_hash, _) = rows.first().expect("checked non-empty above");
    let (last_date, last_hash, _) = rows.last().expect("checked non-empty above");
    assert_ne!(
        first_hash, last_hash,
        "the first ({first_date}) and last ({last_date}) hash rows of \
         {TRANSCRIPT_REL} are identical, so the table records no history. \
         Either a row was rewritten instead of appended, or the two rows \
         were copied from each other."
    );

    // The task text is the other half of the provenance: without it the
    // hash names a document nobody can tell what was asked about.
    assert!(
        transcript.contains("Your ONLY input is the file `SPEC_VERDICT_PACKAGE_V1.md`"),
        "{TRANSCRIPT_REL} no longer reproduces the task text verbatim. The \
         hash says WHICH bytes the implementer read; the task text says what \
         was asked of them. One without the other is not provenance."
    );

    // ─── The LAST row against the specification on disk, wherever the
    // specification is on disk. ───

    let spec_path = crate_root().join(SPEC_REL);
    if spec_path.is_file() {
        let spec_bytes = fs::read(&spec_path).unwrap_or_else(|e| {
            panic!(
                "the specification the transcript names is not readable at {}: {e}",
                spec_path.display()
            )
        });
        let spec_hash = sha256_hex(&spec_bytes);
        assert_eq!(
            last_hash,
            &spec_hash,
            "the LAST hash row of {TRANSCRIPT_REL} ({last_date}, {last_hash}) is \
             not the sha256 of {} ({spec_hash}).\n\n\
             The specification was edited without the transcript following it. \
             Append a NEW dated row carrying the new hash and saying what the \
             edit was — never rewrite an existing row: the earlier rows are the \
             evidence of which bytes the implementer actually read, and that \
             cannot be revised after the fact.",
            spec_path.display()
        );
    } else {
        // A missing specification is excused ONLY by proof of packaging. A
        // source checkout whose `docs/` is gone is a BROKEN tree, not a
        // published one, and it must stay red: this is the assertion that
        // keeps the skip from being the cheap way past a real breakage.
        assert_eq!(
            tree,
            Tree::Packaged,
            "the specification is not at {} and this is not an unpacked \
             `.crate` (`Cargo.toml.orig` is not beside the manifest). In a \
             source checkout that document is the thing the last transcript \
             row is a hash OF; without it the row is unpinned prose, so this \
             is a broken tree rather than a published one.",
            spec_path.display()
        );
        common::skip(
            tree,
            "the last transcript row is not hashed against \
             docs/SPEC_VERDICT_PACKAGE_V1.md: `cargo package` cannot carry a \
             file from outside the package directory, so the document does \
             not travel inside the .crate",
        );
    }

    // ─── Every row against the git blob its commit names — where those blobs
    // exist. ───
    //
    // EVERY row, not just the last (R2-B I-4). Until this loop existed, rows
    // 1..n-1 were pinned by nothing: a hash could be edited, or a row dropped,
    // and the test stayed green — which is exactly the part of the blindness
    // claim an auditor cannot re-derive without them. Each row names the
    // COMMIT whose specification hashes to it; `git show <commit>:<path>`
    // produces those bytes and the sha256 is recomputed here.
    //
    // Whether this leg runs is decided by `common::HISTORY_ANCHOR` — a commit
    // named in CODE — and never by whether an individual row happens to
    // resolve. That distinction is the whole design: degrading per row would
    // mean a forged row is unresolvable and therefore EXCUSED, which is the
    // failure this loop was written to close.
    if !common::anchor_resolves() {
        common::skip(tree, GIT_LEG_SKIP_REASON);
        return;
    }

    let mut resolved = 0usize;
    for (date, hash, commit) in rows.iter() {
        if commit == "HEAD" {
            continue;
        }
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(crate_root())
            .arg("show")
            .arg(format!("{commit}:docs/SPEC_VERDICT_PACKAGE_V1.md"))
            .output()
            .unwrap_or_else(|e| panic!("`git show` could not be spawned: {e}"));
        assert!(
            out.status.success(),
            "{TRANSCRIPT_REL} row {date} names commit `{commit}`, and \
             `git show {commit}:docs/SPEC_VERDICT_PACKAGE_V1.md` failed: {}. \
             A row whose commit does not resolve pins nothing. This tree DOES \
             carry the producer's history — the anchor commit `{}` resolved — \
             so an unresolvable row is a forged or mistyped row, never a \
             reason to skip.",
            String::from_utf8_lossy(&out.stderr).trim(),
            common::HISTORY_ANCHOR
        );
        let measured = sha256_hex(&out.stdout);
        assert_eq!(
            &measured, hash,
            "{TRANSCRIPT_REL} row {date} publishes sha256 {hash} for the \
             specification at commit `{commit}`, and that commit's \
             `docs/SPEC_VERDICT_PACKAGE_V1.md` hashes to {measured}. Either \
             the row was rewritten after the fact or it names the wrong \
             commit; both make the blindness record unusable."
        );
        resolved += 1;
    }
    assert!(
        resolved >= 2,
        "only {resolved} transcript row(s) resolved against a git blob. The \
         history is what makes the claim checkable, so a table whose rows \
         name no commit is prose again."
    );
}
