// SPDX-License-Identifier: Apache-2.0
//! The blindness claim, made checkable.
//!
//! `reference/seetrex_verifier.py` is published as an implementation written
//! from `docs/SPEC_VERDICT_PACKAGE_V1.md` alone. The only part of that claim
//! an auditor can verify mechanically is WHICH BYTES the implementer received,
//! and `reference/BLIND_TRANSCRIPT.md` is where those bytes are named. This
//! file recomputes the hash so the transcript cannot drift behind the
//! document it names.

use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

/// The specification under test. Same escape as `corpus_equivalence.rs`, and
/// on the same allowlist of `intent_public_crate_is_self_contained.rs`.
const SPEC_REL: &str = "../../docs/SPEC_VERDICT_PACKAGE_V1.md";

const TRANSCRIPT_REL: &str = "reference/BLIND_TRANSCRIPT.md";

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
///     and the checkable part is which bytes the implementer received.
/// CONTEXTO: the kit will publish the claim (§7); an unpinned claim is prose.
/// EXPIRA SI: the Python stops being presented as an independent
///     implementation.
#[test]
fn test_intent_blind_transcript_names_the_spec_it_saw() {
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

    let spec_path = crate_root().join(SPEC_REL);
    let spec_bytes = fs::read(&spec_path).unwrap_or_else(|e| {
        panic!(
            "the specification the transcript names is not readable at {}: {e}",
            spec_path.display()
        )
    });
    let spec_hash = sha256_hex(&spec_bytes);

    let rows = hash_rows(&transcript);
    assert!(
        rows.len() >= 2,
        "{TRANSCRIPT_REL} carries {} dated hash row(s). It must carry at \
         least two: the copy handed to the implementer, and the document as \
         it stands now — the difference between them IS the record of what \
         changed after the implementation was frozen.",
        rows.len()
    );

    let (last_date, last_hash, _) = rows.last().expect("checked non-empty above");
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

    // EVERY row, not just the last (R2-B I-4). Until this loop existed, rows
    // 1..n-1 were pinned by nothing: a hash could be edited, or a row dropped,
    // and the test stayed green — which is exactly the part of the blindness
    // claim an auditor cannot re-derive without them. Each row names the
    // COMMIT whose specification hashes to it; `git show <commit>:<path>`
    // produces those bytes and the sha256 is recomputed here.
    // R3-B I-4 / M-2: an EMPTY commit cell used to be skipped exactly like
    // `HEAD`, so a forged row with its commit blanked out was pinned by
    // nothing at all. Only the LAST row may name no commit, and only by
    // spelling it `HEAD`: it is the row about this working tree, which
    // cannot carry the hash of the commit that contains it, and it IS pinned
    // -- against the working-tree bytes, by the assertion above.
    let last_index = rows.len() - 1;
    let mut resolved = 0usize;
    for (index, (date, hash, commit)) in rows.iter().enumerate() {
        assert!(
            !commit.is_empty(),
            "{TRANSCRIPT_REL} row {date} names NO commit. Every row resolves              against a git blob except the last, which says `HEAD`; an empty              cell is a row that pins nothing and is forgeable by construction."
        );
        if commit == "HEAD" {
            assert_eq!(
                index, last_index,
                "{TRANSCRIPT_REL} row {date} says `HEAD`, and it is row {} of                  {}. Only the LAST row may say `HEAD` -- an earlier one would                  exempt itself from the git resolution while claiming to                  record a document nobody can recover.",
                index + 1,
                rows.len()
            );
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
             A row whose commit does not resolve pins nothing.",
            String::from_utf8_lossy(&out.stderr).trim()
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

    // Non-vacuity: the first row must NOT be the current document, or the
    // test would be satisfied by a transcript that simply restated today's
    // hash twice and recorded no history at all. If a future spec edit ever
    // makes this true again by coincidence, that is a real signal — the
    // document came back to the exact bytes the implementer saw.
    let (first_date, first_hash, _) = rows.first().expect("checked non-empty above");
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
}
