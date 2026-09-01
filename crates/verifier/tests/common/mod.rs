// SPDX-License-Identifier: Apache-2.0
//! Which of the three trees is this test running in, decided ONCE.
//!
//! This crate is published three ways and the same test binary has to be
//! honest in all of them:
//!
//! * the PRIVATE workspace -- the producer's checkout: the specifications are
//!   two levels up in `docs/`, and the git history that the blindness
//!   transcript names is right there;
//! * a clone of the PUBLIC repository -- `scripts/export_public.sh` ships the
//!   specification documents (they are on its allowlist), but it exports a
//!   SNAPSHOT: none of the producer's commits exist in that repository, so
//!   `git show <commit>:docs/…` has nothing to resolve;
//! * an unpacked `.crate` -- `cargo package` cannot carry a file from outside
//!   the package directory, so neither specification document travels, and
//!   there is no repository at all.
//!
//! 0.3.6 shipped with `intent_blind_transcript` red in the first two of those
//! (`docs/AUDITOR_KIT.md` §2.2), because one unconditional assertion was
//! written for the tree that has everything. The answer is not to weaken the
//! assertion: it is to let each obligation ask, ONCE and in one place,
//! whether its input is actually present -- and to say so out loud when it is
//! not.
//!
//! Two rules this module exists to keep:
//!
//! 1. **The classification is made from evidence FOUND IN THE TREE**, never
//!    from an environment variable. A variable that is unset by default (the
//!    developer's shell, the CI) would turn the strongest leg off in the only
//!    tree where it means anything, and nothing would say so.
//! 2. **There is exactly one spelling of "skipped"**, [`skip`]. A check that
//!    disappears has to be countable in a log, and a census of skips is only
//!    possible if every one of them prints the same shape.
//!
//! Note that a `tests/` SUBDIRECTORY is not compiled as a test target of its
//! own -- this file is reached with `mod common;` from each test that needs
//! it, and each target gets its own copy, which is why the items carry
//! `dead_code`.

#![allow(dead_code)]

use std::io::Write;
use std::path::PathBuf;

/// The commit that decides whether the PRODUCER'S history is reachable from
/// this tree.
///
/// It is fixed HERE, in code, and deliberately not read from
/// `reference/BLIND_TRANSCRIPT.md`: the transcript is the thing under test,
/// so a table that could nominate its own witness would let a forger pick a
/// commit that does not resolve and be EXCUSED by the skip. Because this
/// object is chosen by the test rather than by the data, a forged row stays a
/// hard failure in every tree that has history.
///
/// `7a221184` is the commit of the transcript's FIRST row -- the copy of
/// `docs/SPEC_VERDICT_PACKAGE_V1.md` handed to the implementer. That is the
/// OLDEST object the blindness claim needs, so a tree that can resolve it can
/// resolve every later row too: no other choice makes the presence of one
/// object evidence about all of them.
///
/// `crates/witness/tests/intent_blind_transcript_history.rs` reads this
/// literal back out of this file and resolves it unconditionally, so an
/// anchor quietly repointed at an object that does not exist -- which would
/// turn the git leg off everywhere -- is red in the private tree.
pub const HISTORY_ANCHOR: &str = "7a221184";

/// The path, inside the producer's repository, whose blob the anchor names.
pub const ANCHOR_BLOB_PATH: &str = "docs/SPEC_VERDICT_PACKAGE_V1.md";

/// Which tree this test binary is running in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tree {
    /// An unpacked `.crate`. Nothing outside the package directory is here.
    Packaged,
    /// A source checkout that can resolve the producer's commits: the private
    /// workspace.
    SourceWithHistory,
    /// A source checkout that cannot: a clone of the public repository, whose
    /// history begins at the export snapshot.
    SourceWithoutHistory,
}

pub fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The classification, from evidence found in the tree.
///
/// The packaging marker is asked FIRST because it is the only positive proof
/// available: `cargo package` writes `Cargo.toml.orig` beside the manifest of
/// every crate it builds, and no source checkout has one.
/// (`.cargo_vcs_info.json` is not used: `cargo package` omits it when the
/// packaging did not happen under VCS, which is exactly how this crate is
/// packaged -- from the export staging tree, which git does not recognise.)
///
/// Only then is the history asked about, and it is asked by resolving
/// [`HISTORY_ANCHOR`] -- an object this file names, not one the data under
/// test names.
pub fn classify() -> Tree {
    if crate_root().join("Cargo.toml.orig").is_file() {
        return Tree::Packaged;
    }
    if anchor_resolves() {
        Tree::SourceWithHistory
    } else {
        Tree::SourceWithoutHistory
    }
}

/// Whether `git show <anchor>:<path>` produces bytes from this tree.
pub fn anchor_resolves() -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(crate_root())
        .arg("show")
        .arg(format!("{HISTORY_ANCHOR}:{ANCHOR_BLOB_PATH}"))
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// The ONE spelling of a skipped obligation.
///
/// One `write_all` of one complete line, to STDERR, for the reasons
/// `src/sbom/private_tree.rs` states and this file inherits: the harness
/// captures `println!` from a passing test, so a `println!` skip is a silent
/// skip; and a line assembled in pieces interleaves with the other threads.
///
/// The shape is fixed -- `skipped [<tree>]: <reason>` -- so that a census of
/// what a given tree does not measure is a `grep` of the log, and so that
/// this leg's skips are distinguishable from the `SEETREX_PRIVATE_TREE` ones,
/// which are spelled `skipped: …` with no bracket.
///
/// The tree is rendered into a `&str` BEFORE the line is assembled so that
/// the format literal below is the same source text as the one in
/// `src/sbom/compare.rs`. That module has its own copy because a `tests/`
/// subdirectory is not reachable from `src/`, and a second copy of a fixed
/// shape is a second place for the shape to change: the two literals are held
/// byte-identical by
/// `crates/witness/tests/intent_skip_spelling_is_single.rs`.
pub fn skip(tree: Tree, reason: &str) {
    let tree = format!("{tree:?}");
    let line = format!("skipped [{tree}]: {reason}\n");
    let _ = std::io::stderr().write_all(line.as_bytes());
}
