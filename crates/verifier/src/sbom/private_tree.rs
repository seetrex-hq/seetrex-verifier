// SPDX-License-Identifier: Apache-2.0
//! The private-tree gate: the single route from a test of this crate to a
//! file that lives OUTSIDE the crate.
//!
//! A handful of tests here are worth running against the lockfiles of the
//! closed repository this crate is developed in, not only against the
//! synthetic corpus in `tests/fixtures/`: a fixture proves the projection
//! handles the shapes somebody thought of, a real lockfile proves it handles
//! the shapes that actually occur. Those lockfiles are not part of the
//! published source tree, so a test that climbs out of the crate to reach
//! them -- two levels up from `CARGO_MANIFEST_DIR`, into `portal/` or
//! `frontend/` -- makes the PUBLISHED crate un-testable: `cargo test` in an
//! exported checkout panics on a file that was never exported.
//!
//! `tests/intent_public_crate_is_self_contained.rs` is the guard that keeps
//! that escape from being written again.
//!
//! This module is the only place allowed to leave the crate, and it is
//! fail-closed in BOTH directions:
//!
//! * `SEETREX_PRIVATE_TREE` unset -> the caller SKIPS, out loud, and counts
//!   as passed. An exported checkout is green without pretending it measured
//!   anything. The line goes to the process stderr rather than through
//!   `println!`, because the test harness CAPTURES the print macros: a
//!   `println!` from a PASSING test is shown only under `--nocapture`, which
//!   is the silent skip this design refuses.
//! * `SEETREX_PRIVATE_TREE` set -> the value must name a directory that
//!   carries every lockfile in `REQUIRED_LOCKFILES`, or the caller FAILS. A
//!   typo, an empty expansion or a moved checkout is an ERROR, never a
//!   silent skip -- otherwise the private CI could quietly stop exercising
//!   these tests and nothing would go red.
//!
//! `#[ignore]` is deliberately not used for this: an ignored test is
//! invisible in the banner of the very run that should have exercised it,
//! and it is skipped in the private tree too.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Environment variable naming the root of the private repository.
const PRIVATE_TREE_VAR: &str = "SEETREX_PRIVATE_TREE";

/// The lockfiles the private-tree tests project. A directory that does not
/// carry all four is not the tree these tests mean, whatever its name.
const REQUIRED_LOCKFILES: [&str; 4] = [
    "Cargo.lock",
    "portal/composer.lock",
    "portal/package-lock.json",
    "frontend/package-lock.json",
];

/// The private repository root, or `None` when this run is not in it.
///
/// A caller that gets `None` must return immediately: the skip line has
/// already been printed on its behalf.
pub(crate) fn private_tree() -> Option<PathBuf> {
    let raw = match std::env::var(PRIVATE_TREE_VAR) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => {
            // One `write_all` of one complete line: the harness runs tests in
            // parallel and a line assembled in pieces would interleave.
            let line = format!(
                "skipped: {PRIVATE_TREE_VAR} not set - this test needs the private repository\n"
            );
            let _ = std::io::stderr().write_all(line.as_bytes());
            return None;
        }
        Err(std::env::VarError::NotUnicode(value)) => panic!(
            "{PRIVATE_TREE_VAR} is set to a non-Unicode value ({value:?}); \
             a path that cannot be read is an error, not a skip"
        ),
    };

    let root = PathBuf::from(raw.trim());
    assert!(
        !root.as_os_str().is_empty(),
        "{PRIVATE_TREE_VAR} is set but EMPTY. That is a broken expansion in \
         whatever set it, not a request to skip: unset the variable to skip \
         these tests deliberately."
    );
    assert!(
        root.is_dir(),
        "{PRIVATE_TREE_VAR} names `{}`, which is not a directory. A wrong \
         path is an error, not a skip: unset the variable to skip these \
         tests deliberately.",
        root.display()
    );
    for lockfile in REQUIRED_LOCKFILES {
        assert!(
            root.join(lockfile).is_file(),
            "{PRIVATE_TREE_VAR} names `{}`, but `{lockfile}` is missing \
             there. That directory is not the private repository these \
             tests read.",
            root.display()
        );
    }
    Some(root)
}

/// Read a file of the private tree. `relative` is always slash-separated and
/// always relative to the root returned by [`private_tree`].
pub(crate) fn read_private_file(root: &Path, relative: &str) -> String {
    let path = root.join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}
