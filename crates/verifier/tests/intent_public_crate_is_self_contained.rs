// SPDX-License-Identifier: Apache-2.0
//! The published crate must be testable from the published tree alone.
//!
//! `scripts/export_public.sh` builds the public tree from an allowlist and
//! then runs `cargo test --locked` inside it, in isolation from the private
//! workspace: "if it does not compile alone, the export is broken". A test
//! that climbs two levels out of `CARGO_MANIFEST_DIR` to read
//! `portal/composer.lock` breaks exactly that, and breaks it INVISIBLY on the
//! machine that wrote it -- in the private checkout the file is right there,
//! so the escape looks harmless until the export tries to run and panics on a
//! file it never copied.
//!
//! This file is the guard that makes the escape visible where it is written
//! rather than at export time. It reads the crate's OWN source, so it travels
//! with the export and holds in the public repository too.
//!
//! The one legitimate route out of the crate is `src/sbom/private_tree.rs`,
//! which reads the private repository only when `SEETREX_PRIVATE_TREE` names
//! it and otherwise skips out loud. That module reaches its files through the
//! variable, not through a relative escape, so it needs no exception here.

use std::fs;
use std::path::{Path, PathBuf};

/// Parent-parent escape token, assembled rather than written, so this file
/// does not trip the guard it implements.
fn escape_token() -> String {
    ["..", "/", ".."].concat()
}

/// Every occurrence of the escape token in the crate must begin one of these
/// paths, and nothing else.
///
/// * `docs/SPEC_SBOM_CANONICAL_V1.md` is a PUBLIC format document, on the
///   export allowlist and promoted to its must-exist check: two levels up from
///   the crate is the staging root and `docs/` is right there, so the two
///   guards that read the specification prove themselves in the exported tree
///   rather than panicking in it.
/// * `etc/passwd` is the classic traversal payload of the package-extraction
///   rejection tests. It is a string literal handed to the code UNDER test and
///   is never opened -- the whole point is that the code refuses it.
///
/// A path that is not on this list is either un-exportable (it leaves the
/// public tree) or unreviewed. Both are the same answer: route it through
/// `src/sbom/private_tree.rs`, or copy it into `tests/fixtures/`.
const ALLOWED_ESCAPES: [&str; 2] = ["/docs/SPEC_SBOM_CANONICAL_V1.md", "/etc/passwd"];

/// The two source roots of this crate, both of which ship in the export.
fn scanned_roots() -> [PathBuf; 2] {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    [crate_root.join("src"), crate_root.join("tests")]
}

fn rust_sources(dir: &Path, found: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read directory {}: {error}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|error| panic!("read entry of {}: {error}", dir.display()))
            .path();
        if path.is_dir() {
            rust_sources(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// INTENT: no source file of this crate reaches a grandparent directory
///   except for the reviewed, exported paths of `ALLOWED_ESCAPES`. Everything
///   else that a test needs from outside the crate goes through the
///   `SEETREX_PRIVATE_TREE` gate of `src/sbom/private_tree.rs`, which skips
///   out loud when the private repository is not there.
/// CONTEXT: T8 landed real-lockfile tests that climbed two levels out of
///   `CARGO_MANIFEST_DIR` to read `portal/`, `frontend/` and the workspace
///   `Cargo.lock`. None of those paths is on the export allowlist, so phase 4
///   of `scripts/export_public.sh` -- `cargo test --locked` in the isolated
///   staging tree -- panicked in a dozen tests and the export was
///   un-runnable, with nothing in the private suite going red to say so.
/// EXPIRES IF: the export stops running the crate's test suite in isolation,
///   which is the property this guard exists to protect. Adding an entry to
///   `ALLOWED_ESCAPES` is allowed only for a path the export allowlist ships,
///   and the assertion below re-measures exactly that.
#[test]
fn test_intent_public_crate_tests_do_not_read_outside_the_crate() {
    let token = escape_token();
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let mut sources = Vec::new();
    for root in scanned_roots() {
        rust_sources(&root, &mut sources);
    }
    assert!(
        sources.len() > 10,
        "only {} source files found under src/ and tests/; a guard that \
         scans nothing passes for the wrong reason",
        sources.len()
    );

    let mut offences = Vec::new();
    for source in &sources {
        let text = fs::read_to_string(source)
            .unwrap_or_else(|error| panic!("read {}: {error}", source.display()));
        for (number, line) in text.lines().enumerate() {
            let mut rest = line;
            while let Some(at) = rest.find(&token) {
                let tail = &rest[at + token.len()..];
                if !ALLOWED_ESCAPES.iter().any(|ok| tail.starts_with(ok)) {
                    offences.push(format!(
                        "{}:{}: {}",
                        source
                            .strip_prefix(&crate_root)
                            .unwrap_or(source)
                            .display()
                            .to_string()
                            .replace('\\', "/"),
                        number + 1,
                        line.trim()
                    ));
                }
                rest = &rest[at + token.len()..];
            }
        }
    }
    assert!(
        offences.is_empty(),
        "these lines leave the crate by a relative path that the public \
         export does not ship, so `cargo test` in the exported tree panics \
         on a file that was never copied. Route the read through the \
         SEETREX_PRIVATE_TREE gate of src/sbom/private_tree.rs, or copy the \
         input into tests/fixtures/:\n{}",
        offences.join("\n")
    );

    // The allowlist is not a free pass: each entry that names a document must
    // actually resolve from this crate, which is what proves it is exported
    // alongside the source rather than merely tolerated by this guard. The
    // traversal payload is a string literal and has no file to check.
    for allowed in ALLOWED_ESCAPES {
        if allowed == "/etc/passwd" {
            continue;
        }
        let resolved = crate_root.join(format!("{token}{allowed}"));
        assert!(
            resolved.is_file(),
            "ALLOWED_ESCAPES lists `{token}{allowed}`, which does not exist \
             at {}. An escape is allowed only while the export ships its \
             target.",
            resolved.display()
        );
    }
}
