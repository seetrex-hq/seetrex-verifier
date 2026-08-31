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
/// * `docs/SPEC_VERDICT_PACKAGE_V1.md` is the same class: the PUBLIC verdict
///   package format document, on the export allowlist, read by
///   `tests/corpus_equivalence.rs` — the conformance corpus cites its headings,
///   so an exported tree without it fails that guard instead of silently
///   dropping the citation check.
/// * `etc/passwd` is the classic traversal payload of the package-extraction
///   rejection tests. It is a string literal handed to the code UNDER test and
///   is never opened -- the whole point is that the code refuses it.
///
/// A path that is not on this list is either un-exportable (it leaves the
/// public tree) or unreviewed. Both are the same answer: route it through
/// `src/sbom/private_tree.rs`, or copy it into `tests/fixtures/`.
const ALLOWED_ESCAPES: [&str; 3] = [
    "/docs/SPEC_SBOM_CANONICAL_V1.md",
    "/docs/SPEC_VERDICT_PACKAGE_V1.md",
    "/etc/passwd",
];

/// The two source roots of this crate, both of which ship in the export.
fn scanned_roots() -> [PathBuf; 2] {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    [crate_root.join("src"), crate_root.join("tests")]
}

/// Path shapes a Python file of this crate may not name. The Rust guard above
/// looks for ONE token (the grandparent escape) because a Rust test resolves
/// everything from `CARGO_MANIFEST_DIR`; a Python file has no such anchor and
/// can leave the crate in more ways, so the list is wider.
///
/// * `../` — any parent escape, not just the grandparent one. `reference/`
///   sits one level deeper than `src/`, so a single `..` already reaches the
///   crate root and a second one is outside it.
/// * `portal/` and `crates/compliance` — the two trees the export does NOT
///   ship. They are named explicitly because a reader who copies a path out
///   of the private checkout writes exactly these, and because
///   `crates/compliance` carries the closed engine: a public reference
///   implementation that reads it is not a reference implementation.
const PY_FORBIDDEN: [&str; 4] = ["../", "portal/", "crates/compliance", "parents["];

/// The per-FILE budget, because the per-LINE checks are blind to a chain
/// SPREAD OVER LINES (review row R3-B I-3): `ROOT = HERE.parent` on one line
/// and `ROOT.parent` on the next climbs two levels with one climb per line,
/// and `HERE / ".."` builds the same escape out of an operator and a string
/// literal that no path-builder heuristic has to notice.
///
/// So each shipped `.py` declares, by name, how many upward-climb tokens
/// (`.parent`, `parents[`, `dirname(`) and how many `".."` string literals it
/// is allowed to contain IN TOTAL. The numbers are small and every one of
/// them is justified below; a file that needs one more has to say so here, in
/// the same commit, where a reader sees it.
///
/// * `run_corpus.py` -- `Path(__file__).resolve().parent` (the file's own
///   directory) and `HERE.parent` (the crate root, which is where
///   `tests/fixtures/corpus` lives). Two, and no `".."` at all.
/// * `run_grammar_probes.py` -- the same two, spelled with `os.path.dirname`.
/// * `seetrex_verifier.py` -- climbs NOTHING: every path it opens is under
///   the package directory the caller named. Its two `".."` literals are the
///   path-CONFINEMENT check itself, which rejects a package whose manifest
///   names a `..` component, plus the error message that quotes it.
const PY_UPWARD_BUDGET: &[(&str, usize, usize)] = &[
    ("run_corpus.py", 2, 0),
    ("run_grammar_probes.py", 2, 0),
    ("seetrex_verifier.py", 0, 2),
];

/// Upward-climb tokens on one line: `.parent` (not `.parents[`, which
/// [`PY_FORBIDDEN`] already refuses on sight), `dirname(`, `parents[`.
fn climb_tokens(line: &str) -> usize {
    let pathlib = line
        .match_indices(".parent")
        .filter(|(at, token)| {
            let after = line[at + token.len()..].chars().next();
            !matches!(after, Some(c) if c.is_alphanumeric() || c == '_')
        })
        .count();
    pathlib + line.matches("dirname(").count() + line.matches("parents[").count()
}

/// `".."` and `'..'` written as a string literal, anywhere on the line --
/// path-builder context or not. `HERE / ".."` is an escape; so is
/// `os.path.join(HERE, "..")`; so is a `".."` handed to a helper three
/// functions away. The only way to tell an escape from a confinement CHECK is
/// to declare the count per file, which [`PY_UPWARD_BUDGET`] does.
fn dotdot_literals(line: &str) -> usize {
    line.matches("\"..\"").count() + line.matches("'..'").count()
}

/// Every `.py` file of this crate, wherever it lives. Scanned from the crate
/// root rather than from a fixed subdirectory so a Python file added in a
/// directory nobody thought of is covered on the day it lands (L34: a
/// per-directory guard does not protect against directory N+1).
fn python_sources(dir: &Path, found: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read directory {}: {error}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|error| panic!("read entry of {}: {error}", dir.display()))
            .path();
        if path.is_dir() {
            // `target/` is build output and never ships; everything else does.
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            python_sources(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "py") {
            found.push(path);
        }
    }
}

/// How many directory levels ONE line climbs.
///
/// `reference/` and `tests/` sit one level below the crate root, so a single
/// climb (`Path(__file__).resolve().parent`, `os.path.dirname(HERE)`) is the
/// most a file of this crate ever needs: two reach the workspace and leave
/// the published tree. Both spellings are counted -- pathlib's `.parent`
/// chain and `os.path`'s nested `dirname(` -- because forbidding one of them
/// only moves the escape to the other.
///
/// `.parent` inside a longer identifier (`self.parent_id`) does not count: the
/// character after the token must not continue the name.
fn upward_climb_depth(line: &str) -> usize {
    let pathlib = line
        .match_indices(".parent")
        .filter(|(at, token)| {
            let after = line[at + token.len()..].chars().next();
            !matches!(after, Some(c) if c.is_alphanumeric() || c == '_')
        })
        .count();
    // `dirname(dirname(` and deeper: one `dirname(` is a single climb, N
    // nested ones are N. Counting occurrences on the line is the same number
    // whenever they nest, which is the only way they are ever written.
    let os_path = line.matches("dirname(").count();
    pathlib.max(os_path)
}

/// The path CONSTRUCTORS a `..` segment would have to travel through to
/// leave the crate. Scoping to them is deliberate: `check_relative` REJECTS a
/// `..` component and therefore has to spell it, and a guard that cannot tell
/// building a path from refusing one is a guard nobody keeps.
const PY_PATH_BUILDERS: [&str; 4] = ["joinpath(", "os.path.join(", "Path(", "PurePath("];

/// Whether the line BUILDS a path with a `..` segment -- `joinpath("..")`,
/// `Path("..", …)`, `os.path.join(x, "a/../b")`. The `"../"` token of
/// [`PY_FORBIDDEN`] misses the quoted-segment spelling, which is the one a
/// path builder uses.
fn names_dotdot_segment(line: &str) -> bool {
    if !PY_PATH_BUILDERS.iter().any(|b| line.contains(b)) {
        return false;
    }
    for quote in ['"', '\''] {
        let mut rest = line;
        while let Some(at) = rest.find(quote) {
            let after = &rest[at + quote.len_utf8()..];
            let Some(end) = after.find(quote) else { break };
            let literal = &after[..end];
            if literal == ".." || literal.split(['/', '\\']).any(|seg| seg == "..") {
                return true;
            }
            rest = &after[end + quote.len_utf8()..];
        }
    }
    false
}

/// The absolute-path literal a line opens, if it opens one: a quote followed
/// by `/` (POSIX root) or by a Windows drive prefix. `"/"` alone is a
/// separator, not a path, so a literal of one character does not count.
fn absolute_literal(line: &str) -> Option<String> {
    let chars: Vec<char> = line.chars().collect();
    for (i, quote) in chars.iter().enumerate() {
        if *quote != '"' && *quote != '\'' {
            continue;
        }
        let rest: String = chars[i + 1..].iter().take_while(|c| *c != quote).collect();
        let posix_root = rest.starts_with('/') && rest.len() > 1;
        let drive = rest.len() > 2
            && rest.as_bytes()[0].is_ascii_alphabetic()
            && rest.as_bytes()[1] == b':'
            && matches!(rest.as_bytes()[2], b'/' | b'\\');
        if posix_root || drive {
            return Some(rest);
        }
    }
    None
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

/// INTENT: no Python file of this crate reaches outside the crate either.
///   The Rust guard above protects `cargo test` in the exported tree; this
///   one protects the reference implementation and its corpus runner, which
///   ship in the same export and which an auditor runs by hand, with no
///   `CARGO_MANIFEST_DIR` and no cargo to fail loudly for them.
/// CONTEXT: T10 put `reference/seetrex_verifier.py` and
///   `reference/run_corpus.py` inside this crate precisely so the export
///   allowlist needs no edit (`export_public.sh` allowlists
///   `crates/verifier` whole). The price of that choice is that a Python
///   file can now break the export the same way a Rust test did in T8 --
///   and more quietly, because nothing compiles it. `Path.parents[n]` is
///   forbidden outright, not merely audited: `run_corpus.py` used
///   `parents[2]` to reach the repository root for a `pkg.txt` indirection,
///   which named no relative escape and still left the crate. The corpus is
///   reached with a single `.parent` from the file's own location, and the
///   material a case needs is COPIED into the case.
/// EXPIRES IF: the Python leaves this crate, at which point the export
///   allowlist -- not this guard -- decides whether it ships.
#[test]
fn test_intent_public_crate_python_does_not_read_outside_the_crate() {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let mut sources = Vec::new();
    python_sources(&crate_root, &mut sources);
    assert!(
        sources.len() >= 2,
        "only {} Python file(s) found under {}; the reference implementation \
         and its corpus runner both live here, so a guard that scans fewer \
         than two passes for the wrong reason",
        sources.len(),
        crate_root.display()
    );

    let mut offences = Vec::new();
    for source in &sources {
        let text = fs::read_to_string(source)
            .unwrap_or_else(|error| panic!("read {}: {error}", source.display()));
        let shown = source
            .strip_prefix(&crate_root)
            .unwrap_or(source)
            .display()
            .to_string()
            .replace('\\', "/");
        let mut climbs_in_file = 0usize;
        let mut dotdots_in_file = 0usize;
        for (number, line) in text.lines().enumerate() {
            for token in PY_FORBIDDEN {
                if line.contains(token) {
                    offences.push(format!("{shown}:{}: [{token}] {}", number + 1, line.trim()));
                }
            }
            if let Some(literal) = absolute_literal(line) {
                offences.push(format!(
                    "{shown}:{}: [absolute path] {literal}",
                    number + 1
                ));
            }
            // R2-B I-2: the token list above is per-token and blind to a
            // CHAIN. `.parent.parent.parent` contains no forbidden token and
            // still leaves the crate; so does a `..` segment written without
            // a slash, which `"../"` never sees.
            let climbs = upward_climb_depth(line);
            if climbs > 1 {
                offences.push(format!(
                    "{shown}:{}: [climbs {climbs} levels] {}",
                    number + 1,
                    line.trim()
                ));
            }
            if names_dotdot_segment(line) {
                offences.push(format!(
                    "{shown}:{}: [`..` path segment] {}",
                    number + 1,
                    line.trim()
                ));
            }
            climbs_in_file += climb_tokens(line);
            dotdots_in_file += dotdot_literals(line);
        }

        // R3-B I-3: the FILE-level budget. Everything above is per line and
        // therefore blind to a chain spread across assignments.
        let name = shown.rsplit('/').next().unwrap_or(&shown).to_string();
        let (max_climbs, max_dotdots) = PY_UPWARD_BUDGET
            .iter()
            .find(|(n, _, _)| *n == name)
            .map(|(_, c, d)| (*c, *d))
            .unwrap_or_else(|| {
                panic!(
                    "`{shown}` is a Python file of this crate and PY_UPWARD_BUDGET does \
                     not declare it. Add it with the number of upward climbs and `\"..\"` \
                     literals it needs, and the reason -- an undeclared file would be \
                     scanned line by line and never against a total."
                )
            });
        if climbs_in_file > max_climbs {
            offences.push(format!(
                "{shown}: [{climbs_in_file} upward-climb tokens, budget {max_climbs}] a \
                 chain SPREAD OVER LINES leaves the crate exactly as a chain on one line does"
            ));
        }
        if dotdots_in_file > max_dotdots {
            offences.push(format!(
                "{shown}: [{dotdots_in_file} `..` string literals, budget {max_dotdots}] a \
                 `..` handed to a path operator escapes the crate whatever built the path"
            ));
        }
    }
    assert!(
        offences.is_empty(),
        "these lines leave the crate, so the reference implementation stops \
         being runnable from the published tree alone -- and unlike the Rust, \
         nothing compiles them, so the break would first appear in an \
         auditor's hands. Anchor the path on the file's own location \
         (`Path(__file__).resolve().parent`, NEVER `.parents[n]`), or copy \
         the input \
         into `tests/fixtures/`:\n{}",
        offences.join("\n")
    );
}
