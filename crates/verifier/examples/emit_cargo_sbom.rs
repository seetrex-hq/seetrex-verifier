// SPDX-License-Identifier: Apache-2.0
//! `emit_cargo_sbom` -- write the canonical SBOM projection of a
//! `Cargo.lock` to a file, and print its SHA-256.
//!
//! The projection itself lives in the library (`sbom::cargo`); this
//! example only parses arguments, reads the lockfile and writes bytes.
//! It exists because the PRODUCER side has to be runnable before the
//! auditor CLI grows its own subcommands: the evidence workflow emits the
//! document on every push, and an example is a build target that is
//! published with the crate yet never enters the dependency set of
//! anybody who installs the tool.
//!
//! Usage:
//!
//! ```text
//! emit_cargo_sbom --lockfile <Cargo.lock> --subject <purl> --out <file>
//! ```
//!
//! `--subject` is an input of the CALLER and is never read back out of a
//! document: a `Cargo.lock` names several workspace members without
//! source and none of them is marked as "the product", so inferring the
//! subject would be inventing it.
//!
//! The bytes written are exactly the canonical form (JCS RFC 8785, ONE
//! line, no trailing newline, UTF-8 without a byte order mark). That is
//! what makes the printed hash checkable with stock tooling: for the file
//! this example wrote, `sha256sum <file>` yields the same value.
//!
//! Argument parsing is `std::env` only, like the auditor CLI next to it:
//! the crate's dependency-purity intent test keeps the open verifier free
//! of any non-essential dependency, an arg-parsing crate included.
//!
//! Exit codes: 0 written; 2 usage error, unreadable lockfile, malformed
//! subject, unwritable destination, or a lockfile shape the projection
//! refuses to guess about. There is no code 1: this tool VERIFIES
//! nothing, so it can never report a verification failure.

use std::fs;
use std::process::ExitCode;

use seetrex_verifier::sbom::cargo::project_lockfile;
use seetrex_verifier::sbom::SubjectPurl;

const USAGE: &str = "usage: emit_cargo_sbom --lockfile <Cargo.lock> --subject <purl> --out <file>";

fn main() -> ExitCode {
    match run() {
        Ok(hash) => {
            println!("{hash}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("emit_cargo_sbom: {message}");
            // 2 is the usage/environment code of the tool family; see the
            // module header for why there is no other failure code here.
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<String, String> {
    let (lockfile, subject, out) = parse_args()?;

    let text = fs::read_to_string(&lockfile)
        .map_err(|e| format!("cannot read the lockfile {lockfile}: {e}"))?;
    let subject = SubjectPurl::parse(&subject).map_err(|e| format!("{e}"))?;

    let projection = project_lockfile(&text, subject).map_err(|e| format!("{e}"))?;
    let bytes = projection
        .to_canonical_bytes()
        .map_err(|e| format!("{e}"))?;
    let hash = projection.canonical_sha256().map_err(|e| format!("{e}"))?;

    // Written WITHOUT a trailing newline on purpose: the file IS the
    // canonical serialization, so any byte the writer adds of its own
    // would break the equality between `sha256sum <file>` and the hash
    // printed on the line above.
    fs::write(&out, bytes.as_bytes()).map_err(|e| format!("cannot write {out}: {e}"))?;

    eprintln!(
        "wrote {out} ({} components, {} top-level)",
        projection.components().len(),
        projection.top_level().len()
    );
    Ok(hash)
}

/// `(lockfile, subject, out)`. Every flag is mandatory and takes exactly
/// one operand; an unknown flag is an error rather than something
/// ignored, because a silently ignored `--out` would write the document
/// nowhere and still exit 0.
fn parse_args() -> Result<(String, String, String), String> {
    let mut lockfile: Option<String> = None;
    let mut subject: Option<String> = None;
    let mut out: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let target = match arg.as_str() {
            "--lockfile" => &mut lockfile,
            "--subject" => &mut subject,
            "--out" | "-o" => &mut out,
            other => return Err(format!("unknown argument {other:?}\n{USAGE}")),
        };
        let value = args
            .next()
            .ok_or_else(|| format!("{arg} needs an operand\n{USAGE}"))?;
        if target.replace(value).is_some() {
            return Err(format!("{arg} given twice\n{USAGE}"));
        }
    }

    let missing = |name: &str| format!("missing {name}\n{USAGE}");
    Ok((
        lockfile.ok_or_else(|| missing("--lockfile"))?,
        subject.ok_or_else(|| missing("--subject"))?,
        out.ok_or_else(|| missing("--out"))?,
    ))
}
