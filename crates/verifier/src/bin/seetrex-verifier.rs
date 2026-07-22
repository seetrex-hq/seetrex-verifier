// SPDX-License-Identifier: Apache-2.0
//! `seetrex-verifier` — the standalone, offline verification tool an
//! external auditor obtains from public material alone
//! (`cargo install seetrex-verifier`).
//!
//! Thin shell over the pure library: every check this binary runs is a
//! public library function (`package::verify_package`,
//! `chain_export::parse_and_verify_package`) — the binary only parses
//! arguments, reads files, prints, and maps results to exit codes.
//! Argument parsing is `std::env` only, on purpose: the crate's
//! dependency-purity intent test keeps the open verifier free of any
//! non-essential dependency, an arg-parsing crate included.
//!
//! Subcommands:
//!
//! - `verify-package <dir> [--expected-verdict-hash <hex>]` — package
//!   integrity verification per spec §9.6 (`SPEC_VERDICT_PACKAGE_V1.md`).
//!   Outcome vocabulary and exit codes are BINDING (§9.6): anchored pass
//!   → `INTEGRITY-OK (weak)` / exit 0; unanchored pass →
//!   `SELF-CONSISTENT (unanchored)` / exit 4; any failure → sanitized
//!   error line / exit 1. Every printed line passes through
//!   `package::sanitize_reserved_token` (§9.6 "Reserved vocabulary"):
//!   the token `VERIFIED` is RESERVED for the strong surfaces and MUST
//!   NOT be emitted by this weak mode — not even via package-controlled
//!   bytes echoed into an error.
//! - `verify-chain <file.json>` — OFFLINE verification of a downloaded
//!   public chain export (§8.1): recomputes every link and the ordinal
//!   contiguity, then reports the head (`verdict_count`,
//!   `last_chain_hash`). Per §9.6 "Reserved vocabulary", `verify-chain`
//!   against the published chain export IS one of the strong surfaces
//!   that emit `VERIFIED` — the success line here is
//!   `Public chain package VERIFIED OFFLINE`, the same wording as the
//!   reference CLI. Failures are sanitized (a hostile export must not
//!   smuggle the strong token into a FAILING run's output) and exit 1.
//!
//! Usage errors (unknown command, missing operand) exit 2 — distinct
//! from the spec-bound verification codes 0/1/4.

use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use seetrex_verifier::chain_export::parse_and_verify_package;
use seetrex_verifier::package::{sanitize_reserved_token, verify_package, SCOPE_STATEMENT};

/// Read cap for the chain export file (DoS guard). A real chain export
/// is a few hundred bytes per row; 50 MiB is far beyond any legitimate
/// export without being unbounded.
const CHAIN_FILE_MAX_BYTES: u64 = 50 * 1024 * 1024;

const HELP: &str = "\
seetrex-verifier — offline verification of Seetrex Compliance verdict
packages and public chain exports (spec: SPEC_VERDICT_PACKAGE_V1.md).

USAGE:
    seetrex-verifier verify-package <dir> [--expected-verdict-hash <hex>]
    seetrex-verifier verify-chain <file.json>
    seetrex-verifier --help | --version

COMMANDS:
    verify-package    Package integrity check over an extracted package
                      directory (spec section 9.6). Re-computes hashes
                      only. With --expected-verdict-hash (an anchor
                      obtained OUTSIDE the package, e.g. from the public
                      chain export): INTEGRITY-OK (weak), exit 0.
                      Without it: SELF-CONSISTENT (unanchored), exit 4 —
                      NOT a verification. Any failure: exit 1.
    verify-chain      Offline verification of a downloaded public chain
                      export (spec section 8.1): recomputes every
                      SHA-256 link and reports the chain head. Success:
                      exit 0. Any failure: exit 1.

Exit code 2 = usage error.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") | Some("-V") => {
            println!("seetrex-verifier {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("--help") | Some("-h") => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        Some("verify-package") => cmd_verify_package(&args[1..]),
        Some("verify-chain") => cmd_verify_chain(&args[1..]),
        Some(other) => {
            eprintln!("error: unknown command `{}`\n\n{HELP}", sanitize_reserved_token(other));
            ExitCode::from(2)
        }
        None => {
            eprintln!("{HELP}");
            ExitCode::from(2)
        }
    }
}

/// `verify-package <dir> [--expected-verdict-hash <hex>]` — mirrors the
/// reference CLI arm line for line: a SELF-CONTAINED output boundary
/// where EVERY printed line — step/report lines, WARNINGs, terminal
/// tokens, the honest-scope statement, and the error path — is routed
/// through `sanitize_reserved_token`, because a `PackageVerifyError`
/// (and, defensively, any report line) can embed package-controlled
/// bytes that would otherwise smuggle the reserved strong-pass token
/// into a WEAK check's output (§9.6).
fn cmd_verify_package(rest: &[String]) -> ExitCode {
    let mut package_dir: Option<&str> = None;
    let mut expected: Option<String> = None;
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--expected-verdict-hash" => match it.next() {
                Some(v) => expected = Some(v.clone()),
                None => {
                    eprintln!("error: --expected-verdict-hash requires a value");
                    return ExitCode::from(2);
                }
            },
            other if package_dir.is_none() && !other.starts_with("--") => {
                package_dir = Some(other);
            }
            other => {
                eprintln!(
                    "error: unexpected argument `{}` for verify-package",
                    sanitize_reserved_token(other)
                );
                return ExitCode::from(2);
            }
        }
    }
    let Some(package_dir) = package_dir else {
        eprintln!("error: verify-package requires a package directory operand");
        return ExitCode::from(2);
    };

    match verify_package(Path::new(package_dir), expected.as_deref()) {
        Ok(report) => {
            for step in &report.steps {
                println!("{}", sanitize_reserved_token(step));
            }
            for w in &report.warnings {
                println!("{}", sanitize_reserved_token(&format!("WARNING: {w}")));
            }
            if report.anchored {
                // Weak pass token (anchored) — binding per §9.6.
                println!("{}", sanitize_reserved_token("INTEGRITY-OK (weak)"));
                println!("{}", sanitize_reserved_token(SCOPE_STATEMENT));
                ExitCode::SUCCESS
            } else {
                println!("{}", sanitize_reserved_token("SELF-CONSISTENT (unanchored)"));
                println!("{}", sanitize_reserved_token(SCOPE_STATEMENT));
                println!(
                    "{}",
                    sanitize_reserved_token(
                        "HINT: pass --expected-verdict-hash <hex> (obtained \
                         from the published chain export or another external \
                         channel) to upgrade this to INTEGRITY-OK (weak) — \
                         the package can never be its own trust root."
                    )
                );
                // Exit 4 — an unanchored pass is NOT a verification (§9.6).
                ExitCode::from(4)
            }
        }
        Err(e) => {
            eprintln!("{}", sanitize_reserved_token(&format!("ERROR: {e}")));
            // The honest-scope statement prints on EVERY terminal outcome,
            // failure included (§9.6).
            eprintln!("{}", sanitize_reserved_token(SCOPE_STATEMENT));
            ExitCode::from(1)
        }
    }
}

/// `verify-chain <file.json>` — thin wrapper over the pure
/// `parse_and_verify_package`: read the export with a byte cap, verify
/// offline, report the head. Success prints the strong `VERIFIED`
/// wording (the §9.6 reserve names this surface as one of its
/// counterparts); the FAILURE path is sanitized — a hostile export
/// could otherwise echo the strong token into a failing run's stderr.
fn cmd_verify_chain(rest: &[String]) -> ExitCode {
    let [file] = rest else {
        eprintln!("error: verify-chain requires exactly one <file.json> operand");
        return ExitCode::from(2);
    };

    let raw = match read_capped_utf8(Path::new(file.as_str())) {
        Ok(raw) => raw,
        Err(detail) => {
            // The filename comes from argv — attacker-influenced in
            // scripted pipelines; sanitize it like every other
            // non-fixed string.
            eprintln!(
                "ERROR: cannot read {}: {}",
                sanitize_reserved_token(file),
                sanitize_reserved_token(&detail)
            );
            return ExitCode::from(1);
        }
    };

    match parse_and_verify_package(&raw) {
        Ok(head) => {
            println!("Public chain package VERIFIED OFFLINE");
            println!("  verdict_count:   {}", head.verdict_count);
            println!("  last_chain_hash: {}", head.last_chain_hash);
            println!();
            // SCOPE, stated at the same volume as the banner. The link
            // preimage covers only `verdict_hash`, `chain_prev_hash` and
            // `chain_hash`; the human-readable columns of the export are
            // NOT inputs to it, so editing them leaves every link — and
            // this head hash — intact. Two of the four (verdict_outcome,
            // ruleset_id) are committed inside the verdict's own hash,
            // recomputable only from its package; the other two
            // (appended_at, verdict_id) are committed nowhere — no artifact
            // we publish binds them. Saying "tamper-evidence of the observed
            // history" here was an overclaim: an external evaluator rewrote
            // the head row's outcome, ruleset id and timestamp and still got
            // this banner with the vendor's exact published head hash.
            println!(
                "Compare these two values against the vendor's public Trust \
                 Center page for this tenant. {}",
                seetrex_verifier::scope::SCOPE_LINK_CLAIM
            );
            println!();
            println!("{}", seetrex_verifier::scope::SCOPE_NOT_COVERED);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{}", sanitize_reserved_token(&format!("ERROR: {e}")));
            ExitCode::from(1)
        }
    }
}

/// Read a file with a hard byte cap (DoS guard), requiring UTF-8.
/// Bounded at the source so a concurrent writer cannot push the read
/// past the cap.
fn read_capped_utf8(path: &Path) -> Result<String, String> {
    let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let meta = f.metadata().map_err(|e| e.to_string())?;
    if meta.len() > CHAIN_FILE_MAX_BYTES {
        return Err(format!(
            "{} bytes exceeds the {CHAIN_FILE_MAX_BYTES} byte cap",
            meta.len()
        ));
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    f.take(CHAIN_FILE_MAX_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() as u64 > CHAIN_FILE_MAX_BYTES {
        return Err("file grew past the byte cap during read".to_string());
    }
    String::from_utf8(buf).map_err(|e| format!("not valid UTF-8: {e}"))
}
