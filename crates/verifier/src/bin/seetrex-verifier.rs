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
//! - `verify-anchor <anchor.json> --kit <kit.json>` — OFFLINE
//!   verification of a producer's published anchor package against the
//!   PINNED auditor kit. The package is UNTRUSTED; the
//!   `--kit` file (a SEPARATE, trusted artifact) supplies the tenant,
//!   genesis key and witness policy that the package must never name.
//!   Prints the v6 two-verdict result — CONSISTENCIA (confirmed offline /
//!   failed) and COMPLETITUD (INCONCLUSIVE offline UNLESS a `--monitor
//!   <bundle>` is supplied, in which case it is a REAL verdict —
//!   CONFIRMED / INCONCLUSIVE / FAILED). Unlike
//!   `verify-chain` it does NOT emit the reserved `VERIFIED` token: this
//!   surface is not §9.6-blessed and a confirmed CONSISTENCIA with
//!   INCONCLUSIVE COMPLETITUD is not a blanket strong pass. CONSISTENCIA
//!   confirmed: exit 0. Failed / bad package: exit 1. Bad kit: exit 2.
//!
//! Usage errors (unknown command, missing operand, malformed auditor
//! kit) exit 2 — distinct from the spec-bound verification codes 0/1/4.

use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use seetrex_verifier::anchor::Verdict;
use seetrex_verifier::anchor_package::{
    parse_anchor_package, parse_auditor_kit, verify_anchored_package, MonitorAudit,
};
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
    seetrex-verifier verify-anchor <anchor.json> --kit <kit.json> [--monitor <bundle.json>]
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
    verify-anchor     Offline verification of a producer's published
                      anchor package (<anchor.json>) against your PINNED
                      auditor kit (--kit <kit.json>, supplying the tenant,
                      genesis key and witness policy — NEVER read from the
                      package). Reports the two v6 verdicts: CONSISTENCIA
                      (non-contradiction, confirmed offline) and
                      COMPLETITUD (INCONCLUSIVE offline UNLESS --monitor
                      <bundle> is supplied — omission needs an independent
                      monitor; with one, COMPLETITUD is a REAL verdict:
                      CONFIRMED / INCONCLUSIVE / FAILED. A supplied monitor's
                      enumeration completeness and recency are a TRUSTED input,
                      NOT cryptographically proven offline — every leaf's
                      inclusion and the checkpoint cosignature ARE). CONSISTENCIA confirmed:
                      exit 0. CONSISTENCIA failed / bad package: exit 1.
                      Bad or missing kit: exit 2. Exit 0 confirms
                      NON-CONTRADICTION only — surfaced anomalous
                      rotations and completeness (omitted leaves) are
                      enumeration-dependent; do not gate
                      automation on exit 0 alone.

Exit code 2 = usage error (or a malformed/missing auditor kit).";

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
        Some("verify-anchor") => cmd_verify_anchor(&args[1..]),
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

/// `verify-anchor <anchor.json> --kit <kit.json>` — thin shell over
/// `verify_anchored_package`. The positional `anchor.json` is the UNTRUSTED,
/// producer-published package (public evidence: chain rows, anchored leaves +
/// inclusion proofs, rotate leaves, checkpoint). The `--kit` file is the
/// TRUSTED auditor kit that supplies the PINNED tenant slug, genesis key and
/// witness policy — a SEPARATE file, so the package can never
/// name its own witnesses or its own genesis.
///
/// Output is the v6 two-verdict result: `CONSISTENCIA` (confirmed offline / or
/// failed) and `COMPLETITUD` (INCONCLUSIVE offline UNLESS `--monitor <bundle>`
/// is supplied, in which case it is a REAL verdict — CONFIRMED / INCONCLUSIVE /
/// FAILED — because the enumeration completeness is then the trusted input,
/// enumeration-dependent). It deliberately does NOT emit the reserved `VERIFIED` token:
/// `verify-anchor` is not a §9.6-blessed strong surface, and a confirmed
/// CONSISTENCIA with INCONCLUSIVE COMPLETITUD is not a blanket strong pass. The
/// success banner is a FIXED string (no reserved token by construction); every
/// variable/package-controlled string (failure reasons, filenames) is routed
/// through `sanitize_reserved_token`.
///
/// Exit codes: CONSISTENCIA confirmed → 0; CONSISTENCIA failed / unreadable /
/// malformed PACKAGE → 1; usage error OR a malformed/unreadable KIT → 2. A bad
/// kit is the AUDITOR's own config error, kept distinct from exit 1 so a script
/// gating on "the vendor's package failed" is not polluted by a typo in the
/// auditor's kit file.
fn cmd_verify_anchor(rest: &[String]) -> ExitCode {
    let mut anchor_file: Option<&str> = None;
    let mut kit_file: Option<String> = None;
    let mut monitor_file: Option<String> = None;
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--kit" => match it.next() {
                Some(v) => kit_file = Some(v.clone()),
                None => {
                    eprintln!("error: --kit requires a value");
                    return ExitCode::from(2);
                }
            },
            "--monitor" => match it.next() {
                Some(v) => monitor_file = Some(v.clone()),
                None => {
                    eprintln!("error: --monitor requires a value");
                    return ExitCode::from(2);
                }
            },
            other if anchor_file.is_none() && !other.starts_with("--") => {
                anchor_file = Some(other);
            }
            other => {
                eprintln!(
                    "error: unexpected argument `{}` for verify-anchor",
                    sanitize_reserved_token(other)
                );
                return ExitCode::from(2);
            }
        }
    }
    let (Some(anchor_file), Some(kit_file)) = (anchor_file, kit_file) else {
        eprintln!("error: verify-anchor requires <anchor.json> and --kit <kit.json>");
        return ExitCode::from(2);
    };

    // The auditor's OWN kit first: a read/parse failure is a CONFIG error
    // (exit 2), distinct from a package verification failure (exit 1).
    let kit_raw = match read_capped_utf8(Path::new(kit_file.as_str())) {
        Ok(raw) => raw,
        Err(detail) => {
            eprintln!(
                "error: cannot read kit {}: {}",
                sanitize_reserved_token(&kit_file),
                sanitize_reserved_token(&detail)
            );
            return ExitCode::from(2);
        }
    };
    let kit = match parse_auditor_kit(&kit_raw) {
        Ok(kit) => kit,
        Err(e) => {
            eprintln!(
                "error: invalid auditor kit: {}",
                sanitize_reserved_token(&format!("{e:?}"))
            );
            return ExitCode::from(2);
        }
    };

    // The UNTRUSTED package: a read/parse failure means the material under
    // audit could not be verified (exit 1). The filename comes from argv —
    // sanitize it like every other non-fixed string.
    let anchor_raw = match read_capped_utf8(Path::new(anchor_file)) {
        Ok(raw) => raw,
        Err(detail) => {
            eprintln!(
                "ERROR: cannot read {}: {}",
                sanitize_reserved_token(anchor_file),
                sanitize_reserved_token(&detail)
            );
            return ExitCode::from(1);
        }
    };
    let pkg = match parse_anchor_package(&anchor_raw) {
        Ok(pkg) => pkg,
        Err(e) => {
            eprintln!(
                "ERROR: malformed anchor package: {}",
                sanitize_reserved_token(&format!("{e:?}"))
            );
            return ExitCode::from(1);
        }
    };

    // The monitor bundle is the AUDITOR's OWN trusted artifact (like `--kit`):
    // any read/parse failure is a CONFIG error (exit 2), NOT a package failure
    // (exit 1). Keep the parsed value alive so `monitor` can borrow from it.
    let parsed_monitor = match monitor_file {
        None => None,
        Some(mf) => {
            let raw = match read_capped_utf8(Path::new(mf.as_str())) {
                Ok(raw) => raw,
                Err(detail) => {
                    eprintln!(
                        "error: cannot read monitor bundle {}: {}",
                        sanitize_reserved_token(&mf),
                        sanitize_reserved_token(&detail)
                    );
                    return ExitCode::from(2);
                }
            };
            match seetrex_verifier::anchor_package::parse_monitor_audit(&raw) {
                Ok(p) => Some(p),
                Err(e) => {
                    eprintln!(
                        "error: invalid monitor bundle: {}",
                        sanitize_reserved_token(&format!("{e:?}"))
                    );
                    return ExitCode::from(2);
                }
            }
        }
    };
    let monitor = parsed_monitor.as_ref().map(|p| MonitorAudit {
        enumeration: &p.enumeration,
        observations: &p.observations,
    });

    // A supplied `--monitor` makes COMPLETITUD a REAL verdict (the enumeration
    // completeness is the trusted input); absent, COMPLETITUD stays INCONCLUSIVE
    // offline (the API accepts a monitor).
    let report = verify_anchored_package(
        &kit.tenant_slug,
        kit.genesis_key_hash,
        &kit.policy,
        &pkg,
        monitor.as_ref(),
    );
    match report.consistencia {
        Verdict::Verified => {
            let (keys, anomalies) = match &report.identity {
                Some(set) => (set.keys.len(), set.anomalous_rotations.len()),
                None => (0, 0),
            };
            // FIXED banner — no reserved token by construction.
            println!("Anchor package CONSISTENCIA CONFIRMED OFFLINE");
            // Debug-print the (trusted) tenant so a stray control byte in the
            // auditor's OWN kit cannot rewrite the line.
            println!("  tenant:                  {:?}", kit.tenant_slug);
            // Show the SUBSTANCE checked: a CONFIRMED over ZERO anchored leaves
            // is VACUOUS (nothing about anchoring was proven) and must never
            // read like a substantive pass — surface the counts explicitly.
            println!("  anchored leaves checked: {}", pkg.anchored_leaves.len());
            println!("  rotations checked:       {}", pkg.rotations.len());
            println!("  identity keys:           {keys} (genesis + accepted rotations)");
            if anomalies > 0 {
                // A published rotation nobody accounts for is where tampering
                // hides — surfaced, not hidden (still non-fatal offline; its
                // FAILED mapping is enumeration-dependent).
                println!(
                    "  anomalous rotations:     {anomalies} surfaced (unaccounted — investigate)"
                );
            }
            // COMPLETITUD is a REAL verdict when a monitor was supplied; render
            // the actual variant (never the reserved token `VERIFIED`: a
            // confirmed COMPLETITUD prints "CONFIRMED OFFLINE").
            println!(
                "  COMPLETITUD:             {}",
                completitud_display(&report.completitud)
            );
            // Only COMPLETITUD drives the exit code on THIS arm: a monitor that
            // caught an omission / unauthorized on-chain leaf downgrades the
            // vacuous pass to exit 1. Inconclusive (the default offline
            // path, no monitor) lives noisily in output, not the exit code.
            let completitud_exit = match &report.completitud {
                Verdict::Failed { .. } => ExitCode::from(1),
                _ => ExitCode::SUCCESS,
            };
            println!();
            println!("{}", seetrex_verifier::scope::SCOPE_ANCHOR);
            completitud_exit
        }
        Verdict::Failed { reason } => {
            eprintln!(
                "ERROR: anchor package CONSISTENCIA FAILED: {}",
                sanitize_reserved_token(&reason)
            );
            // COMPLETITUD is a REAL verdict when a monitor was supplied: the
            // library computes step 4 even when CONSISTENCIA fails at the step-3
            // row-JOIN, so this can be Failed/Verified here — show the TRUE
            // verdict, never a hardcoded "INCONCLUSIVE" label. CONSISTENCIA
            // still drives the exit code (1).
            eprintln!("COMPLETITUD: {}", completitud_display(&report.completitud));
            eprintln!("{}", seetrex_verifier::scope::SCOPE_ANCHOR);
            ExitCode::from(1)
        }
        // Defensive: CONSISTENCIA is Verified or Failed by construction. An
        // Inconclusive here is a contract change — treat as failure, loudly.
        other => {
            eprintln!(
                "ERROR: unexpected CONSISTENCIA verdict: {}",
                sanitize_reserved_token(&format!("{other:?}"))
            );
            // Print COMPLETITUD here too, so the two verdicts never collapse on
            // ANY terminal path (symmetry with the Verified/Failed arms). Show
            // its TRUE verdict — with a monitor it may be Failed/Verified.
            eprintln!("COMPLETITUD: {}", completitud_display(&report.completitud));
            eprintln!("{}", seetrex_verifier::scope::SCOPE_ANCHOR);
            ExitCode::from(1)
        }
    }
}

/// The honest one-line COMPLETITUD render for the CLI, derived from the REAL
/// verdict `verify_anchored_package` returned. With `--monitor` supplied the
/// library computes COMPLETITUD (step 4) even when CONSISTENCIA fails at the
/// row-JOIN (step 3), so this variant can be Failed/Verified on the failing
/// arms too — every arm must show the TRUE verdict, never a hardcoded label.
/// Never emits the reserved token: the Verified case prints "CONFIRMED
/// OFFLINE" (not `VERIFIED`), and every variable reason is routed through
/// the case-insensitive `sanitize_reserved_token` so a debug substring in a
/// reason can never leak it.
fn completitud_display(v: &Verdict) -> String {
    match v {
        Verdict::Verified => "CONFIRMED OFFLINE (monitor supplied; \
             enumeration completeness = trusted input)"
            .to_string(),
        Verdict::Inconclusive { reason } => {
            format!("INCONCLUSIVE — {}", sanitize_reserved_token(reason))
        }
        Verdict::Failed { reason } => format!("FAILED — {}", sanitize_reserved_token(reason)),
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
