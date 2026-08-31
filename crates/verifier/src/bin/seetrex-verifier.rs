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
//!   CONFIRMED / INCONCLUSIVE / FAILED). `--chain <chain.json>` adds the
//!   producer's CURRENT published chain export, which DECIDES the
//!   truncation rule: without it, a monitor head beyond the package's own
//!   rows is UNDECIDABLE (a truncating producer and a package that merely
//!   LAGS the log look identical) and COMPLETITUD says so INCONCLUSIVELY;
//!   with it, beyond the CHAIN is a truncation FAILED. Unlike
//!   `verify-chain` it does NOT emit the reserved `VERIFIED` token: this
//!   surface is not §9.6-blessed and a confirmed CONSISTENCIA with
//!   INCONCLUSIVE COMPLETITUD is not a blanket strong pass. CONSISTENCIA
//!   confirmed: exit 0. Failed / bad package: exit 1. Bad kit: exit 2.
//! - `emit-sbom --kind <cargo|composer|npm> --lockfile <path>
//!   [--manifest <composer.json>] --subject <purl> --out <path>` -- writes
//!   the canonical SBOM projection of a lockfile (spec:
//!   `SPEC_SBOM_CANONICAL_V1.md`) and prints its SHA-256 on stdout. It
//!   VERIFIES NOTHING, so it never exits 1: the only failures it can have
//!   are the auditor's own (unreadable lockfile, malformed subject, a
//!   subject whose purl type is not the one --kind names, unknown option),
//!   which are exit 2.
//! - `verify-sbom --kind <...> --lockfile <path> [--manifest <composer.json>]
//!   --subject <purl> --sbom <path> [--third-party] [--dep-v0 <elf>]` --
//!   re-derives the projection from the AUDITOR's lockfile and confronts the
//!   untrusted document with it (spec section 7). The subject is NEVER read
//!   from the document. Exit 0 only on BYTE IDENTITY; a semantic difference,
//!   an unreadable document, and empty difference sets over differing bytes
//!   are all exit 1. `--third-party` is the LENIENT path for a document
//!   another tool produced: it adapts the document by a fixed, reported list
//!   of reductions, reports the differences, and NEVER exits 0. `--dep-v0`
//!   adds the binary leg: a pair the projection does not account for and a
//!   binary with no section at all are exit 1, while an image that is not
//!   an ELF container is the AUDITOR's own error, exit 2. Like
//!   `verify-package` this surface is not one of the section 9.6 strong
//!   ones: the reserved token `VERIFIED` is sanitized out of every line it
//!   prints.
//!
//! Usage errors (unknown command, missing operand, malformed auditor
//! kit) exit 2 — distinct from the spec-bound verification codes 0/1/4.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use seetrex_format::hashing::canonicalize;
use serde_json::{Map, Value};

use seetrex_verifier::anchor::Verdict;
use seetrex_verifier::anchor_package::{
    parse_anchor_package, parse_auditor_kit, verify_anchored_package_with_chain, MonitorAudit,
};
use seetrex_verifier::anchor_completitud::TruncationReference;
use seetrex_verifier::chain_export::parse_and_verify_package;
use seetrex_verifier::cli_render::{
    cap_refusal, chain_export_text, render_chain_read_failure, render_verify_chain,
    render_verify_package, CommandOutput, CHAIN_EXPORT_MAX_BYTES,
};
use seetrex_verifier::package::{
    sanitize_reserved_token as redact, verify_package, RESERVED_TOKEN_LEGEND, RESERVED_TOKEN_MASK,
};
use seetrex_verifier::sbom::compare::{CompareError, Verdict as SbomVerdict};
use seetrex_verifier::sbom::depv0::DepV0Error;
use seetrex_verifier::sbom::{
    cargo as sbom_cargo, compare, composer as sbom_composer, depv0, npm as sbom_npm, LockfileKind,
    Projection, SbomError, SubjectPurl,
};

/// Read cap for the chain export file (DoS guard), as the library spells
/// it: the offline browser page applies the SAME number to the bytes it
/// read out of the dropped file, so the two surfaces refuse the same export.
const CHAIN_FILE_MAX_BYTES: u64 = CHAIN_EXPORT_MAX_BYTES;

const HELP: &str = "\
seetrex-verifier — offline verification of Seetrex Compliance verdict
packages and public chain exports (spec: SPEC_VERDICT_PACKAGE_V1.md).

USAGE:
    seetrex-verifier verify-package <dir> [--expected-verdict-hash <hex>]
    seetrex-verifier verify-chain <file.json>
    seetrex-verifier verify-anchor <anchor.json> --kit <kit.json> [--monitor <bundle.json>]
                                  [--chain <chain.json>]
    seetrex-verifier emit-sbom --kind <cargo|composer|npm> --lockfile <path>
                               [--manifest <composer.json>] --subject <purl>
                               --out <path>
    seetrex-verifier verify-sbom --kind <cargo|composer|npm> --lockfile <path>
                                 [--manifest <composer.json>] --subject <purl>
                                 --sbom <path> [--third-party] [--dep-v0 <elf>]
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
                      Bad or missing kit: exit 2. --chain <chain.json>
                      is the producer's CURRENT published chain export,
                      the input that DECIDES COMPLETITUD's truncation rule:
                      a package is a SNAPSHOT and legitimately LAGS the log,
                      so without the export a monitor head beyond the
                      package's rows is UNDECIDABLE (never a FAILED) and
                      COMPLETITUD reports INCONCLUSIVE naming this flag;
                      with it, a head beyond the CHAIN's own length is a
                      real truncation and FAILS. An unreadable or
                      non-verifying export is vendor material, exit 1.
                      Exit 0 confirms
                      NON-CONTRADICTION only — surfaced anomalous
                      rotations and completeness (omitted leaves) are
                      enumeration-dependent; do not gate
                      automation on exit 0 alone.
    emit-sbom         Write the canonical SBOM projection of a lockfile
                      (spec SPEC_SBOM_CANONICAL_V1.md) to --out and print
                      its SHA-256 on stdout, and nothing else on stdout, so
                      `sha256sum <out>` reproduces the printed digest. The
                      file holds exactly the canonical bytes: one line, no
                      trailing newline. --manifest is required by, and only
                      accepted for, --kind composer. The --subject purl
                      type MUST be the one --kind names (spec section 5.5).
                      This subcommand VERIFIES NOTHING and therefore never
                      exits 1: its only failure class is the auditor's own,
                      exit 2.
    verify-sbom       Re-derive the projection from YOUR lockfile and
                      confront --sbom with it (spec section 7). --subject is
                      mandatory and is never read from the document: a
                      forged metadata.component presented with a legitimate
                      --subject FAILS. Exit 0 only when the document IS the
                      projection byte for byte; a semantic difference, an
                      unreadable document, and differing bytes with empty
                      difference sets are all exit 1. --third-party is the
                      LENIENT path for a document another tool produced: it
                      applies a fixed, REPORTED list of reductions, prints
                      the difference sets, and NEVER exits 0 -- it cannot
                      claim a match, because the bytes it compares are the
                      adapted ones. --dep-v0 <elf> additionally confronts the
                      projection with the `.dep-v0` section the binary
                      carries about itself (--kind cargo only): a pair the
                      projection does not account for, and a binary with no
                      section at all, are both exit 1; an image that is not
                      an ELF container at all is the auditor's own error,
                      exit 2. The fixed match banner is printed only after
                      every requested optional check has ALSO passed.

Exit code 2 = usage error (or a malformed/missing auditor kit, or an
unreadable/malformed lockfile, manifest or subject -- the AUDITOR's own
inputs, kept out of the verification codes so a script filtering for
\"the vendor's artifact failed\" is not polluted by a local typo).";

/// Whether the reserved-token MASK reached this process's output.
///
/// Set by [`sanitize_reserved_token`], read once by [`main`], which prints
/// the legend afterwards so the sentence explaining the mask appears at
/// most once and only when there is a mask to explain.
static RESERVED_TOKEN_MASK_PRINTED: AtomicBool = AtomicBool::new(false);

/// The binary's output boundary: redact the reserved token, and remember
/// whether the mask is now on screen.
///
/// The condition is "the sanitized text CARRIES the mask", not "this call
/// replaced something": the comparison module sanitizes at its own
/// boundary with the SAME mask, so a report that arrives here already
/// redacted must still earn the legend.
fn sanitize_reserved_token(text: &str) -> String {
    let sanitized = redact(text);
    if sanitized.contains(RESERVED_TOKEN_MASK) {
        RESERVED_TOKEN_MASK_PRINTED.store(true, Ordering::Relaxed);
    }
    sanitized
}

fn main() -> ExitCode {
    let code = run();
    if RESERVED_TOKEN_MASK_PRINTED.load(Ordering::Relaxed) {
        eprintln!("{RESERVED_TOKEN_LEGEND}");
    }
    code
}

fn run() -> ExitCode {
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
        Some("emit-sbom") => cmd_emit_sbom(&args[1..]),
        Some("verify-sbom") => cmd_verify_sbom(&args[1..]),
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

    emit(render_verify_package(verify_package(
        Path::new(package_dir),
        expected.as_deref(),
    )))
}

/// The binary's stream boundary for the two subcommands the offline page
/// also answers.
///
/// The lines are composed by `seetrex_verifier::cli_render` -- already
/// sanitized, already ordered -- so this function only chooses the STREAM
/// and remembers whether the mask reached the screen. The legend condition
/// is the same one [`sanitize_reserved_token`] applies elsewhere: the text
/// CARRIES the mask, not "this process replaced something".
fn emit(out: CommandOutput) -> ExitCode {
    if out.mask_used {
        RESERVED_TOKEN_MASK_PRINTED.store(true, Ordering::Relaxed);
    }
    for line in &out.stdout {
        println!("{line}");
    }
    for line in &out.stderr {
        eprintln!("{line}");
    }
    ExitCode::from(out.exit)
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
            // scripted pipelines; sanitize it like every other non-fixed
            // string. The line is composed by `cli_render`, which is what
            // makes the browser page able to say it too.
            return emit(render_chain_read_failure(file, &detail));
        }
    };

    emit(render_verify_chain(parse_and_verify_package(&raw)))
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
/// `--chain <chain.json>` is OPTIONAL and supplies the producer's CURRENT published
/// chain export. It changes exactly one thing: COMPLETITUD's truncation rule becomes
/// DECIDABLE. An anchor package is a SNAPSHOT of the chain emitted on the producer's
/// packaging cadence while heads reach the log on a faster one, so the package
/// legitimately LAGS the log; judged against the package alone, an enumerated head
/// beyond its rows is indistinguishable from a producer who DELETED those rows.
/// Without the flag that case is a NAMED INCONCLUSIVE that points at this flag (exit
/// stays 0 - INCONCLUSIVE never drives the exit code); with it, a head beyond the
/// EXPORT's own length is a real truncation and FAILS (exit 1). Absent, every
/// invocation behaves exactly as before.
///
/// Exit codes: CONSISTENCIA confirmed → 0; CONSISTENCIA failed / unreadable /
/// malformed PACKAGE → 1; usage error OR a malformed/unreadable KIT → 2. A bad
/// kit is the AUDITOR's own config error, kept distinct from exit 1 so a script
/// gating on "the vendor's package failed" is not polluted by a typo in the
/// auditor's kit file. The `--chain` export is VENDOR material like the package
/// itself (the auditor only downloads it), so an unreadable one, or one whose own
/// SHA-256 links do not verify, is exit 1 with the package's `ERROR:` prefix - NOT
/// the kit's exit 2.
fn cmd_verify_anchor(rest: &[String]) -> ExitCode {
    let mut anchor_file: Option<&str> = None;
    let mut kit_file: Option<String> = None;
    let mut monitor_file: Option<String> = None;
    let mut chain_file: Option<String> = None;
    let mut it = rest.iter();
    // Value flags go through `take_flag_value`, which already refuses a REPEATED
    // flag (exit 2) rather than keeping the last value. That mattered enough to
    // stop hand-rolling it here: last-wins let ARGUMENT ORDER decide a verdict -
    // measured, `--chain <40 rows> --chain <11 rows>` exited 1 while the reverse
    // order exited 0 on the same artifacts.
    while let Some(arg) = it.next() {
        let taken = match arg.as_str() {
            "--kit" => take_flag_value(&mut it, "--kit", &mut kit_file),
            "--monitor" => take_flag_value(&mut it, "--monitor", &mut monitor_file),
            "--chain" => take_flag_value(&mut it, "--chain", &mut chain_file),
            other if anchor_file.is_none() && !other.starts_with("--") => {
                anchor_file = Some(other);
                Ok(())
            }
            other => {
                eprintln!(
                    "error: unexpected argument `{}` for verify-anchor",
                    sanitize_reserved_token(other)
                );
                return ExitCode::from(2);
            }
        };
        if let Err(code) = taken {
            return code;
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

    // The published chain export: VENDOR material the auditor merely downloads, so
    // its failures are exit 1 like the package's, not exit 2 like the kit's. It goes
    // through the SAME offline gate `verify-chain` applies (every SHA-256 link
    // recomputed) before any verdict is allowed to rest on its length: an export
    // whose own links do not verify must never be able to raise the row count a
    // monitor head is explained by. Keep the rows alive for the borrow below.
    let chain_rows = match chain_file {
        None => None,
        Some(cf) => {
            let raw = match read_capped_utf8(Path::new(cf.as_str())) {
                Ok(raw) => raw,
                Err(detail) => {
                    eprintln!(
                        "ERROR: cannot read chain export {}: {}",
                        sanitize_reserved_token(&cf),
                        sanitize_reserved_token(&detail)
                    );
                    return ExitCode::from(1);
                }
            };
            match seetrex_verifier::chain_export::parse_and_verify_package_rows(&raw) {
                Ok((rows, _head)) => Some(rows),
                Err(e) => {
                    eprintln!(
                        "ERROR: chain export does not verify offline: {}",
                        sanitize_reserved_token(&format!("{e:?}"))
                    );
                    return ExitCode::from(1);
                }
            }
        }
    };

    // A supplied `--monitor` makes COMPLETITUD a REAL verdict (the enumeration
    // completeness is the trusted input); absent, COMPLETITUD stays INCONCLUSIVE
    // offline (the API accepts a monitor).
    // An export was read and its links recomputed - NOT "verified": whether it agrees
    // with the package is checked by the rule, which only runs with a monitor. So
    // without one it can decide nothing. Surfaced rather than silently dropped.
    let chain_supplied_but_unused = chain_rows.is_some() && monitor.is_none();

    let report = verify_anchored_package_with_chain(
        &kit.tenant_slug,
        kit.genesis_key_hash,
        &kit.policy,
        &pkg,
        monitor.as_ref(),
        chain_rows.as_deref(),
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
            // WHICH row count COMPLETITUD's truncation rule judged against. Silence
            // here would leave "INCONCLUSIVE" and "FAILED" reading the same whether
            // the deciding input was present or absent.
            println!(
                "  truncation reference:    {}",
                truncation_reference_line(
                    report.truncation_reference.as_ref(),
                    chain_supplied_but_unused,
                )
            );
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
            eprintln!(
                "truncation reference: {}",
                truncation_reference_line(
                    report.truncation_reference.as_ref(),
                    chain_supplied_but_unused,
                )
            );
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
            eprintln!(
                "truncation reference: {}",
                truncation_reference_line(
                    report.truncation_reference.as_ref(),
                    chain_supplied_but_unused,
                )
            );
            eprintln!("{}", seetrex_verifier::scope::SCOPE_ANCHOR);
            ExitCode::from(1)
        }
    }
}

/// The one line that says what COMPLETITUD's truncation rule (`G-v6-2`) judged
/// against, printed on EVERY terminal arm.
///
/// RENDERS the library's own [`TruncationReference`]; it computes nothing. The
/// previous version recomputed `max(supplied_export, package)` here, which is a
/// different number whenever the library DECLINED the export - measured on a live
/// run: a 41-row export diverging from the package at row 3 was declined, the rule
/// judged against N=12, and this line said `reference N=41`. The number is not
/// derivable from the inputs a caller holds, so the caller must not try.
fn truncation_reference_line(
    reference: Option<&TruncationReference>,
    chain_supplied_but_unused: bool,
) -> String {
    let Some(r) = reference else {
        // NB the distinction: COMPLETITUD may well have produced a verdict - it can
        // FAIL on `C_audit` authentication - while never reaching the TRUNCATION
        // rule. Saying "COMPLETITUD did not run" beside a printed COMPLETITUD FAILED
        // is a contradiction the auditor has to resolve; say which rule was skipped.
        let mut line = "not evaluated (the truncation rule was not reached)".to_string();
        if chain_supplied_but_unused {
            // Reading, verifying and then silently discarding an input the auditor
            // deliberately supplied is the same class of silence this whole change
            // exists to remove.
            // "verified" would overstate it: only the offline link recomputation ran.
            // Agreement with the package is checked when the RULE runs, so the same
            // export may still be DECLINED once a monitor is supplied.
            line.push_str("; --chain was supplied and its links recomputed, but it \
                           DECIDES NOTHING without --monitor (whether it AGREES with \
                           the package is only checked when the rule runs)");
        }
        return line;
    };
    let package = r.package_rows;
    match (r.supplied_export_rows, &r.declined) {
        (None, _) => format!(
            "package rows only, {package} rows (no --chain; heads past N are UNDECIDABLE)"
        ),
        (Some(n), None) => format!(
            "published chain export, {n} rows (package {package}; reference N={})",
            r.reference_rows
        ),
        // A DECLINED export is NOT evidence: say so, and show the reference the rule
        // really used, which is the package alone.
        (Some(n), Some(_)) => format!(
            "published chain export DECLINED ({n} rows, not used); package rows only, \
             {package} rows; reference N={}",
            r.reference_rows
        ),
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

// ---------------------------------------------------------------------
// SBOM: emit-sbom / verify-sbom (spec: SPEC_SBOM_CANONICAL_V1.md)
// ---------------------------------------------------------------------

/// Read cap for a lockfile, a root manifest or an SBOM document.
const SBOM_INPUT_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Read cap for the ELF image of `--dep-v0`. Larger than the text cap
/// because an unstripped binary legitimately reaches hundreds of
/// megabytes, and still bounded so a hostile path cannot exhaust the
/// auditor's memory.
const BINARY_INPUT_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// The three CONTAINER keys whose absence and whose emptiness say the
/// same thing about a document, and which `--third-party` may therefore
/// supply when a foreign document omits them.
///
/// The scalar header keys (`bomFormat`, `specVersion`, `version`) are
/// deliberately NOT here: supplying one of those would invent a value the
/// document never stated, which is a forgery rather than an adaptation.
const THIRD_PARTY_FILLABLE_KEYS: [&str; 3] = ["components", "dependencies", "properties"];

/// `--kind` to the ecosystem it names.
fn parse_lockfile_kind(value: &str) -> Option<LockfileKind> {
    match value {
        "cargo" => Some(LockfileKind::Cargo),
        "composer" => Some(LockfileKind::Composer),
        "npm" => Some(LockfileKind::Npm),
        _ => None,
    }
}

/// Pull the value of `flag` out of `it`, or fail as a usage error.
///
/// A REPEATED flag is a usage error too: silently keeping the last
/// `--subject` is how an auditor ends up verifying against a subject they
/// did not mean to supply.
fn take_flag_value(
    it: &mut std::slice::Iter<'_, String>,
    flag: &str,
    slot: &mut Option<String>,
) -> Result<(), ExitCode> {
    if slot.is_some() {
        eprintln!("error: {flag} was supplied twice");
        return Err(ExitCode::from(2));
    }
    match it.next() {
        Some(value) => {
            *slot = Some(value.clone());
            Ok(())
        }
        None => {
            eprintln!("error: {flag} requires a value");
            Err(ExitCode::from(2))
        }
    }
}

/// `--kind` resolved, or a usage error already reported.
fn resolve_kind(raw: &str) -> Result<LockfileKind, ExitCode> {
    parse_lockfile_kind(raw).ok_or_else(|| {
        eprintln!(
            "error: unknown --kind `{}`; expected one of cargo, composer, npm",
            sanitize_reserved_token(raw)
        );
        ExitCode::from(2)
    })
}

/// `--manifest` is meaningful for composer and for nothing else.
///
/// Accepting it silently elsewhere would let an auditor believe a
/// `composer.json` was consulted for a cargo or npm projection, which it
/// never is.
fn check_manifest_applies(kind: LockfileKind, manifest: Option<&str>) -> Result<(), ExitCode> {
    if manifest.is_some() && kind != LockfileKind::Composer {
        eprintln!(
            "error: --manifest is only accepted with --kind composer (only the composer \
             projection reads a root manifest, for its top-level set)"
        );
        return Err(ExitCode::from(2));
    }
    Ok(())
}

/// The purl type a subject MUST carry for each lockfile kind.
fn subject_purl_type(kind: LockfileKind) -> &'static str {
    match kind {
        LockfileKind::Cargo => "cargo",
        LockfileKind::Composer => "composer",
        LockfileKind::Npm => "npm",
    }
}

/// `--subject`'s purl type is the one `--kind` names, or the run stops.
///
/// Spec section 5.5 states it as a MUST and nothing downstream enforced
/// it: an npm subject over a cargo lockfile emitted a perfectly canonical
/// document whose `metadata.component` claimed an ecosystem its own
/// components do not belong to, and exited 0. That is the auditor's own
/// typo, so it is exit 2 on BOTH subcommands -- on `verify-sbom` too,
/// where it used to surface as exit 1, the code reserved for "the vendor's
/// artifact failed".
///
/// A subject that is not a purl at all is left to `SubjectPurl::parse`,
/// which names the malformation better than a type comparison could.
fn check_subject_type_matches_kind(kind: LockfileKind, subject: &str) -> Result<(), ExitCode> {
    let expected = subject_purl_type(kind);
    let Some(declared) = subject
        .strip_prefix("pkg:")
        .and_then(|body| body.split('/').next())
        .filter(|declared| !declared.is_empty())
    else {
        return Ok(());
    };
    if declared != expected {
        eprintln!(
            "error: --subject declares the purl type `{}`, but --kind is `{expected}`; the \
             subject purl type MUST match the lockfile kind (spec section 5.5). Expected \
             a `pkg:{expected}/...` subject",
            sanitize_reserved_token(declared)
        );
        return Err(ExitCode::from(2));
    }
    Ok(())
}

/// Re-derive the projection from the AUDITOR's own inputs.
///
/// EVERY failure here is on the auditor's side of the check -- an
/// unreadable lockfile, a manifest that does not go with it, a subject
/// that is not a purl -- so both callers map all of them to exit 2. That
/// asymmetry is the point of the exit-code table (spec section 7.6): a
/// script filtering for "the vendor's artifact failed" must not be
/// contaminated by the auditor's own typo.
///
/// # Errors
///
/// A rendered message naming which of the auditor's inputs was unusable.
fn build_projection(
    kind: LockfileKind,
    lockfile: &str,
    manifest: Option<&str>,
    subject: &str,
) -> Result<Projection, ProjectionFailure> {
    let subject = SubjectPurl::parse(subject).map_err(ProjectionFailure::from_sbom)?;
    let lock_text =
        read_capped_utf8_at(Path::new(lockfile), SBOM_INPUT_MAX_BYTES).map_err(|detail| {
            ProjectionFailure::unclassified(format!("cannot read lockfile {lockfile}: {detail}"))
        })?;
    let manifest_text = match manifest {
        None => None,
        Some(path) => Some(
            read_capped_utf8_at(Path::new(path), SBOM_INPUT_MAX_BYTES).map_err(|detail| {
                ProjectionFailure::unclassified(format!("cannot read manifest {path}: {detail}"))
            })?,
        ),
    };
    match kind {
        LockfileKind::Cargo => sbom_cargo::project_lockfile(&lock_text, subject),
        LockfileKind::Npm => sbom_npm::project_lockfile(&lock_text, subject),
        LockfileKind::Composer => {
            sbom_composer::project_lockfile(&lock_text, manifest_text.as_deref(), subject)
        }
    }
    .map_err(ProjectionFailure::from_sbom)
}

/// Why a projection could not be built, with the STABLE class token of
/// specification 7.6 when the failure has one.
///
/// The projection leg used to print prose alone, so a reader scripting
/// against this surface had to match a sentence -- while the two legs
/// beside it (`compare_error_class`, `dep_v0_error_class`) each printed a
/// machine-matchable token. Specification 7.6 names these classes
/// explicitly and requires an implementation to distinguish them BY NAME.
struct ProjectionFailure {
    /// The kebab-case class, or `None` for a failure that is not one of
    /// 7.6's classes at all -- an unreadable input file is the auditor's
    /// own I/O, and inventing a class token for it would put a
    /// specification name on something the specification does not name.
    class: Option<&'static str>,
    /// The message, already rendered.
    detail: String,
}

impl ProjectionFailure {
    fn from_sbom(error: SbomError) -> Self {
        Self {
            class: Some(sbom_error_class(&error)),
            detail: error.to_string(),
        }
    }

    fn unclassified(detail: String) -> Self {
        Self {
            class: None,
            detail,
        }
    }

    /// Print the class line (when there is one) and the message, through
    /// the binary's single output boundary.
    fn report(&self) {
        if let Some(class) = self.class {
            eprintln!("error class: {class}");
        }
        eprintln!("error: {}", sanitize_reserved_token(&self.detail));
    }
}

/// The stable class token of a projection failure. Specification 7.6 names
/// `UnsupportedLockShape`, `MissingVersion`, `AmbiguousDependencyRef`,
/// `PurlCollision`, `MalformedManifest` and `UnsupportedBinaryFormat`
/// among the classes an implementation MUST distinguish by name; the
/// remaining variants of [`SbomError`] get one on the same pattern rather
/// than falling back to prose.
fn sbom_error_class(error: &SbomError) -> &'static str {
    match error {
        SbomError::UnsupportedLockShape { .. } => "unsupported-lock-shape",
        SbomError::MissingVersion { .. } => "missing-version",
        SbomError::PurlCollision { .. } => "purl-collision",
        SbomError::MalformedComponentPurl { .. } => "malformed-component-purl",
        SbomError::MalformedManifest { .. } => "malformed-manifest",
        SbomError::MalformedSubject { .. } => "malformed-subject",
        SbomError::AmbiguousDependencyRef { .. } => "ambiguous-dependency-ref",
        SbomError::UnresolvedDependencyRef { .. } => "unresolved-dependency-ref",
        SbomError::Io { .. } => "io",
        SbomError::Canonicalization(_) => "canonicalization",
    }
}

/// `emit-sbom --kind <k> --lockfile <path> [--manifest <path>] --subject
/// <purl> --out <path>`.
///
/// The producer half of the pair. It verifies NOTHING -- it reads a
/// lockfile the auditor already holds and writes the projection of it --
/// so exit 1 is not in its vocabulary at all: either it wrote the file
/// (exit 0) or one of the auditor's own inputs was unusable (exit 2).
///
/// stdout carries the digest and NOTHING else, so the command in a shell
/// substitution IS the hash and `sha256sum <out>` reproduces it: the file
/// holds exactly the canonical bytes, one line, no trailing newline.
fn cmd_emit_sbom(rest: &[String]) -> ExitCode {
    let mut kind: Option<String> = None;
    let mut lockfile: Option<String> = None;
    let mut manifest: Option<String> = None;
    let mut subject: Option<String> = None;
    let mut out: Option<String> = None;
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        let taken = match arg.as_str() {
            "--kind" => take_flag_value(&mut it, "--kind", &mut kind),
            "--lockfile" => take_flag_value(&mut it, "--lockfile", &mut lockfile),
            "--manifest" => take_flag_value(&mut it, "--manifest", &mut manifest),
            "--subject" => take_flag_value(&mut it, "--subject", &mut subject),
            "--out" => take_flag_value(&mut it, "--out", &mut out),
            other => {
                eprintln!(
                    "error: unexpected argument `{}` for emit-sbom",
                    sanitize_reserved_token(other)
                );
                Err(ExitCode::from(2))
            }
        };
        if let Err(code) = taken {
            return code;
        }
    }

    let (Some(kind), Some(lockfile), Some(subject), Some(out)) = (kind, lockfile, subject, out)
    else {
        eprintln!("error: emit-sbom requires --kind, --lockfile, --subject and --out");
        return ExitCode::from(2);
    };
    let kind = match resolve_kind(&kind) {
        Ok(kind) => kind,
        Err(code) => return code,
    };
    if let Err(code) = check_manifest_applies(kind, manifest.as_deref()) {
        return code;
    }
    if let Err(code) = check_subject_type_matches_kind(kind, &subject) {
        return code;
    }

    let projection = match build_projection(kind, &lockfile, manifest.as_deref(), &subject) {
        Ok(projection) => projection,
        Err(failure) => {
            failure.report();
            return ExitCode::from(2);
        }
    };
    let bytes = match projection.to_canonical_bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("error: {}", sanitize_reserved_token(&error.to_string()));
            return ExitCode::from(2);
        }
    };
    let digest = match projection.canonical_sha256() {
        Ok(digest) => digest,
        Err(error) => {
            eprintln!("error: {}", sanitize_reserved_token(&error.to_string()));
            return ExitCode::from(2);
        }
    };
    if let Err(error) = std::fs::write(Path::new(out.as_str()), bytes.as_bytes()) {
        eprintln!(
            "error: cannot write {}: {}",
            sanitize_reserved_token(&out),
            sanitize_reserved_token(&error.to_string())
        );
        return ExitCode::from(2);
    }
    println!("{digest}");
    // The human line goes to stderr so stdout stays exactly one digest.
    eprintln!(
        "wrote {} canonical bytes to {}",
        bytes.len(),
        sanitize_reserved_token(&out)
    );
    ExitCode::SUCCESS
}

/// `verify-sbom --kind <k> --lockfile <path> [--manifest <path>] --subject
/// <purl> --sbom <path> [--third-party] [--dep-v0 <elf>]`.
///
/// The subject is an INPUT and is never read back out of the document: a
/// document declaring what it is supposed to be is evidence of nothing,
/// exactly as an anchor package must not name its own witnesses. A forged
/// `metadata.component` presented beside a legitimate `--subject` lands in
/// the subject-mismatch report rather than being adopted.
fn cmd_verify_sbom(rest: &[String]) -> ExitCode {
    let mut kind: Option<String> = None;
    let mut lockfile: Option<String> = None;
    let mut manifest: Option<String> = None;
    let mut subject: Option<String> = None;
    let mut sbom: Option<String> = None;
    let mut dep_v0: Option<String> = None;
    let mut third_party = false;
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        let taken = match arg.as_str() {
            "--kind" => take_flag_value(&mut it, "--kind", &mut kind),
            "--lockfile" => take_flag_value(&mut it, "--lockfile", &mut lockfile),
            "--manifest" => take_flag_value(&mut it, "--manifest", &mut manifest),
            "--subject" => take_flag_value(&mut it, "--subject", &mut subject),
            "--sbom" => take_flag_value(&mut it, "--sbom", &mut sbom),
            "--dep-v0" => take_flag_value(&mut it, "--dep-v0", &mut dep_v0),
            "--third-party" => {
                third_party = true;
                Ok(())
            }
            other => {
                eprintln!(
                    "error: unexpected argument `{}` for verify-sbom",
                    sanitize_reserved_token(other)
                );
                Err(ExitCode::from(2))
            }
        };
        if let Err(code) = taken {
            return code;
        }
    }

    let (Some(kind), Some(lockfile), Some(subject), Some(sbom)) = (kind, lockfile, subject, sbom)
    else {
        eprintln!("error: verify-sbom requires --kind, --lockfile, --subject and --sbom");
        return ExitCode::from(2);
    };
    let kind = match resolve_kind(&kind) {
        Ok(kind) => kind,
        Err(code) => return code,
    };
    if let Err(code) = check_manifest_applies(kind, manifest.as_deref()) {
        return code;
    }
    if let Err(code) = check_subject_type_matches_kind(kind, &subject) {
        return code;
    }
    if dep_v0.is_some() && kind != LockfileKind::Cargo {
        // A `.dep-v0` section lists cargo crates. Run against a composer or
        // npm projection every pair would be reported missing: a guaranteed
        // failure that means nothing. Refuse instead of producing it.
        eprintln!(
            "error: --dep-v0 is only accepted with --kind cargo (a `.dep-v0` section \
             lists cargo crates)"
        );
        return ExitCode::from(2);
    }

    let projection = match build_projection(kind, &lockfile, manifest.as_deref(), &subject) {
        Ok(projection) => projection,
        Err(failure) => {
            failure.report();
            return ExitCode::from(2);
        }
    };

    let raw = match read_capped_bytes(Path::new(sbom.as_str()), SBOM_INPUT_MAX_BYTES) {
        Ok(raw) => raw,
        Err(detail) => {
            eprintln!(
                "ERROR: cannot read {}: {}",
                sanitize_reserved_token(&sbom),
                sanitize_reserved_token(&detail)
            );
            // On the strict path the document IS the material under audit,
            // so an unreadable one is a verification failure (1). Under
            // --third-party the auditor ASSERTED the file is a foreign
            // CycloneDX document; a file that cannot be read at all means
            // the assertion was wrong, which is their error (2).
            return ExitCode::from(if third_party { 2 } else { 1 });
        }
    };

    // The lenient path NEVER passes: `failed` starts true and the
    // third-party arm never clears it, so no edit inside that arm can turn
    // a third-party comparison into an exit 0.
    let mut failed = true;
    let mut matched: Option<StrictMatch> = None;
    if third_party {
        if let Err(code) = report_third_party(&raw, &projection) {
            return code;
        }
    } else {
        matched = verify_sbom_strict(&raw, &projection);
        failed = matched.is_none();
    }

    if let Some(binary) = dep_v0 {
        match check_dep_v0(&binary, &projection) {
            DepV0Outcome::Passed => {}
            DepV0Outcome::Failed => failed = true,
            // The auditor asserted the path named an ELF image and it did
            // not. The run did not happen as they specified it, so it
            // leaves with THEIR code -- even when the document comparison
            // already failed and printed its report above.
            DepV0Outcome::AuditorError => return ExitCode::from(2),
        }
    }

    if failed {
        return ExitCode::from(1);
    }
    // The fixed banner of section 7.7 is printed HERE and nowhere else:
    // held back until every requested optional check has passed. Printed
    // where the comparison happens, it would ride out on the stdout of a
    // run that goes on to exit 1 on `--dep-v0`, and a reader grepping for
    // it would read a failing run as a match.
    if let Some(matched) = matched {
        println!("{}", compare::MATCH_BANNER);
        println!("components: {}", matched.components);
        println!("top-level entries: {}", matched.top_level);
    }
    ExitCode::SUCCESS
}

/// The substantive counts of a byte-identical comparison, carried until
/// the banner may be printed.
struct StrictMatch {
    /// Components in the projection.
    components: usize,
    /// Top-level entries in the projection.
    top_level: usize,
}

/// The strict path: the document must BE the canonical projection.
///
/// Returns the counts on a pass and `None` on a failure, having printed
/// the difference report. Only [`SbomVerdict::ByteIdentical`] is a pass:
/// "the bytes differ and every difference set is empty" is its own outcome
/// (spec section 7.3), and reporting it as a match is exactly what
/// canonicalization exists to prevent.
///
/// On a pass it prints NOTHING. The banner and the counts belong to the
/// caller, which alone knows whether the optional checks also passed.
fn verify_sbom_strict(raw: &[u8], projection: &Projection) -> Option<StrictMatch> {
    let document = match compare::parse_canonical_sbom(raw) {
        Ok(document) => document,
        Err(error) => {
            print_compare_error(&error);
            return None;
        }
    };
    let comparison = compare::compare(&document, projection);
    if comparison.verdict() == SbomVerdict::ByteIdentical {
        return Some(StrictMatch {
            components: comparison.counts.components_in_projection,
            top_level: comparison.counts.top_level_in_projection,
        });
    }
    print!(
        "{}",
        sanitize_reserved_token(&compare::render_human(&comparison))
    );
    None
}

/// The `--third-party` path: LENIENT, and never a pass.
///
/// # Errors
///
/// The exit code to leave with when the file is not a JSON object at all:
/// the auditor asserted it was a foreign CycloneDX document and it is not
/// one, which is their error (2), not the document's (1). Otherwise the
/// adaptation list and the difference report are printed and the caller
/// exits 1 unconditionally.
fn report_third_party(raw: &[u8], projection: &Projection) -> Result<(), ExitCode> {
    let (adapted, adaptations) = match adapt_third_party(raw) {
        Ok(pair) => pair,
        Err(AdaptError::NotADocument(detail)) => {
            eprintln!(
                "error: --third-party expects a JSON CycloneDX document: {}",
                sanitize_reserved_token(&detail)
            );
            return Err(ExitCode::from(2));
        }
        Err(AdaptError::DuplicateForeignBomRef { reference }) => {
            // The DOCUMENT's error, not the auditor's: reported by class
            // like every other one, and the caller exits 1.
            eprintln!("SBOM could not be adapted for comparison");
            eprintln!("error class: duplicate-foreign-bom-ref");
            eprintln!(
                "{}",
                sanitize_reserved_token(&format!(
                    "two objects declare the same `bom-ref` `{reference}`, which is not \
                     its own `purl`: reduction 6 discards that identifier and retargets \
                     every reference that named it, and with two objects behind one \
                     identifier there is no answer to retarget to. CycloneDX requires a \
                     `bom-ref` to be unique within a document."
                ))
            );
            return Ok(());
        }
    };
    println!("third-party comparison: LENIENT, and never a match");
    println!(
        "the document was ADAPTED before comparison, so the bytes compared are the adapted \
         ones and byte identity is not claimed on this path"
    );
    println!("adaptations applied ({}):", adaptations.len());
    for note in &adaptations {
        println!("  {}", sanitize_reserved_token(note));
    }
    match compare::parse_canonical_sbom(&adapted) {
        Err(error) => print_compare_error(&error),
        Ok(document) => {
            let comparison = compare::compare(&document, projection);
            if comparison.verdict() == SbomVerdict::ByteIdentical {
                // NEVER the fixed match banner. `render_human` would print
                // it here, and the identity on this path is between the
                // projection and an ADAPTED document -- not the one the
                // producer actually published.
                println!(
                    "the ADAPTED document reduces to the canonical projection; this is NOT a \
                     match verdict, because the published bytes are not the compared bytes"
                );
                println!("components: {}", comparison.counts.components_in_projection);
                println!(
                    "top-level entries: {}",
                    comparison.counts.top_level_in_projection
                );
            } else {
                print!(
                    "{}",
                    sanitize_reserved_token(&compare::render_human(&comparison))
                );
            }
        }
    }
    Ok(())
}

/// Why a foreign document could not be ADAPTED at all.
///
/// The two variants are two different parties' errors, and collapsing them
/// would put a local typo and a broken artifact behind one exit code.
enum AdaptError {
    /// The bytes are not a JSON CycloneDX document. The auditor asserted
    /// they were: their error, exit 2.
    NotADocument(String),
    /// Two objects of the document declare the SAME foreign `bom-ref`.
    ///
    /// Reduction 6 discards a foreign identifier and retargets every
    /// reference that named it; with two objects behind one identifier
    /// there is no answer to retarget TO, and taking the last one read
    /// pointed the graph at whichever object happened to come later --
    /// turning a document that is invalid under CycloneDX's own uniqueness
    /// rule into a comparison. It is the DOCUMENT that is wrong: exit 1,
    /// under its own error class (spec section 7.4).
    DuplicateForeignBomRef {
        /// The identifier two objects share.
        reference: String,
    },
}

/// The SIX reductions `--third-party` is allowed to perform, each one
/// NAMED in the returned list so a reader sees what was changed rather
/// than a silently normalized document:
///
/// 1. top-level keys outside the seven the format allows are DROPPED
///    (`serialNumber` above all, whose presence alone makes two emissions
///    of one lockfile differ);
/// 2. `metadata` keys other than `component` are DROPPED (`timestamp`,
///    `tools`);
/// 3. an ABSENT `components`, `dependencies` or `properties` becomes an
///    empty array -- absence and emptiness say the same thing about those
///    three, and the difference sets then report the whole projection as
///    missing, which is the honest answer;
/// 4. `components` are re-sorted ascending by purl;
/// 5. an object that declares a `purl` and NO `bom-ref` gets its purl as
///    the reference;
/// 6. a `bom-ref` that is present and DIFFERENT from its own purl is
///    REWRITTEN to the purl and the foreign identifier is DISCARDED, with
///    every reference that named it following the rewrite. Without this,
///    the lenient path was unreachable for the tool an auditor is most
///    likely to hold: `cargo-cyclonedx` writes cargo package-ids
///    (`registry+https://...#name@version`) as `bom-ref`, so EVERY real
///    document of its shape stopped at `bom-ref-not-purl` before a single
///    difference set was computed. Discarding a reference space is a
///    reduction like the others -- reported by name, and never a match:
///    what the comparison then reports are differences in the purls, which
///    is what an auditor can act on. The count reported is the number of
///    OBJECTS rewritten, and a foreign `bom-ref` declared by TWO objects is
///    REFUSED under its own error class rather than reduced: there is no
///    single purl to retarget its references to.
///
/// Anything the adapted document still violates is reported by error class
/// and the run fails: the lenient path never rewrites a document into
/// conformance, and it never claims a match.
///
/// # Errors
///
/// [`AdaptError::NotADocument`] when the bytes are not a JSON object at
/// all -- the AUDITOR asserted this file was a CycloneDX document, so that
/// is their error. [`AdaptError::DuplicateForeignBomRef`] when reduction 6
/// cannot be applied without inventing an answer.
fn adapt_third_party(raw: &[u8]) -> Result<(Vec<u8>, Vec<String>), AdaptError> {
    let text = std::str::from_utf8(raw)
        .map_err(|error| AdaptError::NotADocument(format!("not UTF-8: {error}")))?;
    let value: Value = serde_json::from_str(text)
        .map_err(|error| AdaptError::NotADocument(format!("not JSON: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| AdaptError::NotADocument("not a JSON object".to_string()))?;

    let mut notes: Vec<String> = Vec::new();
    let mut reduced = Map::new();
    for (key, entry) in object {
        if compare::ALLOWED_TOP_LEVEL_KEYS.contains(&key.as_str()) {
            reduced.insert(key.clone(), entry.clone());
        } else {
            notes.push(format!("dropped top-level key `{key}`"));
        }
    }
    for key in THIRD_PARTY_FILLABLE_KEYS {
        if !reduced.contains_key(key) {
            reduced.insert(key.to_string(), Value::Array(Vec::new()));
            notes.push(format!("`{key}` absent; compared as an empty array"));
        }
    }

    if let Some(metadata) = reduced.get_mut("metadata").and_then(Value::as_object_mut) {
        let dropped: Vec<String> = metadata
            .keys()
            .filter(|key| key.as_str() != "component")
            .cloned()
            .collect();
        for key in dropped {
            metadata.remove(&key);
            notes.push(format!("dropped metadata key `{key}`"));
        }
        if let Some(component) = metadata.get_mut("component").and_then(Value::as_object_mut) {
            if fill_bom_ref(component) {
                notes.push(
                    "metadata.component declared no `bom-ref`; compared as its own `purl`"
                        .to_string(),
                );
            }
        }
    }

    // Reduction 6. Collected first over every object whose `bom-ref` the
    // format governs, then applied to the graph, so a reference that named
    // a discarded identifier follows it instead of dangling.
    //
    // `rewrites` counts OBJECTS rewritten; `rewritten` maps one foreign
    // identifier to the purl that replaced it. Reporting the map's length
    // as the count under-reported every document in which two objects
    // shared one foreign identifier -- which is also the document this
    // loop must REFUSE: retargeting a reference that named it would have
    // to pick one of the two purls, and last-wins picked whichever came
    // later, silently turning an invalid document into a comparison.
    //
    // With the refusal in place the two numbers coincide on every path
    // that reaches the note, so the counter is not independently
    // observable today. It is kept explicit because it is the quantity the
    // note CLAIMS, and it is what keeps that claim true if the refusal is
    // ever relaxed -- a document, not a map, is what a reader is counting.
    let mut rewritten: BTreeMap<String, String> = BTreeMap::new();
    let mut rewrites = 0usize;
    let mut record = |foreign: String, purl: String| -> Result<(), AdaptError> {
        rewrites += 1;
        if rewritten.insert(foreign.clone(), purl).is_some() {
            return Err(AdaptError::DuplicateForeignBomRef { reference: foreign });
        }
        Ok(())
    };
    if let Some(component) = reduced
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .and_then(|metadata| metadata.get_mut("component"))
        .and_then(Value::as_object_mut)
    {
        if let Some((foreign, purl)) = rewrite_bom_ref(component) {
            record(foreign, purl)?;
        }
    }
    if let Some(components) = reduced.get_mut("components").and_then(Value::as_array_mut) {
        for entry in components.iter_mut() {
            if let Some(component) = entry.as_object_mut() {
                if let Some((foreign, purl)) = rewrite_bom_ref(component) {
                    record(foreign, purl)?;
                }
            }
        }
    }
    if rewrites > 0 {
        notes.push(format!(
            "{rewrites} bom-ref(s) rewritten from purl (foreign identifier discarded)"
        ));
        if let Some(graph) = reduced
            .get_mut("dependencies")
            .and_then(Value::as_array_mut)
        {
            for node in graph.iter_mut() {
                let Some(node) = node.as_object_mut() else {
                    continue;
                };
                if let Some(reference) = node.get_mut("ref") {
                    retarget(reference, &rewritten);
                }
                if let Some(edges) = node.get_mut("dependsOn").and_then(Value::as_array_mut) {
                    for edge in edges.iter_mut() {
                        retarget(edge, &rewritten);
                    }
                }
            }
        }
    }

    if let Some(components) = reduced.get_mut("components").and_then(Value::as_array_mut) {
        let mut filled = 0usize;
        for entry in components.iter_mut() {
            if let Some(component) = entry.as_object_mut() {
                if fill_bom_ref(component) {
                    filled += 1;
                }
            }
        }
        if filled > 0 {
            notes.push(format!(
                "{filled} component(s) declared no `bom-ref`; compared as their own `purl`"
            ));
        }
        let before: Vec<String> = components.iter().map(purl_of).collect();
        components.sort_by_key(purl_of);
        let after: Vec<String> = components.iter().map(purl_of).collect();
        if before != after {
            notes.push("`components` re-sorted ascending by purl".to_string());
        }
    }

    let canonical = canonicalize(&Value::Object(reduced)).map_err(|error| {
        AdaptError::NotADocument(format!(
            "the adapted document could not be canonicalized: {error}"
        ))
    })?;
    Ok((canonical.into_bytes(), notes))
}

/// The `purl` of a component object, or the empty string when it declares
/// none -- such an object sorts first and is then rejected by the reader
/// with its own error class, which is where that belongs.
fn purl_of(entry: &Value) -> String {
    entry
        .get("purl")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Replace a `bom-ref` that disagrees with its own `purl`, returning the
/// discarded foreign identifier and the purl that replaced it.
///
/// `None` when the object declares no purl, no `bom-ref`, or a `bom-ref`
/// that already IS the purl -- the three cases where nothing was
/// discarded.
fn rewrite_bom_ref(object: &mut Map<String, Value>) -> Option<(String, String)> {
    let purl = object.get("purl").and_then(Value::as_str)?.to_string();
    let foreign = object.get("bom-ref").and_then(Value::as_str)?.to_string();
    if foreign == purl {
        return None;
    }
    object.insert("bom-ref".to_string(), Value::String(purl.clone()));
    Some((foreign, purl))
}

/// Point a reference at the purl that replaced the identifier it names.
///
/// A string naming nothing that was rewritten is left exactly as it is:
/// the difference sets, and the dangling-reference class, are what report
/// it.
fn retarget(value: &mut Value, rewritten: &BTreeMap<String, String>) {
    let Some(name) = value.as_str() else {
        return;
    };
    if let Some(purl) = rewritten.get(name) {
        *value = Value::String(purl.clone());
    }
}

/// Give an object the `bom-ref` its `purl` implies, when it declares none
/// at all. Returns whether anything was written.
fn fill_bom_ref(object: &mut Map<String, Value>) -> bool {
    if object.contains_key("bom-ref") {
        return false;
    }
    let Some(purl) = object
        .get("purl")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return false;
    };
    object.insert("bom-ref".to_string(), Value::String(purl));
    true
}

/// What the optional binary leg concluded.
///
/// Three claims about two different parties, and collapsing any two of
/// them loses the one thing the exit code is for.
enum DepV0Outcome {
    /// Every pair the binary declares is accounted for by the projection.
    Passed,
    /// The VENDOR's side failed: a pair the projection does not carry, a
    /// binary that attested nothing, or an ELF image whose section could
    /// not be decoded.
    Failed,
    /// The AUDITOR's side failed: the path is unreadable, or names a file
    /// that is not an ELF container at all. They asserted it was an ELF
    /// image; the assertion is false, and nothing was learned about the
    /// artifact.
    AuditorError,
}

/// `--dep-v0 <elf>`: confront the projection with what the BINARY says
/// about itself (spec section 7.5).
///
/// Outcomes, never collapsed: a pair the projection does not account for
/// is a failure; a binary with no section at all is NOT ATTESTED and still
/// a failure, because a check that was requested and could not be
/// performed is not a pass; components of the projection the binary does
/// not carry are INFORMATION -- a lockfile covers a workspace, a binary
/// does not; and an image that is not an ELF, or cannot be read, is the
/// AUDITOR's own error (spec section 7.6), kept out of the vendor-failure
/// code so a script filtering for "the vendor's artifact failed" is not
/// contaminated by a local typo. A MALFORMED ELF is not in that class: the
/// magic says ELF, so what is broken is the image, which is the artifact.
fn check_dep_v0(path: &str, projection: &Projection) -> DepV0Outcome {
    let bytes = match read_capped_bytes(Path::new(path), BINARY_INPUT_MAX_BYTES) {
        Ok(bytes) => bytes,
        Err(detail) => {
            eprintln!(
                "ERROR: cannot read {}: {}",
                sanitize_reserved_token(path),
                sanitize_reserved_token(&detail)
            );
            return DepV0Outcome::AuditorError;
        }
    };
    match depv0::extract_dep_v0(&bytes) {
        Err(error) => {
            eprintln!("SBOM<->binary: ERROR");
            eprintln!("error class: {}", dep_v0_error_class(&error));
            eprintln!("{}", sanitize_reserved_token(&error.to_string()));
            match error {
                DepV0Error::UnsupportedBinaryFormat { .. } => DepV0Outcome::AuditorError,
                _ => DepV0Outcome::Failed,
            }
        }
        Ok(None) => {
            println!("SBOM<->binary: NOT ATTESTED (binary carries no .dep-v0 section)");
            DepV0Outcome::Failed
        }
        Ok(Some(dep)) => {
            let report = depv0::check_projection_covers_binary(projection, &dep);
            println!(
                "SBOM<->binary: pairs declared by the binary: {}",
                dep.packages.len()
            );
            println!(
                "SBOM<->binary: missing from the projection ({}):",
                report.missing.len()
            );
            for (name, version) in &report.missing {
                println!(
                    "  {} {}",
                    sanitize_reserved_token(name),
                    sanitize_reserved_token(version)
                );
            }
            println!(
                "SBOM<->binary: components of the projection the binary does not carry: {} \
                 (informational)",
                report.extra_in_projection
            );
            if report.is_covered() {
                DepV0Outcome::Passed
            } else {
                DepV0Outcome::Failed
            }
        }
    }
}

/// Print the class and the message of a document that could not be read.
///
/// The class is a stable, machine-matchable token -- a reader scripting
/// against this surface should not have to parse prose -- and none of them
/// is the reserved token. `CompareError`'s own Display already sanitizes;
/// it is routed through the binary's sanitizer as well so that ONE output
/// boundary governs every line this binary prints.
fn print_compare_error(error: &CompareError) {
    eprintln!("SBOM could not be read as a canonical document");
    eprintln!("error class: {}", compare_error_class(error));
    eprintln!("{}", sanitize_reserved_token(&error.to_string()));
}

/// The stable class token of a reader failure.
fn compare_error_class(error: &CompareError) -> &'static str {
    match error {
        CompareError::NotUtf8 { .. } => "not-utf8",
        CompareError::ByteOrderMark => "byte-order-mark",
        CompareError::NotJson { .. } => "not-json",
        CompareError::NotCanonical { .. } => "not-canonical",
        CompareError::NotAnObject => "not-an-object",
        CompareError::UnexpectedTopLevelKey { .. } => "unexpected-top-level-key",
        CompareError::MissingTopLevelKey { .. } => "missing-top-level-key",
        CompareError::UnexpectedMetadataKey { .. } => "unexpected-metadata-key",
        CompareError::Malformed { .. } => "malformed",
        CompareError::BomRefNotPurl { .. } => "bom-ref-not-purl",
        CompareError::ComponentsOutOfOrder { .. } => "components-out-of-order",
        CompareError::DuplicateComponentPurl { .. } => "duplicate-component-purl",
        CompareError::DanglingReference { .. } => "dangling-reference",
    }
}

/// The stable class token of a `.dep-v0` extraction failure. Spec section
/// 7.6 names `UnsupportedBinaryFormat` explicitly among the classes an
/// implementation must distinguish BY NAME.
fn dep_v0_error_class(error: &DepV0Error) -> &'static str {
    match error {
        DepV0Error::UnsupportedBinaryFormat { .. } => "unsupported-binary-format",
        DepV0Error::MalformedElf { .. } => "malformed-elf",
        DepV0Error::Compression { .. } => "compression",
        DepV0Error::MalformedPayload { .. } => "malformed-payload",
    }
}

/// Read a file with a hard byte cap (DoS guard).
///
/// Bounded at the source so a concurrent writer cannot push the read past
/// the cap: the metadata check alone is a race, and `take` alone would
/// still allocate the announced size first.
fn read_capped_bytes(path: &Path, cap: u64) -> Result<Vec<u8>, String> {
    let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let meta = f.metadata().map_err(|e| e.to_string())?;
    if meta.len() > cap {
        return Err(cap_refusal(meta.len(), cap));
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    f.take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() as u64 > cap {
        return Err("file grew past the byte cap during read".to_string());
    }
    Ok(buf)
}

/// [`read_capped_bytes`] at an explicit cap, requiring UTF-8.
///
/// The cap and the UTF-8 gate are `cli_render::chain_export_text`, the ONE
/// spelling the browser page applies to the bytes it read: an export this
/// refuses must not verify there.
fn read_capped_utf8_at(path: &Path, cap: u64) -> Result<String, String> {
    let buf = read_capped_bytes(path, cap)?;
    chain_export_text(buf, cap)
}

/// The chain-export read: [`read_capped_utf8_at`] at the export's own cap.
fn read_capped_utf8(path: &Path) -> Result<String, String> {
    read_capped_utf8_at(path, CHAIN_FILE_MAX_BYTES)
}
