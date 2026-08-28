// SPDX-License-Identifier: Apache-2.0
//! Black-box tests of the `seetrex-verifier` CLI binary.
//!
//! The binary is the tool an external auditor installs from public
//! material (`cargo install seetrex-verifier`); these tests exercise it
//! the way that auditor runs it — as a spawned process over real files —
//! and pin the spec-bound outcome vocabulary and exit codes of
//! `SPEC_VERDICT_PACKAGE_V1.md` §9.6 plus the chain-export verification
//! of §8.1.
//!
//! `CARGO_BIN_EXE_seetrex-verifier` is set by Cargo for integration
//! tests of a package that declares the bin target: the binary is BUILT
//! as a prerequisite of running these tests, so the tests double as the
//! guarantee that the package produces an installable executable.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use seetrex_format::types::FactValue;
use seetrex_verifier::canonical::{
    compute_verdict_hash_v1, EvidenceRef, VerdictCanonicalInputV1,
};
use seetrex_verifier::chain_export::{PublicChainExport, PublicChainRow};
use seetrex_verifier::chain::compute_chain_hash;
use seetrex_verifier::hash::sha256_hex;
use seetrex_verifier::types::VerdictOutcome;
use uuid::Uuid;

const BIN: &str = env!("CARGO_BIN_EXE_seetrex-verifier");

/// Name of the environment variable that points this suite at an
/// executable OTHER than the one Cargo just built.
const BIN_OVERRIDE_VAR: &str = "SEETREX_VERIFIER_BIN";

/// The resolution rule itself, as a pure function of the override, so it
/// can be exercised in both directions without mutating the environment
/// of a process whose tests run in parallel threads.
fn bin_from(override_value: Option<String>) -> String {
    override_value.unwrap_or_else(|| BIN.to_string())
}

/// The executable these tests spawn: `SEETREX_VERIFIER_BIN` when it is
/// set in the environment, and the Cargo-built binary otherwise.
///
/// The override exists so the SAME suite can be pointed at a release
/// artifact (a prebuilt, signed binary) and answer whether it yields the
/// same verdicts as the build cargo produces here. Unset — which is how
/// CI and every developer run it — nothing changes.
fn bin() -> String {
    bin_from(std::env::var(BIN_OVERRIDE_VAR).ok())
}

/// INTENT: pointing this suite at another executable is OPT-IN and the
///         default resolution is the binary Cargo just built. If the
///         override were silently dead, a run that reports "the release
///         artifact passes" would in fact have measured cargo's own
///         binary — the verdict-equality claim would be unfalsifiable
///         while looking green.
/// CONTEXT: the suite resolved the executable at compile time only
///          (`const BIN`), so a produced artifact could not be measured
///          by the very tests that define the tool's behaviour.
/// EXPIRES IF: the suite stops spawning an external process (e.g. the
///             CLI is exercised in-process through a library entry
///             point), at which point there is no executable to point
///             anywhere.
#[test]
fn test_intent_bin_e2e_defaults_to_the_cargo_built_binary() {
    // The rule, both directions, independent of the ambient environment:
    // no override -> the Cargo-built binary, verbatim...
    assert_eq!(
        bin_from(None),
        BIN,
        "with no override the suite must spawn the binary cargo built"
    );
    assert!(
        Path::new(&bin_from(None)).is_file(),
        "the default resolution must name a file that exists: {BIN}"
    );
    // ...an override -> that value, verbatim (never the const).
    let sentinel = "/nonexistent/seetrex-verifier-override-sentinel";
    assert_eq!(
        bin_from(Some(sentinel.to_string())),
        sentinel,
        "an override was ignored: the suite would measure cargo's own \
         binary while reporting another one"
    );

    // And the live reader is wired to that rule through the documented
    // variable name. Asserted in whichever state this process is in, so
    // the check is never vacuous and the environment is never mutated.
    match std::env::var(BIN_OVERRIDE_VAR) {
        Ok(v) => assert_eq!(
            bin(),
            v,
            "{BIN_OVERRIDE_VAR} is set but the suite is not reading it"
        ),
        Err(_) => assert_eq!(
            bin(),
            BIN,
            "{BIN_OVERRIDE_VAR} is unset and the default moved off the \
             cargo-built binary"
        ),
    }
}

/// INTENT: the `seetrex-verifier` package manifest DECLARES an
///         installable binary target named `seetrex-verifier`, and the
///         package build actually produces that executable. Without a
///         bin target, `cargo install seetrex-verifier` fails with
///         "it has no binaries" — an external auditor cannot obtain an
///         executable verification tool from public material at all.
/// CONTEXT: 0.2.0 shipped library-only; the gap was found empirically
///          after publication. 0.3.0 adds the bin; this test pins it.
/// EXPIRES IF: the auditor tool is deliberately split into its own
///             package (then THAT package carries this guarantee).
#[test]
fn test_intent_manifest_declares_installable_bin() {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        manifest.contains("[[bin]]"),
        "Cargo.toml no longer declares an explicit [[bin]] target"
    );
    assert!(
        manifest.contains(r#"name = "seetrex-verifier""#),
        "the bin target must be named seetrex-verifier (what cargo install exposes)"
    );
    // CARGO_BIN_EXE_* existing at compile time already proves the target
    // is declared; assert the built artifact exists on disk too.
    assert!(
        Path::new(BIN).is_file(),
        "declared bin was not produced by the build: {BIN}"
    );
}

// ─── fixture builders (same public primitives the library tests use) ────

fn write(path: &Path, v: &serde_json::Value) {
    std::fs::write(path, serde_json::to_vec_pretty(v).unwrap()).unwrap();
}

/// Build a minimal, honest-by-construction v1 package (single inline
/// evidence row); returns the real verdict_hash.
fn minimal_v1_package(dir: &Path) -> String {
    let tenant = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let ev_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
    let inline = r#"{"a":1}"#;
    let content_hash = sha256_hex(inline.as_bytes());

    let mut wm: BTreeMap<String, FactValue> = BTreeMap::new();
    wm.insert("k".to_string(), FactValue::Boolean(true));

    let refs = vec![EvidenceRef {
        evidence_id: ev_id,
        content_hash: content_hash.clone(),
    }];
    let v1 = VerdictCanonicalInputV1 {
        tenant_id: tenant,
        ruleset_id: "rs".to_string(),
        ruleset_version: 1,
        control_id: "ctl".to_string(),
        verdict_outcome: VerdictOutcome::Satisfied,
        evidence_refs: refs,
        engine_semantic_version: 6,
        working_memory_canonical: wm,
    };
    let verdict_hash = hex::encode(compute_verdict_hash_v1(&v1).unwrap());
    let chain_hash = compute_chain_hash(None, &verdict_hash);

    std::fs::create_dir_all(dir.join("evidence")).unwrap();
    write(
        &dir.join("evidence").join(format!("{ev_id}.json")),
        &serde_json::json!({
            "id": ev_id.to_string(),
            "category": "sbom",
            "content_hash": content_hash,
            "canonical_inline": inline,
        }),
    );
    write(
        &dir.join("ruleset.json"),
        &serde_json::json!({
            "ruleset_id": "rs", "framework": "CRA", "article": "1",
            "control": "ctl", "version": 1,
            "engine_semantic_version_floor": 1, "doc": "d",
            "facts_consumed": [], "verdicts_emitted": ["SATISFIED"],
            "rules": []
        }),
    );
    write(
        &dir.join("verdict.json"),
        &serde_json::json!({
            "id": "cbfb1c0d-13dc-4093-874d-c636c8a56653",
            "tenant_id": tenant.to_string(),
            "ruleset_id": "rs", "ruleset_version": 1, "control_id": "ctl",
            "verdict_outcome": "SATISFIED",
            "verdict_hash": verdict_hash,
            "evidence_refs": [{"content_hash": content_hash, "evidence_id": ev_id.to_string()}],
            "engine_semantic_version": 6,
            "working_memory_canonical": {"k": true},
        }),
    );
    write(
        &dir.join("manifest.json"),
        &serde_json::json!({
            "package_format_version": 2,
            "tenant_id": tenant.to_string(),
            "verdict_id": "cbfb1c0d-13dc-4093-874d-c636c8a56653",
            "verdict_hash": verdict_hash,
            "chain_prev_hash": serde_json::Value::Null,
            "chain_hash": chain_hash,
            "files": [
                "verdict.json", "ruleset.json",
                format!("evidence/{ev_id}.json"), "manifest.json"
            ],
        }),
    );
    verdict_hash
}

/// Build a VALID n-row public chain export via the production algorithm.
fn valid_chain_export(n: u32) -> PublicChainExport {
    let mut rows: Vec<PublicChainRow> = Vec::with_capacity(n as usize);
    let mut prev: Option<String> = None;
    for ordinal in 1..=n {
        let verdict_hash = format!("{ordinal:064x}");
        let chain_hash = compute_chain_hash(prev.as_deref(), &verdict_hash);
        rows.push(PublicChainRow {
            ordinal,
            verdict_id: Uuid::nil(),
            verdict_hash,
            chain_prev_hash: prev.clone(),
            chain_hash: chain_hash.clone(),
            appended_at: chrono::Utc::now(),
            ruleset_id: "demo-sbom-presence".to_string(),
            verdict_outcome: "SATISFIED".to_string(),
        });
        prev = Some(chain_hash);
    }
    PublicChainExport::new(rows)
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("spawn seetrex-verifier binary")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// ─── verify-package: the three spec-bound outcomes (§9.6) ────────────────

/// INTENT: the binary's `verify-package` outcome vocabulary and exit
///         codes are the BINDING ones of spec §9.6: anchored pass →
///         `INTEGRITY-OK (weak)` exit 0; unanchored pass →
///         `SELF-CONSISTENT (unanchored)` exit 4; failure → error line,
///         no success token, exit 1. The reserved strong token never
///         appears in the weak mode's output on any path.
/// CONTEXT: the standalone binary is the tool auditors script against;
///          drifting from the reference CLI's tokens/codes would break
///          the conformance the spec promises.
/// EXPIRES IF: the spec versions its outcome vocabulary (§9.6).
#[test]
fn test_scenario_verify_package_three_outcomes() {
    let tmp = tempdir();
    let hash = minimal_v1_package(tmp.path());

    // 1. Unanchored pass → SELF-CONSISTENT, exit 4, hint printed.
    let out = run(&["verify-package", tmp.path().to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(4), "unanchored pass must exit 4");
    let so = stdout(&out);
    assert!(so.contains("SELF-CONSISTENT (unanchored)"), "token missing: {so}");
    assert!(so.contains("HINT:"), "re-run hint missing: {so}");
    assert!(!so.to_ascii_uppercase().contains("VERIFIED"), "reserved token leaked: {so}");

    // 2. Anchored pass → INTEGRITY-OK (weak), exit 0.
    let out = run(&[
        "verify-package",
        tmp.path().to_str().unwrap(),
        "--expected-verdict-hash",
        &hash,
    ]);
    assert_eq!(out.status.code(), Some(0), "anchored pass must exit 0: {}", stderr(&out));
    let so = stdout(&out);
    assert!(so.contains("INTEGRITY-OK (weak)"), "token missing: {so}");
    assert!(so.contains("STEP 7 external anchor OK"), "step lines must print: {so}");
    assert!(!so.to_ascii_uppercase().contains("VERIFIED"), "reserved token leaked: {so}");

    // 3. Failure (wrong external anchor) → exit 1, ERROR on stderr, no
    //    success token anywhere.
    let out = run(&[
        "verify-package",
        tmp.path().to_str().unwrap(),
        "--expected-verdict-hash",
        &"0".repeat(64),
    ]);
    assert_eq!(out.status.code(), Some(1), "failure must exit 1");
    let se = stderr(&out);
    assert!(se.contains("ERROR:"), "loud error line missing: {se}");
    assert!(se.contains("re-forged"), "anchor-mismatch wording missing: {se}");
    let combined = format!("{}{}", stdout(&out), se);
    assert!(!combined.contains("INTEGRITY-OK"), "failure must print no success token");
    assert!(!combined.to_ascii_uppercase().contains("VERIFIED"), "reserved token leaked");
}

/// INTENT: package-controlled bytes can NEVER smuggle the reserved
///         strong-pass token `VERIFIED` into the weak check's output:
///         the binary routes every line through the crate's boundary
///         sanitizer, so a hostile filename that lands verbatim in a
///         Shape error is printed REDACTED (`VERIF[REDACTED]`), never
///         raw.
/// CONTEXT: downstream shell tooling pattern-matches the substring
///          `VERIFIED` as a strong pass (spec §9.6, reserved
///          vocabulary); the fixed error wording alone cannot guarantee
///          absence because several messages interpolate attacker bytes.
/// EXPIRES IF: error rendering stops interpolating package bytes
///             entirely (structured machine output only).
#[test]
fn test_intent_bin_sanitizes_attacker_controlled_reserved_token() {
    let tmp = tempdir();
    minimal_v1_package(tmp.path());
    // Undeclared extra file whose NAME carries the reserved token — the
    // Shape error echoes the extras list.
    std::fs::write(tmp.path().join("VERIFIED_x.txt"), b"x").unwrap();

    let out = run(&["verify-package", tmp.path().to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1), "extra file must fail shape");
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        !combined.to_ascii_uppercase().contains("VERIFIED"),
        "attacker-controlled bytes leaked the reserved token raw: {combined}"
    );
    assert!(
        combined.contains("VERIF[REDACTED]"),
        "the sanitizer's redaction marker must be visible in the echoed \
         filename: {combined}"
    );
}

// ─── verify-chain: offline chain-export verification (§8.1) ──────────────

/// INTENT: `verify-chain <file.json>` verifies a downloaded public chain
///         export fully OFFLINE: success recomputes every link, reports
///         the head (verdict_count + last_chain_hash) and exits 0 with
///         the strong `VERIFIED` wording (this surface is a §9.6
///         reserve counterpart); a tampered export fails LOUD with the
///         breaking ordinal and exits 1, with no strong token in the
///         output.
/// CONTEXT: chain position/freshness is exactly what verify-package
///          cannot prove (§9.4) — the auditor kit needs both commands
///          in one public binary.
/// EXPIRES IF: the export schema is versioned up with its own verifier.
#[test]
fn test_scenario_verify_chain_ok_and_broken() {
    let tmp = tempdir();

    // Valid 3-row export → exit 0, head reported.
    let export = valid_chain_export(3);
    let expected_head = export.chain.last().unwrap().chain_hash.clone();
    let ok_path = tmp.path().join("chain.json");
    std::fs::write(&ok_path, serde_json::to_string_pretty(&export).unwrap()).unwrap();

    let out = run(&["verify-chain", ok_path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "valid export must exit 0: {}", stderr(&out));
    let so = stdout(&out);
    assert!(so.contains("Public chain package VERIFIED OFFLINE"), "strong wording: {so}");
    assert!(so.contains("verdict_count:   3"), "count missing: {so}");
    assert!(so.contains(&expected_head), "head hash missing: {so}");

    // Tampered export (severed link, self-consistent row) → exit 1 loud.
    let mut broken = valid_chain_export(3);
    broken.chain[2].chain_prev_hash = Some("e".repeat(64));
    broken.chain[2].chain_hash = compute_chain_hash(
        broken.chain[2].chain_prev_hash.as_deref(),
        &broken.chain[2].verdict_hash,
    );
    let bad_path = tmp.path().join("broken.json");
    std::fs::write(&bad_path, serde_json::to_string(&broken).unwrap()).unwrap();

    let out = run(&["verify-chain", bad_path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1), "broken export must exit 1");
    let se = stderr(&out);
    assert!(se.contains("CHAIN BROKEN at ordinal 3"), "must name the ordinal: {se}");
    assert!(
        !se.to_ascii_uppercase().contains("VERIFIED"),
        "no strong token on the failure path: {se}"
    );

    // Unreadable path → exit 1, not a panic.
    let out = run(&["verify-chain", tmp.path().join("missing.json").to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1), "missing file must exit 1");
    assert!(stderr(&out).contains("ERROR: cannot read"));

    // Garbage bytes (not even UTF-8) → exit 1, sanitized loud error.
    let junk_path = tmp.path().join("junk.json");
    std::fs::write(&junk_path, [0x00, 0xff, 0xfe, b'{', 0x80]).unwrap();
    let out = run(&["verify-chain", junk_path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1), "garbage bytes must exit 1");
    let se = stderr(&out);
    assert!(se.contains("ERROR:"), "loud error line missing: {se}");
    assert!(!se.to_ascii_uppercase().contains("VERIFIED"), "no strong token: {se}");
}

/// INTENT: the argv FILENAME of verify-chain is sanitized too — a
///         scripted pipeline can be fed a hostile path like
///         `VERIFIED_chain.json`, and the cannot-read error echoes it;
///         printing it raw would leak the reserved strong token into a
///         FAILING run's stderr.
/// CONTEXT: review fix of the first CLI release — the read-error path
///          printed the filename unsanitized.
/// EXPIRES IF: the error path stops echoing the filename.
#[test]
fn test_intent_verify_chain_sanitizes_argv_filename() {
    let tmp = tempdir();
    let hostile = tmp.path().join("VERIFIED_chain.json");
    // The file deliberately does NOT exist — the cannot-read error is
    // the path that echoes the name.
    let out = run(&["verify-chain", hostile.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let se = stderr(&out);
    assert!(
        !se.to_ascii_uppercase().contains("VERIFIED"),
        "argv filename leaked the reserved token raw: {se}"
    );
    assert!(
        se.contains("[REDACTED]"),
        "the redaction marker must appear in the echoed filename: {se}"
    );
}

// ─── usage surface ───────────────────────────────────────────────────────

#[test]
fn version_and_help_are_sober_and_usage_errors_exit_2() {
    let out = run(&["--version"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        stdout(&out).trim(),
        format!("seetrex-verifier {}", env!("CARGO_PKG_VERSION")),
        "--version prints exactly `seetrex-verifier <semver>`"
    );

    let out = run(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    let so = stdout(&out);
    // FIVE subcommands: a subcommand absent from --help is a subcommand an
    // auditor cannot discover from the tool itself.
    for command in [
        "verify-package",
        "verify-chain",
        "verify-anchor",
        "emit-sbom",
        "verify-sbom",
    ] {
        assert!(so.contains(command), "--help does not list `{command}`");
    }

    // Usage errors exit 2 — distinct from the spec-bound 0/1/4.
    for bad in [
        &["frobnicate"] as &[&str],
        &["verify-package"],
        &["verify-chain"],
        &["emit-sbom"],
        &["verify-sbom"],
    ] {
        let out = run(bad);
        assert_eq!(out.status.code(), Some(2), "usage error must exit 2 for {bad:?}");
    }
}

// ─── `<subcommand> --help`: the exit codes, measured ─────────────────────

/// The checked-in record of what `--help` exits with. It is data; the test
/// below makes it true by spawning the executable.
const HELP_EXIT_RECORD: &str = include_str!("fixtures/help_exit_codes.tsv");

/// The one row of that record that is NOT a subcommand: the tool's own
/// top-level `--help`. Same spelling in `crates/witness/tests/kit_doc.rs`,
/// which reads the file for the sentences section 7.4(e) publishes.
const TOP_LEVEL_HELP_KEY: &str = "--help";

/// `<key>\t<value>` rows of a record file, `#` comments and blank lines
/// dropped. Shared shape with the vendored published record `kit_doc.rs`
/// reads.
fn record_rows(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|l| {
            let (k, v) = l
                .split_once('\t')
                .unwrap_or_else(|| panic!("record row is not `<key><TAB><value>`: {l:?}"));
            (k.trim().to_string(), v.trim().to_string())
        })
        .collect()
}

/// The subcommand names the binary's OWN `--help` lists, read from its stdout:
/// the `COMMANDS:` block, one name per line at exactly four spaces of indent.
fn help_listed_subcommands(help_stdout: &str) -> BTreeSet<String> {
    let at = help_stdout
        .find("COMMANDS:")
        .expect("the binary's --help no longer prints a COMMANDS: block");
    let mut listed = BTreeSet::new();
    for line in help_stdout[at..].lines().skip(1) {
        if line.trim().is_empty() {
            break;
        }
        if !line.starts_with("    ") || line.starts_with("     ") {
            continue;
        }
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        if name.starts_with('-') {
            break;
        }
        listed.insert(name.to_string());
    }
    listed
}

/// INTENT: what `<subcommand> --help` exits with is decided by RUNNING the
///     executable and reading the process's exit code. The kit tells auditors
///     these codes, and one of them collides with the code a FAILED
///     verification returns, so the document must be pinned against a
///     measurement — never against a reading of this file's source.
/// CONTEXT: three consecutive blind rounds shipped a source-text matcher in
///     `crates/witness/tests/kit_doc.rs` and a docstring asserting it was
///     sound. A character window reached the neighbouring match arm; brace
///     matching from the nearest preceding `=> {` was then defeated three
///     ways in one round — a nested `match` inside the arm, a braceless
///     `"--help" | "-h" => return ExitCode::from(1),` arm ABOVE the reject
///     arm, and a `#[cfg]`-gated arm pair whose default build takes the
///     `from(1)` one. In all three the gate said `ok. 9 passed` and the
///     binary really exited 1. Arm order, nesting and conditional
///     compilation are semantics; no matcher over the text decides them, and
///     the next narrower matcher loses the same race again.
/// DECLARED LIMIT: this measures the binary THIS package builds. What the
///     PUBLISHED tool does is a separate, vendored record
///     (`crates/witness/tests/fixtures/published_verifier_help.tsv`), because
///     no test in this tree can spawn a binary it does not build.
/// EXPIRES IF: the tool grows a real `--help` per subcommand. The record then
///     reads 0 across the board and the kit paragraph about the collision is
///     deleted, not softened.
/// MUTANT: change any recorded code, the `--help` row included; add a
///     subcommand to `main`'s dispatch and to `COMMANDS:` without adding its
///     row; delete a row.
#[test]
fn test_intent_subcommand_help_exit_codes_are_measured_not_parsed() {
    let mut recorded: BTreeMap<String, i32> = record_rows(HELP_EXIT_RECORD)
        .into_iter()
        .map(|(name, code)| {
            let code = code
                .parse()
                .unwrap_or_else(|e| panic!("exit code for `{name}` is not an integer: {e}"));
            (name, code)
        })
        .collect();
    assert!(
        !recorded.is_empty(),
        "the help-exit record has no rows, so this test would pass over nothing"
    );

    // The tool's OWN `--help` is a row like any other, and NOT a subcommand:
    // it is removed before the set comparison below. It is recorded because
    // `docs/AUDITOR_KIT.md` section 7.4(e) tells an auditor what it exits with,
    // and `kit_doc.rs` binds that sentence to this row; before it existed the
    // number lived only in the assertion literal here, where the document
    // could not reach it and a mutant flipped the published `0` to `2` green.
    let top_level = recorded.remove(TOP_LEVEL_HELP_KEY).unwrap_or_else(|| {
        panic!("the help-exit record carries no `{TOP_LEVEL_HELP_KEY}` row")
    });

    // The SET, both ways: a subcommand the binary offers and the record does
    // not name is one nobody measured, and a row for a subcommand that is not
    // there is a measurement of nothing.
    let out = run(&["--help"]);
    assert_eq!(
        out.status.code(),
        Some(top_level),
        "`--help` really exits {:?}; the record says {top_level}",
        out.status.code()
    );
    let listed = help_listed_subcommands(&stdout(&out));
    let named: BTreeSet<String> = recorded.keys().cloned().collect();
    assert_eq!(
        listed, named,
        "the binary's --help lists {listed:?} and the record names {named:?}. Every \
         subcommand is measured here or none of them is."
    );

    // The CODES, by spawning. This is the whole point: no reading of the
    // source, so a nested match, a braceless arm and a `#[cfg]` pair are
    // irrelevant by construction.
    for (name, expected) in &recorded {
        let dispatch = run(&[name.as_str()]);
        assert!(
            !stderr(&dispatch).contains("unknown command"),
            "`{name}` is in the record but the binary does not dispatch it"
        );
        let out = run(&[name.as_str(), "--help"]);
        assert_eq!(
            out.status.code(),
            Some(*expected),
            "`{name} --help` really exits {:?}; the record says {expected}. stderr:\n{}",
            out.status.code(),
            stderr(&out)
        );
    }
}

// ─── verify-anchor: CLI plumbing over verify_anchored_package ────────────
//
// These black-box tests pin the CLI CONTRACT (arg parsing, two trusted/untrusted
// files, output vocabulary, exit codes) — NOT the crypto, which is exercised
// against REAL test.sigsum.org vectors by the library tests in
// `anchor_package.rs`. The success fixture carries NO leaves and NO rotations,
// so the checkpoint crypto is not reached (an empty package verifies vacuously:
// derive over zero rotations = {genesis}, no per-leaf inclusion, chain JOIN
// only). The checkpoint values below are the REAL frozen ones anyway (public
// data), so nothing here is fabricated.

const A_CP_SIZE: u64 = 196372;
const A_CP_ROOT: &str = "848aff0ecb7315a0fc1cc4a00c1065b51b4c269ff871dc2f048711892739a06e";
const A_CP_LOG_SIG: &str = "c551769caf05b2cf2358d6b93f9582e1e878e2eb3ac65b06d20315dbf7ef78b0f9b956e82a215e61abe2f06d2b30d407e81e2f4247f3e0d03daa4436434c0503";
const A_CP_TS: u64 = 1784740225;
const A_KH_SMARTIT: &str = "42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8";
const A_COSIG_SMARTIT: &str = "e8859da78c26b746a2a0c3350fe0e9984c0b99233887d50dff9f2738a8b88b77026b7022e0fc73d690c450fd5affad18db2d535178e2773e3e8d7738813b740d";
const A_LOG_PK: &str = "4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6";
const A_WIT_NISSE: &str = "1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c";
const A_WIT_RGDD: &str = "28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806";
const A_WIT_SMARTIT: &str = "f4855a0f46e8a3e23bb40faf260ee57ab8a18249fa402f2ca2d28a60e1a3130e";

/// A minimal VALID `anchor.json` (3-row production chain, real checkpoint, no
/// leaves) for `tenant`. Returns a `serde_json::Value` to write to disk.
fn valid_anchor_json_value(tenant: &str) -> serde_json::Value {
    let mut rows = Vec::new();
    let mut prev: Option<String> = None;
    for ordinal in 1..=3u32 {
        let verdict_hash = format!("{ordinal:064x}");
        let chain_hash = compute_chain_hash(prev.as_deref(), &verdict_hash);
        rows.push(serde_json::json!({
            "ordinal": ordinal,
            "verdict_id": "00000000-0000-0000-0000-000000000000",
            "verdict_hash": verdict_hash,
            "chain_prev_hash": prev.clone(),
            "chain_hash": chain_hash.clone(),
            "appended_at": "2026-07-22T12:00:00Z",
            "ruleset_id": "demo",
            "verdict_outcome": "SATISFIED",
        }));
        prev = Some(chain_hash);
    }
    serde_json::json!({
        "version": "seetrex/anchor/v1",
        "tenant_slug": tenant,
        "rows": rows,
        "checkpoint": {
            "size": A_CP_SIZE,
            "root": A_CP_ROOT,
            "log_signature": A_CP_LOG_SIG,
            "cosignatures": [
                {"key_hash": A_KH_SMARTIT, "timestamp": A_CP_TS, "signature": A_COSIG_SMARTIT}
            ],
        },
        "anchored_leaves": [],
        "rotations": [],
    })
}

/// A VALID auditor kit for `tenant`: synthetic pinned genesis + the real
/// Glasklar `sigsum-test1-2025` policy.
fn valid_kit_json_value(tenant: &str) -> serde_json::Value {
    serde_json::json!({
        "version": "seetrex/anchor-kit/v1",
        "tenant_slug": tenant,
        "genesis_key_hash": "11".repeat(32),
        "policy": {
            "log_pubkey": A_LOG_PK,
            "witnesses": [A_WIT_NISSE, A_WIT_RGDD, A_WIT_SMARTIT],
            "quorum_k": 2,
        },
    })
}

/// INTENT: `verify-anchor` prints the v6 TWO-verdict result and NEVER the
///         reserved strong token `VERIFIED`. A confirmed CONSISTENCIA with
///         INCONCLUSIVE COMPLETITUD is not a blanket strong pass, and this
///         surface is not §9.6-blessed to emit the reserved token.
/// CONTEXT: the whole v6 redesign exists because a single "VERIFIED OFFLINE"
///          was misread as completeness. The banner must carry CONSISTENCIA +
///          COMPLETITUD explicitly, and the shell-tooling strong-pass token
///          must be absent.
/// EXPIRES IF: verify-anchor is deliberately blessed as a §9.6 strong surface
///             (then the reserved-token policy for it is revised in that PR).
#[test]
fn test_scenario_verify_anchor_confirmed_offline_no_reserved_token() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    write(&anchor, &valid_anchor_json_value("example-tenant"));
    write(&kit, &valid_kit_json_value("example-tenant"));

    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "confirmed CONSISTENCIA must exit 0; stderr={}",
        stderr(&out)
    );
    let so = stdout(&out);
    assert!(so.contains("CONSISTENCIA CONFIRMED OFFLINE"), "banner missing: {so}");
    assert!(
        completitud_class(&so) == "INCONCLUSIVE",
        "two-verdict honesty missing: {so}"
    );
    // The vacuous case (this fixture has zero leaves) must SHOW the count, so a
    // confirmed-but-vacuous pass can never be misread as substantive (both
    // blind reviewers flagged the silent-vacuous hazard).
    assert!(
        so.contains("anchored leaves checked: 0"),
        "vacuous-pass leaf count not surfaced: {so}"
    );
    assert!(
        !so.to_ascii_uppercase().contains("VERIFIED"),
        "reserved strong token leaked on the anchor surface: {so}"
    );
}

/// A kit auditing a DIFFERENT tenant than the package declares ⇒ the category
/// guard fails CONSISTENCIA ⇒ exit 1 (a package failure, not a config error),
/// and the reserved token must not leak on the failure path either.
#[test]
fn test_scenario_verify_anchor_tenant_mismatch_fails() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    write(&anchor, &valid_anchor_json_value("example-tenant"));
    write(&kit, &valid_kit_json_value("other-tenant"));

    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1), "tenant mismatch is a CONSISTENCIA failure → exit 1");
    let se = stderr(&out);
    assert!(se.contains("CONSISTENCIA FAILED"), "failure line missing: {se}");
    assert!(
        !se.to_ascii_uppercase().contains("VERIFIED"),
        "reserved token leaked on failure: {se}"
    );
}

/// A malformed UNTRUSTED package ⇒ the material under audit cannot be verified
/// ⇒ exit 1.
#[test]
fn verify_anchor_malformed_package_exits_1() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    std::fs::write(&anchor, b"{ not valid json").unwrap();
    write(&kit, &valid_kit_json_value("example-tenant"));

    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1), "malformed package → exit 1");
}

/// A malformed AUDITOR KIT is the auditor's own config error ⇒ exit 2, kept
/// distinct from exit 1 (a vendor-package failure).
#[test]
fn verify_anchor_malformed_kit_exits_2() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    write(&anchor, &valid_anchor_json_value("example-tenant"));
    let mut bad_kit = valid_kit_json_value("example-tenant");
    bad_kit["version"] = serde_json::json!("seetrex/anchor-kit/v2");
    write(&kit, &bad_kit);

    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "malformed kit is a config error → exit 2; stderr={}",
        stderr(&out)
    );
}

/// Missing `--kit` is a usage error ⇒ exit 2.
#[test]
fn verify_anchor_missing_kit_is_usage_error() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    write(&anchor, &valid_anchor_json_value("example-tenant"));
    let out = run(&["verify-anchor", anchor.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "missing --kit is a usage error → exit 2");
}

// ─── verify-anchor --monitor: real enumeration round-trip ────────────────
//
// These feed the REAL `scripts/gate46/fb2c_enumeration_oracle.json` monitor
// bundle (a FULL-SCAN enumeration under the real SUBMITTER_KH against
// test.sigsum.org) into the CLI so COMPLETITUD becomes a REAL verdict, not the
// offline INCONCLUSIVE default. `consistency_proof` in the oracle is `[]`
// (degenerate), so the PACKAGE checkpoint MUST equal the oracle's `c_audit`.

/// The real submitter key_hash of the enumerated captured leaves — the genesis
/// of the round-trip (overwrites the kit's `genesis_key_hash`).
const SUBMITTER_KH: &str = "b112398d0e531a2a1e49ac5a7e2d8d7cd80ab69485e7c97f36ad893ca543717d";

/// The `COMPLETITUD:` line of a `verify-anchor` run, ISOLATED.
///
/// The scope footer every run prints contains the words INCONCLUSIVE, FAILED and
/// CONFIRMED in prose, so `combined.contains("INCONCLUSIVE")` is satisfied by a run
/// whose verdict is the exact opposite - measured: a mutant that made every
/// undecided case pass silently left the assertion green. Assert on the line.
/// The verdict CLASS on that line: the first word after `COMPLETITUD:`.
///
/// Read positionally on purpose. `contains("CONFIRMED")` is satisfied by the scope
/// footer, which names all three classes in prose, and by any reason string that
/// mentions one - measured twice: once by the footer (a mutant that turned every
/// verdict INCONCLUSIVE left the whole e2e layer green) and once by a mutant whose
/// own replacement text carried the word it was hiding.
fn completitud_class(combined: &str) -> String {
    let line = completitud_line(combined);
    let (_, after) = line
        .split_once("COMPLETITUD:")
        .unwrap_or_else(|| panic!("no COMPLETITUD verdict in: {line}"));
    after
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string()
}

fn completitud_line(combined: &str) -> String {
    combined
        .lines()
        .find(|l| l.trim_start().starts_with("COMPLETITUD"))
        .unwrap_or_else(|| panic!("no COMPLETITUD line in: {combined}"))
        .to_string()
}

fn fb2c_oracle_path() -> std::path::PathBuf {
    // The frozen enumeration oracle ships WITH the crate (tests/fixtures/), so
    // this e2e runs identically in the private tree and in the exported public
    // tree — a path outside the crate would silently drop the --monitor
    // coverage from the published artifact.
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/fb2c_enumeration_oracle.json")
}
fn fb2c_oracle_value() -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(fb2c_oracle_path()).unwrap()).unwrap()
}

/// The committed oracle minus its FORGED RETIRED leaf (`ordinal_final=128` with no
/// enumerated `head@128`).
///
/// That leaf is a real, unrelated `G-v6-11` finding which used to be MASKED, because
/// the truncation rule returned before R6 ever ran. Tests about the truncation rule
/// drop it so they isolate the question they are about; the remaining leaves'
/// inclusion proofs are per-leaf under `c_audit` and stay valid.
fn oracle_without_forged_retired() -> serde_json::Value {
    let mut m = fb2c_oracle_value();
    let kept: Vec<serde_json::Value> = m["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["lane"]["kind"] != "retired")
        .cloned()
        .collect();
    m["leaves"] = serde_json::Value::Array(kept);
    m
}

/// Test 1: the real oracle round-trip, WITHOUT the chain export: the monitor's real
/// enumeration carries HEAD@42 while the package publishes 3 rows. That is the
/// LIVE steady state of a producer that submits heads faster than it packages, and
/// from the package alone it is indistinguishable from a truncation, so it is a NAMED
/// INCONCLUSIVE that points at `--chain`, and exit stays 0 (an INCONCLUSIVE never
/// drives the exit code, AUDITOR_KIT section 7.1). Test 1b is the same run WITH
/// the export, where it becomes the FAILED it always should have been.
///
/// INTENT (test_intent_): a verifier must not accuse on an observation it cannot
/// distinguish from honest behaviour. CONTEXT: until 2026-08-26 this very e2e
/// asserted exit 1 and the truncation banner; the defect had been frozen into the
/// suite. EXPIRES IF: anchor packages stop being snapshots that can lag the log.
#[test]
fn test_intent_verify_anchor_lag_without_chain_is_inconclusive_exit_0() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    let mut a = valid_anchor_json_value("example-tenant");
    a["checkpoint"] = fb2c_oracle_value()["c_audit"].clone();
    let mut k = valid_kit_json_value("example-tenant");
    k["genesis_key_hash"] = serde_json::json!(SUBMITTER_KH);
    write(&anchor, &a);
    write(&kit, &k);
    // The committed oracle is now pure wire-schema, so feed it RAW to the CLI —
    // exactly the file a real monitor emits and an auditor consumes unmodified.
    let monitor = tmp.path().join("monitor.json");
    write(&monitor, &oracle_without_forged_retired());
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
        "--monitor",
        monitor.to_str().unwrap(),
    ]);
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    // No accusation, and no silent pass either: the exit code stays 0 because
    // COMPLETITUD is INCONCLUSIVE, and the auditor is told WHICH input decides it.
    assert_eq!(
        out.status.code(),
        Some(0),
        "an undecidable lag must not be an accusation; combined={combined}"
    );
    let verdict = completitud_line(&combined);
    assert!(
        completitud_class(&combined) == "INCONCLUSIVE" && verdict.contains("G-v6-2 UNDECIDED"),
        "COMPLETITUD must be reported INCONCLUSIVE and NAMED: {verdict}"
    );
    assert!(
        verdict.contains("--chain"),
        "the INCONCLUSIVE must name the input that decides it: {verdict}"
    );
    assert!(
        !combined.contains("rows were truncated while their tail leaf stays in the log"),
        "the truncation accusation must NOT be made on the package alone: {combined}"
    );
    // The banner must say which reference the rule actually judged against, or an
    // absent deciding input reads exactly like a present one.
    assert!(
        combined.contains("truncation reference:    package rows only"),
        "the run must surface that it had no chain export: {combined}"
    );
    assert!(
        !combined.to_ascii_uppercase().contains("VERIFIED"),
        "reserved token leaked: {combined}"
    );
}

/// A chain export built from the SAME rows a package carries: the file
/// `trust.seetrex.com/<slug>-chain.json` serves, in the shape
/// `parse_and_verify_package_rows` gates (every SHA-256 link recomputed).
/// `len` rows, so a shorter one is a producer that DELETED its tail.
fn chain_export_json_value(len: u32) -> serde_json::Value {
    let mut chain = Vec::new();
    let mut prev: Option<String> = None;
    for ordinal in 1..=len {
        let verdict_hash = format!("{ordinal:064x}");
        let chain_hash = compute_chain_hash(prev.as_deref(), &verdict_hash);
        chain.push(serde_json::json!({
            "ordinal": ordinal,
            "verdict_id": "00000000-0000-0000-0000-000000000000",
            "verdict_hash": verdict_hash,
            "chain_prev_hash": prev.clone(),
            "chain_hash": chain_hash.clone(),
            "appended_at": "2026-07-22T12:00:00Z",
            "ruleset_id": "demo",
            "verdict_outcome": "SATISFIED",
        }));
        prev = Some(chain_hash);
    }
    serde_json::json!({"schema_version": "1.0", "chain": chain})
}

/// A VALID `len`-row export that agrees with [`chain_export_json_value`] up to
/// `k - 1` and diverges from row `k` on - a well-formed chain with other content,
/// which is what a producer republishing a rewritten history serves.
fn chain_export_json_value_diverging_at(len: u32, k: u32) -> serde_json::Value {
    let mut chain = Vec::new();
    let mut prev: Option<String> = None;
    for ordinal in 1..=len {
        let verdict_hash = if ordinal < k {
            format!("{ordinal:064x}")
        } else {
            format!("{:064x}", ordinal + 1_000_000)
        };
        let chain_hash = compute_chain_hash(prev.as_deref(), &verdict_hash);
        chain.push(serde_json::json!({
            "ordinal": ordinal,
            "verdict_id": "00000000-0000-0000-0000-000000000000",
            "verdict_hash": verdict_hash,
            "chain_prev_hash": prev.clone(),
            "chain_hash": chain_hash.clone(),
            "appended_at": "2026-07-22T12:00:00Z",
            "ruleset_id": "demo",
            "verdict_outcome": "SATISFIED",
        }));
        prev = Some(chain_hash);
    }
    serde_json::json!({"schema_version": "1.0", "chain": chain})
}

/// Test 1b: the SAME package, kit and oracle as test 1, plus the producer's
/// published chain export. Now the question is decided: HEAD@42 is beyond the
/// EXPORT's own rows, so the rows really were deleted while their tail leaf stayed
/// in the log, so it FAILS under the same discriminant `G-v6-2`, exit 1.
///
/// INTENT (test_intent_): removing the false accusation must not remove the true
/// one. CONTEXT: the fix moved R1's reference off `pkg.rows`; a reference that
/// could only ever GROW would have bought a truncating producer permanent silence.
/// EXPIRES IF: G-v6-2 is retired from the rule set.
#[test]
fn test_intent_verify_anchor_real_truncation_with_chain_fails_exit_1() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    let chain = tmp.path().join("chain.json");
    let mut a = valid_anchor_json_value("example-tenant");
    a["checkpoint"] = fb2c_oracle_value()["c_audit"].clone();
    let mut k = valid_kit_json_value("example-tenant");
    k["genesis_key_hash"] = serde_json::json!(SUBMITTER_KH);
    write(&anchor, &a);
    write(&kit, &k);
    // The producer's CURRENT export: 3 rows, the same 3 the package carries. The
    // log holds head@42.
    write(&chain, &chain_export_json_value(3));
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
        "--monitor",
        fb2c_oracle_path().to_str().unwrap(),
        "--chain",
        chain.to_str().unwrap(),
    ]);
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert_eq!(
        out.status.code(),
        Some(1),
        "a decided truncation must downgrade the vacuous pass; combined={combined}"
    );
    let verdict = completitud_line(&combined);
    assert!(
        completitud_class(&combined) == "FAILED",
        "real COMPLETITUD verdict missing: {verdict}"
    );
    // Pin a distinctive substring of the REAL rule-failure reason so this test
    // distinguishes a genuine COMPLETITUD RULE failure (G-v6-2: the tail leaf is
    // still in the log while the published chain no longer explains it) from a mere
    // auth/plumbing failure that would also print "FAILED". Stable across oracle
    // regen (independent of tree size / leaf indices).
    assert!(
        verdict.contains("rows were truncated while their tail leaf stays in the log"),
        "expected the real G-v6-2 truncation reason, got: {verdict}"
    );
    assert!(
        combined.contains(
            "truncation reference:    published chain export, 3 rows (package 3; reference N=3)"
        ),
        "the run must surface the reference it decided against, in full: {combined}"
    );
    assert!(
        !combined.to_ascii_uppercase().contains("VERIFIED"),
        "reserved token leaked: {combined}"
    );
}

/// Test 1c: the evasion `--chain` opens, closed. A producer that DELETED rows
/// could try to re-lengthen its export past the anchored head; length alone would
/// then absolve it. Here the export reaches row 42 but its row 42 is not the row
/// the log attests, and the run FAILS on `G-v6-3` instead of passing: the flag can
/// raise the row count a head is explained by, never explain the head itself.
///
/// INTENT (test_intent_): a producer-published input admitted into a rule must not
/// become a mute button for that rule. CONTEXT: `--chain` is producer material; the
/// per-row `chain_hash` comparison is the only thing standing between it and a
/// silenced G-v6-2. EXPIRES IF: the export stops carrying per-row `chain_hash`.
#[test]
fn test_intent_relengthened_chain_export_cannot_absolve_a_head() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    let chain = tmp.path().join("chain.json");
    let mut a = valid_anchor_json_value("example-tenant");
    a["checkpoint"] = fb2c_oracle_value()["c_audit"].clone();
    let mut k = valid_kit_json_value("example-tenant");
    k["genesis_key_hash"] = serde_json::json!(SUBMITTER_KH);
    write(&anchor, &a);
    write(&kit, &k);
    write(&chain, &chain_export_json_value(42));
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
        "--monitor",
        fb2c_oracle_path().to_str().unwrap(),
        "--chain",
        chain.to_str().unwrap(),
    ]);
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert_eq!(
        out.status.code(),
        Some(1),
        "a re-lengthened export must not buy silence; combined={combined}"
    );
    let verdict = completitud_line(&combined);
    assert!(
        completitud_class(&combined) == "FAILED"
            && verdict.contains("G-v6-3")
            && verdict.contains("published chain export at row 42"),
        "the export's own row must be what refuses it: {verdict}"
    );
    // The WHOLE rendering, including `reference N`. Asserting only the prefix left
    // the one field that carries the arithmetic unmeasured: swapping
    // `r.reference_rows` for `r.package_rows` here printed `reference N=3` on a run
    // decided against 42 and the entire suite stayed green.
    assert!(
        combined.contains(
            "truncation reference:    published chain export, 42 rows (package 3; reference N=42)"
        ),
        "the run must surface the reference it decided against, in full: {combined}"
    );
}

/// The reference an export produces can only RISE - asserted on a run where
/// COMPLETITUD actually ran, and against the number the LIBRARY reports.
///
/// INTENT (test_intent_): `G-v6-2` asserts a row VANISHED from the producer's
/// publication; the anchor package IS a producer publication, so the reference is
/// `max(package, export)` and an export SHORTER than the package lowers nothing.
/// CONTEXT: measured on the live artefacts - package N=12, the published 40-row
/// export truncated to its first 11 rows (an ordinary stale download) ->
/// `FAILED ... HEAD@12 ...`, exit 1, in the same run that printed
/// `CONSISTENCIA CONFIRMED OFFLINE` over the package publishing row 12. The
/// PREDECESSOR of this test ran without `--monitor`, so COMPLETITUD was never
/// evaluated and the whole e2e layer stayed green with the defect re-installed in
/// the library.
/// EXPIRES IF: the anchor package stops being a producer publication.
#[test]
fn test_intent_verify_anchor_reference_rises_never_falls() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    let chain = tmp.path().join("chain.json");
    let monitor = tmp.path().join("monitor.json");
    let mut a = valid_anchor_json_value("example-tenant");
    a["checkpoint"] = fb2c_oracle_value()["c_audit"].clone();
    let mut k = valid_kit_json_value("example-tenant");
    k["genesis_key_hash"] = serde_json::json!(SUBMITTER_KH);
    write(&anchor, &a);
    write(&kit, &k);
    write(&monitor, &oracle_without_forged_retired());

    // (1) FALLS? No. A SHORTER export (2 rows) must not lower the reference below the
    // package's own 3.
    write(&chain, &chain_export_json_value(2));
    let shorter = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
        "--monitor",
        monitor.to_str().unwrap(),
        "--chain",
        chain.to_str().unwrap(),
    ]);
    let combined = format!("{}{}", stdout(&shorter), stderr(&shorter));
    // HEAD@42 is beyond BOTH artefacts, so the accusation here is honest.
    assert_eq!(completitud_class(&combined), "FAILED", "combined={combined}");
    assert!(
        combined.contains("(package 3; reference N=3)"),
        "the shorter export must not lower the reference: {combined}"
    );

    // (2) RISES. The half the predecessor's NAME promised and its fixture never
    // contained: a LONGER export (9 rows) must raise the reference above the
    // package's 3. Without a case where package != reference, every assertion on
    // this line is satisfied by printing the package count.
    write(&chain, &chain_export_json_value(9));
    let longer = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
        "--monitor",
        monitor.to_str().unwrap(),
        "--chain",
        chain.to_str().unwrap(),
    ]);
    let combined = format!("{}{}", stdout(&longer), stderr(&longer));
    assert!(
        combined.contains(
            "truncation reference:    published chain export, 9 rows (package 3; reference N=9)"
        ),
        "an admitted longer export must RAISE the reference: {combined}"
    );
}

/// A `--chain` export that CONTRADICTS the package over their overlap is DECLINED,
/// not accused on - and the auditor is told so on the COMPLETITUD line.
#[test]
fn verify_anchor_contradictory_chain_export_is_declined() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    let chain = tmp.path().join("chain.json");
    let monitor = tmp.path().join("monitor.json");
    let mut a = valid_anchor_json_value("example-tenant");
    a["checkpoint"] = fb2c_oracle_value()["c_audit"].clone();
    let mut k = valid_kit_json_value("example-tenant");
    k["genesis_key_hash"] = serde_json::json!(SUBMITTER_KH);
    write(&anchor, &a);
    write(&kit, &k);
    write(&chain, &chain_export_json_value_diverging_at(4, 2));
    write(&monitor, &oracle_without_forged_retired());
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
        "--monitor",
        monitor.to_str().unwrap(),
        "--chain",
        chain.to_str().unwrap(),
    ]);
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    let verdict = completitud_line(&combined);
    assert!(
        completitud_class(&combined) == "INCONCLUSIVE" && verdict.contains("DECLINED"),
        "a contradictory export must be declined, not accused on: {verdict}"
    );
    assert_eq!(out.status.code(), Some(0), "combined={combined}");
}

/// I-1: the line EVERY invocation without `--monitor` prints - the DEFAULT case -
/// must say the truncation rule was not reached, and must not invent a row count.
///
/// Replacing that branch with `"package rows only, 0 rows (...)"` - a false claim
/// about the package - left the whole suite green.
#[test]
fn test_intent_verify_anchor_without_monitor_says_the_rule_was_not_reached() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    write(&anchor, &valid_anchor_json_value("example-tenant"));
    write(&kit, &valid_kit_json_value("example-tenant"));
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
    ]);
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert_eq!(out.status.code(), Some(0), "combined={combined}");
    assert!(
        combined.contains("truncation reference:    not evaluated (the truncation rule was \
                           not reached)"),
        "the default line must say the rule was not reached: {combined}"
    );
    assert!(
        !combined.contains("rows only"),
        "no row count may be claimed when the rule never ran: {combined}"
    );
}

/// M-2: `--chain` without `--monitor` is read and verified, then decides nothing.
/// It must be ACKNOWLEDGED, not silently discarded.
#[test]
fn test_intent_verify_anchor_chain_without_monitor_is_acknowledged() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    let chain = tmp.path().join("chain.json");
    write(&anchor, &valid_anchor_json_value("example-tenant"));
    write(&kit, &valid_kit_json_value("example-tenant"));
    write(&chain, &chain_export_json_value(9));
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
        "--chain",
        chain.to_str().unwrap(),
    ]);
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert_eq!(out.status.code(), Some(0), "combined={combined}");
    assert!(
        combined.contains(
            "--chain was supplied and its links recomputed, but it DECIDES NOTHING without \
             --monitor (whether it AGREES with the package is only checked when the rule \
             runs)"
        ),
        "a supplied input that decides nothing must be named, without overstating what \
         ran on it: {combined}"
    );
}

/// I-2: COMPLETITUD can produce a verdict (it can FAIL on `C_audit` authentication)
/// without ever reaching the truncation rule. The line beside it must not read as a
/// contradiction of the verdict printed next to it.
#[test]
fn verify_anchor_completitud_failed_before_the_truncation_rule_says_so() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    let monitor = tmp.path().join("monitor.json");
    let mut a = valid_anchor_json_value("example-tenant");
    a["checkpoint"] = fb2c_oracle_value()["c_audit"].clone();
    let mut k = valid_kit_json_value("example-tenant");
    k["genesis_key_hash"] = serde_json::json!(SUBMITTER_KH);
    write(&anchor, &a);
    write(&kit, &k);
    // Falsify the monitor's own C_audit log signature: COMPLETITUD FAILS at
    // authentication, above the truncation rule.
    let mut m = oracle_without_forged_retired();
    m["c_audit"]["log_signature"] = serde_json::json!("00".repeat(64));
    write(&monitor, &m);
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
        "--monitor",
        monitor.to_str().unwrap(),
    ]);
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert_eq!(completitud_class(&combined), "FAILED", "combined={combined}");
    assert!(
        combined.contains("not evaluated (the truncation rule was not reached)"),
        "must scope the skip to the RULE, not to COMPLETITUD: {combined}"
    );
    assert!(
        !combined.contains("COMPLETITUD's rules did not run"),
        "the line must not contradict the COMPLETITUD verdict beside it: {combined}"
    );
}

/// C-1: a DECLINED export contributes NOTHING - not to the rules, and not to what
/// the auditor is told the rules used.
///
/// INTENT (test_intent_): the reference the auditor reads must be the reference the
/// rule used. It is not derivable from the inputs a caller holds, so it comes out of
/// the library and is never recomputed.
/// CONTEXT: measured on the clean tree - a live 41-row export diverging from the
/// package at row 3 was DECLINED, the rule judged against N=12, and the banner said
/// `truncation reference: published chain export, 41 rows (package 12; reference
/// N=41)`, because the bin re-derived `max(supplied, package)` itself.
/// EXPIRES IF: a declined export starts contributing to the reference (it must not).
#[test]
fn test_intent_verify_anchor_declined_export_is_never_shown_as_the_reference() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    let chain = tmp.path().join("chain.json");
    let monitor = tmp.path().join("monitor.json");
    let mut a = valid_anchor_json_value("example-tenant");
    a["checkpoint"] = fb2c_oracle_value()["c_audit"].clone();
    let mut k = valid_kit_json_value("example-tenant");
    k["genesis_key_hash"] = serde_json::json!(SUBMITTER_KH);
    write(&anchor, &a);
    write(&kit, &k);
    // A 4-row export that contradicts the 3-row package from row 2 on.
    write(&chain, &chain_export_json_value_diverging_at(4, 2));
    write(&monitor, &oracle_without_forged_retired());
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
        "--monitor",
        monitor.to_str().unwrap(),
        "--chain",
        chain.to_str().unwrap(),
    ]);
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    // The reviewer's guard, verbatim: the declined export's own count must never be
    // reported as the reference.
    assert!(
        !combined.contains("reference N=4"),
        "a DECLINED export was reported as the reference: {combined}"
    );
    assert!(
        combined.contains("DECLINED (4 rows, not used)") && combined.contains("reference N=3"),
        "the banner must say the export was refused and show the reference used: {combined}"
    );
}

/// C-2: a DECLINED export must not SUPPRESS the enumeration finding underneath it.
///
/// INTENT (test_intent_): supplying a contradictory export must never be WORSE for
/// the auditor than supplying none - that floor is the whole justification for
/// declining rather than accusing. The producer controls the published export, so if
/// a decline could swallow the enumeration note, the producer would control whether
/// the auditor ever sees it.
/// CONTEXT: measured - same anchor, kit and monitor, only `--chain` differing.
/// Without it: `INCONCLUSIVE - monitor enumerates HEAD@42, beyond the anchor
/// package's N=3 rows ... (G-v6-2 UNDECIDED)`. With a contradictory export: the
/// decline reason, and `HEAD@42` GONE - because the decline note was installed first
/// and `get_or_insert` keeps the first.
/// EXPIRES IF: undecided rules stop accumulating.
#[test]
fn test_intent_verify_anchor_declined_export_does_not_suppress_the_enumeration() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    let chain = tmp.path().join("chain.json");
    let monitor = tmp.path().join("monitor.json");
    let mut a = valid_anchor_json_value("example-tenant");
    a["checkpoint"] = fb2c_oracle_value()["c_audit"].clone();
    let mut k = valid_kit_json_value("example-tenant");
    k["genesis_key_hash"] = serde_json::json!(SUBMITTER_KH);
    write(&anchor, &a);
    write(&kit, &k);
    write(&chain, &chain_export_json_value_diverging_at(4, 2));
    write(&monitor, &oracle_without_forged_retired());
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
        "--monitor",
        monitor.to_str().unwrap(),
        "--chain",
        chain.to_str().unwrap(),
    ]);
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    let verdict = completitud_line(&combined);
    assert_eq!(completitud_class(&combined), "INCONCLUSIVE", "combined={combined}");
    assert!(
        verdict.contains("HEAD@42"),
        "the enumeration finding must survive the decline: {verdict}"
    );
    assert!(
        verdict.contains("DECLINED") && verdict.contains("ALSO UNDECIDED"),
        "both undecided rules must reach the auditor: {verdict}"
    );
    // ORDER, not just presence: the enumeration finding is the substantive
    // observation and a refused export is the EXPLANATION of why it could not be
    // resolved. Permuting the ledger to `[declined, lag, retired]` left every
    // presence assertion green while a reader of the first clause was back to
    // reading the decline as the finding.
    assert!(
        verdict.find("HEAD@").unwrap() < verdict.find("DECLINED").unwrap(),
        "the enumeration finding must come FIRST, the decline after it: {verdict}"
    );
    assert_eq!(out.status.code(), Some(0), "combined={combined}");
}

/// I-3: the repeated-flag refusal covers the TRUSTED side of the boundary too.
/// `--kit` supplies the tenant, genesis and witness policy; last-wins there would
/// let argument order choose which pins judge the package.
#[test]
fn test_intent_verify_anchor_repeated_kit_and_monitor_are_usage_errors() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let k1 = tmp.path().join("k1.json");
    let k2 = tmp.path().join("k2.json");
    let monitor = tmp.path().join("m.json");
    write(&anchor, &valid_anchor_json_value("example-tenant"));
    write(&k1, &valid_kit_json_value("example-tenant"));
    let mut other = valid_kit_json_value("example-tenant");
    other["genesis_key_hash"] = serde_json::json!(SUBMITTER_KH);
    write(&k2, &other);
    write(&monitor, &fb2c_oracle_value());
    let repeated_kit = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        k1.to_str().unwrap(),
        "--kit",
        k2.to_str().unwrap(),
    ]);
    assert_eq!(
        repeated_kit.status.code(),
        Some(2),
        "argument order must not choose the PINS: {}",
        stderr(&repeated_kit)
    );
    assert!(stderr(&repeated_kit).contains("--kit was supplied twice"));
    let repeated_monitor = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        k1.to_str().unwrap(),
        "--monitor",
        monitor.to_str().unwrap(),
        "--monitor",
        monitor.to_str().unwrap(),
    ]);
    assert_eq!(repeated_monitor.status.code(), Some(2));
    assert!(stderr(&repeated_monitor).contains("--monitor was supplied twice"));
}

/// A repeated `--chain` is a USAGE error: last-wins let argument ORDER decide an
/// accusation.
#[test]
fn test_intent_verify_anchor_repeated_chain_is_usage_error() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    let c1 = tmp.path().join("c1.json");
    let c2 = tmp.path().join("c2.json");
    write(&anchor, &valid_anchor_json_value("example-tenant"));
    write(&kit, &valid_kit_json_value("example-tenant"));
    write(&c1, &chain_export_json_value(42));
    write(&c2, &chain_export_json_value(3));
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
        "--chain",
        c1.to_str().unwrap(),
        "--chain",
        c2.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "argument order must not decide a verdict: {}",
        stderr(&out)
    );
}

/// A `--chain` export whose own SHA-256 links do not verify must never be allowed
/// to raise the row count a monitor head is explained by. It is VENDOR material
/// like the package, so it exits 1 (the package's class), not 2 (the kit's).
#[test]
fn verify_anchor_broken_chain_export_exits_1() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    let chain = tmp.path().join("chain.json");
    write(&anchor, &valid_anchor_json_value("example-tenant"));
    write(&kit, &valid_kit_json_value("example-tenant"));
    let mut c = chain_export_json_value(3);
    c["chain"][2]["chain_hash"] = serde_json::json!("00".repeat(32));
    write(&chain, &c);
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
        "--chain",
        chain.to_str().unwrap(),
    ]);
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert_eq!(
        out.status.code(),
        Some(1),
        "a non-verifying export is a vendor failure, exit 1: {combined}"
    );
    assert!(
        combined.contains("chain export does not verify offline"),
        "the refusal must say what was refused: {combined}"
    );
}

/// `--chain` is OPTIONAL: every invocation that predates it behaves EXACTLY as
/// before. Same package, same kit, no monitor: confirmed offline, exit 0, and
/// COMPLETITUD still the offline INCONCLUSIVE default.
#[test]
fn test_intent_verify_anchor_without_chain_is_unchanged() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    write(&anchor, &valid_anchor_json_value("example-tenant"));
    write(&kit, &valid_kit_json_value("example-tenant"));
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
    ]);
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert_eq!(out.status.code(), Some(0), "combined={combined}");
    assert!(
        combined.contains("Anchor package CONSISTENCIA CONFIRMED OFFLINE"),
        "the pre-existing no-monitor surface changed: {combined}"
    );
    assert!(
        completitud_class(&combined) == "INCONCLUSIVE",
        "COMPLETITUD must stay the offline INCONCLUSIVE default: {combined}"
    );
}

/// `--chain` without a value is the auditor's own usage error (exit 2), like
/// `--kit` and `--monitor`.
#[test]
fn verify_anchor_chain_without_value_is_usage_error() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    write(&anchor, &valid_anchor_json_value("example-tenant"));
    write(&kit, &valid_kit_json_value("example-tenant"));
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
        "--chain",
    ]);
    assert_eq!(out.status.code(), Some(2));
}

/// Test 2 — an empty honest monitor (enumerated NOTHING under our identity at
/// this C_audit) RAISES COMPLETITUD to CONFIRMED: nothing to contradict, and
/// the package anchored nothing either ⇒ no omission. Clean plumbing check.
#[test]
fn verify_anchor_empty_honest_monitor_confirms_completitud() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    let monitor = tmp.path().join("monitor.json");
    let c_audit = fb2c_oracle_value()["c_audit"].clone();
    let mut a = valid_anchor_json_value("example-tenant");
    a["checkpoint"] = c_audit.clone();
    write(&anchor, &a);
    write(&kit, &valid_kit_json_value("example-tenant"));
    // C_audit == package checkpoint ⇒ degenerate consistency (empty proof).
    write(
        &monitor,
        &serde_json::json!({
            "version": "seetrex/anchor-monitor/v1",
            "c_audit": c_audit,
            "leaves": [],
            "consistency_proof": [],
            "observations": [],
        }),
    );
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
        "--monitor",
        monitor.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "empty honest monitor must confirm; stderr={}",
        stderr(&out)
    );
    let so = stdout(&out);
    assert!(
        completitud_class(&so) == "CONFIRMED",
        "COMPLETITUD not raised to confirmed: {so}"
    );
    assert!(!so.to_ascii_uppercase().contains("VERIFIED"), "reserved token leaked: {so}");
}

/// Test 3 — a malformed monitor bundle is the AUDITOR's own config error ⇒
/// exit 2 (kept distinct from exit 1, a vendor-package failure).
#[test]
fn verify_anchor_malformed_monitor_exits_2() {
    let tmp = tempdir();
    let anchor = tmp.path().join("anchor.json");
    let kit = tmp.path().join("kit.json");
    let monitor = tmp.path().join("monitor.json");
    write(&anchor, &valid_anchor_json_value("example-tenant"));
    write(&kit, &valid_kit_json_value("example-tenant"));
    std::fs::write(&monitor, b"{not valid json").unwrap();
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
        "--monitor",
        monitor.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "malformed monitor bundle is an auditor CONFIG error → exit 2; stderr={}",
        stderr(&out)
    );
    assert!(
        !format!("{}{}", stdout(&out), stderr(&out))
            .to_ascii_uppercase()
            .contains("VERIFIED"),
        "reserved token leaked: {}",
        stderr(&out)
    );
}

// ─── emit-sbom / verify-sbom (SPEC_SBOM_CANONICAL_V1.md sections 6-7) ────
//
// These pin the CLI CONTRACT of the two SBOM arms — argument parsing, the
// output vocabulary and the exit codes — over the REAL binary and REAL
// files. The projection itself is exercised by the library tests and by
// the frozen corpus; what only a spawned process can show is that the
// bytes reach a FILE unchanged, that `sha256sum` over that file
// reproduces the digest the tool printed, and that the exit code an
// auditor's script gates on is the one the specification names.

/// The specification's own normative cargo lockfile (section 6.2),
/// written into a temporary directory by the tests that need a subject
/// with two versions of one name and a non-top-level edge.
const REFERENCE_LOCKFILE: &str = r#"version = 4

[[package]]
name = "demo-app"
version = "0.2.0"
dependencies = [
 "leaf 0.2.0",
 "midlib",
]

[[package]]
name = "leaf"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

[[package]]
name = "leaf"
version = "0.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"

[[package]]
name = "midlib"
version = "0.3.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
dependencies = [
 "leaf 0.1.0",
]
"#;

/// The subject the specification supplies for that lockfile.
const REFERENCE_SUBJECT: &str = "pkg:cargo/demo-app@0.2.0";

/// A committed fixture of the SBOM corpus, by absolute path.
fn sbom_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sbom")
        .join(name)
}

fn as_str(path: &Path) -> String {
    path.to_str().expect("test paths are UTF-8").to_string()
}

/// Spawn the binary with owned arguments.
fn run_owned(args: &[String]) -> Output {
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&borrowed)
}

/// Write the specification's reference lockfile into `dir` and return it.
fn reference_lockfile(dir: &Path) -> PathBuf {
    let path = dir.join("Cargo.lock");
    std::fs::write(&path, REFERENCE_LOCKFILE).expect("write the reference lockfile");
    path
}

/// `emit-sbom` over the reference lockfile; returns the written path and
/// the digest the tool printed on stdout.
fn emit_reference(dir: &Path, lockfile: &Path, out_name: &str) -> (PathBuf, String) {
    let out = dir.join(out_name);
    let output = run_owned(&[
        "emit-sbom".to_string(),
        "--kind".to_string(),
        "cargo".to_string(),
        "--lockfile".to_string(),
        as_str(lockfile),
        "--subject".to_string(),
        REFERENCE_SUBJECT.to_string(),
        "--out".to_string(),
        as_str(&out),
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "emit-sbom must exit 0; stderr: {}",
        stderr(&output)
    );
    (out, stdout(&output).trim().to_string())
}

/// `verify-sbom` over the reference lockfile with extra flags appended.
fn verify_reference(lockfile: &Path, sbom: &Path, extra: &[&str]) -> Output {
    let mut args = vec![
        "verify-sbom".to_string(),
        "--kind".to_string(),
        "cargo".to_string(),
        "--lockfile".to_string(),
        as_str(lockfile),
        "--subject".to_string(),
        REFERENCE_SUBJECT.to_string(),
        "--sbom".to_string(),
        as_str(sbom),
    ];
    args.extend(extra.iter().map(|flag| (*flag).to_string()));
    run_owned(&args)
}

/// Read a canonical SBOM back as a mutable JSON document.
fn read_document(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).expect("read the emitted SBOM");
    serde_json::from_slice(&bytes).expect("the emitted SBOM is JSON")
}

/// Write a document back in the canonical form the strict path demands.
fn write_canonical(path: &Path, document: &serde_json::Value) {
    let bytes = seetrex_format::hashing::canonicalize(document).expect("canonicalize");
    std::fs::write(path, bytes.as_bytes()).expect("write the canonical document");
}

/// INTENT: `emit-sbom` is a PURE PROJECTION reaching a file: two runs over
///         one lockfile write the same bytes, the digest it prints is the
///         digest of those bytes (so `sha256sum <out>` reproduces it with
///         stock coreutils), the file carries NO trailing newline, and the
///         bytes are the ones the committed corpus froze — measured
///         through the spawned binary, not through the library.
/// CONTEXT: the whole value of a canonical projection is that an auditor
///          re-derives the published document and compares byte for byte;
///          a producer that appended a newline, or printed a digest of
///          something other than the file, would break that silently.
/// EXPIRES IF: the projection is versioned (then the corpus pin moves in
///             the same change, and this test follows it there).
/// MUTANT: append a newline to the written file, or print
///         `sha256(document)` of a re-serialization instead of the bytes.
#[test]
fn test_intent_emit_sbom_is_reproducible_and_hashes_with_stock_tooling() {
    let tmp = tempdir();
    let lockfile = sbom_fixture("cargo_lock_v3.lock");
    let subject = "pkg:cargo/example-app@1.2.3";

    let mut written: Vec<(Vec<u8>, String)> = Vec::new();
    for name in ["first.json", "second.json"] {
        let out = tmp.path().join(name);
        let output = run_owned(&[
            "emit-sbom".to_string(),
            "--kind".to_string(),
            "cargo".to_string(),
            "--lockfile".to_string(),
            as_str(&lockfile),
            "--subject".to_string(),
            subject.to_string(),
            "--out".to_string(),
            as_str(&out),
        ]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "emit-sbom must exit 0; stderr: {}",
            stderr(&output)
        );
        written.push((
            std::fs::read(&out).expect("read the emitted SBOM"),
            stdout(&output).trim().to_string(),
        ));
    }

    assert_eq!(
        written[0].0, written[1].0,
        "two emissions of one lockfile must write identical bytes"
    );
    assert!(
        !written[0].0.ends_with(b"\n"),
        "the file IS the canonical bytes: nothing is appended"
    );
    // stdout carries the digest and nothing else, so this equality is the
    // `sha256sum <file>` an auditor runs, computed with the same function
    // coreutils implements.
    assert_eq!(
        written[0].1,
        sha256_hex(&written[0].0),
        "the printed digest must be the digest of the written bytes"
    );
    assert_eq!(written[0].1, written[1].1, "the digest must reproduce");

    // The FROZEN corpus pin, re-used rather than duplicated: the binary
    // must produce the bytes the corpus already committed for this entry.
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(sbom_fixture("corpus/manifest.json")).expect("read the corpus manifest"),
    )
    .expect("the corpus manifest is JSON");
    let pinned = manifest["entries"]
        .as_array()
        .expect("the corpus manifest lists entries")
        .iter()
        .find(|entry| entry["id"] == "cargo-lock-v3")
        .and_then(|entry| entry["canonical_sha256"].as_str())
        .expect("the corpus pins cargo-lock-v3");
    assert_eq!(
        written[0].1, pinned,
        "the binary must produce the bytes the corpus froze"
    );
}

/// INTENT: the pair closes — what `emit-sbom` wrote, `verify-sbom` accepts
///         with exit 0, the FIXED banner and the SUBSTANTIVE counts. The
///         counts are printed because a match over zero components must
///         never read as a substantive approval.
/// CONTEXT: spec section 7.7; the same antidote already written for
///          `verify-anchor`, where a CONFIRMED over zero anchored leaves
///          is vacuous.
/// EXPIRES IF: never — it is an output-honesty rule.
/// MUTANT: drop the two count lines from the banner; change the banner
///         wording.
#[test]
fn test_scenario_emit_then_verify_sbom_closes_with_counts() {
    let tmp = tempdir();
    let lockfile = reference_lockfile(tmp.path());
    let (sbom, _) = emit_reference(tmp.path(), &lockfile, "sbom.json");

    let output = verify_reference(&lockfile, &sbom, &[]);
    let so = stdout(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the emitted document must verify; stderr: {}",
        stderr(&output)
    );
    assert!(
        so.contains("SBOM matches the lockfile projection"),
        "the fixed banner is missing: {so}"
    );
    assert!(
        so.contains("components: 3") && so.contains("top-level entries: 2"),
        "the substantive counts must be printed: {so}"
    );
}

/// INTENT: a document that is the RIGHT VALUE in the WRONG BYTES fails.
///         A pretty-printed copy of the emitted SBOM carries the same JSON
///         value and is rejected as `not-canonical`, with the byte offset
///         of the first divergence, exit 1.
/// CONTEXT: section 6.1 makes the canonical bytes the artifact; a verifier
///          that parsed and compared values would make canonicalization
///          pointless, and every re-serializing proxy would be invisible.
/// EXPIRES IF: the format stops pinning its own serialization.
/// MUTANT: compare parsed values instead of bytes; drop the offset.
#[test]
fn test_intent_verify_sbom_rejects_a_non_canonical_copy() {
    let tmp = tempdir();
    let lockfile = reference_lockfile(tmp.path());
    let (sbom, _) = emit_reference(tmp.path(), &lockfile, "sbom.json");

    let document = read_document(&sbom);
    let pretty = tmp.path().join("pretty.json");
    std::fs::write(
        &pretty,
        serde_json::to_vec_pretty(&document).expect("pretty-print"),
    )
    .expect("write the pretty copy");

    let output = verify_reference(&lockfile, &pretty, &[]);
    let se = stderr(&output);
    assert_eq!(output.status.code(), Some(1), "stdout: {}", stdout(&output));
    assert!(
        se.contains("error class: not-canonical"),
        "the error class must name the property violated: {se}"
    );
    assert!(
        se.contains("at byte "),
        "the first divergence offset must be reported: {se}"
    );
}

/// INTENT: a document whose component was edited fails with the FIELD
///         DIFFERENCE named — purl, field, both sides — never a bare
///         "does not match".
/// CONTEXT: spec section 7.3: the report is difference SETS, never a
///          summary judgement.
/// EXPIRES IF: never.
/// MUTANT: report only the verdict and drop the difference sets.
#[test]
fn test_intent_verify_sbom_reports_the_field_that_differs() {
    let tmp = tempdir();
    let lockfile = reference_lockfile(tmp.path());
    let (sbom, _) = emit_reference(tmp.path(), &lockfile, "sbom.json");

    let mut document = read_document(&sbom);
    document["components"][0]["version"] = serde_json::Value::String("9.9.9".to_string());
    let modified = tmp.path().join("modified.json");
    write_canonical(&modified, &document);

    let output = verify_reference(&lockfile, &modified, &[]);
    let so = stdout(&output);
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(so.contains("verdict: semantic-difference"), "{so}");
    assert!(
        so.contains("pkg:cargo/leaf@0.1.0 version: document `9.9.9`, projection `0.1.0`"),
        "the field difference must be named on both sides: {so}"
    );
}

/// INTENT: "the bytes differ and every difference set is empty" is its OWN
///         outcome and it FAILS. The document below adds a dependency node
///         for a reference that is not the supplied subject: every
///         difference set the comparison enumerates stays empty, and the
///         bytes still differ.
/// CONTEXT: spec section 7.3 — "An implementation MUST NOT report the
///          byte-identical verdict merely because the difference sets are
///          empty; collapsing the two makes canonicalisation pointless."
/// EXPIRES IF: the difference sets are extended to enumerate the whole
///             document, at which point this document reaches
///             `semantic-difference` and the test moves with it.
/// MUTANT: exit 0 on `DifferentBytesNoDifferenceSets`, i.e. gate the exit
///         code on `Comparison::is_match` instead of on the verdict.
#[test]
fn test_intent_verify_sbom_never_passes_on_empty_difference_sets_alone() {
    let tmp = tempdir();
    let lockfile = reference_lockfile(tmp.path());
    let (sbom, _) = emit_reference(tmp.path(), &lockfile, "sbom.json");

    let mut document = read_document(&sbom);
    document["dependencies"]
        .as_array_mut()
        .expect("the document declares a dependency graph")
        .push(serde_json::json!({
            "ref": "pkg:cargo/leaf@0.2.0",
            "dependsOn": []
        }));
    let widened = tmp.path().join("widened.json");
    write_canonical(&widened, &document);

    let output = verify_reference(&lockfile, &widened, &[]);
    let so = stdout(&output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "empty difference sets over differing bytes must FAIL; stdout: {so}"
    );
    assert!(
        so.contains("verdict: different-bytes-no-difference-sets"),
        "the third outcome must be named: {so}"
    );
    assert!(
        so.contains("empty difference sets are NOT a match: only byte identity is"),
        "the reason must be stated at the same volume as the verdict: {so}"
    );
    assert!(
        !so.contains("SBOM matches the lockfile projection"),
        "the fixed match banner must never appear here: {so}"
    );
}

/// INTENT: a document whose `metadata.component` claims to be another
///         product FAILS when the auditor supplies the legitimate
///         `--subject`. The subject is an INPUT and is never read back out
///         of the document under test.
/// CONTEXT: spec section 7.2 — the same principle as `--kit` in
///          `verify-anchor`: an artifact declaring what it is supposed to
///          be is evidence of nothing.
/// EXPIRES IF: it is decided (wrongly) that the document declares its own
///             subject.
/// MUTANT: read the subject from `metadata.component.purl` when
///         `--subject` is absent, or adopt the declared one when the two
///         disagree.
#[test]
fn test_intent_verify_sbom_rejects_a_forged_subject() {
    let tmp = tempdir();
    let lockfile = reference_lockfile(tmp.path());
    let (sbom, _) = emit_reference(tmp.path(), &lockfile, "sbom.json");

    let mut document = read_document(&sbom);
    document["metadata"]["component"]["name"] =
        serde_json::Value::String("other-product".to_string());
    let forged = tmp.path().join("forged.json");
    write_canonical(&forged, &document);

    let output = verify_reference(&lockfile, &forged, &[]);
    let so = stdout(&output);
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(so.contains("subject MISMATCH"), "{so}");
    assert!(
        so.contains("metadata.component.name: document `other-product`, projection `demo-app`"),
        "the forged field must be named on both sides: {so}"
    );
}

/// INTENT: `--third-party` is LENIENT and NEVER a match. It adapts a
///         foreign CycloneDX document by a fixed list of reductions, NAMES
///         every reduction it applied, prints the difference sets, and
///         exits 1 — including when the adapted document happens to reduce
///         to the projection exactly.
/// CONTEXT: spec section 7.4. The bytes compared on this path are the
///          ADAPTED ones, not the bytes the producer published, so byte
///          identity over them is not a statement about the artifact.
/// EXPIRES IF: the specification blesses a second strong verdict for
///             foreign documents (it forbids one today).
/// MUTANT: exit 0 when the adapted document matches; print the fixed match
///         banner on this path; adapt silently, without the list.
#[test]
fn test_intent_verify_sbom_third_party_never_claims_a_match() {
    let tmp = tempdir();
    let lockfile = reference_lockfile(tmp.path());
    let (sbom, _) = emit_reference(tmp.path(), &lockfile, "sbom.json");

    // 1. The specification's own third-party fixture: another vendor's
    //    tool, with a serialNumber, a timestamp, a tools block, licences
    //    and no digests.
    let foreign = sbom_fixture("compare/third_party_cyclonedx.json");
    let output = verify_reference(&lockfile, &foreign, &["--third-party"]);
    let so = stdout(&output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "the lenient path never passes; stderr: {}",
        stderr(&output)
    );
    assert!(
        so.contains("third-party comparison: LENIENT, and never a match"),
        "{so}"
    );
    assert!(
        so.contains("dropped top-level key `serialNumber`")
            && so.contains("dropped metadata key `timestamp`"),
        "every adaptation must be NAMED, not applied silently: {so}"
    );
    // FOUR, not three: the header counts DIFFERENCES, and this fixture
    // carries four of them across three components (a `licenses` block on
    // one of them, and a missing `hashes` on each). It read `(3)` while
    // printing four lines, which is a reader counting components and
    // calling them differences.
    assert!(
        so.contains("component field differences (4):") && so.contains("hashes: document absent"),
        "the difference sets are the report: {so}"
    );
    assert_eq!(
        so.matches("\n  pkg:cargo/").count(),
        4,
        "the header must count the printed difference lines, not the components: {so}"
    );
    assert!(
        !so.contains("SBOM matches the lockfile projection"),
        "the fixed match banner must never appear on the lenient path: {so}"
    );

    // 2. The CANONICAL document itself, fed to the lenient path: it needs
    //    no adaptation and reduces to the projection exactly, and it STILL
    //    exits 1 without the banner. This is the arm a "return 0 on match"
    //    mutation would flip.
    let output = verify_reference(&lockfile, &sbom, &["--third-party"]);
    let so = stdout(&output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "--third-party must not exit 0 even over the canonical document"
    );
    assert!(
        so.contains("this is NOT a match verdict"),
        "the non-verdict must be stated: {so}"
    );
    assert!(!so.contains("SBOM matches the lockfile projection"), "{so}");

    // 3. A file that is not JSON at all is the AUDITOR pointing at the
    //    wrong file, not a failing artifact: exit 2, not 1.
    let garbage = tmp.path().join("garbage.bin");
    std::fs::write(&garbage, b"\x00not json at all").expect("write the garbage file");
    let output = verify_reference(&lockfile, &garbage, &["--third-party"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "--third-party over a non-JSON file is a usage error; stderr: {}",
        stderr(&output)
    );
}

/// INTENT: `--third-party` REACHES the difference sets over a document of
///         the shape `cargo-cyclonedx` actually emits, and names the
///         reduction that made it reachable.
/// CONTEXT: spec section 7.4, reduction 6. That tool writes cargo
///          package-ids (`registry+https://...#name@version`,
///          `path+file:///...#name@version`) as `bom-ref` and a
///          `?download_url=` qualifier into the subject purl, so EVERY
///          document of its shape stopped at `bom-ref-not-purl` before one
///          difference set was computed: the lenient path was unreachable
///          for the tool an auditor is most likely to hold. The fixture's
///          shape was taken from a real `cargo cyclonedx --format json
///          --spec-version 1.5` run (0.5.9) over this workspace and
///          re-pointed at the reference lockfile's packages.
/// EXPIRES IF: `cargo-cyclonedx` starts writing purls as `bom-ref`, or the
///             specification withdraws reduction 6.
/// MUTANT: drop reduction 6 (the run stops at `bom-ref-not-purl`); rewrite
///         the component references but not the graph (the run stops at
///         `dangling-reference`); apply the rewrite without naming it.
#[test]
fn test_scenario_third_party_reaches_the_sets_on_a_cargo_cyclonedx_document() {
    let tmp = tempdir();
    let lockfile = reference_lockfile(tmp.path());
    let foreign = sbom_fixture("compare/cargo_cyclonedx_real_shape.json");

    let output = verify_reference(&lockfile, &foreign, &["--third-party"]);
    let so = stdout(&output);
    let se = stderr(&output);

    assert_eq!(
        output.status.code(),
        Some(1),
        "the lenient path never passes; stdout: {so}\nstderr: {se}"
    );
    assert!(
        !se.contains("bom-ref-not-purl") && !so.contains("bom-ref-not-purl"),
        "a real cargo-cyclonedx document must not be refused before the \
         comparison; stdout: {so}\nstderr: {se}"
    );
    assert!(
        !se.contains("dangling-reference") && !so.contains("dangling-reference"),
        "the reduction must carry the graph with it, not leave references \
         pointing at discarded identifiers; stdout: {so}\nstderr: {se}"
    );
    assert!(
        so.contains("bom-ref(s) rewritten from purl (foreign identifier discarded)"),
        "the sixth reduction must be NAMED, not applied silently: {so}"
    );
    assert!(
        so.contains("dropped top-level key `serialNumber`")
            && so.contains("dropped metadata key `timestamp`")
            && so.contains("dropped metadata key `tools`"),
        "the other reductions are reported too: {so}"
    );

    // The difference sets were REACHED: the qualified subject purl is
    // reported as a mismatch, the graph rooted at it is therefore missing
    // both of the auditor's top-level edges, and the metadata this
    // projection discards shows up as component field differences.
    assert!(
        so.contains("subject MISMATCH: document declares `pkg:cargo/demo-app@0.2.0?download_url="),
        "the qualified subject purl must be confronted, not adopted: {so}"
    );
    assert!(
        so.contains("top-level edges missing from the document (2):")
            && so.contains("pkg:cargo/leaf@0.2.0")
            && so.contains("pkg:cargo/midlib@0.3.0"),
        "the top-level edges are part of the comparison: {so}"
    );
    assert!(
        so.contains("component field differences (")
            && so.contains("author: document")
            && so.contains("licenses: document"),
        "the per-component differences are the report: {so}"
    );
    assert!(
        !so.contains("SBOM matches the lockfile projection"),
        "the fixed match banner must never appear on the lenient path: {so}"
    );
}

/// INTENT: the `--subject` purl type is the one `--kind` names, and a
///         mismatch is the AUDITOR's own error (exit 2) on BOTH
///         subcommands and in BOTH directions.
/// CONTEXT: spec section 5.5 states it as a MUST and nothing enforced it:
///          `emit-sbom --kind cargo --subject pkg:npm/...` wrote a
///          perfectly canonical document whose `metadata.component`
///          claimed an ecosystem its own components do not belong to and
///          exited 0, and `verify-sbom` answered the same typo with exit
///          1 -- the code reserved for "the vendor's artifact failed".
/// EXPIRES IF: the projection accepts a subject whose type is not its
///             lockfile's ecosystem.
/// MUTANT: remove the check -- `emit-sbom` exits 0 and writes the file,
///         `verify-sbom` exits 1.
#[test]
fn test_intent_sbom_subject_purl_type_must_match_the_kind() {
    let tmp = tempdir();
    let cargo_lock = reference_lockfile(tmp.path());
    let npm_lock = sbom_fixture("npm_lock_v2.json");
    let (sbom, _) = emit_reference(tmp.path(), &cargo_lock, "sbom.json");

    // (kind, lockfile, a subject of the WRONG ecosystem)
    let mismatches: [(&str, String, &str); 2] = [
        ("cargo", as_str(&cargo_lock), "pkg:npm/example-app@1.0.0"),
        ("npm", as_str(&npm_lock), "pkg:cargo/demo-app@0.2.0"),
    ];

    for (kind, lockfile, subject) in &mismatches {
        let out = tmp.path().join(format!("never-written-{kind}.json"));
        let output = run_owned(&[
            "emit-sbom".into(),
            "--kind".into(),
            (*kind).to_string(),
            "--lockfile".into(),
            lockfile.clone(),
            "--subject".into(),
            (*subject).to_string(),
            "--out".into(),
            as_str(&out),
        ]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "emit-sbom --kind {kind} accepted the subject {subject}; stderr: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("MUST match the lockfile kind"),
            "the message must name what is wrong: {}",
            stderr(&output)
        );
        assert!(
            !out.exists(),
            "a document was written for a subject of the wrong ecosystem"
        );

        let output = run_owned(&[
            "verify-sbom".into(),
            "--kind".into(),
            (*kind).to_string(),
            "--lockfile".into(),
            lockfile.clone(),
            "--subject".into(),
            (*subject).to_string(),
            "--sbom".into(),
            as_str(&sbom),
        ]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "verify-sbom answered the auditor's typo with a verification \
             code for --kind {kind}; stderr: {}",
            stderr(&output)
        );
    }

    // The control: the MATCHING direction still runs to a real verdict, so
    // the check above is a type comparison and not a blanket refusal.
    let out = tmp.path().join("npm.json");
    let output = run_owned(&[
        "emit-sbom".into(),
        "--kind".into(),
        "npm".into(),
        "--lockfile".into(),
        as_str(&npm_lock),
        "--subject".into(),
        "pkg:npm/example-app@1.0.0".into(),
        "--out".into(),
        as_str(&out),
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "an npm subject over an npm lockfile must still be accepted; stderr: {}",
        stderr(&output)
    );
    assert!(out.exists(), "the matching direction writes its document");
}

/// INTENT: the token `VERIFIED` is RESERVED for this product's strong
///         surfaces and `verify-sbom` is not one of them. Neither arm may
///         emit it — not in a banner, and not by echoing bytes the
///         document under test controls.
/// CONTEXT: spec section 7.7 and `package::sanitize_reserved_token`;
///          downstream tooling pattern-matches that substring as a strong
///          pass.
/// EXPIRES IF: the specification blesses `verify-sbom` as a strong
///             surface.
/// MUTANT: print `SBOM VERIFIED`; print the comparison report without
///         routing it through the sanitizer.
#[test]
fn test_intent_verify_sbom_never_emits_the_reserved_token() {
    let tmp = tempdir();
    let lockfile = reference_lockfile(tmp.path());
    let (sbom, _) = emit_reference(tmp.path(), &lockfile, "sbom.json");

    // The document names itself with the reserved token, in a field the
    // report is guaranteed to echo (the subject mismatch).
    let mut document = read_document(&sbom);
    document["metadata"]["component"]["name"] =
        serde_json::Value::String("VERIFIED-by-another-tool".to_string());
    let hostile = tmp.path().join("hostile.json");
    write_canonical(&hostile, &document);

    for extra in [&[] as &[&str], &["--third-party"]] {
        let output = verify_reference(&lockfile, &hostile, extra);
        let so = stdout(&output);
        let se = stderr(&output);
        assert_ne!(
            output.status.code(),
            Some(0),
            "a document naming itself with the reserved token must not pass"
        );
        assert!(
            !so.contains("VERIFIED") && !se.contains("VERIFIED"),
            "the reserved token leaked with {extra:?}\nstdout: {so}\nstderr: {se}"
        );
        // THREE sanitizers meet on this surface -- the comparison
        // module's, the projection module's and the binary's -- and they
        // now render ONE mask, with a legend on stderr saying what it
        // means. Several masks and no legend left a reader to guess
        // whether they were the same thing.
        assert!(
            so.contains("-by-another-tool") || se.contains("-by-another-tool"),
            "the echoed bytes must survive sanitization, not be dropped; \
             stdout: {so}\nstderr: {se}"
        );
        assert!(
            so.contains("VERIF[REDACTED]") || se.contains("VERIF[REDACTED]"),
            "the reserved token must be REPLACED, not merely absent; \
             stdout: {so}\nstderr: {se}"
        );
        assert_no_alternative_mask(&so, &se);
        assert!(
            se.contains("marks the reserved token redacted"),
            "a mask with no legend is an unexplained string in the middle \
             of evidence; stderr: {se}"
        );
    }

    // And the passing run says nothing of the kind either -- neither the
    // token, nor the mask, nor the legend that explains a mask that is not
    // there.
    let output = verify_reference(&lockfile, &sbom, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(!stdout(&output).contains("VERIFIED"));
    assert!(
        !stderr(&output).contains("marks the reserved token redacted"),
        "the legend was printed with no mask on screen: {}",
        stderr(&output)
    );
}

/// Every spelling of the reserved-token mask this product has ever
/// rendered, EXCEPT the one it renders now.
///
/// The guard used to forbid `[reserved-token]` alone -- a literal already
/// dead when it was written, since `sbom::compare` had been re-pointed at
/// the shared mask. The mask actually reaching a reader from a second
/// place was `sbom`'s own `<reserved token>`, on the `--subject` rejection
/// path, and no legend pointed at it: forbidding the dead literal
/// certified nothing about the live one.
const ALTERNATIVE_MASKS: [&str; 2] = ["[reserved-token]", "<reserved token>"];

fn assert_no_alternative_mask(so: &str, se: &str) {
    for mask in ALTERNATIVE_MASKS {
        assert!(
            !so.contains(mask) && !se.contains(mask),
            "a second, unexplained mask `{mask}` reached the surface; \
             stdout: {so}\nstderr: {se}"
        );
    }
}

/// INTENT: the `--subject` rejection path obeys the same output boundary
///         as the comparison path: ONE mask, and the legend that explains
///         it, on a surface that is not blessed to emit the token.
/// CONTEXT: a subject carrying the reserved token is refused by the purl
///         grammar of `sbom`, whose error used to render a mask of its own
///         (`<reserved token>`). The binary's boundary only recognises the
///         shared mask, so it never armed the legend, and an auditor met
///         an unexplained string in the middle of an error message.
/// EXPIRES IF: the specification blesses this surface as a strong one.
/// MUTANT: render a second mask from `sbom::redact_reserved`; drop the
///         `sanitize_reserved_token` wrapper from the projection leg.
#[test]
fn test_intent_subject_rejection_masks_once_and_prints_the_legend() {
    let tmp = tempdir();
    let lockfile = reference_lockfile(tmp.path());
    let (sbom, _) = emit_reference(tmp.path(), &lockfile, "sbom.json");

    for subcommand in ["verify-sbom", "emit-sbom"] {
        let out_path = tmp.path().join("never-written.json");
        let _ = std::fs::remove_file(&out_path);
        let mut args: Vec<String> = vec![
            subcommand.to_string(),
            "--kind".to_string(),
            "cargo".to_string(),
            "--lockfile".to_string(),
            lockfile.display().to_string(),
            "--subject".to_string(),
            "pkg:cargo/VERIFIED@0.2.0".to_string(),
        ];
        if subcommand == "verify-sbom" {
            args.push("--sbom".to_string());
            args.push(sbom.display().to_string());
        } else {
            args.push("--out".to_string());
            args.push(out_path.display().to_string());
        }
        let output = std::process::Command::new(bin())
            .args(&args)
            .output()
            .expect("spawn the verifier");
        let so = stdout(&output);
        let se = stderr(&output);

        assert_eq!(
            output.status.code(),
            Some(2),
            "a subject the grammar refuses is the AUDITOR's own input; \
             stdout: {so}\nstderr: {se}"
        );
        assert!(
            !so.to_ascii_uppercase().contains("VERIFIED")
                && !se.to_ascii_uppercase().contains("VERIFIED"),
            "the reserved token was echoed back out of the rejection; \
             stdout: {so}\nstderr: {se}"
        );
        assert!(
            se.contains("VERIF[REDACTED]"),
            "the token must be REPLACED by the ONE mask, not merely absent; \
             stderr: {se}"
        );
        assert_no_alternative_mask(&so, &se);
        assert!(
            se.contains("marks the reserved token redacted"),
            "a mask with no legend is an unexplained string in the middle of \
             evidence; stderr: {se}"
        );
        assert!(
            se.contains("error class: malformed-subject"),
            "the projection leg must report its failure by CLASS, like the \
             reader and binary legs do; stderr: {se}"
        );
    }
}

/// INTENT: `--dep-v0` confronts the projection with what the BINARY says
///         about itself, and keeps three outcomes apart: a pair the
///         projection does not account for is a FAILURE; a binary with no
///         section at all is NOT ATTESTED and still a failure, because a
///         check that was requested and could not be performed is not a
///         pass; components of the projection the binary does not carry
///         are INFORMATION.
/// CONTEXT: spec section 7.5. A lockfile covers a workspace and a
///          `.dep-v0` section covers one binary, so the containment is
///          one-directional by construction.
/// EXPIRES IF: the embedding tool changes the section name or payload
///             encoding.
/// MUTANT: exit 0 with a non-empty `missing` set; exit 0 on the absent
///         section; make `extra_in_projection` fatal.
#[test]
fn test_intent_verify_sbom_dep_v0_keeps_its_three_outcomes_apart() {
    let tmp = tempdir();
    let lockfile = reference_lockfile(tmp.path());
    let (sbom, _) = emit_reference(tmp.path(), &lockfile, "sbom.json");

    // 1. A binary carrying only pairs the projection accounts for. The
    //    projection has three components and the binary two, which is
    //    information, not a failure.
    let covered = tmp.path().join("covered.elf");
    std::fs::write(
        &covered,
        build_elf(&[
            (".text", b"\x90\x90\x90\x90"),
            (
                ".dep-v0",
                &zlib_stored(&dep_v0_document(&[("leaf", "0.2.0"), ("midlib", "0.3.0")])),
            ),
        ]),
    )
    .expect("write the covered image");
    let output = verify_reference(&lockfile, &sbom, &["--dep-v0", &as_str(&covered)]);
    let so = stdout(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a covered binary must not fail; stdout: {so}\nstderr: {}",
        stderr(&output)
    );
    assert!(
        so.contains("SBOM<->binary: missing from the projection (0):"),
        "{so}"
    );
    assert!(
        so.contains("components of the projection the binary does not carry: 1 (informational)"),
        "the one-directional containment must be stated as information: {so}"
    );
    // The banner is HELD until every requested check has passed, so on the
    // one arm that does pass it appears -- after the binary leg, not before
    // it.
    let banner = so
        .find("SBOM matches the lockfile projection")
        .unwrap_or_else(|| panic!("a passing run must still print the fixed banner: {so}"));
    let binary_leg = so
        .find("SBOM<->binary:")
        .expect("the binary leg was requested and reported");
    assert!(
        banner > binary_leg,
        "the banner was printed BEFORE the optional check it depends on: {so}"
    );

    // 2. A binary built from something the lockfile does not account for.
    let uncovered = tmp.path().join("uncovered.elf");
    std::fs::write(
        &uncovered,
        build_elf(&[(
            ".dep-v0",
            &zlib_stored(&dep_v0_document(&[
                ("leaf", "0.2.0"),
                ("ghostcrate", "9.9.9"),
            ])),
        )]),
    )
    .expect("write the uncovered image");
    let output = verify_reference(&lockfile, &sbom, &["--dep-v0", &as_str(&uncovered)]);
    let so = stdout(&output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a pair the projection does not carry is a failure; stdout: {so}"
    );
    assert!(
        !so.contains("SBOM matches the lockfile projection"),
        "the document IS the projection here, but the RUN failed: the fixed \
         banner of section 7.7 must not be on the stdout of an exit 1: {so}"
    );
    assert!(
        so.contains("SBOM<->binary: missing from the projection (1):")
            && so.contains("ghostcrate 9.9.9"),
        "the offending pair must be listed: {so}"
    );

    // 3. A binary with no section at all: NOT ATTESTED, and still exit 1.
    let bare = tmp.path().join("bare.elf");
    std::fs::write(&bare, build_elf(&[(".text", b"\x90\x90\x90\x90")]))
        .expect("write the bare image");
    let output = verify_reference(&lockfile, &sbom, &["--dep-v0", &as_str(&bare)]);
    let so = stdout(&output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a check that could not be performed is not a pass; stdout: {so}"
    );
    assert!(
        so.contains("SBOM<->binary: NOT ATTESTED (binary carries no .dep-v0 section)"),
        "the specification pins this wording: {so}"
    );
    assert!(
        !so.contains("SBOM matches the lockfile projection"),
        "NOT ATTESTED is not a match, and the banner must not appear beside \
         it: {so}"
    );

    // 4. A container that is not an ELF at all fails LOUD, by class name,
    //    never as an empty dependency list -- and it is the AUDITOR's own
    //    error (exit 2), not the artifact's: they asserted the path named
    //    an ELF image and it does not. The opposite claim, a valid ELF with
    //    no section (arm 3), stays exit 1.
    let not_elf = tmp.path().join("not.elf");
    std::fs::write(&not_elf, b"MZ this is not an ELF image").expect("write the non-ELF file");
    let output = verify_reference(&lockfile, &sbom, &["--dep-v0", &as_str(&not_elf)]);
    let se = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "stdout: {}", stdout(&output));
    assert!(
        se.contains("error class: unsupported-binary-format"),
        "the specification names this class explicitly: {se}"
    );
    assert!(
        !stdout(&output).contains("SBOM matches the lockfile projection"),
        "the match banner rode out of a run that did not match: {}",
        stdout(&output)
    );

    // 5. A path that does not exist at all is the same class of mistake.
    let absent = tmp.path().join("no-such-image.elf");
    let output = verify_reference(&lockfile, &sbom, &["--dep-v0", &as_str(&absent)]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an unreadable image is the auditor's own input; stderr: {}",
        stderr(&output)
    );
}

/// INTENT: the AUDITOR's own mistakes exit 2, never 1. A missing or
///         malformed `--subject`, an unusable lockfile or manifest, an
///         unknown option and a flag supplied twice are all the auditor's
///         side of the check; a script filtering for "the vendor's
///         artifact failed" must not be contaminated by a local typo.
/// CONTEXT: spec section 7.6, and the 1/2 asymmetry already established
///          for `verify-anchor`'s `--kit`.
/// EXPIRES IF: the exit-code table of section 7.6 changes.
/// MUTANT: return 1 for any of these; accept a repeated `--subject` and
///         keep the last one.
#[test]
fn test_intent_sbom_auditor_side_errors_exit_2() {
    let tmp = tempdir();
    let lockfile = reference_lockfile(tmp.path());
    let (sbom, _) = emit_reference(tmp.path(), &lockfile, "sbom.json");
    let lock = as_str(&lockfile);
    let doc = as_str(&sbom);
    let missing = as_str(&tmp.path().join("absent.lock"));

    let cases: Vec<Vec<String>> = vec![
        // No subject at all.
        vec![
            "verify-sbom".into(),
            "--kind".into(),
            "cargo".into(),
            "--lockfile".into(),
            lock.clone(),
            "--sbom".into(),
            doc.clone(),
        ],
        // A subject that is not a purl.
        vec![
            "verify-sbom".into(),
            "--kind".into(),
            "cargo".into(),
            "--lockfile".into(),
            lock.clone(),
            "--subject".into(),
            "demo-app".into(),
            "--sbom".into(),
            doc.clone(),
        ],
        // A lockfile that is not there.
        vec![
            "verify-sbom".into(),
            "--kind".into(),
            "cargo".into(),
            "--lockfile".into(),
            missing.clone(),
            "--subject".into(),
            REFERENCE_SUBJECT.into(),
            "--sbom".into(),
            doc.clone(),
        ],
        // An unknown ecosystem.
        vec![
            "verify-sbom".into(),
            "--kind".into(),
            "gradle".into(),
            "--lockfile".into(),
            lock.clone(),
            "--subject".into(),
            REFERENCE_SUBJECT.into(),
            "--sbom".into(),
            doc.clone(),
        ],
        // A flag that does not exist.
        vec![
            "verify-sbom".into(),
            "--kind".into(),
            "cargo".into(),
            "--lockfile".into(),
            lock.clone(),
            "--subject".into(),
            REFERENCE_SUBJECT.into(),
            "--sbom".into(),
            doc.clone(),
            "--lenient".into(),
        ],
        // The same flag twice: keeping the last one silently is how an
        // auditor verifies against a subject they did not mean to supply.
        vec![
            "verify-sbom".into(),
            "--kind".into(),
            "cargo".into(),
            "--lockfile".into(),
            lock.clone(),
            "--subject".into(),
            REFERENCE_SUBJECT.into(),
            "--subject".into(),
            "pkg:cargo/other@1.0.0".into(),
            "--sbom".into(),
            doc.clone(),
        ],
        // `--manifest` is meaningful for composer and nothing else.
        vec![
            "verify-sbom".into(),
            "--kind".into(),
            "cargo".into(),
            "--lockfile".into(),
            lock.clone(),
            "--manifest".into(),
            lock.clone(),
            "--subject".into(),
            REFERENCE_SUBJECT.into(),
            "--sbom".into(),
            doc.clone(),
        ],
        // `.dep-v0` lists cargo crates; against another ecosystem the
        // check would be a guaranteed failure that means nothing.
        vec![
            "verify-sbom".into(),
            "--kind".into(),
            "npm".into(),
            "--lockfile".into(),
            as_str(&sbom_fixture("npm_nested.json")),
            "--subject".into(),
            "pkg:npm/example-app@1.0.0".into(),
            "--sbom".into(),
            doc.clone(),
            "--dep-v0".into(),
            doc.clone(),
        ],
        // emit-sbom without its output operand.
        vec![
            "emit-sbom".into(),
            "--kind".into(),
            "cargo".into(),
            "--lockfile".into(),
            lock.clone(),
            "--subject".into(),
            REFERENCE_SUBJECT.into(),
        ],
        // A flag whose value is missing at the end of the line.
        vec![
            "emit-sbom".into(),
            "--kind".into(),
            "cargo".into(),
            "--lockfile".into(),
            lock.clone(),
            "--subject".into(),
        ],
    ];

    for case in &cases {
        let output = run_owned(case);
        assert_eq!(
            output.status.code(),
            Some(2),
            "auditor-side error must exit 2 for {case:?}; stderr: {}",
            stderr(&output)
        );
    }
}

/// INTENT: `emit-sbom` VERIFIES NOTHING, so exit 1 is not in its
///         vocabulary at all: an unusable input is the auditor's own error
///         (2), and there is no third outcome to confuse a script with.
/// CONTEXT: the producer half reads a lockfile the auditor already holds
///          and writes the projection of it; there is no untrusted
///          artifact in the run.
/// EXPIRES IF: `emit-sbom` grows a verification step.
/// MUTANT: return 1 on a malformed lockfile.
#[test]
fn test_intent_emit_sbom_never_exits_1() {
    let tmp = tempdir();
    let broken = tmp.path().join("broken.lock");
    std::fs::write(&broken, "version = 3\n\n[[package]]\nname = \"nameless\"\n")
        .expect("write the broken lockfile");
    let out = tmp.path().join("never-written.json");

    let output = run_owned(&[
        "emit-sbom".to_string(),
        "--kind".to_string(),
        "cargo".to_string(),
        "--lockfile".to_string(),
        as_str(&broken),
        "--subject".to_string(),
        REFERENCE_SUBJECT.to_string(),
        "--out".to_string(),
        as_str(&out),
    ]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a malformed lockfile is the auditor's own error; stderr: {}",
        stderr(&output)
    );
    assert!(
        !out.exists(),
        "nothing may be written when the projection failed"
    );
}

/// The composer arm needs a SECOND input (the root manifest), and the CLI
/// has to carry it through. Without `--manifest` the projection has no
/// top-level set at all and the honest answer is an error, not an empty
/// `dependsOn`.
#[test]
fn emit_and_verify_sbom_carry_the_composer_manifest_through() {
    let tmp = tempdir();
    let lockfile = sbom_fixture("composer_two_scopes.lock");
    let manifest = sbom_fixture("composer_two_scopes.json");
    let subject = "pkg:composer/example-org/example-portal@1.0.0";
    let out = tmp.path().join("composer.json");

    let with_manifest: Vec<String> = vec![
        "--kind".into(),
        "composer".into(),
        "--lockfile".into(),
        as_str(&lockfile),
        "--manifest".into(),
        as_str(&manifest),
        "--subject".into(),
        subject.into(),
    ];

    let mut args = vec!["emit-sbom".to_string()];
    args.extend(with_manifest.clone());
    args.push("--out".into());
    args.push(as_str(&out));
    let output = run_owned(&args);
    assert_eq!(
        output.status.code(),
        Some(0),
        "emit-sbom (composer) must exit 0; stderr: {}",
        stderr(&output)
    );

    let mut args = vec!["verify-sbom".to_string()];
    args.extend(with_manifest.clone());
    args.push("--sbom".into());
    args.push(as_str(&out));
    let output = run_owned(&args);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the composer round trip must close; stderr: {}",
        stderr(&output)
    );
    assert!(stdout(&output).contains("SBOM matches the lockfile projection"));

    // Drop the manifest: the top-level set is then underivable and the run
    // must fail as an auditor-side error rather than emit an empty graph.
    let output = run_owned(&[
        "verify-sbom".to_string(),
        "--kind".to_string(),
        "composer".to_string(),
        "--lockfile".to_string(),
        as_str(&lockfile),
        "--subject".to_string(),
        subject.to_string(),
        "--sbom".to_string(),
        as_str(&out),
    ]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "composer without --manifest is an auditor-side error; stderr: {}",
        stderr(&output)
    );
}

// ─── synthetic ELF64 for the --dep-v0 arm ────────────────────────────────
//
// Hand-built, because no binary this repository produces carries a
// `.dep-v0` section: without a synthetic image the whole `--dep-v0` arm
// would be unfalsifiable from the CLI. The library's own builder is
// private to its test module, so the layout is reproduced here.

/// `{"packages":[{"name":..,"version":..},..]}` — the payload shape the
/// embedding tool writes.
fn dep_v0_document(pairs: &[(&str, &str)]) -> Vec<u8> {
    let entries: Vec<String> = pairs
        .iter()
        .map(|(name, version)| format!("{{\"name\":\"{name}\",\"version\":\"{version}\"}}"))
        .collect();
    format!("{{\"packages\":[{}]}}", entries.join(",")).into_bytes()
}

/// A zlib stream carrying `payload` in STORED blocks, so a test can embed
/// arbitrary content without pulling in a compressor.
fn zlib_stored(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78u8, 0x01];
    let mut rest = payload;
    loop {
        let take = rest.len().min(0xffff);
        let (chunk, remainder) = rest.split_at(take);
        let last = remainder.is_empty();
        out.push(u8::from(last));
        out.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
        out.extend_from_slice(&(!(chunk.len() as u16)).to_le_bytes());
        out.extend_from_slice(chunk);
        if last {
            break;
        }
        rest = remainder;
    }
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in payload {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    out.extend_from_slice(&((b << 16) | a).to_be_bytes());
    out
}

/// Build an ELF64 little-endian image carrying the named sections.
///
/// The section-name string table is placed BEFORE the payloads on
/// purpose: an extractor that searched the raw image for the section name
/// would find the name in the string table first and read the wrong
/// bytes, so this layout is what makes the section-table walk falsifiable.
fn build_elf(sections: &[(&str, &[u8])]) -> Vec<u8> {
    const EHDR_SIZE: usize = 64;
    const SHDR_SIZE: usize = 64;

    let mut shstrtab: Vec<u8> = vec![0];
    let mut name_offsets: Vec<u32> = Vec::new();
    for (name, _) in sections {
        name_offsets.push(shstrtab.len() as u32);
        shstrtab.extend_from_slice(name.as_bytes());
        shstrtab.push(0);
    }
    let shstrtab_name = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");

    let mut image = vec![0u8; EHDR_SIZE];
    let shstrtab_off = image.len() as u64;
    image.extend_from_slice(&shstrtab);

    let mut payload_spans: Vec<(u64, u64)> = Vec::new();
    for (_, body) in sections {
        payload_spans.push((image.len() as u64, body.len() as u64));
        image.extend_from_slice(body);
    }

    let shoff = image.len() as u64;
    // The reserved null entry, one per section, and the string table.
    let count = sections.len() + 2;

    let mut header = |name: u32, sh_type: u32, offset: u64, size: u64| {
        let mut entry = [0u8; SHDR_SIZE];
        entry[0..4].copy_from_slice(&name.to_le_bytes());
        entry[4..8].copy_from_slice(&sh_type.to_le_bytes());
        entry[24..32].copy_from_slice(&offset.to_le_bytes());
        entry[32..40].copy_from_slice(&size.to_le_bytes());
        image.extend_from_slice(&entry);
    };
    header(0, 0, 0, 0);
    for (index, (offset, size)) in payload_spans.iter().enumerate() {
        header(name_offsets[index], 1, *offset, *size);
    }
    header(shstrtab_name, 3, shstrtab_off, shstrtab.len() as u64);

    image[0..4].copy_from_slice(b"\x7fELF");
    image[4] = 2; // ELFCLASS64
    image[5] = 1; // ELFDATA2LSB
    image[6] = 1; // EV_CURRENT
    image[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    image[0x12..0x14].copy_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
    image[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
    image[0x34..0x36].copy_from_slice(&(EHDR_SIZE as u16).to_le_bytes());
    image[0x3a..0x3c].copy_from_slice(&(SHDR_SIZE as u16).to_le_bytes());
    image[0x3c..0x3e].copy_from_slice(&(count as u16).to_le_bytes());
    image[0x3e..0x40].copy_from_slice(&((count - 1) as u16).to_le_bytes());
    image
}

// ─── tiny tempdir helper (no tempfile dev-dependency) ────────────────────

struct TempDir(PathBuf);
impl TempDir {
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn tempdir() -> TempDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let mut base = std::env::temp_dir();
    base.push(format!(
        "seetrex-bin-e2e-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    if base.exists() {
        let _ = std::fs::remove_dir_all(&base);
    }
    std::fs::create_dir_all(&base).unwrap();
    TempDir(base)
}

/// INTENT: reduction 6 reports the number of OBJECTS it rewrote, and
///         REFUSES a document in which two objects declare the same
///         foreign `bom-ref` -- under its own error class, and never as a
///         comparison.
/// CONTEXT: spec section 7.4. The count came from the map keyed by
///          foreign identifier, so two objects behind one identifier were
///          reported as one rewrite; worse, the map's last write won, so
///          the graph was retargeted at whichever object came later and a
///          document that is invalid under CycloneDX's own uniqueness rule
///          was silently reduced into a comparison.
/// EXPIRES IF: CycloneDX drops the uniqueness requirement on `bom-ref`.
/// MUTANT: drop the refusal and let the map take the last write (the first
///         half goes red). Reporting `rewritten.len()` as the count is NOT
///         separately observable once the refusal stands -- the two
///         numbers then coincide on every path that reaches the note --
///         which is the stronger closure, not a gap: the document that
///         made them differ no longer reaches a comparison at all.
#[test]
fn test_intent_third_party_duplicate_foreign_bom_ref_is_refused_and_rewrites_are_counted() {
    let tmp = tempdir();
    let lockfile = reference_lockfile(tmp.path());
    let (sbom, _) = emit_reference(tmp.path(), &lockfile, "sbom.json");
    let canonical = read_document(&sbom);

    // Two components, two DIFFERENT purls, ONE foreign `bom-ref`. Each is
    // a rewrite; there is no single purl to retarget the shared identifier
    // to.
    let mut duplicate = canonical.clone();
    let components = duplicate["components"]
        .as_array_mut()
        .expect("the reference document has components");
    assert!(
        components.len() >= 2,
        "this guard needs two components to put behind one identifier"
    );
    for component in components.iter_mut().take(2) {
        component["bom-ref"] = serde_json::Value::String("foreign-id-1".to_string());
    }
    let path = tmp.path().join("duplicate-foreign.json");
    write_canonical(&path, &duplicate);

    let output = verify_reference(&lockfile, &path, &["--third-party"]);
    let so = stdout(&output);
    let se = stderr(&output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a document invalid under CycloneDX's own uniqueness rule is the \
         DOCUMENT's failure, not the auditor's; stdout: {so}\nstderr: {se}"
    );
    assert!(
        se.contains("error class: duplicate-foreign-bom-ref"),
        "the refusal must carry the stable class token spec 7.4 names; \
         stderr: {se}"
    );
    assert!(
        se.contains("foreign-id-1"),
        "the refusal must name the identifier two objects share; stderr: {se}"
    );
    assert!(
        !so.contains("bom-ref(s) rewritten"),
        "the reduction must be REFUSED, not applied and then reported: {so}"
    );

    // And the count is objects, not identifiers: two components with two
    // DISTINCT foreign identifiers report two rewrites.
    let mut distinct = canonical;
    let components = distinct["components"].as_array_mut().expect("components");
    for (index, component) in components.iter_mut().take(2).enumerate() {
        component["bom-ref"] = serde_json::Value::String(format!("foreign-id-{index}"));
    }
    let path = tmp.path().join("distinct-foreign.json");
    write_canonical(&path, &distinct);
    let output = verify_reference(&lockfile, &path, &["--third-party"]);
    let so = stdout(&output);
    assert!(
        so.contains("2 bom-ref(s) rewritten from purl (foreign identifier discarded)"),
        "two objects rewritten must be reported as two: {so}"
    );
}
