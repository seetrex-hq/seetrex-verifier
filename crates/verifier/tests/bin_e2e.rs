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

use std::collections::BTreeMap;
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
    Command::new(BIN)
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
    assert!(so.contains("verify-package") && so.contains("verify-chain"));

    // Usage errors exit 2 — distinct from the spec-bound 0/1/4.
    for bad in [&["frobnicate"] as &[&str], &["verify-package"], &["verify-chain"]] {
        let out = run(bad);
        assert_eq!(out.status.code(), Some(2), "usage error must exit 2 for {bad:?}");
    }
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
