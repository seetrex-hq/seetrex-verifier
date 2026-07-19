// SPDX-License-Identifier: Apache-2.0
//! `verify_package` — pure, offline package-integrity verification of an
//! extracted Seetrex Compliance verdict package.
//!
//! A "package" is an extracted directory with the layout
//! `replay --full --package-dir` consumes:
//!
//! ```text
//! manifest.json
//! verdict.json
//! ruleset.json
//! evidence/<uuid>.json
//! ```
//!
//! [`verify_package`] RE-COMPUTES hashes only. It does NOT re-execute the
//! inference engine (that is `replay --full`) and does NOT prove chain
//! position or freshness (that is `verify-chain` against the public chain
//! export with an externally obtained anchor). See §9 of
//! `docs/SPEC_VERDICT_PACKAGE_V1.md` for the normative "what each mode
//! proves and does not prove" statement — [`SCOPE_STATEMENT`] carries the
//! honest-scope wording the CLI prints on every terminal outcome.
//!
//! The logic lives here, in the pure crate, so the open-source auditor
//! compiles the SAME code the CLI runs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use chrono::SubsecRound;
use seetrex_format::types::FactValue;
use serde::Deserialize;
use thiserror::Error;
use uuid::Uuid;

use crate::canonical::{
    compute_verdict_hash, compute_verdict_hash_v1, format_derived_at, EvidenceRef,
    VerdictCanonicalInput, VerdictCanonicalInputV1,
};
use crate::chain::compute_chain_hash;
use crate::hash::sha256_hex;
use crate::rulesets::{ruleset_content_hash_hex, RulesetFile};
use crate::types::VerdictOutcome;

/// The honest-scope statement. Printed by the CLI on EVERY terminal
/// outcome — success or failure — so a reader can never mistake a
/// package-integrity pass for a full re-derivation or a freshness
/// proof. The substring `VERIFIED` deliberately never appears (it is a
/// reserved token: the repo's shell tooling reads it as a strong
/// pass).
pub const SCOPE_STATEMENT: &str = "\
This check re-computes hashes only. It does NOT re-execute the inference \
engine (that is `replay --full`), and it does NOT prove this verdict's \
position in the chain or its freshness (that is `verify-chain` against the \
published chain export with an externally obtained anchor). Package-internal \
consistency alone is never a trust root.";

/// Read cap for any single package file (bytes). Mirrors the CLI replay
/// paths' `MAX_INPUT_FILE_BYTES` (10 MiB) — an adversarial file must never
/// hang or OOM the auditor's process.
const MAX_INPUT_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Cardinality cap on the recursive directory walk. A faithful package
/// carries a handful of files; a hostile package with millions of tiny
/// entries is a DoS by count, not by bytes (mirrors the replay
/// `MAX_EVIDENCE_FILES` guard).
const MAX_PACKAGE_FILES: usize = 8192;

/// The recomputed outcome of a package-integrity check.
///
/// Carries the per-step confirmations (auditor-facing lines the CLI
/// prints in order), the accumulated non-fatal WARNINGs, the recomputed
/// `verdict_hash` (lowercase hex), and whether an EXTERNAL anchor pinned
/// it (`anchored`). A successful `verify_package` that returns
/// `anchored == false` is only SELF-CONSISTENT: nothing outside the
/// package attested the hash.
#[derive(Debug, Clone)]
pub struct PackageReport {
    /// Per-step confirmations, in execution order (steps 1..7).
    pub steps: Vec<String>,
    /// Non-fatal advisories (e.g. legacy package shapes).
    pub warnings: Vec<String>,
    /// The recomputed verdict hash, lowercase hex.
    pub verdict_hash: String,
    /// `true` iff an `expected_verdict_hash` was supplied AND matched the
    /// recomputed hash (step 7). `false` = self-consistent only.
    pub anchored: bool,
}

/// Failure modes of [`verify_package`]. Every `Display` is loud and names
/// the file + expected + got where relevant. The FIXED wording below is
/// chosen so no message contains the reserved substring `VERIFIED` —
/// "integrity check failed", never "not verified".
///
/// **CALLER CONTRACT:** several variants interpolate
/// PACKAGE-CONTROLLED bytes into their `Display` — a hostile package can
/// plant an extra file named `VERIFIED_x.txt` ([`Shape`] echoes the
/// filename), a `"ruleset_version":"VERIFIED"` type error ([`Malformed`]
/// quotes the serde value), or a ruleset key named `VERIFIED_key`
/// ([`Anchor`] echoes the strict-parser's unknown-field diagnostic). The
/// fixed wording therefore does NOT guarantee the token is absent from a
/// rendered error. CLI callers MUST sanitize reserved vocabulary at their
/// OUTPUT BOUNDARY before printing — the compliance CLI's `verify-package`
/// arm routes every line (errors included) through a `VERIFIED` →
/// `VERIF[REDACTED]` sanitizer.
///
/// [`Shape`]: PackageVerifyError::Shape
/// [`Malformed`]: PackageVerifyError::Malformed
/// [`Anchor`]: PackageVerifyError::Anchor
#[derive(Debug, Error)]
pub enum PackageVerifyError {
    /// A package file could not be read, was missing, or exceeded the
    /// read cap.
    #[error("integrity check failed — cannot read {path}: {detail}")]
    Io { path: String, detail: String },

    /// A package JSON document did not parse.
    #[error("integrity check failed — malformed {path}: {detail}")]
    Malformed { path: String, detail: String },

    /// Package shape violation: a listed file is missing, an undeclared
    /// extra file is present, or a manifest-listed filename escapes the
    /// package directory (a path-traversal read oracle).
    #[error("integrity check failed — package shape: {0}")]
    Shape(String),

    /// The manifest declares a `package_format_version` this verifier does
    /// not understand. Fail-closed and loud (naming the version), symmetric
    /// to the `preimage_version` doctrine (§7.4): an unknown format may lay
    /// out files or fields differently, so the verifier MUST NOT proceed as
    /// if it were the current format.
    #[error("integrity check failed — package format: {0}")]
    FormatVersion(String),

    /// A `files_sha256` entry did not match, or the map's key set did not
    /// match the listed files (load-bearing when present).
    #[error("integrity check failed — files_sha256: {0}")]
    FilesSha256(String),

    /// An evidence content hash did not match, or the evidence-file set
    /// diverged from `evidence_refs`.
    #[error("integrity check failed — evidence: {0}")]
    Evidence(String),

    /// manifest ↔ verdict coherence (verdict_hash / verdict_id / chain
    /// link) is broken.
    #[error("integrity check failed — coherence: {0}")]
    Coherence(String),

    /// The ruleset anchor recomputed from `ruleset.json` does not match
    /// the anchor the verdict declares.
    #[error("integrity check failed — ruleset anchor: {0}")]
    Anchor(String),

    /// The recomputed verdict hash did not reproduce the packaged
    /// `verdict_hash` (step 6), or a required preimage-v2 input was
    /// missing (possible field stripping), or the `preimage_version` is
    /// unknown (fail-closed).
    #[error("integrity check failed — preimage: {0}")]
    Preimage(String),

    /// The recomputed hash did not match the EXTERNAL
    /// `expected_verdict_hash` (step 7).
    #[error(
        "integrity check failed — external anchor mismatch: the package is \
         internally consistent but does NOT reproduce the externally \
         supplied hash; treat it as re-forged.\n  external anchor: {expected}\n  \
         recomputed:      {got}"
    )]
    ExternalAnchor { expected: String, got: String },
}

/// The one package format version this verifier understands. `manifest`
/// entries carry `package_format_version: 2` (§1.2/§3.1); a MISSING field
/// defaults to this current value (the tolerant reading — the field is
/// always emitted by ≥0.1.11 and describes only the file/JSON layout, which
/// has been stable). An UNKNOWN value bails loud ([`step0_format_version`]).
const CURRENT_PACKAGE_FORMAT_VERSION: u16 = 2;

fn default_package_format_version() -> u16 {
    CURRENT_PACKAGE_FORMAT_VERSION
}

/// `manifest.json`, serde-tolerant of unknown keys (format v2 forward
/// compat — no `deny_unknown_fields`).
#[derive(Deserialize)]
struct Manifest {
    /// Layout discriminator (§1.2). Absent (legacy) ⇒ current format;
    /// unknown ⇒ fail-closed (`step0_format_version`).
    #[serde(default = "default_package_format_version")]
    package_format_version: u16,
    verdict_id: String,
    verdict_hash: String,
    #[serde(default)]
    chain_prev_hash: Option<String>,
    chain_hash: String,
    files: Vec<String>,
    /// OPTIONAL sibling field (emitted since 0.1.11):
    /// filename → sha256 hex lowercase of the file bytes as stored. When
    /// present it is load-bearing (every entry checked). `manifest.json`
    /// itself is excluded from this map — it cannot commit to its own
    /// bytes, since the map lives inside it.
    #[serde(default)]
    files_sha256: Option<BTreeMap<String, String>>,
}

/// `verdict.json`, serde-tolerant of unknown keys. Field mapping mirrors
/// the reference `replay` weak path (`mod replay` in the CLI) and §7 of
/// the spec.
#[derive(Deserialize)]
struct PackagedVerdict {
    /// Verdict id — cross-checked against `manifest.verdict_id` (§3.1).
    id: String,
    tenant_id: Uuid,
    ruleset_id: String,
    ruleset_version: u32,
    control_id: String,
    verdict_outcome: String,
    verdict_hash: String,
    evidence_refs: Vec<EvidenceRef>,
    engine_semantic_version: u32,
    /// Derivation clock (wire name `inferred_at`, preimage name
    /// `derived_at`, §7.3). Variable precision accepted on parse; the
    /// preimage always re-formats with the pinned 6-digit encoding.
    #[serde(default)]
    inferred_at: Option<chrono::DateTime<chrono::Utc>>,
    working_memory_canonical: BTreeMap<String, FactValue>,
    #[serde(default)]
    ruleset_content_hash: Option<String>,
    #[serde(default)]
    preimage_version: Option<u16>,
}

/// One `evidence/<uuid>.json`, serde-tolerant of unknown keys.
#[derive(Deserialize)]
struct PackagedEvidence {
    id: String,
    content_hash: String,
    #[serde(default)]
    canonical_inline: Option<String>,
}

/// Verify the integrity of an extracted verdict package.
///
/// Steps run in order and fail fast; each error names the file + the
/// expected and observed values. `expected_verdict_hash`, when supplied,
/// is the EXTERNAL trust anchor (step 7) — obtained from the published
/// chain export or another channel the auditor controls; the package can
/// never be its own trust root (§9.3). When it is `None`, the returned
/// [`PackageReport::anchored`] is `false` (self-consistent only).
///
/// PURE: no database, no network, no clock. Deterministic over the
/// package bytes.
pub fn verify_package(
    package_dir: &Path,
    expected_verdict_hash: Option<&str>,
) -> Result<PackageReport, PackageVerifyError> {
    let mut report = PackageReport {
        steps: Vec::new(),
        warnings: Vec::new(),
        verdict_hash: String::new(),
        anchored: false,
    };

    // ── parse manifest.json + verdict.json (+ raw verdict Value for the
    // wire-form check) ───────────────────────────────────────────────────
    let manifest_bytes = read_capped(&package_dir.join("manifest.json"))?;
    let manifest: Manifest = parse_json(&manifest_bytes, "manifest.json")?;

    let verdict_bytes = read_capped(&package_dir.join("verdict.json"))?;
    let verdict: PackagedVerdict = parse_json(&verdict_bytes, "verdict.json")?;
    let verdict_value: serde_json::Value = parse_json(&verdict_bytes, "verdict.json")?;

    // ── STEP 0 — package format version (fail-closed on unknown) ─────────
    step0_format_version(&manifest, &mut report)?;

    // ── STEP 1 — manifest + shape ───────────────────────────────────────
    step1_shape(package_dir, &manifest, &mut report)?;

    // ── STEP 2 — files_sha256 (optional, load-bearing when present) ──────
    step2_files_sha256(package_dir, &manifest, &mut report)?;

    // ── STEP 3 — evidence content hashes (stored-bytes semantics) ────────
    step3_evidence(package_dir, &verdict, &mut report)?;

    // ── STEP 4 — verdict.json ↔ manifest coherence ──────────────────────
    step4_coherence(&manifest, &verdict, &mut report)?;

    // ── STEP 5 — ruleset anchor ─────────────────────────────────────────
    step5_anchor(package_dir, &verdict, &mut report)?;

    // WARN — non-canonical wire `inferred_at` (a package emitted before
    // the pinned wire encoding).
    warn_noncanonical_inferred_at(&verdict, &verdict_value, &mut report);

    // ── STEP 6 — preimage recompute ─────────────────────────────────────
    let recomputed = step6_preimage(&verdict, &mut report)?;
    report.verdict_hash = recomputed.clone();

    // ── STEP 7 — external anchor ────────────────────────────────────────
    step7_external_anchor(expected_verdict_hash, &recomputed, &mut report)?;

    Ok(report)
}

// ─── step 0 ─────────────────────────────────────────────────────────────

fn step0_format_version(
    manifest: &Manifest,
    report: &mut PackageReport,
) -> Result<(), PackageVerifyError> {
    // Fail-closed on an unknown format BEFORE inspecting the layout — an
    // unrecognized version may lay out files or fields differently, so
    // proceeding as if it were the current format is unsound. Mirrors the
    // `preimage_version` unknown-version rule (§7.4). A MISSING field has
    // already defaulted to the current version at parse time (tolerant
    // reading, §1.2), so only a present-but-unknown value reaches here.
    if manifest.package_format_version != CURRENT_PACKAGE_FORMAT_VERSION {
        return Err(PackageVerifyError::FormatVersion(format!(
            "unsupported package_format_version {} — this verifier understands \
             package format {CURRENT_PACKAGE_FORMAT_VERSION} only. An unknown \
             format may lay out files or fields differently; do NOT proceed, \
             upgrade the verifier.",
            manifest.package_format_version
        )));
    }
    report.steps.push(format!(
        "STEP 0 format OK — package_format_version {CURRENT_PACKAGE_FORMAT_VERSION}"
    ));
    Ok(())
}

// ─── step 1 ─────────────────────────────────────────────────────────────

/// Reject any manifest-listed filename that is not a plain relative path
/// confined to the package directory. A hostile manifest entry like
/// `../../etc/passwd`, an absolute path (`/etc/passwd`, `C:\…`), or
/// `evidence/../manifest.json` would otherwise make `verify_package` read +
/// hash a file OUTSIDE the package on the auditor's machine — an existence
/// and content oracle. Every path component MUST be
/// `Component::Normal` (rejecting `RootDir`/`Prefix` — absolute & drive
/// prefixed — and `ParentDir` — `..`; the `evidence/` subdir the format uses
/// is itself two `Normal` components). We do NOT canonicalize: the target may
/// not exist, and symlink resolution would itself be a probe. Runs in the
/// PURE crate at step 1, before any file read, so an independent verifier is
/// safe too.
///
/// Additionally, EVERY component is checked against the Win32 reserved
/// device names. On Windows, `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9` and
/// `LPT1`-`LPT9` resolve to DEVICES in any directory, case-insensitively,
/// even with an extension (`NUL.txt`), with trailing dots or spaces
/// (`NUL.`, `nul `), and with SUPERSCRIPT digits (`COM¹`/`COM²`/`COM³` —
/// the Win32 device matcher treats U+00B9/U+00B2/U+00B3 as digits). `std`
/// parses all of these as ordinary `Component::Normal`, so without this
/// denylist a hostile manifest entry would make the verifier open a device
/// on the auditor's machine (hang on `CON`, probe serial/parallel ports,
/// read `NUL`) instead of a package file. Components containing `:` are
/// rejected outright: the DOS device form (`CON:`) and NTFS alternate data
/// streams (`name:stream`) both use it, and no legitimate package file
/// ever does. The guard is lexical and platform-independent — rejected on
/// every OS, not only where it would misbehave.
fn validate_confined_relpath(rel: &str) -> Result<(), PackageVerifyError> {
    use std::path::Component;
    let mut saw_normal = false;
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(name) => {
                let name = name.to_string_lossy();
                if name.contains(':') {
                    return Err(PackageVerifyError::Shape(format!(
                        "manifest lists `{rel}`, whose path component contains \
                         `:` — DOS device syntax and NTFS alternate data \
                         streams are refused; package files never contain a \
                         colon"
                    )));
                }
                if is_windows_reserved_device_name(&name) {
                    return Err(PackageVerifyError::Shape(format!(
                        "manifest lists `{rel}`, whose path component `{name}` \
                         is a reserved Windows device name (CON/PRN/AUX/NUL/\
                         COM1-9/LPT1-9, case-insensitive, with or without \
                         extension) — opening it on a Windows machine would \
                         address a device, not a package file"
                    )));
                }
                saw_normal = true;
            }
            other => {
                return Err(PackageVerifyError::Shape(format!(
                    "manifest lists `{rel}`, which is not a plain relative path \
                     confined to the package (offending path component: \
                     {other:?}) — refusing to read outside the package directory"
                )));
            }
        }
    }
    if !saw_normal {
        return Err(PackageVerifyError::Shape(format!(
            "manifest lists the empty/invalid filename `{rel}`"
        )));
    }
    Ok(())
}

/// True when `name` (a single path component, as written in the manifest)
/// would be treated by Win32 as a reserved DOS device name. The match
/// mirrors the Win32 normalizer: trailing dots and spaces are stripped
/// first, then the device match is against the part BEFORE the first dot
/// (any extension is ignored), case-insensitively — so `NUL`, `nul.txt`,
/// `AUX.` and `prn ` all match, while `null.json`, `com10.txt` and
/// `console.log` do not.
fn is_windows_reserved_device_name(name: &str) -> bool {
    // Win32 strips trailing dots and spaces from a filename component…
    let trimmed = name.trim_end_matches([' ', '.']);
    // …and matches the device name on the stem before the first dot,
    // ignoring any spaces between the stem and the dot (`nul .txt`).
    let stem = trimmed.split('.').next().unwrap_or("").trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    match upper.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" => true,
        _ => {
            // COM/LPT + exactly one digit 1-9. The Win32 device matcher
            // also accepts the SUPERSCRIPT digits ¹ ² ³ (U+00B9, U+00B2,
            // U+00B3) in that position — match on chars, not bytes, so
            // `COM¹` (5 UTF-8 bytes, 4 chars) is caught too. `0` and the
            // superscript zero-forms are NOT reserved (COM0/LPT0 are
            // ordinary names).
            let chars: Vec<char> = upper.chars().collect();
            chars.len() == 4
                && (upper.starts_with("COM") || upper.starts_with("LPT"))
                && matches!(chars[3], '1'..='9' | '\u{00B9}' | '\u{00B2}' | '\u{00B3}')
        }
    }
}

fn step1_shape(
    package_dir: &Path,
    manifest: &Manifest,
    report: &mut PackageReport,
) -> Result<(), PackageVerifyError> {
    // Confinement guard (path-traversal read oracle) — validate BEFORE any
    // file read, over BOTH `files` and the `files_sha256` keys (step 2 joins
    // the latter onto package_dir and reads them).
    for rel in &manifest.files {
        validate_confined_relpath(rel)?;
    }
    if let Some(map) = &manifest.files_sha256 {
        for rel in map.keys() {
            validate_confined_relpath(rel)?;
        }
    }

    let listed: BTreeSet<String> = manifest.files.iter().cloned().collect();

    // Every listed file must exist on disk AND be a regular file — NOT a
    // symlink. `validate_confined_relpath` is lexical, so a symlink stored
    // INSIDE the package but pointing OUTSIDE it would still be followed by
    // the later `File::open`/`read` in steps 2-3, re-opening the traversal
    // read oracle the confinement guard closes. `symlink_metadata` does not
    // follow the link, so a symlinked entry fails here — before any content
    // read — instead of being resolved downstream. (`is_file()` would follow
    // it and pass.)
    for rel in &listed {
        let path = package_dir.join(rel);
        let meta = std::fs::symlink_metadata(&path).map_err(|_| {
            PackageVerifyError::Shape(format!(
                "manifest lists `{rel}` but it is not a file in the package"
            ))
        })?;
        if !meta.file_type().is_file() {
            return Err(PackageVerifyError::Shape(format!(
                "manifest lists `{rel}`, which is not a regular file \
                 (symlinks and special files are refused — a symlink could \
                 point outside the package)"
            )));
        }
    }

    // No EXTRA files beyond `manifest.json` + the listed files.
    let present = walk_relative_files(package_dir)?;
    let mut allowed = listed.clone();
    allowed.insert("manifest.json".to_string());
    let extras: Vec<&String> = present.difference(&allowed).collect();
    if !extras.is_empty() {
        return Err(PackageVerifyError::Shape(format!(
            "undeclared extra file(s) present in the package (not in \
             manifest `files`): {extras:?}"
        )));
    }

    report.steps.push(format!(
        "STEP 1 shape OK — {} listed file(s) present, no undeclared extras",
        manifest.files.len()
    ));
    Ok(())
}

// ─── step 2 ─────────────────────────────────────────────────────────────

fn step2_files_sha256(
    package_dir: &Path,
    manifest: &Manifest,
    report: &mut PackageReport,
) -> Result<(), PackageVerifyError> {
    let Some(map) = &manifest.files_sha256 else {
        report.warnings.push(
            "manifest carries no files_sha256 (pre-0.1.11 package) — until the \
             emitter ships it (0.1.11), evidence-file fields OTHER than \
             canonical_inline (e.g. category) are pinned by no hash and could \
             be altered without tripping any check here"
                .to_string(),
        );
        report
            .steps
            .push("STEP 2 files_sha256 SKIPPED — absent (see WARNING)".to_string());
        return Ok(());
    };

    // `manifest.json` cannot commit to its own bytes (the map lives inside
    // it), so the covered set is the listed files MINUS manifest.json. The
    // map's key set must equal that covered set exactly.
    let covered: BTreeSet<String> = manifest
        .files
        .iter()
        .filter(|f| f.as_str() != "manifest.json")
        .cloned()
        .collect();
    let map_keys: BTreeSet<String> = map.keys().cloned().collect();

    for missing in covered.difference(&map_keys) {
        return Err(PackageVerifyError::FilesSha256(format!(
            "listed file `{missing}` has no entry in files_sha256 (the map, \
             when present, must cover every listed file except manifest.json)"
        )));
    }
    for extra in map_keys.difference(&covered) {
        return Err(PackageVerifyError::FilesSha256(format!(
            "files_sha256 has an entry for `{extra}`, which is not a listed \
             file (or is manifest.json, which cannot commit to its own bytes)"
        )));
    }

    for (rel, expected) in map {
        let bytes = read_capped(&package_dir.join(rel))?;
        let got = sha256_hex(&bytes);
        if !got.eq_ignore_ascii_case(expected) {
            return Err(PackageVerifyError::FilesSha256(format!(
                "stored-bytes hash mismatch for `{rel}`:\n  manifest: \
                 {expected}\n  computed: {got}"
            )));
        }
    }

    report.steps.push(format!(
        "STEP 2 files_sha256 OK — {} file(s) matched by stored-bytes hash",
        map.len()
    ));
    Ok(())
}

// ─── step 3 ─────────────────────────────────────────────────────────────

fn step3_evidence(
    package_dir: &Path,
    verdict: &PackagedVerdict,
    report: &mut PackageReport,
) -> Result<(), PackageVerifyError> {
    let evidence_dir = package_dir.join("evidence");

    // Collect (id → content_hash) declared by verdict.json.
    let mut declared: BTreeMap<Uuid, String> = BTreeMap::new();
    for r in &verdict.evidence_refs {
        if declared.insert(r.evidence_id, r.content_hash.clone()).is_some() {
            return Err(PackageVerifyError::Evidence(format!(
                "verdict.json evidence_refs lists evidence_id {} twice",
                r.evidence_id
            )));
        }
    }

    // Walk evidence/*.json, recompute the content hash over the STORED
    // payload bytes (verbatim — never re-canonicalized), and collect the
    // file id set.
    let mut present: BTreeSet<Uuid> = BTreeSet::new();
    let mut paths: Vec<PathBuf> = Vec::new();
    if evidence_dir.is_dir() {
        for entry in std::fs::read_dir(&evidence_dir).map_err(|e| PackageVerifyError::Io {
            path: display(&evidence_dir),
            detail: e.to_string(),
        })? {
            let entry = entry.map_err(|e| PackageVerifyError::Io {
                path: display(&evidence_dir),
                detail: e.to_string(),
            })?;
            paths.push(entry.path());
        }
    }
    // Deterministic bail order cross-platform (`read_dir` is unordered).
    paths.sort();

    for path in &paths {
        let bytes = read_capped(path)?;
        let ev: PackagedEvidence = parse_json(&bytes, &display(path))?;
        let id: Uuid = ev.id.parse().map_err(|_| {
            PackageVerifyError::Evidence(format!(
                "evidence file {} carries a malformed UUID id `{}`",
                display(path),
                ev.id
            ))
        })?;
        let inline = ev.canonical_inline.ok_or_else(|| {
            PackageVerifyError::Evidence(format!(
                "evidence {id} has canonical_inline: null (blob reference) — it \
                 cannot be integrity-checked offline from the package alone (§5)"
            ))
        })?;
        // sha256 over the STORED bytes of canonical_inline, verbatim (§5).
        let got = sha256_hex(inline.as_bytes());
        // Compare against the matching ref in verdict.json.evidence_refs.
        let Some(ref_hash) = declared.get(&id) else {
            return Err(PackageVerifyError::Evidence(format!(
                "evidence file {id} is present in evidence/ but not referenced \
                 by verdict.json evidence_refs (orphan file)"
            )));
        };
        if !got.eq_ignore_ascii_case(ref_hash) {
            return Err(PackageVerifyError::Evidence(format!(
                "evidence {id} content hash does not match the verdict's \
                 evidence_refs entry:\n  evidence_refs: {ref_hash}\n  \
                 sha256(canonical_inline): {got}"
            )));
        }
        // The evidence file's own content_hash field must agree too — a
        // package whose evidence self-declaration diverges from its payload
        // is malformed even if the verdict ref happens to match.
        if !got.eq_ignore_ascii_case(&ev.content_hash) {
            return Err(PackageVerifyError::Evidence(format!(
                "evidence {id} declares content_hash {} but \
                 sha256(canonical_inline) is {got}",
                ev.content_hash
            )));
        }
        if !present.insert(id) {
            return Err(PackageVerifyError::Evidence(format!(
                "two evidence files carry the same id {id}"
            )));
        }
    }

    // Set equality: no orphan files, no dangling refs.
    let declared_ids: BTreeSet<Uuid> = declared.keys().copied().collect();
    if present != declared_ids {
        let file_only: Vec<Uuid> = present.difference(&declared_ids).copied().collect();
        let ref_only: Vec<Uuid> = declared_ids.difference(&present).copied().collect();
        return Err(PackageVerifyError::Evidence(format!(
            "evidence/ files do not match verdict.json evidence_refs — \
             in evidence/ only: {file_only:?}; declared by verdict.json \
             only: {ref_only:?}"
        )));
    }

    report.steps.push(format!(
        "STEP 3 evidence OK — {} evidence content hash(es) match, file set == \
         evidence_refs",
        present.len()
    ));
    Ok(())
}

// ─── step 4 ─────────────────────────────────────────────────────────────

fn step4_coherence(
    manifest: &Manifest,
    verdict: &PackagedVerdict,
    report: &mut PackageReport,
) -> Result<(), PackageVerifyError> {
    // verdict_hash agrees across the two files that carry it.
    if !manifest.verdict_hash.eq_ignore_ascii_case(&verdict.verdict_hash) {
        return Err(PackageVerifyError::Coherence(format!(
            "verdict_hash disagrees between files:\n  manifest.json: {}\n  \
             verdict.json:  {}",
            manifest.verdict_hash, verdict.verdict_hash
        )));
    }
    // verdict id agrees (§3.1: manifest.verdict_id == verdict.json.id).
    if manifest.verdict_id != verdict.id {
        return Err(PackageVerifyError::Coherence(format!(
            "verdict id disagrees:\n  manifest.verdict_id: {}\n  verdict.id: {}",
            manifest.verdict_id, verdict.id
        )));
    }
    // Chain link: chain_prev_hash / chain_hash live only in manifest.json
    // (§3.1 — verdict.json does not carry them). Recompute the link and
    // require it to equal the declared chain_hash.
    let recomputed_link =
        compute_chain_hash(manifest.chain_prev_hash.as_deref(), &manifest.verdict_hash);
    if !recomputed_link.eq_ignore_ascii_case(&manifest.chain_hash) {
        return Err(PackageVerifyError::Coherence(format!(
            "chain link does not recompute:\n  declared chain_hash: {}\n  \
             recomputed:          {recomputed_link}",
            manifest.chain_hash
        )));
    }
    report.steps.push(
        "STEP 4 coherence OK — verdict_hash + verdict_id agree; chain link \
         recomputes to the declared chain_hash"
            .to_string(),
    );
    Ok(())
}

// ─── step 5 ─────────────────────────────────────────────────────────────

fn step5_anchor(
    package_dir: &Path,
    verdict: &PackagedVerdict,
    report: &mut PackageReport,
) -> Result<(), PackageVerifyError> {
    let ruleset_bytes = read_capped(&package_dir.join("ruleset.json"))?;
    let ruleset_str = std::str::from_utf8(&ruleset_bytes).map_err(|e| {
        PackageVerifyError::Malformed {
            path: "ruleset.json".to_string(),
            detail: format!("not valid UTF-8: {e}"),
        }
    })?;
    // Strict parser — unknown/duplicate keys bail here; surface loudly.
    let ruleset = RulesetFile::from_json(ruleset_str).map_err(|e| PackageVerifyError::Anchor(
        format!("ruleset.json rejected by the strict parser: {e}"),
    ))?;
    let computed = ruleset_content_hash_hex(&ruleset).map_err(|e| {
        PackageVerifyError::Anchor(format!("cannot hash ruleset.json: {e}"))
    })?;

    match &verdict.ruleset_content_hash {
        Some(anchor) => {
            if !computed.eq_ignore_ascii_case(anchor) {
                return Err(PackageVerifyError::Anchor(format!(
                    "the packaged ruleset.json is NOT the ruleset the verdict \
                     declares:\n  verdict anchor: {anchor}\n  computed:       \
                     {computed}"
                )));
            }
            report.steps.push(format!(
                "STEP 5 anchor OK — ruleset.json hashes to the verdict's \
                 declared ruleset_content_hash ({computed})"
            ));
        }
        None => {
            report.steps.push(format!(
                "STEP 5 anchor NOTED — verdict carries no ruleset_content_hash \
                 (pure legacy v1); ruleset.json content hash is {computed} but \
                 there is no anchor to check against"
            ));
        }
    }
    Ok(())
}

// ─── wire-form WARN ──────────────────────────────────────────────────────

fn warn_noncanonical_inferred_at(
    verdict: &PackagedVerdict,
    verdict_value: &serde_json::Value,
    report: &mut PackageReport,
) {
    let (Some(parsed), Some(raw)) = (
        verdict.inferred_at,
        verdict_value.get("inferred_at").and_then(|v| v.as_str()),
    ) else {
        return;
    };
    if format_derived_at(&parsed) != raw {
        report.warnings.push(
            "verdict.json inferred_at is not in the pinned 6-digit wire form \
             (non-canonical wire form from an older emitter) — the preimage \
             re-formats it, so this is not a failure"
                .to_string(),
        );
    }
}

// ─── step 6 ─────────────────────────────────────────────────────────────

fn step6_preimage(
    verdict: &PackagedVerdict,
    report: &mut PackageReport,
) -> Result<String, PackageVerifyError> {
    // fail-closed on unknown versions BEFORE any work.
    let preimage_version = verdict.preimage_version.unwrap_or(1);
    if preimage_version != 1 && preimage_version != 2 {
        return Err(PackageVerifyError::Preimage(format!(
            "unsupported preimage_version {preimage_version} — this verifier \
             predates it (supported: absent/1, 2). Do NOT strip the field; \
             upgrade the verifier."
        )));
    }

    let outcome = parse_outcome(&verdict.verdict_outcome)?;
    let packaged_hash = verdict.verdict_hash.to_ascii_lowercase();

    let recomputed = match preimage_version {
        2 => {
            let inferred_at = verdict.inferred_at.ok_or_else(|| {
                PackageVerifyError::Preimage(
                    "verdict declares preimage_version 2 but has no inferred_at \
                     — the derivation clock is part of the v2 hash preimage \
                     (`derived_at`); it may have been STRIPPED"
                        .to_string(),
                )
            })?;
            let ruleset_content_hash = verdict.ruleset_content_hash.clone().ok_or_else(|| {
                PackageVerifyError::Preimage(
                    "verdict declares preimage_version 2 but has no \
                     ruleset_content_hash — the anchor is part of the v2 hash \
                     preimage; it may have been STRIPPED"
                        .to_string(),
                )
            })?;
            let input = VerdictCanonicalInput {
                tenant_id: verdict.tenant_id,
                ruleset_id: verdict.ruleset_id.clone(),
                ruleset_version: verdict.ruleset_version,
                control_id: verdict.control_id.clone(),
                verdict_outcome: outcome,
                evidence_refs: verdict.evidence_refs.clone(),
                engine_semantic_version: verdict.engine_semantic_version,
                // Defensive micro-truncation; the pinned formatter
                // truncates identically, so this only normalizes
                // hand-crafted nanos.
                derived_at: inferred_at.trunc_subsecs(6),
                ruleset_content_hash,
                working_memory_canonical: verdict.working_memory_canonical.clone(),
            };
            hex_of(compute_verdict_hash(&input).map_err(|e| {
                PackageVerifyError::Preimage(format!("cannot canonicalize verdict input: {e}"))
            })?)
        }
        _ => {
            let input = VerdictCanonicalInputV1 {
                tenant_id: verdict.tenant_id,
                ruleset_id: verdict.ruleset_id.clone(),
                ruleset_version: verdict.ruleset_version,
                control_id: verdict.control_id.clone(),
                verdict_outcome: outcome,
                evidence_refs: verdict.evidence_refs.clone(),
                engine_semantic_version: verdict.engine_semantic_version,
                working_memory_canonical: verdict.working_memory_canonical.clone(),
            };
            hex_of(compute_verdict_hash_v1(&input).map_err(|e| {
                PackageVerifyError::Preimage(format!("cannot canonicalize verdict input: {e}"))
            })?)
        }
    };

    if recomputed != packaged_hash {
        return Err(PackageVerifyError::Preimage(format!(
            "the recomputed verdict_hash does not reproduce the packaged \
             claim (preimage v{preimage_version}):\n  packaged:   \
             {packaged_hash}\n  recomputed: {recomputed}"
        )));
    }

    report.steps.push(format!(
        "STEP 6 preimage OK — recomputed verdict_hash reproduces the packaged \
         claim (preimage v{preimage_version}): {recomputed}"
    ));
    Ok(recomputed)
}

// ─── step 7 ─────────────────────────────────────────────────────────────

fn step7_external_anchor(
    expected: Option<&str>,
    recomputed: &str,
    report: &mut PackageReport,
) -> Result<(), PackageVerifyError> {
    match expected {
        Some(expected) => {
            let expected_lower = expected.to_ascii_lowercase();
            if recomputed != expected_lower {
                return Err(PackageVerifyError::ExternalAnchor {
                    expected: expected_lower,
                    got: recomputed.to_string(),
                });
            }
            report.anchored = true;
            report.steps.push(
                "STEP 7 external anchor OK — the recomputed hash matches the \
                 externally supplied expected hash"
                    .to_string(),
            );
        }
        None => {
            report.anchored = false;
            report.steps.push(
                "STEP 7 external anchor SKIPPED — no --expected-verdict-hash \
                 supplied; the result is self-consistent only"
                    .to_string(),
            );
        }
    }
    Ok(())
}

// ─── helpers ─────────────────────────────────────────────────────────────

fn parse_outcome(s: &str) -> Result<VerdictOutcome, PackageVerifyError> {
    VerdictOutcome::from_motor_string(s).ok_or_else(|| {
        PackageVerifyError::Preimage(format!(
            "verdict_outcome must be SATISFIED|AT_RISK|VIOLATED; got {s:?}"
        ))
    })
}

fn hex_of(bytes: [u8; 32]) -> String {
    hex::encode(bytes)
}

fn display(path: &Path) -> String {
    path.display().to_string()
}

/// Read a package file with a hard byte cap (DoS guard). Bounded at the
/// source so a concurrent writer cannot make us read past the cap.
fn read_capped(path: &Path) -> Result<Vec<u8>, PackageVerifyError> {
    use std::io::Read;
    let f = std::fs::File::open(path).map_err(|e| PackageVerifyError::Io {
        path: display(path),
        detail: e.to_string(),
    })?;
    let meta = f.metadata().map_err(|e| PackageVerifyError::Io {
        path: display(path),
        detail: e.to_string(),
    })?;
    if meta.len() > MAX_INPUT_FILE_BYTES {
        return Err(PackageVerifyError::Io {
            path: display(path),
            detail: format!(
                "{} bytes exceeds the {MAX_INPUT_FILE_BYTES} byte cap",
                meta.len()
            ),
        });
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    f.take(MAX_INPUT_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| PackageVerifyError::Io {
            path: display(path),
            detail: e.to_string(),
        })?;
    if buf.len() as u64 > MAX_INPUT_FILE_BYTES {
        return Err(PackageVerifyError::Io {
            path: display(path),
            detail: "file grew past the byte cap during read".to_string(),
        });
    }
    Ok(buf)
}

fn parse_json<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    what: &str,
) -> Result<T, PackageVerifyError> {
    serde_json::from_slice(bytes).map_err(|e| PackageVerifyError::Malformed {
        path: what.to_string(),
        detail: e.to_string(),
    })
}

/// Recursively collect the regular files under `dir` as forward-slash
/// relative paths (`evidence/<uuid>.json`, `manifest.json`, …). Capped by
/// cardinality (DoS guard).
fn walk_relative_files(dir: &Path) -> Result<BTreeSet<String>, PackageVerifyError> {
    let mut out = BTreeSet::new();
    let mut stack: Vec<(PathBuf, String)> = vec![(dir.to_path_buf(), String::new())];
    while let Some((cur, prefix)) = stack.pop() {
        let rd = std::fs::read_dir(&cur).map_err(|e| PackageVerifyError::Io {
            path: display(&cur),
            detail: e.to_string(),
        })?;
        for entry in rd {
            let entry = entry.map_err(|e| PackageVerifyError::Io {
                path: display(&cur),
                detail: e.to_string(),
            })?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let file_type = entry.file_type().map_err(|e| PackageVerifyError::Io {
                path: display(&entry.path()),
                detail: e.to_string(),
            })?;
            if file_type.is_dir() {
                stack.push((entry.path(), rel));
            } else {
                out.insert(rel);
                if out.len() > MAX_PACKAGE_FILES {
                    return Err(PackageVerifyError::Shape(format!(
                        "package contains more than {MAX_PACKAGE_FILES} files \
                         — refusing to process (cardinality DoS guard)"
                    )));
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Guards that the FIXED-wording error Displays and the exposed
    /// constants carry no `VERIFIED` substring (the repo's shell tooling
    /// reads that as a strong pass). NOTE: this only covers the fixed
    /// wording — variants that interpolate PACKAGE-CONTROLLED bytes (Shape
    /// filename, Malformed serde value, Anchor unknown-key) can still
    /// render the token, so the REAL reserved-token guarantee is the CLI's
    /// output-boundary sanitizer plus its black-box exploit tests. This
    /// test remains as a cheap regression on the constant wording.
    #[test]
    fn no_error_display_contains_verified_token() {
        let samples = [
            PackageVerifyError::Io {
                path: "verdict.json".into(),
                detail: "boom".into(),
            },
            PackageVerifyError::Shape("x".into()),
            PackageVerifyError::FormatVersion("x".into()),
            PackageVerifyError::FilesSha256("x".into()),
            PackageVerifyError::Evidence("x".into()),
            PackageVerifyError::Coherence("x".into()),
            PackageVerifyError::Anchor("x".into()),
            PackageVerifyError::Preimage("x".into()),
            PackageVerifyError::ExternalAnchor {
                expected: "a".into(),
                got: "b".into(),
            },
        ];
        for e in samples {
            assert!(
                !e.to_string().contains("VERIFIED"),
                "error Display must not contain the reserved token `VERIFIED`: {e}"
            );
        }
        assert!(!SCOPE_STATEMENT.contains("VERIFIED"));
    }

    /// Build a minimal in-tempdir package around a v1 preimage (no engine
    /// needed) and prove the happy path returns anchored/self-consistent
    /// as the external anchor dictates. This exercises steps 1,3,4,5,6,7
    /// on a self-consistent package without depending on the checked-in
    /// fixture (that end-to-end coverage lives in the compliance
    /// black-box test).
    fn write(path: &Path, v: &serde_json::Value) {
        fs::write(path, serde_json::to_vec_pretty(v).unwrap()).unwrap();
    }

    fn minimal_v1_package(dir: &Path) -> String {
        // A v1 verdict with a single inline evidence row. We compute the
        // real verdict_hash with the crate's own primitive so the package
        // is honest by construction.
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
            working_memory_canonical: wm.clone(),
        };
        let verdict_hash = hex::encode(compute_verdict_hash_v1(&v1).unwrap());
        let chain_hash = compute_chain_hash(None, &verdict_hash);

        fs::create_dir_all(dir.join("evidence")).unwrap();
        write(
            &dir.join("evidence").join(format!("{ev_id}.json")),
            &serde_json::json!({
                "id": ev_id.to_string(),
                "category": "sbom",
                "content_hash": content_hash,
                "canonical_inline": inline,
            }),
        );
        // A ruleset.json that clears the strict parser; no anchor is
        // declared by the verdict (pure legacy v1), so its content hash is
        // never checked.
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

    #[test]
    fn happy_path_self_consistent_then_anchored() {
        let tmp = tempdir();
        let hash = minimal_v1_package(tmp.path());

        // No external anchor → self-consistent only.
        let r = verify_package(tmp.path(), None).unwrap();
        assert!(!r.anchored);
        assert_eq!(r.verdict_hash, hash);

        // Correct external anchor → anchored.
        let r = verify_package(tmp.path(), Some(&hash)).unwrap();
        assert!(r.anchored);

        // Wrong external anchor → ExternalAnchor error.
        let err = verify_package(tmp.path(), Some(&"0".repeat(64))).unwrap_err();
        assert!(matches!(err, PackageVerifyError::ExternalAnchor { .. }));
    }

    #[test]
    fn extra_file_fails_shape() {
        let tmp = tempdir();
        minimal_v1_package(tmp.path());
        fs::write(tmp.path().join("sneaky.txt"), b"x").unwrap();
        let err = verify_package(tmp.path(), None).unwrap_err();
        assert!(matches!(err, PackageVerifyError::Shape(_)));
    }

    #[test]
    fn traversal_relative_parent_in_files_fails_shape() {
        // A manifest `files` entry that climbs out of the package must be
        // rejected at step 1 (before any read), naming the bad entry — no
        // existence/content oracle on the auditor's machine.
        let tmp = tempdir();
        minimal_v1_package(tmp.path());
        let m_path = tmp.path().join("manifest.json");
        let mut m: serde_json::Value =
            serde_json::from_slice(&fs::read(&m_path).unwrap()).unwrap();
        m["files"].as_array_mut().unwrap().push(serde_json::Value::String(
            "../manifest.json".to_string(),
        ));
        write(&m_path, &m);
        let err = verify_package(tmp.path(), None).unwrap_err();
        match err {
            PackageVerifyError::Shape(msg) => {
                assert!(msg.contains("../manifest.json"), "must name the bad entry: {msg}");
                assert!(msg.contains("refusing to read outside"), "must be loud: {msg}");
            }
            other => panic!("expected Shape error, got {other}"),
        }
    }

    #[test]
    fn traversal_absolute_path_in_files_fails_shape() {
        let tmp = tempdir();
        minimal_v1_package(tmp.path());
        let m_path = tmp.path().join("manifest.json");
        let mut m: serde_json::Value =
            serde_json::from_slice(&fs::read(&m_path).unwrap()).unwrap();
        // Absolute POSIX path (RootDir component) — rejected regardless of
        // whether /etc/passwd exists.
        m["files"].as_array_mut().unwrap().push(serde_json::Value::String(
            "/etc/passwd".to_string(),
        ));
        write(&m_path, &m);
        let err = verify_package(tmp.path(), None).unwrap_err();
        match err {
            PackageVerifyError::Shape(msg) => assert!(msg.contains("/etc/passwd")),
            other => panic!("expected Shape error, got {other}"),
        }
    }

    #[test]
    fn traversal_in_files_sha256_key_fails_shape() {
        // The confinement guard also covers `files_sha256` keys (step 2
        // reads them), and bails at step 1 before step 2 ever joins the key.
        let tmp = tempdir();
        minimal_v1_package(tmp.path());
        let m_path = tmp.path().join("manifest.json");
        let mut m: serde_json::Value =
            serde_json::from_slice(&fs::read(&m_path).unwrap()).unwrap();
        let mut map = serde_json::Map::new();
        map.insert(
            "../../etc/passwd".to_string(),
            serde_json::Value::String("0".repeat(64)),
        );
        m["files_sha256"] = serde_json::Value::Object(map);
        write(&m_path, &m);
        let err = verify_package(tmp.path(), None).unwrap_err();
        match err {
            PackageVerifyError::Shape(msg) => assert!(msg.contains("../../etc/passwd")),
            other => panic!("expected Shape error, got {other}"),
        }
    }

    /// INTENT: the confinement guard rejects, in EVERY path component, the
    ///         Win32 reserved device names (`CON PRN AUX NUL COM1-9
    ///         LPT1-9`), case-insensitively, with an extension (`nul.txt`),
    ///         with trailing dots/spaces (`AUX.`, `prn `), and with the
    ///         superscript-digit quirk (`COM¹`) — Win32 normalizes all of
    ///         these and resolves them to DEVICES in any directory, while
    ///         `std` parses them as ordinary `Component::Normal`; without
    ///         the denylist the verifier would open a device on the
    ///         auditor's Windows machine. Colons are rejected outright
    ///         (DOS device form `CON:`, NTFS alternate data streams). The
    ///         rejection is lexical and applies on every OS.
    /// CONTEXT: pre-publication hardening of the open verifier crate — the
    ///          guard is public attack surface once the source is released.
    /// EXPIRES IF: verify_package stops opening files by manifest-listed
    ///             name (e.g. an in-memory embedded tar format), or the
    ///             guard resolves paths through an API that excludes device
    ///             names by construction.
    #[test]
    fn test_intent_confined_relpath_rejects_windows_device_names() {
        let rejected = [
            "NUL",
            "nul.txt",
            "COM1",
            "lpt9.json",
            "AUX.",
            "prn ",
            "NUL..",       // multiple trailing dots — Win32 strips them all
            "nul .txt",    // space between stem and dot — Win32 strips it
            "COM\u{00B9}", // superscript digit — Win32 treats it as a digit
            "a/NUL/b.json", // rule applies to EVERY component, not just the last
        ];
        for rel in rejected {
            match validate_confined_relpath(rel) {
                Err(PackageVerifyError::Shape(msg)) => assert!(
                    msg.contains("reserved Windows device name"),
                    "must call out the device-name refusal for `{rel}`: {msg}"
                ),
                Err(other) => panic!("expected Shape error for `{rel}`, got {other}"),
                Ok(()) => panic!("`{rel}` must be rejected as a Windows device name"),
            }
        }
        let accepted = [
            "null.json",       // NUL is a prefix, not the stem
            "CONFIG.toml",     // CON is a prefix, not the stem
            "com10.txt",       // only COM1-COM9 are reserved
            "COM0",            // digit 0 is NOT reserved — pins the b'0' exclusion
            "LPT0",            // idem
            "console.log",
            "naul",
            "data/aux2/x.json", // aux2 != AUX
        ];
        for rel in accepted {
            validate_confined_relpath(rel).unwrap_or_else(|e| {
                panic!("`{rel}` must be accepted (not a reserved device name): {e}")
            });
        }

        // Colon forms are refused by their own guard (DOS device syntax and
        // NTFS alternate data streams), with a distinct message.
        for rel in ["CON:", "COM1:", "evidence/a.json:stream"] {
            match validate_confined_relpath(rel) {
                Err(PackageVerifyError::Shape(msg)) => assert!(
                    msg.contains("contains `:`"),
                    "must call out the colon refusal for `{rel}`: {msg}"
                ),
                Err(other) => panic!("expected Shape error for `{rel}`, got {other}"),
                Ok(()) => panic!("`{rel}` must be rejected (colon component)"),
            }
        }
    }

    /// INTENT: a LISTED file that is a symlink pointing OUTSIDE the
    ///         package is rejected at step 1 (before any content read)
    ///         — the lexical guard `validate_confined_relpath` cannot
    ///         see a symlink's target, so the real defense is
    ///         `symlink_metadata` demanding a regular file. Without
    ///         it, `File::open` in steps 2-3 would follow the link =
    ///         the read oracle reopened.
    /// CONTEXT: the original confinement check was purely lexical;
    ///          this closes the symlink residual.
    /// EXPIRES IF: verify_package stops reading files by listed name
    ///             (e.g. if the format moves to an in-memory embedded
    ///             tar).
    #[cfg(unix)]
    #[test]
    fn symlinked_listed_file_pointing_outside_fails_shape() {
        use std::os::unix::fs::symlink;
        let outside = tempdir();
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, b"auditor-machine-secret").unwrap();

        let tmp = tempdir();
        minimal_v1_package(tmp.path());
        // Replace a listed regular file with a symlink to the external secret,
        // keeping the SAME confined relative name (lexically valid).
        let victim = tmp.path().join("ruleset.json");
        fs::remove_file(&victim).unwrap();
        symlink(&secret, &victim).unwrap();

        let err = verify_package(tmp.path(), None).unwrap_err();
        match err {
            PackageVerifyError::Shape(msg) => {
                assert!(msg.contains("ruleset.json"), "must name the entry: {msg}");
                assert!(
                    msg.contains("regular file") || msg.contains("symlink"),
                    "must call out the symlink refusal: {msg}"
                );
            }
            other => panic!("expected Shape error, got {other}"),
        }
    }

    #[test]
    fn unknown_package_format_version_bails() {
        let tmp = tempdir();
        minimal_v1_package(tmp.path());
        let m_path = tmp.path().join("manifest.json");
        let mut m: serde_json::Value =
            serde_json::from_slice(&fs::read(&m_path).unwrap()).unwrap();
        m["package_format_version"] = serde_json::Value::from(3);
        write(&m_path, &m);
        let err = verify_package(tmp.path(), None).unwrap_err();
        match err {
            PackageVerifyError::FormatVersion(msg) => {
                assert!(msg.contains("unsupported package_format_version 3"), "{msg}")
            }
            other => panic!("expected FormatVersion error, got {other}"),
        }
    }

    #[test]
    fn absent_package_format_version_defaults_current() {
        // A legacy manifest without the field is treated as the current
        // format (tolerant reading, §1.2) — verification still succeeds.
        let tmp = tempdir();
        let hash = minimal_v1_package(tmp.path());
        let m_path = tmp.path().join("manifest.json");
        let mut m: serde_json::Value =
            serde_json::from_slice(&fs::read(&m_path).unwrap()).unwrap();
        m.as_object_mut().unwrap().remove("package_format_version");
        write(&m_path, &m);
        let r = verify_package(tmp.path(), None).unwrap();
        assert_eq!(r.verdict_hash, hash);
    }

    #[test]
    fn tampered_evidence_fails() {
        let tmp = tempdir();
        minimal_v1_package(tmp.path());
        // Append a byte to the inline payload without fixing the hash.
        let ev_path = tmp
            .path()
            .join("evidence")
            .join("11111111-1111-1111-1111-111111111111.json");
        let mut ev: serde_json::Value =
            serde_json::from_slice(&fs::read(&ev_path).unwrap()).unwrap();
        ev["canonical_inline"] = serde_json::Value::String(r#"{"a":1} "#.to_string());
        write(&ev_path, &ev);
        let err = verify_package(tmp.path(), None).unwrap_err();
        assert!(matches!(err, PackageVerifyError::Evidence(_)));
    }

    #[test]
    fn unknown_preimage_version_bails() {
        let tmp = tempdir();
        minimal_v1_package(tmp.path());
        let v_path = tmp.path().join("verdict.json");
        let mut v: serde_json::Value =
            serde_json::from_slice(&fs::read(&v_path).unwrap()).unwrap();
        v["preimage_version"] = serde_json::Value::from(3);
        write(&v_path, &v);
        let err = verify_package(tmp.path(), None).unwrap_err();
        match err {
            PackageVerifyError::Preimage(m) => assert!(m.contains("unsupported preimage_version 3")),
            other => panic!("expected Preimage error, got {other}"),
        }
    }

    #[test]
    fn files_sha256_load_bearing() {
        let tmp = tempdir();
        minimal_v1_package(tmp.path());
        // Add a CORRECT files_sha256 map (all listed files except
        // manifest.json), then flip one hex char → must fail.
        let m_path = tmp.path().join("manifest.json");
        let mut m: serde_json::Value =
            serde_json::from_slice(&fs::read(&m_path).unwrap()).unwrap();
        let files: Vec<String> = m["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let mut map = serde_json::Map::new();
        for f in &files {
            if f == "manifest.json" {
                continue;
            }
            let bytes = fs::read(tmp.path().join(f)).unwrap();
            map.insert(f.clone(), serde_json::Value::String(sha256_hex(&bytes)));
        }
        m["files_sha256"] = serde_json::Value::Object(map.clone());
        write(&m_path, &m);
        // Correct map passes.
        assert!(verify_package(tmp.path(), None).is_ok());

        // Flip one hex char in one entry → fail even though everything
        // else is intact.
        let (k, v) = map.iter().next().unwrap();
        let mut bad = v.as_str().unwrap().to_string();
        let last = bad.pop().unwrap();
        bad.push(if last == 'a' { 'b' } else { 'a' });
        let mut bad_map = map.clone();
        bad_map.insert(k.clone(), serde_json::Value::String(bad));
        m["files_sha256"] = serde_json::Value::Object(bad_map);
        write(&m_path, &m);
        let err = verify_package(tmp.path(), None).unwrap_err();
        assert!(matches!(err, PackageVerifyError::FilesSha256(_)));
    }

    // Tiny tempdir helper (avoids a dev-dependency on `tempfile` in the
    // pure crate).
    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        // Uniqueness = pid + process-wide atomic counter. The previous
        // `pid + SystemTime nanos` scheme collided under the parallel test
        // runner on Windows (coarse clock granularity → two tests in the
        // same tick shared a directory → flaky cross-test interference).
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let mut base = std::env::temp_dir();
        let unique = format!(
            "seetrex-verify-pkg-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        );
        base.push(unique);
        // Defensive cleanup: pid reuse across runs could resurrect a stale
        // leftover directory from a crashed earlier process; start fresh.
        if base.exists() {
            let _ = fs::remove_dir_all(&base);
        }
        fs::create_dir_all(&base).unwrap();
        TempDir(base)
    }
}
