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

/// The ONE spelling of the reserved strong-pass token, for every surface
/// of these crates.
///
/// It lived as three separate literals -- the byte string of the sanitizer
/// below, a `const` of `sbom::compare`, and a `const` of `sbom` -- and the
/// three did not agree about CASE, which is the whole of the guarantee:
/// the sanitizer matched case-insensitively while the purl grammar refused
/// only the uppercase spelling, so `VeRiFiEd` became a legal component
/// name and then a masked one, and a difference report printed two
/// distinct purls as one identical string.
pub const RESERVED_TOKEN: &str = "VERIFIED";

/// True when `value`, taken WHOLE, is the reserved token -- in any case.
///
/// This is the predicate a GRAMMAR asks: `is` a purl path segment, or a
/// version, the reserved token? It is deliberately not "does this string
/// contain it": npm ships real packages whose names carry the substring
/// (`verified-fetch` and its scoped siblings), and refusing to project a
/// lockfile that resolves one would be a false refusal of a real artifact
/// -- a worse outcome than the masking it would avoid. What remains is
/// handled at the output boundary of the VERDICT surfaces: a value that
/// CARRIES the token without being it is admitted and then masked by
/// [`sanitize_reserved_token`] before any report line reaches a `stdout` or
/// a `stderr`.
///
/// The obligation stops there, and stops there deliberately. A canonical
/// SBOM is a faithful projection of a lockfile, so a dependency whose real
/// name carries the token is projected under its real name and the EMITTED
/// ARTEFACT contains the literal: `emit-sbom` over a lockfile that resolves
/// `VERIFIED-app` writes those bytes, and it must, because masking them
/// would forge the bill of materials to protect a shell `grep`. "No surface
/// ever prints the token" was therefore false of the artefact; what is true
/// is what the sanitizer actually enforces -- no surface that carries a
/// VERDICT prints it.
///
/// The comparison is case-insensitive because [`sanitize_reserved_token`]
/// is: a grammar stricter or looser than the sanitizer that follows it is
/// the drift this predicate exists to remove.
pub fn is_reserved_token(value: &str) -> bool {
    value.eq_ignore_ascii_case(RESERVED_TOKEN)
}

/// Redact every occurrence of the reserved strong-pass token `VERIFIED`
/// (matched case-insensitively, belt-and-braces) from a line before a
/// `verify-package` output boundary prints it — spec §9.6 "Reserved
/// vocabulary".
///
/// `verify-package` is a WEAK integrity check; downstream shell tooling
/// treats the substring `VERIFIED` in a tool's output as a STRONG pass.
/// [`PackageVerifyError`] Display texts (and, defensively, every report
/// line) may embed package-controlled bytes — an attacker who names a file
/// `VERIFIED_x.txt` or plants a `"ruleset_version":"VERIFIED"` type error
/// gets that string quoted into a serde/shape error. Routing EVERY line a
/// `verify-package` surface prints through this sanitizer is the output
/// boundary that keeps the reserved token out of a weak check's
/// stdout/stderr. Both CLI surfaces (the reference `compliance-cli` and
/// the open `seetrex-verifier` binary) use THIS function — single source
/// of truth, pinned by black-box exploit tests on both binaries.
///
/// The token is pure ASCII, so a byte-level scan never splits a multibyte
/// UTF-8 sequence (continuation bytes are all >= 0x80 and never match an
/// ASCII byte); replacing ASCII spans with the ASCII [`RESERVED_TOKEN_MASK`]
/// and copying every other byte verbatim yields valid UTF-8. Note the mask
/// does NOT itself contain the substring `VERIFIED`.
pub fn sanitize_reserved_token(s: &str) -> String {
    let replacement = RESERVED_TOKEN_MASK.as_bytes();
    let token = RESERVED_TOKEN.as_bytes();
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes.len() - i >= token.len() && bytes[i..i + token.len()].eq_ignore_ascii_case(token) {
            out.extend_from_slice(replacement);
            i += token.len();
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).expect("sanitizer preserves UTF-8 validity (ASCII-only edits)")
}

/// The ONE mask every redaction of the reserved token renders, on every
/// surface of these crates.
///
/// It is a constant, and public, because a reader who meets it in a report
/// must be able to look it up. Two masks used to reach one surface -- this
/// one and a `[reserved-token]` of the comparison module -- with no legend
/// on either, which left the reader to guess whether they meant the same
/// thing. One mask, named here, is what a legend can point at.
pub const RESERVED_TOKEN_MASK: &str = "VERIF[REDACTED]";

/// The one-line legend a surface prints, ONCE, when the mask actually
/// reached its output.
///
/// A mask with no legend is an unexplained string in the middle of
/// evidence; a legend printed unconditionally is noise that teaches a
/// reader to skip it. The condition is "the mask is on screen", not "this
/// process replaced something": an artifact that plants the mask verbatim
/// is exactly the case where a reader needs the sentence.
pub const RESERVED_TOKEN_LEGEND: &str = "note: `VERIF[REDACTED]` marks the reserved token \
                                         redacted from bytes taken from the artifact under \
                                         test; this tool never emits that token itself";

/// Read cap for any single package file (bytes). Mirrors the CLI replay
/// paths' `MAX_INPUT_FILE_BYTES` (10 MiB) — an adversarial file must never
/// hang or OOM the auditor's process.
const MAX_INPUT_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Cardinality cap on the recursive directory walk. A faithful package
/// carries a handful of files; a hostile package with millions of tiny
/// entries is a DoS by count, not by bytes (mirrors the replay
/// `MAX_EVIDENCE_FILES` guard).
const MAX_PACKAGE_FILES: usize = 8192;

/// The ONE spelling of the cardinality DoS refusal, for BOTH arms of
/// [`PackageSource`].
///
/// It lived as two independent `format!` literals -- the directory walk's
/// and [`PackageFiles::insert`]'s -- which is precisely the drift this seam
/// exists to remove: the two arms must refuse an over-populated package
/// with the same bytes, and nothing but a reader's memory kept them equal.
fn cardinality_dos_refusal() -> PackageVerifyError {
    PackageVerifyError::Shape(format!(
        "package contains more than {MAX_PACKAGE_FILES} files \
         — refusing to process (cardinality DoS guard)"
    ))
}

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

// ─── the package source seam ─────────────────────────────────────────────

/// One package as a flat, ordered set of relative paths → stored bytes,
/// plus the DIRECTORIES that package contains.
///
/// Keys are forward-slash relative paths, spelled exactly as the manifest
/// spells them (`"manifest.json"`, `"evidence/<uuid>.json"`), and only
/// paths a directory walk could actually emit — [`PackageFiles::insert`]
/// refuses the rest. `BTreeMap` iteration is already sorted, which is what
/// lets the in-memory arm reproduce the directory arm's deterministic bail
/// order without a second sort.
///
/// # Every builder MUST record directories
///
/// A directory is not a key in a flat map. A map built from FILES alone can
/// still infer the directories that NEST something — `evidence/sub/x.json`
/// names `evidence/sub` — but it cannot infer an EMPTY one, and `read_dir`
/// can see it: a package carrying an empty `evidence/empty_sub/` is refused
/// by the `Dir` arm (step 3 tries to read the directory and fails) and
/// would be ACCEPTED by a `Memory` arm that never heard of it. That is a
/// different VERDICT, not a different sentence. A browser directory drop
/// enumerates empty directories, so EVERY builder of a `PackageFiles` — the
/// in-crate loader, the page's own loader — must call
/// [`PackageFiles::insert_dir`] for every directory it walks, empty ones
/// included. Declaring a non-empty directory as well is harmless: it is
/// synthesised from its keys either way.
///
/// # Total bytes are the HOST's obligation
///
/// `MAX_PACKAGE_FILES` is enforced here, by [`PackageFiles::insert`].
/// `MAX_INPUT_FILE_BYTES` is not: it stays where the READS are, on both
/// arms (see [`PackageFiles::insert`] for why moving it would change a
/// verdict). Neither is a bound on a package's TOTAL bytes — 8192 files of
/// 10 MiB is 80 GiB on the `Dir` arm too, and a total-bytes bound on one
/// arm only would be a divergence rather than a shared limit. A host that
/// accepts a drop from an untrusted source must therefore bound the total
/// bytes it accepts BEFORE it builds the map: by the time `insert` is
/// called the bytes are already allocated in the host's own memory, and no
/// check inside this crate can undo that.
#[derive(Debug, Clone, Default)]
pub struct PackageFiles {
    files: BTreeMap<String, Vec<u8>>,
    dirs: BTreeSet<String>,
}

impl PackageFiles {
    /// An empty package.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store `bytes` under the forward-slash relative path `rel`.
    ///
    /// `rel` must be a path a directory walk could emit
    /// ([`validate_package_key`]); anything else is a
    /// [`PackageVerifyError::Shape`], the variant the `Dir` arm answers for
    /// a manifest entry of the same shape.
    ///
    /// Enforces `MAX_PACKAGE_FILES` with the SAME error value the directory
    /// walk produces ([`cardinality_dos_refusal`] is that one spelling): the
    /// 8193rd DISTINCT key is refused, a repeated key replaces and grows
    /// nothing. On any refusal the map is left UNCHANGED — the caller keeps
    /// the `PackageFiles` it had.
    ///
    /// `MAX_INPUT_FILE_BYTES` is deliberately NOT enforced here. The
    /// directory arm applies that cap inside [`PackageSource::read_capped`],
    /// i.e. only to the files a verification actually READS, so a package
    /// that merely LISTS an oversized file the seven steps never open is
    /// ACCEPTED on disk. Enforcing the cap at load time would turn that same
    /// package into a refusal in memory — a different VERDICT, not merely an
    /// earlier point — so the byte cap stays where the reads are and both
    /// arms answer alike. Refusing here would save nothing anyway: the
    /// caller has already allocated the bytes it is handing over.
    pub fn insert(&mut self, rel: &str, bytes: Vec<u8>) -> Result<(), PackageVerifyError> {
        validate_package_key(rel)?;
        // A name is a file or a directory, never both -- and a key is a
        // DIRECTORY in three ways, not one: declared with `insert_dir`,
        // NESTING an existing file key, or being nested UNDER one. Only the
        // first was checked, so `insert("evidence")` after
        // `insert("evidence/x.json")` was accepted in either order and the
        // map then held a shape no disk can hold: `entry_kind` answers
        // `Regular` for the file and `read_capped` refuses the same name as
        // a directory, which is the guess this refusal exists to prevent.
        if self.dirs.contains(rel) || self.nests_something(rel) {
            return Err(both_file_and_directory_refusal(rel));
        }
        // Reported under the ANCESTOR's own key: that is the name given as
        // both, and the one the auditor has to go and look at.
        if let Some(ancestor) = self.ancestor_file(rel) {
            return Err(both_file_and_directory_refusal(&ancestor));
        }
        // The walk refuses once the set would exceed the cap; a repeated
        // key replaces and grows nothing, so only a NEW key can trip it.
        if !self.files.contains_key(rel) && self.files.len() >= MAX_PACKAGE_FILES {
            return Err(cardinality_dos_refusal());
        }
        self.files.insert(rel.to_string(), bytes);
        Ok(())
    }

    /// Record that the package contains the DIRECTORY `rel`.
    ///
    /// Validated exactly like a file key. Directories carry no bytes and are
    /// not counted against `MAX_PACKAGE_FILES`: the directory walk counts
    /// FILES only, so capping them here would refuse a package the `Dir` arm
    /// accepts.
    ///
    /// # The cardinality of DIRECTORIES is the HOST's obligation
    ///
    /// Measured, not assumed: a package carrying `MAX_PACKAGE_FILES + 1`
    /// empty directories at its root is ACCEPTED on disk -- see
    /// `test_intent_directory_cardinality_is_the_hosts_obligation`, which
    /// runs both arms over exactly that tree. `walk_relative_files` counts
    /// files, `read_dir` recurses through the empty ones and yields nothing,
    /// and no step ever lists the package root. A cap here would therefore
    /// refuse a package the executable passes -- a different VERDICT, which
    /// is the one thing the two arms may never have.
    ///
    /// So the bound belongs where the entries are BUILT, not here: a host
    /// that accepts a drop from an untrusted source bounds what it walks,
    /// exactly as it must already bound the package's TOTAL bytes (see
    /// [`PackageFiles`]). What this crate owes in return is that the cost of
    /// carrying them stays sub-linear per lookup, which is why
    /// [`PackageFiles::nests_something`] ranges instead of scanning.
    ///
    /// Declaring a directory is what lets an EMPTY one be seen at all, and
    /// it is why every builder must walk directories as well as files — see
    /// [`PackageFiles`].
    pub fn insert_dir(&mut self, rel: &str) -> Result<(), PackageVerifyError> {
        validate_package_key(rel)?;
        if self.files.contains_key(rel) {
            return Err(both_file_and_directory_refusal(rel));
        }
        self.dirs.insert(rel.to_string());
        Ok(())
    }

    /// The stored bytes for `rel`, or `None` when the package has no such
    /// FILE (a directory is never readable bytes).
    pub fn get(&self, rel: &str) -> Option<&[u8]> {
        self.files.get(rel).map(Vec::as_slice)
    }

    /// Every relative FILE path in the package, in sorted order. Directories
    /// are not files and are not yielded — the directory walk does not yield
    /// them either.
    pub fn names(&self) -> impl Iterator<Item = &str> + '_ {
        self.files.keys().map(String::as_str)
    }

    /// Every DECLARED directory, in sorted order.
    fn dir_names(&self) -> impl Iterator<Item = &str> + '_ {
        self.dirs.iter().map(String::as_str)
    }

    /// Whether `rel` names a directory of this package: one a builder
    /// declared with [`PackageFiles::insert_dir`], or one that exists only
    /// as the prefix of a nested key.
    fn contains_dir(&self, rel: &str) -> bool {
        self.dirs.contains(rel) || self.nests_something(rel)
    }

    /// Whether any FILE key or DECLARED directory is nested under `rel`,
    /// i.e. whether `rel` is used as a directory by something already here.
    ///
    /// `range` and not a scan: both collections are ordered, so every key
    /// nested under `{rel}/` is contiguous and the FIRST one at or after
    /// that bound decides. A linear scan made this O(entries) on a call the
    /// steps make per key, i.e. O(entries x dirs) over a verification, on a
    /// structure an untrusted package chooses the size of.
    fn nests_something(&self, rel: &str) -> bool {
        let prefix = format!("{rel}/");
        let nested = |first: Option<&String>| first.is_some_and(|k| k.starts_with(&prefix));
        nested(self.files.range(prefix.clone()..).next().map(|(k, _)| k))
            || nested(self.dirs.range(prefix.clone()..).next())
    }

    /// The nearest ANCESTOR of `rel` that is already stored as a FILE, if
    /// any: `evidence` when `rel` is `evidence/x.json`.
    fn ancestor_file(&self, rel: &str) -> Option<String> {
        rel.match_indices('/')
            .map(|(at, _)| &rel[..at])
            .find(|ancestor| self.files.contains_key(*ancestor))
            .map(str::to_string)
    }

    /// How many FILES the package holds.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether the package holds no files at all.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// The one spelling of the refusal for a name given as both a file and a
/// directory. On disk a name is one or the other; a map that holds both
/// would make [`PackageSource::entry_kind`] guess.
fn both_file_and_directory_refusal(rel: &str) -> PackageVerifyError {
    PackageVerifyError::Shape(format!(
        "the package key `{rel}` is given as both a file and a directory; on \
         disk a name is one or the other"
    ))
}

/// The keys a [`PackageFiles`] accepts: forward-slash relative paths a
/// directory walk could actually EMIT.
///
/// A key the `Dir` arm can never produce is a key the two arms cannot be
/// made to agree on. `"evidence/"` and `"evidence//b.json"` were stored
/// verbatim and then read by two steps in two different ways —
/// [`PackageSource::walk_relative_files`] lists a key as written, while
/// [`PackageSource::list_dir_sorted`] splits on `/` and finds no child — so
/// the entry became INVISIBLE to the very step that would refuse it.
///
/// The refusal is [`PackageVerifyError::Shape`], the variant the `Dir` arm
/// answers for a manifest entry of the same shape (step 1 refuses a
/// traversal or an empty name through [`validate_confined_relpath`], and an
/// entry that resolves to nothing as `not a file in the package`).
fn validate_package_key(rel: &str) -> Result<(), PackageVerifyError> {
    if rel.is_empty() {
        return Err(PackageVerifyError::Shape(
            "the package key is empty; keys are forward-slash relative paths \
             a directory walk could emit"
                .to_string(),
        ));
    }
    if rel.contains('\\') {
        return Err(PackageVerifyError::Shape(format!(
            "the package key `{rel}` contains a backslash; keys are \
             forward-slash relative paths, on every platform"
        )));
    }
    for component in rel.split('/') {
        if component.is_empty() {
            return Err(PackageVerifyError::Shape(format!(
                "the package key `{rel}` has an empty path component (a \
                 leading or trailing `/`, or `//`); no directory walk emits one"
            )));
        }
        if component == "." || component == ".." {
            return Err(PackageVerifyError::Shape(format!(
                "the package key `{rel}` has a `{component}` component; keys \
                 are plain relative paths confined to the package"
            )));
        }
    }
    // The same lexical guard step 1 applies to every manifest entry:
    // traversal, reserved Windows device names and `:` components, refused
    // on every OS.
    validate_confined_relpath(rel)
}

/// The one thing the seven verification steps read a package through.
///
/// `Dir` is the CLI's arm: it does the I/O, in the same order, with the
/// same caps and the same error values as before this seam existed.
/// `Memory` is a view for a host that has no filesystem (the browser
/// page) and whose bytes are already in hand. Both arms drive ONE
/// implementation of the steps — this is an enum and not a trait because
/// there are exactly two arms, both in this crate, and a third would be a
/// spec change rather than an extension.
///
/// The differences between the two arms are DECLARED LIMITS, not
/// accidents. Every one of them is a difference in WORDING or in what can
/// be OBSERVED; none of them is a difference in VERDICT — the variant and
/// the exit class an arm answers with are the same on both, which is the
/// claim `test_intent_dir_and_memory_sources_agree_on_every_corpus_package`
/// and `test_intent_the_two_arms_agree_on_the_shapes_no_corpus_case_has`
/// exist to falsify.
///
/// * **symlinks** — [`PackageSource::entry_kind`] answers `Regular` for
///   every present key. A drop into a browser cannot report a symlink;
///   the OS resolved or refused it before the bytes were handed over. So
///   step 1's symlink refusal is a DISK-ONLY guarantee.
/// * **a missing file's wording** — both arms answer
///   [`PackageVerifyError::Io`] for a file the steps read and cannot find,
///   but the `detail` differs: the `Dir` arm quotes the OS
///   (`The system cannot find the file specified. (os error 2)`), the
///   `Memory` arm writes `no such file in the package`. There is no OS to
///   quote. Same variant, same exit class, different sentence.
/// * **a manifest entry that names a DIRECTORY** — on disk that entry is
///   present but not a regular file, so step 1 refuses it with the
///   `not a regular file` wording. In memory a directory is not a file key
///   either, but it IS known: a builder declares it
///   ([`PackageFiles::insert_dir`]) or it is implied by a nested key, and
///   [`PackageSource::entry_kind`] answers `NotRegular` for it, so the same
///   package is refused with the same sentence. A name that is neither a
///   file nor a directory is `Missing` on both arms and refused as
///   `not a file in the package`. All of it is
///   [`PackageVerifyError::Shape`], all of it exits 1.
/// * **nesting and EMPTY directories** —
///   [`PackageSource::list_dir_sorted`] must yield the same immediate
///   children `read_dir` yields, DIRECTORIES INCLUDED. A package that nests
///   `evidence/sub/x.json` has no in-memory entry for `sub` itself, so the
///   `Memory` arm SYNTHESISES the name from the keys below it; an EMPTY
///   `evidence/empty_sub/` has no keys below it to synthesise from, so the
///   builder must have DECLARED it. Either way step 3 then tries to read
///   the directory and fails on both arms, instead of the memory arm
///   silently skipping the tree and passing a package the CLI refuses. The
///   sentence differs: on disk the OS explains why a directory is not
///   readable, in memory the `detail` says `is a directory, not a file in
///   the package`. Same variant ([`PackageVerifyError::Io`]), same exit.
/// * **bounds** — `MAX_PACKAGE_FILES` moves to [`PackageFiles::insert`]:
///   same value, same error value, an EARLIER point (both arms refuse).
///   `MAX_INPUT_FILE_BYTES` does NOT move: it stays in
///   [`PackageSource::read_capped`] on both arms, so a package that merely
///   LISTS an oversized file the steps never read is accepted by both. See
///   [`PackageFiles::insert`] for why the earlier point would have been a
///   different verdict rather than an earlier one. Neither arm bounds a
///   package's TOTAL bytes; that bound is the host's, and [`PackageFiles`]
///   says so.
pub enum PackageSource<'a> {
    /// A package on disk, rooted at this directory.
    Dir(&'a Path),
    /// A package already in memory.
    Memory(&'a PackageFiles),
}

/// What a relative path names in a source. `Missing` and `NotRegular` are
/// distinct because step 1 refuses them with different messages.
#[derive(PartialEq, Eq)]
enum EntryKind {
    /// A regular file.
    Regular,
    /// Present, but a directory, a symlink or a special file.
    NotRegular,
    /// Absent, or not readable enough to tell.
    Missing,
}

impl PackageSource<'_> {
    /// Build the on-disk path for a forward-slash relative path, one
    /// component at a time.
    ///
    /// On POSIX this is `dir.join(rel)` exactly — `/` IS the separator, so
    /// the two are the same bytes and the same `Display`. It exists for
    /// Windows, where they are not, and where the pre-seam code produced
    /// BOTH spellings depending on which step wrote the error:
    /// * step 3 pushed `entry.path()` straight out of `read_dir`, so an
    ///   evidence error named `…\pkg\evidence\x.json`;
    /// * steps 2 and 5 wrote `package_dir.join(rel)`, which on Windows
    ///   appends the relative path VERBATIM and so named
    ///   `…\pkg\evidence/x.json` — a mixed separator.
    ///
    /// No single join reproduces both. Joining per component reproduces the
    /// `read_dir` spelling (the evidence surface, the one most package
    /// failures land on) and NORMALISES the mixed one; the difference is
    /// confined to the `Display` of a Windows `Io`/`Malformed` path in
    /// steps 2 and 5, is invisible on the platform the CI gates on, and is
    /// pinned by `test_intent_join_rel_spells_paths_the_way_read_dir_does`
    /// so `dir.join(rel)` cannot be substituted for it in silence.
    fn join_rel(dir: &Path, rel: &str) -> PathBuf {
        let mut out = dir.to_path_buf();
        for component in rel.split('/') {
            out.push(component);
        }
        out
    }

    /// Read one package file with a hard byte cap (DoS guard). Bounded at
    /// the source so a concurrent writer cannot make us read past the cap.
    fn read_capped(&self, rel: &str) -> Result<Vec<u8>, PackageVerifyError> {
        match self {
            PackageSource::Dir(dir) => {
                use std::io::Read;
                let path = Self::join_rel(dir, rel);
                let f = std::fs::File::open(&path).map_err(|e| PackageVerifyError::Io {
                    path: display(&path),
                    detail: e.to_string(),
                })?;
                let meta = f.metadata().map_err(|e| PackageVerifyError::Io {
                    path: display(&path),
                    detail: e.to_string(),
                })?;
                if meta.len() > MAX_INPUT_FILE_BYTES {
                    return Err(PackageVerifyError::Io {
                        path: display(&path),
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
                        path: display(&path),
                        detail: e.to_string(),
                    })?;
                if buf.len() as u64 > MAX_INPUT_FILE_BYTES {
                    return Err(PackageVerifyError::Io {
                        path: display(&path),
                        detail: "file grew past the byte cap during read".to_string(),
                    });
                }
                Ok(buf)
            }
            // Same cap, same sentence, at the same point of the
            // verification as the `Dir` arm applies it: a file the steps
            // never read is never capped, on either arm. The two other ways
            // this arm can fail — an absent key, and a key that names a
            // DIRECTORY — are `Io` on both arms, and their `detail` is a
            // DECLARED difference (there is no OS error to quote) — see
            // `PackageSource`.
            PackageSource::Memory(files) => {
                let Some(bytes) = files.get(rel) else {
                    let detail = if files.contains_dir(rel) {
                        "is a directory, not a file in the package"
                    } else {
                        "no such file in the package"
                    };
                    return Err(PackageVerifyError::Io {
                        path: rel.to_string(),
                        detail: detail.to_string(),
                    });
                };
                if bytes.len() as u64 > MAX_INPUT_FILE_BYTES {
                    return Err(PackageVerifyError::Io {
                        path: rel.to_string(),
                        detail: format!(
                            "{} bytes exceeds the {MAX_INPUT_FILE_BYTES} byte cap",
                            bytes.len()
                        ),
                    });
                }
                Ok(bytes.to_vec())
            }
        }
    }

    /// What `rel` names. Never follows a symlink on the `Dir` arm
    /// (`symlink_metadata`): a symlink stored INSIDE the package but
    /// pointing outside it must be refused at step 1, before any content
    /// read, not resolved downstream.
    fn entry_kind(&self, rel: &str) -> EntryKind {
        match self {
            PackageSource::Dir(dir) => {
                match std::fs::symlink_metadata(Self::join_rel(dir, rel)) {
                    Err(_) => EntryKind::Missing,
                    Ok(meta) if meta.file_type().is_file() => EntryKind::Regular,
                    Ok(_) => EntryKind::NotRegular,
                }
            }
            // Declared limit: a host without a filesystem cannot tell us
            // a key was a symlink, so every present FILE key is `Regular`.
            // A DIRECTORY — declared by the builder, or implied by a key
            // nested under it — is `NotRegular`, the same answer
            // `symlink_metadata` gives for a directory on disk.
            PackageSource::Memory(files) => {
                if files.get(rel).is_some() {
                    EntryKind::Regular
                } else if files.contains_dir(rel) {
                    EntryKind::NotRegular
                } else {
                    EntryKind::Missing
                }
            }
        }
    }

    /// Every regular file in the package as a forward-slash relative path
    /// (`manifest.json`, `evidence/<uuid>.json`, …). Capped by
    /// cardinality (DoS guard) on the `Dir` arm; the `Memory` arm's cap
    /// was already enforced by [`PackageFiles::insert`].
    fn walk_relative_files(&self) -> Result<BTreeSet<String>, PackageVerifyError> {
        match self {
            PackageSource::Dir(dir) => {
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
                                return Err(cardinality_dos_refusal());
                            }
                        }
                    }
                }
                Ok(out)
            }
            // Files only, like the walk above: `read_dir` yields
            // directories, but the walk recurses into them instead of
            // recording them, so a package's empty directory is not an
            // undeclared extra file on either arm.
            PackageSource::Memory(files) => Ok(files.names().map(str::to_string).collect()),
        }
    }

    /// The children of `rel_dir`, sorted, as relative paths. Empty when
    /// the directory is absent.
    ///
    /// The `Dir` arm reproduces the pre-seam `read_dir` + `paths.sort()`
    /// verbatim — `read_dir` is unordered, so the sort is what makes the
    /// bail order deterministic cross-platform — and then names each
    /// entry relatively. `read_dir` yields DIRECTORIES as well as files,
    /// and step 3 then fails trying to read one; that refusal is what
    /// stops a package from hiding evidence in a nested tree.
    ///
    /// The `Memory` arm must therefore yield the same names, and a nested
    /// key is the only trace a directory leaves in a flat map: every key
    /// under `{rel_dir}/` contributes its FIRST path component, so
    /// `evidence/sub/x.json` contributes `evidence/sub` — a name
    /// [`PackageSource::read_capped`] then fails to find, exactly as the
    /// `Dir` arm fails to read the directory. The `BTreeSet` is what
    /// deduplicates several keys nested under one directory and keeps the
    /// result ascending.
    fn list_dir_sorted(&self, rel_dir: &str) -> Result<Vec<String>, PackageVerifyError> {
        match self {
            PackageSource::Dir(dir) => {
                let abs = Self::join_rel(dir, rel_dir);
                let mut paths: Vec<PathBuf> = Vec::new();
                if abs.is_dir() {
                    for entry in std::fs::read_dir(&abs).map_err(|e| PackageVerifyError::Io {
                        path: display(&abs),
                        detail: e.to_string(),
                    })? {
                        let entry = entry.map_err(|e| PackageVerifyError::Io {
                            path: display(&abs),
                            detail: e.to_string(),
                        })?;
                        paths.push(entry.path());
                    }
                }
                // Deterministic bail order cross-platform.
                paths.sort();
                Ok(paths
                    .iter()
                    .map(|p| {
                        let name = p
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        format!("{rel_dir}/{name}")
                    })
                    .collect())
            }
            PackageSource::Memory(files) => {
                let prefix = format!("{rel_dir}/");
                let mut out: BTreeSet<String> = BTreeSet::new();
                // Files first, then the DECLARED directories: an empty one
                // has no key nested under it to be synthesised from, and is
                // exactly the entry `read_dir` sees and a flat map does not.
                for name in files.names().chain(files.dir_names()) {
                    let Some(tail) = name.strip_prefix(prefix.as_str()) else {
                        continue;
                    };
                    // The immediate child: the file's own name, or the
                    // name of the directory nesting it.
                    let Some(child) = tail.split('/').next().filter(|c| !c.is_empty()) else {
                        continue;
                    };
                    out.insert(format!("{rel_dir}/{child}"));
                }
                Ok(out.into_iter().collect())
            }
        }
    }

    /// The string that goes into `Io`/`Malformed` error values for `rel`.
    /// `Dir` → the joined on-disk path; `Memory` → `rel` verbatim (a host
    /// without a filesystem has no prefix to name).
    fn display(&self, rel: &str) -> String {
        match self {
            PackageSource::Dir(dir) => display(&Self::join_rel(dir, rel)),
            PackageSource::Memory(_) => rel.to_string(),
        }
    }
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
/// No database, no network, no clock: deterministic over the package
/// bytes. The filesystem reads live in [`PackageSource::Dir`]; this
/// function is the thin wrapper that names it. See
/// [`verify_package_files`] for the same verification over bytes already
/// in memory.
pub fn verify_package(
    package_dir: &Path,
    expected_verdict_hash: Option<&str>,
) -> Result<PackageReport, PackageVerifyError> {
    verify_with(&PackageSource::Dir(package_dir), expected_verdict_hash)
}

/// Verify a package whose bytes are already in memory — the same seven
/// steps, the same order, the same tokens and error values as
/// [`verify_package`], for a host with no filesystem (see
/// [`PackageSource`] for the three declared limits of this arm).
///
/// PURE: no filesystem, no database, no network, no clock. Deterministic
/// over the package bytes. That purity is not a promise of this comment:
/// `test_intent_verification_steps_never_touch_the_filesystem` reads this
/// file back and refuses any `std::fs` outside the `PackageSource::Dir`
/// match arms.
pub fn verify_package_files(
    files: &PackageFiles,
    expected_verdict_hash: Option<&str>,
) -> Result<PackageReport, PackageVerifyError> {
    verify_with(&PackageSource::Memory(files), expected_verdict_hash)
}

/// The seven steps, once, over whichever source. Both public entry points
/// are one line each on top of this — there is no second implementation
/// of any step to drift.
fn verify_with(
    src: &PackageSource,
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
    let manifest_bytes = src.read_capped("manifest.json")?;
    let manifest: Manifest = parse_json(&manifest_bytes, "manifest.json")?;

    let verdict_bytes = src.read_capped("verdict.json")?;
    let verdict: PackagedVerdict = parse_json(&verdict_bytes, "verdict.json")?;
    let verdict_value: serde_json::Value = parse_json(&verdict_bytes, "verdict.json")?;

    // ── STEP 0 — package format version (fail-closed on unknown) ─────────
    step0_format_version(&manifest, &mut report)?;

    // ── STEP 1 — manifest + shape ───────────────────────────────────────
    step1_shape(src, &manifest, &mut report)?;

    // ── STEP 2 — files_sha256 (optional, load-bearing when present) ──────
    step2_files_sha256(src, &manifest, &mut report)?;

    // ── STEP 3 — evidence content hashes (stored-bytes semantics) ────────
    step3_evidence(src, &verdict, &mut report)?;

    // ── STEP 4 — verdict.json ↔ manifest coherence ──────────────────────
    step4_coherence(&manifest, &verdict, &mut report)?;

    // ── STEP 5 — ruleset anchor ─────────────────────────────────────────
    step5_anchor(src, &verdict, &mut report)?;

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
    src: &PackageSource,
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

    // Every listed file must exist in the package AND be a regular file —
    // NOT a symlink. `validate_confined_relpath` is lexical, so a symlink
    // stored INSIDE the package but pointing OUTSIDE it would still be
    // followed by the later `File::open`/`read` in steps 2-3, re-opening the
    // traversal read oracle the confinement guard closes. On the `Dir` arm
    // `entry_kind` uses `symlink_metadata`, which does not follow the link,
    // so a symlinked entry fails here — before any content read — instead of
    // being resolved downstream. (`is_file()` would follow it and pass.) On
    // the `Memory` arm a symlink cannot be reported at all: that refusal is
    // a disk-only guarantee (see `PackageSource`).
    for rel in &listed {
        match src.entry_kind(rel) {
            EntryKind::Regular => {}
            EntryKind::Missing => {
                return Err(PackageVerifyError::Shape(format!(
                    "manifest lists `{rel}` but it is not a file in the package"
                )));
            }
            EntryKind::NotRegular => {
                return Err(PackageVerifyError::Shape(format!(
                    "manifest lists `{rel}`, which is not a regular file \
                     (symlinks and special files are refused — a symlink could \
                     point outside the package)"
                )));
            }
        }
    }

    // No EXTRA files beyond `manifest.json` + the listed files.
    let present = src.walk_relative_files()?;
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
    src: &PackageSource,
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

    // Fail-fast: any single missing/extra key is enough to reject (a verifier
    // needs one reason). `if let … .next()` states that intent directly — a
    // `for` that always returns on the first item reads as an accident.
    if let Some(missing) = covered.difference(&map_keys).next() {
        return Err(PackageVerifyError::FilesSha256(format!(
            "listed file `{missing}` has no entry in files_sha256 (the map, \
             when present, must cover every listed file except manifest.json)"
        )));
    }
    if let Some(extra) = map_keys.difference(&covered).next() {
        return Err(PackageVerifyError::FilesSha256(format!(
            "files_sha256 has an entry for `{extra}`, which is not a listed \
             file (or is manifest.json, which cannot commit to its own bytes)"
        )));
    }

    for (rel, expected) in map {
        let bytes = src.read_capped(rel)?;
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
    src: &PackageSource,
    verdict: &PackagedVerdict,
    report: &mut PackageReport,
) -> Result<(), PackageVerifyError> {
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
    // Deterministic bail order cross-platform (`read_dir` is unordered;
    // `list_dir_sorted` is what sorts it).
    let paths = src.list_dir_sorted("evidence")?;

    for path in &paths {
        let bytes = src.read_capped(path)?;
        let ev: PackagedEvidence = parse_json(&bytes, &src.display(path))?;
        let id: Uuid = ev.id.parse().map_err(|_| {
            PackageVerifyError::Evidence(format!(
                "evidence file {} carries a malformed UUID id `{}`",
                src.display(path),
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
    src: &PackageSource,
    verdict: &PackagedVerdict,
    report: &mut PackageReport,
) -> Result<(), PackageVerifyError> {
    let ruleset_bytes = src.read_capped("ruleset.json")?;
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

fn parse_json<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    what: &str,
) -> Result<T, PackageVerifyError> {
    serde_json::from_slice(bytes).map_err(|e| PackageVerifyError::Malformed {
        path: what.to_string(),
        detail: e.to_string(),
    })
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

    /// The output-boundary sanitizer redacts the reserved token in every
    /// case form, leaves other text untouched, and never breaks UTF-8
    /// around multibyte neighbors.
    #[test]
    fn sanitize_reserved_token_redacts_all_case_forms() {
        assert_eq!(
            sanitize_reserved_token("VERIFIED"),
            "VERIF[REDACTED]",
            "exact token redacted"
        );
        assert_eq!(
            sanitize_reserved_token("file Verified_x.txt vErIfIeD"),
            "file VERIF[REDACTED]_x.txt VERIF[REDACTED]",
            "case-insensitive, every occurrence"
        );
        let sanitized = sanitize_reserved_token("§ before VERIFIED after µ");
        assert!(!sanitized.to_ascii_uppercase().contains("VERIFIED"));
        assert!(sanitized.contains('§') && sanitized.contains('µ'), "UTF-8 intact");
        assert_eq!(
            sanitize_reserved_token("integrity check failed"),
            "integrity check failed",
            "non-matching text passes verbatim"
        );
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

    // ─── the seam: `Dir` and `Memory` are two views of ONE verification ──

    /// Load a package directory the way a host with no filesystem would
    /// receive it: every regular file keyed by its forward-slash relative
    /// path, AND every directory walked on the way — empty ones included,
    /// which is what a browser directory drop also enumerates and what an
    /// empty `evidence/empty_sub/` needs in order to exist at all.
    fn load_package_files(dir: &Path) -> PackageFiles {
        let mut files = PackageFiles::new();
        let mut stack: Vec<(PathBuf, String)> = vec![(dir.to_path_buf(), String::new())];
        while let Some((cur, prefix)) = stack.pop() {
            for entry in fs::read_dir(&cur).expect("corpus package is readable") {
                let entry = entry.expect("corpus package entry");
                let name = entry.file_name().to_string_lossy().into_owned();
                let rel = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                if entry.file_type().expect("entry file type").is_dir() {
                    files
                        .insert_dir(&rel)
                        .expect("a corpus directory name is a valid key");
                    stack.push((entry.path(), rel));
                } else {
                    let bytes = fs::read(entry.path()).expect("corpus package file");
                    files.insert(&rel, bytes).expect("corpus packages are under the caps");
                }
            }
        }
        files
    }

    /// The `Dir` arm names files by their on-disk path; the `Memory` arm
    /// names them by the relative key. Strip the one prefix that separates
    /// them (and the platform separator) so the REST of the message is
    /// compared byte for byte.
    fn strip_dir_prefix(msg: &str, dir: &Path) -> String {
        let prefix = format!("{}{}", dir.display(), std::path::MAIN_SEPARATOR);
        msg.replace(&prefix, "").replace('\\', "/")
    }

    /// The `--expected-verdict-hash` the corpus case passes, if any.
    fn corpus_expected_hash(case_dir: &Path) -> Option<String> {
        let cmd = fs::read_to_string(case_dir.join("cmd.txt")).ok()?;
        let mut it = cmd.split_whitespace();
        while let Some(a) = it.next() {
            if a == "--expected-verdict-hash" {
                return it.next().map(str::to_string);
            }
        }
        None
    }

    /// INTENT: `PackageSource::Dir` and `PackageSource::Memory` are two
    /// VIEWS of one verification, not two implementations. For every
    /// corpus package, loading the tree into `PackageFiles` and calling
    /// `verify_package_files` must yield a report/error whose discriminant,
    /// steps, warnings, recomputed hash and anchoring are equal to
    /// `verify_package(dir)`'s, and whose message differs only by the
    /// directory prefix. The two DoS caps that moved to
    /// `PackageFiles::insert` keep their values and their error values.
    ///
    /// CONTEXT: T11's hypothesis is that ONE code path serves two hosts —
    /// the CLI on a filesystem and a browser page with none. This is that
    /// claim reduced to a native test that needs no wasm toolchain, and it
    /// is the only reason the refactor is allowed to exist.
    ///
    /// EXPIRES IF: the page stops reconstructing an extracted package
    /// directory (i.e. the `Memory` arm is no longer a view of a directory
    /// but of some other container).
    #[test]
    fn test_intent_dir_and_memory_sources_agree_on_every_corpus_package() {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corpus");
        let mut visited = 0usize;
        let mut multi_evidence = 0usize;

        for entry in fs::read_dir(&corpus).expect("corpus root is readable") {
            let case_dir = entry.expect("corpus case entry").path();
            let pkg = case_dir.join("pkg");
            if !pkg.is_dir() {
                continue;
            }
            visited += 1;
            let case = case_dir.file_name().unwrap().to_string_lossy().into_owned();
            let files = load_package_files(&pkg);
            let expected = corpus_expected_hash(&case_dir);
            let expected = expected.as_deref();

            // The two arms must agree on the ORDER they see `evidence/` in
            // — that order decides which evidence file a failing package
            // is blamed on.
            let dir_listing = PackageSource::Dir(&pkg)
                .list_dir_sorted("evidence")
                .expect("dir listing");
            let mem_listing = PackageSource::Memory(&files)
                .list_dir_sorted("evidence")
                .expect("memory listing");
            assert_eq!(
                dir_listing, mem_listing,
                "case `{case}`: the two arms disagree on the evidence/ order"
            );
            let mut ascending = dir_listing.clone();
            ascending.sort();
            assert_eq!(
                dir_listing, ascending,
                "case `{case}`: evidence/ must be listed in ascending order"
            );
            if dir_listing.len() > 1 {
                multi_evidence += 1;
            }

            match (
                verify_package(&pkg, expected),
                verify_package_files(&files, expected),
            ) {
                (Ok(d), Ok(m)) => {
                    assert_eq!(d.steps, m.steps, "case `{case}`: steps diverge");
                    assert_eq!(d.warnings, m.warnings, "case `{case}`: warnings diverge");
                    assert_eq!(
                        d.verdict_hash, m.verdict_hash,
                        "case `{case}`: recomputed hash diverges"
                    );
                    assert_eq!(d.anchored, m.anchored, "case `{case}`: anchoring diverges");
                }
                (Err(d), Err(m)) => {
                    assert_eq!(
                        std::mem::discriminant(&d),
                        std::mem::discriminant(&m),
                        "case `{case}`: error VARIANT diverges — dir: {d}; memory: {m}"
                    );
                    assert_eq!(
                        strip_dir_prefix(&d.to_string(), &pkg),
                        strip_dir_prefix(&m.to_string(), &pkg),
                        "case `{case}`: error message diverges by more than the \
                         directory prefix"
                    );
                }
                (d, m) => panic!(
                    "case `{case}`: one arm succeeded and the other did not — \
                     dir: {d:?}; memory: {m:?}"
                ),
            }
        }

        assert!(
            visited >= 80,
            "only {visited} corpus packages visited; a suite that runs nothing \
             passes for the wrong reason"
        );
        assert!(
            multi_evidence >= 1,
            "no corpus package carries two evidence files, so the evidence/ \
             ordering claim above was never exercised"
        );

        // `Memory` cannot report a symlink, but it MUST still report an
        // absent key as absent — otherwise step 1's existence check is a
        // no-op for a host without a filesystem.
        let empty = PackageFiles::new();
        assert!(
            matches!(
                PackageSource::Memory(&empty).entry_kind("manifest.json"),
                EntryKind::Missing
            ),
            "an absent key must be Missing, not Regular"
        );

        // `display` is what puts a file's NAME into an Io/Malformed error;
        // an empty one turns every such error anonymous.
        assert_eq!(
            PackageSource::Memory(&empty).display("evidence/a.json"),
            "evidence/a.json",
            "the memory arm names a file by its relative path"
        );

        // The CARDINALITY cap moved to `insert`: same value, same error
        // value, an earlier point. (The BYTE cap did not move — it stays in
        // `read_capped` on both arms; see the boundary test below.)
        let mut many = PackageFiles::new();
        for i in 0..MAX_PACKAGE_FILES {
            many.insert(&format!("f{i}.json"), Vec::new())
                .expect("entries up to the cardinality cap are accepted");
        }
        let before = many.len();
        let too_many = many
            .insert("one-too-many.json", Vec::new())
            .expect_err("the entry past the cardinality cap must be refused");
        assert!(
            matches!(&too_many, PackageVerifyError::Shape(m)
                if m.contains(&format!("more than {MAX_PACKAGE_FILES} files"))),
            "insert must refuse past MAX_PACKAGE_FILES with the walk's \
             wording: {too_many}"
        );
        // ONE spelling for both arms (M-1): the refusal `insert` returns is
        // byte-for-byte the one the directory walk returns, because there is
        // only one `format!` left in the file — see
        // `test_intent_verification_steps_never_touch_the_filesystem`, which
        // counts it.
        assert_eq!(
            too_many.to_string(),
            cardinality_dos_refusal().to_string(),
            "the two arms must refuse an over-populated package with the same bytes"
        );
        // The doc says the map is left unchanged on a refusal (M-3).
        assert_eq!(many.len(), before, "a refused insert must not grow the map");
        assert!(
            many.get("one-too-many.json").is_none(),
            "a refused insert must not store the entry"
        );
    }

    /// INTENT: the seam must not move WHICH failure a broken package is
    /// blamed on. When several defects coexist, both arms name the same
    /// file in the same variant, because both drive the same seven steps
    /// in the same order — the enum exists so an eager loader cannot
    /// reorder the reads.
    ///
    /// CONTEXT: 38 of the 92 corpus cases are `class=FAIL` and their token
    /// and exit code depend on WHICH check bails first. A refactor that
    /// preserved only the pass cases would be invisible to the corpus's
    /// pass half and wrong for its fail half.
    ///
    /// EXPIRES IF: the seven steps are deliberately reordered — which is a
    /// specification change (§9.6), not a refactor.
    #[test]
    fn test_intent_seam_preserves_the_first_error() {
        // (a) The SAME file is both oversized and malformed: both arms
        //     blame it, in the same variant, with the same cap sentence —
        //     at the same point of the verification, because the byte cap
        //     is applied by `read_capped` on BOTH arms.
        let tmp = tempdir();
        let oversized = vec![b'{'; MAX_INPUT_FILE_BYTES as usize + 1];
        fs::write(tmp.path().join("manifest.json"), &oversized).unwrap();
        let dir_err = verify_package(tmp.path(), None).unwrap_err();
        let mut files = PackageFiles::new();
        files
            .insert("manifest.json", oversized)
            .expect("the byte cap is a read-time refusal, not a load-time one");
        let mem_err = verify_package_files(&files, None)
            .expect_err("the memory arm caps the read exactly as the dir arm does");
        assert!(
            matches!(&dir_err, PackageVerifyError::Io { path, .. } if path.ends_with("manifest.json")),
            "the dir arm must blame manifest.json's size: {dir_err}"
        );
        assert_eq!(
            strip_dir_prefix(&dir_err.to_string(), tmp.path()),
            mem_err.to_string(),
            "an oversized file must be refused identically by both arms"
        );

        // (b) Two malformed documents: the STEP ORDER decides, not the
        //     container order. manifest.json is read before verdict.json.
        let tmp = tempdir();
        fs::write(tmp.path().join("manifest.json"), b"{ not json").unwrap();
        fs::write(tmp.path().join("verdict.json"), b"{ not json either").unwrap();
        let files = load_package_files(tmp.path());
        let dir_err = verify_package(tmp.path(), None).unwrap_err();
        let mem_err = verify_package_files(&files, None).unwrap_err();
        assert!(
            matches!(&dir_err, PackageVerifyError::Malformed { path, .. } if path == "manifest.json"),
            "manifest.json is parsed first: {dir_err}"
        );
        assert_eq!(
            strip_dir_prefix(&dir_err.to_string(), tmp.path()),
            strip_dir_prefix(&mem_err.to_string(), tmp.path()),
            "both arms must blame the same document first"
        );

        // (c) A malformed verdict.json alongside a malformed evidence file:
        //     verdict.json is parsed at the top, long before step 3 walks
        //     evidence/ — the evidence defect must stay invisible.
        let tmp = tempdir();
        fs::write(
            tmp.path().join("manifest.json"),
            br#"{"verdict_id":"x","verdict_hash":"y","chain_hash":"z","files":[]}"#,
        )
        .unwrap();
        fs::write(tmp.path().join("verdict.json"), b"{ not json").unwrap();
        fs::create_dir_all(tmp.path().join("evidence")).unwrap();
        fs::write(tmp.path().join("evidence").join("a.json"), b"{ nope").unwrap();
        let files = load_package_files(tmp.path());
        let dir_err = verify_package(tmp.path(), None).unwrap_err();
        let mem_err = verify_package_files(&files, None).unwrap_err();
        assert!(
            matches!(&dir_err, PackageVerifyError::Malformed { path, .. } if path == "verdict.json"),
            "verdict.json is parsed before step 3 walks evidence/: {dir_err}"
        );
        assert_eq!(
            strip_dir_prefix(&dir_err.to_string(), tmp.path()),
            strip_dir_prefix(&mem_err.to_string(), tmp.path()),
            "both arms must blame verdict.json, not the evidence file"
        );
    }


    /// The exit code the CLI derives from a verification
    /// (`bin/seetrex-verifier.rs`: anchored pass → 0, unanchored pass → 4,
    /// any failure → 1). Two arms that disagree on THIS disagree on the
    /// verdict, whatever their wording does.
    fn exit_class(r: &Result<PackageReport, PackageVerifyError>) -> u8 {
        match r {
            Ok(rep) if rep.anchored => 0,
            Ok(_) => 4,
            Err(_) => 1,
        }
    }

    /// Verify `dir` through both arms and demand they agree on the VARIANT
    /// and the EXIT CLASS. Returns the `Dir` arm's result so the caller can
    /// pin WHAT the agreed answer was — two arms that agree on the wrong
    /// answer are still a regression.
    fn assert_arms_agree(
        dir: &Path,
        what: &str,
    ) -> Result<PackageReport, PackageVerifyError> {
        let files = load_package_files(dir);
        let d = verify_package(dir, None);
        let m = verify_package_files(&files, None);
        assert_eq!(
            exit_class(&d),
            exit_class(&m),
            "{what}: the two arms disagree on the EXIT CLASS — dir: {d:?}; memory: {m:?}"
        );
        match (&d, &m) {
            (Err(de), Err(me)) => assert_eq!(
                std::mem::discriminant(de),
                std::mem::discriminant(me),
                "{what}: the two arms disagree on the error VARIANT — dir: {de}; memory: {me}"
            ),
            (Ok(dr), Ok(mr)) => {
                assert_eq!(dr.steps, mr.steps, "{what}: steps diverge");
                assert_eq!(dr.warnings, mr.warnings, "{what}: warnings diverge");
                assert_eq!(dr.verdict_hash, mr.verdict_hash, "{what}: hash diverges");
                assert_eq!(dr.anchored, mr.anchored, "{what}: anchoring diverges");
            }
            _ => unreachable!("an equal exit class means both arms took the same branch"),
        }
        d
    }

    /// Rewrite `manifest.json`'s `files` array in place.
    fn edit_manifest_files(dir: &Path, edit: impl FnOnce(&mut Vec<serde_json::Value>)) {
        let path = dir.join("manifest.json");
        let mut m: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut listed = m["files"].as_array().unwrap().clone();
        edit(&mut listed);
        m["files"] = serde_json::Value::Array(listed);
        write(&path, &m);
    }

    /// INTENT: the `Memory` arm is a VIEW of one verification, and that has
    /// to hold for the package shapes the corpus happens NOT to contain — a
    /// nested evidence tree, a core file absent, a manifest entry that names
    /// a directory, an oversized file no step ever reads. On every one of
    /// them the two arms must answer the same error VARIANT and the same
    /// EXIT CLASS. Wording may differ; where it does, the difference is
    /// declared on [`PackageSource`]. A VERDICT may not differ.
    ///
    /// CONTEXT: the corpus is 83 real packages. A view that agrees on all of
    /// them and diverges on the first shape nobody ever packaged is not a
    /// view — it is a second implementation that has not been caught yet.
    /// Each case below WAS a measured divergence of this seam before it was
    /// a test: the nested tree passed in memory (exit 4) while the CLI
    /// refused it (exit 1), and an oversized file no step reads was accepted
    /// on disk and refused at load.
    ///
    /// EXPIRES IF: the page stops reconstructing an extracted package
    /// directory, or the seven steps stop reading through `PackageSource`.
    #[test]
    fn test_intent_the_two_arms_agree_on_the_shapes_no_corpus_case_has() {
        // (a) A nested tree under `evidence/`. `read_dir` yields the
        //     DIRECTORY `evidence/sub`, and step 3 fails trying to read it;
        //     a flat map has no entry for `sub`, so the memory arm has to
        //     synthesise the name from the keys nested below it. Without
        //     that, the same bytes pass in memory and fail on disk.
        let tmp = tempdir();
        minimal_v1_package(tmp.path());
        fs::create_dir_all(tmp.path().join("evidence").join("sub")).unwrap();
        fs::write(
            tmp.path().join("evidence").join("sub").join("x.json"),
            br#"{"id":"11111111-1111-1111-1111-111111111111"}"#,
        )
        .unwrap();
        edit_manifest_files(tmp.path(), |f| {
            f.push(serde_json::Value::String("evidence/sub/x.json".to_string()))
        });
        let files = load_package_files(tmp.path());
        let dir_listing = PackageSource::Dir(tmp.path())
            .list_dir_sorted("evidence")
            .expect("dir listing");
        let mem_listing = PackageSource::Memory(&files)
            .list_dir_sorted("evidence")
            .expect("memory listing");
        assert!(
            dir_listing.iter().any(|e| e == "evidence/sub"),
            "read_dir yields the nested DIRECTORY itself: {dir_listing:?}"
        );
        assert_eq!(
            dir_listing, mem_listing,
            "the memory arm must list the same immediate children, directories included"
        );
        let d = assert_arms_agree(tmp.path(), "a nested tree under evidence/");
        assert!(
            matches!(&d, Err(PackageVerifyError::Io { .. })),
            "a nested evidence tree is an unreadable entry, not a pass: {d:?}"
        );

        // (b) A core file the steps READ is absent. This is the only way the
        //     memory arm's missing-key branch can fire, and its `detail` is
        //     a declared difference (there is no OS error to quote).
        let tmp = tempdir();
        minimal_v1_package(tmp.path());
        fs::remove_file(tmp.path().join("ruleset.json")).unwrap();
        edit_manifest_files(tmp.path(), |f| f.retain(|v| v != "ruleset.json"));
        let d = assert_arms_agree(tmp.path(), "ruleset.json absent");
        assert!(
            matches!(&d, Err(PackageVerifyError::Io { path, .. }) if path.ends_with("ruleset.json")),
            "step 5 must blame the absent ruleset.json: {d:?}"
        );
        let files = load_package_files(tmp.path());
        let mem = PackageSource::Memory(&files)
            .read_capped("ruleset.json")
            .expect_err("a key that is not in the map cannot be read");
        assert!(
            mem.to_string().contains("no such file in the package"),
            "the declared memory wording for an absent key: {mem}"
        );

        // (c) A manifest entry that names a DIRECTORY. On disk it is present
        //     but not regular; in memory it is not a key at all. Both are
        //     Shape, both exit 1, and the wording difference is declared.
        let tmp = tempdir();
        minimal_v1_package(tmp.path());
        fs::create_dir_all(tmp.path().join("nested")).unwrap();
        edit_manifest_files(tmp.path(), |f| {
            f.push(serde_json::Value::String("nested".to_string()))
        });
        let d = assert_arms_agree(tmp.path(), "a manifest entry naming a directory");
        assert!(
            matches!(&d, Err(PackageVerifyError::Shape(m)) if m.contains("not a regular file")),
            "the dir arm refuses a directory as `not a regular file`: {d:?}"
        );

        // (d) An oversized file that is LISTED but that no step ever reads.
        //     The directory arm accepts it (the cap lives at the reads), so
        //     the memory arm must accept it too — a load-time cap would make
        //     the same package a different VERDICT, not an earlier point.
        let tmp = tempdir();
        minimal_v1_package(tmp.path());
        fs::write(
            tmp.path().join("unread.bin"),
            vec![b'x'; MAX_INPUT_FILE_BYTES as usize + 1],
        )
        .unwrap();
        edit_manifest_files(tmp.path(), |f| {
            f.push(serde_json::Value::String("unread.bin".to_string()))
        });
        let d = assert_arms_agree(tmp.path(), "an oversized file no step reads");
        assert!(
            matches!(&d, Ok(rep) if !rep.anchored),
            "a listed-but-unread oversized file is accepted on disk: {d:?}"
        );

        // (e) An EMPTY directory under `evidence/`. `read_dir` yields it and
        //     step 3 fails trying to read it; a map built from FILES ALONE
        //     has no trace of it whatsoever — not even a nested key to
        //     synthesise the name from — so the memory arm listed nothing
        //     and PASSED the package the CLI refuses. An empty directory is
        //     the one shape a flat map cannot infer: the builder has to
        //     DECLARE it (`PackageFiles::insert_dir`).
        let tmp = tempdir();
        minimal_v1_package(tmp.path());
        fs::create_dir_all(tmp.path().join("evidence").join("empty_sub")).unwrap();
        let files = load_package_files(tmp.path());
        let dir_listing = PackageSource::Dir(tmp.path())
            .list_dir_sorted("evidence")
            .expect("dir listing");
        let mem_listing = PackageSource::Memory(&files)
            .list_dir_sorted("evidence")
            .expect("memory listing");
        assert!(
            dir_listing.iter().any(|e| e == "evidence/empty_sub"),
            "read_dir yields the EMPTY directory itself: {dir_listing:?}"
        );
        assert_eq!(
            dir_listing, mem_listing,
            "the memory arm must list the same immediate children, EMPTY \
             directories included"
        );
        let d = assert_arms_agree(tmp.path(), "an empty directory under evidence/");
        assert!(
            matches!(&d, Err(PackageVerifyError::Io { .. })),
            "an empty evidence subdirectory is an unreadable entry, not a pass: {d:?}"
        );

        // (f) An empty directory at the ROOT of the package. No step ever
        //     lists the root's directories, so this one has to agree the
        //     OTHER way: `walk_relative_files` yields FILES on both arms, an
        //     empty directory is not an undeclared extra, and both arms
        //     accept. Recording directories must not turn a pass into a
        //     refusal.
        let tmp = tempdir();
        minimal_v1_package(tmp.path());
        fs::create_dir_all(tmp.path().join("stray_dir")).unwrap();
        let d = assert_arms_agree(tmp.path(), "an empty directory at the package root");
        assert!(
            matches!(&d, Ok(rep) if !rep.anchored),
            "an empty directory at the root is not an undeclared extra file: {d:?}"
        );
    }

    /// INTENT: `MAX_PACKAGE_FILES` bounds FILES, and DIRECTORIES are the
    ///     HOST's obligation -- measured on both arms over the same tree,
    ///     not reasoned from the code. A package carrying one MORE empty
    ///     root directory than the file cap is ACCEPTED on disk, so a cap on
    ///     `insert_dir` would refuse a package the executable passes: a
    ///     different VERDICT, which the two arms may never have.
    /// CONTEXT: round R3 asked for a shared ceiling over files + directories.
    ///     The `Dir` arm cannot have one: `walk_relative_files` counts files,
    ///     `read_dir` recurses through empty directories and yields nothing
    ///     from them, and no step lists the package root at all. Capping the
    ///     memory arm alone is the divergence, not the fix. What the crate
    ///     owes instead is that the COST of carrying them stays sub-linear
    ///     per lookup, which `PackageFiles::nests_something` does by ranging
    ///     an ordered collection instead of scanning it.
    /// EXPIRES IF: the directory walk starts counting directories against a
    ///     cardinality cap of its own -- at which point the two arms can and
    ///     must share it.
    #[test]
    fn test_intent_directory_cardinality_is_the_hosts_obligation() {
        let tmp = tempdir();
        minimal_v1_package(tmp.path());
        // One MORE than the FILE cap, at the package root, all empty.
        for i in 0..=MAX_PACKAGE_FILES {
            fs::create_dir_all(tmp.path().join(format!("d{i}"))).unwrap();
        }
        let d = assert_arms_agree(
            tmp.path(),
            "more empty root directories than MAX_PACKAGE_FILES",
        );
        assert!(
            matches!(&d, Ok(report) if !report.anchored),
            "the Dir arm counts FILES: {} empty directories are not a cardinality              refusal, and the memory arm must not invent one: {d:?}",
            MAX_PACKAGE_FILES + 1
        );
        let files = load_package_files(tmp.path());
        assert_eq!(
            files.dir_names().count(),
            MAX_PACKAGE_FILES + 2,
            "the memory arm holds every directory the walk met (the {} roots plus              `evidence`)",
            MAX_PACKAGE_FILES + 1
        );
        assert!(
            files.contains_dir(&format!("d{MAX_PACKAGE_FILES}")),
            "the directory past the file cap is one of them"
        );
    }

    /// INTENT: a `PackageFiles` key is a relative path a directory walk
    /// could actually EMIT. `""`, `"evidence/"`, `"evidence//b.json"`,
    /// `"evidence\\b.json"`, `"./b.json"` and `"../b.json"` are not, and
    /// every one of them is refused at insert time with
    /// [`PackageVerifyError::Shape`] — the variant the `Dir` arm answers
    /// for a manifest entry of the same shape.
    ///
    /// CONTEXT: measured — `insert("evidence/", …)` and
    /// `insert("evidence//b.json", …)` both returned `Ok`, and the key was
    /// then INVISIBLE to step 3: `walk_relative_files` lists a key verbatim
    /// while `list_dir_sorted` splits it on `/` and finds no child, so an
    /// entry the `Dir` arm would refuse was carried silently past the only
    /// step that looks at it. A key the directory walk can never emit is a
    /// key the two arms cannot be made to agree on.
    ///
    /// EXPIRES IF: package keys stop being forward-slash relative paths
    /// (i.e. `PackageFiles` stops being a view of an extracted directory).
    #[test]
    fn test_intent_package_files_rejects_keys_no_directory_could_produce() {
        let bad = [
            "",
            "/",
            ".",
            "..",
            "evidence/",
            "/evidence/b.json",
            "evidence//b.json",
            "evidence\\b.json",
            "./b.json",
            "../b.json",
            "evidence/../../etc/passwd",
        ];
        for key in bad {
            let mut files = PackageFiles::new();
            let err = files
                .insert(key, b"{}".to_vec())
                .expect_err("a key no directory walk could emit must be refused");
            assert!(
                matches!(err, PackageVerifyError::Shape(_)),
                "a malformed key is refused the way the Dir arm refuses the \
                 manifest entry: {key:?} gave {err:?}"
            );
            assert_eq!(files.len(), 0, "a refused key must not be stored: {key:?}");
            let mut dirs = PackageFiles::new();
            let err = dirs
                .insert_dir(key)
                .expect_err("insert_dir validates exactly the keys insert does");
            assert!(
                matches!(err, PackageVerifyError::Shape(_)),
                "a malformed directory key is a Shape refusal too: {key:?} gave {err:?}"
            );
        }

        let good = ["manifest.json", "evidence/x.json", "a/b/c/d.json"];
        for key in good {
            let mut files = PackageFiles::new();
            files
                .insert(key, b"{}".to_vec())
                .expect("a plain relative path is a key");
            assert_eq!(files.get(key), Some(&b"{}"[..]));
            let mut dirs = PackageFiles::new();
            dirs.insert_dir(key)
                .expect("a plain relative path names a directory too");
        }

        // A name cannot be BOTH a file and a directory: on disk it is one or
        // the other, and `entry_kind` would have to guess. Refused in either
        // order.
        let mut both = PackageFiles::new();
        both.insert("evidence", b"{}".to_vec()).unwrap();
        assert!(
            matches!(both.insert_dir("evidence"), Err(PackageVerifyError::Shape(_))),
            "a file key cannot be re-declared as a directory"
        );
        let mut both = PackageFiles::new();
        both.insert_dir("evidence").unwrap();
        assert!(
            matches!(
                both.insert("evidence", b"{}".to_vec()),
                Err(PackageVerifyError::Shape(_))
            ),
            "a directory key cannot be re-declared as a file"
        );

        // …and a name is a DIRECTORY when a file key is nested under it,
        // even though nobody declared it. Measured before this guard: both
        // orders below returned `Ok`, and the map then held `evidence` as a
        // file AND as the parent of `evidence/x.json` — a shape no disk can
        // hold, where `entry_kind` says `Regular` and `read_capped` says
        // "is a directory".
        let mut implied = PackageFiles::new();
        implied.insert("evidence/x.json", b"{}".to_vec()).unwrap();
        let err = implied
            .insert("evidence", b"{}".to_vec())
            .expect_err("a name that already nests a file is not also a file");
        assert!(
            matches!(&err, PackageVerifyError::Shape(m) if m.contains("evidence")),
            "the implied-directory refusal is the declared one, word for word: {err:?}"
        );
        assert_eq!(implied.len(), 1, "a refused insert must not grow the map");

        let mut implied = PackageFiles::new();
        implied.insert("evidence", b"{}".to_vec()).unwrap();
        let err = implied
            .insert("evidence/x.json", b"{}".to_vec())
            .expect_err("a file cannot be nested under a name stored as a file");
        assert!(
            matches!(&err, PackageVerifyError::Shape(m) if m.contains("`evidence`")),
            "the refusal names the ANCESTOR given as both: {err:?}"
        );
        assert_eq!(implied.len(), 1, "a refused insert must not grow the map");

        // The same, one level deeper, so the check is not "the first
        // segment" by accident.
        let mut implied = PackageFiles::new();
        implied.insert("a/b", b"{}".to_vec()).unwrap();
        assert!(
            matches!(
                implied.insert("a/b/c.json", b"{}".to_vec()),
                Err(PackageVerifyError::Shape(_))
            ),
            "an ancestor at any depth is still a name given as both"
        );
        // A SIBLING prefix is not an ancestor: `a/bb.json` is not under
        // `a/b`, and a guard that used a bare string prefix would refuse it.
        implied
            .insert("a/bb.json", b"{}".to_vec())
            .expect("a sibling whose name merely starts the same is not nested");
    }

    /// INTENT: `MAX_INPUT_FILE_BYTES` is a `>` boundary, and it is the SAME
    /// boundary on both arms — a file of exactly the cap is readable, one
    /// byte more is refused with the same sentence.
    ///
    /// CONTEXT: the cap moved to the seam. `>=` instead of `>` shifts the
    /// boundary by one byte on a DoS guard and no corpus package sits on it,
    /// so nothing but this test can see the difference.
    ///
    /// EXPIRES IF: the cap stops being a per-file read bound.
    #[test]
    fn test_intent_the_byte_cap_is_the_same_boundary_on_both_arms() {
        let tmp = tempdir();
        let at_cap = vec![b'x'; MAX_INPUT_FILE_BYTES as usize];
        let over_cap = vec![b'x'; MAX_INPUT_FILE_BYTES as usize + 1];
        fs::write(tmp.path().join("at-cap.bin"), &at_cap).unwrap();
        fs::write(tmp.path().join("over-cap.bin"), &over_cap).unwrap();
        let mut files = PackageFiles::new();
        files.insert("at-cap.bin", at_cap).unwrap();
        files.insert("over-cap.bin", over_cap).unwrap();

        let dir = PackageSource::Dir(tmp.path());
        let mem = PackageSource::Memory(&files);

        // EXACTLY the cap is accepted. The boundary is `>`, not `>=`.
        assert_eq!(
            dir.read_capped("at-cap.bin")
                .expect("dir: a file of exactly the cap is readable")
                .len() as u64,
            MAX_INPUT_FILE_BYTES
        );
        assert_eq!(
            mem.read_capped("at-cap.bin")
                .expect("memory: a file of exactly the cap is readable")
                .len() as u64,
            MAX_INPUT_FILE_BYTES
        );

        // One byte past it is refused, with the same bytes on both arms.
        let d = dir
            .read_capped("over-cap.bin")
            .expect_err("dir: one byte past the cap is refused");
        let m = mem
            .read_capped("over-cap.bin")
            .expect_err("memory: one byte past the cap is refused");
        assert_eq!(
            strip_dir_prefix(&d.to_string(), tmp.path()),
            m.to_string(),
            "the two arms must refuse an oversized file with the same bytes"
        );
        assert!(
            m.to_string()
                .contains(&format!("exceeds the {MAX_INPUT_FILE_BYTES} byte cap")),
            "the cap sentence names the cap: {m}"
        );
    }

    /// INTENT: `join_rel` builds a path ONE COMPONENT AT A TIME; it is not
    /// `Path::join` of the whole relative string. Two consequences are
    /// asserted here, both unconditionally: the rendered path carries the
    /// platform's separator between every component (on Windows
    /// `dir.join("evidence/x.json")` keeps the forward slash verbatim and
    /// renders a MIXED separator), and a relative string can never REPLACE
    /// the base — `Path::join` of a rooted string discards the base on every
    /// platform, `join_rel` pushes it as ordinary components.
    ///
    /// CONTEXT: the first version of this pin asserted, under
    /// `cfg(not(windows))`, that `join_rel(base, rel) == base.join(rel)` —
    /// which is exactly what the mutant `dir.join(rel)` produces, so on the
    /// platform CI gates on the pin CERTIFIED the mutant instead of
    /// refusing it. For a well-formed relative path the two really are
    /// byte-identical on POSIX (`/` IS the separator) and nothing can
    /// separate them; the ROOTED input below is what makes the same mutant
    /// red on POSIX as well as on Windows. `validate_confined_relpath`
    /// refuses a rooted manifest entry long before any join, so that input
    /// reaches `join_rel` only from this test — which is the point: the
    /// difference between the two implementations has to be observable
    /// somewhere, or it cannot be held.
    ///
    /// EXPIRES IF: package error messages stop carrying an on-disk path.
    #[test]
    fn test_intent_join_rel_spells_paths_the_way_read_dir_does() {
        let base = Path::new("base");
        let joined = PackageSource::join_rel(base, "evidence/x.json");

        // One component at a time, on every platform.
        let per_component: PathBuf = ["base", "evidence", "x.json"].iter().collect();
        assert_eq!(
            joined, per_component,
            "join_rel pushes one component at a time"
        );
        assert_eq!(
            joined.components().count(),
            base.components().count() + 2,
            "a two-segment relative path adds exactly two components"
        );
        for component in joined.components() {
            let name = component.as_os_str().to_string_lossy();
            assert!(
                !name.contains('/') && !name.contains('\\'),
                "no separator may survive INSIDE a component: {name:?}"
            );
        }
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(
            joined.display().to_string(),
            format!("base{sep}evidence{sep}x.json"),
            "every separator in the rendered path is the platform's own"
        );

        // A ROOTED relative string is pushed as ordinary components and does
        // not replace the base. `Path::join` discards the base for the same
        // string on BOTH Windows and POSIX, so this is the assertion that
        // makes the mutant `dir.join(rel)` red on the platform CI gates on.
        let rooted = PackageSource::join_rel(base, "/etc/passwd");
        assert!(
            rooted.starts_with(base),
            "join_rel never lets a relative string replace the base: {rooted:?}"
        );
        // `join_absolute_paths` is exactly the behaviour under test here.
        #[allow(clippy::join_absolute_paths)]
        let joined_absolute = base.join("/etc/passwd");
        assert!(
            !joined_absolute.starts_with(base),
            "… and `Path::join` of the same string does, which is exactly why \
             the two are not interchangeable"
        );

        #[cfg(windows)]
        assert_ne!(
            joined.display().to_string(),
            base.join("evidence/x.json").display().to_string(),
            "on Windows `dir.join(rel)` renders a mixed separator; join_rel is what normalises it"
        );
    }

    /// This file, with every comment, string literal and char literal
    /// blanked out and its BYTE LENGTH preserved. A test that scans source
    /// for `File::open` must not fire on a comment that merely mentions it,
    /// and it must not fire on its own assertion messages either.
    fn blank_comments_and_literals(src: &str) -> String {
        let b = src.as_bytes();
        let n = b.len();
        let mut out = vec![b' '; n];
        let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        let mut i = 0usize;
        while i < n {
            // Keep newlines everywhere so offsets AND lines both survive.
            if b[i] == b'\n' {
                out[i] = b[i];
                i += 1;
                continue;
            }
            // Line comment.
            if b[i] == b'/' && i + 1 < n && b[i + 1] == b'/' {
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            // Block comment (nesting).
            if b[i] == b'/' && i + 1 < n && b[i + 1] == b'*' {
                let mut depth = 1usize;
                i += 2;
                while i < n && depth > 0 {
                    if b[i] == b'/' && i + 1 < n && b[i + 1] == b'*' {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && i + 1 < n && b[i + 1] == b'/' {
                        depth -= 1;
                        i += 2;
                    } else {
                        if b[i] == b'\n' {
                            out[i] = b[i];
                        }
                        i += 1;
                    }
                }
                continue;
            }
            // Raw / byte string: [b][r]#*" ... "#*
            if (b[i] == b'r' || b[i] == b'b') && (i == 0 || !ident(b[i - 1])) {
                let mut j = i;
                if b[j] == b'b' {
                    j += 1;
                }
                if j < n && b[j] == b'r' {
                    j += 1;
                    let mut hashes = 0usize;
                    while j < n && b[j] == b'#' {
                        hashes += 1;
                        j += 1;
                    }
                    if j < n && b[j] == b'"' {
                        j += 1;
                        while j < n {
                            if b[j] == b'"' {
                                let close = b[j + 1..n.min(j + 1 + hashes)]
                                    .iter()
                                    .filter(|c| **c == b'#')
                                    .count();
                                if close == hashes {
                                    j += 1 + hashes;
                                    break;
                                }
                            }
                            if b[j] == b'\n' {
                                out[j] = b[j];
                            }
                            j += 1;
                        }
                        i = j;
                        continue;
                    }
                }
            }
            // Ordinary string literal (b"…" included).
            if b[i] == b'"' || (b[i] == b'b' && i + 1 < n && b[i + 1] == b'"') {
                let mut j = if b[i] == b'"' { i + 1 } else { i + 2 };
                while j < n {
                    if b[j] == b'\\' {
                        j += 2;
                        continue;
                    }
                    if b[j] == b'"' {
                        j += 1;
                        break;
                    }
                    if b[j] == b'\n' {
                        out[j] = b[j];
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
            // Char literal vs lifetime.
            if b[i] == b'\'' {
                let escaped = i + 1 < n && b[i + 1] == b'\\';
                let plain = i + 2 < n && b[i + 2] == b'\'';
                if escaped || plain {
                    let mut j = if escaped { i + 3 } else { i + 1 };
                    while j < n && b[j] != b'\'' {
                        j += 1;
                    }
                    i = (j + 1).min(n);
                    continue;
                }
            }
            out[i] = b[i];
            i += 1;
        }
        String::from_utf8(out).expect("blanking only ever writes ASCII spaces")
    }

    /// Every `fn` declared in the NON-test half of this file, as
    /// `(name, open, close)`: the byte span of the `{ … }` body that
    /// follows the signature.
    ///
    /// Scanning the HALF is what makes the purity gate closed. A list of
    /// anchors can only see the bodies somebody remembered to name; a
    /// helper a later change adds, or a step renamed, is simply not in it.
    fn production_fn_bodies(scrubbed: &str) -> Vec<(String, usize, usize)> {
        let end = scrubbed
            .find("#[cfg(test)]")
            .expect("package.rs separates its production half with a cfg(test) marker");
        let prod = &scrubbed[..end];
        let b = prod.as_bytes();
        let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        let mut out: Vec<(String, usize, usize)> = Vec::new();
        let mut i = 0usize;
        while let Some(rel) = prod[i..].find("fn ") {
            let at = i + rel;
            i = at + 3;
            if at > 0 && ident(b[at - 1]) {
                continue; // `…_fn ` is not a declaration
            }
            let name_start = at + 3;
            let mut j = name_start;
            while j < b.len() && ident(b[j]) {
                j += 1;
            }
            if j == name_start {
                continue;
            }
            let name = prod[name_start..j].to_string();
            let Some(open_rel) = prod[j..].find('{') else {
                continue;
            };
            let open = j + open_rel;
            let mut depth = 0i32;
            let mut close = None;
            for (k, byte) in b.iter().enumerate().skip(open) {
                if *byte == b'{' {
                    depth += 1;
                } else if *byte == b'}' {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(k);
                        break;
                    }
                }
            }
            let close = close.unwrap_or_else(|| panic!("unbalanced body for `fn {name}`"));
            out.push((name, open, close));
            // A nested `fn`'s text is part of the body already recorded.
            i = close + 1;
        }
        out
    }

    /// Whether `text` contains `needle` as a TOKEN — at a word boundary.
    ///
    /// `RulesetFile::` is not `File::`, and a scan that cannot tell them
    /// apart fires on code that touches nothing, which is how a purity gate
    /// stops being read.
    fn contains_token(text: &str, needle: &str) -> bool {
        let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        let b = text.as_bytes();
        let n = needle.as_bytes();
        if n.is_empty() || b.len() < n.len() {
            return false;
        }
        (0..=(b.len() - n.len()))
            .any(|at| &b[at..at + n.len()] == n && (at == 0 || !ident(b[at - 1])))
    }

    /// `text` with every whitespace byte removed.
    ///
    /// Rust does not care where a path expression breaks: `std :: fs ::
    /// read` and `std::fs::read` are the same call, and rustfmt would only
    /// normalise the first one if it ever ran on it. Offsets are NOT
    /// preserved here -- unlike the scrubber -- which is why this is a
    /// second PASS over an already-delimited body rather than the text the
    /// bodies are cut out of.
    fn without_whitespace(text: &str) -> String {
        text.chars().filter(|c| !c.is_whitespace()).collect()
    }

    /// [`contains_token`], blind to whitespace inside the token.
    ///
    /// Measured: `contains_token` alone did not see `std :: fs :: read`,
    /// and a purity gate a space walks past is a purity gate.
    fn scan_hit(text: &str, needle: &str) -> bool {
        contains_token(text, needle) || contains_token(&without_whitespace(text), needle)
    }

    /// INTENT: `verify_package_files` says PURE — no filesystem. EVERY
    /// function in the production half of this file is scanned, and only a
    /// CLOSED allowlist of `PackageSource::Dir` helpers may contain a
    /// filesystem token. Everything else — the seven steps, their helpers,
    /// `PackageFiles`, and any function a later change adds — must be free
    /// of one; and outside those helpers no `use` may import `std::fs` or
    /// `std::io::Read`. A page compiled for a host with no `std::fs` runs
    /// THIS code, so a single `std::fs::read` smuggled into a step is a page
    /// that answers nothing while looking like it works.
    ///
    /// CONTEXT: the purity claim was a doc comment and nothing else — a
    /// `std::fs::read` added inside `step4_coherence` left the entire suite
    /// green, because every native test has a filesystem underneath it. The
    /// first version of THIS gate was a list of thirteen named bodies, and
    /// two measured mutants walked past it: `use std::fs::read as slurp;` at
    /// module scope called from `step4_coherence` (the call site carries no
    /// filesystem token at all), and a new helper `fn reread_manifest` that
    /// the list did not name. A list cannot see what it does not name, which
    /// is why the unit of the scan is the half and the allowlist is the
    /// thing that has to be justified. It is a SOURCE scan because no
    /// runtime assertion on a machine that HAS a filesystem can distinguish
    /// the two.
    ///
    /// WHAT IT DOES NOT COVER, stated rather than implied: the scan is
    /// `package.rs` and nothing else. A `std::fs` call smuggled into
    /// another module the steps reach would be invisible here, and what
    /// answers for that is BEHAVIOURAL: the wasm corpus oracle
    /// (`crates/verifier-web/tests/page_corpus.rs`) runs the whole of
    /// `verify_package_files` on `wasm32-unknown-unknown`, a target with no
    /// filesystem at all, against 92 cases. A source scan cannot follow a
    /// call out of the file; that build cannot make one.
    ///
    /// EXPIRES IF: the crate stops offering a filesystem-free entry point,
    /// or the steps stop reading through `PackageSource`.
    #[test]
    fn test_intent_verification_steps_never_touch_the_filesystem() {
        let source = include_str!("package.rs");
        let scrubbed = blank_comments_and_literals(source);
        assert_eq!(
            scrubbed.len(),
            source.len(),
            "the scrubber must preserve byte offsets"
        );
        // Non-vacuity of the scrubber itself: it must blank a comment while
        // keeping the code around it.
        assert!(
            scrubbed.contains("fn step4_coherence("),
            "the scrubber removed code it should have kept"
        );

        let needles = [
            "std::fs",
            "fs::",
            "File::",
            "read_dir",
            "symlink_metadata",
            "metadata(",
        ];
        // The ONLY functions allowed to reach a filesystem: the `Dir` arm
        // helpers of the seam. Adding a name here is a deliberate act.
        let allowed = [
            "read_capped",
            "entry_kind",
            "walk_relative_files",
            "list_dir_sorted",
        ];

        let cfg_test = scrubbed
            .find("#[cfg(test)]")
            .expect("package.rs separates its production half with a cfg(test) marker");
        let prod = &scrubbed[..cfg_test];
        let fns = production_fn_bodies(&scrubbed);
        assert!(
            fns.len() >= 30,
            "only {} production functions were scanned — the scanner is \
             looking at the wrong text",
            fns.len()
        );

        let mut allowlisted_seen: BTreeSet<String> = BTreeSet::new();
        for (name, open, close) in &fns {
            let body = &prod[*open..=*close];
            assert!(
                body.len() > 2,
                "`fn {name}` resolved to an empty body — the scanner is stale"
            );
            if allowed.contains(&name.as_str()) {
                allowlisted_seen.insert(name.clone());
                // An allowlisted helper that does no I/O is an allowlist
                // entry that has stopped being load-bearing.
                assert!(
                    needles.iter().any(|n| scan_hit(body, n)),
                    "`fn {name}` is allowlisted for filesystem access but \
                     contains none — remove it from the allowlist"
                );
                // … and its I/O sits in the `Dir` match arm, not the other.
                let split = body
                    .find("PackageSource::Memory")
                    .unwrap_or_else(|| panic!("`fn {name}` has no Memory arm to split on"));
                let (dir_arm, memory_arm) = body.split_at(split);
                assert!(
                    dir_arm.contains("PackageSource::Dir"),
                    "`fn {name}`'s filesystem access must sit in the \
                     `PackageSource::Dir` match arm"
                );
                for needle in needles {
                    assert!(
                        !scan_hit(memory_arm, needle),
                        "the Memory arm of `fn {name}` contains `{needle}`; it \
                         must reach no filesystem"
                    );
                }
                continue;
            }
            for needle in needles {
                assert!(
                    !scan_hit(body, needle),
                    "`fn {name}` contains the filesystem token `{needle}`; \
                     every read belongs behind PackageSource::Dir"
                );
            }
        }
        assert_eq!(
            allowlisted_seen.len(),
            allowed.len(),
            "the allowlist names a function this file no longer declares: \
             seen {allowlisted_seen:?}, allowed {allowed:?}"
        );

        // What is left of the production half once the allowlisted bodies are
        // blanked: module scope, `impl` headers, every signature. No
        // filesystem token may survive there — and no `use` may import one,
        // because `use std::fs::read as slurp;` renames the token away and
        // the needles alone cannot see the call site.
        let mut residue: Vec<u8> = prod.as_bytes().to_vec();
        for (name, open, close) in &fns {
            if allowed.contains(&name.as_str()) {
                for byte in &mut residue[*open..=*close] {
                    if *byte != b'\n' {
                        *byte = b' ';
                    }
                }
            }
        }
        let residue = String::from_utf8(residue).expect("blanking writes ASCII spaces");
        for needle in needles {
            assert!(
                !scan_hit(&residue, needle),
                "the filesystem token `{needle}` sits outside every allowlisted \
                 Dir helper"
            );
        }
        let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        let rb = residue.as_bytes();
        let mut idx = 0usize;
        let mut use_statements = 0usize;
        while let Some(rel) = residue[idx..].find("use ") {
            let at = idx + rel;
            idx = at + 4;
            if at > 0 && ident(rb[at - 1]) {
                continue; // the tail of an identifier, not a declaration
            }
            let end = residue[at..]
                .find(';')
                .map(|e| at + e)
                .unwrap_or(residue.len());
            let stmt = &residue[at..end];
            use_statements += 1;
            assert!(
                !stmt.contains("fs"),
                "a `use` outside the Dir helpers imports the filesystem: `{stmt}`"
            );
            assert!(
                !stmt.contains("io::Read"),
                "`std::io::Read` belongs inside the Dir helpers only: `{stmt}`"
            );
            idx = end.max(idx);
        }
        assert!(
            use_statements >= 8,
            "only {use_statements} `use` statements were scanned — the residue \
             is not the module scope"
        );

        // M-1: ONE spelling of the cardinality refusal in the whole file.
        // The needle is assembled here so this assertion is not itself an
        // occurrence of it.
        let refusal = ["refusing to process (cardinality", " DoS guard)"].concat();
        assert_eq!(
            source.matches(refusal.as_str()).count(),
            1,
            "the cardinality refusal must have exactly one spelling in this file"
        );
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
