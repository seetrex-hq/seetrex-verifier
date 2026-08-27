// SPDX-License-Identifier: Apache-2.0
//! `Cargo.lock` -> [`Projection`].
//!
//! The parser is OWN CODE over a deliberately small subset of TOML, not
//! a general TOML library. The reason is the auditor: this crate's
//! declared identity is a verification core free of any non-essential
//! dependency, and a general TOML parser drags half a dozen transitive
//! crates into `cargo install` for a file whose grammar Cargo itself
//! emits mechanically.
//!
//! The price of that choice is paid in two places, both here:
//!
//! - Anything outside the declared subset is [`SbomError::UnsupportedLockShape`],
//!   never a best-effort read. A hand-written parser that guesses wrong
//!   in silence produces an SBOM that is wrong in silence, which is the
//!   worst outcome available.
//! - A differential test parses the real `Cargo.lock` of this workspace
//!   through BOTH this parser and a reference TOML parser (a
//!   dev-dependency, so it never reaches an auditor's `cargo install`)
//!   and requires identical structures. "The own parser is correct" is
//!   therefore a falsifiable claim, re-checked on every run.
//!
//! ## The declared subset
//!
//! - `# ...` comments and blank lines, anywhere.
//! - exactly one top-level `version` key before the first table, whose
//!   value is one of [`SUPPORTED_LOCK_VERSIONS`];
//! - `[[package]]` array-of-table headers, each followed by the bare
//!   keys `name`, `version`, `source`, `checksum` (TOML basic strings
//!   with no escapes and no embedded quotes) and `dependencies` (either
//!   the inline empty array or the multi-line array of basic strings
//!   Cargo writes), each key defined AT MOST ONCE inside its table;
//! - a `[metadata]` table, whose contents are ignored -- EXCEPT that a
//!   `checksum ...` key inside it is an error rather than a line skipped:
//!   see below.
//!
//! Every other construct is an error, and so is a leading UTF-8
//! byte-order mark.
//!
//! ## The digests must be where this parser reads them
//!
//! Two rules hold whatever the top-level `version` says, because that key
//! is a LABEL and the thing that matters is the SHAPE:
//!
//! - a `checksum ...` key inside `[metadata]` is
//!   [`SbomError::UnsupportedLockShape`]. That is where formats 1 and 2
//!   record their digests, and this parser ignores that table by name.
//! - a package with a `source` outside [`DIGEST_FREE_SOURCE_SCHEMES`] and
//!   no `checksum` is [`SbomError::UnsupportedLockShape`] naming the
//!   package. Cargo writes the digest of everything it fetches, so a
//!   resolved entry without one is the format-1/2 shape.
//!
//! Without them, a file declaring `version = 3` while keeping the format-2
//! layout projected at exit 0 with every `hashes` entry silently absent --
//! an SBOM that looks complete and attests nothing.
//!
//! ## Top-level set
//!
//! The top-level dependencies are the union of the `dependencies` lists
//! of the packages with NO `source` -- those are the workspace members --
//! minus the SUBJECT alone, since an edge from the root of the graph to
//! itself is a self-loop. Another workspace member is NOT subtracted: a
//! crate the product links is a top-level dependency of the product, and
//! subtracting it made the emitted set a SUBSET of the runtime top level
//! instead of the superset the specification claims.
//!
//! `Cargo.lock` merges normal, build and development dependencies into one
//! list, and the union is taken across every member, so this set
//! OVER-approximates the runtime top level on both axes.
//! Over-approximating is the safe direction for a requirement written as
//! "at the very least the top-level dependencies", and the limitation
//! travels inside the document, in [`TOP_LEVEL_BASIS`], rather than in
//! prose beside it.

use super::{
    build_purl, starts_with_byte_order_mark, Component, ComponentHash, HashAlg, LockfileKind,
    Projection, ProjectionCounters, SbomError, SubjectPurl, BOM_DETAIL,
};

/// How the top-level set of a `Cargo.lock` projection was derived.
///
/// The token names the limitation on purpose: `Cargo.lock` does not
/// separate development from runtime dependencies, so the set is the
/// merged one.
pub const TOP_LEVEL_BASIS: &str = "cargo-lock-workspace-members-merged-dev";

/// The lockfile format versions this parser reads (specification 2.1).
///
/// A version 2 lockfile carries its checksums in a `[metadata]` table
/// whose contents this parser IGNORES by name, so reading one as if it
/// were a v3 would silently drop every digest and publish a document that
/// looks complete. A version 1 lockfile has no `checksum` at all. Both are
/// rejected rather than half-read; so is a lockfile with no `version` key,
/// which is a v1 by Cargo's own default.
pub const SUPPORTED_LOCK_VERSIONS: [i64; 2] = [3, 4];

/// The `source` scheme prefixes for which cargo records NO `checksum`, by
/// design: a git checkout is identified by its revision inside the source
/// string itself, and a path dependency is a directory on disk with no
/// distributed artifact to digest.
///
/// Every OTHER source is a fetched artifact for which cargo writes a
/// digest -- the 508 `source` packages of this workspace's own `Cargo.lock`
/// are all `registry+` and all carry one -- so a resolved entry without it
/// is a format 1 or 2 shape whatever version the file declares.
///
/// PUBLIC because it is the exemption list of rule (b) of specification
/// 2.1, and a published exemption a reader cannot enumerate is not an
/// exemption, it is a hole. It is the same two tokens the specification
/// prints in that sentence, and `intent_sbom_spec_matches_code.rs` asserts
/// set equality against them: adding a scheme here MUTES rule (b) for every
/// package that carries it -- a `sparse+` entry with no digest would project
/// as a component with no `hashes` and the suite would stay green -- so the
/// widening has to be argued in the published document or it does not
/// happen at all.
pub const DIGEST_FREE_SOURCE_SCHEMES: [&str; 2] = ["git+", "path+"];

/// The `[metadata]` key prefix under which lockfile formats 1 and 2 record
/// their digests: `"checksum <name> <version> (<source>)" = "<hex>"`.
const METADATA_CHECKSUM_KEY_PREFIX: &str = "checksum ";

/// One `[[package]]` entry of a `Cargo.lock`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LockPackage {
    /// `name` key.
    pub name: String,
    /// `version` key. Absent only in a corrupt lockfile.
    pub version: Option<String>,
    /// `source` key. ABSENT means a workspace member; an EMPTY string is
    /// a source that happens to be empty, which is not the same thing.
    pub source: Option<String>,
    /// `checksum` key: lowercase-hex SHA-256 of the distributed crate.
    pub checksum: Option<String>,
    /// `dependencies` list, verbatim, in lockfile order.
    pub dependencies: Vec<String>,
}

/// A parsed `Cargo.lock`, reduced to what the projection needs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CargoLock {
    /// Top-level `version` key of the lockfile format.
    pub version: Option<i64>,
    /// `[[package]]` entries, in lockfile order.
    pub packages: Vec<LockPackage>,
}

/// Parser state: which table the current line belongs to.
enum Section {
    /// Before the first table header.
    Preamble,
    /// Inside a `[[package]]`.
    Package,
    /// Inside a table whose contents are ignored (`[metadata]`).
    Ignored,
}

fn unsupported(line: usize, detail: &str) -> SbomError {
    SbomError::UnsupportedLockShape {
        line,
        detail: detail.to_string(),
    }
}

/// Parse a `Cargo.lock`, failing loud on anything outside the declared
/// subset.
///
/// Line endings are not part of the grammar: `str::lines` splits on
/// `\n` and drops a trailing `\r`, so a CRLF checkout parses to the same
/// structure as an LF one.
pub fn parse_cargo_lock(text: &str) -> Result<CargoLock, SbomError> {
    reject_byte_order_mark(text)?;

    let mut lock = CargoLock::default();
    let mut section = Section::Preamble;
    let mut current: Option<LockPackage> = None;
    // Keys already assigned inside the CURRENT `[[package]]`. TOML forbids
    // defining a key twice; this parser must too, or a lockfile that a
    // reference implementation rejects would be read here as last-wins and
    // project a component the file never resolved.
    let mut seen_keys: Vec<&str> = Vec::new();
    // Line of the top-level `version` key, once seen. `None` after the
    // whole file means a lockfile with no version at all.
    let mut version_line: Option<usize> = None;
    // When `Some`, we are inside a multi-line `dependencies = [` array
    // that started on the recorded line.
    let mut open_array: Option<usize> = None;
    // Line of the first `checksum ...` key found inside a `[metadata]`
    // table, once seen. That table is ignored BY NAME, so a digest living
    // there is a digest this parser does not read.
    let mut metadata_checksum_line: Option<usize> = None;
    // Line of the `[[package]]` header of the table being read, and the
    // same for every package already finished, in lockfile order. The
    // digest rules below name the offending package AND its line.
    let mut package_line: usize = 0;
    let mut package_lines: Vec<usize> = Vec::new();

    for (index, raw) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.trim();

        if let Some(opened_at) = open_array {
            if line == "]" {
                open_array = None;
                continue;
            }
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let item = line.strip_suffix(',').unwrap_or(line);
            let value = parse_basic_string(item, line_number)?;
            let package = current.as_mut().ok_or_else(|| {
                unsupported(
                    opened_at,
                    "a dependencies array outside a [[package]] table",
                )
            })?;
            package.dependencies.push(value);
            continue;
        }

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') {
            if let Some(package) = current.take() {
                lock.packages.push(finish_package(package, line_number)?);
                package_lines.push(package_line);
            }
            match line {
                "[[package]]" => {
                    section = Section::Package;
                    current = Some(LockPackage::default());
                    seen_keys.clear();
                    package_line = line_number;
                }
                "[metadata]" => section = Section::Ignored,
                other => {
                    return Err(unsupported(
                        line_number,
                        &format!("unexpected table header `{other}`"),
                    ))
                }
            }
            continue;
        }

        if matches!(section, Section::Ignored) {
            // The table is ignored, but the FACT that it carries digests is
            // not: see `reject_metadata_digests`.
            if metadata_checksum_line.is_none() && is_metadata_checksum_key(line) {
                metadata_checksum_line = Some(line_number);
            }
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| unsupported(line_number, "expected a `key = value` assignment"))?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(unsupported(
                line_number,
                &format!("expected a bare key, got `{key}`"),
            ));
        }

        match section {
            Section::Preamble => {
                if key != "version" {
                    return Err(unsupported(
                        line_number,
                        &format!("unexpected top-level key `{key}`"),
                    ));
                }
                if let Some(first) = version_line {
                    return Err(unsupported(
                        line_number,
                        &format!("the top-level key `version` is defined again; TOML forbids it, and the first definition is on line {first}"),
                    ));
                }
                let parsed = value.parse::<i64>().map_err(|_| {
                    unsupported(line_number, "expected an integer lockfile version")
                })?;
                lock.version = Some(parsed);
                version_line = Some(line_number);
            }
            Section::Package => {
                let package = current
                    .as_mut()
                    .ok_or_else(|| unsupported(line_number, "a key outside any table"))?;
                if let Some(duplicate) = seen_keys.iter().find(|seen| **seen == key) {
                    return Err(unsupported(
                        line_number,
                        &format!(
                            "the key `{duplicate}` is defined twice inside one [[package]] \
                             table; TOML forbids it, and reading it as last-wins would \
                             project a component this lockfile never resolved"
                        ),
                    ));
                }
                seen_keys.push(key);
                match key {
                    "name" => package.name = parse_basic_string(value, line_number)?,
                    "version" => package.version = Some(parse_basic_string(value, line_number)?),
                    "source" => package.source = Some(parse_basic_string(value, line_number)?),
                    "checksum" => package.checksum = Some(parse_basic_string(value, line_number)?),
                    "dependencies" => {
                        if value == "[]" {
                            continue;
                        }
                        if value != "[" {
                            return Err(unsupported(
                                line_number,
                                "expected `[]` or a multi-line array of basic strings",
                            ));
                        }
                        open_array = Some(line_number);
                    }
                    other => {
                        return Err(unsupported(
                            line_number,
                            &format!("unexpected package key `{other}`"),
                        ))
                    }
                }
            }
            Section::Ignored => unreachable!("the ignored section returns above"),
        }
    }

    if let Some(opened_at) = open_array {
        return Err(unsupported(opened_at, "unterminated array"));
    }
    if let Some(package) = current.take() {
        let last_line = text.lines().count();
        lock.packages.push(finish_package(package, last_line)?);
        package_lines.push(package_line);
    }

    // The format version is READ and then CHECKED. Parsing it and never
    // looking at it accepted a v2 -- whose checksums live in the
    // `[metadata]` table this parser ignores by name -- and emitted a
    // document with every digest silently dropped.
    match lock.version {
        Some(version) if SUPPORTED_LOCK_VERSIONS.contains(&version) => {
            // The version check reads a LABEL. These two read the SHAPE,
            // which is what the label was standing in for: a file that
            // says `version = 3` and records its digests the way a
            // version 2 does is the same silently digestless document.
            reject_metadata_digests(metadata_checksum_line)?;
            reject_sources_without_digest(&lock, &package_lines)?;
            Ok(lock)
        }
        Some(version) => Err(unsupported(
            version_line.unwrap_or(1),
            &format!(
                "lockfile format version {version} is outside the supported set \
                 {SUPPORTED_LOCK_VERSIONS:?}: a version 2 lockfile records its \
                 checksums in the `[metadata]` table this parser ignores by name, \
                 so reading one would publish a document with every digest \
                 silently dropped"
            ),
        )),
        None => Err(unsupported(
            1,
            &format!(
                "no top-level `version` key: Cargo defaults that to format version 1, \
                 which records no checksum at all; the supported set is \
                 {SUPPORTED_LOCK_VERSIONS:?}"
            ),
        )),
    }
}

/// True when a line of an IGNORED table assigns a `checksum ...` key --
/// quoted, as cargo writes it, or bare.
fn is_metadata_checksum_key(line: &str) -> bool {
    let Some((key, _)) = line.split_once('=') else {
        return false;
    };
    key.trim()
        .trim_start_matches('"')
        .starts_with(METADATA_CHECKSUM_KEY_PREFIX)
}

/// Reject a lockfile whose digests live in the `[metadata]` table.
///
/// That table is ignored BY NAME (module header, "The declared subset"),
/// so every digest inside it is a digest this parser does not read. The
/// format-version check alone did not close this: it reads the top-level
/// `version` LABEL, and a file is free to say `version = 3` while keeping
/// the format-2 digest layout -- by hand, by a rewriting tool, or by a
/// producer that wants an SBOM with no hashes in it. The result was an
/// exit 0 over a document with every `hashes` entry silently absent, which
/// is the failure mode this whole module is built against.
fn reject_metadata_digests(metadata_checksum_line: Option<usize>) -> Result<(), SbomError> {
    let Some(line) = metadata_checksum_line else {
        return Ok(());
    };
    Err(unsupported(
        line,
        "the `[metadata]` table carries a `checksum` key: that is where lockfile \
         formats 1 and 2 record their digests, and this parser ignores that table \
         by name, so the document it would publish carries no digest at all for \
         the packages listed there -- whatever format version the file declares",
    ))
}

/// Reject a package that was RESOLVED from a digest-bearing source and
/// carries no `checksum`.
///
/// A `source` key means cargo fetched the package from somewhere. For
/// every scheme outside [`DIGEST_FREE_SOURCE_SCHEMES`] cargo writes the
/// digest of what it fetched, on formats 3 and 4 alike -- all 508 `source`
/// packages of this workspace's own `Cargo.lock` are `registry+` and all
/// 508 carry one. A resolved entry WITHOUT it is therefore the format-1 or
/// format-2 shape, and projecting it would emit a component with no
/// `hashes` while the document looks complete.
///
/// Structural on purpose: it holds whatever the top-level `version` says,
/// so relabelling a v1 or v2 file as a v3 does not buy the silence back.
fn reject_sources_without_digest(
    lock: &CargoLock,
    package_lines: &[usize],
) -> Result<(), SbomError> {
    for (index, package) in lock.packages.iter().enumerate() {
        let Some(source) = &package.source else {
            continue;
        };
        if package.checksum.is_some() || !source_carries_digest(source) {
            continue;
        }
        let line = package_lines.get(index).copied().unwrap_or(1);
        return Err(unsupported(
            line,
            &format!(
                "the package `{}` declares `source = \"{source}\"` and no `checksum`: \
                 cargo records the digest of every package it FETCHES, so a resolved \
                 entry without one is a format 1 or 2 shape whatever format version \
                 the file declares. Only {DIGEST_FREE_SOURCE_SCHEMES:?} sources \
                 legitimately carry none -- a git revision is named inside the source \
                 string, and a path dependency distributes no artifact to digest",
                package.name
            ),
        ));
    }
    Ok(())
}

/// Whether cargo records a `checksum` for a package resolved from this
/// `source`.
fn source_carries_digest(source: &str) -> bool {
    !DIGEST_FREE_SOURCE_SCHEMES
        .iter()
        .any(|scheme| source.starts_with(scheme))
}

/// Reject a leading UTF-8 byte-order mark (specification 8, obligation 3).
///
/// Explicit rather than incidental. Without it the rejection depended on
/// the BOM happening to break the next rule the parser applied -- so an
/// implementation that merely stripped it would still have passed, and a
/// first package silently named `\u{feff}serde` is a document that looks
/// complete and names a package that does not exist.
fn reject_byte_order_mark(text: &str) -> Result<(), SbomError> {
    if starts_with_byte_order_mark(text) {
        return Err(unsupported(1, BOM_DETAIL));
    }
    Ok(())
}

fn finish_package(package: LockPackage, line: usize) -> Result<LockPackage, SbomError> {
    if package.name.is_empty() {
        return Err(unsupported(line, "a [[package]] table with no `name` key"));
    }
    Ok(package)
}

/// A TOML basic string with no escapes and no embedded quotes.
///
/// Escapes are rejected rather than decoded: Cargo does not emit them in
/// a lockfile, and decoding them would be a second, untested
/// implementation of a corner of TOML.
fn parse_basic_string(value: &str, line: usize) -> Result<String, SbomError> {
    let inner = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or_else(|| unsupported(line, "expected a TOML basic string"))?;
    if inner.contains('"') || inner.contains('\\') {
        return Err(unsupported(
            line,
            "basic strings with escapes or embedded quotes are outside the subset",
        ));
    }
    Ok(inner.to_string())
}

/// Project a parsed `Cargo.lock` against a subject the auditor supplies.
///
/// The subject is never inferred from the lockfile: a `Cargo.lock` names
/// every workspace member and marks none of them as "the product", so
/// picking one would be invention rather than projection.
pub fn project(lock: &CargoLock, subject: SubjectPurl) -> Result<Projection, SbomError> {
    let mut components = Vec::with_capacity(lock.packages.len());
    for package in &lock.packages {
        let version = package
            .version
            .clone()
            .ok_or_else(|| SbomError::MissingVersion {
                name: package.name.clone(),
            })?;
        let purl = build_purl(LockfileKind::Cargo, &package.name, &version)?;
        // The subject is the document's `metadata.component`. Listing it
        // again under `components` would put two components under one
        // reference, which is exactly what a purl collision is.
        if purl == subject.as_str() {
            continue;
        }
        // The `checksum` of a `Cargo.lock` is already lowercase-hex
        // SHA-256, so it is emitted as one -- after being checked to BE
        // one, because labelling something else `SHA-256` would be a
        // false statement inside the document.
        let hash = match &package.checksum {
            Some(checksum) => Some(ComponentHash::checked(
                HashAlg::Sha256,
                checksum,
                &package.name,
            )?),
            None => None,
        };
        components.push(Component {
            purl,
            type_: "library",
            name: package.name.clone(),
            group: None,
            // `Cargo.lock` merges normal, build and development
            // dependencies into one list, so it cannot tell required
            // from optional. Emitting a scope would be a guess.
            scope: None,
            version,
            hash,
        });
    }

    let mut top_level = Vec::new();
    for member in lock.packages.iter().filter(|p| p.source.is_none()) {
        for reference in &member.dependencies {
            let resolved = resolve_dependency_ref(reference, &lock.packages)?;
            let version = resolved
                .version
                .clone()
                .ok_or_else(|| SbomError::MissingVersion {
                    name: resolved.name.clone(),
                })?;
            let purl = build_purl(LockfileKind::Cargo, &resolved.name, &version)?;
            // The SUBJECT is the root of the graph, so an edge to it would
            // be a self-loop. Every OTHER workspace member a member depends
            // on IS a top-level dependency of the product: it is code the
            // product links and an auditor must see, and it is already a
            // component of the document. Subtracting members made the
            // emitted set a subset of the runtime top level rather than the
            // superset specification 4.2 claims -- the published document
            // named neither `seetrex-core` nor `seetrex-verifier` under
            // `dependsOn` while `compliance` depends on both directly.
            if purl == subject.as_str() {
                continue;
            }
            top_level.push(purl);
        }
    }

    Projection::new(
        LockfileKind::Cargo,
        subject,
        components,
        top_level,
        TOP_LEVEL_BASIS,
        // A `Cargo.lock` has neither platform requirements nor linked
        // entries, so it contributes no counter at all -- an ABSENT
        // counter, never a `"0"` that would claim the concept exists here.
        ProjectionCounters::default(),
    )
}

/// Parse and project in one step.
pub fn project_lockfile(text: &str, subject: SubjectPurl) -> Result<Projection, SbomError> {
    let lock = parse_cargo_lock(text)?;
    project(&lock, subject)
}

/// Resolve one entry of a `dependencies` list to the lockfile entry it
/// names.
///
/// Cargo writes the reference in three shapes: `"name"`,
/// `"name version"` and `"name version (source)"`. The shorter shapes
/// are only legal when they are unambiguous; when they are not, this is
/// an error rather than a guess, because guessing (say, the highest
/// version) puts a component in the SBOM that the lockfile does not
/// name.
fn resolve_dependency_ref<'a>(
    reference: &str,
    packages: &'a [LockPackage],
) -> Result<&'a LockPackage, SbomError> {
    let mut parts = reference.splitn(3, ' ');
    let name = parts.next().unwrap_or_default();
    let version = parts.next();
    let source = parts
        .next()
        .map(|s| s.trim_start_matches('(').trim_end_matches(')'));

    let mut matched = packages.iter().filter(|package| {
        package.name == name
            && version.is_none_or(|v| package.version.as_deref() == Some(v))
            && source.is_none_or(|s| package.source.as_deref() == Some(s))
    });
    let first = matched
        .next()
        .ok_or_else(|| SbomError::UnresolvedDependencyRef {
            reference: reference.to_string(),
        })?;
    let extra = matched.count();
    if extra > 0 {
        return Err(SbomError::AmbiguousDependencyRef {
            reference: reference.to_string(),
            count: extra + 1,
        });
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom::private_tree::{private_tree, read_private_file};
    use sha2::{Digest, Sha256};
    use std::path::{Path, PathBuf};

    /// Canonical hash of the projection of `cargo_two_versions.lock`,
    /// FROZEN. The fixture never changes, so this constant is what makes
    /// a change of serialization, of ordering or of number encoding
    /// observable. The real lockfiles carry no pin: they change
    /// legitimately.
    const TWO_VERSIONS_CANONICAL_SHA256: &str =
        "4337aa3c1e6a5947062be1633bf5d2cb61d383f8509e47ec1fb94272975b6739";

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sbom")
    }

    fn fixture(name: &str) -> String {
        let path = fixture_dir().join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
    }

    /// The real `Cargo.lock` of the PRIVATE workspace, read rather than
    /// copied, so a dependency bump cannot leave a stale copy behind.
    ///
    /// `None` when this run is not in the private tree -- the caller must
    /// return, and the gate has already said so out loud. See
    /// `crate::sbom::private_tree`.
    fn workspace_lockfile() -> Option<String> {
        let root = private_tree()?;
        Some(read_private_file(&root, "Cargo.lock"))
    }

    fn subject() -> SubjectPurl {
        SubjectPurl::parse("pkg:cargo/example-app@1.2.3").expect("subject parses")
    }

    /// Parse a lockfile with a reference TOML implementation, reduced to
    /// the same structure this module produces.
    fn reference_parse(text: &str) -> CargoLock {
        let document: toml::Value = toml::from_str(text).expect("reference TOML parse");
        let table = document.as_table().expect("lockfile root is a table");
        let version = table.get("version").map(|v| {
            v.as_integer()
                .expect("the lockfile version key is an integer")
        });
        let packages = table
            .get("package")
            .map(|p| {
                p.as_array()
                    .expect("`package` is an array of tables")
                    .iter()
                    .map(|entry| {
                        let entry = entry.as_table().expect("a package is a table");
                        let string = |key: &str| {
                            entry
                                .get(key)
                                .map(|v| v.as_str().expect("string value").to_string())
                        };
                        LockPackage {
                            name: string("name").expect("every package has a name"),
                            version: string("version"),
                            source: string("source"),
                            checksum: string("checksum"),
                            dependencies: entry
                                .get("dependencies")
                                .map(|d| {
                                    d.as_array()
                                        .expect("dependencies is an array")
                                        .iter()
                                        .map(|v| v.as_str().expect("string item").to_string())
                                        .collect()
                                })
                                .unwrap_or_default(),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        CargoLock { version, packages }
    }

    /// INTENT: the own `Cargo.lock` parser produces EXACTLY the structure
    ///   a reference TOML parser produces, over the real lockfile of this
    ///   workspace and over every synthetic shape in the corpus. If the
    ///   two ever diverge, the own parser is wrong and the SBOM it feeds
    ///   is wrong in silence.
    /// CONTEXT: the own parser exists so that an auditor's
    ///   `cargo install` of this crate does not pull a general TOML
    ///   parser and its transitive crates; the reference parser is a
    ///   DEV-dependency, so it never reaches that install. This test is
    ///   the price of that choice.
    /// EXPIRES IF: a general TOML parser is adopted as a normal
    ///   dependency of this crate, in which case the own parser and this
    ///   test disappear together.
    #[test]
    fn test_intent_cargo_lock_parser_matches_reference_toml() {
        // The SYNTHETIC halves run everywhere: they need no private tree,
        // and gating them behind one made every assertion of this test --
        // the corpus and the both-reject direction included -- silently
        // absent from an exported checkout.
        differential_over_the_corpus();
        differential_over_inputs_toml_rejects();

        let Some(workspace) = workspace_lockfile() else {
            return;
        };
        assert_eq!(
            parse_cargo_lock(&workspace).expect("own parser reads the workspace lockfile"),
            reference_parse(&workspace),
            "the own parser and the reference TOML parser disagree about the \
             workspace lockfile"
        );
    }

    /// The two parsers agree about every synthetic shape in the corpus.
    fn differential_over_the_corpus() {
        for name in [
            "cargo_two_versions.lock",
            "cargo_lock_v3.lock",
            "cargo_lock_v4.lock",
            "cargo_v3_path_source.lock",
            "cargo_empty_source.lock",
            "cargo_ambiguous_dep.lock",
        ] {
            let text = fixture(name);
            assert_eq!(
                parse_cargo_lock(&text).unwrap_or_else(|e| panic!("own parser reads {name}: {e}")),
                reference_parse(&text),
                "the own parser and the reference TOML parser disagree about {name}"
            );
        }
    }

    /// The SECOND direction of the differential, which the first one alone
    /// cannot see: inputs the reference parser REJECTS must be rejected
    /// here too. Agreeing only on what both ACCEPT lets the own parser be
    /// strictly more permissive than TOML -- which is exactly what
    /// duplicate keys were, read as last-wins where `toml` errors.
    fn differential_over_inputs_toml_rejects() {
        for (text, what) in [
            (
                "version = 4\n[[package]]\nname = \"a\"\nname = \"b\"\nversion = \"1.0.0\"\n",
                "a duplicated `name` inside one [[package]]",
            ),
            (
                "version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nversion = \"2.0.0\"\n",
                "a duplicated `version` inside one [[package]]",
            ),
            (
                "version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\ndependencies = [\n \"b\",\n]\ndependencies = [\n \"c\",\n]\n",
                "two `dependencies` arrays inside one [[package]]",
            ),
            (
                "version = 3\nversion = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n",
                "a duplicated top-level `version`",
            ),
        ] {
            assert!(
                toml::from_str::<toml::Value>(text).is_err(),
                "{what}: the reference TOML parser is expected to REJECT this \
                 input; if it started accepting it, this arm would demand a \
                 rejection the standard does not"
            );
            let error = parse_cargo_lock(text).expect_err(&format!(
                "{what}: the reference TOML parser rejects this input and the own \
                 parser accepted it, so the own parser is strictly more permissive \
                 than the format it claims to read"
            ));
            assert!(
                matches!(error, SbomError::UnsupportedLockShape { .. }),
                "{what}: expected UnsupportedLockShape, got {error:?}"
            );
        }
    }

    /// INTENT: the top-level `version` is READ AND CHECKED. Only format 3
    ///   and 4 project; 1, 2, 99 and a lockfile with no `version` key at
    ///   all are `UnsupportedLockShape` naming the value.
    /// CONTEXT: the key was parsed into the structure and never looked at,
    ///   so a version 2 lockfile -- which records its checksums in the
    ///   `[metadata]` table this parser ignores BY NAME -- projected
    ///   happily with every digest silently dropped. Specification 2.1
    ///   already required the rejection; nothing executed it.
    /// EXPIRES IF: a further lockfile format version is adopted, which is
    ///   a non-breaking change under specification 9 and moves this set.
    #[test]
    fn test_intent_cargo_lock_format_version_is_checked() {
        // A real v2 shape: the checksums are in `[metadata]`, which this
        // parser ignores by name, so reading it would drop them in silence.
        let v2 = "version = 2\n\
             [[package]]\n\
             name = \"leftpad\"\n\
             version = \"1.0.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             \n\
             [metadata]\n\
             \"checksum leftpad 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)\" = \
             \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n";
        // Non-vacuity: the digest really is in the file, so the arm below
        // is about the version check and not about an input with nothing
        // to lose.
        assert!(
            v2.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "the v2 sample must carry a checksum for the rejection to matter"
        );

        for (text, what) in [
            (v2, "a version 2 lockfile with `[metadata]` checksums"),
            (
                "version = 1\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n",
                "a version 1 lockfile",
            ),
            (
                "version = 99\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n",
                "an unknown future lockfile version",
            ),
            (
                "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n",
                "a lockfile with no `version` key",
            ),
        ] {
            let error = parse_cargo_lock(text)
                .expect_err(&format!("{what} must not parse as a supported lockfile"));
            match error {
                SbomError::UnsupportedLockShape { ref detail, .. } => assert!(
                    detail.contains("version"),
                    "{what}: the rejection must NAME the version it refused, so a \
                     reader of the error can tell which lockfile they handed over: \
                     {detail}"
                ),
                other => panic!("{what}: expected UnsupportedLockShape, got {other:?}"),
            }
        }

        // The other direction: the two supported versions still parse, so
        // the check was added rather than the parser broken.
        assert_eq!(SUPPORTED_LOCK_VERSIONS, [3, 4]);
        for name in ["cargo_lock_v3.lock", "cargo_lock_v4.lock"] {
            let lock = parse_cargo_lock(&fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(SUPPORTED_LOCK_VERSIONS.contains(&lock.version.expect("a version key")));
        }
    }

    /// A lockfile beginning with a UTF-8 byte-order mark is rejected by an
    /// EXPLICIT check on line 1, not by whatever rule the BOM happens to
    /// break next.
    #[test]
    fn cargo_lock_with_a_byte_order_mark_is_fail_loud() {
        let error = parse_cargo_lock(&format!("\u{feff}{}", fixture("cargo_lock_v4.lock")))
            .expect_err("a lockfile with a BOM must not parse");
        assert!(
            matches!(
                error,
                SbomError::UnsupportedLockShape { line: 1, ref detail } if detail == "UTF-8 BOM"
            ),
            "expected the explicit BOM rejection on line 1, got {error:?}"
        );
    }

    /// INTENT: a workspace member the product depends on directly IS a
    ///   top-level dependency and reaches `dependsOn`. Only the SUBJECT is
    ///   excluded, because an edge from the root to itself is a self-loop.
    /// CONTEXT: the set used to subtract every member, on the reading that
    ///   a member is "internal". The regulation asks for the top-level
    ///   dependencies OF THE PRODUCTS, and a workspace crate the product
    ///   links is exactly what an auditor must be shown -- the more so
    ///   when it is a closed component. The subtraction made the emitted
    ///   set a SUBSET of the runtime top level while specification 4.2
    ///   claimed a superset: measured on the published artifact, neither
    ///   `seetrex-core` nor `seetrex-verifier` appeared under `dependsOn`
    ///   although `compliance` depends on both directly.
    /// EXPIRES IF: the subject stops being the root of the graph.
    /// MUTANT: subtract packages with no `source` from the top-level set
    ///   again.
    #[test]
    fn test_intent_cargo_top_level_includes_workspace_members_it_depends_on() {
        let projection = project_lockfile(&fixture("cargo_lock_v4.lock"), subject())
            .expect("the v4 fixture projects");

        // The fixture has two members: `example-app` -- the SUBJECT, which
        // depends on the other member and on two registry crates -- and
        // `example-core`.
        assert_eq!(
            projection.top_level(),
            [
                "pkg:cargo/example-core@0.2.0".to_string(),
                "pkg:cargo/leftpad@1.0.0".to_string(),
                "pkg:cargo/rightpad@0.4.0".to_string(),
            ],
            "the top-level set is the members' direct dependencies, minus the \
             subject alone"
        );

        // And it is a component too, so the edge resolves against a
        // DECLARED bom-ref rather than dangling.
        assert!(projection
            .components()
            .iter()
            .any(|c| c.purl == "pkg:cargo/example-core@0.2.0"));

        // The subject never names itself, whichever member reaches it.
        assert!(
            projection
                .top_level()
                .iter()
                .all(|purl| purl != "pkg:cargo/example-app@1.2.3"),
            "the subject must not appear among its own top-level edges: {:?}",
            projection.top_level()
        );
    }

    /// INTENT: a bare `"name"` dependency reference that matches more
    ///   than one lockfile entry is an ERROR. Resolving it by picking a
    ///   version puts a component in the SBOM that the lockfile does not
    ///   name.
    /// CONTEXT: this workspace's own lockfile resolves several versions
    ///   for dozens of names, so the ambiguous case is ordinary rather
    ///   than exotic.
    /// EXPIRES IF: Cargo starts writing fully qualified references
    ///   unconditionally.
    #[test]
    fn test_intent_cargo_ambiguous_dep_ref_is_fail_loud() {
        let error = project_lockfile(&fixture("cargo_ambiguous_dep.lock"), subject())
            .expect_err("an ambiguous dependency reference must not project");
        assert!(
            matches!(
                error,
                SbomError::AmbiguousDependencyRef { ref reference, count }
                    if reference == "leftpad" && count == 2
            ),
            "expected AmbiguousDependencyRef, got {error:?}"
        );
    }

    /// The `top_level_basis` token that travels inside the document says
    /// that the set is the MERGED one: `Cargo.lock` does not separate
    /// development from runtime dependencies, and the document must not
    /// claim otherwise.
    #[test]
    fn test_cargo_top_level_basis_declares_the_dev_merge() {
        assert_eq!(TOP_LEVEL_BASIS, "cargo-lock-workspace-members-merged-dev");
        let projection = project_lockfile(&fixture("cargo_lock_v4.lock"), subject())
            .expect("the v4 fixture projects");
        assert_eq!(projection.top_level_basis(), TOP_LEVEL_BASIS);
        let doc = projection.to_cyclonedx();
        let basis = doc["properties"]
            .as_array()
            .expect("properties")
            .iter()
            .find(|p| p["name"] == "seetrex:sbom.top_level_basis")
            .expect("the top_level_basis property")["value"]
            .clone();
        assert_eq!(basis, serde_json::json!(TOP_LEVEL_BASIS));
    }

    /// INTENT: the projection of a given lockfile is byte-identical
    ///   across repeated runs AND across line-ending conventions. If it
    ///   is not, an auditor on another platform re-derives different
    ///   bytes and can never confirm a published SBOM.
    /// CONTEXT: this repository normalizes checkouts to LF, so a CRLF
    ///   fixture committed to the tree would be normalized back and the
    ///   test would certify nothing. The CRLF copy is therefore built in
    ///   memory, at test time.
    /// EXPIRES IF: the projection stops being a pure function of the
    ///   lockfile bytes.
    #[test]
    fn test_intent_cargo_projection_is_byte_reproducible() {
        let Some(raw) = workspace_lockfile() else {
            return;
        };
        let first = project_lockfile(&raw, subject()).expect("first projection");
        let second = project_lockfile(&raw, subject()).expect("second projection");

        let crlf = raw.replace('\n', "\r\n");
        assert_ne!(crlf, raw, "the in-memory CRLF copy must actually differ");
        let from_crlf = project_lockfile(&crlf, subject()).expect("projection of the CRLF copy");

        let a = first.to_canonical_bytes().expect("canonical bytes");
        let b = second.to_canonical_bytes().expect("canonical bytes");
        let c = from_crlf.to_canonical_bytes().expect("canonical bytes");
        assert_eq!(
            a, b,
            "two projections of one lockfile must agree byte for byte"
        );
        assert_eq!(
            a, c,
            "the line-ending convention of the lockfile must not reach the \
             emitted bytes"
        );
        assert_eq!(
            first.canonical_sha256().expect("hash"),
            from_crlf.canonical_sha256().expect("hash")
        );

        // A real lockfile is substantive: the invariants are asserted,
        // never a package count, which changes on every legitimate bump.
        assert!(
            first.components().len() > 100,
            "the workspace lockfile projects far more than a handful of \
             components; got {}",
            first.components().len()
        );
        assert!(
            !first.top_level().is_empty(),
            "the workspace lockfile has top-level dependencies"
        );
        for pair in first.components().windows(2) {
            assert!(
                pair[0].purl < pair[1].purl,
                "component order must be strictly increasing over purls"
            );
        }
    }

    /// The frozen byte-level pin. One `assert_eq` over a constant is what
    /// makes a change of serialization, of ordering or of number encoding
    /// observable at all -- including a divergence between the platform
    /// this runs on in continuous integration and the one a developer
    /// runs it on.
    #[test]
    fn cargo_two_versions_fixture_canonical_hash_is_pinned() {
        let projection = project_lockfile(
            &fixture("cargo_two_versions.lock"),
            SubjectPurl::parse("pkg:cargo/example-app@1.2.3").expect("subject"),
        )
        .expect("the two-versions fixture projects");

        let bytes = projection.to_canonical_bytes().expect("canonical bytes");
        let mut hasher = Sha256::new();
        hasher.update(bytes.as_bytes());
        assert_eq!(
            format!("{:x}", hasher.finalize()),
            TWO_VERSIONS_CANONICAL_SHA256,
            "the canonical bytes of the frozen fixture changed:\n{bytes}"
        );
    }

    /// Two versions of one crate are two components, and the one with a
    /// `checksum` carries a `SHA-256` hash while the one without carries
    /// none.
    #[test]
    fn cargo_two_versions_are_two_components_with_their_own_hashes() {
        let projection =
            project_lockfile(&fixture("cargo_two_versions.lock"), subject()).expect("projects");
        let leftpad: Vec<&Component> = projection
            .components()
            .iter()
            .filter(|c| c.name == "leftpad")
            .collect();
        assert_eq!(leftpad.len(), 2, "two resolved versions are two components");
        assert_eq!(leftpad[0].version, "1.0.0");
        assert_eq!(leftpad[1].version, "2.0.0");
        assert!(leftpad[0].hash.is_some(), "the checksummed one has a hash");
        assert!(
            leftpad[1].hash.is_none(),
            "the one with no checksum carries no hash rather than an empty one"
        );
        let doc = projection.to_cyclonedx();
        let hashed = doc["components"]
            .as_array()
            .expect("components")
            .iter()
            .find(|c| c["purl"] == "pkg:cargo/leftpad@1.0.0")
            .expect("the checksummed component");
        assert_eq!(hashed["hashes"][0]["alg"], "SHA-256");
    }

    /// An ABSENT `source` marks a workspace member; an EMPTY `source` is
    /// a source that happens to be empty and does not.
    #[test]
    fn cargo_absent_source_is_a_member_but_empty_source_is_not() {
        let lock = parse_cargo_lock(&fixture("cargo_empty_source.lock")).expect("parses");
        let member = lock
            .packages
            .iter()
            .find(|p| p.name == "example-app")
            .expect("the member");
        let empty = lock
            .packages
            .iter()
            .find(|p| p.name == "emptysource")
            .expect("the empty-source package");
        assert_eq!(member.source, None);
        assert_eq!(empty.source, Some(String::new()));

        let projection = project_lockfile(&fixture("cargo_empty_source.lock"), subject())
            .expect("the empty-source fixture projects");
        // Two consequences, in opposite directions, of the same
        // distinction. `emptysource` is NOT a member, so (a) the real
        // member's dependency on it IS a top-level dependency, and (b)
        // its OWN dependency on `farpad` is NOT: only members contribute
        // top-level edges.
        assert_eq!(
            projection.top_level(),
            ["pkg:cargo/emptysource@0.1.0".to_string()],
            "an empty `source` is a source, so `emptysource` is an ordinary \
             dependency: it belongs in the top-level set and its own \
             dependencies do not"
        );
        // `farpad` is still a component of the product, just not a
        // top-level one.
        assert!(projection
            .components()
            .iter()
            .any(|c| c.purl == "pkg:cargo/farpad@0.3.0"));
    }

    /// A `[[package]]` with no `version` is an error, not a component
    /// emitted without one.
    #[test]
    fn cargo_package_without_version_is_fail_loud() {
        let error = project_lockfile(&fixture("cargo_missing_version.lock"), subject())
            .expect_err("a package with no version must not project");
        assert!(
            matches!(error, SbomError::MissingVersion { ref name } if name == "noversion"),
            "expected MissingVersion, got {error:?}"
        );
    }

    /// A dependency reference naming a package the lockfile does not
    /// contain is an error, not a silently dropped edge.
    #[test]
    fn cargo_unresolved_dependency_ref_is_fail_loud() {
        let error = project_lockfile(&fixture("cargo_unresolved_dep.lock"), subject())
            .expect_err("a dangling dependency reference must not project");
        assert!(
            matches!(
                error,
                SbomError::UnresolvedDependencyRef { ref reference } if reference == "ghost"
            ),
            "expected UnresolvedDependencyRef, got {error:?}"
        );
    }

    /// INTENT: a lockfile keeps its digests where THIS parser reads them,
    ///   or it does not parse. Two structural rules, both independent of
    ///   the top-level `version`: a `checksum` key inside the ignored
    ///   `[metadata]` table is a rejection, and so is a package resolved
    ///   from a digest-bearing `source` with no `checksum` of its own.
    /// CONTEXT: the format-version check reads a LABEL. `version = 3` on a
    ///   file that keeps the format-2 digest layout passed it, and the
    ///   `[metadata]` table -- ignored by name -- took every digest with
    ///   it: exit 0 over a document whose components carry no `hashes` at
    ///   all. `cargo_metadata_table.lock` was exactly that file, pinned in
    ///   the reproducibility corpus as a projection worth reproducing.
    /// EXPIRES IF: cargo adopts a format that records digests somewhere
    ///   else again, at which point this parser learns to read that place
    ///   in the same change.
    /// MUTANT: relabel `cargo_metadata_table.lock` to any supported
    ///   version (it already says 3); drop either rule.
    #[test]
    fn test_intent_cargo_digests_must_be_where_this_parser_reads_them() {
        // Rule (a): the shape whose digests live in `[metadata]`. The file
        // declares a SUPPORTED version, so nothing but the shape rule can
        // be rejecting it.
        let text = fixture("cargo_metadata_table.lock");
        assert!(
            text.contains("version = 3"),
            "the fixture must declare a SUPPORTED version, or this test measures \
             the version check instead of the shape rule"
        );
        assert!(
            text.contains("1111111122222222333333334444444455555555666666667777777788888888"),
            "the fixture must really carry a digest in `[metadata]`, or there is \
             nothing to lose by ignoring it"
        );
        let error = parse_cargo_lock(&text)
            .expect_err("a lockfile whose digests live in `[metadata]` must not parse");
        assert!(
            matches!(error, SbomError::UnsupportedLockShape { .. }),
            "expected UnsupportedLockShape, got {error:?}"
        );
        assert!(
            format!("{error}").contains("[metadata]"),
            "the rejection must name the table the digests were found in: {error}"
        );

        // Rule (b): a registry package with no digest, and NO `[metadata]`
        // table at all -- so rule (a) cannot be what rejects it.
        let hashless = "version = 4\n\
             [[package]]\n\
             name = \"example-app\"\n\
             version = \"1.2.3\"\n\
             dependencies = [\n \"leftpad\",\n]\n\
             \n\
             [[package]]\n\
             name = \"leftpad\"\n\
             version = \"1.0.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        assert!(
            !hashless.contains("[metadata]"),
            "this sample must isolate rule (b) from rule (a)"
        );
        let error = parse_cargo_lock(hashless)
            .expect_err("a resolved registry package with no `checksum` must not parse");
        assert!(
            matches!(error, SbomError::UnsupportedLockShape { .. }),
            "expected UnsupportedLockShape, got {error:?}"
        );
        assert!(
            format!("{error}").contains("leftpad"),
            "the rejection must NAME the package that lost its digest: {error}"
        );

        // The exception, by source scheme: a git checkout and a path
        // dependency legitimately carry none, and both still parse.
        for source in [
            "git+https://example.invalid/leftpad.git",
            "path+file:///workspace/vendored/leftpad",
        ] {
            let text = format!(
                "version = 4\n\
                 [[package]]\n\
                 name = \"leftpad\"\n\
                 version = \"1.0.0\"\n\
                 source = \"{source}\"\n"
            );
            parse_cargo_lock(&text).unwrap_or_else(|e| {
                panic!("a `{source}` package carries no digest by design: {e}")
            });
        }
    }

    /// A `[metadata]` table that carries no digest is still IGNORED, not
    /// read as a package: its keys are quoted strings that the package
    /// grammar would reject.
    #[test]
    fn cargo_metadata_table_without_digests_is_ignored_not_parsed_as_a_package() {
        let lock = parse_cargo_lock(
            "version = 3\n\
             [[package]]\n\
             name = \"example-app\"\n\
             version = \"1.2.3\"\n\
             \n\
             [metadata]\n\
             \"some-other-key example\" = \"whatever\"\n",
        )
        .expect("parses");
        assert_eq!(lock.version, Some(3));
        assert_eq!(
            lock.packages
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            vec!["example-app"]
        );
    }

    /// Constructs outside the declared subset abort the parse with the
    /// offending line, instead of being read best-effort.
    #[test]
    fn cargo_lock_shapes_outside_the_subset_are_fail_loud() {
        // Every sample declares a SUPPORTED format version, so each one is
        // rejected for the construction it names rather than for the
        // version check that now guards the parse.
        for (text, what) in [
            (
                "version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nyanked = true\n",
                "an unknown package key",
            ),
            (
                "version = 4\n[[patch.unused]]\nname = \"a\"\n",
                "an unknown table",
            ),
            (
                "version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\ndependencies = [\"b\"]\n",
                "an inline non-empty array",
            ),
            (
                "version = 4\n[[package]]\nversion = \"1.0.0\"\n",
                "a package with no name",
            ),
            (
                "version = 4\n[[package]]\nname = \"a\"\nversion = 1\n",
                "a non-string version",
            ),
            (
                "version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\ndependencies = [\n \"b\",\n",
                "an unterminated array",
            ),
        ] {
            let error = parse_cargo_lock(text).expect_err(&format!("{what} must abort the parse"));
            assert!(
                matches!(error, SbomError::UnsupportedLockShape { .. }),
                "{what}: expected UnsupportedLockShape, got {error:?}"
            );
        }
    }

    /// A `checksum` that is not 64 lowercase hex characters must not be
    /// published under a `SHA-256` label.
    #[test]
    fn cargo_checksum_that_is_not_sha256_is_fail_loud() {
        assert!(ComponentHash::checked(HashAlg::Sha256, &"a".repeat(64), "a").is_ok());
        for bad in ["", "abc", &"A".repeat(64), &"a".repeat(63), &"z".repeat(64)] {
            assert!(
                ComponentHash::checked(HashAlg::Sha256, bad, "a").is_err(),
                "`{bad}` must not be published as a SHA-256"
            );
        }
    }

    /// The subject is the document's `metadata.component` and is not
    /// repeated inside `components`, so no two components share a
    /// reference.
    #[test]
    fn cargo_subject_is_metadata_component_and_not_repeated() {
        let subject = SubjectPurl::parse("pkg:cargo/example-app@1.2.3").expect("subject");
        let projection =
            project_lockfile(&fixture("cargo_lock_v4.lock"), subject.clone()).expect("projects");
        assert!(
            projection
                .components()
                .iter()
                .all(|c| c.purl != subject.as_str()),
            "the subject must not also appear as a component"
        );
        let doc = projection.to_cyclonedx();
        assert_eq!(
            doc["metadata"]["component"]["purl"],
            "pkg:cargo/example-app@1.2.3"
        );
        assert_eq!(doc["metadata"]["component"]["type"], "application");
        assert_eq!(doc["metadata"]["component"]["name"], "example-app");
        assert_eq!(doc["metadata"]["component"]["version"], "1.2.3");
    }
}
