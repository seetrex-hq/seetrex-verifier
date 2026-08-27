// SPDX-License-Identifier: Apache-2.0
//! `package-lock.json` (lockfileVersion 2 and 3) -> [`Projection`].
//!
//! The `packages` map of a v2/v3 lockfile is the INSTALLED TREE: every
//! key is a path, every value carries the version that path resolved to.
//! That map is a pure projection source. The per-entry `dependencies`
//! objects are NOT: they hold CONSTRAINTS, not resolved edges, and
//! turning them into edges would mean reimplementing the resolution
//! algorithm of the package manager -- which is why the graph stops at
//! depth 1 and comes from the ROOT entry alone.
//!
//! ## What is read
//!
//! - `lockfileVersion`: 2 or 3. A version 1 layout (a top-level
//!   `dependencies` object and NO `packages` map) is fail-loud: it
//!   records a different tree shape, and reading it as if it were a v2
//!   would be a guess.
//! - `packages[""]`: the root entry. Its `dependencies`,
//!   `devDependencies`, `optionalDependencies` and `peerDependencies`
//!   KEYS are the top-level set.
//! - `packages[<path>]` for every other entry: the name is everything
//!   after the LAST `node_modules` SEGMENT of the path, so a nested entry
//!   keeps its own identity instead of collapsing into the outer one.
//! - per entry: `version` (mandatory) and `dev` (scope).
//!
//! Everything else -- `integrity`, `resolved`, `license`, `engines`,
//! `funding`, `os`, `cpu`, `bin`, `hasInstallScript`, and the per-entry
//! constraint maps -- is DISCARDED.
//!
//! An entry with `"link": true` is not an installed package: it points
//! at another place in the tree, and the package it names lives under a
//! key this projection does not read. Such entries are OMITTED from the
//! components AND COUNTED in `seetrex:sbom.links_omitted`, so the
//! omission is visible in the document rather than mute -- the same
//! discipline as composer's platform requirements. A ROOT requirement
//! satisfied by one is omitted from the top-level set for the same
//! reason: emitting an edge to a component the document does not carry
//! would leave a dangling `dependsOn`, and failing would make every
//! workspace that links a local package unprojectable.
//!
//! npm writes such a link in TWO halves: the `node_modules/<name>` entry
//! carrying `"link": true`, and a full entry under the path that entry
//! `resolved` to (`workspaces/<name>`). The second half is SKIPPED as the
//! target of a link already omitted -- membership in the set of `resolved`
//! values, never a prefix -- so a real linked lockfile projects instead of
//! being rejected by the workspace rule below. It is not counted a second
//! time: one link is one omission, however many keys npm spends on it.
//! Every other key with no `node_modules` segment is still fail-loud.
//!
//! Both halves of that rule read the key through ONE function,
//! `classify_key`, which sorts a key into exactly three classes: an
//! install path (a `node_modules` SEGMENT, name after the last one), a
//! workspace path (no `node_modules` at all), and a key in which
//! `node_modules` appears WITHOUT being a segment, which is neither and is
//! refused wherever it appears -- including as the target of a link, so a
//! `resolved` the file chooses cannot disarm the refusal.
//!
//! ## One purl, two entries
//!
//! An installed tree reaches the same package at the same version by
//! several paths (`node_modules/a/node_modules/x` and
//! `node_modules/b/node_modules/x`), and those entries can disagree about
//! `dev`. The purl is the identity, so they are ONE component, and the
//! `scope` that survives is the more permissive one: `required` beats
//! `optional`, because the artifact does ship in the product if any path
//! needs it at runtime. `scope` is therefore NOT part of what makes two
//! entries a collision -- a purl collision is reserved for entries that
//! disagree about something the purl does not already settle.
//!
//! ## No `hashes`
//!
//! An npm projection emits NO `hashes`, on any component. `integrity` is
//! a subresource-integrity digest of the REGISTRY TARBALL -- not of the
//! component identity, and not of an artifact the auditor holds -- and
//! publishing it as `hashes[].content` would additionally require a
//! base64-to-hex conversion, a transformation with judgement in it.
//! Cargo's `checksum`, already lowercase hex and already a digest of the
//! crate file, is the one digest the projection publishes
//! (specification 2.4 and 5.2).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{
    build_namespaced_purl, build_purl, starts_with_byte_order_mark, Component, LockfileKind,
    Projection, ProjectionCounters, SbomError, SubjectPurl, BOM_DETAIL,
};

/// How the top-level set of an npm projection was derived.
///
/// The token names the limitation on purpose: development and runtime
/// requirements of the root entry are MERGED into one set, so the set
/// over-approximates the runtime top level.
pub const TOP_LEVEL_BASIS: &str = "npm-lock-root-dependencies-merged-dev";

/// The root requirement maps of a `package-lock.json` root entry.
const ROOT_REQUIREMENT_MAPS: [&str; 4] = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

/// One installed entry of the `packages` map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmPackage {
    /// The key of the entry: the install path.
    pub path: String,
    /// Package name: everything after the LAST `node_modules` segment.
    pub name: String,
    /// `version`. Absent only in a corrupt lockfile.
    pub version: Option<String>,
    /// `dev: true`.
    pub dev: bool,
}

/// A parsed `package-lock.json`, reduced to what the projection needs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NpmLock {
    /// `lockfileVersion`.
    pub lockfile_version: i64,
    /// The KEYS of the requirement maps of the root entry, in the order
    /// the maps are declared above.
    pub root_requirements: Vec<String>,
    /// Every entry of `packages` except the root one and the linked ones.
    pub packages: Vec<NpmPackage>,
    /// The KEYS of the `link: true` entries, in file order.
    ///
    /// The paths and not merely a count, because a ROOT requirement can
    /// resolve to one: the top-level derivation has to be able to tell "a
    /// linked entry, omitted by rule" from "a requirement the tree does
    /// not install", which is a fail-loud error.
    pub linked_paths: Vec<String>,
}

fn unsupported(line: usize, detail: String) -> SbomError {
    SbomError::UnsupportedLockShape { line, detail }
}

/// The rejection of a `packages` key this module cannot read honestly.
///
/// One constructor, because the rejection is raised from two places -- the
/// parse loop, before any skip, and [`parse_entry`] -- and a reader must
/// not have to check that the two say the same thing.
fn malformed_key(path: &str, reason: &str) -> SbomError {
    unsupported(1, format!("the `packages` key `{path}` {reason}"))
}

/// Parse a `package-lock.json` of lockfileVersion 2 or 3.
///
/// Unknown keys are IGNORED rather than rejected: the discarded field
/// set is the design (provenance and personal data must not reach the
/// document), so an entry carrying a field this module does not read is
/// ordinary. What IS fail-loud is a shape this module cannot read
/// HONESTLY: a v1 layout, a path with no `node_modules` segment, a path
/// whose `node_modules` is not a segment at all, a missing version.
pub fn parse_npm_lock(text: &str) -> Result<NpmLock, SbomError> {
    // Explicit, and first (specification 8, obligation 3): otherwise the
    // rejection is only whatever the JSON parser happens to say about a
    // stray code point, and an implementation that stripped the mark
    // instead would pass the same tests.
    if starts_with_byte_order_mark(text) {
        return Err(unsupported(1, BOM_DETAIL.to_string()));
    }
    let document: Value = serde_json::from_str(text).map_err(|e| {
        unsupported(
            e.line(),
            format!("package-lock.json is not valid JSON: {e}"),
        )
    })?;
    let root = document
        .as_object()
        .ok_or_else(|| unsupported(1, "package-lock.json is not a JSON object".to_string()))?;

    let lockfile_version = root
        .get("lockfileVersion")
        .and_then(Value::as_i64)
        .ok_or_else(|| unsupported(1, "no integer `lockfileVersion`".to_string()))?;
    if !(2..=3).contains(&lockfile_version) {
        return Err(unsupported(
            1,
            format!(
                "lockfileVersion {lockfile_version} is outside the supported \
                 range 2..=3; version 1 records a different tree shape and \
                 reading it as a v2 would be a guess"
            ),
        ));
    }

    let packages_map = root
        .get("packages")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            unsupported(
                1,
                "no `packages` map: a lockfile with only the legacy top-level \
                 `dependencies` tree is a version 1 layout"
                    .to_string(),
            )
        })?;

    // FIRST pass: the keys a `link: true` entry POINTS AT. npm writes both
    // halves of a link -- the `node_modules/<name>` entry that carries
    // `"link": true` and the target entry under the workspace path it
    // `resolved` to -- so a lockfile carrying only the first half is not
    // one npm produces. The target is skipped BECAUSE it is the target,
    // not because its key looks like a workspace path (Section 2.3).
    let link_targets = link_targets(packages_map);

    let mut root_requirements = Vec::new();
    let mut packages = Vec::with_capacity(packages_map.len());
    let mut linked_paths = Vec::new();
    for (path, value) in packages_map {
        let entry = value.as_object().ok_or_else(|| {
            unsupported(1, format!("the `packages` entry `{path}` is not an object"))
        })?;
        if path.is_empty() {
            root_requirements.extend(root_requirement_keys(entry)?);
            continue;
        }
        // The SHAPE of a key is a property of the key alone, and it is
        // decided HERE, before any skip below can run: a key this module
        // cannot read honestly is fail-loud whether or not something in
        // the file points at it. Letting the link skip run first made the
        // rejection depend on a `resolved` the lockfile itself chooses.
        if let PackageKey::Malformed(reason) = classify_key(path) {
            return Err(malformed_key(path, reason));
        }
        // A linked entry carries no version of its own: it points at
        // another key of the tree. It is omitted here and COUNTED, so the
        // omission reaches the document.
        if entry.get("link").and_then(Value::as_bool) == Some(true) {
            linked_paths.push(path.clone());
            continue;
        }
        // The other half of a link the projection already omitted -- and
        // only ever a WORKSPACE key, see `link_targets`. It is skipped, and
        // NOT counted a second time: `links_omitted` counts links, and one
        // link is one omission however many keys npm spends writing it
        // down. Every OTHER key with no `node_modules/` segment is still
        // the workspace path Section 2.3 rejects.
        if link_targets.contains(path.as_str()) {
            continue;
        }
        packages.push(parse_entry(path, entry)?);
    }

    Ok(NpmLock {
        lockfile_version,
        root_requirements,
        packages,
        linked_paths,
    })
}

/// The WORKSPACE `packages` keys that a `link: true` entry names in its
/// `resolved`.
///
/// A `"link": true` entry is one half of what npm writes for a linked
/// local package; the other half is a full entry under the path it
/// `resolved` to -- `workspaces/<name>` for a workspace member. Both
/// halves describe ONE thing the projection omits, so the target is
/// skipped rather than rejected as the workspace path its key looks like.
///
/// The admission is narrow BY CONSTRUCTION, and narrow in TWO ways. The
/// first is membership in this set, not a prefix or a glob: a
/// `workspaces/<name>` key that no link points at is still
/// `UnsupportedLockShape`, because projecting it would mean deciding which
/// member is "the product" and mapping the root's own `workspaces` globs
/// onto lockfile keys -- resolution rather than projection.
///
/// The second is [`is_workspace_key`], and it is the one that matters to a
/// reader of the document. Membership alone made the skip reachable from a
/// `resolved` the lockfile CHOOSES: a `link: true` entry whose `resolved`
/// names a real `node_modules/<name>` key erased that installed package
/// from `components`, and the only trace was a `links_omitted` of 1 that an
/// auditor would read as the one link. An installed package that vanishes
/// from a document which still looks complete is the failure mode this
/// module exists to prevent. A `resolved` pointing INTO `node_modules` is
/// not a workspace link at all: the package it names stays projected, and
/// the `link: true` entry itself is omitted and counted exactly as before.
///
/// `is_workspace_key` is [`classify_key`] and nothing else, so "a key a
/// link may point at" and "a key that names an installed package" are two
/// answers of ONE reading and cannot disagree. A key that is neither --
/// `node_modules` present but not as a segment -- is admitted here by no
/// arm, and the parse loop refuses it before this skip can run.
fn link_targets(packages_map: &Map<String, Value>) -> std::collections::BTreeSet<&str> {
    packages_map
        .values()
        .filter_map(Value::as_object)
        .filter(|entry| entry.get("link").and_then(Value::as_bool) == Some(true))
        .filter_map(|entry| entry.get("resolved").and_then(Value::as_str))
        .filter(|resolved| is_workspace_key(resolved))
        .collect()
}

/// What a `packages` key IS -- the module's ONE reading of it.
///
/// Two questions are asked of every key: "does this name an installed
/// package, and which one?" ([`parse_entry`]) and "is this a workspace path
/// a link may point at?" ([`link_targets`]). They used to be asked by two
/// different readings -- a `node_modules` path SEGMENT for the second, the
/// SUBSTRING `node_modules/` for the first -- and two readings of one key
/// can disagree. `vendor_node_modules/hidden-lib` was a workspace path to
/// one and an installed package to the other, so a `link: true` naming it
/// erased a real installed package from `components`; a key spelling the
/// separator the other way round was a fail-loud shape to one and a
/// skippable workspace path to the other, so a `resolved` the FILE chooses
/// disarmed a rejection. One reading answers both, and the third arm is
/// why it can: a key in which `node_modules` appears without being a
/// segment is NEITHER -- the module cannot tell an install path written
/// with the wrong separator from a directory that merely resembles one,
/// and guessing is what this module refuses to do.
enum PackageKey<'a> {
    /// An installed location. The name is everything after the LAST
    /// `node_modules` segment, so a nested entry keeps its own identity.
    /// The segment is matched WITHOUT regard to ASCII case: see
    /// [`classify_key`].
    Installed(&'a str),
    /// No `node_modules` anywhere in the key, in any ASCII case: the
    /// workspace path Section 2.3 declines to read.
    Workspace,
    /// A shape this module cannot read honestly, with the reason.
    Malformed(&'static str),
}

/// The install directory of every npm tree, and the segment [`classify_key`]
/// looks for.
const INSTALL_DIR: &str = "node_modules";

/// The reason a key that stops at the segment is refused.
const NAMES_NO_PACKAGE: &str = "names no package";

/// The reason a look-alike key is refused.
const NOT_A_SEGMENT: &str = "carries `node_modules` without it being a path SEGMENT, so it \
     is neither an install path this module can read nor a workspace path a link may \
     point at";

/// The reason a key with an empty path segment is refused.
const EMPTY_SEGMENT: &str = "carries an EMPTY path segment, so the package name it would \
     yield is a fragment the lockfile never wrote";

/// True when `needle` -- which must be ASCII and non-empty -- occurs in
/// `haystack` ignoring ASCII case. No allocation, so classifying a key
/// stays a read of that key. The only caller passes [`INSTALL_DIR`].
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

/// Read a `packages` key, once, for every caller.
///
/// Segment equality, never `contains`, and the equality IGNORES ASCII
/// case. npm writes `node_modules` in lower case, but on a
/// case-insensitive filesystem -- Windows, macOS -- `NODE_MODULES` IS the
/// install directory, so a key spelled that way names a REAL installed
/// package. Reading it as a workspace path made it a legal target for a
/// `link: true`, and the measured result was `components` EMPTY with a
/// `links_omitted` of 1: the installed package vanished from a document
/// that still looked complete, which is the failure this module exists to
/// prevent. A nested entry `packages/a/node_modules/b` is an installed
/// location however deep, in any case.
///
/// A key that carries `node_modules` WITHOUT it being a segment is
/// neither an install path nor a workspace path, and is refused. That
/// refusal is deliberately BROAD: `my-node_modules-tools` -- a workspace
/// directory an author is free to name -- is refused too. It differs from
/// `vendor_node_modules/hidden-lib` only in what follows the look-alike,
/// and admitting THAT one as a workspace path is exactly how a `link`
/// erases an installed package, so the honest answer to both is a
/// refusal. The cost is narrow and loud: it is observable only when a
/// `link: true` resolves to such a key, and it is an error, never a
/// silent omission.
///
/// An EMPTY segment is refused as well. `node_modules//x` and
/// `node_modules/foo/` used to be read as installed locations named `/x`
/// and `foo/`; the purl grammar then rejected those names, so nothing was
/// ever projected under a broken purl, but the rejection named a fragment
/// the lockfile never wrote instead of the key an auditor can go and look
/// at. A multi-segment name that is not a scope -- `node_modules/a/b` --
/// stays the purl grammar's to refuse: that is a NAME this module cannot
/// read, not a key shape it cannot read.
fn classify_key(key: &str) -> PackageKey<'_> {
    let segments: Vec<&str> = key.split('/').collect();
    if segments.iter().any(|segment| segment.is_empty()) {
        return PackageKey::Malformed(EMPTY_SEGMENT);
    }
    if let Some(last) = segments
        .iter()
        .rposition(|segment| segment.eq_ignore_ascii_case(INSTALL_DIR))
    {
        let name_at: usize = segments[..=last]
            .iter()
            .map(|segment| segment.len() + 1)
            .sum();
        let name = key.get(name_at..).unwrap_or_default();
        if name.is_empty() {
            return PackageKey::Malformed(NAMES_NO_PACKAGE);
        }
        return PackageKey::Installed(name);
    }
    if contains_ignore_ascii_case(key, INSTALL_DIR) {
        return PackageKey::Malformed(NOT_A_SEGMENT);
    }
    PackageKey::Workspace
}

/// True when `key` is a workspace path rather than an installed location.
///
/// Derived from [`classify_key`] and from nothing else, so the admission
/// above cannot drift away from what [`parse_entry`] reads. A look-alike is
/// NOT a workspace path: it is refused, never skipped.
fn is_workspace_key(key: &str) -> bool {
    matches!(classify_key(key), PackageKey::Workspace)
}

fn root_requirement_keys(entry: &Map<String, Value>) -> Result<Vec<String>, SbomError> {
    let mut keys = Vec::new();
    for map in ROOT_REQUIREMENT_MAPS {
        let Some(value) = entry.get(map) else {
            continue;
        };
        let table = value.as_object().ok_or_else(|| {
            unsupported(
                1,
                format!("the root `{map}` of the lockfile is not an object"),
            )
        })?;
        keys.extend(table.keys().cloned());
    }
    Ok(keys)
}

fn parse_entry(path: &str, entry: &Map<String, Value>) -> Result<NpmPackage, SbomError> {
    let name = match classify_key(path) {
        PackageKey::Installed(name) => name,
        PackageKey::Workspace => {
            return Err(unsupported(
                1,
                format!(
                    "the `packages` key `{path}` has no `node_modules` segment, so it \
                     is a workspace path rather than an installed package"
                ),
            ))
        }
        PackageKey::Malformed(reason) => return Err(malformed_key(path, reason)),
    };
    let version = match entry.get("version") {
        None => None,
        Some(Value::String(version)) => Some(version.clone()),
        Some(_) => {
            return Err(unsupported(
                1,
                format!("the `packages` entry `{path}` carries a non-string `version`"),
            ))
        }
    };
    Ok(NpmPackage {
        path: path.to_string(),
        name: name.to_string(),
        version,
        dev: entry.get("dev").and_then(Value::as_bool) == Some(true),
    })
}

/// Project a parsed `package-lock.json` against a subject the auditor
/// supplies.
pub fn project(lock: &NpmLock, subject: SubjectPurl) -> Result<Projection, SbomError> {
    // Keyed by purl, because one installed tree reaches the SAME package
    // at the same version by two paths -- `node_modules/a/node_modules/x`
    // and `node_modules/b/node_modules/x` -- and the two entries can
    // disagree about `dev`. The purl is the identity, so those are ONE
    // component; see `merge_scope` for which scope survives.
    let mut components: BTreeMap<String, Component> = BTreeMap::new();
    for package in &lock.packages {
        let version = package
            .version
            .clone()
            .filter(|version| !version.is_empty())
            .ok_or_else(|| SbomError::MissingVersion {
                name: package.name.clone(),
            })?;
        let purl = purl_of(&package.name, &version)?;
        // The subject is the document's `metadata.component`; listing it
        // again under `components` would put two components under one
        // reference.
        if purl == subject.as_str() {
            continue;
        }
        let (group, name) = split_scope(&package.name)?;
        let scope = scope_of(package.dev);
        match components.get_mut(&purl) {
            Some(existing) => existing.scope = Some(merge_scope(existing.scope, scope)),
            None => {
                components.insert(
                    purl.clone(),
                    Component {
                        purl,
                        type_: "library",
                        name: name.to_string(),
                        group: group.map(str::to_string),
                        version,
                        scope: Some(scope),
                        // No digest: `integrity` is discarded (module
                        // header, "No `hashes`").
                        hash: None,
                    },
                );
            }
        }
    }

    let mut top_level = Vec::with_capacity(lock.root_requirements.len());
    for requirement in &lock.root_requirements {
        // A root requirement satisfied by a LINKED entry is omitted from
        // the top-level set by rule (specification 2.3), exactly as the
        // entry itself is omitted from the components. Failing here would
        // make every workspace that links a local package unprojectable,
        // and inventing an edge to a component the document does not carry
        // would leave a dangling `dependsOn`.
        if lock
            .linked_paths
            .iter()
            .any(|path| path == &format!("node_modules/{requirement}"))
        {
            continue;
        }
        let resolved = resolve_root_requirement(requirement, &lock.packages)?;
        let version = resolved
            .version
            .clone()
            .ok_or_else(|| SbomError::MissingVersion {
                name: resolved.name.clone(),
            })?;
        top_level.push(purl_of(&resolved.name, &version)?);
    }

    Projection::new(
        LockfileKind::Npm,
        subject,
        components.into_values().collect(),
        top_level,
        TOP_LEVEL_BASIS,
        ProjectionCounters {
            // A `package-lock.json` has no platform requirements, so that
            // counter is ABSENT rather than `"0"`.
            platform_requirements_excluded: None,
            links_omitted: Some(lock.linked_paths.len()),
        },
    )
}

/// The CycloneDX `scope` of an entry, from its `dev` flag.
fn scope_of(dev: bool) -> &'static str {
    if dev {
        "optional"
    } else {
        "required"
    }
}

/// The scope that survives when one purl is reached by two entries.
///
/// `required` wins over `optional`, always. The two entries name ONE
/// artifact -- same name, same version, same registry tarball -- and it is
/// installed for the runtime if ANY path needs it for the runtime. Taking
/// the last entry read would make the scope depend on the iteration order
/// of the tree, and taking `optional` would state, inside the document,
/// that a package which does ship in the product does not.
fn merge_scope(existing: Option<&'static str>, incoming: &'static str) -> &'static str {
    if existing == Some("required") || incoming == "required" {
        "required"
    } else {
        "optional"
    }
}

/// Parse and project in one step.
pub fn project_lockfile(text: &str, subject: SubjectPurl) -> Result<Projection, SbomError> {
    let lock = parse_npm_lock(text)?;
    project(&lock, subject)
}

/// The purl of an npm package name.
///
/// A scoped name becomes `pkg:npm/%40<scope>/<name>@<version>`: the purl
/// specification says a namespace segment is percent-encoded, and `@` is
/// not an unreserved character, so the scope's `@` becomes `%40`. The
/// `@` that SEPARATES the version is part of the purl grammar and stays
/// literal -- encoding that one would destroy the grammar.
fn purl_of(full_name: &str, version: &str) -> Result<String, SbomError> {
    match split_scope(full_name)? {
        (Some(scope), name) => {
            build_namespaced_purl(LockfileKind::Npm, &format!("%40{scope}"), name, version)
        }
        (None, name) => build_purl(LockfileKind::Npm, name, version),
    }
}

/// Split `@scope/name` into the scope WITHOUT its `@` and the bare name.
/// An unscoped name has no scope.
fn split_scope(full_name: &str) -> Result<(Option<&str>, &str), SbomError> {
    let malformed = || SbomError::MalformedComponentPurl {
        name: full_name.to_string(),
        purl: format!("<npm name `{full_name}` is neither `name` nor `@scope/name`>"),
    };
    match full_name.strip_prefix('@') {
        Some(rest) => match rest.split_once('/') {
            Some((scope, name)) if !scope.is_empty() && !name.is_empty() && !name.contains('/') => {
                Ok((Some(scope), name))
            }
            _ => Err(malformed()),
        },
        None if full_name.contains('/') || full_name.is_empty() => Err(malformed()),
        None => Ok((None, full_name)),
    }
}

/// Resolve one root requirement to the entry it was installed at.
///
/// The root's own dependencies are hoisted to `node_modules/<name>` by
/// construction, so the lookup is exact rather than a search: a name
/// that is NOT there means the lockfile does not describe the tree the
/// manifest asks for, and dropping the edge silently is the failure this
/// projection exists to make impossible.
fn resolve_root_requirement<'a>(
    requirement: &str,
    packages: &'a [NpmPackage],
) -> Result<&'a NpmPackage, SbomError> {
    let path = format!("node_modules/{requirement}");
    packages
        .iter()
        .find(|package| package.path == path)
        .ok_or_else(|| SbomError::UnresolvedDependencyRef {
            reference: requirement.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom::private_tree::{private_tree, read_private_file};
    use sha2::{Digest, Sha256};
    use std::path::Path;

    /// Canonical hash of the projection of the frozen synthetic corpus,
    /// PINNED. The fixture never changes, so this constant is what makes
    /// a change of serialization, of ordering or of number encoding
    /// observable. The real lockfiles carry no pin: they change
    /// legitimately.
    const NESTED_CANONICAL_SHA256: &str =
        "99b1915dc6bd39609ed460429f0f382713c5d4052fdf207f371c5b950d4f9d77";

    fn fixture(name: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sbom")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
    }

    /// A real `package-lock.json` of the PRIVATE repository, read rather
    /// than copied, so a dependency bump cannot leave a stale copy behind.
    ///
    /// `None` when this run is not in the private tree -- the caller must
    /// return, and the gate has already said so out loud. See
    /// `crate::sbom::private_tree`.
    fn real_lockfile(project_dir: &str) -> Option<String> {
        let root = private_tree()?;
        Some(read_private_file(
            &root,
            &format!("{project_dir}/package-lock.json"),
        ))
    }

    fn subject() -> SubjectPurl {
        SubjectPurl::parse("pkg:npm/example-app@1.0.0").expect("subject parses")
    }

    fn nested() -> Projection {
        project_lockfile(&fixture("npm_nested.json"), subject())
            .expect("the nested fixture projects")
    }

    /// INTENT: a nested entry keeps its OWN version. The name of an entry
    ///   is everything after the LAST `node_modules/`, so
    ///   `node_modules/outer/node_modules/inner` is `inner` at the version
    ///   installed THERE, and two versions of one name are two
    ///   components.
    /// CONTEXT: measured on this repository: the portal lockfile has 14
    ///   nested entries and every one of them resolves a version that
    ///   differs from the hoisted one (`supports-color` 7.2.0 nested
    ///   against 8.1.1 hoisted, `picomatch` 2.3.2 against 4.0.5, eleven
    ///   platform binaries at 1.32.0 against 1.33.0). Taking the FIRST
    ///   segment after `node_modules/` would name the outer package and
    ///   attribute the inner version to it.
    /// EXPIRES IF: the package manager stops allowing nested trees.
    #[test]
    fn test_intent_npm_nested_entries_keep_their_own_version() {
        let projection = nested();
        let purls: Vec<&str> = projection
            .components()
            .iter()
            .map(|c| c.purl.as_str())
            .collect();
        assert!(
            purls.contains(&"pkg:npm/inner-lib@1.0.0"),
            "the hoisted entry keeps its version: {purls:?}"
        );
        assert!(
            purls.contains(&"pkg:npm/inner-lib@2.5.0"),
            "the NESTED entry keeps its own version: {purls:?}"
        );
        assert!(
            !purls.iter().any(|purl| purl.contains("outer-lib@2.5.0")),
            "the nested version must not be attributed to the outer \
             package: {purls:?}"
        );
        let inner: Vec<&Component> = projection
            .components()
            .iter()
            .filter(|c| c.name == "inner-lib")
            .collect();
        assert_eq!(inner.len(), 2, "two installed versions are two components");

        // The same shape, at scale, in the real tree.
        let Some(portal) = real_lockfile("portal") else {
            return;
        };
        let real = project_lockfile(&portal, subject()).expect("the real portal lockfile projects");
        let nested_names: Vec<&str> = real
            .components()
            .iter()
            .filter(|c| c.name == "supports-color")
            .map(|c| c.version.as_str())
            .collect();
        assert!(
            nested_names.len() >= 2,
            "the real lockfile installs several versions of one name; got \
             {nested_names:?}"
        );
    }

    /// INTENT: a scoped package percent-encodes the `@` of its SCOPE
    ///   (`pkg:npm/%40scope/name@version`) and leaves the `@` that
    ///   separates the VERSION literal.
    /// CONTEXT: the purl specification percent-encodes a namespace
    ///   segment, and `@` is not an unreserved character; the version
    ///   separator is part of the grammar. Encoding neither, or both,
    ///   produces a string that is not a purl, and the purl is the
    ///   identity of the component and its `bom-ref`.
    /// EXPIRES IF: the purl specification changes the namespace rule for
    ///   the npm type.
    #[test]
    fn test_intent_npm_scoped_purl_percent_encodes_the_scope() {
        let projection = project_lockfile(&fixture("npm_scoped.json"), subject())
            .expect("the scoped fixture projects");
        let scoped = projection
            .components()
            .iter()
            .find(|c| c.name == "widget")
            .expect("the scoped component");
        assert_eq!(scoped.purl, "pkg:npm/%40example-scope/widget@0.4.0");
        assert!(
            !scoped.purl.contains("/@"),
            "the `@` of the scope must not survive unencoded: {}",
            scoped.purl
        );
        assert!(
            !scoped.purl.contains("%400.4.0"),
            "the `@` that separates the version must stay literal: {}",
            scoped.purl
        );
        // The scope reaches `group` WITHOUT its `@`, and the bare name is
        // the name.
        assert_eq!(scoped.group.as_deref(), Some("example-scope"));
        assert_eq!(scoped.name, "widget");

        // An unscoped package has no namespace segment at all.
        let plain = projection
            .components()
            .iter()
            .find(|c| c.name == "plain-lib")
            .expect("the unscoped component");
        assert_eq!(plain.purl, "pkg:npm/plain-lib@1.2.3");
        assert_eq!(plain.group, None);

        // The emitted `bom-ref` is that same purl, escapes included.
        let emitted = projection.to_cyclonedx()["components"]
            .as_array()
            .expect("components")
            .iter()
            .find(|c| c["purl"] == "pkg:npm/%40example-scope/widget@0.4.0")
            .expect("the scoped component")
            .clone();
        assert_eq!(
            emitted["bom-ref"],
            serde_json::json!("pkg:npm/%40example-scope/widget@0.4.0")
        );

        // The real tree carries scoped packages, and every one of them
        // projects to a purl of the same grammar.
        let Some(portal) = real_lockfile("portal") else {
            return;
        };
        let real = project_lockfile(&portal, subject()).expect("the real portal lockfile projects");
        let scoped_real: Vec<&str> = real
            .components()
            .iter()
            .filter(|c| c.group.is_some())
            .map(|c| c.purl.as_str())
            .collect();
        assert!(
            !scoped_real.is_empty(),
            "the real lockfile installs scoped packages"
        );
        for purl in scoped_real {
            assert!(
                purl.starts_with("pkg:npm/%40"),
                "a scoped purl starts with the encoded scope: {purl}"
            );
        }
    }

    /// INTENT: the top-level set comes from the ROOT entry `""` of the
    ///   `packages` map, never from the first level of installed
    ///   directories.
    /// CONTEXT: measured on this repository: the portal root declares 5
    ///   development requirements and nothing else, while the lockfile
    ///   installs 106 packages, 93 of them directly under
    ///   `node_modules/`. Using the installed directories would inflate a
    ///   5-edge graph to 93 and turn "top-level dependency" into
    ///   "everything the resolver hoisted".
    /// EXPIRES IF: the lockfile stops recording the root requirements in
    ///   the `""` entry.
    #[test]
    fn test_intent_npm_root_entry_is_the_top_level_source() {
        let Some(portal) = real_lockfile("portal") else {
            return;
        };
        let real = project_lockfile(&portal, subject()).expect("the real portal lockfile projects");
        assert_eq!(
            real.top_level().len(),
            5,
            "the portal root declares exactly five requirements; got {:?}",
            real.top_level()
        );
        let hoisted = real
            .components()
            .iter()
            .filter(|c| !c.purl.is_empty())
            .count();
        assert!(
            hoisted > 5 * 10,
            "the installed tree is an order of magnitude larger than the \
             top-level set ({hoisted} components), so a mutant that used \
             the installed entries could not pass"
        );
        for purl in real.top_level() {
            assert!(
                real.components().iter().any(|c| &c.purl == purl),
                "every top-level edge names a component of the document: {purl}"
            );
        }

        // The frontend root declares both runtime and development
        // requirements, and BOTH reach the set (the merge the basis token
        // declares).
        let Some(frontend_text) = real_lockfile("frontend") else {
            return;
        };
        let frontend = project_lockfile(&frontend_text, subject())
            .expect("the real frontend lockfile projects");
        assert_eq!(
            frontend.top_level().len(),
            17,
            "5 dependencies + 12 devDependencies; got {:?}",
            frontend.top_level()
        );
    }

    /// INTENT: the projection of a given lockfile is byte-identical
    ///   across repeated runs AND across line-ending conventions.
    /// CONTEXT: this repository normalizes checkouts to LF, so a CRLF
    ///   fixture committed to the tree would be normalized back and the
    ///   test would certify nothing. The CRLF copy is built in memory, at
    ///   test time.
    /// EXPIRES IF: the projection stops being a pure function of the
    ///   lockfile bytes.
    #[test]
    fn test_intent_npm_projection_is_byte_reproducible() {
        for project_dir in ["portal", "frontend"] {
            let Some(raw) = real_lockfile(project_dir) else {
                return;
            };
            let bytes = |text: &str| {
                project_lockfile(text, subject())
                    .expect("the real lockfile projects")
                    .to_canonical_bytes()
                    .expect("canonical bytes")
            };
            let first = bytes(&raw);
            let second = bytes(&raw);
            assert_eq!(
                first, second,
                "two projections of one lockfile must agree byte for byte"
            );

            let crlf = raw.replace('\n', "\r\n");
            assert_ne!(crlf, raw, "the in-memory CRLF copy must actually differ");
            assert_eq!(
                first,
                bytes(&crlf),
                "the line-ending convention of the lockfile must not reach \
                 the emitted bytes"
            );

            let projection = project_lockfile(&raw, subject()).expect("projects");
            assert!(
                projection.components().len() > 50,
                "a real lockfile projects far more than a handful of \
                 components; got {}",
                projection.components().len()
            );
            assert!(!projection.top_level().is_empty());
            for pair in projection.components().windows(2) {
                assert!(
                    pair[0].purl < pair[1].purl,
                    "component order must be strictly increasing over purls"
                );
            }
            // Reported, never pinned: a real lockfile changes legitimately.
            println!(
                "npm real projection canonical sha256 ({project_dir}) = {}",
                projection.canonical_sha256().expect("canonical hash")
            );
        }
    }

    /// The frozen byte-level pin of the synthetic corpus.
    ///
    /// The fixture behind it carries a SCOPED, DEVELOPMENT-only entry with
    /// an `integrity`, an `author` and a `funding` block, so the pin is
    /// what makes each of those observable: a leaked `author` on that
    /// component, a `%40` that stopped being emitted, or a scope flipped
    /// to `required` all move these bytes. Without such an entry the pin
    /// covered only unscoped, provenance-free packages and every one of
    /// those regressions was mute.
    #[test]
    fn npm_fixture_canonical_hash_is_pinned() {
        let text = fixture("npm_nested.json");
        // Non-vacuity: the discarded fields really are in the input.
        for needle in [
            "node_modules/@example-scope/dev-widget",
            "\"integrity\": \"sha512-",
            "\"author\"",
            "\"funding\"",
        ] {
            assert!(
                text.contains(needle),
                "the pinned fixture must keep `{needle}`: the pin is what makes \
                 its DISCARD observable"
            );
        }

        let projection = nested();
        let scoped = projection
            .components()
            .iter()
            .find(|c| c.purl == "pkg:npm/%40example-scope/dev-widget@0.4.0")
            .expect("the scoped development component");
        assert_eq!(scoped.group.as_deref(), Some("example-scope"));
        assert_eq!(scoped.scope, Some("optional"));
        assert!(scoped.hash.is_none());

        let bytes = projection.to_canonical_bytes().expect("canonical bytes");
        for leaked in ["author", "integrity", "funding", "maintainer", "license"] {
            assert!(
                !bytes.contains(leaked),
                "the emitted bytes carry `{leaked}`, which the projection \
                 discards:\n{bytes}"
            );
        }

        let mut hasher = Sha256::new();
        hasher.update(bytes.as_bytes());
        assert_eq!(
            format!("{:x}", hasher.finalize()),
            NESTED_CANONICAL_SHA256,
            "the canonical bytes of the frozen fixture changed:\n{bytes}"
        );
    }

    /// A lockfileVersion 2 lockfile carries BOTH the `packages` map and
    /// the legacy `dependencies` tree. The `packages` map wins: it is the
    /// installed tree, and the legacy block is a compatibility shim.
    #[test]
    fn npm_v2_reads_the_packages_map_and_ignores_the_legacy_tree() {
        let lock = parse_npm_lock(&fixture("npm_lock_v2.json")).expect("the v2 fixture parses");
        assert_eq!(lock.lockfile_version, 2);
        let projection = project(&lock, subject()).expect("the v2 fixture projects");
        assert_eq!(
            projection
                .components()
                .iter()
                .map(|c| c.purl.as_str())
                .collect::<Vec<_>>(),
            vec!["pkg:npm/plain-lib@1.2.3"],
            "the legacy `dependencies` block must not add a second, \
             differently versioned component"
        );
        assert_eq!(projection.top_level(), ["pkg:npm/plain-lib@1.2.3"]);
    }

    /// A version 1 layout -- a legacy `dependencies` tree and NO
    /// `packages` map -- is fail-loud, not read as if it were a v2.
    #[test]
    fn npm_v1_layout_is_fail_loud() {
        let error =
            parse_npm_lock(&fixture("npm_v1_legacy.json")).expect_err("a v1 layout must not parse");
        assert!(
            matches!(error, SbomError::UnsupportedLockShape { .. }),
            "expected UnsupportedLockShape, got {error:?}"
        );
    }

    /// The synthetic corpus keeps its `integrity` values on purpose, and
    /// the real trees of this repository record thousands of them: none
    /// reaches a component, here or there.
    #[test]
    fn npm_projects_no_digest_at_all() {
        let projection = project_lockfile(&fixture("npm_scoped.json"), subject())
            .expect("the scoped fixture projects");
        assert!(
            projection.components().iter().all(|c| c.hash.is_none()),
            "an npm component carries no digest"
        );
        for project_dir in ["portal", "frontend"] {
            let Some(raw) = real_lockfile(project_dir) else {
                return;
            };
            let real = project_lockfile(&raw, subject()).expect("the real lockfile projects");
            assert!(
                real.components().iter().all(|c| c.hash.is_none()),
                "the real {project_dir} lockfile contributes no digest either"
            );
        }
    }

    /// An entry with no `version` is an error, not a component emitted
    /// without one.
    #[test]
    fn npm_entry_without_version_is_fail_loud() {
        let error = project_lockfile(&fixture("npm_missing_version.json"), subject())
            .expect_err("an entry with no version must not project");
        assert!(
            matches!(error, SbomError::MissingVersion { ref name } if name == "no-version-lib"),
            "expected MissingVersion, got {error:?}"
        );
    }

    /// A root requirement with no installed entry is an error, not a
    /// silently dropped top-level edge.
    #[test]
    fn npm_root_requirement_absent_from_the_tree_is_fail_loud() {
        let error = project_lockfile(&fixture("npm_ghost_root_dep.json"), subject())
            .expect_err("a root requirement with no entry must not project");
        assert!(
            matches!(
                error,
                SbomError::UnresolvedDependencyRef { ref reference } if reference == "ghost-lib"
            ),
            "expected UnresolvedDependencyRef, got {error:?}"
        );
    }

    /// INTENT: a `link: true` entry is OMITTED from the components and
    ///   COUNTED in `seetrex:sbom.links_omitted`, so the omission is
    ///   visible in the document instead of mute.
    /// CONTEXT: a linked entry points at another key of the tree and
    ///   carries no version of its own, so it cannot be projected as an
    ///   installed package. A component that disappears from a document
    ///   which still LOOKS complete is the worst failure mode available
    ///   to a bill of materials, and the counter is what makes the
    ///   difference observable.
    /// EXPIRES IF: the projection learns to read the workspace key a link
    ///   points at, at which point the entry becomes a component and the
    ///   counter stops being the honest answer.
    #[test]
    fn test_intent_npm_linked_entries_are_omitted_and_counted() {
        let lock = parse_npm_lock(&fixture("npm_linked.json")).expect("the link fixture parses");
        assert_eq!(lock.linked_paths, ["node_modules/linked-lib"]);
        assert!(
            lock.packages.iter().all(|p| p.name != "linked-lib"),
            "a linked entry is not an installed package"
        );

        let projection = project(&lock, subject()).expect("the link fixture projects");
        assert_eq!(projection.links_omitted(), Some(1));
        assert!(projection
            .components()
            .iter()
            .all(|c| c.name != "linked-lib"));

        let property = projection.to_cyclonedx()["properties"]
            .as_array()
            .expect("properties")
            .iter()
            .find(|p| p["name"] == "seetrex:sbom.links_omitted")
            .expect("the links_omitted property")["value"]
            .clone();
        assert_eq!(property, serde_json::json!("1"));
    }

    /// INTENT: a `link: true` entry cannot erase an INSTALLED package. Only
    ///   a workspace key is admitted as the other half of a link; a
    ///   `resolved` that names a `node_modules/...` key is not a workspace
    ///   link, so the package it names stays in `components` and the link
    ///   entry alone is omitted and counted.
    /// CONTEXT: the target was admitted by SET MEMBERSHIP alone -- "some
    ///   `link: true` entry named this key" -- and the naming half is a
    ///   field of the lockfile under test. A two-line entry
    ///   (`"node_modules/decoy": {"resolved": "node_modules/hidden-lib",
    ///   "link": true}`) therefore deleted `hidden-lib@6.6.6` from the
    ///   document, leaving `links_omitted: 1`, which an auditor reads as
    ///   the one link and not as a missing dependency. A component that
    ///   disappears from a document that still LOOKS complete is the worst
    ///   failure mode available to a bill of materials, and this one was
    ///   reachable by the party the document is supposed to hold to
    ///   account.
    /// EXPIRES IF: npm starts writing link targets under `node_modules/`,
    ///   at which point workspace paths stop being what distinguishes the
    ///   two halves of a link.
    #[test]
    fn test_intent_npm_link_into_node_modules_cannot_erase_a_package() {
        let lock = parse_npm_lock(&fixture("npm_link_into_node_modules.json"))
            .expect("the fixture parses");
        assert_eq!(
            lock.linked_paths,
            ["node_modules/decoy"],
            "the link entry itself is still the one omission"
        );

        let projection = project(&lock, subject()).expect("the fixture projects");
        assert_eq!(
            projection.links_omitted(),
            Some(1),
            "one link is one omission; the package it pointed at is not a second"
        );

        let purls: Vec<&str> = projection
            .components()
            .iter()
            .map(|c| c.purl.as_str())
            .collect();
        assert_eq!(
            purls,
            ["pkg:npm/hidden-lib@6.6.6", "pkg:npm/plain-lib@1.2.3"],
            "`hidden-lib` is an installed package the lockfile resolves; a `link: true` \
             entry pointing at its key does not make it disappear"
        );
    }

    /// INTENT: a ROOT requirement satisfied by a `link: true` entry is
    ///   OMITTED from the top-level set, exactly as the entry itself is
    ///   omitted from the components -- and the omission is already
    ///   counted in `seetrex:sbom.links_omitted`.
    /// CONTEXT: a linked entry points at a workspace path this projection
    ///   does not read, so there is no component to point an edge at.
    ///   Failing instead made every tree that links a local package
    ///   unprojectable, and inventing the edge anyway would leave a
    ///   `dependsOn` naming a bom-ref the document never declares --
    ///   invalid for a strict CycloneDX consumer. Specification 2.3
    ///   already said "omitted from `components` AND from the top-level
    ///   set"; only the first half was executed.
    /// EXPIRES IF: the projection learns to read the workspace key a link
    ///   points at, at which point the entry becomes a component and the
    ///   edge becomes emittable.
    #[test]
    fn test_intent_npm_linked_root_requirement_is_omitted_not_fatal() {
        let projection = project_lockfile(&fixture("npm_linked_root_dep.json"), subject())
            .expect("a root requirement satisfied by a link must project, not fail");

        assert_eq!(
            projection.top_level(),
            [
                "pkg:npm/extra-lib@2.0.0".to_string(),
                "pkg:npm/plain-lib@1.2.3".to_string(),
            ],
            "the two linked requirements contribute no edge; the two ordinary \
             ones do, one from `dependencies` and one from `devDependencies`"
        );
        assert_eq!(
            projection.links_omitted(),
            Some(2),
            "the omissions stay COUNTED, so they are visible in the document"
        );

        // The document has no dangling reference: every edge resolves
        // against a component the document declares.
        let doc = projection.to_cyclonedx();
        let declared: Vec<&str> = doc["components"]
            .as_array()
            .expect("components")
            .iter()
            .map(|c| c["purl"].as_str().expect("a purl"))
            .collect();
        for edge in doc["dependencies"][0]["dependsOn"]
            .as_array()
            .expect("dependsOn")
        {
            let reference = edge.as_str().expect("a string edge");
            assert!(
                declared.contains(&reference),
                "the graph names `{reference}`, which no component declares: {declared:?}"
            );
        }
    }

    /// INTENT: the target entry of an omitted `link: true` is SKIPPED as
    ///   that link's other half, and every OTHER key with no
    ///   `node_modules/` segment is still rejected as the workspace path
    ///   Section 2.3 declines to read.
    /// CONTEXT: npm writes a link in two halves -- the
    ///   `node_modules/<name>` entry carrying `"link": true` and a full
    ///   entry under the `workspaces/<name>` path it `resolved` to. The
    ///   link fixtures carried only the first half, so the linked-entry
    ///   rule was measured against a lockfile npm never produces; a REAL
    ///   one was rejected outright by the workspace rule, which made the
    ///   whole `link` path unreachable in practice.
    /// EXPIRES IF: npm workspaces stop being a non-goal of version 1, at
    ///   which point the target becomes a component and this narrow skip
    ///   becomes a read.
    /// MUTANT: skip any key that has no `node_modules/` segment (the
    ///   general workspace admission) -- the second half below goes red.
    #[test]
    fn test_intent_npm_link_target_is_skipped_but_workspaces_stay_rejected() {
        // Non-vacuity: the fixture really carries both halves.
        let text = fixture("npm_linked_root_dep.json");
        assert!(
            text.contains("\"workspaces/linked-lib\"") && text.contains("\"link\": true"),
            "the fixture must carry BOTH halves of a link, or the skip below is \
             measured against a lockfile npm does not write"
        );
        let lock = parse_npm_lock(&text).expect("a REAL linked lockfile must parse");
        assert!(
            lock.packages
                .iter()
                .all(|p| !p.path.starts_with("workspaces/")),
            "a link target is skipped, not projected: {:?}",
            lock.packages.iter().map(|p| &p.path).collect::<Vec<_>>()
        );
        assert_eq!(
            lock.linked_paths.len(),
            2,
            "one link is one omission however many keys npm spends writing it"
        );

        // The general rule is untouched: a workspace entry NO link points
        // at is still fail-loud.
        // Only the KEY is renamed, so nothing `resolved` points at it any
        // more; the link's own half is left exactly as it was.
        let orphan = text.replace(
            "\"workspaces/linked-lib\": {",
            "\"workspaces/orphan-member\": {",
        );
        assert_ne!(orphan, text, "the key rename must actually apply");
        let error = parse_npm_lock(&orphan)
            .expect_err("a workspace path no link points at must not be read");
        assert!(
            matches!(error, SbomError::UnsupportedLockShape { .. }),
            "expected UnsupportedLockShape, got {error:?}"
        );
        assert!(
            format!("{error}").contains("workspaces/orphan-member"),
            "the rejection must name the key it refused: {error}"
        );
    }

    /// INTENT: ONE reading of a `packages` key decides both questions the
    ///   module asks of it -- "does this key name an installed package?"
    ///   and "is this key a workspace path a link may point at?" -- so the
    ///   two can never disagree, and a key the module cannot read HONESTLY
    ///   is fail-loud whether or not something in the file points at it.
    /// CONTEXT: the two questions were asked by two different readings.
    ///   The skip asked for a `node_modules` path SEGMENT; the name
    ///   extraction asked for the SUBSTRING `node_modules/`. A key such as
    ///   `vendor_node_modules/hidden-lib` was therefore a workspace path to
    ///   the first and an installed package to the second, so a
    ///   `"link": true` whose `resolved` named it erased that installed
    ///   package from `components` -- measured: the purls lost
    ///   `hidden-lib@6.6.6` and the only trace was a `links_omitted` of 1,
    ///   which an auditor reads as the one link. The mirror image was as
    ///   bad: `node_modules\hidden-lib` alone was an `UnsupportedLockShape`
    ///   -- a shape the module states it cannot read -- and the SAME key as
    ///   a link target parsed green, so the fail-loud rule was disarmed by
    ///   a `resolved` the lockfile itself chooses.
    /// EXPIRES IF: the projection learns to read workspace keys, at which
    ///   point the skip disappears and only the name extraction remains.
    /// MUTANT: give the skip and the name extraction separate readings
    ///   again (`!key.split('/').any(|s| s == "node_modules")` beside
    ///   `rsplit_once("node_modules/")`) -- both fixtures below go green
    ///   and the first one silently loses a package.
    #[test]
    fn test_intent_npm_one_key_reading_decides_both_the_skip_and_the_name() {
        // A key that merely LOOKS like an install path. It is not a
        // workspace path (a link may not point at it) and it is not an
        // installed location either, so it is neither skipped nor read.
        let lookalike = fixture("npm_link_into_lookalike_dir.json");
        assert!(
            lookalike.contains("\"resolved\": \"vendor_node_modules/hidden-lib\"")
                && lookalike.contains("\"vendor_node_modules/hidden-lib\": {"),
            "the fixture must carry a link POINTING AT the look-alike key, or the \
             disagreement it measures is not exercised"
        );
        let error = parse_npm_lock(&lookalike).expect_err(
            "a key whose `node_modules` is not a path segment cannot be read as an \
             install path and must not be skipped as a workspace path either",
        );
        assert!(
            matches!(error, SbomError::UnsupportedLockShape { .. }),
            "expected UnsupportedLockShape, got {error:?}"
        );
        assert!(
            format!("{error}").contains("vendor_node_modules/hidden-lib"),
            "the rejection must name the key it refused: {error}"
        );

        // The same shape the module already refused when nothing pointed
        // at it. The refusal must not depend on a `resolved` the file
        // chooses: the skip cannot run before the rejection.
        let backslash = fixture("npm_link_into_backslash_key.json");
        let error = parse_npm_lock(&backslash).expect_err(
            "a shape this module states it cannot read must stay fail-loud when a \
             link points at it",
        );
        assert!(
            matches!(error, SbomError::UnsupportedLockShape { .. }),
            "expected UnsupportedLockShape, got {error:?}"
        );
        // And the very same key with no link pointing at it is refused
        // too, which is what "one reading" means.
        let unlinked = backslash.replace("\"link\": true", "\"link\": false");
        assert_ne!(unlinked, backslash, "the link must actually be disarmed");
        assert!(
            matches!(
                parse_npm_lock(&unlinked),
                Err(SbomError::UnsupportedLockShape { .. })
            ),
            "the same key must be refused whether or not a link points at it"
        );

        // The reading that must NOT change: a nested install path is an
        // installed location however deep, and keeps its own name.
        let nested_key = "{\"lockfileVersion\":3,\"packages\":{\"\":{},\
             \"packages/a/node_modules/b\":{\"version\":\"1.0.0\"}}}";
        let lock = parse_npm_lock(nested_key)
            .expect("`packages/a/node_modules/b` is an installed location");
        assert_eq!(
            lock.packages
                .iter()
                .map(|p| (p.path.as_str(), p.name.as_str()))
                .collect::<Vec<_>>(),
            [("packages/a/node_modules/b", "b")],
            "a nested install path stays projected under its own name"
        );
    }

    /// INTENT: one purl reached by two entries that disagree about `dev`
    ///   is ONE component, scoped `required`. `scope` is not part of what
    ///   makes two entries a collision: the purl already settles name and
    ///   version, and the artifact ships in the product if ANY path needs
    ///   it at runtime.
    /// CONTEXT: an installed tree reaches the same package at the same
    ///   version by several paths, and a nested copy under a dev-only
    ///   parent carries `dev: true` while the hoisted one does not.
    ///   Emitting both made `Projection::new` fail with `PurlCollision` --
    ///   an ordinary tree refused as corrupt -- and taking the last entry
    ///   read would have made the scope depend on iteration order.
    /// EXPIRES IF: `scope` becomes part of the identity of a component,
    ///   which would first require the purl to carry it.
    /// MUTANT: make `merge_scope` return `incoming` (pure last-wins).
    #[test]
    fn test_intent_npm_one_purl_two_scopes_resolves_to_required() {
        // BOTH ORDERS, and the test says out loud which is which. With a
        // single fixture whose dev entry happens to sort FIRST, pure
        // last-wins gives the same answer as the merge, and `merge_scope`
        // is unmeasured: the mutant above stayed green.
        let cases = [
            ("npm_same_purl_two_scopes.json", true),
            ("npm_same_purl_runtime_first.json", false),
        ];
        let mut orders_seen = std::collections::BTreeSet::new();

        for (name, expect_dev_first) in cases {
            let text = fixture(name);
            let lock = parse_npm_lock(&text).expect("the fixture parses");
            let shared: Vec<&NpmPackage> = lock
                .packages
                .iter()
                .filter(|package| package.name == "shared-lib")
                .collect();
            assert_eq!(shared.len(), 2, "{name}: two entries produce the same purl");
            assert!(
                shared.iter().any(|package| package.dev)
                    && shared.iter().any(|package| !package.dev),
                "{name}: the two entries must disagree about `dev`, or the merge \
                 below would be testing nothing"
            );
            // The ORDER is the whole point of having two fixtures, so it is
            // asserted rather than assumed: a rename inside either lockfile
            // that reshuffled the keys would otherwise leave both cases on
            // the same side and the mutant green again.
            assert_eq!(
                shared[0].dev,
                expect_dev_first,
                "{name}: the entries reach the projection in the wrong order \
                 ({:?}); this fixture exists to put the {} entry FIRST",
                shared.iter().map(|p| (&p.path, p.dev)).collect::<Vec<_>>(),
                if expect_dev_first { "dev" } else { "runtime" }
            );
            orders_seen.insert(shared[0].dev);

            let projection = project(&lock, subject())
                .expect("two entries under one purl are one component, not a collision");
            let merged: Vec<&Component> = projection
                .components()
                .iter()
                .filter(|c| c.purl == "pkg:npm/shared-lib@2.0.0")
                .collect();
            assert_eq!(merged.len(), 1, "{name}: one purl is one component");
            assert_eq!(
                merged[0].scope,
                Some("required"),
                "{name}: the more permissive scope wins whatever the order -- the \
                 artifact does ship in the product, so calling it optional would \
                 be a false statement inside the document"
            );

            // Determinism, in the direction the bug would have taken: the
            // same lockfile read again yields the same bytes.
            let bytes = projection.to_canonical_bytes().expect("canonical bytes");
            let again = project(&lock, subject())
                .expect("projects")
                .to_canonical_bytes()
                .expect("canonical bytes");
            assert_eq!(bytes, again, "{name}");
        }

        assert_eq!(
            orders_seen.len(),
            2,
            "both orders must actually occur across the fixtures, or last-wins \
             and the merge are indistinguishable"
        );
    }

    /// A leading UTF-8 byte-order mark is rejected by an EXPLICIT check on
    /// line 1, not by whatever the JSON parser happens to say about a
    /// stray code point.
    #[test]
    fn npm_lock_with_a_byte_order_mark_is_fail_loud() {
        let error = parse_npm_lock(&format!("\u{feff}{}", fixture("npm_nested.json")))
            .expect_err("a lockfile with a BOM must not parse");
        assert!(
            matches!(
                error,
                SbomError::UnsupportedLockShape { line: 1, ref detail } if detail == "UTF-8 BOM"
            ),
            "expected the explicit BOM rejection on line 1, got {error:?}"
        );
    }

    /// The counter is PRESENT for every npm projection -- `"0"` when the
    /// tree has no link -- and the composer-only counter is ABSENT, so a
    /// reader can tell "no links" from "this lockfile cannot have one".
    #[test]
    fn npm_link_counter_is_present_even_at_zero() {
        let projection = nested();
        assert_eq!(projection.links_omitted(), Some(0));
        assert_eq!(projection.platform_requirements_excluded(), None);

        let doc = projection.to_cyclonedx();
        let names: Vec<&str> = doc["properties"]
            .as_array()
            .expect("properties")
            .iter()
            .map(|p| p["name"].as_str().expect("property name"))
            .collect();
        assert_eq!(
            names,
            vec![
                "seetrex:sbom.links_omitted",
                "seetrex:sbom.lockfile_kind",
                "seetrex:sbom.projection",
                "seetrex:sbom.top_level_basis",
            ],
            "the BOM properties are sorted ascending by name"
        );
    }

    /// The token that travels inside the document names the ecosystem,
    /// the source of the set and the dev merge.
    #[test]
    fn npm_top_level_basis_declares_the_root_and_the_dev_merge() {
        assert_eq!(TOP_LEVEL_BASIS, "npm-lock-root-dependencies-merged-dev");
        let basis = nested().to_cyclonedx()["properties"]
            .as_array()
            .expect("properties")
            .iter()
            .find(|p| p["name"] == "seetrex:sbom.top_level_basis")
            .expect("the top_level_basis property")["value"]
            .clone();
        assert_eq!(basis, serde_json::json!(TOP_LEVEL_BASIS));
    }

    /// `dev: true` becomes `scope: "optional"`, everything else
    /// `"required"`.
    #[test]
    fn npm_dev_entries_are_scoped_optional() {
        let projection = nested();
        let scope_of = |purl: &str| {
            projection
                .components()
                .iter()
                .find(|c| c.purl == purl)
                .unwrap_or_else(|| panic!("component {purl} is in the projection"))
                .scope
        };
        assert_eq!(scope_of("pkg:npm/outer-lib@3.0.0"), Some("required"));
        assert_eq!(scope_of("pkg:npm/dev-only-lib@0.9.0"), Some("optional"));

        // The real portal tree is development-only, so every component of
        // it is optional -- and the frontend tree has both.
        let Some(frontend_text) = real_lockfile("frontend") else {
            return;
        };
        let frontend = project_lockfile(&frontend_text, subject())
            .expect("the real frontend lockfile projects");
        assert!(frontend
            .components()
            .iter()
            .any(|c| c.scope == Some("optional")));
        assert!(frontend
            .components()
            .iter()
            .any(|c| c.scope == Some("required")));
    }

    /// Shapes outside what the parser reads abort the parse instead of
    /// being read best-effort.
    #[test]
    fn npm_shapes_outside_the_subset_are_fail_loud() {
        for (text, what) in [
            ("{", "truncated JSON"),
            ("[]", "a lockfile that is not an object"),
            ("{\"packages\":{}}", "no lockfileVersion"),
            (
                "{\"lockfileVersion\":4,\"packages\":{}}",
                "a lockfileVersion above the supported range",
            ),
            (
                "{\"lockfileVersion\":3,\"packages\":{\"node_modules/a\":42}}",
                "an entry that is not an object",
            ),
            (
                "{\"lockfileVersion\":3,\"packages\":{\"packages/inner\":{\"version\":\"1.0.0\"}}}",
                "a key with no node_modules segment",
            ),
            (
                "{\"lockfileVersion\":3,\"packages\":{\"node_modules/\":{\"version\":\"1.0.0\"}}}",
                "a key naming no package",
            ),
            (
                "{\"lockfileVersion\":3,\"packages\":{\"node_modules/a\":{\"version\":1}}}",
                "a non-string version",
            ),
            (
                "{\"lockfileVersion\":3,\"packages\":{\"\":{\"dependencies\":[]}}}",
                "a root requirement map that is not an object",
            ),
        ] {
            let error = parse_npm_lock(text).expect_err(&format!("{what} must abort the parse"));
            assert!(
                matches!(error, SbomError::UnsupportedLockShape { .. }),
                "{what}: expected UnsupportedLockShape, got {error:?}"
            );
        }
    }

    /// An npm name that is neither `name` nor `@scope/name` cannot become
    /// a purl.
    #[test]
    fn npm_name_outside_the_grammar_is_fail_loud() {
        for bad in ["@scope", "@/name", "@scope/", "a/b", "@scope/a/b", ""] {
            assert!(
                split_scope(bad).is_err(),
                "`{bad}` must not split into a scope and a name"
            );
        }
        assert_eq!(split_scope("plain").expect("valid"), (None, "plain"));
        assert_eq!(
            split_scope("@scope/name").expect("valid"),
            (Some("scope"), "name")
        );
    }

    /// The subject is the document's `metadata.component` and is not
    /// repeated inside `components`.
    #[test]
    fn npm_subject_is_metadata_component_and_not_repeated() {
        let projection = nested();
        assert!(
            projection
                .components()
                .iter()
                .all(|c| c.purl != subject().as_str()),
            "the subject must not also appear as a component"
        );
        let doc = projection.to_cyclonedx();
        assert_eq!(
            doc["metadata"]["component"]["purl"],
            "pkg:npm/example-app@1.0.0"
        );
        assert_eq!(
            doc["metadata"]["component"]["bom-ref"],
            "pkg:npm/example-app@1.0.0"
        );
        assert_eq!(doc["dependencies"][0]["ref"], "pkg:npm/example-app@1.0.0");
    }

    /// INTENT: the `node_modules` segment of a `packages` key is matched
    ///   without regard to ASCII case, so `NODE_MODULES/<pkg>` names an
    ///   INSTALLED package and can never be skipped as the target of a
    ///   `link: true`.
    /// CONTEXT: `classify_key` compared the segment with `==`. On a
    ///   case-insensitive filesystem -- Windows, macOS -- `NODE_MODULES`
    ///   IS the install directory, so such a key names a real installed
    ///   package; the module read it as a workspace path instead, which
    ///   made it a legal link target. Measured on the lockfile below:
    ///   `components` came back EMPTY and `links_omitted` was 1, so the
    ///   only trace of the erased package was a counter an auditor reads
    ///   as the one link. That is the same erasure the one-reading rule
    ///   exists to prevent, reached through the SPELLING of the key.
    /// EXPIRES IF: the projection learns to read workspace keys, at which
    ///   point a skipped target is projected rather than erased.
    /// MUTANT: put `*s == INSTALL_DIR` back in `classify_key` -- the
    ///   component assertion below goes red with an EMPTY component set.
    #[test]
    fn test_intent_npm_install_dir_segment_is_case_insensitive() {
        // Both halves of a link npm would write on a case-insensitive
        // filesystem: the `link: true` entry, and a `resolved` naming the
        // install directory in upper case.
        let text = "{\"lockfileVersion\":3,\"packages\":{\
             \"\":{},\
             \"node_modules/hidden-lib\":{\"link\":true,\
             \"resolved\":\"NODE_MODULES/hidden-lib\"},\
             \"NODE_MODULES/hidden-lib\":{\"version\":\"6.6.6\"}}}";
        assert!(
            text.contains("\"link\": true") || text.contains("\"link\":true"),
            "the lockfile must carry the link half, or the skip is unexercised"
        );

        let lock = parse_npm_lock(text).expect("the lockfile parses");
        assert_eq!(
            lock.linked_paths,
            vec!["node_modules/hidden-lib".to_string()],
            "the `link: true` entry is the one omission"
        );
        let projection = project(&lock, subject()).expect("the lockfile projects");
        assert_eq!(
            projection
                .components()
                .iter()
                .map(|c| c.purl.as_str())
                .collect::<Vec<_>>(),
            vec!["pkg:npm/hidden-lib@6.6.6"],
            "the installed package survives the link: reading its key as a \
             workspace path erased it and left only the counter"
        );
        assert_eq!(
            projection.links_omitted(),
            Some(1),
            "the link itself is still omitted and counted exactly once"
        );

        // The reading itself, stated once: an upper-case install directory
        // is an installed location and NOT a workspace path.
        assert!(
            matches!(
                classify_key("NODE_MODULES/hidden-lib"),
                PackageKey::Installed("hidden-lib")
            ),
            "`NODE_MODULES/hidden-lib` names an installed package"
        );
        assert!(
            matches!(
                classify_key("Node_Modules/a/NODE_MODULES/b"),
                PackageKey::Installed("b")
            ),
            "a nested install path keeps its own name whatever the case"
        );
        assert!(
            !is_workspace_key("NODE_MODULES/hidden-lib"),
            "an install path in upper case is not a workspace path a link may point at"
        );

        // The lower-case control: same tree, same answer, so the assertion
        // above measures the CASE and not the shape of the lockfile.
        let lower = text.replace(
            "NODE_MODULES/hidden-lib",
            "node_modules/vendor/node_modules/hidden-lib",
        );
        assert_ne!(lower, text, "the control must actually differ");
        let control = project(
            &parse_npm_lock(&lower).expect("the control parses"),
            subject(),
        )
        .expect("the control projects");
        assert_eq!(
            control
                .components()
                .iter()
                .map(|c| c.purl.as_str())
                .collect::<Vec<_>>(),
            vec!["pkg:npm/hidden-lib@6.6.6"]
        );
    }

    /// A `packages` key with an EMPTY path segment is refused, and the
    /// refusal names the KEY.
    ///
    /// `node_modules//x` and `node_modules/foo/` were read as installed
    /// locations whose names were `/x` and `foo/`. Those names reached the
    /// purl grammar and were rejected there -- measured
    /// `MalformedComponentPurl`, so nothing was ever projected under a
    /// broken purl -- but the rejection named a fragment the lockfile
    /// never wrote instead of the key an auditor can go and look at. The
    /// key is what a reader can find, so the key is what is named.
    #[test]
    fn npm_key_with_an_empty_path_segment_is_fail_loud() {
        for key in ["node_modules//x", "node_modules/foo/", "packages//a"] {
            assert!(
                matches!(classify_key(key), PackageKey::Malformed(EMPTY_SEGMENT)),
                "`{key}` carries an empty segment and must be refused"
            );
            let text = format!(
                "{{\"lockfileVersion\":3,\"packages\":{{\"\":{{}},\
                 \"{key}\":{{\"version\":\"1.0.0\"}}}}}}"
            );
            let error = match parse_npm_lock(&text) {
                Ok(_) => panic!("`{key}` carries an empty segment and must not parse"),
                Err(error) => error,
            };
            assert!(
                matches!(error, SbomError::UnsupportedLockShape { .. }),
                "expected UnsupportedLockShape for `{key}`, got {error:?}"
            );
            assert!(
                format!("{error}").contains(key),
                "the rejection must name the key it refused: {error}"
            );
        }
    }

    /// INTENT: a key that carries `node_modules` without it being a path
    ///   segment is a HARD ERROR even when it could be a legitimate
    ///   workspace directory, because the module has no honest way to tell
    ///   the two apart.
    /// CONTEXT: `classify_key` documented `my-node_modules-tools` as a
    ///   workspace path it would admit. Measured, it is refused. The
    ///   refusal is not an accident of the look-alike rule but the price
    ///   of it: `my-node_modules-tools` differs from
    ///   `vendor_node_modules/hidden-lib` only in what follows the
    ///   look-alike, and admitting the second as a workspace path is
    ///   exactly how a `link: true` erases an installed package from
    ///   `components`. The cost is an npm workspace whose member directory
    ///   name contains `node_modules` being unprojectable -- loudly, and
    ///   only when a link resolves to it.
    /// EXPIRES IF: the projection learns to read workspace keys, at which
    ///   point the target of a link is projected rather than skipped and
    ///   the look-alike stops being a decision at all.
    /// MUTANT: narrow the look-alike arm to keys where the look-alike is
    ///   followed by a separator (`contains("node_modules/")`) -- the
    ///   first half below goes green and `vendor_node_modules/hidden-lib`
    ///   becomes a skippable workspace path again; drop the arm's case
    ///   folding (`key.contains(INSTALL_DIR)` in place of
    ///   `contains_ignore_ascii_case(key, INSTALL_DIR)`) -- the segment
    ///   arm above still folds case, so only a look-alike that is NOT a
    ///   segment shows it, and `vendor_NODE_MODULES/hidden-lib` becomes a
    ///   workspace path a `link: true` can erase a package through.
    #[test]
    fn test_intent_npm_lookalike_key_is_refused_even_if_it_could_be_a_workspace_dir() {
        // The look-alike is matched WITHOUT regard to case, like the
        // segment arm above it: a case-folded segment that is refused as
        // `node_modules` must not become admissible as `NODE_MODULES`
        // one character to the left of the separator.
        for key in [
            "my-node_modules-tools",
            "vendor_node_modules/hidden-lib",
            "vendor_NODE_MODULES/hidden-lib",
            "my-Node_Modules-tools",
        ] {
            assert!(
                matches!(classify_key(key), PackageKey::Malformed(NOT_A_SEGMENT)),
                "`{key}` must be refused, not read as a workspace path"
            );
            assert!(
                !is_workspace_key(key),
                "`{key}` must not be admitted as a link target"
            );
        }
        // A workspace key with no look-alike at all stays what it was: a
        // workspace path, rejected by Section 2.3 but skippable when a
        // link resolves to it.
        assert!(matches!(
            classify_key("workspaces/member"),
            PackageKey::Workspace
        ));
        assert!(is_workspace_key("workspaces/member"));
    }

    /// The boundary of the key-shape decision, stated once: a key whose
    /// NAME is outside the npm grammar is the purl builder's to refuse,
    /// not the classifier's.
    #[test]
    fn npm_multi_segment_name_is_refused_by_the_purl_grammar() {
        assert!(matches!(
            classify_key("node_modules/a/b"),
            PackageKey::Installed("a/b")
        ));
        let text = "{\"lockfileVersion\":3,\"packages\":{\"\":{},\
             \"node_modules/a/b\":{\"version\":\"1.0.0\"}}}";
        let lock = parse_npm_lock(text).expect("the key shape is readable");
        assert!(
            matches!(
                project(&lock, subject()),
                Err(SbomError::MalformedComponentPurl { .. })
            ),
            "`a/b` is not an npm name and must not become a purl"
        );
        // The scoped name that DOES carry a separator still projects.
        let scoped = "{\"lockfileVersion\":3,\"packages\":{\"\":{},\
             \"node_modules/@s/n\":{\"version\":\"1.0.0\"}}}";
        let projection = project(
            &parse_npm_lock(scoped).expect("a scoped key parses"),
            subject(),
        )
        .expect("a scoped name projects");
        assert_eq!(
            projection
                .components()
                .iter()
                .map(|c| c.purl.as_str())
                .collect::<Vec<_>>(),
            vec!["pkg:npm/%40s/n@1.0.0"]
        );
        // And a key that stops AT the segment still has its own reason.
        assert!(matches!(
            classify_key("node_modules"),
            PackageKey::Malformed(NAMES_NO_PACKAGE)
        ));
    }
}
