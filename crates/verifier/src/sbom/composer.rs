// SPDX-License-Identifier: Apache-2.0
//! `composer.lock` + `composer.json` -> [`Projection`].
//!
//! Composer is the one ecosystem of the three whose lockfile does NOT
//! contain the root requirement set: `composer.lock` lists the resolved
//! packages (`packages`, `packages-dev`) and never the `require` of the
//! project itself. The top-level set therefore needs a SECOND input, the
//! root `composer.json`, and this module refuses to project without it
//! -- an empty `dependsOn` is the exact signature of a document that
//! satisfies the shape of the regulation while covering nothing.
//!
//! Both inputs are JSON, so the parser is `serde_json` (already a
//! dependency of this crate for the verdict package) rather than own
//! code: the reason the `Cargo.lock` parser is hand written -- keeping a
//! TOML implementation out of an auditor's `cargo install` -- does not
//! apply to a format the crate already parses.
//!
//! ## What is read
//!
//! - `packages[]` -> components with `scope: "required"`.
//! - `packages-dev[]` -> components with `scope: "optional"`.
//! - per package: `name` (`vendor/name`) and `version` (verbatim,
//!   including a leading `v` when the lockfile writes one).
//! - from the manifest: the KEYS of `require` and `require-dev`, minus
//!   the platform requirements.
//!
//! Everything else -- `source`, `dist.url`, `dist.reference`,
//! `dist.shasum`, `time`, `authors`, `license`, `description`,
//! `keywords`, `support`, `funding` -- is DISCARDED: provenance and
//! personal data, not identity.
//!
//! ## No `hashes`
//!
//! A composer projection emits NO `hashes`, on any component.
//! `dist.shasum` is a SHA-1 of a zipball the registry builds on demand
//! -- not of an artifact the auditor holds, and EMPTY on every entry of
//! this repository's own `composer.lock`. Cargo's `checksum` is the one
//! digest the projection publishes (specification 2.4 and 5.2).
//!
//! ## Top-level set
//!
//! The keys of `require` and `require-dev` of the root manifest, merged.
//! The merge is declared in [`TOP_LEVEL_BASIS`] so the limitation travels
//! inside the artifact: the set OVER-approximates the runtime top level,
//! which is the safe direction for a requirement written as "at the very
//! least the top-level dependencies".
//!
//! Platform requirements (`php`, `php-*`, `ext-*`, `lib-*`, `composer*`)
//! are NOT software components and have no package purl -- emitting
//! `pkg:composer/php@^8.3` would invent a component that exists in no
//! registry. They are excluded from the set AND COUNTED, so the
//! exclusion is visible in the document rather than mute.

use serde_json::Value;

use super::{
    build_namespaced_purl, starts_with_byte_order_mark, Component, LockfileKind, Projection,
    ProjectionCounters, SbomError, SubjectPurl, BOM_DETAIL,
};

/// How the top-level set of a composer projection was derived.
///
/// The token names the limitation on purpose: the set is the MERGE of
/// `require` and `require-dev`, so it over-approximates the runtime top
/// level.
pub const TOP_LEVEL_BASIS: &str = "composer-json-require-merged-dev";

/// One entry of `packages` or `packages-dev`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposerPackage {
    /// `name`, as the lockfile spells it: `vendor/name`.
    pub name: String,
    /// `version`, verbatim. Absent only in a corrupt lockfile.
    pub version: Option<String>,
    /// True when the entry came from `packages-dev`.
    pub dev: bool,
}

/// A parsed `composer.lock`, reduced to what the projection needs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComposerLock {
    /// `packages` followed by `packages-dev`, in file order.
    pub packages: Vec<ComposerPackage>,
}

/// A parsed root `composer.json`, reduced to what the projection needs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComposerManifest {
    /// Keys of `require` and `require-dev` that name PACKAGES, in file
    /// order, `require` first.
    pub requirements: Vec<String>,
    /// How many platform requirements were dropped on the way.
    pub platform_requirements_excluded: usize,
}

fn unsupported(line: usize, detail: String) -> SbomError {
    SbomError::UnsupportedLockShape { line, detail }
}

fn malformed_manifest(detail: &str) -> SbomError {
    SbomError::MalformedManifest {
        detail: detail.to_string(),
    }
}

/// True for a composer requirement that is a PLATFORM requirement -- a
/// runtime, an extension or a library, none of which is a package with a
/// purl.
///
/// Composer normalizes package names to lowercase, so the test is over
/// the lowercased key.
pub fn is_platform_requirement(requirement: &str) -> bool {
    let key = requirement.to_ascii_lowercase();
    key == "php"
        || key.starts_with("php-")
        || key.starts_with("ext-")
        || key.starts_with("lib-")
        || key.starts_with("composer")
}

/// Parse a `composer.lock`.
///
/// Unknown top-level and per-package keys are IGNORED rather than
/// rejected: unlike the `Cargo.lock` subset, the discarded field set is
/// the design (provenance and personal data must not reach the
/// document), so a composer lockfile carrying a field this module does
/// not read is ordinary, not suspicious. What IS fail-loud is a missing
/// or wrongly typed field this module DOES read.
pub fn parse_composer_lock(text: &str) -> Result<ComposerLock, SbomError> {
    // Explicit, and first (specification 8, obligation 3): otherwise the
    // rejection is only whatever the JSON parser happens to say about a
    // stray code point, and an implementation that stripped the mark
    // instead would pass the same tests.
    if starts_with_byte_order_mark(text) {
        return Err(unsupported(1, BOM_DETAIL.to_string()));
    }
    let document: Value = serde_json::from_str(text)
        .map_err(|e| unsupported(e.line(), format!("composer.lock is not valid JSON: {e}")))?;
    let root = document
        .as_object()
        .ok_or_else(|| unsupported(1, "composer.lock is not a JSON object".to_string()))?;

    let mut packages = Vec::new();
    for (key, dev) in [("packages", false), ("packages-dev", true)] {
        let Some(value) = root.get(key) else {
            // `packages-dev` is legitimately absent from a project with
            // no development requirements. `packages` is not.
            if dev {
                continue;
            }
            return Err(unsupported(
                1,
                "composer.lock carries no `packages` array".to_string(),
            ));
        };
        let array = value
            .as_array()
            .ok_or_else(|| unsupported(1, format!("`{key}` is not an array")))?;
        for entry in array {
            packages.push(parse_package(entry, dev)?);
        }
    }
    Ok(ComposerLock { packages })
}

fn parse_package(entry: &Value, dev: bool) -> Result<ComposerPackage, SbomError> {
    let object = entry
        .as_object()
        .ok_or_else(|| unsupported(1, "a composer package entry is not an object".to_string()))?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| unsupported(1, "a composer package entry has no `name`".to_string()))?
        .to_string();
    let version = match object.get("version") {
        None => None,
        Some(Value::String(version)) => Some(version.clone()),
        Some(_) => {
            return Err(unsupported(
                1,
                format!("package `{name}` carries a non-string `version`"),
            ))
        }
    };
    Ok(ComposerPackage { name, version, dev })
}

/// Parse the root `composer.json`, keeping the requirement KEYS and the
/// count of the platform requirements that were excluded.
pub fn parse_composer_manifest(text: &str) -> Result<ComposerManifest, SbomError> {
    // The manifest is not a lockfile, so its BOM carries the manifest's
    // own error class -- a reader has to be able to tell WHICH of the two
    // inputs was malformed.
    if starts_with_byte_order_mark(text) {
        return Err(malformed_manifest(BOM_DETAIL));
    }
    let document: Value = serde_json::from_str(text)
        .map_err(|e| malformed_manifest(&format!("composer.json is not valid JSON: {e}")))?;
    let root = document
        .as_object()
        .ok_or_else(|| malformed_manifest("composer.json is not a JSON object"))?;

    let mut requirements = Vec::new();
    let mut platform_requirements_excluded = 0;
    for key in ["require", "require-dev"] {
        let Some(value) = root.get(key) else { continue };
        let table = value
            .as_object()
            .ok_or_else(|| malformed_manifest(&format!("`{key}` is not an object")))?;
        for requirement in table.keys() {
            if is_platform_requirement(requirement) {
                platform_requirements_excluded += 1;
                continue;
            }
            requirements.push(requirement.clone());
        }
    }
    Ok(ComposerManifest {
        requirements,
        platform_requirements_excluded,
    })
}

/// Project a parsed lockfile plus its root manifest against a subject
/// the auditor supplies.
pub fn project(
    lock: &ComposerLock,
    manifest: &ComposerManifest,
    subject: SubjectPurl,
) -> Result<Projection, SbomError> {
    let mut components = Vec::with_capacity(lock.packages.len());
    for package in &lock.packages {
        let version = package
            .version
            .clone()
            .filter(|version| !version.is_empty())
            .ok_or_else(|| SbomError::MissingVersion {
                name: package.name.clone(),
            })?;
        let (group, name) = split_vendor_name(&package.name)?;
        let purl = composer_purl(group, name, &version)?;
        // The subject is the document's `metadata.component`; listing it
        // again under `components` would put two components under one
        // reference.
        if purl == subject.as_str() {
            continue;
        }
        components.push(Component {
            purl,
            type_: "library",
            name: name.to_string(),
            group: Some(group.to_string()),
            version,
            scope: Some(if package.dev { "optional" } else { "required" }),
            // No digest: composer records none this projection may
            // publish (module header, "No `hashes`").
            hash: None,
        });
    }

    let mut top_level = Vec::with_capacity(manifest.requirements.len());
    for requirement in &manifest.requirements {
        let resolved = resolve_requirement(requirement, &lock.packages)?;
        let version = resolved
            .version
            .clone()
            .ok_or_else(|| SbomError::MissingVersion {
                name: resolved.name.clone(),
            })?;
        let (group, name) = split_vendor_name(&resolved.name)?;
        top_level.push(composer_purl(group, name, &version)?);
    }

    Projection::new(
        LockfileKind::Composer,
        subject,
        components,
        top_level,
        TOP_LEVEL_BASIS,
        ProjectionCounters {
            platform_requirements_excluded: Some(manifest.platform_requirements_excluded),
            // A `composer.lock` has no linked entries, so the counter is
            // ABSENT rather than `"0"`.
            links_omitted: None,
        },
    )
}

/// Parse both inputs and project in one step.
///
/// The manifest is an `Option` so that its ABSENCE is expressible, and
/// therefore testable: without a `composer.json` there is no top-level
/// set at all, and the honest answer is an error rather than an empty
/// `dependsOn`.
pub fn project_lockfile(
    lock_text: &str,
    manifest_text: Option<&str>,
    subject: SubjectPurl,
) -> Result<Projection, SbomError> {
    let manifest_text = manifest_text.ok_or_else(|| {
        malformed_manifest(
            "composer.lock does not record the root `require`, so the root \
             composer.json is a mandatory second input",
        )
    })?;
    let lock = parse_composer_lock(lock_text)?;
    let manifest = parse_composer_manifest(manifest_text)?;
    project(&lock, &manifest, subject)
}

/// Build the purl of a composer package: `pkg:composer/<vendor>/<name>@<version>`
/// with the vendor and the name LOWERCASED.
///
/// The purl specification lowercases the namespace and the name of the
/// `composer` type, and composer itself normalizes package names the same
/// way -- `Acme/Widget` and `acme/widget` are one package, which is
/// already why [`resolve_requirement`] and [`is_platform_requirement`]
/// compare over the lowercased key. Emitting the lockfile's own casing
/// made the purl of the SAME package depend on how the entry happened to
/// be spelled: two documents of one dependency set failing to compare, and
/// a purl that no purl-conformant consumer would match.
///
/// The `version` is NOT touched: the purl specification lowercases the
/// namespace and the name, and Section 3 rule 1 keeps the version verbatim
/// (`v1.2.3` stays `v1.2.3`). `name` and `group` of the component object
/// likewise keep the lockfile's spelling (Section 5.2): what is normalized
/// here is the IDENTITY, not the display.
fn composer_purl(group: &str, name: &str, version: &str) -> Result<String, SbomError> {
    build_namespaced_purl(
        LockfileKind::Composer,
        &group.to_ascii_lowercase(),
        &name.to_ascii_lowercase(),
        version,
    )
}

/// Split `vendor/name` into its two halves.
fn split_vendor_name(full: &str) -> Result<(&str, &str), SbomError> {
    match full.split_once('/') {
        Some((vendor, name)) if !vendor.is_empty() && !name.is_empty() && !name.contains('/') => {
            Ok((vendor, name))
        }
        _ => Err(SbomError::MalformedComponentPurl {
            name: full.to_string(),
            purl: format!("<composer name `{full}` is not `vendor/name`>"),
        }),
    }
}

/// Resolve one requirement key of the manifest to the lockfile entry it
/// names.
///
/// A requirement naming a package the lockfile does not contain is an
/// ERROR: the manifest and the lockfile are then out of step, and a
/// top-level dependency silently dropped is precisely the failure this
/// projection exists to make impossible.
fn resolve_requirement<'a>(
    requirement: &str,
    packages: &'a [ComposerPackage],
) -> Result<&'a ComposerPackage, SbomError> {
    // Composer NORMALIZES package names to lowercase, so `Acme/Widget` in a
    // manifest and `acme/widget` in the lockfile are ONE package. Comparing
    // the two byte for byte made a manifest that composer itself installs
    // fine come out as `UnresolvedDependencyRef` -- a top-level edge lost to
    // a difference the ecosystem does not recognise. The same lowercasing
    // already governs `is_platform_requirement` above.
    let key = requirement.to_ascii_lowercase();
    // Composer resolves at most one version per name, so a second match
    // is a corrupt lockfile rather than an ordinary ambiguity.
    let mut matched = packages
        .iter()
        .filter(|package| package.name.to_ascii_lowercase() == key);
    let first = matched
        .next()
        .ok_or_else(|| SbomError::UnresolvedDependencyRef {
            reference: requirement.to_string(),
        })?;
    let extra = matched.count();
    if extra > 0 {
        return Err(SbomError::AmbiguousDependencyRef {
            reference: requirement.to_string(),
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

    /// Canonical hash of the projection of the frozen synthetic corpus,
    /// PINNED. The fixture never changes, so this constant is what makes
    /// a change of serialization, of ordering or of number encoding
    /// observable. The real lockfiles carry no pin: they change
    /// legitimately.
    const TWO_SCOPES_CANONICAL_SHA256: &str =
        "c5554594b6e232cc74922eec98d15f7738bbe91de6b36d90dae30f5286770bc5";

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sbom")
    }

    fn fixture(name: &str) -> String {
        let path = fixture_dir().join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
    }

    /// The real `composer.lock` and `composer.json` of the PRIVATE
    /// repository, read rather than copied, so a dependency bump cannot
    /// leave a stale copy behind.
    ///
    /// `None` when this run is not in the private tree -- the caller must
    /// return, and the gate has already said so out loud. See
    /// `crate::sbom::private_tree`.
    fn real_pair() -> Option<(String, String)> {
        let root = private_tree()?;
        Some((
            read_private_file(&root, "portal/composer.lock"),
            read_private_file(&root, "portal/composer.json"),
        ))
    }

    fn subject() -> SubjectPurl {
        SubjectPurl::parse("pkg:composer/example-org/example-portal@1.0.0").expect("subject parses")
    }

    fn two_scopes() -> Projection {
        project_lockfile(
            &fixture("composer_two_scopes.lock"),
            Some(&fixture("composer_two_scopes.json")),
            subject(),
        )
        .expect("the two-scopes fixture projects")
    }

    /// INTENT: without the root `composer.json` the projection FAILS. It
    ///   never emits an empty `dependsOn`.
    /// CONTEXT: `composer.lock` does not serialize the root `require` --
    ///   measured on this repository's own lockfile, whose top-level keys
    ///   are `_readme`, `content-hash`, `packages`, `packages-dev`,
    ///   `aliases`, `minimum-stability`, `stability-flags`,
    ///   `prefer-stable`, `prefer-lowest`, `platform`, `platform-dev`,
    ///   `plugin-api-version` and no `require`. An empty `dependsOn` is
    ///   the exact signature of a document that satisfies the shape of
    ///   Annex I Part II (1) while covering nothing.
    /// EXPIRES IF: composer starts serializing the root require inside
    ///   the lockfile, at which point the manifest stops being a second
    ///   mandatory input.
    #[test]
    fn test_intent_composer_top_level_needs_the_manifest() {
        let error = project_lockfile(&fixture("composer_no_manifest.lock"), None, subject())
            .expect_err("a composer projection with no manifest must not succeed");
        assert!(
            matches!(error, SbomError::MalformedManifest { .. }),
            "expected MalformedManifest, got {error:?}"
        );

        // The lockfile alone really does carry no root require: the same
        // bytes project fine the moment a manifest is supplied, so the
        // failure above is about the MISSING INPUT and not about a
        // malformed lockfile.
        let with_manifest = project_lockfile(
            &fixture("composer_no_manifest.lock"),
            Some(&fixture("composer_two_scopes.json")),
            subject(),
        )
        .expect("the same lockfile projects once the manifest is supplied");
        assert!(
            !with_manifest.top_level().is_empty(),
            "the manifest is what makes the top-level set non-empty"
        );

        // And the real lockfile of this repository has no `require` key
        // of its own -- the fact the whole design rests on.
        let Some((lock_text, _)) = real_pair() else {
            return;
        };
        let document: serde_json::Value =
            serde_json::from_str(&lock_text).expect("the real lockfile is JSON");
        assert!(
            document.get("require").is_none(),
            "composer.lock must not be expected to carry the root require"
        );
    }

    /// INTENT: platform requirements (`php`, `php-*`, `ext-*`, `lib-*`,
    ///   `composer*`) are excluded from the top-level set AND COUNTED in
    ///   `seetrex:sbom.platform_requirements_excluded`.
    /// CONTEXT: they are not software components and have no package
    ///   purl -- `pkg:composer/php@^8.3` would name a component that
    ///   exists in no registry, and the version there would be a
    ///   CONSTRAINT rather than a resolved version. This repository's own
    ///   manifest requires `php`.
    /// EXPIRES IF: the purl specification defines a canonical type for
    ///   platform runtimes, at which point they could be emitted honestly.
    #[test]
    fn test_intent_composer_platform_requirements_are_excluded_and_counted() {
        let projection = two_scopes();

        for purl in projection.top_level() {
            assert!(
                !purl.contains("/php@") && !purl.contains("/ext-") && !purl.contains("/lib-"),
                "a platform requirement must not reach the top-level set: {purl}"
            );
        }
        assert_eq!(
            projection.platform_requirements_excluded(),
            Some(3),
            "the fixture requires `php`, `ext-json` and `lib-icu`, and the \
             exclusion must be COUNTED, not mute"
        );

        // The count is visible in the emitted document, not only in the
        // in-memory projection.
        let doc = projection.to_cyclonedx();
        let property = doc["properties"]
            .as_array()
            .expect("properties")
            .iter()
            .find(|p| p["name"] == "seetrex:sbom.platform_requirements_excluded")
            .expect("the platform_requirements_excluded property");
        assert_eq!(property["value"], serde_json::json!("3"));

        // The real manifest of this repository requires `php` and that
        // exclusion is equally visible.
        let Some((lock_text, manifest_text)) = real_pair() else {
            return;
        };
        let real = project_lockfile(&lock_text, Some(&manifest_text), subject())
            .expect("the real pair projects");
        assert!(
            real.platform_requirements_excluded().unwrap_or(0) >= 1,
            "the real manifest requires at least `php`"
        );
    }

    /// INTENT: `packages-dev` entries are scoped `optional` and
    ///   `packages` entries `required`. The document must not claim that
    ///   a test-only package ships in the product.
    /// CONTEXT: composer is the only one of the three ecosystems whose
    ///   LOCKFILE separates the two sets, so the distinction is a
    ///   projection here and would be a guess anywhere else.
    /// EXPIRES IF: composer merges the two arrays.
    #[test]
    fn test_intent_composer_dev_packages_are_scoped_optional() {
        let projection = two_scopes();
        let scope_of = |purl: &str| {
            projection
                .components()
                .iter()
                .find(|c| c.purl == purl)
                .unwrap_or_else(|| panic!("component {purl} is in the projection"))
                .scope
        };
        assert_eq!(
            scope_of("pkg:composer/example-vendor/runtime-lib@1.4.0"),
            Some("required")
        );
        assert_eq!(
            scope_of("pkg:composer/example-vendor/test-lib@3.1.0"),
            Some("optional")
        );

        // Both scopes really are present, so a mutant that marks
        // everything `required` cannot pass by accident.
        let optionals = projection
            .components()
            .iter()
            .filter(|c| c.scope == Some("optional"))
            .count();
        assert_eq!(optionals, 1, "exactly one dev package in the fixture");

        // The real lockfile has both, in quantity.
        let Some((lock_text, manifest_text)) = real_pair() else {
            return;
        };
        let real = project_lockfile(&lock_text, Some(&manifest_text), subject())
            .expect("the real pair projects");
        assert!(
            real.components()
                .iter()
                .any(|c| c.scope == Some("optional")),
            "the real lockfile has development packages"
        );
        assert!(
            real.components()
                .iter()
                .any(|c| c.scope == Some("required")),
            "the real lockfile has runtime packages"
        );
    }

    /// INTENT: the projection of a given pair of inputs is byte-identical
    ///   across repeated runs AND across line-ending conventions.
    /// CONTEXT: this repository normalizes checkouts to LF, so a CRLF
    ///   fixture committed to the tree would be normalized back and the
    ///   test would certify nothing. The CRLF copy is built in memory, at
    ///   test time.
    /// EXPIRES IF: the projection stops being a pure function of its
    ///   input bytes.
    #[test]
    fn test_intent_composer_projection_is_byte_reproducible() {
        let Some((lock_text, manifest_text)) = real_pair() else {
            return;
        };
        let project_once = |lock: &str, manifest: &str| {
            project_lockfile(lock, Some(manifest), subject())
                .expect("the real pair projects")
                .to_canonical_bytes()
                .expect("canonical bytes")
        };

        let first = project_once(&lock_text, &manifest_text);
        let second = project_once(&lock_text, &manifest_text);
        assert_eq!(first, second, "two projections must agree byte for byte");

        let crlf_lock = lock_text.replace('\n', "\r\n");
        let crlf_manifest = manifest_text.replace('\n', "\r\n");
        assert_ne!(
            crlf_lock, lock_text,
            "the in-memory CRLF copy must actually differ"
        );
        let from_crlf = project_once(&crlf_lock, &crlf_manifest);
        assert_eq!(
            first, from_crlf,
            "the line-ending convention of the inputs must not reach the \
             emitted bytes"
        );

        // Invariants of a real lockfile, never a package count: the count
        // changes on every legitimate bump.
        let projection = project_lockfile(&lock_text, Some(&manifest_text), subject())
            .expect("the real pair projects");
        assert!(
            projection.components().len() > 100,
            "the real lockfile projects far more than a handful of \
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
        // Reported, never pinned: the real lockfile changes legitimately.
        println!(
            "composer real projection canonical sha256 = {}",
            projection.canonical_sha256().expect("canonical hash")
        );
    }

    /// The frozen byte-level pin of the synthetic corpus.
    #[test]
    fn composer_fixture_canonical_hash_is_pinned() {
        let bytes = two_scopes().to_canonical_bytes().expect("canonical bytes");
        let mut hasher = Sha256::new();
        hasher.update(bytes.as_bytes());
        assert_eq!(
            format!("{:x}", hasher.finalize()),
            TWO_SCOPES_CANONICAL_SHA256,
            "the canonical bytes of the frozen fixture changed:\n{bytes}"
        );
    }

    /// The purl grammar of the ecosystem: `pkg:composer/<vendor>/<name>`
    /// with the version VERBATIM, including a leading `v` when the
    /// lockfile writes one. Normalizing it would introduce criterion and
    /// stop this being a projection.
    #[test]
    fn composer_purl_carries_vendor_and_the_verbatim_version() {
        let projection = two_scopes();
        let purls: Vec<&str> = projection
            .components()
            .iter()
            .map(|c| c.purl.as_str())
            .collect();
        assert!(purls.contains(&"pkg:composer/example-vendor/runtime-lib@1.4.0"));
        assert!(
            purls.contains(&"pkg:composer/example-vendor/v-prefixed@v2.0.1"),
            "a `v` prefix in the lockfile stays in the purl: {purls:?}"
        );

        let component = projection
            .components()
            .iter()
            .find(|c| c.name == "runtime-lib")
            .expect("the runtime component");
        assert_eq!(component.group.as_deref(), Some("example-vendor"));
        assert_eq!(component.name, "runtime-lib");

        // `group` and `name` are separate fields of the document, and the
        // purl carries both.
        let doc = projection.to_cyclonedx();
        let emitted = doc["components"]
            .as_array()
            .expect("components")
            .iter()
            .find(|c| c["purl"] == "pkg:composer/example-vendor/runtime-lib@1.4.0")
            .expect("the runtime component");
        assert_eq!(emitted["group"], serde_json::json!("example-vendor"));
        assert_eq!(emitted["name"], serde_json::json!("runtime-lib"));
        assert_eq!(emitted["version"], serde_json::json!("1.4.0"));
        assert_eq!(
            emitted["bom-ref"],
            serde_json::json!("pkg:composer/example-vendor/runtime-lib@1.4.0")
        );
    }

    /// The real `composer.lock` of this repository projects with no
    /// digest on any component, and so does the synthetic corpus, whose
    /// `dist.shasum` values are deliberately left in the fixture.
    #[test]
    fn composer_projects_no_digest_at_all() {
        assert!(
            two_scopes().components().iter().all(|c| c.hash.is_none()),
            "a composer component carries no digest"
        );
        let Some((lock_text, manifest_text)) = real_pair() else {
            return;
        };
        let real = project_lockfile(&lock_text, Some(&manifest_text), subject())
            .expect("the real pair projects");
        assert!(
            real.components().iter().all(|c| c.hash.is_none()),
            "the real lockfile contributes no digest either"
        );
    }

    /// A package with no `version` is an error, not a component emitted
    /// without one.
    #[test]
    fn composer_package_without_version_is_fail_loud() {
        let error = project_lockfile(
            &fixture("composer_missing_version.lock"),
            Some(&fixture("composer_two_scopes.json")),
            subject(),
        )
        .expect_err("a package with no version must not project");
        assert!(
            matches!(error, SbomError::MissingVersion { ref name } if name == "example-vendor/no-version"),
            "expected MissingVersion, got {error:?}"
        );
    }

    /// A root requirement naming a package the lockfile does not contain
    /// is an error, not a silently dropped top-level edge.
    #[test]
    fn composer_requirement_absent_from_the_lock_is_fail_loud() {
        let error = project_lockfile(
            &fixture("composer_two_scopes.lock"),
            Some(&fixture("composer_ghost_require.json")),
            subject(),
        )
        .expect_err("a requirement absent from the lockfile must not project");
        assert!(
            matches!(
                error,
                SbomError::UnresolvedDependencyRef { ref reference }
                    if reference == "example-vendor/ghost"
            ),
            "expected UnresolvedDependencyRef, got {error:?}"
        );
    }

    /// INTENT: a root requirement resolves against the lockfile with the
    ///   case folding composer itself applies. `Acme/Widget` in the
    ///   manifest and `acme/widget` in the lockfile are ONE package, and
    ///   the purl emitted is the LOCKFILE's spelling, which is the
    ///   resolved one.
    /// CONTEXT: composer normalizes package names to lowercase -- the same
    ///   fact `is_platform_requirement` already relies on, one screen
    ///   above. Comparing the two byte for byte turned a manifest composer
    ///   installs without complaint into `UnresolvedDependencyRef`, so a
    ///   real top-level edge was lost to a difference the ecosystem does
    ///   not recognise.
    /// EXPIRES IF: composer starts treating package names as
    ///   case-sensitive.
    #[test]
    fn test_intent_composer_requirement_resolution_folds_case() {
        let projection = project_lockfile(
            &fixture("composer_two_scopes.lock"),
            Some(&fixture("composer_mixed_case_require.json")),
            subject(),
        )
        .expect("a manifest spelling its requirements in mixed case projects");

        // Non-vacuity: the fixture really does disagree in case with the
        // lockfile, so a byte-for-byte comparison could not resolve it.
        let manifest = fixture("composer_mixed_case_require.json");
        assert!(
            manifest.contains("Example-Vendor/Runtime-Lib"),
            "the manifest must spell the requirement in mixed case"
        );
        assert!(
            fixture("composer_two_scopes.lock").contains("example-vendor/runtime-lib"),
            "the lockfile must spell the same package in lowercase"
        );

        assert_eq!(
            projection.top_level(),
            [
                "pkg:composer/example-vendor/runtime-lib@1.4.0".to_string(),
                "pkg:composer/example-vendor/test-lib@3.1.0".to_string(),
            ],
            "both requirements resolve, and the purl carries the LOCKFILE \
             spelling: that is the resolved name"
        );
        // The platform predicate folds case the same way, so the mixed-case
        // `PHP` and `Ext-Json` are still excluded and still counted.
        assert_eq!(projection.platform_requirements_excluded(), Some(2));
    }

    /// INTENT: a composer purl carries the vendor and the name
    ///   LOWERCASED, whatever case the lockfile spells them in. The purl
    ///   specification lowercases both segments for the `composer` type,
    ///   and composer itself normalizes package names the same way.
    /// CONTEXT: the case fold existed only on the RESOLUTION side --
    ///   `resolve_requirement` and `is_platform_requirement` compared over
    ///   a lowercased key -- while the emitted purl kept the lockfile's
    ///   spelling. Two documents describing one dependency set therefore
    ///   failed to compare over a difference the ecosystem does not
    ///   recognise, and the purl was one no purl-conformant consumer would
    ///   match.
    /// EXPIRES IF: the purl specification stops lowercasing the composer
    ///   namespace and name.
    /// MUTANT: drop the `to_ascii_lowercase` calls in `composer_purl`.
    #[test]
    fn test_intent_composer_purl_is_lowercased() {
        // The lockfile spells ONE package in mixed case; the manifest
        // requires it in a THIRD spelling. Both sides must land on the
        // same, lowercase, purl.
        let lock = r#"{"packages":[{"name":"Example-Vendor/Runtime-Lib","version":"1.4.0"}],
                       "packages-dev":[]}"#;
        let manifest = r#"{"require":{"EXAMPLE-VENDOR/runtime-lib":"^1.4"}}"#;
        let projection = project_lockfile(lock, Some(manifest), subject())
            .expect("a lockfile spelling a package in mixed case projects");

        assert_eq!(
            projection
                .components()
                .iter()
                .map(|component| component.purl.as_str())
                .collect::<Vec<_>>(),
            ["pkg:composer/example-vendor/runtime-lib@1.4.0"],
            "the vendor and the name are lowercased in the purl"
        );
        assert_eq!(
            projection.top_level(),
            ["pkg:composer/example-vendor/runtime-lib@1.4.0".to_string()],
            "the top-level edge names the SAME purl, or the document dangles"
        );
        // The version is NOT folded: Section 3 rule 1 keeps it verbatim.
        let with_v = r#"{"packages":[{"name":"Example-Vendor/Runtime-Lib","version":"V1.4.0-RC1"}],
                         "packages-dev":[]}"#;
        let projection =
            project_lockfile(with_v, Some(r#"{"require":{}}"#), subject()).expect("projects");
        assert_eq!(
            projection.components()[0].purl,
            "pkg:composer/example-vendor/runtime-lib@V1.4.0-RC1",
            "the version keeps the lockfile's own spelling"
        );
    }

    /// A leading UTF-8 byte-order mark is rejected by an EXPLICIT check on
    /// each of the two inputs, with the error class of the input it was
    /// found in -- a reader has to be able to tell which file was wrong.
    #[test]
    fn composer_inputs_with_a_byte_order_mark_are_fail_loud() {
        let lock_error =
            parse_composer_lock(&format!("\u{feff}{}", fixture("composer_two_scopes.lock")))
                .expect_err("a lockfile with a BOM must not parse");
        assert!(
            matches!(
                lock_error,
                SbomError::UnsupportedLockShape { line: 1, ref detail } if detail == "UTF-8 BOM"
            ),
            "expected the explicit BOM rejection on line 1, got {lock_error:?}"
        );

        let manifest_error =
            parse_composer_manifest(&format!("\u{feff}{}", fixture("composer_two_scopes.json")))
                .expect_err("a manifest with a BOM must not parse");
        assert!(
            matches!(
                manifest_error,
                SbomError::MalformedManifest { ref detail } if detail == "UTF-8 BOM"
            ),
            "expected MalformedManifest naming the BOM, got {manifest_error:?}"
        );
    }

    /// A manifest whose requirements are ALL platform requirements
    /// projects an empty top-level set with the exclusion counted -- the
    /// one case where an empty `dependsOn` is the truth.
    #[test]
    fn composer_platform_only_manifest_projects_an_empty_top_level() {
        let projection = project_lockfile(
            &fixture("composer_two_scopes.lock"),
            Some(&fixture("composer_platform_only.json")),
            subject(),
        )
        .expect("a platform-only manifest projects");
        assert!(projection.top_level().is_empty());
        assert_eq!(projection.platform_requirements_excluded(), Some(4));
    }

    /// The platform-requirement predicate, over the exact set the
    /// decision names.
    #[test]
    fn composer_platform_predicate_covers_the_declared_set() {
        for platform in [
            "php",
            "php-64bit",
            "php-ipv6",
            "ext-json",
            "ext-mbstring",
            "lib-icu",
            "composer-runtime-api",
            "composer-plugin-api",
            "composer",
        ] {
            assert!(
                is_platform_requirement(platform),
                "`{platform}` is a platform requirement"
            );
        }
        for package in [
            "laravel/framework",
            "phpunit/phpunit",
            "example-vendor/php-helper",
            "phpseclib/phpseclib",
        ] {
            assert!(
                !is_platform_requirement(package),
                "`{package}` is a package, not a platform requirement"
            );
        }
    }

    /// A composer name that is not `vendor/name` cannot become a purl.
    #[test]
    fn composer_name_without_a_vendor_is_fail_loud() {
        for bad in ["monolog", "/name", "vendor/", "a/b/c"] {
            assert!(
                split_vendor_name(bad).is_err(),
                "`{bad}` must not split into a vendor and a name"
            );
        }
        assert_eq!(
            split_vendor_name("vendor/name").expect("valid"),
            ("vendor", "name")
        );
    }

    /// The subject is the document's `metadata.component` and is not
    /// repeated inside `components`.
    #[test]
    fn composer_subject_is_metadata_component_and_not_repeated() {
        let projection = two_scopes();
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
            "pkg:composer/example-org/example-portal@1.0.0"
        );
        assert_eq!(
            doc["metadata"]["component"]["bom-ref"],
            "pkg:composer/example-org/example-portal@1.0.0"
        );
        assert_eq!(
            doc["dependencies"][0]["ref"],
            "pkg:composer/example-org/example-portal@1.0.0"
        );
    }

    /// Shapes outside what the parser reads abort the parse instead of
    /// being read best-effort.
    #[test]
    fn composer_shapes_outside_the_subset_are_fail_loud() {
        for (text, what) in [
            ("{", "truncated JSON"),
            ("[]", "a lockfile that is not an object"),
            ("{}", "a lockfile with no `packages`"),
            ("{\"packages\":{}}", "a `packages` that is not an array"),
            ("{\"packages\":[42]}", "a package that is not an object"),
            ("{\"packages\":[{}]}", "a package with no name"),
            (
                "{\"packages\":[{\"name\":\"a/b\",\"version\":1}]}",
                "a non-string version",
            ),
        ] {
            let error =
                parse_composer_lock(text).expect_err(&format!("{what} must abort the parse"));
            assert!(
                matches!(error, SbomError::UnsupportedLockShape { .. }),
                "{what}: expected UnsupportedLockShape, got {error:?}"
            );
        }
        for (text, what) in [
            ("{", "truncated JSON"),
            ("[]", "a manifest that is not an object"),
            ("{\"require\":[]}", "a `require` that is not an object"),
        ] {
            let error =
                parse_composer_manifest(text).expect_err(&format!("{what} must abort the parse"));
            assert!(
                matches!(error, SbomError::MalformedManifest { .. }),
                "{what}: expected MalformedManifest, got {error:?}"
            );
        }
    }
}
