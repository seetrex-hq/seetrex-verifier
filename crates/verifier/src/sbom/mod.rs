// SPDX-License-Identifier: Apache-2.0
//! `sbom` -- the canonical SBOM projection: lockfile -> CycloneDX.
//!
//! A SBOM emitted by this module is a PURE PROJECTION of a dependency
//! lockfile. It carries no clock, no random identifier and no ambient
//! state, so the same lockfile always yields the same bytes: an auditor
//! who holds the public lockfile re-derives the published document and
//! compares it byte for byte, with no trust in the producer.
//!
//! The three properties that make that possible, all enforced by tests
//! in this file:
//!
//! 1. **No volatile fields.** No `serialNumber`, no `metadata.timestamp`.
//!    Either one would make two emissions of the same lockfile differ.
//! 2. **Total order and content identity.** The identity of a component
//!    is its `purl` -- never its name, because one lockfile routinely
//!    resolves several versions of the same name. `components` is sorted
//!    ascending by `purl` compared as UTF-8 bytes, and the `purl` carries
//!    the version, so no two entries tie.
//! 3. **Canonical bytes.** The emitted file IS the JCS (RFC 8785) form of
//!    the document, on ONE line, with no trailing newline, produced by the
//!    same platform primitive that hashes verdicts and evidence
//!    (`seetrex_format::hashing`). The derived property is checkable with
//!    stock coreutils: `sha256sum <file>` equals the canonical hash of the
//!    document.
//!
//! The dependency graph is deliberately shallow: one entry, the subject,
//! listing the top-level dependencies. That is the literal minimum the
//! regulation asks for, and it is the deepest graph that stays a pure
//! projection across every lockfile format (some record constraints, not
//! resolved edges, for anything below the root).
//!
//! The subject is an INPUT (`SubjectPurl`), never read back out of a
//! document under test: a document must not be allowed to name its own
//! subject, exactly as an anchor package must not name its own witnesses.

pub mod cargo;
pub mod compare;
pub mod composer;
pub mod depv0;
pub mod npm;

/// The one route from a test of this crate to a file outside it. Test-only
/// by construction, and the SAME file the integration tests pull in with
/// `#[path = "../src/sbom/private_tree.rs"]` -- one gate, one behaviour.
#[cfg(test)]
pub(crate) mod private_tree;

use serde_json::{json, Map, Value};

use seetrex_format::hashing::{canonical_hash, canonicalize, CanonicalizationError};

/// CycloneDX specification version emitted by the projection.
///
/// `1.5` and not `1.6`: the two SBOM producers that already exist in the
/// platform emit 1.5, the ingest normalizer passes `specVersion` through
/// untouched, and both `dependencies` and `properties` exist in 1.5. A
/// second spec version in the same evidence chain would buy nothing.
pub const SPEC_VERSION: &str = "1.5";

/// `bomFormat` -- the only value CycloneDX defines.
pub const BOM_FORMAT: &str = "CycloneDX";

/// `version` of the BOM document itself. Pinned to 1: a BOM revision
/// counter is state, and this projection has none.
pub const BOM_VERSION: u64 = 1;

/// Value of the `seetrex:sbom.projection` property -- the identifier of
/// THIS projection algorithm. Bump it if the projection changes shape, so
/// an old document stays readable as what it was.
pub const PROJECTION_ID: &str = "lockfile-v1";

/// Property name prefix of the self-description properties.
const PROPERTY_PREFIX: &str = "seetrex:sbom.";

/// Characters allowed unescaped in the name and version segments of a
/// purl built by this module. Anything outside the set is a fail-loud
/// error rather than an invented percent-encoding: a projection does not
/// transform its input.
fn is_purl_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+')
}

/// The purl types this projection produces, and therefore the only ones a
/// subject may name. A subject of another type would describe an artifact
/// no lockfile of this module can project.
const PURL_TYPES: [&str; 3] = ["cargo", "composer", "npm"];

/// One segment of a purl path, or a version: at least one character, all
/// of them purl token characters, never a relative-path name, and never
/// the reserved token of specification 7.7.
///
/// This is the SAME grammar [`build_purl`] enforces on the way in, so a
/// subject an auditor types and a component this module builds are held
/// to one rule rather than to two that can drift.
///
/// The reserved-token half is asked of [`crate::package::is_reserved_token`]
/// and of nothing else in this module. It used to be a local `const` and a
/// case-SENSITIVE `contains`, while the sanitizer that redacts the same
/// token at every output boundary matched case-INSENSITIVELY: `VeRiFiEd`
/// was therefore a legal component name AND a masked one, so a difference
/// report could print two distinct purls as one identical string.
fn is_purl_token(token: &str) -> bool {
    !token.is_empty()
        && token != "."
        && token != ".."
        && token.chars().all(is_purl_token_char)
        && !crate::package::is_reserved_token(token)
}

/// An npm scope segment: `%40` followed by a purl token. `%40` is the ONE
/// escape this grammar admits, and only here -- the purl specification
/// percent-encodes the `@` that introduces a scope, and nothing else in
/// these ecosystems needs an escape at all.
fn is_npm_scope_segment(segment: &str) -> bool {
    segment.strip_prefix("%40").is_some_and(is_purl_token)
}

/// Replace the reserved token before a rejected value travels back out
/// inside an error message (specification 7.7: sanitise at the output
/// boundary). Without this, refusing `pkg:cargo/VERIFIED@1.0.0` would
/// print the very substring downstream tooling reads as a strong pass.
///
/// It delegates to [`crate::package::sanitize_reserved_token`] so that ONE
/// mask ([`crate::package::RESERVED_TOKEN_MASK`]) reaches a reader, and
/// the one legend that explains it is therefore true of every masked line.
/// This module used to render a third mask of its own,
/// `<reserved token>`, which no legend pointed at.
fn redact_reserved(value: &str) -> String {
    crate::package::sanitize_reserved_token(value)
}

/// The `detail` every parser of this module reports for a leading UTF-8
/// byte-order mark, so the three ecosystems answer with ONE sentence and a
/// caller can recognise the case without matching three spellings.
pub(crate) const BOM_DETAIL: &str = "UTF-8 BOM";

/// True when `text` begins with a UTF-8 byte-order mark.
///
/// Every parser calls this FIRST (specification 8, obligation 3). The
/// rejection used to be incidental -- the BOM happened to break whatever
/// rule the parser applied next -- so an implementation that merely
/// stripped it would have passed the same tests, and a first package
/// silently named `\u{feff}serde` is a document that looks complete and
/// names a package that exists nowhere.
pub(crate) fn starts_with_byte_order_mark(text: &str) -> bool {
    text.starts_with('\u{feff}')
}

/// Errors of the projection. Every one of them is fail-loud: a lockfile
/// this module cannot read completely produces an error, never a
/// silently incomplete SBOM. An incomplete SBOM that looks complete is
/// the worst failure mode available here.
#[derive(Debug, thiserror::Error)]
pub enum SbomError {
    /// The lockfile uses a construct outside the declared subset.
    #[error("unsupported lockfile shape at line {line}: {detail}")]
    UnsupportedLockShape {
        /// 1-based line number of the offending line.
        line: usize,
        /// What was expected there.
        detail: String,
    },
    /// A lockfile entry carries no resolvable version. A lockfile is by
    /// definition already resolved, so this means a corrupt file or a
    /// broken parser -- never a component that legitimately has no
    /// version.
    #[error("package `{name}` carries no resolvable version in the lockfile")]
    MissingVersion {
        /// Name of the package as the lockfile spells it.
        name: String,
    },
    /// Two lockfile entries produced the same purl with substantively
    /// different payloads. The purl IS the reference of the component,
    /// so collapsing them would emit a document with two components
    /// under one reference.
    #[error("purl collision: `{purl}` names two substantively different components")]
    PurlCollision {
        /// The colliding purl.
        purl: String,
    },
    /// A component carries a purl this module cannot have produced.
    #[error("component `{name}` carries a malformed purl `{purl}`")]
    MalformedComponentPurl {
        /// Name of the component.
        name: String,
        /// The malformed purl.
        purl: String,
    },
    /// The root manifest that a lockfile needs as a second input is
    /// missing or unreadable.
    #[error("malformed manifest: {detail}")]
    MalformedManifest {
        /// What was expected.
        detail: String,
    },
    /// The subject purl supplied by the auditor is not a purl.
    #[error("malformed subject purl `{subject}`: {detail}")]
    MalformedSubject {
        /// The value as supplied.
        subject: String,
        /// What was expected.
        detail: String,
    },
    /// A dependency reference matched more than one lockfile entry.
    /// Guessing (for instance, taking the highest version) would put a
    /// component in the SBOM that the lockfile does not name.
    #[error(
        "ambiguous dependency reference `{reference}`: {count} lockfile entries carry that name"
    )]
    AmbiguousDependencyRef {
        /// The reference as the lockfile spells it.
        reference: String,
        /// How many entries matched.
        count: usize,
    },
    /// A dependency reference matched no lockfile entry at all.
    #[error("unresolved dependency reference `{reference}`: no lockfile entry matches it")]
    UnresolvedDependencyRef {
        /// The reference as the lockfile spells it.
        reference: String,
    },
    /// JCS canonicalization of the document failed.
    #[error("canonicalization of the SBOM document failed")]
    Canonicalization(#[from] CanonicalizationError),
    /// Reading an input file failed.
    #[error("cannot read {path}: {detail}")]
    Io {
        /// Path that could not be read.
        path: String,
        /// The underlying reason.
        detail: String,
    },
}

/// The lockfile ecosystems the projection understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockfileKind {
    /// `Cargo.lock`.
    Cargo,
    /// `composer.lock` (plus its `composer.json` root manifest).
    Composer,
    /// `package-lock.json`.
    Npm,
}

impl LockfileKind {
    /// The value emitted in `seetrex:sbom.lockfile_kind`, which is also
    /// the purl type of every component of that ecosystem.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Composer => "composer",
            Self::Npm => "npm",
        }
    }
}

/// A validated subject purl.
///
/// The subject is an input of the AUDITOR, not a field read back out of
/// the document under test, so it is parsed and validated once, here,
/// and the parsed halves are kept. That makes "the subject is a purl" a
/// structural fact of the type rather than a check somebody must
/// remember to run before emitting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectPurl {
    purl: String,
    name: String,
    version: String,
}

impl SubjectPurl {
    /// Parse `pkg:<type>/<namespace...>/<name>@<version>`.
    ///
    /// The subject is validated against the SAME grammar this module
    /// BUILDS component purls with: the type is one of the three
    /// ecosystems, every path segment and the version are purl tokens,
    /// and the one escape admitted anywhere is the `%40` of an npm scope.
    /// A looser reading here would let an auditor-supplied string carrying
    /// a space, an unencoded `@`, a `../`, a JSON metacharacter or the
    /// reserved token of 7.7 reach `metadata.component`, `dependencies[].ref`
    /// and every error message that quotes them -- inside a document whose
    /// whole value is that a stranger can re-derive it.
    ///
    /// Only the two halves the document needs are extracted: the name and
    /// the version. The namespace, when there is one, stays inside the
    /// purl string; decoding it back into a `group` would be a
    /// transformation, and this module does not transform its input.
    pub fn parse(subject: &str) -> Result<Self, SbomError> {
        let malformed = |detail: &str| SbomError::MalformedSubject {
            subject: redact_reserved(subject),
            detail: detail.to_string(),
        };
        let body = subject
            .strip_prefix("pkg:")
            .ok_or_else(|| malformed("expected the `pkg:` scheme"))?;
        let (path, version) = body
            .rsplit_once('@')
            .ok_or_else(|| malformed("expected a `@<version>` suffix"))?;
        if !is_purl_token(version) {
            return Err(malformed(
                "the version must be a non-empty purl token: ASCII letters, \
                 digits, `.`, `_`, `-` and `+`",
            ));
        }
        let mut segments = path.split('/');
        let kind = segments.next().unwrap_or_default();
        if !PURL_TYPES.contains(&kind) {
            return Err(malformed(
                "the purl type must be one of `cargo`, `composer`, `npm`",
            ));
        }
        let path_segments: Vec<&str> = segments.collect();
        let name = match (kind, path_segments.as_slice()) {
            // cargo has a flat namespace; composer's is the mandatory
            // vendor; an npm package is either bare or `%40scope/name`.
            ("cargo", [name]) => name,
            ("composer", [vendor, name]) if is_purl_token(vendor) => name,
            ("npm", [name]) => name,
            ("npm", [scope, name]) if is_npm_scope_segment(scope) => name,
            _ => {
                return Err(malformed(
                    "expected `pkg:cargo/<name>`, `pkg:composer/<vendor>/<name>`, \
                     `pkg:npm/<name>` or `pkg:npm/%40<scope>/<name>` before the version",
                ))
            }
        };
        if !is_purl_token(name) {
            return Err(malformed(
                "the name must be a non-empty purl token: ASCII letters, digits, \
                 `.`, `_`, `-` and `+`",
            ));
        }
        Ok(Self {
            purl: subject.to_string(),
            name: name.to_string(),
            version: version.to_string(),
        })
    }

    /// The purl, verbatim as the auditor supplied it.
    pub fn as_str(&self) -> &str {
        &self.purl
    }

    /// The name segment.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The version segment.
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// The ONE digest algorithm this projection is allowed to name.
///
/// Only cargo contributes a digest: `checksum` is already a
/// lowercase-hex SHA-256 of the crate file and is copied verbatim.
/// Composer `dist.shasum` and npm `integrity` are DISCARDED, so no other
/// label can ever be true of an emitted digest, and the enum carries no
/// other variant -- re-adding one is the visible cost of re-opening that
/// decision.
///
/// The label is emitted verbatim into `hashes[].alg`, so it has to be
/// the CycloneDX spelling and it has to be TRUE of the content beside
/// it: a digest of the wrong length under a `SHA-256` label is a false
/// statement inside the document, not a formatting detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    /// 256-bit SHA-2 -- cargo `checksum`.
    Sha256,
}

impl HashAlg {
    /// The CycloneDX `hashes[].alg` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
        }
    }

    /// Length of the digest written as lowercase hex.
    pub fn hex_len(self) -> usize {
        match self {
            Self::Sha256 => 64,
        }
    }
}

/// One `hashes[]` entry: an algorithm label and the lowercase-hex digest
/// it is true of.
///
/// The only constructor validates the pair, so "the label matches the
/// content" is a structural fact of the type rather than a check the
/// producing module has to remember to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentHash {
    alg: HashAlg,
    content: String,
}

impl ComponentHash {
    /// Validate a digest against the algorithm it claims to be.
    ///
    /// Lowercase hex of exactly the right length, or an error: uppercase
    /// hex would still be the same digest but not the same BYTES, and
    /// these bytes are the artifact.
    pub fn checked(alg: HashAlg, content: &str, name: &str) -> Result<Self, SbomError> {
        let valid = content.len() == alg.hex_len()
            && content
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
        if !valid {
            return Err(SbomError::UnsupportedLockShape {
                line: 0,
                detail: format!(
                    "package `{name}` carries a digest that is not {} lowercase hex \
                     characters for {}",
                    alg.hex_len(),
                    alg.as_str()
                ),
            });
        }
        Ok(Self {
            alg,
            content: content.to_string(),
        })
    }

    /// The algorithm.
    pub fn alg(&self) -> HashAlg {
        self.alg
    }

    /// The lowercase-hex digest.
    pub fn content(&self) -> &str {
        &self.content
    }
}

/// One component of the projection.
///
/// The field set is deliberately narrow: identity only. Provenance
/// fields (`author`, `publisher`, `supplier`, `externalReferences`,
/// `description`) are NOT projected -- they carry personal data and are
/// not identity -- and neither are `cpe`/`swid`, which no lockfile
/// records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    /// The identity: `pkg:<type>/<name>@<version>`. Also the reference
    /// under which the dependency graph names this component.
    pub purl: String,
    /// CycloneDX component type. `"library"` for everything a lockfile
    /// resolves.
    pub type_: &'static str,
    /// Package name as the lockfile spells it.
    pub name: String,
    /// Namespace of the package (composer vendor, npm scope). Absent for
    /// ecosystems with a flat namespace.
    pub group: Option<String>,
    /// Version, verbatim from the lockfile.
    pub version: String,
    /// `"required"` or `"optional"`, when the lockfile distinguishes
    /// runtime from development. Absent when it does not.
    pub scope: Option<&'static str>,
    /// Digest of the distributed artifact. Present ONLY on a cargo
    /// component whose lockfile entry records a `checksum`; composer and
    /// npm contribute none, so `hashes` is absent from every component
    /// of their documents.
    pub hash: Option<ComponentHash>,
}

impl Component {
    /// A library component with no namespace, no scope and no hash -- the
    /// shape of an ecosystem whose lockfile records neither.
    pub fn library(purl: String, name: String, version: String) -> Self {
        Self {
            purl,
            type_: "library",
            name,
            group: None,
            version,
            scope: None,
            hash: None,
        }
    }

    fn to_json(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("type".to_string(), json!(self.type_));
        obj.insert("name".to_string(), json!(self.name));
        if let Some(group) = &self.group {
            obj.insert("group".to_string(), json!(group));
        }
        obj.insert("version".to_string(), json!(self.version));
        obj.insert("purl".to_string(), json!(self.purl));
        // `bom-ref` is EXPLICIT and equal to the purl. CycloneDX resolves
        // `dependencies[].ref` against declared `bom-ref` values, so a
        // document whose graph names a component that declares none is
        // not valid under the 1.5 schema. Emitting the purl there costs
        // nothing -- it is already the identity -- and keeps the
        // reference deterministic, which is exactly the property the
        // ingest normalizer names as its blocker for re-adding the graph.
        obj.insert("bom-ref".to_string(), json!(self.purl));
        if let Some(scope) = self.scope {
            obj.insert("scope".to_string(), json!(scope));
        }
        if let Some(hash) = &self.hash {
            obj.insert(
                "hashes".to_string(),
                json!([{ "alg": hash.alg().as_str(), "content": hash.content() }]),
            );
        }
        Value::Object(obj)
    }
}

/// The non-load-bearing counters an ecosystem contributes to the
/// document, each one making an EXCLUSION visible instead of mute.
///
/// They travel in one struct rather than as a row of `Option<usize>`
/// parameters: two adjacent optional counts of the same type are a
/// silent swap waiting to happen, and a swapped count is a false
/// statement inside the document.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProjectionCounters {
    /// Composer: how many PLATFORM requirements (`php`, `ext-*`, ...)
    /// were left out of the top-level set because they are not software
    /// components. `None` for the ecosystems that have no such concept.
    pub platform_requirements_excluded: Option<usize>,
    /// npm: how many `link: true` entries were omitted from the
    /// components because they point at another place in the tree rather
    /// than at an installed package. `None` for the ecosystems whose
    /// lockfiles cannot carry one.
    pub links_omitted: Option<usize>,
}

/// A lockfile projected into the shape a CycloneDX document needs.
///
/// The invariants of the projection -- components sorted by purl,
/// deduplicated, every version present, every purl well formed -- are
/// established once in [`Projection::new`] and then held structurally:
/// the collections are private, so no caller can reorder or extend them
/// behind the emitter's back.
#[derive(Debug, Clone)]
pub struct Projection {
    kind: LockfileKind,
    subject: SubjectPurl,
    components: Vec<Component>,
    top_level: Vec<String>,
    top_level_basis: &'static str,
    counters: ProjectionCounters,
}

impl Projection {
    /// Validate, sort and deduplicate a projection.
    ///
    /// `top_level_basis` is a short, stable token naming HOW the
    /// top-level set was derived, so the limitation of that derivation
    /// travels inside the artifact instead of in prose beside it.
    pub fn new(
        kind: LockfileKind,
        subject: SubjectPurl,
        components: Vec<Component>,
        top_level: Vec<String>,
        top_level_basis: &'static str,
        counters: ProjectionCounters,
    ) -> Result<Self, SbomError> {
        for component in &components {
            if component.version.is_empty() {
                return Err(SbomError::MissingVersion {
                    name: component.name.clone(),
                });
            }
            if !is_projected_purl(&component.purl) {
                return Err(SbomError::MalformedComponentPurl {
                    name: component.name.clone(),
                    purl: component.purl.clone(),
                });
            }
        }

        let mut components = components;
        // Byte-wise ordering of the UTF-8 purl. `str::cmp` is exactly
        // that; a locale collation would order differently on a
        // different machine and the bytes would stop being reproducible.
        components.sort_by(|a, b| a.purl.cmp(&b.purl));

        let mut deduplicated: Vec<Component> = Vec::with_capacity(components.len());
        for component in components {
            match deduplicated.last() {
                // Same purl AND the same payload: the same component
                // reached twice. Collapse.
                Some(previous) if previous.purl == component.purl && *previous == component => {
                    continue
                }
                // Same purl, different payload: two different components
                // under one reference. Fail loud.
                Some(previous) if previous.purl == component.purl => {
                    return Err(SbomError::PurlCollision {
                        purl: component.purl,
                    })
                }
                _ => deduplicated.push(component),
            }
        }

        let mut top_level = top_level;
        top_level.sort();
        top_level.dedup();

        Ok(Self {
            kind,
            subject,
            components: deduplicated,
            top_level,
            top_level_basis,
            counters,
        })
    }

    /// The ecosystem this projection came from.
    pub fn kind(&self) -> LockfileKind {
        self.kind
    }

    /// The subject the auditor named.
    pub fn subject(&self) -> &SubjectPurl {
        &self.subject
    }

    /// The components, sorted by purl and deduplicated.
    pub fn components(&self) -> &[Component] {
        &self.components
    }

    /// The top-level dependency purls, sorted.
    pub fn top_level(&self) -> &[String] {
        &self.top_level
    }

    /// The token describing how the top-level set was derived.
    pub fn top_level_basis(&self) -> &'static str {
        self.top_level_basis
    }

    /// The counters this projection contributes to the document.
    pub fn counters(&self) -> ProjectionCounters {
        self.counters
    }

    /// How many platform requirements were excluded from the top-level
    /// set, for the ecosystems that have them.
    pub fn platform_requirements_excluded(&self) -> Option<usize> {
        self.counters.platform_requirements_excluded
    }

    /// How many linked entries were omitted from the components, for the
    /// ecosystems whose lockfiles can carry one.
    pub fn links_omitted(&self) -> Option<usize> {
        self.counters.links_omitted
    }

    /// The CycloneDX document.
    ///
    /// Key insertion order is irrelevant -- JCS sorts keys -- but the
    /// order below is the order a reader expects.
    pub fn to_cyclonedx(&self) -> Value {
        let mut doc = Map::new();
        doc.insert("bomFormat".to_string(), json!(BOM_FORMAT));
        doc.insert("specVersion".to_string(), json!(SPEC_VERSION));
        doc.insert("version".to_string(), json!(BOM_VERSION));
        // No `serialNumber` and no `metadata.timestamp`: both are
        // volatile, and either one alone would make two emissions of the
        // same lockfile differ.
        doc.insert(
            "metadata".to_string(),
            json!({
                "component": {
                    "type": "application",
                    "name": self.subject.name(),
                    "version": self.subject.version(),
                    "purl": self.subject.as_str(),
                    // The single `dependencies[].ref` of the graph is the
                    // subject's purl, so the subject has to DECLARE that
                    // bom-ref for the reference to resolve.
                    "bom-ref": self.subject.as_str(),
                }
            }),
        );
        doc.insert(
            "components".to_string(),
            Value::Array(self.components.iter().map(Component::to_json).collect()),
        );
        // Depth 1: the subject and its top-level dependencies. The
        // components do not declare edges of their own.
        doc.insert(
            "dependencies".to_string(),
            json!([{ "ref": self.subject.as_str(), "dependsOn": self.top_level }]),
        );
        doc.insert("properties".to_string(), Value::Array(self.properties()));
        Value::Object(doc)
    }

    /// The self-description properties, at BOM level and sorted by name.
    ///
    /// None of them is load-bearing. The regulatory signal -- the
    /// top-level set -- lives in the STANDARD `dependencies` field, not
    /// here: the ingest normalizer keeps a whitelist of substantive
    /// component fields that `properties` is not part of, so a signal
    /// hidden in a property would not survive ingestion.
    fn properties(&self) -> Vec<Value> {
        let mut properties = vec![
            (
                format!("{PROPERTY_PREFIX}projection"),
                PROJECTION_ID.to_string(),
            ),
            (
                format!("{PROPERTY_PREFIX}lockfile_kind"),
                self.kind.as_str().to_string(),
            ),
            (
                format!("{PROPERTY_PREFIX}top_level_basis"),
                self.top_level_basis.to_string(),
            ),
        ];
        // Decimal strings with no leading zeros -- `usize::to_string` is
        // exactly that -- and PRESENT only for the ecosystem that has the
        // concept: an absent counter says "this lockfile cannot carry
        // one", which a `"0"` would not.
        if let Some(excluded) = self.counters.platform_requirements_excluded {
            properties.push((
                format!("{PROPERTY_PREFIX}platform_requirements_excluded"),
                excluded.to_string(),
            ));
        }
        if let Some(omitted) = self.counters.links_omitted {
            properties.push((
                format!("{PROPERTY_PREFIX}links_omitted"),
                omitted.to_string(),
            ));
        }
        properties.sort_by(|a, b| a.0.cmp(&b.0));
        properties
            .into_iter()
            .map(|(name, value)| json!({ "name": name, "value": value }))
            .collect()
    }

    /// The canonical bytes of the document: JCS RFC 8785, ONE line, no
    /// trailing newline, UTF-8 without BOM.
    ///
    /// These bytes ARE the file. The derived property an auditor checks
    /// with stock tooling is
    /// `sha256sum <file> == Projection::canonical_sha256`.
    pub fn to_canonical_bytes(&self) -> Result<String, SbomError> {
        Ok(canonicalize(&self.to_cyclonedx())?)
    }

    /// Lowercase-hex SHA-256 of the canonical bytes.
    pub fn canonical_sha256(&self) -> Result<String, SbomError> {
        Ok(canonical_hash(&self.to_cyclonedx())?)
    }
}

/// True if `purl` has the shape this module produces, which is EXACTLY
/// the grammar [`SubjectPurl::parse`] accepts: `pkg:<type>/...@<version>`
/// with the type one of `cargo`, `composer`, `npm`, the segment count of
/// that type (flat, `<vendor>/<name>`, or an optional `%40<scope>`), and
/// every segment and the version a purl token.
///
/// It is deliberately the same function and not a second reading of the
/// same rule: a component and a subject end up in the same reference
/// space of the same document, so a grammar that admitted one and not the
/// other would let the graph name something the components cannot.
fn is_projected_purl(purl: &str) -> bool {
    SubjectPurl::parse(purl).is_ok()
}

/// Build `pkg:<kind>/<name>@<version>`, rejecting anything that would
/// need an invented encoding.
pub(crate) fn build_purl(
    kind: LockfileKind,
    name: &str,
    version: &str,
) -> Result<String, SbomError> {
    for (token, what) in [(name, "name"), (version, "version")] {
        if !is_purl_token(token) {
            return Err(SbomError::MalformedComponentPurl {
                name: redact_reserved(name),
                purl: format!("<{what} `{}` is not a purl token>", redact_reserved(token)),
            });
        }
    }
    Ok(format!("pkg:{}/{name}@{version}", kind.as_str()))
}

/// Build `pkg:<kind>/<namespace>/<name>@<version>`.
///
/// `namespace` is already in its PURL-ENCODED form -- the encoding rule
/// belongs to the ecosystem (npm percent-encodes the `@` of a scope,
/// composer's vendor needs no encoding), and this function only checks
/// that what it was handed is a legal namespace segment: purl tokens
/// plus `%XX` escapes, nothing invented here.
pub(crate) fn build_namespaced_purl(
    kind: LockfileKind,
    namespace: &str,
    name: &str,
    version: &str,
) -> Result<String, SbomError> {
    if !is_purl_namespace(namespace) {
        return Err(SbomError::MalformedComponentPurl {
            name: name.to_string(),
            purl: format!("<namespace `{namespace}` is not a purl namespace segment>"),
        });
    }
    let prefix = format!("pkg:{}/", kind.as_str());
    let flat = build_purl(kind, name, version)?;
    let body = flat.strip_prefix(&prefix).unwrap_or(&flat);
    Ok(format!("{prefix}{namespace}/{body}"))
}

/// A purl namespace segment: purl tokens plus `%XX` percent-escapes.
fn is_purl_namespace(namespace: &str) -> bool {
    if namespace.is_empty() {
        return false;
    }
    let bytes = namespace.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            match bytes.get(index + 1..index + 3) {
                Some(pair) if pair.iter().all(u8::is_ascii_hexdigit) => index += 3,
                _ => return false,
            }
        } else if is_purl_token_char(byte as char) {
            index += 1;
        } else {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn subject() -> SubjectPurl {
        SubjectPurl::parse("pkg:cargo/example-app@1.2.3").expect("subject parses")
    }

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sbom")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
    }

    /// Does any object anywhere under `value` carry a `hashes` key?
    fn mentions_hashes(value: &Value) -> bool {
        match value {
            Value::Object(map) => map.contains_key("hashes") || map.values().any(mentions_hashes),
            Value::Array(items) => items.iter().any(mentions_hashes),
            _ => false,
        }
    }

    fn component(name: &str, version: &str) -> Component {
        Component::library(
            format!("pkg:cargo/{name}@{version}"),
            name.to_string(),
            version.to_string(),
        )
    }

    fn projection(components: Vec<Component>, top_level: Vec<String>) -> Projection {
        Projection::new(
            LockfileKind::Cargo,
            subject(),
            components,
            top_level,
            "test-basis",
            ProjectionCounters::default(),
        )
        .expect("projection is valid")
    }

    /// INTENT: the canonical SBOM carries no `serialNumber` and no
    ///   `metadata.timestamp`. Without that, two emissions of the same
    ///   lockfile produce different bytes and different hashes, and the
    ///   whole claim -- that an auditor re-derives the published document
    ///   from the public lockfile -- is false by construction.
    /// CONTEXT: the same discipline the platform's other CycloneDX
    ///   producer already pins, and the reason the ingest normalizer
    ///   drops `serialNumber` before hashing evidence.
    /// EXPIRES IF: a content-derived `serialNumber` is adopted (today
    ///   rejected as circular: the identifier would be part of the very
    ///   document whose hash defines it).
    #[test]
    fn test_intent_sbom_canonical_omits_volatile_fields() {
        let doc = projection(vec![component("alpha", "1.0.0")], vec![]).to_cyclonedx();
        let object = doc.as_object().expect("document is an object");

        assert!(
            !object.contains_key("serialNumber"),
            "the canonical SBOM must not carry a serialNumber; got {doc}"
        );
        let metadata = object
            .get("metadata")
            .and_then(Value::as_object)
            .expect("metadata is an object");
        assert!(
            !metadata.contains_key("timestamp"),
            "the canonical SBOM must not carry metadata.timestamp; got {doc}"
        );

        // The observable consequence: two emissions are byte-identical.
        let once = projection(vec![component("alpha", "1.0.0")], vec![])
            .to_canonical_bytes()
            .expect("canonical bytes");
        let twice = projection(vec![component("alpha", "1.0.0")], vec![])
            .to_canonical_bytes()
            .expect("canonical bytes");
        assert_eq!(once, twice, "two emissions of one projection must agree");
    }

    /// INTENT: `components` is ordered ascending by purl compared as
    ///   UTF-8 bytes, and that order is TOTAL -- the purl carries the
    ///   version, so two entries never tie.
    /// CONTEXT: a real lockfile resolves several versions of the same
    ///   name (this repository's own resolves 31 such names). Ordering by
    ///   name leaves ties, and a tie makes the emitted order depend on
    ///   the order the entries were read in, which is not a property of
    ///   the lockfile.
    /// EXPIRES IF: the identity of a component stops being the purl.
    #[test]
    fn test_intent_sbom_component_order_is_total_over_purl() {
        // Deliberately adversarial input: fed in an order where sorting
        // by NAME and sorting by PURL disagree, and where two entries
        // tie on name.
        let projection = projection(
            vec![
                component("beta", "1.0.0"),
                component("alpha", "2.0.0"),
                component("alpha", "10.0.0"),
            ],
            vec![],
        );
        let purls: Vec<&str> = projection
            .components()
            .iter()
            .map(|c| c.purl.as_str())
            .collect();
        assert_eq!(
            purls,
            vec![
                "pkg:cargo/alpha@10.0.0",
                "pkg:cargo/alpha@2.0.0",
                "pkg:cargo/beta@1.0.0",
            ],
            "components must be sorted ascending by purl as UTF-8 bytes \
             (byte order, not numeric and not locale collation)"
        );

        // Totality: consecutive purls are strictly increasing, so no two
        // entries tie and the order cannot depend on input order.
        for pair in purls.windows(2) {
            assert!(
                pair[0] < pair[1],
                "the order over purls must be strict: `{}` !< `{}`",
                pair[0],
                pair[1]
            );
        }

        // The same set fed in a different order emits the same bytes.
        let shuffled = projection_bytes(vec![
            component("alpha", "10.0.0"),
            component("beta", "1.0.0"),
            component("alpha", "2.0.0"),
        ]);
        assert_eq!(
            shuffled,
            projection.to_canonical_bytes().expect("canonical bytes"),
            "the emitted bytes must not depend on the order the components \
             were read in"
        );
    }

    fn projection_bytes(components: Vec<Component>) -> String {
        projection(components, vec![])
            .to_canonical_bytes()
            .expect("canonical bytes")
    }

    /// INTENT: deduplication is by exact purl, never by name. Two
    ///   versions of one package are TWO components.
    /// CONTEXT: the platform's other CycloneDX producer once collapsed
    ///   two versions of one dependency into a single component, and
    ///   that silent collapse is recorded there as a fixed bug. The purl
    ///   carries the version precisely so it cannot happen again.
    /// EXPIRES IF: the purl stops carrying the version.
    #[test]
    fn test_intent_sbom_dedup_is_by_purl_not_name() {
        let projection = projection(
            vec![
                component("alpha", "1.0.0"),
                component("alpha", "2.0.0"),
                // An exact repeat: same purl, same payload. This one IS
                // one component, and collapsing it is correct.
                component("alpha", "2.0.0"),
            ],
            vec![],
        );
        assert_eq!(
            projection.components().len(),
            2,
            "two versions of one name are two components, and an exact \
             repeat of one of them is not a third"
        );
        let versions: Vec<&str> = projection
            .components()
            .iter()
            .map(|c| c.version.as_str())
            .collect();
        assert_eq!(versions, vec!["1.0.0", "2.0.0"]);
    }

    /// INTENT: the bytes of the emitted file ARE the JCS RFC 8785
    ///   canonical form of the document: one line, no trailing newline,
    ///   and `sha256(bytes) == canonical_hash(document)`.
    /// CONTEXT: that identity is what lets an auditor check the
    ///   published SBOM against its own hash with stock `sha256sum`,
    ///   with none of our tooling installed.
    /// EXPIRES IF: the platform changes its canonicalization primitive
    ///   (today the shared JCS primitive of the format layer, the same
    ///   one that hashes verdicts and evidence).
    #[test]
    fn test_intent_sbom_bytes_are_jcs_single_line() {
        let projection = projection(
            vec![component("alpha", "1.0.0"), component("beta", "2.0.0")],
            vec!["pkg:cargo/alpha@1.0.0".to_string()],
        );
        let bytes = projection.to_canonical_bytes().expect("canonical bytes");

        assert!(
            !bytes.contains('\n') && !bytes.contains('\r'),
            "the canonical form is ONE line with no trailing newline; got \
             {} line breaks",
            bytes.matches('\n').count() + bytes.matches('\r').count()
        );
        assert!(
            !bytes.starts_with('\u{feff}'),
            "the canonical form is UTF-8 without a byte-order mark"
        );
        assert!(
            !bytes.contains(": ") && !bytes.contains(", "),
            "the canonical form carries no pretty-printing whitespace"
        );

        let mut hasher = Sha256::new();
        hasher.update(bytes.as_bytes());
        let over_the_file = format!("{:x}", hasher.finalize());
        assert_eq!(
            over_the_file,
            projection.canonical_sha256().expect("canonical hash"),
            "sha256 of the emitted bytes must equal the canonical hash of \
             the document, or an auditor cannot check the file with \
             sha256sum alone"
        );
    }

    /// INTENT: a component with no resolvable version is an ERROR, never
    ///   a component emitted without a `version`.
    /// CONTEXT: a lockfile is by definition already resolved. A missing
    ///   version there can only mean a corrupt file or a broken parser,
    ///   and the worst failure mode for compliance is a BOM that looks
    ///   complete and is not.
    /// EXPIRES IF: the projection is extended to an input that legitimately
    ///   carries unresolved constraints rather than resolved versions.
    #[test]
    fn test_intent_sbom_missing_version_is_fail_loud() {
        let mut broken = component("alpha", "1.0.0");
        broken.version = String::new();
        let error = Projection::new(
            LockfileKind::Cargo,
            subject(),
            vec![broken],
            vec![],
            "test-basis",
            ProjectionCounters::default(),
        )
        .expect_err("a component with no version must not project");
        assert!(
            matches!(error, SbomError::MissingVersion { ref name } if name == "alpha"),
            "expected MissingVersion, got {error:?}"
        );
    }

    /// INTENT: two entries that produce the same purl with different
    ///   payloads are an ERROR, not a silent collapse.
    /// CONTEXT: the purl IS the reference under which the dependency
    ///   graph names a component. Two different components under one
    ///   reference make the document self-contradictory, so the
    ///   collision has to surface at production time.
    /// EXPIRES IF: the reference of a component stops being its purl.
    #[test]
    fn test_intent_sbom_purl_collision_is_fail_loud() {
        let mut clashing = component("alpha", "1.0.0");
        clashing.hash =
            Some(ComponentHash::checked(HashAlg::Sha256, &"a".repeat(64), "alpha").expect("valid"));
        let error = Projection::new(
            LockfileKind::Cargo,
            subject(),
            vec![component("alpha", "1.0.0"), clashing],
            vec![],
            "test-basis",
            ProjectionCounters::default(),
        )
        .expect_err("a purl collision must not project");
        assert!(
            matches!(error, SbomError::PurlCollision { ref purl } if purl == "pkg:cargo/alpha@1.0.0"),
            "expected PurlCollision, got {error:?}"
        );
    }

    /// The BOM-level self-description is exactly three properties for a
    /// lockfile with no platform requirements, sorted by name, all under
    /// the `seetrex:sbom.` prefix, and none of them load-bearing: the
    /// top-level set is in the STANDARD `dependencies` field.
    #[test]
    fn sbom_properties_are_the_three_bom_level_names() {
        let doc = projection(
            vec![component("alpha", "1.0.0")],
            vec!["pkg:cargo/alpha@1.0.0".to_string()],
        )
        .to_cyclonedx();
        let properties = doc
            .get("properties")
            .and_then(Value::as_array)
            .expect("BOM-level properties");
        let names: Vec<&str> = properties
            .iter()
            .map(|p| p["name"].as_str().expect("property name"))
            .collect();
        assert_eq!(
            names,
            vec![
                "seetrex:sbom.lockfile_kind",
                "seetrex:sbom.projection",
                "seetrex:sbom.top_level_basis",
            ]
        );
        assert_eq!(properties[1]["value"], json!(PROJECTION_ID));

        // The regulatory signal is NOT in a property.
        let depends_on = doc["dependencies"][0]["dependsOn"]
            .as_array()
            .expect("dependsOn array");
        assert_eq!(depends_on, &vec![json!("pkg:cargo/alpha@1.0.0")]);
        assert_eq!(doc["dependencies"][0]["ref"], json!(subject().as_str()));

        // Components carry no properties of their own.
        assert!(doc["components"][0].get("properties").is_none());
    }

    #[test]
    fn subject_purl_parses_the_shapes_the_projection_emits() {
        let cargo = SubjectPurl::parse("pkg:cargo/example-app@1.2.3").expect("cargo subject");
        assert_eq!(cargo.name(), "example-app");
        assert_eq!(cargo.version(), "1.2.3");

        let scoped =
            SubjectPurl::parse("pkg:npm/%40scope/widget@0.4.0").expect("scoped npm subject");
        assert_eq!(scoped.name(), "widget");
        assert_eq!(scoped.version(), "0.4.0");
        // The namespace stays inside the purl, undecoded.
        assert_eq!(scoped.as_str(), "pkg:npm/%40scope/widget@0.4.0");
    }

    #[test]
    fn subject_purl_rejects_everything_that_is_not_a_purl() {
        for bad in [
            "example-app@1.2.3",
            "pkg:cargo/example-app",
            "pkg:cargo/example-app@",
            "pkg:/example-app@1.2.3",
            "pkg:cargo@1.2.3",
            "pkg:cargo/@1.2.3",
        ] {
            assert!(
                SubjectPurl::parse(bad).is_err(),
                "`{bad}` must not parse as a subject purl"
            );
        }
    }

    /// INTENT: the subject is held to the SAME grammar the module builds
    ///   component purls with. It is the one string in the document that
    ///   an auditor types by hand, and it reaches `metadata.component`,
    ///   the single `dependencies[].ref`, and every error message that
    ///   quotes it -- so a permissive reading here puts a space, an
    ///   unencoded `@`, a `../`, a JSON metacharacter or the reserved
    ///   token of specification 7.7 inside a published artifact whose
    ///   whole claim is that a stranger re-derives it.
    /// CONTEXT: the earlier parser only required a `pkg:` prefix, a
    ///   non-empty type, a non-empty last segment and a non-empty version,
    ///   so every probe below parsed and was emitted verbatim.
    /// EXPIRES IF: the purl specification admits an escape beyond the
    ///   `%40` of an npm scope for one of these three types.
    #[test]
    fn test_intent_subject_purl_is_held_to_the_build_purl_grammar() {
        for (bad, what) in [
            ("pkg:cargo/example app@1.2.3", "a space in the name"),
            ("pkg:cargo/example-app@1.2 3", "a space in the version"),
            (
                "pkg:npm/@scope/widget@0.4.0",
                "an unencoded `@` in the scope",
            ),
            ("pkg:npm/%40sc ope/widget@0.4.0", "a space in the scope"),
            ("pkg:cargo/../../etc/passwd@1.0.0", "a traversal path"),
            ("pkg:cargo/..@1.0.0", "a relative-path name"),
            (
                "pkg:cargo/example\"-app@1.2.3",
                "a JSON metacharacter in the name",
            ),
            ("pkg:cargo/{app}@1.2.3", "JSON braces in the name"),
            ("pkg:cargo/VERIFIED@1.2.3", "the reserved token as a name"),
            ("pkg:cargo/app@VERIFIED", "the reserved token as a version"),
            (
                "pkg:golang/example.com/app@1.2.3",
                "an unsupported purl type",
            ),
            (
                "pkg:cargo/vendor/app@1.2.3",
                "a namespace cargo cannot have",
            ),
            ("pkg:composer/app@1.2.3", "a composer name with no vendor"),
            ("pkg:npm/a/b/c@1.2.3", "three npm path segments"),
        ] {
            let error = SubjectPurl::parse(bad)
                .err()
                .unwrap_or_else(|| panic!("{what}: `{bad}` must not parse as a subject purl"));
            assert!(
                matches!(error, SbomError::MalformedSubject { .. }),
                "{what}: expected MalformedSubject, got {error:?}"
            );
            assert!(
                !format!("{error}").contains("VERIFIED"),
                "{what}: the rejection echoes the reserved token back out, and \
                 downstream tooling reads that substring as a strong pass: {error}"
            );
        }

        // The shapes the module actually produces still parse, so the
        // grammar was tightened rather than broken.
        for good in [
            "pkg:cargo/example-app@1.2.3",
            "pkg:cargo/example_app@0.1.0-beta.1+build.7",
            "pkg:composer/example-vendor/runtime-lib@v1.4.0",
            "pkg:npm/plain-lib@1.2.3",
            "pkg:npm/%40example-scope/widget@0.4.0",
        ] {
            assert!(
                SubjectPurl::parse(good).is_ok(),
                "`{good}` is a purl this module emits and must parse"
            );
        }
    }

    /// INTENT: the purl grammar and the sanitizer that redacts the
    ///   reserved token at every output boundary agree about WHAT the
    ///   token is. One spelling, one case rule, one mask.
    /// CONTEXT: three literals used to exist -- this module's `VERIFIED`
    ///   compared case-SENSITIVELY, `sbom::compare`'s compared
    ///   case-SENSITIVELY, and `package::sanitize_reserved_token`
    ///   compared case-INSENSITIVELY -- and this module rendered a third
    ///   mask, `<reserved token>`, that no legend pointed at. The gap was
    ///   observable: `VeRiFiEd` passed the grammar, became a component
    ///   purl, and was then masked on the way out, so a difference report
    ///   could print two DISTINCT purls as one identical string.
    /// EXPIRES IF: the token stops being reserved, or the sanitizer stops
    ///   being case-insensitive (at which point the grammar follows it in
    ///   the same change).
    /// MUTANT: make `is_reserved_token` compare with `==`; render
    ///   `<reserved token>` again from `redact_reserved`.
    #[test]
    fn test_intent_reserved_token_grammar_matches_the_sanitizer() {
        // Facet 1: CASE. Every spelling the sanitizer would mask whole is
        // refused by the grammar, in the name and in the version.
        for spelling in ["VERIFIED", "verified", "VeRiFiEd", "Verified"] {
            for bad in [
                format!("pkg:cargo/{spelling}@1.2.3"),
                format!("pkg:cargo/app@{spelling}"),
                format!("pkg:npm/%40scope/{spelling}@1.2.3"),
            ] {
                let error = SubjectPurl::parse(&bad).err().unwrap_or_else(|| {
                    panic!(
                        "`{bad}` carries the reserved token and must not parse; the \
                         sanitizer masks that spelling, so admitting it makes two \
                         different purls print as one"
                    )
                });
                let rendered = format!("{error}");
                assert!(
                    !rendered
                        .to_ascii_uppercase()
                        .contains(crate::package::RESERVED_TOKEN),
                    "the rejection of `{bad}` echoes the reserved token back out: {rendered}"
                );
            }
        }

        // Facet 2: ONE MASK. The rejection renders the mask every other
        // surface of these crates renders, and never a second spelling of
        // the same idea.
        let error = SubjectPurl::parse("pkg:cargo/VERIFIED@1.2.3")
            .expect_err("the reserved token as a name must not parse");
        let rendered = format!("{error}");
        assert!(
            rendered.contains(crate::package::RESERVED_TOKEN_MASK),
            "the rejection must render the ONE mask a reader can look up in the \
             legend, got: {rendered}"
        );
        assert!(
            !rendered.contains("<reserved token>"),
            "a second, unexplained mask reached the output: {rendered}"
        );

        // A name that CARRIES the token without BEING it is a real
        // package (`verified-fetch` and its siblings ship on npm). It
        // projects, and the output boundary masks it -- a false refusal
        // of a real artifact would be worse than the masking.
        assert!(
            SubjectPurl::parse("pkg:npm/verified-fetch@1.0.0").is_ok(),
            "a real package whose name merely carries the token must project"
        );
    }

    /// INTENT: `metadata.component` carries EXACTLY five keys --
    ///   `bom-ref`, `name`, `purl`, `type`, `version` -- even when the
    ///   subject purl carries a namespace. No `group`.
    /// CONTEXT: decoding the namespace back out of the purl into a
    ///   `group` is a TRANSFORMATION, and this module does not transform
    ///   its input; the purl already carries the namespace verbatim.
    ///   Specification 5.5 said the opposite until this change, so the
    ///   document and the code disagreed about the shape of the one
    ///   object every consumer reads first.
    /// EXPIRES IF: the subject stops being carried verbatim, at which
    ///   point inverting the grammar stops being a transformation.
    #[test]
    fn test_intent_subject_metadata_component_has_no_group() {
        let namespaced = composer::project_lockfile(
            &fixture("composer_two_scopes.lock"),
            Some(&fixture("composer_two_scopes.json")),
            SubjectPurl::parse("pkg:composer/example-org/example-portal@1.0.0")
                .expect("subject parses"),
        )
        .expect("the composer fixture projects")
        .to_cyclonedx();

        let component = namespaced["metadata"]["component"]
            .as_object()
            .expect("metadata.component is an object");
        let keys: Vec<&str> = component.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec!["bom-ref", "name", "purl", "type", "version"],
            "the subject of a NAMESPACED purl carries exactly five keys and no \
             `group`: the namespace is already inside the purl, and decoding it \
             back out would be a transformation"
        );
        assert_eq!(
            component["purl"],
            json!("pkg:composer/example-org/example-portal@1.0.0"),
            "the namespace stays inside the purl, verbatim"
        );

        // Non-vacuity: the COMPONENTS of the same document do carry
        // `group`, because there it is read from the lockfile rather than
        // decoded back out of a purl.
        assert!(
            namespaced["components"][0].get("group").is_some(),
            "a composer component carries `group`; the assertion above is \
             about the SUBJECT and would be vacuous if nothing ever did"
        );
    }

    #[test]
    fn build_purl_rejects_tokens_that_would_need_an_invented_encoding() {
        assert_eq!(
            build_purl(LockfileKind::Cargo, "alpha", "1.0.0").expect("valid tokens"),
            "pkg:cargo/alpha@1.0.0"
        );
        for (name, version) in [("al pha", "1.0.0"), ("alpha", "1.0 0"), ("", "1.0.0")] {
            assert!(
                build_purl(LockfileKind::Cargo, name, version).is_err(),
                "`{name}`/`{version}` must not build a purl"
            );
        }
    }

    /// INTENT: `hashes` is a CARGO-ONLY key. A composer or an npm
    ///   document carries none, anywhere; a cargo document carries one
    ///   per entry whose lockfile line records a `checksum`.
    /// CONTEXT: cargo's `checksum` is already a lowercase-hex SHA-256 of
    ///   the crate file, so it is copied verbatim and an auditor
    ///   re-derives it from the public lockfile with no judgement in
    ///   between. Composer `dist.shasum` (a SHA-1 of a zipball the
    ///   registry builds on demand, EMPTY on every entry of this
    ///   repository's own lockfile) and npm `integrity` (a digest of the
    ///   registry tarball, base64, so a transformation away from
    ///   `hashes[].content`) are digests of something OTHER than the
    ///   component identity. An earlier revision of these modules
    ///   published both; specification 2.4 and 5.2 now forbid it.
    /// EXPIRES IF: the specification is amended to admit, for those
    ///   ecosystems, a digest an auditor can re-derive without a
    ///   transformation that carries judgement.
    #[test]
    fn test_intent_hashes_are_cargo_only() {
        // Non-vacuity: both fixtures still RECORD a digest, so the
        // assertions below measure the projection and not an input that
        // happens to be silent.
        assert!(
            fixture("composer_two_scopes.lock").contains(r#""shasum": "da39a3ee"#),
            "the composer fixture must keep a non-empty dist.shasum"
        );
        assert!(
            fixture("npm_scoped.json").contains(r#""integrity": "sha512-"#),
            "the npm fixture must keep an integrity value"
        );

        let composer_doc = composer::project_lockfile(
            &fixture("composer_two_scopes.lock"),
            Some(&fixture("composer_two_scopes.json")),
            SubjectPurl::parse("pkg:composer/example-org/example-portal@1.0.0")
                .expect("subject parses"),
        )
        .expect("the composer fixture projects")
        .to_cyclonedx();
        assert!(
            !mentions_hashes(&composer_doc),
            "a composer document carries no `hashes` anywhere: {composer_doc}"
        );

        let npm_doc = npm::project_lockfile(
            &fixture("npm_scoped.json"),
            SubjectPurl::parse("pkg:npm/example-app@1.0.0").expect("subject parses"),
        )
        .expect("the npm fixture projects")
        .to_cyclonedx();
        assert!(
            !mentions_hashes(&npm_doc),
            "an npm document carries no `hashes` anywhere: {npm_doc}"
        );

        // The other direction: cargo DOES emit, under `SHA-256`, and the
        // content is the checksum of the lockfile verbatim.
        let cargo_doc = cargo::project_lockfile(&fixture("cargo_two_versions.lock"), subject())
            .expect("the cargo fixture projects")
            .to_cyclonedx();
        let emitted: Vec<&Value> = cargo_doc["components"]
            .as_array()
            .expect("components")
            .iter()
            .filter_map(|component| component.get("hashes"))
            .collect();
        assert!(
            !emitted.is_empty(),
            "a cargo lockfile WITH checksums must carry hashes: {cargo_doc}"
        );
        for hashes in emitted {
            assert_eq!(hashes[0]["alg"], "SHA-256");
            let content = hashes[0]["content"].as_str().expect("a hex digest");
            assert_eq!(content.len(), 64);
            assert!(
                fixture("cargo_two_versions.lock").contains(content),
                "`{content}` is the lockfile checksum verbatim"
            );
        }
    }
}
