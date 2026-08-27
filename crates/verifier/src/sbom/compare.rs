// SPDX-License-Identifier: Apache-2.0
//! `sbom::compare` -- the comparison half of `verify-sbom`: a CycloneDX
//! document of unknown provenance, confronted with a re-projection of
//! the lockfile the auditor holds.
//!
//! The asymmetry of the two inputs is the whole point. The document is
//! UNTRUSTED: it is the artifact whose claim is under test. The
//! lockfile, the manifest and the SUBJECT belong to the auditor, and the
//! subject in particular is an INPUT of this comparison, never a value
//! read back out of the document. An artifact that names what it is
//! supposed to be is evidence of nothing, so a forged
//! `metadata.component` presented beside a legitimate subject has to
//! fail -- and it does, as [`Comparison::subject_mismatch`].
//!
//! ## Two verdicts, never conflated
//!
//! 1. **Byte-identical** ([`Comparison::byte_identical`]). The bytes of
//!    the document equal the canonical bytes of the re-projection. This
//!    is the only STRONG verdict and the expected outcome for a document
//!    this projection produced.
//! 2. **Difference sets** ([`Comparison::is_match`]). Everything else is
//!    reported as SETS -- purls only here, purls only there, fields that
//!    disagree, top-level edges present on one side alone -- never as a
//!    summary judgement of "equivalent".
//!
//! Reporting verdict 1 because the difference sets came out empty would
//! make canonicalization pointless, so the two are computed from
//! different material: verdict 1 from the bytes, verdict 2 from the
//! parsed documents. They are not redundant. The difference sets are the
//! enumeration the specification fixes, which is deliberately not a
//! completeness claim: a document can carry an extra graph entry, or an
//! unsorted `dependsOn`, and land in "bytes differ, every set empty".
//! That outcome has its own name
//! ([`Verdict::DifferentBytesNoDifferenceSets`]) precisely so it can
//! never be read as a match.
//!
//! ## Strictness of the parse
//!
//! [`parse_canonical_sbom`] does not merely read the document, it holds
//! it to the format: canonical bytes, the seven allowed top-level keys,
//! no volatile field, `bom-ref` equal to `purl` everywhere, components
//! in total purl order, and every reference resolving against a DECLARED
//! `bom-ref`. Each of those is a property an auditor can check by hand;
//! a verifier that skipped them would be certifying a document it never
//! read.
//!
//! ## The reserved token
//!
//! `verify-sbom` is not one of this product's strong verification
//! surfaces and must not emit the reserved token, including inside a
//! message that interpolates bytes taken from the document. Both output
//! boundaries of this module -- [`render_human`] and the `Display` of
//! [`CompareError`] -- sanitize the WHOLE of their output, so the
//! guarantee does not depend on remembering it at each interpolation
//! site.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use seetrex_format::hashing::canonicalize;
use serde_json::{Map, Value};

use super::Projection;

/// The FIXED success banner. A success line that varied would be a line
/// no downstream reader could match on.
pub const MATCH_BANNER: &str = "SBOM matches the lockfile projection";

/// The token reserved for this product's strong verification surfaces.
/// `verify-sbom` is not one of them.
///
/// It is [`crate::package::RESERVED_TOKEN`] and not a literal of this
/// module's own: three spellings of one token used to exist, and they did
/// not agree about case.
pub const RESERVED_TOKEN: &str = crate::package::RESERVED_TOKEN;

/// What the reserved token is replaced with when it appears in bytes
/// that came out of the document under test.
///
/// It is [`crate::package::RESERVED_TOKEN_MASK`] and not a mask of this
/// module's own: both sanitizers meet on the `verify-sbom` surface -- this
/// one at the module boundary, the binary's at the output boundary -- and
/// two masks reaching one report left the reader to guess whether they
/// meant the same thing. One mask, and one legend
/// ([`crate::package::RESERVED_TOKEN_LEGEND`]) printed when a substitution
/// actually happened.
pub const RESERVED_TOKEN_REPLACEMENT: &str = crate::package::RESERVED_TOKEN_MASK;

/// The seven top-level keys the format allows. No other key is
/// permitted -- in particular no `serialNumber`, whose presence alone
/// would make two emissions of one lockfile differ.
pub const ALLOWED_TOP_LEVEL_KEYS: [&str; 7] = [
    "bomFormat",
    "components",
    "dependencies",
    "metadata",
    "properties",
    "specVersion",
    "version",
];

/// The top-level keys whose values are scalars, compared as document
/// header fields rather than as sets.
const HEADER_KEYS: [&str; 3] = ["bomFormat", "specVersion", "version"];

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

/// Why a document could not be read AS a canonical SBOM.
///
/// Every variant is a verification failure, not an auditor-side error:
/// the document is the untrusted artifact, so "it is malformed" is a
/// statement about it, in the same class as "it disagrees with the
/// lockfile". The auditor's own inputs fail elsewhere, with the
/// projection's own error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareError {
    /// The bytes are not UTF-8.
    NotUtf8 {
        /// How many leading bytes were valid UTF-8.
        valid_up_to: usize,
    },
    /// The bytes begin with a UTF-8 byte-order mark. The canonical form
    /// has none, and a mark parsed away silently would let a document
    /// differ from its own hash preimage.
    ByteOrderMark,
    /// The bytes are not JSON at all.
    NotJson {
        /// What the JSON reader said.
        detail: String,
    },
    /// The bytes are JSON, but not the JCS (RFC 8785) form of the value
    /// they encode: re-serializing the parsed value yields other bytes.
    NotCanonical {
        /// Offset, in bytes from the start of the document under test,
        /// of the first position where the document and its own
        /// re-serialization differ. When one is a prefix of the other,
        /// the length of the shorter.
        first_diff_offset: usize,
    },
    /// The document is JSON, but not a JSON object.
    NotAnObject,
    /// A top-level key outside the seven the format allows.
    UnexpectedTopLevelKey {
        /// The offending key.
        key: String,
    },
    /// One of the seven mandatory top-level keys is absent.
    MissingTopLevelKey {
        /// The absent key.
        key: String,
    },
    /// `metadata` carries something besides `component` -- a
    /// `timestamp`, for instance, which is volatile by construction.
    UnexpectedMetadataKey {
        /// The offending key.
        key: String,
    },
    /// A value is absent or of the wrong JSON type.
    Malformed {
        /// Where in the document, as a path a reader can follow.
        path: String,
        /// What was expected there.
        detail: String,
    },
    /// A `bom-ref` that is not byte-identical to its object's own
    /// `purl`. The purl IS the identity; a second, unrelated identifier
    /// on the same object is a reference space with two names in it.
    BomRefNotPurl {
        /// Where in the document.
        path: String,
        /// The declared reference.
        bom_ref: String,
        /// The purl it was supposed to equal.
        purl: String,
    },
    /// `components` is not in ascending purl order over UTF-8 bytes.
    ComponentsOutOfOrder {
        /// The purl that appears first.
        previous: String,
        /// The purl that follows it out of order.
        next: String,
    },
    /// Two components of one document carry the same purl. The purl is
    /// the reference of the component, so this is two objects claiming
    /// one identity.
    DuplicateComponentPurl {
        /// The repeated purl.
        purl: String,
    },
    /// A `dependencies[].ref` or `dependsOn` entry that resolves against
    /// no declared `bom-ref`. A dangling reference makes the document
    /// invalid for exactly the strict consumers this format serves.
    DanglingReference {
        /// The reference that resolves to nothing.
        reference: String,
    },
}

impl fmt::Display for CompareError {
    /// Renders the message and then sanitizes the WHOLE of it, so a
    /// reserved token smuggled into a purl or a key cannot reach a
    /// reader through an error path.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = match self {
            Self::NotUtf8 { valid_up_to } => {
                format!("the document is not UTF-8 (valid up to byte {valid_up_to})")
            }
            Self::ByteOrderMark => {
                "the document begins with a UTF-8 byte-order mark; the canonical form has none"
                    .to_string()
            }
            Self::NotJson { detail } => format!("the document is not JSON: {detail}"),
            Self::NotCanonical { first_diff_offset } => format!(
                "the document is not in canonical form: it differs from its own JCS \
                 re-serialization at byte {first_diff_offset}"
            ),
            Self::NotAnObject => "the document is not a JSON object".to_string(),
            Self::UnexpectedTopLevelKey { key } => {
                format!("top-level key `{key}` is not one of the seven the format allows")
            }
            Self::MissingTopLevelKey { key } => {
                format!("mandatory top-level key `{key}` is missing")
            }
            Self::UnexpectedMetadataKey { key } => format!(
                "`metadata` carries the key `{key}`; it may carry `component` and nothing else"
            ),
            Self::Malformed { path, detail } => format!("{path} is malformed: {detail}"),
            Self::BomRefNotPurl {
                path,
                bom_ref,
                purl,
            } => format!(
                "{path} declares `bom-ref` `{bom_ref}` while its `purl` is `{purl}`; \
                 the two must be byte-identical"
            ),
            Self::ComponentsOutOfOrder { previous, next } => format!(
                "`components` is not sorted ascending by purl: `{previous}` precedes `{next}`"
            ),
            Self::DuplicateComponentPurl { purl } => {
                format!("purl `{purl}` names two components of the same document")
            }
            Self::DanglingReference { reference } => {
                format!("reference `{reference}` resolves against no declared `bom-ref`")
            }
        };
        formatter.write_str(&sanitize(&raw))
    }
}

impl std::error::Error for CompareError {}

// ---------------------------------------------------------------------
// The document under test
// ---------------------------------------------------------------------

/// A document that has been READ as a canonical SBOM: its bytes, the
/// value they encode, and the projections of it the comparison needs.
///
/// Holding one of these is a statement: these bytes are canonical, the
/// top-level key set is exactly the seven, every `bom-ref` equals its
/// own `purl`, the components are in total purl order and every
/// reference resolves. Nothing downstream re-checks any of it, so the
/// only constructor is [`parse_canonical_sbom`].
#[derive(Debug, Clone)]
pub struct CanonicalSbom {
    bytes: Vec<u8>,
    document: Value,
    components: Vec<(String, Value)>,
    subject_component: Value,
    declared_subject_purl: String,
    dependencies: Vec<(String, Vec<String>)>,
    properties: Vec<(String, String)>,
}

impl CanonicalSbom {
    /// The bytes as they were handed in -- which, the document being
    /// canonical, are also the bytes an auditor hashes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The parsed document.
    pub fn document(&self) -> &Value {
        &self.document
    }

    /// The components, in the document's own (purl-ascending) order.
    pub fn components(&self) -> &[(String, Value)] {
        &self.components
    }

    /// `metadata.component` as the document declares it.
    pub fn subject_component(&self) -> &Value {
        &self.subject_component
    }

    /// The purl the document CLAIMS as its subject.
    ///
    /// Untrusted, and never the subject of a comparison: the subject is
    /// supplied by the auditor. This exists so the claim can be
    /// CONFRONTED with the supplied one and reported when the two
    /// disagree, which is the only legitimate use of it.
    pub fn declared_subject_purl(&self) -> &str {
        &self.declared_subject_purl
    }

    /// The dependency graph as pairs of `(ref, dependsOn)`.
    pub fn dependencies(&self) -> &[(String, Vec<String>)] {
        &self.dependencies
    }

    /// The `dependsOn` list declared for `reference`, if the document
    /// declares one at all.
    pub fn top_level_of(&self, reference: &str) -> Option<&[String]> {
        self.dependencies
            .iter()
            .find(|(name, _)| name == reference)
            .map(|(_, edges)| edges.as_slice())
    }

    /// The BOM-level properties as `(name, value)` pairs.
    pub fn properties(&self) -> &[(String, String)] {
        &self.properties
    }
}

/// Read bytes as a canonical SBOM, holding them to the format.
///
/// The check that carries the others is the canonical one: the bytes
/// must be the JCS re-serialization of the value they encode. It
/// rejects pretty-printing, unsorted object keys, duplicate keys, a
/// number outside the shortest round-trip form and a trailing newline
/// in ONE criterion, because every one of them makes the published
/// bytes differ from the bytes the format defines.
///
/// # Errors
///
/// [`CompareError`], one variant per property violated; the canonical
/// check runs FIRST, so a document that fails it is reported as
/// non-canonical rather than by whichever structural rule happened to
/// be examined next.
pub fn parse_canonical_sbom(bytes: &[u8]) -> Result<CanonicalSbom, CompareError> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(CompareError::ByteOrderMark);
    }
    let text = std::str::from_utf8(bytes).map_err(|error| CompareError::NotUtf8 {
        valid_up_to: error.valid_up_to(),
    })?;
    let document: Value = serde_json::from_str(text).map_err(|error| CompareError::NotJson {
        detail: error.to_string(),
    })?;

    // Canonical bytes, checked against the document's OWN
    // re-serialization rather than against a re-projection: this is a
    // property of the artifact alone, and it holds (or not) before any
    // lockfile is involved.
    let recanonicalized = canonicalize(&document).map_err(|error| CompareError::NotJson {
        detail: error.to_string(),
    })?;
    if recanonicalized.as_bytes() != bytes {
        return Err(CompareError::NotCanonical {
            first_diff_offset: first_difference(bytes, recanonicalized.as_bytes()),
        });
    }

    let object = document.as_object().ok_or(CompareError::NotAnObject)?;
    for key in object.keys() {
        if !ALLOWED_TOP_LEVEL_KEYS.contains(&key.as_str()) {
            return Err(CompareError::UnexpectedTopLevelKey { key: key.clone() });
        }
    }
    for key in ALLOWED_TOP_LEVEL_KEYS {
        if !object.contains_key(key) {
            return Err(CompareError::MissingTopLevelKey {
                key: key.to_string(),
            });
        }
    }

    let (subject_component, declared_subject_purl) = read_subject(object)?;
    let components = read_components(object)?;
    let properties = read_properties(object)?;

    // Every reference resolves against a DECLARED `bom-ref`. The
    // declared set is the components plus the subject, and the subject
    // is in it because the single edge of the graph names it.
    let mut declared: BTreeSet<&str> = components.iter().map(|(purl, _)| purl.as_str()).collect();
    declared.insert(declared_subject_purl.as_str());
    let dependencies = read_dependencies(object, &declared)?;

    Ok(CanonicalSbom {
        bytes: bytes.to_vec(),
        document: document.clone(),
        components,
        subject_component,
        declared_subject_purl,
        dependencies,
        properties,
    })
}

/// `metadata` carries `component` and nothing else; the component
/// declares a `purl` and a `bom-ref` equal to it.
fn read_subject(object: &Map<String, Value>) -> Result<(Value, String), CompareError> {
    let metadata = object
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed("metadata", "expected an object"))?;
    for key in metadata.keys() {
        if key != "component" {
            return Err(CompareError::UnexpectedMetadataKey { key: key.clone() });
        }
    }
    let component = metadata
        .get("component")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed("metadata.component", "expected an object"))?;
    let purl = checked_bom_ref(component, "metadata.component")?;
    Ok((Value::Object(component.clone()), purl))
}

/// The components: objects, each with a `purl` and an equal `bom-ref`,
/// in strictly ascending purl order over UTF-8 bytes.
fn read_components(object: &Map<String, Value>) -> Result<Vec<(String, Value)>, CompareError> {
    let array = object
        .get("components")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("components", "expected an array"))?;
    let mut components: Vec<(String, Value)> = Vec::with_capacity(array.len());
    for (index, entry) in array.iter().enumerate() {
        let path = format!("components[{index}]");
        let component = entry
            .as_object()
            .ok_or_else(|| malformed(&path, "expected an object"))?;
        let purl = checked_bom_ref(component, &path)?;
        if let Some((previous, _)) = components.last() {
            // Byte-wise, via `str::cmp`. A locale collation would order
            // differently on another machine, and this order is part of
            // the bytes.
            match purl.as_str().cmp(previous.as_str()) {
                std::cmp::Ordering::Greater => {}
                std::cmp::Ordering::Equal => {
                    return Err(CompareError::DuplicateComponentPurl { purl })
                }
                std::cmp::Ordering::Less => {
                    return Err(CompareError::ComponentsOutOfOrder {
                        previous: previous.clone(),
                        next: purl,
                    })
                }
            }
        }
        components.push((purl, Value::Object(component.clone())));
    }
    Ok(components)
}

/// The graph: `ref` and `dependsOn`, every string in both resolving
/// against a declared `bom-ref`.
fn read_dependencies(
    object: &Map<String, Value>,
    declared: &BTreeSet<&str>,
) -> Result<Vec<(String, Vec<String>)>, CompareError> {
    let array = object
        .get("dependencies")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("dependencies", "expected an array"))?;
    let mut graph = Vec::with_capacity(array.len());
    for (index, entry) in array.iter().enumerate() {
        let path = format!("dependencies[{index}]");
        let node = entry
            .as_object()
            .ok_or_else(|| malformed(&path, "expected an object"))?;
        let reference = node
            .get("ref")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed(&format!("{path}.ref"), "expected a string"))?
            .to_string();
        if !declared.contains(reference.as_str()) {
            return Err(CompareError::DanglingReference { reference });
        }
        let mut edges = Vec::new();
        // An absent `dependsOn` is an empty one: both say the same thing
        // about the graph.
        if let Some(listed) = node.get("dependsOn") {
            let listed = listed
                .as_array()
                .ok_or_else(|| malformed(&format!("{path}.dependsOn"), "expected an array"))?;
            for (position, edge) in listed.iter().enumerate() {
                let edge = edge
                    .as_str()
                    .ok_or_else(|| {
                        malformed(
                            &format!("{path}.dependsOn[{position}]"),
                            "expected a string",
                        )
                    })?
                    .to_string();
                if !declared.contains(edge.as_str()) {
                    return Err(CompareError::DanglingReference { reference: edge });
                }
                edges.push(edge);
            }
        }
        graph.push((reference, edges));
    }
    Ok(graph)
}

/// The BOM-level properties as `(name, value)` pairs.
fn read_properties(object: &Map<String, Value>) -> Result<Vec<(String, String)>, CompareError> {
    let array = object
        .get("properties")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("properties", "expected an array"))?;
    let mut properties = Vec::with_capacity(array.len());
    for (index, entry) in array.iter().enumerate() {
        let path = format!("properties[{index}]");
        let property = entry
            .as_object()
            .ok_or_else(|| malformed(&path, "expected an object"))?;
        let name = property
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed(&format!("{path}.name"), "expected a string"))?;
        let value = property
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed(&format!("{path}.value"), "expected a string"))?;
        properties.push((name.to_string(), value.to_string()));
    }
    Ok(properties)
}

/// The `purl` of an object, after checking that its `bom-ref` is
/// byte-identical to it.
fn checked_bom_ref(object: &Map<String, Value>, path: &str) -> Result<String, CompareError> {
    let purl = object
        .get("purl")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(&format!("{path}.purl"), "expected a string"))?;
    let bom_ref = object
        .get("bom-ref")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(&format!("{path}.bom-ref"), "expected a string"))?;
    if bom_ref != purl {
        return Err(CompareError::BomRefNotPurl {
            path: path.to_string(),
            bom_ref: bom_ref.to_string(),
            purl: purl.to_string(),
        });
    }
    Ok(purl.to_string())
}

fn malformed(path: &str, detail: &str) -> CompareError {
    CompareError::Malformed {
        path: path.to_string(),
        detail: detail.to_string(),
    }
}

/// Offset of the first byte where two slices differ; when one is a
/// prefix of the other, the length of the shorter.
fn first_difference(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right.iter())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| left.len().min(right.len()))
}

// ---------------------------------------------------------------------
// The comparison
// ---------------------------------------------------------------------

/// One field of one object disagreeing between the two sides.
///
/// Both halves are optional because "absent here, present there" is a
/// difference in its own right, and a shape that could not express it
/// would report an added field as no difference at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDiff {
    /// The key, or the property name.
    pub field: String,
    /// The value the document carries, rendered; `None` when absent.
    pub in_document: Option<String>,
    /// The value the re-projection carries; `None` when absent.
    pub in_projection: Option<String>,
}

/// The fields of one component, identified by purl, that disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentFieldDiff {
    /// The purl, which both sides share -- a component whose purl
    /// differs is not a field difference, it is one purl missing and
    /// another extra.
    pub purl: String,
    /// The disagreeing fields, sorted by name.
    pub diffs: Vec<FieldDiff>,
}

/// The document's `metadata.component` disagreeing with the subject the
/// auditor supplied.
///
/// This is the forgery the specification names explicitly: a document
/// that declares a subject of its own choosing, presented beside a
/// legitimate supplied subject. The comparison never reads the subject
/// from the document, so the forgery lands here rather than being
/// adopted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectMismatch {
    /// The purl the document claims.
    pub declared_purl: String,
    /// The purl the auditor supplied.
    pub supplied_purl: String,
    /// The disagreeing fields of `metadata.component`, sorted by name.
    pub diffs: Vec<FieldDiff>,
}

/// The substantive counts printed beside a match, so a match over zero
/// components cannot be read as a substantive approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComparisonCounts {
    /// Components the document lists.
    pub components_in_document: usize,
    /// Components the re-projection produces.
    pub components_in_projection: usize,
    /// Top-level entries the document declares for the SUPPLIED subject.
    pub top_level_in_document: usize,
    /// Top-level entries the re-projection produces.
    pub top_level_in_projection: usize,
}

/// The named outcomes. Three, not two: "the bytes differ and every
/// difference set is empty" is its OWN outcome, and giving it a name is
/// how it stays impossible to report as a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The document IS the canonical projection, byte for byte. The only
    /// strong verdict.
    ByteIdentical,
    /// The bytes differ, yet every difference set came out empty. The
    /// document differs in something the difference sets do not
    /// enumerate.
    DifferentBytesNoDifferenceSets,
    /// The bytes differ and at least one difference set is non-empty.
    SemanticDifference,
}

impl Verdict {
    /// A stable token for machine consumers. None of them is the
    /// reserved token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ByteIdentical => "byte-identical",
            Self::DifferentBytesNoDifferenceSets => "different-bytes-no-difference-sets",
            Self::SemanticDifference => "semantic-difference",
        }
    }
}

/// The structured result of confronting a document with a re-projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparison {
    /// Verdict 1: the bytes of the document equal the canonical bytes of
    /// the re-projection. Computed from the BYTES, never from the
    /// difference sets below.
    pub byte_identical: bool,
    /// The document's `metadata.component` against the supplied subject.
    pub subject_mismatch: Option<SubjectMismatch>,
    /// Purls the re-projection has and the document does not, sorted.
    pub components_missing_in_document: Vec<String>,
    /// Purls the document has and the re-projection does not, sorted.
    pub components_extra_in_document: Vec<String>,
    /// Fields disagreeing on components both sides carry, sorted by
    /// purl.
    pub component_field_diffs: Vec<ComponentFieldDiff>,
    /// Top-level edges of the SUPPLIED subject that the re-projection
    /// has and the document does not, sorted.
    pub top_level_edges_missing: Vec<String>,
    /// Top-level edges the document has and the re-projection does not,
    /// sorted.
    pub top_level_edges_extra: Vec<String>,
    /// BOM-level properties that disagree, sorted by name.
    pub properties_diffs: Vec<FieldDiff>,
    /// `bomFormat`, `specVersion` and `version` where they disagree.
    pub header_diffs: Vec<FieldDiff>,
    /// The substantive counts.
    pub counts: ComparisonCounts,
}

impl Comparison {
    /// True when EVERY difference set is empty.
    ///
    /// This is verdict 2 and it is NOT the strong verdict: only
    /// [`Self::byte_identical`] is. A document can satisfy this and
    /// still not be the projection -- see
    /// [`Verdict::DifferentBytesNoDifferenceSets`] -- which is exactly
    /// why the two are separate fields computed from separate material.
    pub fn is_match(&self) -> bool {
        self.subject_mismatch.is_none()
            && self.components_missing_in_document.is_empty()
            && self.components_extra_in_document.is_empty()
            && self.component_field_diffs.is_empty()
            && self.top_level_edges_missing.is_empty()
            && self.top_level_edges_extra.is_empty()
            && self.properties_diffs.is_empty()
            && self.header_diffs.is_empty()
    }

    /// The named outcome.
    pub fn verdict(&self) -> Verdict {
        match (self.byte_identical, self.is_match()) {
            (true, _) => Verdict::ByteIdentical,
            (false, true) => Verdict::DifferentBytesNoDifferenceSets,
            (false, false) => Verdict::SemanticDifference,
        }
    }
}

/// Confront a document under test with a re-projection of the lockfile.
///
/// The subject of the comparison is the one carried by `reprojected`,
/// which the auditor supplied. The document's own `metadata.component`
/// is read for ONE purpose -- to be reported when it disagrees -- and
/// the top-level edges are looked up under the SUPPLIED subject, so a
/// document that renames its subject loses its graph rather than
/// redefining what is being verified.
pub fn compare(under_test: &CanonicalSbom, reprojected: &Projection) -> Comparison {
    let expected = reprojected.to_cyclonedx();
    let expected_object = expected.as_object().cloned().unwrap_or_default();
    let supplied_subject = reprojected.subject().as_str();

    // Verdict 1, from the bytes and from nothing else. A
    // canonicalization failure here is impossible for a document this
    // module built, and if it ever happened the safe reading is "not
    // byte-identical": never a claim of identity that was not measured.
    let byte_identical = reprojected
        .to_canonical_bytes()
        .is_ok_and(|canonical| canonical.as_bytes() == under_test.bytes());

    let header_diffs = HEADER_KEYS
        .iter()
        .filter_map(|key| {
            field_diff(
                key,
                under_test.document().get(*key),
                expected_object.get(*key),
            )
        })
        .collect();

    let expected_subject = expected_object
        .get("metadata")
        .and_then(|metadata| metadata.get("component"))
        .cloned()
        .unwrap_or(Value::Null);
    let subject_diffs = object_field_diffs(under_test.subject_component(), &expected_subject);
    let subject_mismatch = (!subject_diffs.is_empty()).then(|| SubjectMismatch {
        declared_purl: under_test.declared_subject_purl().to_string(),
        supplied_purl: supplied_subject.to_string(),
        diffs: subject_diffs,
    });

    let in_document: BTreeMap<&str, &Value> = under_test
        .components()
        .iter()
        .map(|(purl, value)| (purl.as_str(), value))
        .collect();
    let expected_components = expected_object
        .get("components")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let in_projection: BTreeMap<&str, &Value> = expected_components
        .iter()
        .filter_map(|component| {
            component
                .get("purl")
                .and_then(Value::as_str)
                .map(|purl| (purl, component))
        })
        .collect();

    let components_missing_in_document = difference(&in_projection, &in_document);
    let components_extra_in_document = difference(&in_document, &in_projection);
    let component_field_diffs = in_projection
        .iter()
        .filter_map(|(purl, projected)| {
            let document = in_document.get(purl)?;
            let diffs = object_field_diffs(document, projected);
            (!diffs.is_empty()).then(|| ComponentFieldDiff {
                purl: (*purl).to_string(),
                diffs,
            })
        })
        .collect();

    // The edges are looked up under the SUPPLIED subject. A document
    // whose graph is rooted elsewhere declares none for it, which is
    // reported as every expected edge missing -- not as a graph adopted
    // from the document's own idea of what it describes.
    let document_edges: BTreeSet<&str> = under_test
        .top_level_of(supplied_subject)
        .unwrap_or_default()
        .iter()
        .map(String::as_str)
        .collect();
    let projected_edges: BTreeSet<&str> =
        reprojected.top_level().iter().map(String::as_str).collect();

    let document_properties: BTreeMap<&str, &str> = under_test
        .properties()
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let projected_properties = property_map(&expected_object);
    let mut property_names: BTreeSet<&str> = document_properties.keys().copied().collect();
    property_names.extend(projected_properties.keys().copied());
    let properties_diffs = property_names
        .into_iter()
        .filter_map(|name| {
            let document = document_properties
                .get(name)
                .map(|value| (*value).to_string());
            let projection = projected_properties
                .get(name)
                .map(|value| (*value).to_string());
            (document != projection).then(|| FieldDiff {
                field: name.to_string(),
                in_document: document,
                in_projection: projection,
            })
        })
        .collect();

    Comparison {
        byte_identical,
        subject_mismatch,
        components_missing_in_document,
        components_extra_in_document,
        component_field_diffs,
        top_level_edges_missing: sorted_difference(&projected_edges, &document_edges),
        top_level_edges_extra: sorted_difference(&document_edges, &projected_edges),
        properties_diffs,
        header_diffs,
        counts: ComparisonCounts {
            components_in_document: in_document.len(),
            components_in_projection: in_projection.len(),
            top_level_in_document: document_edges.len(),
            top_level_in_projection: projected_edges.len(),
        },
    }
}

/// The BOM-level properties of an emitted document as a map.
fn property_map(object: &Map<String, Value>) -> BTreeMap<&str, &str> {
    object
        .get("properties")
        .and_then(Value::as_array)
        .map(|array| {
            array
                .iter()
                .filter_map(|property| {
                    let name = property.get("name").and_then(Value::as_str)?;
                    let value = property.get("value").and_then(Value::as_str)?;
                    Some((name, value))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Keys of `left` that `right` does not carry, sorted.
fn difference(left: &BTreeMap<&str, &Value>, right: &BTreeMap<&str, &Value>) -> Vec<String> {
    left.keys()
        .filter(|key| !right.contains_key(*key))
        .map(|key| (*key).to_string())
        .collect()
}

/// Members of `left` that `right` does not carry, sorted.
fn sorted_difference(left: &BTreeSet<&str>, right: &BTreeSet<&str>) -> Vec<String> {
    left.difference(right)
        .map(|key| (*key).to_string())
        .collect()
}

/// Every key of two objects whose values disagree, sorted by key.
///
/// A side that is not an object contributes no keys, so every key of the
/// other side is reported as present on one side alone -- which is what
/// it is.
fn object_field_diffs(in_document: &Value, in_projection: &Value) -> Vec<FieldDiff> {
    let empty = Map::new();
    let document = in_document.as_object().unwrap_or(&empty);
    let projection = in_projection.as_object().unwrap_or(&empty);
    let mut keys: BTreeSet<&str> = document.keys().map(String::as_str).collect();
    keys.extend(projection.keys().map(String::as_str));
    keys.into_iter()
        .filter_map(|key| field_diff(key, document.get(key), projection.get(key)))
        .collect()
}

/// One field, or `None` when the two sides agree.
fn field_diff(
    field: &str,
    in_document: Option<&Value>,
    in_projection: Option<&Value>,
) -> Option<FieldDiff> {
    if in_document == in_projection {
        return None;
    }
    Some(FieldDiff {
        field: field.to_string(),
        in_document: in_document.map(render_value),
        in_projection: in_projection.map(render_value),
    })
}

/// A value as a single line: a string as itself, anything else in its
/// canonical form, so two renderings of one value never differ.
fn render_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => canonicalize(other).unwrap_or_else(|_| other.to_string()),
    }
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

/// Replace the reserved token wherever it appears.
///
/// It is [`crate::package::sanitize_reserved_token`] and not a `replace`
/// of this module's own: that one matched the token case-SENSITIVELY
/// while the binary's boundary matched case-INSENSITIVELY, so which
/// spelling reached a reader depended on which of the two boundaries the
/// line crossed last.
fn sanitize(text: &str) -> String {
    crate::package::sanitize_reserved_token(text)
}

/// The human-readable report: deterministic, sorted, and free of the
/// reserved token.
///
/// Every section is printed with its count, empty ones included, so that
/// what was compared is visible rather than inferred -- the top-level
/// edges in particular, whose omission from a comparison is the exact
/// silent failure this projection exists to close.
pub fn render_human(comparison: &Comparison) -> String {
    let mut out = String::new();
    match comparison.verdict() {
        Verdict::ByteIdentical => {
            out.push_str(MATCH_BANNER);
            out.push('\n');
            out.push_str(&format!(
                "components: {}\ntop-level entries: {}\n",
                comparison.counts.components_in_projection,
                comparison.counts.top_level_in_projection
            ));
            return sanitize(&out);
        }
        Verdict::DifferentBytesNoDifferenceSets => {
            out.push_str(
                "SBOM differs from the lockfile projection in its BYTES, \
                 and every difference set below is empty\n",
            );
            out.push_str("empty difference sets are NOT a match: only byte identity is\n");
        }
        Verdict::SemanticDifference => {
            out.push_str("SBOM does not match the lockfile projection\n");
        }
    }
    out.push_str(&format!("verdict: {}\n", comparison.verdict().as_str()));

    match &comparison.subject_mismatch {
        None => out.push_str("subject: the document declares the supplied subject\n"),
        Some(mismatch) => {
            if mismatch.declared_purl == mismatch.supplied_purl {
                // The purls AGREE and something beside them does not.
                // Printing "document declares `X`, auditor supplied `X`"
                // put one identical string on both sides of the word
                // MISMATCH, which reads as a contradiction and tells a
                // reader nothing about what actually differs -- the more
                // so once the sanitizer has masked a reserved token in
                // both. The header names the fields; the lines below give
                // their values.
                //
                // `diffs` is non-empty in every value THIS MODULE builds:
                // `compare` constructs a `SubjectMismatch` only inside
                // `(!subject_diffs.is_empty()).then(...)`. That is a
                // statement about this module and not about the type --
                // `SubjectMismatch` is `pub` with `pub` fields, so a
                // consumer of this crate owns one it can empty, and the
                // claim "non-empty by construction" was therefore false as
                // written: it printed `differs in ` followed by nothing.
                // The type is left constructible on purpose. Sealing it
                // would take either a private field, which does not stop
                // `mismatch.diffs.clear()` on an owned value and so buys
                // only the appearance of enforcement, or private fields
                // with accessors -- a breaking change to a PUBLISHED
                // crate, pinned `=` by two others, for a reporter's
                // formatting. So the reporter handles the state instead,
                // and says where the value came from rather than printing
                // a sentence that trails off.
                let fields: Vec<&str> = mismatch
                    .diffs
                    .iter()
                    .map(|diff| diff.field.as_str())
                    .collect();
                if fields.is_empty() {
                    out.push_str(&format!(
                        "subject MISMATCH: the purls agree (`{}`) and the mismatch names \
                         no differing field; `compare` never builds one, so this value \
                         did not come from a comparison\n",
                        mismatch.declared_purl
                    ));
                } else {
                    out.push_str(&format!(
                        "subject MISMATCH: the purls agree (`{}`); `metadata.component` \
                         differs in {}\n",
                        mismatch.declared_purl,
                        fields.join(", ")
                    ));
                }
            } else {
                out.push_str(&format!(
                    "subject MISMATCH: document declares `{}`, auditor supplied `{}`\n",
                    mismatch.declared_purl, mismatch.supplied_purl
                ));
            }
            for diff in &mismatch.diffs {
                out.push_str(&format!("  metadata.component.{}\n", render_diff(diff)));
            }
        }
    }

    push_purls(
        &mut out,
        "components missing from the document",
        &comparison.components_missing_in_document,
    );
    push_purls(
        &mut out,
        "components only in the document",
        &comparison.components_extra_in_document,
    );

    // The count is the number of DIFFERENCES, not the number of components
    // carrying one: a header reading `(3)` above four printed lines is a
    // reader counting the wrong thing, and the lines are what an auditor
    // acts on.
    let component_field_diff_count: usize = comparison
        .component_field_diffs
        .iter()
        .map(|component| component.diffs.len())
        .sum();
    out.push_str(&format!(
        "component field differences ({component_field_diff_count}):\n"
    ));
    for component in &comparison.component_field_diffs {
        for diff in &component.diffs {
            out.push_str(&format!("  {} {}\n", component.purl, render_diff(diff)));
        }
    }

    push_purls(
        &mut out,
        "top-level edges missing from the document",
        &comparison.top_level_edges_missing,
    );
    push_purls(
        &mut out,
        "top-level edges only in the document",
        &comparison.top_level_edges_extra,
    );

    push_field_diffs(
        &mut out,
        "BOM property differences",
        &comparison.properties_diffs,
    );
    push_field_diffs(
        &mut out,
        "document header differences",
        &comparison.header_diffs,
    );

    out.push_str(&format!(
        "counts: components document={} projection={}; \
         top-level document={} projection={}\n",
        comparison.counts.components_in_document,
        comparison.counts.components_in_projection,
        comparison.counts.top_level_in_document,
        comparison.counts.top_level_in_projection
    ));
    sanitize(&out)
}

fn push_purls(out: &mut String, label: &str, purls: &[String]) {
    out.push_str(&format!("{label} ({}):\n", purls.len()));
    for purl in purls {
        out.push_str(&format!("  {purl}\n"));
    }
}

fn push_field_diffs(out: &mut String, label: &str, diffs: &[FieldDiff]) {
    out.push_str(&format!("{label} ({}):\n", diffs.len()));
    for diff in diffs {
        out.push_str(&format!("  {}\n", render_diff(diff)));
    }
}

/// `<field>: document <x>, projection <y>`, with `absent` for a side
/// that carries nothing -- an absent field and an empty one are
/// different claims.
fn render_diff(diff: &FieldDiff) -> String {
    let side = |value: &Option<String>| match value {
        Some(text) => format!("`{text}`"),
        None => "absent".to_string(),
    };
    format!(
        "{}: document {}, projection {}",
        diff.field,
        side(&diff.in_document),
        side(&diff.in_projection)
    )
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::{Path, PathBuf};

    use crate::sbom::{cargo, SubjectPurl};

    /// The published specification, whose reference vector is NORMATIVE.
    /// It is read from disk on every run: transcribing it into a Rust
    /// constant would let the document and the code drift apart in
    /// silence, which is the one failure these tests exist to prevent.
    const SPEC_RELATIVE_PATH: &str = "../../docs/SPEC_SBOM_CANONICAL_V1.md";

    /// The subject the specification fixes for its reference vector.
    const REFERENCE_SUBJECT: &str = "pkg:cargo/demo-app@0.2.0";

    fn spec_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(SPEC_RELATIVE_PATH)
    }

    fn fixture(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sbom/compare")
            .join(name);
        std::fs::read(&path)
            .unwrap_or_else(|error| panic!("fixture {} could not be read: {error}", path.display()))
    }

    /// The contents of the fenced code block delimited by
    /// `<!-- BEGIN <tag> -->` / `<!-- END <tag> -->`. Fails loudly when a
    /// marker is missing: a test that quietly found nothing would certify
    /// the code against an empty string.
    fn delimited_code_block(tag: &str) -> String {
        let spec = std::fs::read_to_string(spec_path()).unwrap_or_else(|error| {
            panic!(
                "the canonical SBOM specification could not be read at {}: {error}",
                spec_path().display()
            )
        });
        let begin = format!("<!-- BEGIN {tag} -->");
        let end = format!("<!-- END {tag} -->");
        let start = spec
            .find(&begin)
            .unwrap_or_else(|| panic!("marker `{begin}` is missing from the specification"));
        let after = &spec[start + begin.len()..];
        let stop = after
            .find(&end)
            .unwrap_or_else(|| panic!("marker `{end}` is missing from the specification"));
        let mut lines: Vec<&str> = after[..stop]
            .lines()
            .skip_while(|line| line.trim().is_empty())
            .collect();
        while matches!(lines.last(), Some(line) if line.trim().is_empty()) {
            lines.pop();
        }
        assert!(
            lines.len() >= 2
                && lines[0].trim_start().starts_with("```")
                && lines[lines.len() - 1].trim() == "```",
            "the region delimited by `{tag}` is not a fenced code block"
        );
        lines[1..lines.len() - 1].join("\n")
    }

    /// The normative lockfile, with the one trailing newline the
    /// specification says the file carries.
    fn reference_lockfile() -> String {
        format!("{}\n", delimited_code_block("SBOM-REFERENCE-LOCKFILE"))
    }

    /// The normative canonical projection: one line, no trailing newline.
    fn reference_document() -> String {
        delimited_code_block("SBOM-REFERENCE-CANONICAL")
    }

    fn reference_value() -> Value {
        serde_json::from_str(&reference_document()).expect("the reference vector is JSON")
    }

    /// The projection the CODE derives from the normative lockfile, under
    /// the subject the AUDITOR supplies.
    fn reference_projection() -> Projection {
        cargo::project_lockfile(
            &reference_lockfile(),
            SubjectPurl::parse(REFERENCE_SUBJECT).expect("the reference subject is a purl"),
        )
        .expect("the reference lockfile projects")
    }

    /// A mutant document: the reference value, altered, then RE-CANONICALIZED.
    ///
    /// Re-canonicalizing is what makes the mutant test what it claims to:
    /// a mutant that also happened to break the canonical form would be
    /// rejected by the canonical criterion, and the structural criterion
    /// under test would never run.
    fn mutant(alter: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut document = reference_value();
        alter(&mut document);
        canonicalize(&document)
            .expect("the mutant canonicalizes")
            .into_bytes()
    }

    fn parsed(bytes: &[u8]) -> CanonicalSbom {
        parse_canonical_sbom(bytes).expect("the document parses as canonical")
    }

    fn compared(bytes: &[u8]) -> Comparison {
        compare(&parsed(bytes), &reference_projection())
    }

    // -----------------------------------------------------------------
    // The reference vector
    // -----------------------------------------------------------------

    /// INTENT: the document the specification publishes as normative must
    /// be readable as canonical by this parser AND must be exactly what
    /// this code projects from the same lockfile under the same subject.
    /// The two halves are the contract an external auditor exercises: the
    /// published bytes on one side, a re-derivation on the other.
    /// CONTEXT: the specification prints the vector, its bytes and its
    /// hash as NORMATIVE, and states that an implementation which does not
    /// reproduce them is non-conforming whatever else it does.
    /// EXPIRES IF: the projection identifier changes, at which point the
    /// specification recomputes its reference vector in the SAME change
    /// that alters the behaviour.
    #[test]
    fn test_intent_reference_vector_is_canonical_and_matches_its_own_projection() {
        let bytes = reference_document().into_bytes();
        let document = parse_canonical_sbom(&bytes).expect("the reference vector is canonical");
        let comparison = compare(&document, &reference_projection());

        assert!(
            comparison.byte_identical,
            "the normative vector is not byte-identical to the code's own projection of the \
             normative lockfile; render: {}",
            render_human(&comparison)
        );
        assert!(
            comparison.is_match(),
            "the difference sets over the normative vector are not empty: {}",
            render_human(&comparison)
        );
        assert_eq!(comparison.verdict(), Verdict::ByteIdentical);
        // Substantive counts, so a match over an empty document could
        // never pass this test as a match over the real one.
        assert_eq!(comparison.counts.components_in_projection, 3);
        assert_eq!(comparison.counts.top_level_in_projection, 2);
        assert_eq!(comparison.counts.components_in_document, 3);
        assert_eq!(comparison.counts.top_level_in_document, 2);
    }

    // -----------------------------------------------------------------
    // Canonical form
    // -----------------------------------------------------------------

    /// INTENT: a pretty-printed document is NOT the artifact, even when it
    /// encodes the same value. The file IS the canonical bytes, so the
    /// whitespace is not cosmetic and the parser must say where the two
    /// first part company.
    /// CONTEXT: the format's whole premise is
    /// `sha256(file) == sha256(JCS(document))`; a verifier that accepted a
    /// re-indented copy would certify a file whose hash no auditor can
    /// reproduce.
    /// EXPIRES IF: the canonicalization, the line policy or the encoding
    /// of the format changes, which the specification classes as a
    /// BREAKING change requiring a new projection identifier.
    #[test]
    fn test_intent_pretty_printed_document_is_rejected_as_not_canonical() {
        let pretty = serde_json::to_string_pretty(&reference_value())
            .expect("the reference value re-serializes");
        let error = parse_canonical_sbom(pretty.as_bytes())
            .expect_err("a pretty-printed document is not canonical");
        // Byte 0 is `{` on both sides; byte 1 is `"` in the canonical form
        // and the newline of the indentation in the pretty one.
        assert_eq!(
            error,
            CompareError::NotCanonical {
                first_diff_offset: 1
            },
            "the first difference is not reported at the first byte that actually differs"
        );
    }

    /// INTENT: a trailing newline appended to the canonical bytes is a
    /// DIFFERENT file with a different hash, and the offset reported for
    /// it is the end of the canonical prefix.
    /// CONTEXT: the specification prints this exact mistake as its first
    /// negative control, with its own wrong hash, because appending a
    /// newline is what most tooling does by default.
    /// EXPIRES IF: the format stops defining the file as exactly the
    /// canonical bytes with no trailing newline.
    #[test]
    fn test_intent_trailing_newline_is_rejected_at_the_end_of_the_canonical_prefix() {
        let canonical = reference_document();
        let with_newline = format!("{canonical}\n");
        let error = parse_canonical_sbom(with_newline.as_bytes())
            .expect_err("a trailing newline is not canonical");
        assert_eq!(
            error,
            CompareError::NotCanonical {
                first_diff_offset: canonical.len()
            }
        );
    }

    // -----------------------------------------------------------------
    // Structural rejections
    // -----------------------------------------------------------------

    /// INTENT: `serialNumber` is refused outright. It is not a field this
    /// comparison can absorb: a document carrying one cannot be the
    /// projection of any lockfile, because two emissions of one lockfile
    /// would differ by it alone.
    /// CONTEXT: the seven top-level keys are exhaustive and the absence of
    /// `serialNumber` and `metadata.timestamp` is load-bearing; a
    /// content-derived serial number is not a repair either, since it
    /// would be part of the document whose hash defines it.
    /// EXPIRES IF: the format admits an eighth top-level key, a breaking
    /// change by the specification's own versioning rule.
    #[test]
    fn test_intent_serial_number_is_rejected_even_in_canonical_form() {
        let bytes = mutant(|document| {
            document["serialNumber"] = json!("urn:uuid:00000000-0000-4000-8000-000000000000");
        });
        let error = parse_canonical_sbom(&bytes).expect_err("`serialNumber` is not an allowed key");
        assert_eq!(
            error,
            CompareError::UnexpectedTopLevelKey {
                key: "serialNumber".to_string()
            },
            "a canonical document carrying a volatile identifier was accepted"
        );
    }

    /// INTENT: a `dependsOn` entry naming nothing the document declares is
    /// refused. A dangling reference makes the document invalid for the
    /// strict consumers this format exists to serve, and quietly ignoring
    /// it would let a graph name components that are not there.
    /// CONTEXT: every reference in the format resolves against an
    /// explicitly declared `bom-ref`, which is why the format writes the
    /// key out rather than relying on implicit resolution.
    /// EXPIRES IF: the format stops requiring declared references.
    #[test]
    fn test_intent_dangling_depends_on_is_rejected() {
        let ghost = "pkg:cargo/ghost@1.0.0";
        let bytes = mutant(|document| {
            document["dependencies"][0]["dependsOn"]
                .as_array_mut()
                .expect("`dependsOn` is an array")
                .insert(0, json!(ghost));
        });
        let error = parse_canonical_sbom(&bytes).expect_err("a dangling edge is not resolvable");
        assert_eq!(
            error,
            CompareError::DanglingReference {
                reference: ghost.to_string()
            }
        );
    }

    /// INTENT: a `bom-ref` that is not its object's own `purl` is refused.
    /// The purl IS the identity of a component; a second, unrelated
    /// identifier on the same object opens a reference space with two
    /// names in it, and a graph could then point at the one nobody reads.
    /// CONTEXT: the format writes `bom-ref` explicitly and fixes it equal
    /// to the purl, so that the reference stays content-derived and
    /// deterministic rather than a counter or an index.
    /// EXPIRES IF: the format admits a `bom-ref` that is not the purl.
    #[test]
    fn test_intent_bom_ref_other_than_the_purl_is_rejected() {
        let bytes = mutant(|document| {
            document["components"][0]["bom-ref"] = json!("pkg:cargo/leaf@9.9.9");
        });
        let error = parse_canonical_sbom(&bytes).expect_err("`bom-ref` must equal `purl`");
        assert_eq!(
            error,
            CompareError::BomRefNotPurl {
                path: "components[0]".to_string(),
                bom_ref: "pkg:cargo/leaf@9.9.9".to_string(),
                purl: "pkg:cargo/leaf@0.1.0".to_string(),
            }
        );
    }

    // -----------------------------------------------------------------
    // Difference sets
    // -----------------------------------------------------------------

    /// INTENT: a component the lockfile resolves and the document omits is
    /// reported, by purl, as missing from the document. A dependency that
    /// disappears from a bill of materials is the finding, not a detail.
    /// CONTEXT: the regulation asks for the dependencies to be covered;
    /// an omission that the verifier does not name is an omission the
    /// reader cannot see.
    /// EXPIRES IF: the comparison stops reporting difference sets by purl,
    /// which the specification forbids for as long as the purl is the
    /// identity.
    /// MUTANT: comparing only `components.len()` -- which ties whenever one
    /// component is swapped for another, the case the next test pins.
    #[test]
    fn test_intent_missing_component_is_reported_as_missing_from_the_document() {
        // `leaf@0.1.0` is reachable from no edge of the graph, so removing
        // it leaves every reference resolvable and isolates ONE difference.
        let bytes = mutant(|document| {
            document["components"]
                .as_array_mut()
                .expect("`components` is an array")
                .remove(0);
        });
        let comparison = compared(&bytes);

        assert_eq!(
            comparison.components_missing_in_document,
            vec!["pkg:cargo/leaf@0.1.0".to_string()]
        );
        assert!(comparison.components_extra_in_document.is_empty());
        assert!(!comparison.is_match());
        assert!(!comparison.byte_identical);
        assert_eq!(comparison.verdict(), Verdict::SemanticDifference);
        assert_eq!(comparison.counts.components_in_document, 2);
        assert_eq!(comparison.counts.components_in_projection, 3);
    }

    /// INTENT: one component swapped for another is reported as BOTH a
    /// missing purl and an extra one, even though the two sides list the
    /// same NUMBER of components.
    /// CONTEXT: a count is not an identity. A comparison that reduced the
    /// components to their cardinality would pass a document in which a
    /// dependency was quietly replaced by a different one.
    /// EXPIRES IF: the identity of a component stops being its purl.
    /// MUTANT: comparing only `components.len()`.
    #[test]
    fn test_intent_component_swap_is_not_hidden_by_equal_counts() {
        let bytes = mutant(|document| {
            document["components"][0] = json!({
                "bom-ref": "pkg:cargo/aaa@0.1.0",
                "name": "aaa",
                "purl": "pkg:cargo/aaa@0.1.0",
                "type": "library",
                "version": "0.1.0",
            });
        });
        let comparison = compared(&bytes);

        assert_eq!(
            comparison.counts.components_in_document, comparison.counts.components_in_projection,
            "the mutant is only interesting while the two counts tie"
        );
        assert_eq!(
            comparison.components_missing_in_document,
            vec!["pkg:cargo/leaf@0.1.0".to_string()]
        );
        assert_eq!(
            comparison.components_extra_in_document,
            vec!["pkg:cargo/aaa@0.1.0".to_string()]
        );
        assert!(!comparison.is_match());
    }

    /// INTENT: a component present on both sides under the same purl but
    /// carrying a different field value is reported as a FIELD difference,
    /// named field by field -- not as two unrelated components, and not as
    /// no difference at all.
    /// CONTEXT: the version inside a component and the version inside its
    /// purl are two statements; a document in which they disagree is
    /// making a claim the lockfile does not support.
    /// EXPIRES IF: the component field set of the format changes, which is
    /// a breaking change by the specification's own versioning rule.
    #[test]
    fn test_intent_changed_component_version_is_a_field_difference() {
        let bytes = mutant(|document| {
            document["components"][2]["version"] = json!("0.4.0");
        });
        let comparison = compared(&bytes);

        assert_eq!(
            comparison.component_field_diffs,
            vec![ComponentFieldDiff {
                purl: "pkg:cargo/midlib@0.3.0".to_string(),
                diffs: vec![FieldDiff {
                    field: "version".to_string(),
                    in_document: Some("0.4.0".to_string()),
                    in_projection: Some("0.3.0".to_string()),
                }],
            }]
        );
        assert!(comparison.components_missing_in_document.is_empty());
        assert!(comparison.components_extra_in_document.is_empty());
        assert!(!comparison.is_match());
    }

    /// INTENT: an edge removed from the subject's `dependsOn` is a
    /// finding. The top-level set is the regulatory content of the
    /// document, so a comparison that ignored the graph would be blind to
    /// exactly the claim the artifact exists to make.
    /// CONTEXT: the graph is deliberately depth 1 and lives in the
    /// standard `dependencies` field precisely so that it survives
    /// normalization; the ingest normalizer of this product drops it
    /// today, which is the silent failure this criterion closes.
    /// EXPIRES IF: the regulatory requirement on the dependency listing
    /// changes through the implementing act the regulation itself
    /// foresees.
    /// MUTANT: ignoring `dependencies` in the comparison.
    #[test]
    fn test_intent_top_level_shrink_is_reported() {
        let bytes = mutant(|document| {
            document["dependencies"][0]["dependsOn"]
                .as_array_mut()
                .expect("`dependsOn` is an array")
                .remove(1);
        });
        let comparison = compared(&bytes);

        assert_eq!(
            comparison.top_level_edges_missing,
            vec!["pkg:cargo/midlib@0.3.0".to_string()],
            "an edge removed from the subject's top-level set was not reported"
        );
        assert!(comparison.top_level_edges_extra.is_empty());
        // The components are untouched: the finding comes from the graph
        // alone, which is what makes this a test OF the graph.
        assert!(comparison.components_missing_in_document.is_empty());
        assert!(comparison.components_extra_in_document.is_empty());
        assert!(comparison.component_field_diffs.is_empty());
        assert!(!comparison.is_match());
    }

    // -----------------------------------------------------------------
    // The subject
    // -----------------------------------------------------------------

    /// INTENT: the subject comes from the CALLER and never from the
    /// document. A document that declares a subject of its own -- graph
    /// and all, so that it is internally consistent -- must fail against
    /// the subject the auditor supplied, not redefine what is being
    /// verified.
    /// CONTEXT: an artifact that names what it is supposed to be is
    /// evidence of nothing, exactly as an audit package can never name its
    /// own trust anchor; the specification requires a forged
    /// `metadata.component` presented with a legitimate supplied subject
    /// to fail.
    /// EXPIRES IF: the subject stops being a mandatory input of the
    /// verification, which would dissolve the property this test protects.
    /// MUTANT: reading the subject out of `metadata.component`.
    #[test]
    fn test_intent_forged_subject_is_reported_against_the_supplied_one() {
        let forged = "pkg:cargo/other-app@9.9.9";
        let bytes = mutant(|document| {
            document["metadata"]["component"] = json!({
                "bom-ref": forged,
                "name": "other-app",
                "purl": forged,
                "type": "application",
                "version": "9.9.9",
            });
            // Retargeted too, so the document stays internally consistent:
            // a forgery that left a dangling reference behind would be
            // caught by the parser and never reach the comparison.
            document["dependencies"][0]["ref"] = json!(forged);
        });
        let comparison = compared(&bytes);

        let mismatch = comparison
            .subject_mismatch
            .as_ref()
            .expect("a document declaring another subject is a subject mismatch");
        assert_eq!(mismatch.declared_purl, forged);
        assert_eq!(mismatch.supplied_purl, REFERENCE_SUBJECT);
        assert_eq!(
            mismatch
                .diffs
                .iter()
                .map(|diff| diff.field.as_str())
                .collect::<Vec<_>>(),
            vec!["bom-ref", "name", "purl", "version"]
        );
        // The graph is looked up under the SUPPLIED subject, so the
        // forgery loses its edges rather than carrying them over.
        assert_eq!(comparison.counts.top_level_in_document, 0);
        assert_eq!(
            comparison.top_level_edges_missing,
            vec![
                "pkg:cargo/leaf@0.2.0".to_string(),
                "pkg:cargo/midlib@0.3.0".to_string()
            ]
        );
        assert!(!comparison.is_match());
    }

    // -----------------------------------------------------------------
    // The two verdicts
    // -----------------------------------------------------------------

    /// INTENT: byte identity is measured on the BYTES and is never
    /// inferred from empty difference sets. The two verdicts answer
    /// different questions, and collapsing them would make
    /// canonicalization pointless.
    /// CONTEXT: the specification forbids reporting the byte-identical
    /// verdict merely because the difference sets came out empty; the
    /// difference sets are a fixed enumeration, not a completeness claim.
    /// EXPIRES IF: the difference sets ever became provably exhaustive
    /// over canonical documents, which no enumeration of sets can be.
    /// MUTANT: `byte_identical = self.is_match()`.
    #[test]
    fn test_intent_byte_identity_is_not_derived_from_the_difference_sets() {
        // A second graph entry, for a component the document declares:
        // canonical, resolvable, and invisible to every difference set,
        // because the sets compare the SUBJECT's edges.
        let bytes = mutant(|document| {
            document["dependencies"]
                .as_array_mut()
                .expect("`dependencies` is an array")
                .push(json!({ "ref": "pkg:cargo/leaf@0.1.0", "dependsOn": [] }));
        });
        let comparison = compared(&bytes);

        assert!(
            comparison.is_match(),
            "the difference sets were expected to be empty here: {}",
            render_human(&comparison)
        );
        assert!(
            !comparison.byte_identical,
            "empty difference sets were reported as byte identity"
        );
        assert_eq!(
            comparison.verdict(),
            Verdict::DifferentBytesNoDifferenceSets,
            "the outcome must carry its own name and never the match banner"
        );
        let rendered = render_human(&comparison);
        assert!(
            !rendered.contains(MATCH_BANNER),
            "the match banner was printed for a document that is not the projection: {rendered}"
        );
    }

    // -----------------------------------------------------------------
    // Output
    // -----------------------------------------------------------------

    /// INTENT: the report is deterministic and never emits the reserved
    /// token, including when the token arrives inside bytes taken from the
    /// document under test.
    /// CONTEXT: `verify-sbom` is not one of this product's strong
    /// verification surfaces, and downstream tooling pattern-matches the
    /// reserved substring as a strong pass; a purl is free to contain it,
    /// since the token is made of ordinary purl characters.
    /// EXPIRES IF: the token stops being reserved, or `verify-sbom` is
    /// promoted to a strong verification surface.
    #[test]
    fn test_intent_render_human_is_deterministic_and_sanitizes_the_reserved_token() {
        let hostile = format!("pkg:cargo/{RESERVED_TOKEN}@1.0.0");
        let bytes = mutant(|document| {
            // Uppercase sorts before the lowercase purls of the vector, so
            // the mutant stays in total purl order.
            document["components"]
                .as_array_mut()
                .expect("`components` is an array")
                .insert(
                    0,
                    json!({
                        "bom-ref": hostile,
                        "name": RESERVED_TOKEN,
                        "purl": hostile,
                        "type": "library",
                        "version": "1.0.0",
                    }),
                );
        });
        let comparison = compared(&bytes);

        assert_eq!(
            comparison.components_extra_in_document,
            vec![hostile.clone()],
            "the hostile component must reach the report for the sanitization to be tested"
        );
        let rendered = render_human(&comparison);
        assert!(
            !rendered.contains(RESERVED_TOKEN),
            "the reserved token reached the report: {rendered}"
        );
        assert!(
            rendered.contains(RESERVED_TOKEN_REPLACEMENT),
            "the sanitized purl is not in the report: {rendered}"
        );
        assert_eq!(
            rendered,
            render_human(&compared(&bytes)),
            "two renders of the same comparison differ; some iteration order is not fixed"
        );
    }

    /// INTENT: when the subject purls AGREE and a field beside them does
    ///   not, the MISMATCH header names the differing FIELDS instead of
    ///   printing one identical purl on both sides of the word "mismatch".
    /// CONTEXT: the header read "document declares `X`, auditor supplied
    ///   `X`". A reader met the same string twice under a word that
    ///   promises a difference, learned nothing about what actually
    ///   differed, and -- once the sanitizer had masked a reserved token in
    ///   both -- could not even tell whether the two strings had ever been
    ///   different.
    /// EXPIRES IF: `metadata.component` stops carrying any field beside
    ///   the purl, at which point the case cannot arise.
    /// MUTANT: print the two purls unconditionally.
    #[test]
    fn test_intent_subject_mismatch_header_names_the_differing_field() {
        // The purl is untouched; the `name` beside it is not.
        let bytes = mutant(|document| {
            document["metadata"]["component"]["name"] = json!("renamed-by-another-tool");
        });
        let comparison = compared(&bytes);
        let mismatch = comparison
            .subject_mismatch
            .as_ref()
            .expect("the subject differs in a field");
        assert_eq!(
            mismatch.declared_purl, mismatch.supplied_purl,
            "this guard measures the case where the PURLS agree"
        );

        let rendered = render_human(&comparison);
        assert!(
            rendered.contains("subject MISMATCH: the purls agree"),
            "the header must say that the purls agree rather than print one \
             of them twice: {rendered}"
        );
        assert!(
            rendered.contains("differs in name"),
            "the header must NAME the field that differs: {rendered}"
        );
        assert!(
            !rendered.contains("auditor supplied"),
            "the two-purls header belongs to the case where they differ: {rendered}"
        );

        // And that header is still what a genuine purl difference gets.
        // The `bom-ref` moves with the purl: they must agree, or the
        // document does not parse at all and this arm measures nothing.
        let bytes = mutant(|document| {
            document["metadata"]["component"]["purl"] = json!("pkg:cargo/other-app@9.9.9");
            document["metadata"]["component"]["bom-ref"] = json!("pkg:cargo/other-app@9.9.9");
            document["dependencies"][0]["ref"] = json!("pkg:cargo/other-app@9.9.9");
        });
        let rendered = render_human(&compared(&bytes));
        assert!(
            rendered.contains("subject MISMATCH: document declares")
                && rendered.contains("auditor supplied"),
            "two different purls must still be printed side by side: {rendered}"
        );
    }

    /// A `SubjectMismatch` that names no differing field renders an honest
    /// line instead of a sentence that trails off.
    ///
    /// `compare` never builds one -- it constructs the value only inside
    /// `(!subject_diffs.is_empty()).then(...)`. The type is nonetheless
    /// `pub` with `pub` fields in a crate other people depend on, so a
    /// consumer owns a value it can empty, and the reporter printed
    /// `differs in ` followed by nothing. The comment that used to call the
    /// field "non-empty by construction" was making a claim about this
    /// module and stating it about the type.
    #[test]
    fn subject_mismatch_naming_no_field_renders_an_honest_line() {
        let bytes = mutant(|document| {
            document["metadata"]["component"]["name"] = json!("renamed-by-another-tool");
        });
        let mut comparison = compared(&bytes);
        comparison
            .subject_mismatch
            .as_mut()
            .expect("the subject differs in a field")
            .diffs
            .clear();

        let rendered = render_human(&comparison);
        assert!(
            !rendered.contains("differs in \n"),
            "the reporter printed a sentence that trails off: {rendered}"
        );
        assert!(
            rendered.contains("names no differing field"),
            "the reporter must say the mismatch names no field: {rendered}"
        );
    }

    /// INTENT: an error message is sanitized too. The reserved token must
    /// not reach a reader through the error path, which is the path that
    /// interpolates the most untrusted bytes.
    /// CONTEXT: the specification names error messages explicitly as a
    /// place the token must not appear.
    /// EXPIRES IF: the token stops being reserved.
    #[test]
    fn test_intent_error_messages_sanitize_the_reserved_token() {
        let message = CompareError::DanglingReference {
            reference: format!("pkg:cargo/{RESERVED_TOKEN}@1.0.0"),
        }
        .to_string();
        assert!(
            !message.contains(RESERVED_TOKEN),
            "the reserved token reached an error message: {message}"
        );
        assert!(message.contains(RESERVED_TOKEN_REPLACEMENT));
    }

    // -----------------------------------------------------------------
    // Third-party documents
    // -----------------------------------------------------------------

    /// INTENT: a CycloneDX document from another tool is REFUSED by this
    /// parser rather than silently absorbed, and the refusal names the
    /// first byte at which the document stops being the canonical form.
    /// It is never rewritten: an independent tool disagreeing with this
    /// projection is a signal, and overwriting its output would destroy
    /// that signal.
    /// CONTEXT: such documents carry a `serialNumber`, a timestamp, tool
    /// metadata and licence fields, and are pretty-printed; the strict
    /// parse is what keeps "this is the canonical artifact" from being
    /// claimed about a file that is not one.
    /// EXPIRES IF: the verification surface grows a documented path that
    /// reports difference sets for non-canonical third-party input, which
    /// the specification leaves open (Section 7.4 describes such a
    /// document reaching the difference-set verdict, while the strict
    /// parse required here rejects it first).
    #[test]
    fn test_intent_third_party_document_is_refused_rather_than_rewritten() {
        let bytes = fixture("third_party_cyclonedx.json");
        let error =
            parse_canonical_sbom(&bytes).expect_err("a third-party document is not canonical");
        assert!(
            matches!(error, CompareError::NotCanonical { .. }),
            "a third-party document was refused for the wrong reason: {error}"
        );
    }
}
