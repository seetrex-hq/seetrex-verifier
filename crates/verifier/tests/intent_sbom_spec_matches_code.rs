// SPDX-License-Identifier: Apache-2.0
//! Structural guards binding the published canonical-SBOM specification to
//! the implementation in `src/sbom/`.
//!
//! The specification prints a NORMATIVE reference vector: an input
//! `Cargo.lock`, the exact canonical bytes it projects to, the SHA-256 of
//! those bytes, two negative controls, the seven allowed top-level keys and
//! the property table. Those printed artifacts ARE the public contract: an
//! independent auditor reads the document, never this crate. If the document
//! and the code drift apart, one of the two is lying to that auditor and
//! neither side alone can say which.
//!
//! Every test here therefore reads the specification FROM DISK and confronts
//! it with what the code actually emits. Nothing normative is transcribed
//! into a Rust constant: a transcription drifts silently with the document,
//! which is the exact failure these guards exist to make impossible.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use seetrex_format::hashing::canonicalize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use seetrex_verifier::sbom::{cargo, SubjectPurl};

/// The ONE private-tree gate of this crate, shared verbatim with
/// `src/sbom/` and with `intent_sbom_corpus.rs` rather than reimplemented:
/// one skip line, one fail-closed behaviour, one place to change. This
/// file used to open the variable by hand, so its skip was spelled
/// differently from every other and a wrong path here was a silent skip
/// where everywhere else it is an error.
///
/// `read_private_file` is unused here -- this guard reads a source file,
/// not a lockfile -- and the module is shared, so the allow is on the
/// import rather than on the shared source.
#[path = "../src/sbom/private_tree.rs"]
#[allow(dead_code)]
mod private_tree;

/// The specification, relative to this crate's manifest directory.
const SPEC_RELATIVE_PATH: &str = "../../docs/SPEC_SBOM_CANONICAL_V1.md";

/// The subject the specification fixes for its reference vector.
const REFERENCE_SUBJECT: &str = "pkg:cargo/demo-app@0.2.0";

// ---------------------------------------------------------------------------
// Reading the specification
// ---------------------------------------------------------------------------

fn spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SPEC_RELATIVE_PATH)
}

fn spec_text() -> String {
    let path = spec_path();
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "the canonical SBOM specification could not be read at {}: {error}. \
             These guards compare the published document against the code; with \
             no document there is nothing to compare, and passing quietly would \
             be the worst outcome available.",
            path.display()
        )
    })
}

/// The contents of the fenced code block delimited by
/// `<!-- BEGIN <tag> -->` / `<!-- END <tag> -->`, without the fence lines
/// and without a trailing newline.
///
/// Fails loudly when either marker is missing: a renamed or deleted marker
/// means the normative vector moved, and a test that quietly found nothing
/// would certify the code against an empty string.
fn delimited_code_block(spec: &str, tag: &str) -> String {
    let begin = format!("<!-- BEGIN {tag} -->");
    let end = format!("<!-- END {tag} -->");
    let start = spec.find(&begin).unwrap_or_else(|| {
        panic!(
            "marker `{begin}` is missing from {}: the normative vector cannot \
             be located",
            spec_path().display()
        )
    });
    let after = &spec[start + begin.len()..];
    let stop = after.find(&end).unwrap_or_else(|| {
        panic!(
            "marker `{end}` is missing from {} after `{begin}`",
            spec_path().display()
        )
    });

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
        "the region delimited by `{tag}` in {} is not a fenced code block; \
         the normative vector cannot be extracted",
        spec_path().display()
    );
    lines[1..lines.len() - 1].join("\n")
}

/// The body of a section, from its heading up to the next heading of level
/// two or deeper.
fn section_body(spec: &str, heading: &str) -> String {
    let start = spec.find(heading).unwrap_or_else(|| {
        panic!(
            "section `{heading}` is missing from {}",
            spec_path().display()
        )
    });
    let after = &spec[start + heading.len()..];
    let end = after
        .match_indices("\n##")
        .next()
        .map_or(after.len(), |(index, _)| index);
    after[..end].to_string()
}

/// Every inline-code span of a fragment of prose, in order.
fn backticked_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else { break };
        tokens.push(after[..close].to_string());
        rest = &after[close + 1..];
    }
    tokens
}

fn assert_lowercase_sha256(value: &str, what: &str) {
    assert!(
        value.len() == 64
            && value
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "{what} is not a lowercase hex SHA-256: `{value}`"
    );
}

// ---------------------------------------------------------------------------
// The normative artifacts, as the document prints them
// ---------------------------------------------------------------------------

/// The reference lockfile, with the one trailing newline the specification
/// says the file carries (the fenced block cannot show it).
fn printed_lockfile(spec: &str) -> String {
    format!(
        "{}\n",
        delimited_code_block(spec, "SBOM-REFERENCE-LOCKFILE")
    )
}

/// The canonical projection exactly as printed: one line, no trailing
/// newline.
fn printed_canonical(spec: &str) -> String {
    delimited_code_block(spec, "SBOM-REFERENCE-CANONICAL")
}

fn printed_canonical_sha256(spec: &str) -> String {
    let block = delimited_code_block(spec, "SBOM-REFERENCE-SHA256");
    let value = block
        .trim()
        .strip_prefix("sha256 = ")
        .unwrap_or_else(|| {
            panic!("the reference hash block does not read `sha256 = <hex>`: `{block}`")
        })
        .trim()
        .to_string();
    assert_lowercase_sha256(&value, "the printed reference hash");
    value
}

/// The two negative controls of the specification, in the order it prints
/// them: trailing newline appended, then deduplication by name.
fn printed_negative_controls(spec: &str) -> Vec<String> {
    let section = section_body(spec, "### 6.3 Negative controls");
    let hashes: Vec<String> = section
        .lines()
        .filter_map(|line| line.trim().strip_prefix("WRONG"))
        .filter_map(|rest| rest.split_whitespace().next().map(str::to_string))
        .collect();
    assert_eq!(
        hashes.len(),
        2,
        "the specification is expected to print exactly two negative controls, \
         found {}: {hashes:?}",
        hashes.len()
    );
    for hash in &hashes {
        assert_lowercase_sha256(hash, "a printed negative control");
    }
    hashes
}

/// The seven allowed top-level keys, read from the sentence that enumerates
/// them. The parenthetical VALUES the sentence also prints are not
/// identifiers and are filtered out.
fn printed_allowed_top_level_keys(spec: &str) -> Vec<String> {
    let section = section_body(spec, "### 5.1 Allowed top-level keys");
    let marker = "Exactly seven, all mandatory:";
    let start = section.find(marker).unwrap_or_else(|| {
        panic!(
            "the enumeration `{marker}` is missing from section 5.1 of {}",
            spec_path().display()
        )
    });
    let paragraph = section[start..].split("\n\n").next().unwrap_or_default();
    let mut keys: Vec<String> = backticked_tokens(paragraph)
        .into_iter()
        .filter(|token| !token.is_empty() && token.chars().all(|c| c.is_ascii_alphabetic()))
        .collect();
    keys.sort();
    keys.dedup();
    assert_eq!(
        keys.len(),
        7,
        "section 5.1 is expected to name seven top-level keys, found {}: {keys:?}",
        keys.len()
    );
    keys
}

/// The rows of the property table of section 5.4, as
/// `(name, raw value cell)` in document order.
fn printed_property_rows(spec: &str) -> Vec<(String, String)> {
    let section = section_body(spec, "### 5.4 ");
    let rows: Vec<(String, String)> = section
        .lines()
        .filter(|line| line.starts_with("| `seetrex:"))
        .map(|line| {
            let cells: Vec<&str> = line.split('|').collect();
            assert!(
                cells.len() >= 3,
                "property table row is not a two-column row: `{line}`"
            );
            let name = backticked_tokens(cells[1])
                .into_iter()
                .next()
                .unwrap_or_else(|| panic!("property table row has no name: `{line}`"));
            (name, cells[2].to_string())
        })
        .collect();
    assert!(
        !rows.is_empty(),
        "the property table of section 5.4 has no `seetrex:` rows in {}",
        spec_path().display()
    );
    rows
}

// ---------------------------------------------------------------------------
// What the code produces from the printed lockfile
// ---------------------------------------------------------------------------

/// The document the CODE builds from the lockfile the SPECIFICATION prints,
/// for the subject the specification fixes.
fn reference_document(spec: &str) -> Value {
    let subject = SubjectPurl::parse(REFERENCE_SUBJECT)
        .unwrap_or_else(|error| panic!("the reference subject was rejected: {error}"));
    cargo::project_lockfile(&printed_lockfile(spec), subject)
        .unwrap_or_else(|error| {
            panic!("the reference lockfile of the specification was rejected: {error}")
        })
        .to_cyclonedx()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn canonical_bytes(document: &Value) -> String {
    canonicalize(document).unwrap_or_else(|error| panic!("canonicalization failed: {error}"))
}

fn fragment(text: &str, start: usize, width: usize) -> String {
    let bytes = text.as_bytes();
    let from = start.min(bytes.len());
    let to = (from + width).min(bytes.len());
    String::from_utf8_lossy(&bytes[from..to]).into_owned()
}

/// A byte-level account of where two canonical strings part company, so a
/// failure names the defect instead of dumping two kilobytes side by side.
fn describe_difference(produced: &str, expected: &str) -> String {
    let (left, right) = (produced.as_bytes(), expected.as_bytes());
    let offset = left
        .iter()
        .zip(right.iter())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| left.len().min(right.len()));
    let start = offset.saturating_sub(40);
    format!(
        "first differing byte at offset {offset} \
         (code emits {} bytes, the specification prints {} bytes)\n  \
         code emits:  ...{}...\n  spec prints: ...{}...",
        left.len(),
        right.len(),
        fragment(produced, start, 140),
        fragment(expected, start, 140)
    )
}

// ---------------------------------------------------------------------------
// The guards
// ---------------------------------------------------------------------------

/// INTENT: the normative reference vector of the specification is what this
/// code actually produces, byte for byte and hash for hash. The vector is the
/// only thing a second implementation can be built against, so a vector the
/// reference implementation does not reproduce is worse than no vector: it
/// certifies conformance to a document nothing conforms to.
///
/// CONTEXT: the specification was written before the implementation existed,
/// and its header now names the release that carries it ("shipped in
/// `seetrex-verifier` 0.3.4"). Nothing but a test crossing the two can keep
/// that sentence true after the first edit to either side.
///
/// EXPIRES IF: the projection identifier `lockfile-v1` is retired, or the
/// specification stops printing a normative vector for the cargo ecosystem.
#[test]
fn test_intent_spec_vector_is_reproduced_by_the_code() {
    let spec = spec_text();
    let expected = printed_canonical(&spec);
    let produced = canonical_bytes(&reference_document(&spec));

    assert!(
        produced == expected,
        "the code does not reproduce the normative vector of {}.\n{}",
        spec_path().display(),
        describe_difference(&produced, &expected)
    );
    assert_eq!(
        sha256_hex(produced.as_bytes()),
        printed_canonical_sha256(&spec),
        "the SHA-256 of the emitted document differs from the hash the \
         specification pins"
    );
}

/// INTENT: the two deliberately wrong hashes of section 6.3 keep identifying
/// the mistakes they claim to identify. An implementer diagnoses their own
/// defect from those values alone; a control that no longer corresponds to
/// its described mistake sends them hunting for a bug they do not have.
///
/// CONTEXT: both controls are derived from the correct document, so any
/// change to the projection moves them silently. They are printed as bare
/// hex in prose, with no way for a reader to recompute them without the
/// mutation being reimplemented -- which is what this test does.
///
/// EXPIRES IF: section 6.3 stops publishing negative controls, or publishes
/// controls for mistakes other than the appended trailing newline and the
/// deduplication by name.
#[test]
fn test_intent_spec_negative_controls_hold() {
    let spec = spec_text();
    let controls = printed_negative_controls(&spec);
    let mut document = reference_document(&spec);
    let correct = canonical_bytes(&document);

    // Control one: the canonical bytes with a newline appended. The file IS
    // the canonical bytes (6.1 rule 2); nothing is appended.
    assert_eq!(
        sha256_hex(format!("{correct}\n").as_bytes()),
        controls[0],
        "the first negative control no longer identifies an appended \
         trailing newline"
    );

    // Control two: deduplication by NAME instead of by purl. The components
    // are already ordered by purl, so first-wins by name drops every later
    // version of a name that already appeared.
    let components = document["components"]
        .as_array()
        .expect("the document carries a `components` array")
        .clone();
    let mut seen: Vec<String> = Vec::new();
    let deduplicated: Vec<Value> = components
        .iter()
        .filter(|component| {
            let name = component["name"]
                .as_str()
                .expect("every component carries a `name`")
                .to_string();
            let first = !seen.contains(&name);
            if first {
                seen.push(name);
            }
            first
        })
        .cloned()
        .collect();
    assert!(
        deduplicated.len() < components.len(),
        "deduplication by name dropped nothing, so the second negative \
         control describes no mistake: the reference vector no longer \
         resolves one name at two versions"
    );
    document["components"] = Value::Array(deduplicated);
    assert_eq!(
        sha256_hex(canonical_bytes(&document).as_bytes()),
        controls[1],
        "the second negative control no longer identifies deduplication by \
         name"
    );
}

/// INTENT: the property names and values printed in the table of section 5.4
/// are the ones the emitter writes. The `seetrex:` prefix is a de facto
/// namespace: a reader has no registry to consult, only this table, so a
/// table naming a property the document does not carry is unfalsifiable
/// prose.
///
/// CONTEXT: the names are built at run time from a private prefix constant
/// and the values come from per-ecosystem constants; none of them is visible
/// outside the crate. This test reads them back out of the GENERATED
/// document, so it measures what is published rather than what is declared.
///
/// EXPIRES IF: the properties become load-bearing (section 5.4 states they
/// are not), which would move their contract out of a self-description table
/// and into the normative body.
#[test]
fn test_intent_spec_property_literals_match_code() {
    let spec = spec_text();
    let rows = printed_property_rows(&spec);
    assert!(
        rows.len() >= 3,
        "section 5.4 is expected to table at least the three always-emitted \
         properties, found {}",
        rows.len()
    );

    let document = reference_document(&spec);
    let properties = document["properties"]
        .as_array()
        .expect("the document carries a `properties` array");
    let emitted: Vec<String> = properties
        .iter()
        .map(|property| {
            property["name"]
                .as_str()
                .expect("every property carries a `name`")
                .to_string()
        })
        .collect();

    // The first three rows are the ones the specification says are emitted
    // always; a cargo document carries those and nothing else.
    let mut always: Vec<String> = rows[..3].iter().map(|(name, _)| name.clone()).collect();
    always.sort();
    let mut emitted_sorted = emitted.clone();
    emitted_sorted.sort();
    assert_eq!(
        emitted_sorted, always,
        "the always-emitted properties of the specification and the ones the \
         cargo document carries are not the same set"
    );

    // Emitted order is the sorted order the specification requires.
    assert_eq!(
        emitted, emitted_sorted,
        "the emitted properties are not sorted ascending by name"
    );

    // Every value the code writes is one the table prints for that name.
    for (name, cell) in &rows[..3] {
        let property = properties
            .iter()
            .find(|property| property["name"].as_str() == Some(name.as_str()))
            .unwrap_or_else(|| panic!("the document emits no property named `{name}`"));
        let value = property["value"]
            .as_str()
            .unwrap_or_else(|| panic!("the property `{name}` carries no string value"));
        let printed = backticked_tokens(cell);
        assert!(
            !printed.is_empty(),
            "the table cell of `{name}` prints no literal to check against"
        );
        assert!(
            printed.iter().any(|token| token == value),
            "the code emits `{name}` = `{value}`, which the specification \
             does not print for that property: {printed:?}"
        );
    }
}

/// INTENT: the emitted document carries exactly the seven top-level keys the
/// specification allows -- no more, no fewer. Two of the omissions are
/// load-bearing: a `serialNumber` or a `metadata.timestamp` makes two
/// emissions of one lockfile differ, which falsifies the premise of the whole
/// document.
///
/// CONTEXT: the keys are inserted one by one by the emitter, so an added key
/// is a one-line change that no other test would notice, while every hash it
/// breaks is only ever compared against hashes this same code produced.
///
/// EXPIRES IF: the document is migrated to a CycloneDX revision whose
/// mandatory key set differs, which section 9 makes a spec-version change.
#[test]
fn test_intent_spec_allowed_top_level_keys_match_code() {
    let spec = spec_text();
    let allowed = printed_allowed_top_level_keys(&spec);
    let document = reference_document(&spec);
    let mut emitted: Vec<String> = document
        .as_object()
        .expect("the emitted document is a JSON object")
        .keys()
        .cloned()
        .collect();
    emitted.sort();
    assert_eq!(
        emitted, allowed,
        "the top-level keys the code emits differ from the seven section 5.1 \
         allows"
    );
}

/// INTENT: the specification is internally consistent -- the hash it pins is
/// the hash of the bytes it prints, right next to it. An auditor who trusts
/// the printed hash over the printed bytes, or the reverse, must reach the
/// same conclusion either way.
///
/// CONTEXT: the vector and its hash are two independently editable blocks of
/// one markdown file. Editing the bytes without recomputing the hash produces
/// a document that is wrong on its own terms, and every implementation
/// checked against it inherits the error. This test involves NO code from
/// this crate on purpose: it holds even when the projection is broken, and it
/// is the one that separates "the specification is wrong" from "the code is
/// wrong" when both fail at once.
///
/// EXPIRES IF: the specification stops printing the canonical bytes in full,
/// leaving only a hash to check against.
#[test]
fn test_intent_spec_sha_literal_is_the_hash_of_the_printed_vector() {
    let spec = spec_text();
    let printed = printed_canonical(&spec);

    assert!(
        !printed.contains('\n'),
        "the printed canonical vector is not a single line, which rule 2 of \
         section 6.1 requires of the emitted file"
    );
    assert!(
        !printed.ends_with('\n'),
        "the printed canonical vector carries a trailing newline, which rule \
         2 of section 6.1 forbids"
    );
    assert_eq!(
        sha256_hex(printed.as_bytes()),
        printed_canonical_sha256(&spec),
        "the hash the specification pins is not the hash of the bytes it \
         prints: the document contradicts itself"
    );
}

// ---------------------------------------------------------------------------
// Guards that spawn the binary, or read a file the public export does not ship
// ---------------------------------------------------------------------------

/// The CLI this crate publishes, built by Cargo as a prerequisite of these
/// tests.
const BIN: &str = env!("CARGO_BIN_EXE_seetrex-verifier");

/// The ingest normaliser of this product, relative to the PRIVATE tree.
///
/// It is not part of the published crate, so this path is reached through
/// the `SEETREX_PRIVATE_TREE` gate and never by climbing out of the crate:
/// an exported checkout must stay testable, which is what
/// `tests/intent_public_crate_is_self_contained.rs` enforces.
const INGEST_NORMALISER: &str = "crates/compliance/src/connectors/cyclonedx/mod.rs";

/// A scratch directory Cargo gives integration tests, so no guard here has
/// to invent one or clean it up.
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    fs::create_dir_all(&dir).unwrap_or_else(|error| {
        panic!(
            "cannot create the scratch directory {}: {error}",
            dir.display()
        )
    });
    dir
}

/// The ingest normaliser's source, or `None` when this run is not inside
/// the private repository.
///
/// The gate is [`private_tree::private_tree`], shared with every other
/// private-tree test of this crate: it prints ONE skip line, directly to
/// the process stderr (the harness captures the print macros, and a silent
/// skip in a PASSING test is the one outcome this guard must not have),
/// and it FAILS rather than skips on a variable that is set to a wrong or
/// empty path. Opening the variable by hand here gave this one guard a
/// skip of its own spelling and a silent pass on a typo.
fn ingest_normaliser_source() -> Option<String> {
    let root = private_tree::private_tree()?;
    let path = root.join(INGEST_NORMALISER);
    Some(fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "SEETREX_PRIVATE_TREE names {}, but the ingest normaliser is not readable at \
             {}: {error}. A typo in the variable must be an ERROR, never a silent skip.",
            root.display(),
            path.display()
        )
    }))
}

/// The BOM-level keys the ingest normaliser writes into its canonical form,
/// read TEXTUALLY from its source.
///
/// `metadata` is reported as `metadata.component`, which is what the
/// normaliser actually keeps under it and what the specification names.
fn ingest_whitelist(source: &str) -> BTreeSet<String> {
    let marker = "canonical.insert(\"";
    let mut keys = BTreeSet::new();
    let mut rest = source;
    while let Some(at) = rest.find(marker) {
        let after = &rest[at + marker.len()..];
        let end = after
            .find('"')
            .unwrap_or_else(|| panic!("unterminated key literal after `{marker}`"));
        let key = &after[..end];
        keys.insert(if key == "metadata" {
            "metadata.component".to_string()
        } else {
            key.to_string()
        });
        rest = &after[end..];
    }
    assert!(
        keys.contains("bomFormat") && keys.contains("components"),
        "the ingest whitelist was read as {keys:?}, which does not look like the \
         normaliser's canonical map. The extraction anchor `{marker}` has moved, and a \
         guard that reads nothing certifies nothing."
    );
    keys
}

/// A fragment of prose with every run of whitespace collapsed to one space,
/// so a claim can be matched regardless of where the document wraps it.
fn unwrapped(text: &str) -> String {
    text.split_whitespace().collect::<Vec<&str>>().join(" ")
}

/// INTENT: section 5.4 item 1 does not claim that the top-level set SURVIVES
///   this product's normalisation while `dependencies` is absent from the
///   ingest whitelist, and the four keys it names ARE that whitelist. The
///   sentence is the only place a reader learns what the emitted
///   `dependencies` array is worth inside the evidence chain, and it claimed
///   survival that does not happen.
/// CONTEXT: the normaliser (`crates/compliance/src/connectors/cyclonedx/mod.rs`)
///   builds a four-key canonical map and drops `dependencies`; widening it is a
///   pinned-ruleset change with its own gate. When that lands, this guard flips:
///   the survival claim becomes the required wording and the "today" sentence
///   the forbidden one.
/// EXPIRES IF: the canonical SBOM stops being ingested into the chain at all,
///   or the normaliser's canonical map stops being built by `canonical.insert`.
/// MUTANT: restore "precisely so that it survives normalisation" to 5.4(1);
///   add `dependencies` to the normaliser's map without touching the document.
#[test]
fn test_intent_spec_ingest_whitelist_matches_5_4() {
    let Some(source) = ingest_normaliser_source() else {
        return;
    };
    let keys = ingest_whitelist(&source);

    let spec = spec_text();
    let section = unwrapped(&section_body(&spec, "### 5.4 "));

    // The keys the document names, from item 1's own parenthetical.
    let marker = "the normaliser keeps";
    let start = section.find(marker).unwrap_or_else(|| {
        panic!(
            "section 5.4 no longer says what the ingest normaliser keeps. That sentence is \
             the claim this guard exists to hold to the code; rewriting it without keeping \
             a statement of the whitelist leaves the reader with nothing to check."
        )
    });
    let open = start
        + section[start..]
            .find('(')
            .expect("the normaliser sentence names no key set");
    let close = open
        + section[open..]
            .find(')')
            .expect("unterminated key set in the normaliser sentence");
    let named: BTreeSet<String> = backticked_tokens(&section[open..close])
        .into_iter()
        .collect();
    assert_eq!(
        named, keys,
        "section 5.4 says the ingest normaliser keeps {named:?}, the normaliser keeps \
         {keys:?}. One of the two is lying to an auditor about what the published \
         document is worth inside the evidence chain."
    );

    const SURVIVAL_CLAIM: &str = "precisely so that it survives normalisation";
    const TODAY_CLAIM: &str = "the top-level set reaches no content hash of the chain";
    if keys.contains("dependencies") {
        assert!(
            section.contains(SURVIVAL_CLAIM),
            "the ingest whitelist now carries `dependencies`, so the top-level set DOES \
             survive normalisation and section 5.4 must say so ({SURVIVAL_CLAIM:?})"
        );
        assert!(
            !section.contains(TODAY_CLAIM),
            "the ingest whitelist carries `dependencies`, but section 5.4 still says the \
             top-level set reaches no content hash"
        );
    } else {
        assert!(
            !section.contains(SURVIVAL_CLAIM),
            "section 5.4 claims the top-level set lives in `dependencies` {SURVIVAL_CLAIM}, \
             while `dependencies` is absent from the ingest whitelist {keys:?}: it does not \
             survive, and the sentence is false"
        );
        assert!(
            section.contains(TODAY_CLAIM),
            "with `dependencies` outside the ingest whitelist, section 5.4 must state what \
             the emitted array is worth in the chain today ({TODAY_CLAIM:?})"
        );
    }
}

/// INTENT: the MUST of section 5.5 -- the subject purl's type matches the
///   lockfile kind -- is ENFORCED by the CLI, on both subcommands, as the
///   auditor-side error the exit-code table names.
/// CONTEXT: the sentence sat in the document unimplemented: `emit-sbom --kind
///   cargo --subject pkg:npm/...` wrote a canonical document whose
///   `metadata.component` claimed an ecosystem its own components do not belong
///   to, and exited 0.
/// EXPIRES IF: section 5.5 withdraws the requirement.
/// MUTANT: remove the check from either subcommand.
#[test]
fn test_intent_spec_subject_type_must_match_kind_is_enforced() {
    let spec = spec_text();
    let requirement = "The subject purl's type MUST match the lockfile kind";
    let section = unwrapped(&section_body(&spec, "### 5.5 "));
    assert!(
        section.contains(requirement),
        "section 5.5 no longer states {requirement:?}; this guard measures that MUST and \
         has nothing to measure without it"
    );

    let dir = scratch("spec_subject_type");
    let lockfile = dir.join("Cargo.lock");
    fs::write(&lockfile, printed_lockfile(&spec)).expect("write the reference lockfile");
    let out = dir.join("never-written.json");
    let _ = fs::remove_file(&out);
    let lockfile = lockfile.to_str().expect("test paths are UTF-8");
    let out_path = out.to_str().expect("test paths are UTF-8");

    let emit = Command::new(BIN)
        .args([
            "emit-sbom",
            "--kind",
            "cargo",
            "--lockfile",
            lockfile,
            "--subject",
            "pkg:npm/wrong-ecosystem@0.2.0",
            "--out",
            out_path,
        ])
        .output()
        .expect("spawn the verifier");
    assert_eq!(
        emit.status.code(),
        Some(2),
        "emit-sbom accepted a subject of the wrong ecosystem; stderr: {}",
        String::from_utf8_lossy(&emit.stderr)
    );
    assert!(
        !out.exists(),
        "a document was written for a subject the specification forbids"
    );

    let verify = Command::new(BIN)
        .args([
            "verify-sbom",
            "--kind",
            "cargo",
            "--lockfile",
            lockfile,
            "--subject",
            "pkg:npm/wrong-ecosystem@0.2.0",
            "--sbom",
            lockfile,
        ])
        .output()
        .expect("spawn the verifier");
    assert_eq!(
        verify.status.code(),
        Some(2),
        "verify-sbom answered the auditor's own typo with a verification code; stderr: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

/// INTENT: Appendix A -- the editorial completions a reviewer is told to
///   challenge one by one -- agrees with the normative sections about the
///   key set of `metadata.component`. Five keys, and never a `group`.
/// CONTEXT: entry A.3 admitted a `group` "for a namespaced purl" while
///   section 5.5 and the conformance checklist of section 10 both forbid
///   the key, and the code emits five. A reviewer reading the appendix --
///   which exists precisely to be read on its own -- was told the opposite
///   of the rule, inside the one document an external auditor holds.
/// EXPIRES IF: section 5.5 starts admitting a `group` on
///   `metadata.component`, at which point all three places move together.
/// MUTANT: restore "plus `group` for a namespaced purl" in Appendix A.
#[test]
fn test_intent_spec_appendix_a_agrees_about_metadata_component_keys() {
    let spec = spec_text();
    let appendix = unwrapped(&section_body(&spec, "## Appendix A. Editorial completions"));

    // Non-vacuity: the appendix really does discuss the object.
    assert!(
        appendix.contains("metadata.component"),
        "Appendix A no longer mentions `metadata.component`; this guard measures \
         an agreement it can no longer locate"
    );
    assert!(
        appendix.contains("never a `group`"),
        "Appendix A must state that `metadata.component` never carries a `group`, \
         as sections 5.5 and 10 do. It reads:\n{appendix}"
    );
    assert!(
        !appendix.contains("plus `group`"),
        "Appendix A admits a `group` on `metadata.component`, contradicting 5.5 and \
         the conformance checklist of section 10:\n{appendix}"
    );

    // And the code is the third party to the agreement: the reference
    // vector's own subject object carries exactly the five keys.
    let document = reference_document(&spec);
    let keys: BTreeSet<String> = document["metadata"]["component"]
        .as_object()
        .expect("metadata.component is an object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "bom-ref".to_string(),
            "name".to_string(),
            "purl".to_string(),
            "type".to_string(),
            "version".to_string(),
        ]),
        "the emitted `metadata.component` does not carry the five keys Appendix A \
         and section 5.5 both name"
    );
}

// ---------------------------------------------------------------------------
// Section 2.1: the digest-free source schemes
// ---------------------------------------------------------------------------

/// The source schemes section 2.1 exempts from rule (b), read from the
/// normative sentence that grants the exemption.
///
/// The anchor is the clause that states WHY they are exempt, and the tokens
/// are the inline-code spans between it and the parenthetical that explains
/// each one. Reading the sentence rather than a heading is deliberate: a
/// scheme silently added to the constant has to be argued HERE, in the
/// published document, or the two sets part company.
fn printed_digest_free_schemes(spec: &str) -> BTreeSet<String> {
    let section = unwrapped(&section_body(spec, "### 2.1 "));
    const MARKER: &str = "the source schemes cargo resolves without recording a digest";
    let start = section.find(MARKER).unwrap_or_else(|| {
        panic!(
            "section 2.1 of {} no longer grants the digest-free exemption in the sentence \
             this guard reads ({MARKER:?}). That sentence is the published exemption list; \
             a guard that cannot find it certifies nothing.",
            spec_path().display()
        )
    });
    let rest = &section[start..];
    let stop = rest.find('(').unwrap_or_else(|| {
        panic!("the digest-free exemption sentence of section 2.1 names no explanation")
    });
    let schemes: BTreeSet<String> = backticked_tokens(&rest[..stop]).into_iter().collect();
    assert!(
        !schemes.is_empty(),
        "section 2.1 grants a digest-free exemption and names no scheme for it"
    );
    schemes
}

/// INTENT: the digest-free exemption of specification 2.1 rule (b) and the
///   constant that implements it are ONE set. Rule (b) is what makes a
///   format 1 or 2 lockfile relabelled as a `3` fail loud instead of
///   projecting components with no `hashes`; every scheme on the exemption
///   list is a hole in it, and a hole an auditor cannot read out of the
///   published document is not an exemption but an undeclared capability.
/// CONTEXT: `DIGEST_FREE_SOURCE_SCHEMES` was private and bound to the
///   document by nothing at all. Adding `sparse+` to it -- the scheme of
///   every sparse registry, which is now cargo's default protocol -- muted
///   rule (b) for every package cargo fetches that way, and the whole suite
///   stayed green. Set equality against the sentence the specification
///   prints is what makes that edit an argument in public instead of a
///   one-token commit.
/// EXPIRES IF: rule (b) is withdrawn from section 2.1, or the exemption
///   stops being expressible as a set of `source` scheme prefixes.
/// MUTANT: add `"sparse+"` to the constant; drop `path+` from the constant;
///   add a third scheme to the sentence in 2.1 without touching the code.
#[test]
fn test_intent_spec_digest_free_schemes_match_code() {
    let spec = spec_text();
    let printed = printed_digest_free_schemes(&spec);
    let implemented: BTreeSet<String> = cargo::DIGEST_FREE_SOURCE_SCHEMES
        .iter()
        .map(|scheme| (*scheme).to_string())
        .collect();

    assert_eq!(
        printed, implemented,
        "section 2.1 exempts {printed:?} from the `source`-without-`checksum` rule and \
         `cargo::DIGEST_FREE_SOURCE_SCHEMES` exempts {implemented:?}. Every scheme on that \
         list is a package the projection publishes with no `hashes` and no complaint, so \
         a difference between the two is an exemption an auditor cannot read."
    );
}

// ---------------------------------------------------------------------------
// Section 10: what the reserved-token obligation is ON
// ---------------------------------------------------------------------------

/// The one conformance-checklist item of section 10 that speaks about the
/// reserved token.
fn printed_reserved_token_item(spec: &str) -> String {
    let section = section_body(spec, "## 10. Conformance checklist");
    let items: Vec<String> = section
        .split("\n- [ ] ")
        .skip(1)
        .map(unwrapped)
        .filter(|item| item.contains("reserved token"))
        .collect();
    assert_eq!(
        items.len(),
        1,
        "section 10 of {} is expected to carry exactly one checklist item about the \
         reserved token, found {}: {items:?}",
        spec_path().display(),
        items.len()
    );
    items.into_iter().next().unwrap_or_default()
}

/// The phrasings of the UNSCOPED claim -- "the token is never emitted at
/// all" -- that this specification has carried and must not carry again.
///
/// Named LITERALLY and matched over the WHOLE document, because the claim
/// is false wherever it stands: the checklist item, the normative prose of
/// section 7, an appendix. Pinning it in one checklist item left every
/// other surface of the same document free to say the opposite.
const FORBIDDEN_UNSCOPED_CLAIMS: [&str; 3] = [
    "the reserved token is never emitted",
    "the token is never emitted",
    "no surface of this product ever prints the token",
];

/// How a sentence NAMES the reserved token, matched against the LOWERCASED
/// sentence.
///
/// Case-sensitive was a hole with a measured escape: a mention that opens a
/// sentence is capitalised, so `The token MUST NOT be printed anywhere this
/// product writes.` named the token to every reader and to none of these
/// literals, and the structural rule below skipped it.
const RESERVED_TOKEN_MENTIONS: [&str; 3] = ["reserved token", "`verified`", "the token"];

/// How a sentence makes an ABSOLUTE negative claim (matched lowercased).
const ABSOLUTE_NEGATIONS: [&str; 5] = [
    "never",
    "must not",
    "no surface",
    "not emitted",
    "not printed",
];

thread_local! {
    /// How many denial decisions [`denies_absolutely`] has made ON THIS THREAD.
    ///
    /// THREAD-LOCAL, not global, for the reason its twin in
    /// `crates/witness/tests/kit_doc.rs` gives: the observation is `load`,
    /// call, `load` around a direct invocation, and libtest runs this binary's
    /// tests in parallel, so a process-wide counter could be advanced inside
    /// that window by the standalone run of the same guard. Measured, deleting
    /// the direct call reddens today -- the window is too narrow to be hit --
    /// but that is a race and not a property.
    static DENIAL_DECISIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// True when `lowered` makes an absolute negative claim, decided by
/// [`ABSOLUTE_NEGATIONS`] and by nothing else.
///
/// A free function rather than an inline condition so the decision is a
/// CALL a companion guard can watch happen, and so the rule that uses it
/// can be EXERCISED on fixtures instead of recognised in source text.
fn denies_absolutely(lowered: &str) -> bool {
    DENIAL_DECISIONS.with(|calls| calls.set(calls.get() + 1));
    ABSOLUTE_NEGATIONS
        .iter()
        .any(|negation| lowered.contains(negation))
}

/// The surfaces the obligation is ON. A sentence that denies the token
/// absolutely must name one of them, or it is denying it of the artefact.
///
/// Matched lowercased, like the mentions: a surface named at the head of a
/// sentence is still that surface.
const VERDICT_SURFACES: [&str; 5] = [
    "`stdout`",
    "`stderr`",
    "verify-sbom",
    "emit-sbom",
    "verdict surface",
];

/// How many sentences of the LIVE document the structural rule below reads
/// as claims about the reserved token -- naming it outright, or inheriting
/// it from the sentence before inside the same unit.
///
/// Measured against `docs/SPEC_SBOM_CANONICAL_V1.md` as it stands: SIX --
/// five that name it outright (Section 3's purl paragraph; the two prose
/// sentences of 7.7 that spell "the token `VERIFIED`" and "the reserved
/// token"; the two sentences of the section 10 checklist item), and one,
/// "`verify-sbom` is not one of them and MUST NOT emit it", that inherits
/// the subject from the sentence before it.
///
/// The floor is set AT the measurement, not below it. The previous floor
/// was 4 against 5 live sentences, which bought nothing but silence for the
/// first deletion; at the measurement, the FIRST sentence that stops being
/// certified is loud, and a legitimate rewrite that merges or drops one
/// says so here and is re-measured on purpose.
const NAMING_SENTENCES: usize = 6;

/// One WRITTEN-OUT sentence per literal of [`ABSOLUTE_NEGATIONS`].
///
/// Written out, and not generated from the list, because a fixture that
/// iterates the list can only ever check the list against ITSELF: drop a
/// literal and the loop simply runs one time fewer, still green. Measured
/// -- dropping `"not printed"`, or `"not emitted"` and `"not printed"`
/// together, left the whole target at 12 passed, and after that mutant a
/// future spec sentence "The reserved token is not printed anywhere." is an
/// unscoped denial nothing catches. `DENIAL_SENTENCES` does not help there:
/// it is a floor on what the LIVE document produces, so it covers only the
/// literals the document already uses -- two of the five.
///
/// Each sentence names the token, carries exactly ONE literal of the list,
/// and names no verdict surface. Dropping that literal from the list makes
/// the sentence stop being a denial, and this fixture reddens.
const DENIAL_FIXTURES: [(&str, &str); 5] = [
    ("never", "The reserved token is never written by this tool."),
    ("must not", "The reserved token must not appear in this file."),
    ("no surface", "No surface of this product writes the reserved token."),
    ("not emitted", "The reserved token is not emitted by this tool."),
    ("not printed", "The reserved token is not printed by this tool."),
];

/// How many of those sentences the LIVE document has `denies_absolutely`
/// call denials.
///
/// Measured against `docs/SPEC_SBOM_CANONICAL_V1.md` as it stands: TWO --
/// the two sentences of the section 10 checklist item, which carry `never`
/// and `MUST NOT` and name `stdout`/`stderr`. Set AT the measurement, for
/// the reason the constant above gives: a floor below it buys silence for
/// exactly as many losses as the gap is wide.
const DENIAL_SENTENCES: usize = 2;

/// True when this line opens a markdown list item -- `-`, `*`, `+`, or an
/// ordered `1.` / `1)` marker -- at any indentation.
fn opens_list_item(line: &str) -> bool {
    let trimmed = line.trim_start();
    if ["- ", "* ", "+ "].iter().any(|m| trimmed.starts_with(m)) {
        return true;
    }
    let digits = trimmed.chars().take_while(char::is_ascii_digit).count();
    digits > 0 && {
        let rest = &trimmed[digits..];
        rest.starts_with(". ") || rest.starts_with(") ")
    }
}

/// True when this line is a markdown table row (header, delimiter or body).
fn is_table_row(line: &str) -> bool {
    line.trim_start().starts_with('|')
}

/// True when this line is an ATX heading or a thematic break -- markdown
/// that separates what is above it from what is below whether or not the
/// author left a blank line.
fn is_block_separator(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.starts_with('#') {
        return true;
    }
    trimmed.len() >= 3
        && ['-', '*', '_']
            .iter()
            .any(|rule| trimmed.chars().all(|c| c == *rule))
}

/// The specification's UNITS of analysis, each unwrapped onto one line.
///
/// A unit is the smallest fragment of markdown in which a claim stands on
/// its own: a paragraph, a single list item, a single table row, a heading
/// or a thematic break. Blank lines alone were not enough, and the gap was
/// measured: `unwrapped` collapses every run of whitespace, so a whole
/// table -- or a whole list -- arrived here as ONE string, and a denial
/// written in row 1 was "satisfied" by a surface named in row 2. A list
/// item therefore begins a unit; a table row, a heading and a thematic
/// break begin one AND end one, because each is exactly one line of
/// markdown and nothing below it is the same claim.
///
/// Line wrapping INSIDE a unit is still undone: the document is
/// hard-wrapped at 90 columns and a sentence that spans two source lines is
/// one sentence to a reader -- including the continuation lines of a list
/// item, which stay with the item that opened it.
fn spec_units(spec: &str) -> Vec<String> {
    let mut units = Vec::new();
    for block in spec.split("\n\n") {
        let mut current: Vec<&str> = Vec::new();
        let mut previous_stands_alone = false;
        for line in block.lines() {
            let stands_alone = is_table_row(line) || is_block_separator(line);
            if (stands_alone || previous_stands_alone || opens_list_item(line))
                && !current.is_empty()
            {
                units.push(unwrapped(&current.join(" ")));
                current.clear();
            }
            current.push(line);
            previous_stands_alone = stands_alone;
        }
        if !current.is_empty() {
            units.push(unwrapped(&current.join(" ")));
        }
    }
    units.retain(|unit| !unit.is_empty());
    units
}

/// A lockfile whose resolved dependency is really named with the reserved
/// token inside it. `verified-fetch` and its scoped siblings are real npm
/// packages; this is the cargo shape of the same fact.
fn lockfile_naming_the_reserved_token() -> String {
    format!(
        "version = 3\n\
         \n\
         [[package]]\n\
         name = \"demo-app\"\n\
         version = \"0.2.0\"\n\
         dependencies = [\n\
         \x20\"{token}-app\",\n\
         ]\n\
         \n\
         [[package]]\n\
         name = \"{token}-app\"\n\
         version = \"1.0.0\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
         checksum = \"{digest}\"\n",
        token = seetrex_verifier::package::RESERVED_TOKEN,
        digest = "a".repeat(64),
    )
}

/// What the structural rule finds in a document: how many sentences it read
/// as claims about the reserved token, and every UNSCOPED denial among them.
struct DenialScan {
    naming: usize,
    /// How many of those sentences `denies_absolutely` called a denial.
    ///
    /// The denial side's non-vacuity. Without it, dropping a literal from
    /// [`ABSOLUTE_NEGATIONS`] is invisible: the fixtures below iterate the
    /// list itself, so a shorter list is checked more shallowly and stays
    /// green -- measured. This counts what the LIVE document produces, so
    /// a dropped literal that the document actually uses shows up as a
    /// smaller number.
    denials: usize,
    unscoped: Vec<String>,
}

/// The rule itself, over an ARBITRARY document.
///
/// A free function rather than a loop inside the guard so the rule can be
/// EXERCISED -- fed a sentence and asked what it decides. That is the only
/// way to establish which list decides denial that does not come down to
/// recognising a shape in the guard's source text, and five rounds of
/// recognising shapes were each defeated by text that merely looked like
/// the check.
fn scan_denials(doc: &str) -> DenialScan {
    let mut scan = DenialScan {
        naming: 0,
        denials: 0,
        unscoped: Vec::new(),
    };
    for unit in spec_units(doc) {
        // The subject carries forward INSIDE a unit. `It is never emitted,
        // in any artefact this tool writes.` names the token to every
        // reader and to no literal list, and it denies it as squarely as
        // the sentence that introduced it -- so a sentence that follows one
        // whose subject is the token inherits that subject. The carry is
        // reset at the unit boundary: a list item, a table row or a fresh
        // paragraph starts a new subject, and inheriting across one would
        // be inventing a claim the document does not make.
        let mut subject_is_the_token = false;
        for sentence in unit.split(". ") {
            let sentence = sentence.trim();
            if sentence.is_empty() {
                continue;
            }
            let lowered = sentence.to_lowercase();
            if RESERVED_TOKEN_MENTIONS
                .iter()
                .any(|mention| lowered.contains(mention))
            {
                subject_is_the_token = true;
            }
            if !subject_is_the_token {
                continue;
            }
            scan.naming += 1;
            if !denies_absolutely(&lowered) {
                continue;
            }
            scan.denials += 1;
            if !VERDICT_SURFACES
                .iter()
                .any(|surface| lowered.contains(surface))
            {
                let mut record = String::from(sentence);
                record.push_str("\n--- in this unit ---\n");
                record.push_str(&unit);
                scan.unscoped.push(record);
            }
        }
    }
    scan
}

/// INTENT: the reserved-token obligation of the specification names the
///   surfaces it is ON -- the `stdout` and `stderr` a verdict reaches a
///   reader through -- and does not claim the token is never emitted at
///   all. The canonical bytes are a faithful projection: a dependency whose
///   real name carries the token is projected under its real name, and an
///   `emit-sbom` artefact therefore contains the literal.
/// CONTEXT: section 10 read "the reserved token is never emitted" and the
///   crate's own doc comment read "no surface of this product ever prints
///   the token itself". Both were false of the emitted artefact, and false
///   in the direction that matters: an implementer reading them would
///   conclude the projection has to rename or mask a real package, which
///   would forge the bill of materials to protect a downstream `grep`. The
///   sanitizer never did that -- it guards report lines -- so the document
///   overstated what the code does and understated what the artefact holds.
///   The first version of this guard read the ONE checklist item that
///   speaks about the token, which pinned the corrected wording exactly
///   where it already stood and nowhere else: putting the false sentence
///   back into the normative prose of section 7 left the guard green and
///   an implementer reading section 7 none the wiser. A claim about a
///   document is a claim about ALL of it, so the denial is now stated over
///   every sentence -- by name for the phrasings already written, and
///   structurally for the ones nobody has written yet. That structural half
///   claimed more than it did for one round: it matched the naming tokens
///   CASE-SENSITIVELY, so a mention that opens a sentence escaped it, and
///   it took a blank-line block as its unit while collapsing all whitespace
///   inside it, so a whole table or a whole list was ONE string and a
///   denial in row 1 was "satisfied" by a surface named in row 2. Three
///   unscoped denials were written and all three passed -- measured. The
///   unit is now the list item and the table row as well as the paragraph,
///   the naming tokens are matched lowercased, and a sentence with no
///   naming token inherits the subject of the one before it inside the same
///   unit, which is how a pronoun ("It is never emitted") is read.
///   LIMIT, measured and NOT closed: the structural half is structural in
///   how a sentence NAMES the token and where a unit begins, never in how
///   it DENIES. Denial is decided by `ABSOLUTE_NEGATIONS`, a fixed list of
///   literals, so an absolute denial written in words that list does not
///   carry -- `The reserved token appears nowhere in any artefact this
///   tool writes.`, an unscoped claim as false as the ones named above --
///   is read as a claim about the token, is never read as a denial, and is
///   therefore never asked to name a surface. It was written into the
///   document and the guard stayed green. English absolute negation is
///   unbounded (`nowhere`, `at no point`, `in no artefact`, `absent
///   from`), so no list closes the class: this list is a floor under the
///   phrasings already written, never a proof that the document cannot say
///   it again in a phrasing nobody has written yet. The companion guard
///   `test_intent_reserved_token_guard_declares_its_denial_list_limit`
///   requires three SUBSTRINGS of this paragraph to be present byte for
///   byte; it requires the guard above to still exist under that name; it
///   RUNS that guard and requires the run to REACH the denial decision;
///   and it EXERCISES the rule that decision belongs to, checking that
///   every literal of `ABSOLUTE_NEGATIONS` turns a fixture sentence into
///   an unscoped denial, that the same sentence naming a verdict surface
///   is not one, and that a sentence carrying no literal of the list is
///   not one either. None of that reads the guard's source. Those fixtures
///   iterate the list itself, so they cannot see it SHRINK; what does is
///   `DENIAL_SENTENCES`, the floor the guard above carries on how many
///   denials the live document produces -- measured, dropping a literal
///   the document relies on reddens that instead. Of this prose it
///   requires nothing else, and a substring
///   survives any sentence built around it: measured, it stays GREEN when
///   a paragraph is inserted above declaring the limit closed, and when
///   these sentences are rewritten in place into their own negations with
///   the three substrings untouched. What is measured is those three
///   requirements and nothing about what may be written AROUND the
///   substrings.
/// EXPIRES IF: `emit-sbom` stops writing a faithful projection of the
///   lockfile, or the token stops being reserved.
/// MUTANT: restore "the reserved token is never emitted" to the section 10
///   item; add it to the normative prose of section 7 instead; write the
///   same claim in words the literal list does not carry ("An
///   implementation MUST NOT emit the reserved token"); open the sentence
///   with the mention ("The token MUST NOT be printed anywhere this product
///   writes."); write it as a pronoun in the sentence after the one that
///   names the token ("It is never emitted, in any artefact this tool
///   writes."); write it as row 1 of a two-row table whose row 2 names
///   `stdout`; drop `stdout`/`stderr` from the checklist item; make the
///   projection mask or rename a component whose name carries the token.
#[test]
fn test_intent_spec_reserved_token_obligation_is_scoped_to_verdict_surfaces() {
    let spec = spec_text();
    let item = printed_reserved_token_item(&spec);

    assert!(
        item.contains("`stdout`") && item.contains("`stderr`"),
        "the section 10 item about the reserved token does not name the surfaces the \
         obligation is on. An unscoped prohibition reads as a rule about the artefact, \
         which the artefact does not and must not obey. It reads:\n{item}"
    );

    // ... and the claim is false WHEREVER it stands, so it is denied over
    // the whole document. Pinning it in this one checklist item left the
    // normative prose of section 7 free to restore the sentence with the
    // guard silent -- measured.
    let lowered = spec.to_lowercase();
    for claim in FORBIDDEN_UNSCOPED_CLAIMS {
        assert!(
            !lowered.contains(claim),
            "{} carries the sentence `{claim}`. The canonical bytes carry the token \
             whenever a real dependency is named with it, so the claim is false of the \
             one artefact an auditor keeps -- and false in the direction that matters, \
             because an implementer reading it would mask or rename a real package.",
            spec_path().display()
        );
    }

    // A literal list only forbids the phrasings somebody already wrote.
    // The rule underneath it is structural: a sentence of this document
    // that names the reserved token AND denies it absolutely must name the
    // surface the denial is about.
    // The rule, run over the live document. Its OUTPUT is what this guard
    // asserts on.
    let scan = scan_denials(&spec);
    assert!(
        scan.unscoped.is_empty(),
        "{} sentence(s) of {} deny the reserved token absolutely and name no surface \
         the denial is about, so each reads as a rule about the ARTEFACT -- which \
         the artefact does not and must not obey:\n{}",
        scan.unscoped.len(),
        spec_path().display(),
        scan.unscoped.join("

")
    );
    let naming = scan.naming;

    // The DENIAL side's non-vacuity, and it is a MEASUREMENT like the one
    // below: the live document puts exactly DENIAL_SENTENCES sentences
    // through `denies_absolutely` and gets a denial back. Set AT the
    // measurement, because the fixtures in the companion guard iterate
    // `ABSOLUTE_NEGATIONS` itself -- a shorter list is checked more
    // shallowly and stays green there. Here a literal the document
    // actually uses cannot be dropped without this number falling.
    assert!(
        scan.denials >= DENIAL_SENTENCES,
        "only {} sentences of {} are read as absolute DENIALS, and {DENIAL_SENTENCES} \
         were measured when this floor was written. Either the document stopped denying \
         the token, or a literal it relies on has left `ABSOLUTE_NEGATIONS`.",
        scan.denials,
        spec_path().display()
    );
    // Non-vacuity. The number is a MEASUREMENT, not a margin: under the
    // unit-of-analysis above the live document puts exactly NAMING_SENTENCES
    // sentences under this rule (measured, see the constant), and the floor
    // is set AT that count so the FIRST sentence that stops being certified
    // -- a deleted mention, a merged pair, a split that drifts -- is loud.
    // A floor below the measurement buys nothing but silence for exactly as
    // many deletions as the gap is wide.
    assert!(
        naming >= NAMING_SENTENCES,
        "only {naming} sentences of {} are read as claims about the reserved token, and \
         {NAMING_SENTENCES} were measured when this floor was written; the rule above now \
         certifies less than it did. Either the document stopped discussing the token or \
         the unit split has drifted.",
        spec_path().display()
    );

    // And the code is the third party to the agreement: the emitted bytes
    // really do carry the literal, so the unscoped claim is not merely
    // imprecise -- it is refuted by the reference implementation.
    let subject = SubjectPurl::parse(REFERENCE_SUBJECT)
        .unwrap_or_else(|error| panic!("the reference subject was rejected: {error}"));
    let document = cargo::project_lockfile(&lockfile_naming_the_reserved_token(), subject)
        .unwrap_or_else(|error| {
            panic!(
                "a lockfile resolving a dependency whose real name carries the reserved \
                 token must project, not fail: {error}"
            )
        })
        .to_cyclonedx();
    let bytes = canonical_bytes(&document);
    assert!(
        bytes.contains(seetrex_verifier::package::RESERVED_TOKEN),
        "the projection of a lockfile that resolves `{}-app` does not carry that name in \
         its canonical bytes: the artefact is no longer a faithful projection, and the \
         scoped wording section 10 now carries would be describing something else.\n{bytes}",
        seetrex_verifier::package::RESERVED_TOKEN
    );
}

/// This file's own bytes.
///
/// The guard below is about what the prose of the guard ABOVE claims, and
/// the only authority for that is the source it is written in.
fn own_source() -> String {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/intent_sbom_spec_matches_code.rs");
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// The `///` prose attached to the test called `name`, unwrapped onto one
/// line.
///
/// Attributes between the prose and the declaration are stepped over:
/// `#[test]` stands there in every case, and a doc comment separated from
/// its item by an attribute is still that item's doc comment.
fn test_prose(source: &str, name: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let at = lines
        .iter()
        .position(|line| line.trim_start().starts_with(&format!("fn {name}(")))
        .unwrap_or_else(|| panic!("no line of this file declares `fn {name}`; it has moved"));
    let mut doc: Vec<&str> = Vec::new();
    for line in lines[..at].iter().rev() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("///") {
            doc.push(rest);
            continue;
        }
        if trimmed.starts_with("#[") {
            continue;
        }
        break;
    }
    assert!(
        !doc.is_empty(),
        "`fn {name}` carries no `///` prose at all, so there is nothing to check"
    );
    doc.reverse();
    unwrapped(&doc.join(" "))
}


/// The name of the guard whose limit is declared.
const SCOPED_OBLIGATION_GUARD: &str =
    "test_intent_spec_reserved_token_obligation_is_scoped_to_verdict_surfaces";

/// What that guard's prose MUST keep saying about the half of it that is
/// a literal list.
///
/// Three fragments, not one, so a rewrite that keeps the words and drops
/// the claim is caught: the DIRECTION of the limit (naming is structural,
/// denial is not), the NAME of the list that decides it, and the refusal
/// to call the class closed.
const DENIAL_LIMIT_STATEMENTS: [&str; 3] = [
    "never in how it DENIES",
    "Denial is decided by `ABSOLUTE_NEGATIONS`, a fixed list of literals",
    "no list closes the class",
];

/// INTENT: the guard that scopes the reserved-token obligation STATES the
///   half of itself it does not close. Its denial side is a fixed list of
///   literals; a claim it cannot make must not be re-asserted in its own
///   prose, because the prose is what a later reader trusts when deciding
///   whether the class is covered.
/// CONTEXT: that prose read "structurally for the ones nobody has written
///   yet", which is true of how a sentence NAMES the token and false of
///   how a sentence DENIES it. `The reserved token appears nowhere in any
///   artefact this tool writes.` -- unscoped, absolute, and false of the
///   emitted bytes -- names the token, matches no literal of
///   `ABSOLUTE_NEGATIONS`, is therefore never asked to name a surface, and
///   passes. A guard cannot be widened into English, so the honest move is
///   to keep the strongest approximation available and refuse to describe
///   it as more than it is. Left to prose alone that refusal survives
///   exactly until somebody tidies the paragraph.
///   WHAT THIS GUARD MEASURES, and only that: three SUBSTRINGS of that
///   refusal must be present byte for byte; the guard it is about must
///   still exist under that name; RUNNING it must reach the denial
///   decision; and the rule that decision belongs to is EXERCISED against
///   every literal of `ABSOLUTE_NEGATIONS`. That last requirement used to
///   be a SOURCE PIN, and five rounds of them were each defeated by text
///   that merely looked like the check -- a comment in front of it, a
///   QUOTATION of it in a `let _note`, a quote-bearing char literal
///   written with an ESCAPE, a raw C string. Rust's literal grammar has
///   `b`, `r`, `br`, `c`, `cr` and whatever the next edition adds, so a
///   check that must enumerate literal prefixes to stay honest keeps
///   losing; behaviour does not have to. Nothing
///   else about the prose is measured: a paragraph inserted above
///   declaring the limit closed is GREEN, and so is the refusal rewritten
///   in place into its own negation with all three substrings intact.
///   Forbidding every way of contradicting a paragraph is the same
///   unbounded problem as forbidding every way of denying a token, one
///   level up, so it is not attempted, and this comment says so rather
///   than implying otherwise.
/// EXPIRES IF: the denial side stops being a literal list -- a guard that
///   really does decide denial structurally makes this statement false,
///   and it must then be deleted rather than kept.
/// MUTANT: delete the LIMIT paragraph from the guard's prose; reword it so
///   it no longer names `ABSOLUTE_NEGATIONS`; put "structurally for the
///   ones nobody has written yet" back as an unqualified claim by dropping
///   the "no list closes the class" clause; rename the guard it is about,
///   which stops the file compiling; drop ANY literal from
///   `ABSOLUTE_NEGATIONS` (each has a written-out fixture sentence, so the
///   two the live document does not use are covered too -- they were not
///   before, and it was measured); add a literal without a fixture; make
///   `denies_absolutely` decide by anything else; make the guard stop
///   reaching it.
///   NOT CAUGHT, and measured so: a `RESOLVED` paragraph inserted above
///   the LIMIT heading that keeps every pinned sentence intact, and a
///   rewrite of those sentences into their own negations around the
///   untouched substrings.
#[test]
fn test_intent_reserved_token_guard_declares_its_denial_list_limit() {
    let source = own_source();
    let prose = test_prose(&source, SCOPED_OBLIGATION_GUARD);
    for statement in DENIAL_LIMIT_STATEMENTS {
        assert!(
            prose.contains(statement),
            "the prose of `{SCOPED_OBLIGATION_GUARD}` no longer says `{statement}`. Its \
             denial side is `ABSOLUTE_NEGATIONS`, a fixed list of literals, and a \
             paragraph that stops saying so reads as a guard covering a class it does \
             not cover. It reads:\n{prose}"
        );
    }
    // NON-VACUITY, BY EXECUTION, in two halves. The declaration says the
    // guard decides denial with that list; the way to know is to RUN it and
    // then to EXERCISE the rule it runs.
    //
    // Every source-READING version of this check lost the same race.
    // Naming the constant was satisfied by a commented-out check; pinning
    // the whole condition, by a block comment around the real line;
    // stripping comments first, by a QUOTATION of the condition in a
    // `let _note`; and refusing the literal shapes that stripper could not
    // pair, by a quote-bearing char literal written with an ESCAPE and by a
    // raw C string. Rust's literal grammar has `b`, `r`, `br`, `c`, `cr`
    // and whatever the next edition adds, so a check that must enumerate
    // literal prefixes to stay honest keeps losing.
    //
    // FIRST HALF: the guard must REACH the decision at all.
    let before = DENIAL_DECISIONS.with(std::cell::Cell::get);
    test_intent_spec_reserved_token_obligation_is_scoped_to_verdict_surfaces();
    let after = DENIAL_DECISIONS.with(std::cell::Cell::get);
    assert!(
        after > before,
        "running `{SCOPED_OBLIGATION_GUARD}` decided denial not once, so the limit its \
         prose declares is a limit of nothing: the guard no longer reaches the decision \
         the paragraph describes"
    );

    // SECOND HALF: and the rule it reaches is decided BY THAT LIST. Every
    // literal on it turns a fixture sentence into an unscoped denial; the
    // same sentence naming a verdict surface is not one; and a sentence
    // carrying no literal of the list is not one either. A
    // `denies_absolutely` rewritten to consult anything else fails one of
    // these, whatever its source looks like.
    // The corpus and the list must COVER each other, both ways round, or
    // the fixtures below check a set that has drifted from the one that
    // decides.
    for negation in ABSOLUTE_NEGATIONS {
        assert!(
            DENIAL_FIXTURES.iter().any(|(literal, _)| *literal == negation),
            "`{negation}` is on `ABSOLUTE_NEGATIONS` and no fixture exercises it, so \
             dropping it from the list would be invisible here"
        );
    }
    for (literal, sentence) in DENIAL_FIXTURES {
        // This is the assertion a DROPPED literal fires, and it fires
        // before the scan below is reached at all.
        assert!(
            ABSOLUTE_NEGATIONS.contains(&literal),
            "the fixture for `{literal}` no longer matches any literal of \
             `ABSOLUTE_NEGATIONS`: the list lost it, or the fixture drifted"
        );
        // ... and the row really tests the literal it is filed under:
        // one of the list, and only that one.
        let lowered = sentence.to_lowercase();
        let carried: Vec<&str> = ABSOLUTE_NEGATIONS
            .into_iter()
            .filter(|negation| lowered.contains(negation))
            .collect();
        assert_eq!(
            carried,
            vec![literal],
            "the fixture sentence for `{literal}` carries {carried:?} of \
             `ABSOLUTE_NEGATIONS`; it must carry exactly the one it is filed under, \
             or it is not evidence about that literal"
        );
        assert_eq!(
            scan_denials(sentence).unscoped.len(),
            1,
            "`{literal}` is on `ABSOLUTE_NEGATIONS` and the rule does not read \
             `{sentence}` as an unscoped denial: that list is not what decides"
        );
        let scoped = sentence.replace(" by this tool.", " on `stdout`.")
            .replace(" in this file.", " on `stdout`.")
            .replace(" the reserved token.", " the reserved token on `stdout`.");
        assert_ne!(
            scoped, sentence,
            "the scoped variant of `{sentence}` was not built: the fixture text changed \
             and this half now checks the unscoped sentence twice"
        );
        assert!(
            scan_denials(&scoped).unscoped.is_empty(),
            "the rule reports `{scoped}` as UNSCOPED although it names a verdict surface"
        );
    }
    assert!(
        scan_denials("The reserved token appears in the canonical bytes.")
            .unscoped
            .is_empty(),
        "the rule reads a sentence carrying no literal of `ABSOLUTE_NEGATIONS` as a \
         denial, so something other than that list is deciding"
    );
}

/// The `///` comment immediately above the line that declares `anchor`.
///
/// Unwrapped onto one line, because a doc comment is hard-wrapped source
/// and the sentence a reader sees spans several lines of it.
fn doc_comment_above(source: &str, anchor: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let at = lines
        .iter()
        .position(|line| line.trim_start().starts_with(anchor))
        .unwrap_or_else(|| {
            panic!("no line of `src/package.rs` declares `{anchor}`; the anchor has moved")
        });
    let mut doc: Vec<&str> = Vec::new();
    for line in lines[..at].iter().rev() {
        let Some(rest) = line.trim_start().strip_prefix("///") else {
            break;
        };
        doc.push(rest);
    }
    doc.reverse();
    unwrapped(&doc.join(" "))
}

/// INTENT: the doc comment of `is_reserved_token` -- the one place the CODE
///   states what the reserved-token obligation is ON -- says out loud that
///   the emitted artefact CONTAINS the literal, and that what the sanitizer
///   enforces is that no VERDICT surface prints it. It is pinned here for
///   the same reason the specification's wording is pinned above: this
///   comment is what an implementer of the public crate reads.
/// CONTEXT: the comment read "no surface of this product ever prints the
///   token itself", which is false of `emit-sbom`'s output and false in the
///   direction that makes an implementer forge a bill of materials. The
///   correction was written and nothing held it: reverting the paragraph
///   left the whole verifier suite green (371 tests, measured), so the
///   crate could return to its false claim in one edit and no gate would
///   say so. A corrected sentence bound by nothing is a sentence that
///   un-corrects itself at the next revert.
/// EXPIRES IF: `emit-sbom` stops writing a faithful projection of the
///   lockfile, at which point masking becomes the honest behaviour and this
///   paragraph has to change with it.
/// MUTANT: restore "no surface of this product ever prints the token
///   itself" as the comment's claim; delete the paragraph; drop the word
///   `VERDICT` from it.
#[test]
fn test_intent_reserved_token_docstring_scopes_the_obligation_to_verdict_surfaces() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/package.rs");
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let doc = doc_comment_above(&source, "pub fn is_reserved_token(");

    for required in [
        "the EMITTED ARTEFACT contains the literal",
        "no surface that carries a VERDICT prints it",
    ] {
        assert!(
            doc.contains(required),
            "the doc comment of `is_reserved_token` no longer says `{required}`. It is the \
             only place the crate states what the obligation is ON, and the claim it \
             replaced -- that no surface ever prints the token -- is false of the artefact \
             `emit-sbom` writes. It reads:\n{doc}"
        );
    }
}
