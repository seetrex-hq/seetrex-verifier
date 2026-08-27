// SPDX-License-Identifier: Apache-2.0
//! The cross-ecosystem, cross-platform reproducibility layer of the canonical
//! SBOM projection.
//!
//! `src/sbom/{cargo,composer,npm}.rs` each carry their own reproducibility
//! tests, one ecosystem at a time. This file is the layer above them: a single
//! corpus, described by data rather than by code
//! (`tests/fixtures/sbom/corpus/manifest.json`), whose every entry is projected
//! through the same four obligations regardless of which ecosystem it came
//! from. Adding an ecosystem, or a lockfile shape, is an edit to the manifest
//! and to nothing else -- so the obligations cannot be met for two ecosystems
//! and quietly skipped for the third.
//!
//! The obligations are Section 8 of `docs/SPEC_SBOM_CANONICAL_V1.md`:
//!
//! 1. **Frozen pin** -- every corpus entry projects to the SHA-256 the manifest
//!    records. Section 8 states the obligation for the specification's own
//!    reference vector (guarded in `intent_sbom_spec_matches_code.rs`); here it
//!    is carried across all three ecosystems at once.
//! 2. **Line endings** -- the CRLF copy is built in memory, at test time. A CRLF
//!    fixture committed to this repository would be normalised back to LF on
//!    checkout (`.gitattributes`) and the test would certify its own copy.
//! 3. **Byte-order mark** -- a lockfile that begins with a UTF-8 BOM is rejected
//!    loudly, never parsed into a first package whose name silently carries
//!    `U+FEFF`.
//! 4. **Two-run stability** -- projecting one input twice in one process yields
//!    the same bytes, which is what catches an unordered map iteration.
//! 6. **Real-lockfile invariants** -- the four actual lockfiles of the PRIVATE
//!    repository this crate is developed in project, re-canonicalise to
//!    themselves, and satisfy the structural invariants, with **no count and
//!    no hash pinned**: a dependency bump must never turn this file red.
//!    Those lockfiles are not part of the published source tree, so that one
//!    obligation runs behind the `SEETREX_PRIVATE_TREE` gate (`private_tree`
//!    below): set in the private CI, unset in an exported checkout, where the
//!    test prints its skip line instead of panicking on a file that was never
//!    exported. Obligations 1-5 need no private tree and run everywhere.
//!
//! ## Obligation 5, platform independence, and how it is met here
//!
//! Continuous integration for this repository runs Linux runners only
//! (`.forgejo/workflows/security.yml`), and the workspace test step
//! `cargo test (workspace, lib + integration)` includes this crate's
//! integration tests -- with `SEETREX_PRIVATE_TREE` set on that step, so
//! obligation 6 runs there on every push too. The development machine these
//! pins were computed on runs Windows.
//!
//! That is the whole cross-platform instrument, and it needs no second runner:
//! the pins in `manifest.json` are constants in a file, and both machines
//! compare their own freshly computed bytes against the SAME constants. If a
//! serializer, a float formatter, a path separator or a line-ending assumption
//! made the two operating systems disagree by one byte, one of the two runs
//! goes red against a value the other one produced. A second CI job would
//! restate the obligation without adding a second platform, so none is added.
//!
//! The one edit forbidden here is recomputing a pin to make a run green: that
//! turns a measurement into a transcription and retires the instrument in
//! silence. A pin moves only in the same change that moves the projection
//! identifier to `lockfile-v2`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use seetrex_format::hashing::canonicalize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use seetrex_verifier::sbom::{cargo, composer, npm, Projection, SbomError, SubjectPurl};

/// The private-tree gate, pulled in from the crate source rather than copied:
/// the unit tests of `src/sbom/{cargo,composer,npm}.rs` compile the very same
/// file, so there is ONE gate with ONE behaviour, not two that drift.
#[path = "../src/sbom/private_tree.rs"]
mod private_tree;
use private_tree::{private_tree, read_private_file};

// ---------------------------------------------------------------------------
// The corpus, read from data
// ---------------------------------------------------------------------------

/// One corpus entry: an immutable synthetic lockfile, the subject an auditor
/// supplies for it, and the canonical hash it must project to.
struct CorpusEntry {
    id: String,
    kind: String,
    lockfile: String,
    manifest: Option<String>,
    subject: String,
    canonical_sha256: String,
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sbom")
}

fn read_fixture(relative: &str) -> String {
    let path = fixture_dir().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "the corpus names a fixture that cannot be read at {}: {error}. \
             A corpus entry pointing at nothing would pass every obligation \
             by testing nothing.",
            path.display()
        )
    })
}

/// The corpus manifest, parsed and validated.
///
/// The validation is not decoration: an entry with a missing field, a
/// duplicated id or a composer entry without its root manifest would be a
/// silently weaker corpus, and the whole point of describing the corpus as data
/// is that its coverage is readable rather than inferred.
fn corpus() -> Vec<CorpusEntry> {
    let path = fixture_dir().join("corpus/manifest.json");
    let text = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "the corpus manifest could not be read at {}: {error}",
            path.display()
        )
    });
    let document: Value = serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("the corpus manifest is not valid JSON: {error}"));
    let raw = document["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("the corpus manifest carries no `entries` array"));
    assert!(
        !raw.is_empty(),
        "the corpus manifest lists no entry: every obligation below would \
         iterate over nothing and pass"
    );

    let string = |value: &Value, key: &str, id: &str| -> String {
        value[key]
            .as_str()
            .unwrap_or_else(|| panic!("corpus entry `{id}` carries no string `{key}`"))
            .to_string()
    };

    let entries: Vec<CorpusEntry> = raw
        .iter()
        .map(|value| {
            let id = string(value, "id", "<unnamed>");
            let kind = string(value, "kind", &id);
            let manifest = match &value["manifest"] {
                Value::Null => None,
                Value::String(name) => Some(name.clone()),
                other => panic!("corpus entry `{id}` carries a non-string manifest: {other}"),
            };
            assert_eq!(
                kind == "composer",
                manifest.is_some(),
                "corpus entry `{id}`: composer projections need the root manifest as a \
                 second input and the other ecosystems have none"
            );
            let canonical_sha256 = string(value, "canonical_sha256", &id);
            assert!(
                canonical_sha256.len() == 64
                    && canonical_sha256
                        .chars()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "corpus entry `{id}` pins `{canonical_sha256}`, which is not a \
                 lowercase hex SHA-256"
            );
            CorpusEntry {
                lockfile: string(value, "lockfile", &id),
                subject: string(value, "subject", &id),
                kind,
                manifest,
                canonical_sha256,
                id,
            }
        })
        .collect();

    let ids: BTreeSet<&str> = entries.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(
        ids.len(),
        entries.len(),
        "the corpus carries duplicated entry ids: {:?}",
        entries.iter().map(|e| &e.id).collect::<Vec<_>>()
    );
    let kinds: BTreeSet<&str> = entries.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(
        kinds,
        BTreeSet::from(["cargo", "composer", "npm"]),
        "the corpus must cover every ecosystem the projection claims to \
         support; a missing ecosystem is an obligation met for the others and \
         mute for that one"
    );
    let pins: BTreeSet<&str> = entries
        .iter()
        .map(|e| e.canonical_sha256.as_str())
        .collect();
    assert_eq!(
        pins.len(),
        entries.len(),
        "two corpus entries pin the same hash: two different lockfiles cannot \
         project to the same bytes, so one pin was copied rather than measured"
    );
    entries
}

fn subject_of(entry: &CorpusEntry) -> SubjectPurl {
    SubjectPurl::parse(&entry.subject).unwrap_or_else(|error| {
        panic!(
            "corpus entry `{}` names the subject `{}`, which is not a purl: {error}",
            entry.id, entry.subject
        )
    })
}

/// Project one corpus entry from the texts supplied, whatever ecosystem it
/// belongs to.
///
/// The texts are parameters rather than being read here, because the mutant
/// obligations project the SAME entry from a mutated copy of its bytes.
fn project(
    entry: &CorpusEntry,
    lockfile_text: &str,
    manifest_text: Option<&str>,
) -> Result<Projection, SbomError> {
    let subject = subject_of(entry);
    match entry.kind.as_str() {
        "cargo" => cargo::project_lockfile(lockfile_text, subject),
        "composer" => composer::project_lockfile(lockfile_text, manifest_text, subject),
        "npm" => npm::project_lockfile(lockfile_text, subject),
        other => panic!(
            "corpus entry `{}` names an unknown kind `{other}`",
            entry.id
        ),
    }
}

/// Read the entry's inputs and project them.
fn project_entry(entry: &CorpusEntry) -> Projection {
    let lockfile_text = read_fixture(&entry.lockfile);
    let manifest_text = entry.manifest.as_ref().map(|name| read_fixture(name));
    project(entry, &lockfile_text, manifest_text.as_deref())
        .unwrap_or_else(|error| panic!("corpus entry `{}` fails to project: {error}", entry.id))
}

fn sha256_hex(bytes: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// The structural invariants, as a checker rather than as assertions
// ---------------------------------------------------------------------------

/// The seven top-level keys Section 5.1 permits, and no eighth.
const ALLOWED_TOP_LEVEL_KEYS: [&str; 7] = [
    "bomFormat",
    "components",
    "dependencies",
    "metadata",
    "properties",
    "specVersion",
    "version",
];

/// Keys a component may carry (Section 5.2). `group`, `scope` and `hashes` are
/// ecosystem-dependent; the other five are always present.
const ALLOWED_COMPONENT_KEYS: [&str; 8] = [
    "bom-ref", "group", "hashes", "name", "purl", "scope", "type", "version",
];

/// Keys that make a document depend on when or where it was emitted. Section
/// 5.1 forbids both by name; they are searched for at every depth because a
/// nested one would be just as fatal to reproducibility as a top-level one.
const VOLATILE_KEYS: [&str; 2] = ["serialNumber", "timestamp"];

/// Check the structural invariants of an emitted document.
///
/// This returns `Result` rather than asserting, for one reason: a checker whose
/// only user is the happy path is itself unchecked. Returning an error lets
/// `test_intent_corpus_invariants_reject_mutated_documents` hand it deliberately
/// broken documents and observe that it says so -- which is the only evidence
/// that a green run of the other tests means anything.
fn check_document_invariants(doc: &Value) -> Result<(), String> {
    let object = doc
        .as_object()
        .ok_or_else(|| "the document is not a JSON object".to_string())?;

    let keys: Vec<&str> = object.keys().map(String::as_str).collect();
    if keys != ALLOWED_TOP_LEVEL_KEYS {
        return Err(format!(
            "top-level keys must be exactly {ALLOWED_TOP_LEVEL_KEYS:?}, found {keys:?}"
        ));
    }
    if object["bomFormat"] != json!("CycloneDX") {
        return Err(format!("bomFormat is {}", object["bomFormat"]));
    }
    if object["specVersion"] != json!("1.5") {
        return Err(format!("specVersion is {}", object["specVersion"]));
    }
    // `version` is the only number in the document and it must be the INTEGER
    // 1. A float would serialise as `1.0` under some encoders and `1` under
    // others, which is a byte divergence with no observable cause.
    if !matches!(object["version"].as_u64(), Some(1)) {
        return Err(format!(
            "version must be the integer 1, found {}",
            object["version"]
        ));
    }

    find_volatile_key(doc)?;

    // metadata carries exactly one key, and the subject declares its own
    // bom-ref.
    let metadata = object["metadata"]
        .as_object()
        .ok_or_else(|| "metadata is not an object".to_string())?;
    let metadata_keys: Vec<&str> = metadata.keys().map(String::as_str).collect();
    if metadata_keys != ["component"] {
        return Err(format!(
            "metadata must carry exactly `component`, found {metadata_keys:?}"
        ));
    }
    let subject = metadata["component"]
        .as_object()
        .ok_or_else(|| "metadata.component is not an object".to_string())?;
    if subject.get("type") != Some(&json!("application")) {
        return Err("metadata.component.type must be `application`".to_string());
    }
    let subject_purl = check_self_reference(subject, "metadata.component")?;

    // Components: every one self-referential, the whole array strictly
    // increasing over purls, which is a total order because the purl carries
    // the version.
    let components = object["components"]
        .as_array()
        .ok_or_else(|| "components is not an array".to_string())?;
    let mut declared: BTreeSet<String> = BTreeSet::new();
    declared.insert(subject_purl.clone());
    let mut previous: Option<String> = None;
    for (index, component) in components.iter().enumerate() {
        let component = component
            .as_object()
            .ok_or_else(|| format!("component {index} is not an object"))?;
        for key in component.keys() {
            if !ALLOWED_COMPONENT_KEYS.contains(&key.as_str()) {
                return Err(format!("component {index} carries a forbidden key `{key}`"));
            }
        }
        if component.get("type") != Some(&json!("library")) {
            return Err(format!("component {index} is not of type `library`"));
        }
        let purl = check_self_reference(component, &format!("component {index}"))?;
        if let Some(previous) = &previous {
            if previous.as_str() >= purl.as_str() {
                return Err(format!(
                    "component order must be strictly increasing over purls: \
                     `{previous}` is not before `{purl}`"
                ));
            }
        }
        if !declared.insert(purl.clone()) {
            return Err(format!("`{purl}` is declared as a bom-ref twice"));
        }
        previous = Some(purl);
    }

    // The graph: exactly one entry, rooted at the subject, every edge
    // resolving against a declared bom-ref.
    let dependencies = object["dependencies"]
        .as_array()
        .ok_or_else(|| "dependencies is not an array".to_string())?;
    if dependencies.len() != 1 {
        return Err(format!(
            "the graph must carry exactly one entry, found {}",
            dependencies.len()
        ));
    }
    let edge = dependencies[0]
        .as_object()
        .ok_or_else(|| "the graph entry is not an object".to_string())?;
    let edge_keys: Vec<&str> = edge.keys().map(String::as_str).collect();
    if edge_keys != ["dependsOn", "ref"] {
        return Err(format!(
            "the graph entry must carry exactly `dependsOn` and `ref`, found {edge_keys:?}"
        ));
    }
    if edge["ref"] != json!(subject_purl) {
        return Err(format!(
            "the graph is rooted at {} rather than at the subject `{subject_purl}`",
            edge["ref"]
        ));
    }
    let depends_on = edge["dependsOn"]
        .as_array()
        .ok_or_else(|| "dependsOn is not an array".to_string())?;
    let mut previous: Option<&str> = None;
    for value in depends_on {
        let reference = value
            .as_str()
            .ok_or_else(|| format!("dependsOn carries a non-string entry {value}"))?;
        if let Some(previous) = previous {
            if previous >= reference {
                return Err(format!(
                    "dependsOn must be strictly increasing over purls: \
                     `{previous}` is not before `{reference}`"
                ));
            }
        }
        if !declared.contains(reference) {
            return Err(format!(
                "dependsOn names `{reference}`, which no bom-ref in the document declares"
            ));
        }
        previous = Some(reference);
    }

    // The self-description: sorted by name, unique, and inside the reserved
    // prefix, so no property can be mistaken for a standard one.
    let properties = object["properties"]
        .as_array()
        .ok_or_else(|| "properties is not an array".to_string())?;
    let mut previous: Option<&str> = None;
    for property in properties {
        let property = property
            .as_object()
            .ok_or_else(|| "a property is not an object".to_string())?;
        let property_keys: Vec<&str> = property.keys().map(String::as_str).collect();
        if property_keys != ["name", "value"] {
            return Err(format!(
                "a property must carry exactly `name` and `value`, found {property_keys:?}"
            ));
        }
        let name = property["name"]
            .as_str()
            .ok_or_else(|| "a property name is not a string".to_string())?;
        if !name.starts_with("seetrex:sbom.") {
            return Err(format!("property `{name}` is outside the reserved prefix"));
        }
        if property["value"].as_str().is_none() {
            return Err(format!("property `{name}` carries a non-string value"));
        }
        if let Some(previous) = previous {
            if previous >= name {
                return Err(format!(
                    "properties must be strictly increasing over names: \
                     `{previous}` is not before `{name}`"
                ));
            }
        }
        previous = Some(name);
    }

    Ok(())
}

/// The `bom-ref` of an object equals its own `purl`, and both are present.
fn check_self_reference(object: &Map<String, Value>, what: &str) -> Result<String, String> {
    let purl = object
        .get("purl")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{what} carries no purl"))?;
    let bom_ref = object
        .get("bom-ref")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{what} carries no bom-ref"))?;
    if purl != bom_ref {
        return Err(format!(
            "{what} declares bom-ref `{bom_ref}` for purl `{purl}`; a reference \
             that is not the identity makes the graph depend on something other \
             than the lockfile"
        ));
    }
    if object.get("name").and_then(Value::as_str).is_none() {
        return Err(format!("{what} carries no name"));
    }
    if object.get("version").and_then(Value::as_str).is_none() {
        return Err(format!("{what} carries no version"));
    }
    Ok(purl.to_string())
}

/// Search every depth for a key whose presence would make two emissions of one
/// lockfile differ.
fn find_volatile_key(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if VOLATILE_KEYS.contains(&key.as_str()) {
                    return Err(format!(
                        "the document carries the volatile key `{key}`; two emissions \
                         of one lockfile would differ and the projection would stop \
                         being a function of its input"
                    ));
                }
                find_volatile_key(child)?;
            }
            Ok(())
        }
        Value::Array(items) => items.iter().try_for_each(find_volatile_key),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Obligation 1 and 4: the frozen pins, across every ecosystem
// ---------------------------------------------------------------------------

/// INTENT: every entry of the corpus re-projects to the SHA-256 its manifest
///   records, on every machine that runs this suite. One `assert_eq` against a
///   constant is the only thing that makes a change of serializer, of key
///   order, of array order or of number encoding OBSERVABLE at all; without it
///   a projection can change shape and stay green, and the auditor who checks
///   a published document against the lockfile is the one who finds out.
/// CONTEXT: `src/sbom/{cargo,composer,npm}.rs` each pin one fixture of their
///   own ecosystem. Three per-ecosystem pins are three tests that can be met
///   one at a time; this corpus carries the pin across all three at once, from
///   data, so an added ecosystem inherits the obligation instead of needing
///   somebody to remember it. Three of the entries deliberately re-pin the
///   fixtures the per-ecosystem tests pin, so the two layers cross-check each
///   other rather than merely coexisting.
/// CONTEXT (platform independence, Section 8 item 5): these constants were
///   computed on Windows and are re-derived on Linux by the workspace test
///   step of continuous integration. Both platforms compare their own bytes
///   against the SAME file, so a one-byte divergence between operating systems
///   turns one of the two runs red. That is the second-platform proof; a
///   second CI job would add a runner, not a platform.
/// EXPIRES IF: the projection identifier moves to `lockfile-v2`, at which point
///   every pin is recomputed IN THE SAME CHANGE that alters the behaviour --
///   never afterwards, which would leave a window where nothing is red.
#[test]
fn test_intent_corpus_pins_are_reproduced() {
    for entry in corpus() {
        let lockfile_text = read_fixture(&entry.lockfile);
        let manifest_text = entry.manifest.as_ref().map(|name| read_fixture(name));

        // Obligation 4: two projections in one process. An unordered map
        // iterated without sorting shows up here and nowhere else.
        let first =
            project(&entry, &lockfile_text, manifest_text.as_deref()).unwrap_or_else(|error| {
                panic!("corpus entry `{}` fails to project: {error}", entry.id)
            });
        let second =
            project(&entry, &lockfile_text, manifest_text.as_deref()).unwrap_or_else(|error| {
                panic!("corpus entry `{}` fails to project: {error}", entry.id)
            });
        let bytes = first.to_canonical_bytes().expect("canonical bytes");
        assert_eq!(
            bytes,
            second.to_canonical_bytes().expect("canonical bytes"),
            "corpus entry `{}`: two projections of one input in one process \
             disagree, so the projection is not a function of its input",
            entry.id
        );

        // The declared ecosystem is the one the projection reports: a corpus
        // that mislabels an entry would satisfy the obligation for a
        // different ecosystem than the one it claims to cover.
        assert_eq!(
            first.kind().as_str(),
            entry.kind,
            "corpus entry `{}` is declared `{}` but projects as `{}`",
            entry.id,
            entry.kind,
            first.kind().as_str()
        );

        // Obligation 1: the pin. The failure message prints BOTH values and
        // the bytes, because the reader of a red run needs to decide whether
        // the projection changed or the pin was edited, and cannot do that
        // from a boolean.
        let measured = sha256_hex(&bytes);
        assert_eq!(
            measured, entry.canonical_sha256,
            "corpus entry `{}` no longer projects to its frozen hash.\n  \
             pinned in the corpus manifest: {}\n  \
             produced by this build:        {measured}\n  \
             canonical bytes:               {bytes}\n\
             If the projection changed on purpose, the pin moves in the SAME \
             change that moved the projection identifier; if it did not, this \
             build emits different bytes than the machine that measured the pin.",
            entry.id, entry.canonical_sha256
        );

        // The crate's own helper and a plain SHA-256 of the emitted file agree.
        // That equality IS the property the specification sells: an auditor
        // runs `sha256sum` on the published file and needs no vendor software.
        assert_eq!(
            first.canonical_sha256().expect("canonical hash"),
            measured,
            "corpus entry `{}`: the reported hash is not the hash of the \
             emitted bytes",
            entry.id
        );

        // The bytes are one line with no trailing newline, and canonicalising
        // them again is the identity: the published file IS its own canonical
        // form.
        assert!(
            !bytes.contains('\n') && !bytes.contains('\r'),
            "corpus entry `{}`: the canonical form is a single line",
            entry.id
        );
        let reparsed: Value = serde_json::from_str(&bytes)
            .unwrap_or_else(|error| panic!("corpus entry `{}`: {error}", entry.id));
        assert_eq!(
            canonicalize(&reparsed).expect("re-canonicalization"),
            bytes,
            "corpus entry `{}`: re-canonicalising the published bytes changes \
             them, so the file is not its own canonical form",
            entry.id
        );

        check_document_invariants(&first.to_cyclonedx()).unwrap_or_else(|failure| {
            panic!(
                "corpus entry `{}` violates a structural invariant: {failure}",
                entry.id
            )
        });
    }
}

// ---------------------------------------------------------------------------
// Obligations 2 and 3: line endings and the byte-order mark
// ---------------------------------------------------------------------------

/// INTENT: across every ecosystem, a UTF-8 BOM at the head of an input is a
///   loud error, and a CRLF line-ending convention reaches the emitted bytes
///   nowhere. The first keeps a BOM out of the first package name -- a
///   component silently named `\u{feff}serde` would be a wrong SBOM that looks
///   right. The second is what lets an auditor on another operating system
///   re-derive the published bytes from a checkout of their own.
/// CONTEXT: this repository normalises checkouts to LF (`.gitattributes`), so a
///   CRLF fixture committed to the tree would arrive as LF and the test would
///   certify its own copy rather than the behaviour. The CRLF and BOM mutants
///   are therefore built IN MEMORY, at test time, from the same fixture the pin
///   test reads. The class of error is asserted, not merely its existence: an
///   input rejected for the wrong reason is a parser that will accept the next
///   variant of the same input.
/// EXPIRES IF: the projection starts stripping a BOM instead of rejecting it,
///   which would require the specification to say so first.
#[test]
fn test_intent_corpus_rejects_utf8_bom_and_survives_crlf() {
    for entry in corpus() {
        let lockfile_text = read_fixture(&entry.lockfile);
        let manifest_text = entry.manifest.as_ref().map(|name| read_fixture(name));
        let pinned = project(&entry, &lockfile_text, manifest_text.as_deref())
            .unwrap_or_else(|error| panic!("corpus entry `{}` fails to project: {error}", entry.id))
            .to_canonical_bytes()
            .expect("canonical bytes");

        // Obligation 2. Both inputs are converted, because a composer
        // projection reads two files and a rule applied to one of them only
        // would be half a rule.
        let crlf_lockfile = lockfile_text.replace('\n', "\r\n");
        assert_ne!(
            crlf_lockfile, lockfile_text,
            "corpus entry `{}`: the in-memory CRLF copy is identical to the \
             original, so this obligation would assert nothing",
            entry.id
        );
        let crlf_manifest = manifest_text
            .as_ref()
            .map(|text| text.replace('\n', "\r\n"));
        let from_crlf = project(&entry, &crlf_lockfile, crlf_manifest.as_deref())
            .unwrap_or_else(|error| {
                panic!(
                    "corpus entry `{}`: the CRLF copy must project, not fail: {error}",
                    entry.id
                )
            })
            .to_canonical_bytes()
            .expect("canonical bytes");
        assert_eq!(
            from_crlf, pinned,
            "corpus entry `{}`: the line-ending convention of the input reached \
             the emitted bytes",
            entry.id
        );
        assert_eq!(
            sha256_hex(&from_crlf),
            entry.canonical_sha256,
            "corpus entry `{}`: the CRLF projection does not reproduce the \
             frozen pin",
            entry.id
        );

        // Obligation 3, on the lockfile.
        let bom_lockfile = format!("\u{feff}{lockfile_text}");
        match project(&entry, &bom_lockfile, manifest_text.as_deref()) {
            Err(SbomError::UnsupportedLockShape { line, .. }) => assert_eq!(
                line, 1,
                "corpus entry `{}`: a BOM is a defect of the FIRST line",
                entry.id
            ),
            Err(other) => panic!(
                "corpus entry `{}`: a lockfile with a BOM must be rejected as \
                 UnsupportedLockShape -- the shape of the input is what is \
                 wrong -- but was rejected as {other:?}",
                entry.id
            ),
            Ok(projection) => panic!(
                "corpus entry `{}`: a lockfile beginning with a UTF-8 BOM was \
                 PARSED. The first component of the accepted document is `{}`; \
                 a name silently carrying U+FEFF is an SBOM that looks complete \
                 and names a package that does not exist.",
                entry.id,
                projection
                    .components()
                    .first()
                    .map(|component| component.purl.as_str())
                    .unwrap_or("<no component>")
            ),
        }

        // Obligation 3, on the second input of the ecosystem that has one. A
        // manifest is not a lockfile, so its rejection carries its own class.
        if let Some(manifest_text) = &manifest_text {
            let bom_manifest = format!("\u{feff}{manifest_text}");
            match project(&entry, &lockfile_text, Some(&bom_manifest)) {
                Err(SbomError::MalformedManifest { .. }) => {}
                Err(other) => panic!(
                    "corpus entry `{}`: a root manifest with a BOM must be \
                     rejected as MalformedManifest, not as {other:?}",
                    entry.id
                ),
                Ok(_) => panic!(
                    "corpus entry `{}`: a root manifest beginning with a UTF-8 \
                     BOM was parsed",
                    entry.id
                ),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Obligation 6: this repository's real lockfiles, with nothing counted
// ---------------------------------------------------------------------------

/// One real lockfile of the PRIVATE repository, read rather than copied, so a
/// dependency bump cannot leave a stale copy behind. Paths are relative to the
/// private tree root -- see `private_tree`.
struct RealLockfile {
    kind: &'static str,
    lockfile: &'static str,
    manifest: Option<&'static str>,
    subject: &'static str,
}

const REAL_LOCKFILES: [RealLockfile; 4] = [
    RealLockfile {
        kind: "cargo",
        lockfile: "Cargo.lock",
        manifest: None,
        subject: "pkg:cargo/example-workspace@1.0.0",
    },
    RealLockfile {
        kind: "composer",
        lockfile: "portal/composer.lock",
        manifest: Some("portal/composer.json"),
        subject: "pkg:composer/example-org/example-portal@1.0.0",
    },
    RealLockfile {
        kind: "npm",
        lockfile: "portal/package-lock.json",
        manifest: None,
        subject: "pkg:npm/example-portal@1.0.0",
    },
    RealLockfile {
        kind: "npm",
        lockfile: "frontend/package-lock.json",
        manifest: None,
        subject: "pkg:npm/example-frontend@1.0.0",
    },
];

/// INTENT: the four lockfiles this repository actually resolves project without
///   error, are their own canonical form, and satisfy every structural
///   invariant -- component order total, every bom-ref equal to its purl, every
///   reference resolving, no volatile key at any depth, a non-empty top-level
///   set -- and NOTHING here pins a count or a hash. A synthetic corpus proves
///   the projection handles the shapes somebody thought of; only the real
///   lockfiles prove it handles the shapes that actually occur, and the ones
///   that occur change on every dependency bump.
/// CONTEXT: a count assertion over a real lockfile ("514 components") goes red
///   on a legitimate `cargo update`, and a test that goes red for a legitimate
///   reason is a test somebody eventually edits without reading. The pins live
///   on the immutable synthetic corpus, where a red run always means the
///   projection changed. The counts are printed instead, so a reader of the log
///   can still see what was measured.
/// EXPIRES IF: an ecosystem is dropped from the product, or a lockfile moves.
#[test]
fn test_intent_real_lockfiles_project_without_count_pins() {
    let Some(root) = private_tree() else { return };
    for real in REAL_LOCKFILES {
        let entry = CorpusEntry {
            id: real.lockfile.to_string(),
            kind: real.kind.to_string(),
            lockfile: real.lockfile.to_string(),
            manifest: real.manifest.map(str::to_string),
            subject: real.subject.to_string(),
            canonical_sha256: String::new(),
        };
        let lockfile_text = read_private_file(&root, real.lockfile);
        let manifest_text = real
            .manifest
            .map(|relative| read_private_file(&root, relative));

        let projection = project(&entry, &lockfile_text, manifest_text.as_deref())
            .unwrap_or_else(|error| panic!("{} fails to project: {error}", real.lockfile));
        let bytes = projection.to_canonical_bytes().expect("canonical bytes");

        // The published file is its own canonical form: parsing it back and
        // canonicalising again returns the same bytes. This is the property an
        // auditor relies on when they re-serialise the document with their own
        // JCS implementation.
        let reparsed: Value = serde_json::from_str(&bytes)
            .unwrap_or_else(|error| panic!("{}: {error}", real.lockfile));
        assert_eq!(
            canonicalize(&reparsed).expect("re-canonicalization"),
            bytes,
            "{}: re-canonicalising the emitted bytes changes them",
            real.lockfile
        );
        assert_eq!(
            projection.canonical_sha256().expect("canonical hash"),
            sha256_hex(&bytes),
            "{}: the reported hash is not the hash of the emitted bytes",
            real.lockfile
        );

        check_document_invariants(&projection.to_cyclonedx()).unwrap_or_else(|failure| {
            panic!(
                "{} violates a structural invariant: {failure}",
                real.lockfile
            )
        });

        // Non-empty, never counted. An empty component set or an empty
        // top-level set from a real lockfile is the signature of a projection
        // that read nothing and said so quietly.
        assert!(
            !projection.components().is_empty(),
            "{} projects no component at all",
            real.lockfile
        );
        assert!(
            !projection.top_level().is_empty(),
            "{} projects an empty top-level set; an empty dependsOn is \
             reachable only from a lockfile that genuinely declares no \
             dependency, which this one does not",
            real.lockfile
        );

        // Measured and reported, never asserted: these numbers change with
        // every legitimate dependency bump.
        println!(
            "{}: {} components, {} top-level, sha256 {}",
            real.lockfile,
            projection.components().len(),
            projection.top_level().len(),
            sha256_hex(&bytes)
        );
    }
}

// ---------------------------------------------------------------------------
// The checker is itself checked
// ---------------------------------------------------------------------------

/// INTENT: the invariant checker used by the two tests above actually rejects
///   the violations it claims to detect. A checker exercised only on documents
///   that satisfy it is indistinguishable from `fn check(_) -> Ok(())`, and a
///   green suite built on one certifies nothing.
/// CONTEXT: four mutants, each isolating one way a document stops being
///   reproducible or stops being checkable by a stranger: components ordered by
///   NAME instead of by purl (the mutant a stable sort on the wrong key
///   produces, and invisible in any document where the two orders agree); an
///   edge naming a bom-ref nobody declares; a `serialNumber`, which makes two
///   emissions of one lockfile differ; and `version` as a float, which two JSON
///   encoders spell two ways.
/// EXPIRES IF: the invariants move into the projection type itself, at which
///   point the checker has no independent existence to verify.
#[test]
fn test_intent_corpus_invariants_reject_mutated_documents() {
    // A document with two components sharing a name and differing in version:
    // the only shape in which "sorted by name" and "sorted by purl" can
    // disagree, and therefore the only shape in which the mutant is visible.
    let entry = corpus()
        .into_iter()
        .find(|entry| entry.id == "cargo-two-versions")
        .expect("the corpus carries the two-versions entry");
    let base = project_entry(&entry).to_cyclonedx();
    check_document_invariants(&base).expect("the unmutated document satisfies every invariant");

    let mutate = |mutant: &str, edit: &dyn Fn(&mut Value)| {
        let mut doc = base.clone();
        edit(&mut doc);
        assert_ne!(
            doc, base,
            "the `{mutant}` mutant did not change the document"
        );
        let failure = check_document_invariants(&doc).expect_err(&format!(
            "the invariant checker ACCEPTED the `{mutant}` mutant, so a green \
             run of the corpus tests says nothing about that invariant"
        ));
        println!("mutant `{mutant}` rejected: {failure}");
    };

    // Sorted by name instead of by purl. A stable sort on `name` leaves two
    // entries of one name in their input order, so swapping them is exactly
    // what that mistake produces -- and the name order still looks correct.
    mutate("components sorted by name", &|doc: &mut Value| {
        let components = doc["components"].as_array_mut().expect("components");
        let pair = components
            .windows(2)
            .position(|pair| pair[0]["name"] == pair[1]["name"])
            .expect("the fixture carries two components of one name");
        components.swap(pair, pair + 1);
    });

    // An edge naming a component nobody declares. A strict CycloneDX consumer
    // rejects the whole document; a lax one silently drops the edge.
    mutate("dangling dependsOn", &|doc: &mut Value| {
        doc["dependencies"][0]["dependsOn"]
            .as_array_mut()
            .expect("dependsOn")
            .push(json!("pkg:cargo/undeclared@9.9.9"));
    });

    // A serialNumber: the document stops being a function of the lockfile.
    mutate("serialNumber", &|doc: &mut Value| {
        doc.as_object_mut()
            .expect("document")
            .insert("serialNumber".to_string(), json!("urn:uuid:0"));
    });

    // `version` as a float. `1` and `1.0` are the same number and two
    // different files.
    mutate("float version", &|doc: &mut Value| {
        doc.as_object_mut()
            .expect("document")
            .insert("version".to_string(), json!(1.0));
    });

    // A bom-ref that is not the identity: the reference space of the document
    // stops being the purl space of the lockfile.
    mutate("bom-ref detached from purl", &|doc: &mut Value| {
        doc["components"][0]["bom-ref"] = json!("component-0");
    });
}
