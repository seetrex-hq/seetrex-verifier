// SPDX-License-Identifier: Apache-2.0
//! INTENT: every divergence the review found between the two implementations
//! is either carried by a corpus case or declared, by name, as one the corpus
//! cannot carry.
//!
//! CONTEXT: the equivalence work catalogued its findings in a session ledger
//! -- one row per divergence, each with an identifier -- and linked them to
//! the corpus in PROSE. Prose does not fail. Three review rounds each found a
//! new grammar edge, and the only reason the earlier ones stayed fixed is
//! that somebody remembered to write the case; nothing said so if they did
//! not. The ledger is a working document of the project and is not exported,
//! so the link cannot be a path out of the crate: what travels is the
//! IDENTIFIER LIST, mirrored into `tests/fixtures/spec_gap_ids.txt`.
//!
//! EXPIRES IF: the corpus stops being the instrument that decides equivalence
//! -- for instance if the differential grammar probe absorbs the value-level
//! cases entirely -- or if the ledger's identifier scheme is replaced. Until
//! then a new divergence means a new identifier here AND a case, or an
//! explicit line in the `[text pins]` section saying why no package can
//! exercise it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// The `SPEC-GAP-Q<n>` identifiers whose finding a verdict package CAN
/// exercise. The rest of the `Q` series are gaps in prose the specification
/// closed with a sentence about a CLI shape, an output order, a stream or a
/// size bound -- nothing a package's bytes can make a verifier get wrong.
const CORPUS_TESTABLE_Q: &[&str] = &[
    "SPEC-GAP-Q3",
    "SPEC-GAP-Q5",
    "SPEC-GAP-Q7",
    "SPEC-GAP-Q8",
    "SPEC-GAP-Q10",
    "SPEC-GAP-Q11",
    "SPEC-GAP-Q12",
    "SPEC-GAP-Q13",
    "SPEC-GAP-Q14",
    "SPEC-GAP-Q15",
];

/// Families whose every member must be carried by a corpus case: the value
/// grammar of section 4.1, the ASCII duty of section 4, the leap-second
/// mapping of section 7.3, and the numbered divergences.
fn needs_a_corpus_case(id: &str) -> bool {
    id.starts_with("SPEC-GAP-4.1")
        || id.starts_with("SPEC-GAP-4-ascii")
        || id.starts_with("SPEC-GAP-7.3")
        || id.starts_with("DIV-")
        || CORPUS_TESTABLE_Q.contains(&id)
}

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The mirrored identifier list: id -> section name.
fn ledger_ids() -> BTreeMap<String, String> {
    let path = crate_dir().join("tests/fixtures/spec_gap_ids.txt");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} is unreadable: {e}", path.display()));
    let mut section = String::new();
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    // `split('\n')`, never `lines()` on a lenient splitter: the two
    // implementations must see the same number of lines in every fixture.
    for raw in text.split('\n') {
        let line = raw.trim_end_matches('\r').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            section = rest
                .strip_suffix(']')
                .unwrap_or_else(|| panic!("malformed section header {line:?}"))
                .to_string();
            continue;
        }
        assert!(
            !section.is_empty(),
            "identifier {line:?} appears before any [section] header"
        );
        assert!(
            line.starts_with("SPEC-GAP-") || line.starts_with("DIV-"),
            "{line:?} is not a ledger identifier"
        );
        assert!(
            out.insert(line.to_string(), section.clone()).is_none(),
            "identifier {line:?} is listed twice"
        );
    }
    assert!(
        out.len() >= 40,
        "the mirrored identifier list shrank to {} entries; it is the record of \
         what three review rounds found, not a scratch file",
        out.len()
    );
    out
}

/// id -> the corpus cases that carry it. A case may carry more than one
/// `# gap:` line: the numbered divergences and the section-4.1 families
/// overlap on the values that first exposed them.
fn corpus_gaps() -> BTreeMap<String, BTreeSet<String>> {
    let dir = crate_dir().join("tests/fixtures/corpus");
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut cases = 0usize;
    for entry in std::fs::read_dir(&dir).expect("the corpus directory is readable") {
        let entry = entry.expect("a corpus entry is readable");
        if !entry.file_type().expect("a file type is readable").is_dir() {
            continue;
        }
        cases += 1;
        let name = entry.file_name().to_string_lossy().to_string();
        let expected = entry.path().join("expected.txt");
        let text = std::fs::read_to_string(&expected)
            .unwrap_or_else(|e| panic!("{} is unreadable: {e}", expected.display()));
        for raw in text.split('\n') {
            let line = raw.trim_end_matches('\r');
            if let Some(rest) = line.strip_prefix("# gap:") {
                out.entry(rest.trim().to_string())
                    .or_default()
                    .insert(name.clone());
            }
        }
    }
    assert!(
        cases >= 90,
        "the corpus fell to {cases} cases; this test reads the same directory the \
         equivalence runner does and a shrinking corpus is how a gap goes quiet"
    );
    out
}

#[test]
fn test_intent_every_spec_gap_has_a_corpus_case() {
    let ledger = ledger_ids();
    let carried = corpus_gaps();

    // (a) no case may invent an identifier.
    let unknown: Vec<String> = carried
        .iter()
        .filter(|(id, _)| !ledger.contains_key(*id))
        .map(|(id, cases)| {
            format!(
                "  {id} (carried by {})",
                cases.iter().cloned().collect::<Vec<_>>().join(", ")
            )
        })
        .collect();
    assert!(
        unknown.is_empty(),
        "corpus cases carry {} identifier(s) that the mirrored ledger list does not \
         know:\n{}\n\nAdd the row to the ledger and the identifier to \
         tests/fixtures/spec_gap_ids.txt, or fix the typo.",
        unknown.len(),
        unknown.join("\n")
    );

    // (b) every corpus-testable identifier must actually be carried.
    let orphan: Vec<String> = ledger
        .keys()
        .filter(|id| needs_a_corpus_case(id) && !carried.contains_key(*id))
        .cloned()
        .collect();
    assert!(
        orphan.is_empty(),
        "{} ledger identifier(s) name a divergence a package can exercise, and NO \
         corpus case carries them:\n  {}\n\nWrite the case (`# gap: <id>` in its \
         expected.txt). A divergence with no case is a divergence that comes back.",
        orphan.len(),
        orphan.join("\n  ")
    );

    // (c) the two sections must mean what they say, so that an identifier
    // cannot dodge (b) by being filed under [text pins].
    let misfiled: Vec<String> = ledger
        .iter()
        .filter(|(id, section)| needs_a_corpus_case(id) != (section.as_str() == "corpus-backed"))
        .map(|(id, section)| format!("  {id} is filed under [{section}]"))
        .collect();
    assert!(
        misfiled.is_empty(),
        "{} identifier(s) are in the wrong section of tests/fixtures/spec_gap_ids.txt:\n{}",
        misfiled.len(),
        misfiled.join("\n")
    );
}
