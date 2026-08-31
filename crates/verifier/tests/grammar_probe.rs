// SPDX-License-Identifier: Apache-2.0
//! The DIFFERENTIAL GRAMMAR PROBE -- the instrument change of fix-pack R2
//! (review row R2-A I-1).
//!
//! The corpus (`corpus_equivalence.rs`) answers whole packages: it proves the
//! two implementations agree on the cases somebody thought to write down. It
//! cannot find the boundary values nobody thought of, and three review rounds
//! measured exactly that failure mode -- every round found NEW grammar edges
//! (`+5`, `1e-30`, a leading `_`, `+24:00`, a JSON `null` fact) that the
//! corpus was blind to because no case carried them.
//!
//! This file changes the instrument. `tests/fixtures/grammar_probes.txt`
//! carries one JSON scalar per line (JSON-encoded, so a string, a number, a
//! boolean and `null` are unambiguous). Each probe is canonicalized as ONE
//! `working_memory_canonical` entry `{"p": <value>}` through the same path
//! `verify-package` uses -- `seetrex_format::FactValue`'s untagged
//! deserialization, then the shared validation of `compute_verdict_hash`,
//! then `serialize_wm_canonical_jcs`. The Python reference
//! (`reference/run_grammar_probes.py`) canonicalizes the same file through
//! `canonical_fact_value` + its own JCS. Equality is asserted PER VALUE, so a
//! divergence names the exact input instead of a hash that differs for an
//! unknown reason.
//!
//! Output format, one line per probe, three TAB-separated fields:
//!
//! ```text
//! <input line>\t<verdict>\t<detail>
//! ```
//!
//! `<verdict>` is the canonical JCS object (`{"p":"100.5"}`), or the literal
//! `REJECT` when the implementation refuses the value, or `PANIC` when it
//! crashes. `<detail>` carries the implementation's own wording and is NOT
//! compared -- the two implementations are different programs and their error
//! prose is not part of the format. Fields 1 and 2 ARE compared.
//!
//! `PANIC` on the Rust side is a failure line EXCEPT inside one named band,
//! which is the only tolerated crash of the reference implementation.
//!
//! # The one tolerated PANIC: `KNOWN_REFERENCE_DEFECT`
//!
//! SPEC_VERDICT_PACKAGE_V1 4.1 (Duration) declares that between the format's
//! bound (summed seconds fitting a signed 64-bit integer) and the narrower
//! bound of the reference's millisecond-scaled representation -- magnitude
//! strictly above `i64::MAX / 1000` = 9_223_372_036_854_775 seconds -- the
//! reference CRASHES instead of reaching `String`. That is a declared defect
//! of the reference implementation, not of the format, and paying it down
//! means a version bump of the reference; until then it is carried as
//! version-bump debt of the reference and NOT as a probe divergence.
//!
//! So a probe whose summed duration seconds land inside that band is a NAMED
//! expectation, checked in both directions:
//!
//! * Rust `PANIC` + Python yielding the specification's answer (the value
//!   falls through to `String` and canonicalizes verbatim) is recorded as
//!   `KNOWN_REFERENCE_DEFECT` and counts as AGREEMENT, with a printed notice
//!   listing every value that took the exemption (`--nocapture` to see it on
//!   a green run).
//! * a `PANIC` OUTSIDE the band is a failure, as before.
//! * a value INSIDE the band that does NOT panic is also a failure: the band
//!   is declared, so it must not silently widen or heal without the spec
//!   sentence moving with it. Shrinking [`DECLARED_PANIC_BOUND_SECS`] turns
//!   `"9223372036854775s"` -- which the spec declares a valid duration --
//!   into a band member that is expected to crash, and the test goes red.
//! * any other Python answer for a band value is a failure: the exemption
//!   covers the reference's crash, never a second divergence hiding behind
//!   it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use seetrex_format::types::FactValue;
use seetrex_verifier::canonical::{
    compute_verdict_hash, serialize_wm_canonical_jcs, VerdictCanonicalInput,
};
use seetrex_verifier::types::VerdictOutcome;

/// The probe list. Lives inside the crate, so it travels with the public
/// export exactly like the corpus.
const PROBES_REL: &str = "tests/fixtures/grammar_probes.txt";

const RUST_OUT: &str = "grammar_probe_rust.txt";
const PYTHON_OUT: &str = "grammar_probe_python.txt";

/// The floor the fix-pack pinned for the instrument itself. The SAME numeral
/// the Python leg pins (`PROBE_FLOOR` in `reference/run_grammar_probes.py`):
/// two legs with two floors is one leg unguarded (review row R3-A M-2).
const PROBE_FLOOR: usize = 520;

/// The bound SPEC_VERDICT_PACKAGE_V1 4.1 (Duration) declares for the
/// reference's internal millisecond-scaled representation: `i64::MAX / 1000`
/// seconds. A summed duration whose MAGNITUDE is strictly above this and
/// still fits `i64` is inside the declared crash band -- see the module
/// header. This constant IS the declared bound; moving it must move the spec
/// sentence too.
const DECLARED_PANIC_BOUND_SECS: i64 = i64::MAX / 1000;

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Where both legs drop their answers. Derived from the test binary's own
/// target directory (`<target>/<profile>/seetrex-verifier` -> `<target>`) so
/// the two legs meet in the same place whatever `CARGO_TARGET_DIR` says;
/// `PROBE_OUT_DIR` overrides it for a caller that wants them elsewhere.
fn out_dir() -> PathBuf {
    if let Ok(d) = std::env::var("PROBE_OUT_DIR") {
        return PathBuf::from(d);
    }
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_seetrex-verifier"));
    bin.parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("the test binary always sits under <target>/<profile>/")
}

/// The probe list, one JSON scalar per line. A trailing CR is stripped: the
/// repo pins `eol=lf`, but a checkout on a machine that ignores
/// `.gitattributes` must not shift every answer by one byte.
fn read_probes() -> Vec<String> {
    let path = crate_dir().join(PROBES_REL);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} is not readable: {e}", path.display()));
    raw.lines()
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// One-line, tab-free rendering of an implementation's own error prose.
fn flatten(msg: &str) -> String {
    msg.chars()
        .map(|c| if c == '\t' || c == '\n' || c == '\r' { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Canonicalize ONE probe through the verifier's own path.
///
/// Returns `(verdict, detail)`. Every step that can fail is INSIDE the
/// `catch_unwind`, because the crash this probe list exists to surface
/// (`"9223372036854775807s"`, review row R2-A C-4) happens during
/// deserialization, not after it.
fn canonicalize_rust(line: &str) -> (String, String) {
    let doc = format!("{{\"p\":{line}}}");
    let outcome = std::panic::catch_unwind(|| {
        let wm: BTreeMap<String, FactValue> = match serde_json::from_str(&doc) {
            Ok(wm) => wm,
            Err(e) => return Err(format!("deserialize: {e}")),
        };
        let input = VerdictCanonicalInput {
            tenant_id: uuid::Uuid::nil(),
            ruleset_id: "probe".to_string(),
            ruleset_version: 1,
            control_id: "probe".to_string(),
            verdict_outcome: VerdictOutcome::Satisfied,
            evidence_refs: Vec::new(),
            engine_semantic_version: 1,
            derived_at: chrono::DateTime::from_timestamp(0, 0)
                .expect("the epoch is a valid instant"),
            ruleset_content_hash: "00".repeat(32),
            working_memory_canonical: wm.clone(),
        };
        // The validation duties of the preimage pipeline (ASCII fact values,
        // no NaN/Inf) live here; a probe the verifier would refuse must show
        // up as REJECT, not as a canonical string nobody would ever hash.
        if let Err(e) = compute_verdict_hash(&input) {
            return Err(format!("validate: {e}"));
        }
        serialize_wm_canonical_jcs(&wm).map_err(|e| format!("serialize: {e}"))
    });
    match outcome {
        Ok(Ok(jcs)) => (jcs, String::new()),
        Ok(Err(reason)) => ("REJECT".to_string(), flatten(&reason)),
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic payload>".to_string());
            ("PANIC".to_string(), flatten(&msg))
        }
    }
}

/// The summed seconds of a probe string read through the Duration grammar of
/// SPEC_VERDICT_PACKAGE_V1 4.1: optional leading `-`, then one or more
/// `<digits><unit>` groups with unit `s`/`m`/`h`/`d`, summed, surrounding
/// whitespace trimmed. `None` when the string is not a duration at all, or
/// when the sum overflows the widened accumulator this helper uses.
///
/// Deliberately an INDEPENDENT reading of the grammar and not a call into the
/// crate: the band this feeds is a claim ABOUT the implementation, so it must
/// not be computed by the implementation it judges.
fn duration_seconds(s: &str) -> Option<i128> {
    let t = s.trim();
    let (negative, rest) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t),
    };
    if rest.is_empty() {
        return None;
    }
    let mut total: i128 = 0;
    let mut digits = String::new();
    for c in rest.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let unit: i128 = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            _ => return None,
        };
        if digits.is_empty() {
            return None;
        }
        let n: i128 = digits.parse().ok()?;
        total = total.checked_add(n.checked_mul(unit)?)?;
        digits.clear();
    }
    if !digits.is_empty() {
        return None;
    }
    Some(if negative { -total } else { total })
}

/// Is this string a duration inside the DECLARED crash band -- summed seconds
/// of magnitude strictly above [`DECLARED_PANIC_BOUND_SECS`] and still within
/// `i64`? Above `i64` the value is not a duration at all and both
/// implementations must reach `String`.
fn in_declared_panic_band(s: &str) -> bool {
    match duration_seconds(s) {
        Some(v) => {
            let magnitude = v.unsigned_abs();
            magnitude > u128::from(DECLARED_PANIC_BOUND_SECS as u64)
                && magnitude <= u128::from(i64::MAX as u64)
        }
        None => false,
    }
}

/// The same question for a whole probe: a band duration nested at any depth
/// inside a list crashes the reference exactly like a bare one.
fn probe_in_declared_panic_band(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::String(s) => in_declared_panic_band(s),
        serde_json::Value::Array(items) => items.iter().any(probe_in_declared_panic_band),
        _ => false,
    }
}

/// The answer the SPECIFICATION gives for a band value: no candidate takes
/// it, so it falls through to `String` and canonicalizes verbatim. Strings
/// and lists of them re-serialize identically under JCS and under
/// `serde_json`, which is the whole of the JSON these probes carry.
fn spec_fallthrough_verdict(v: &serde_json::Value) -> String {
    format!(
        "{{\"p\":{}}}",
        serde_json::to_string(v).expect("a probe value always re-serializes")
    )
}

/// Leg 1: answer every probe with the Rust implementation and persist the
/// answers. It only RECORDS what the implementation does; the verdict on
/// those answers is [`test_grammar_probe_legs_agree`].
fn write_rust_answers() -> Vec<String> {
    let probes = read_probes();
    assert!(
        probes.len() >= PROBE_FLOOR,
        "the probe list IS the instrument: {} values is below the {PROBE_FLOOR} floor \
         the fix-pack pinned; a shrinking instrument is how the boundary defects came back",
        probes.len()
    );
    // The panics are EXPECTED output of this leg; the default hook would
    // print a backtrace per crashing probe and bury the report.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut out = String::new();
    for line in &probes {
        let (verdict, detail) = canonicalize_rust(line);
        out.push_str(line);
        out.push('\t');
        out.push_str(&verdict);
        out.push('\t');
        out.push_str(&detail);
        out.push('\n');
    }
    std::panic::set_hook(previous);
    let dir = out_dir();
    std::fs::create_dir_all(&dir).expect("the target directory is writable");
    std::fs::write(dir.join(RUST_OUT), out).expect("the Rust probe answers are writable");
    probes
}

/// SHA-256 of a text file with CRLF normalized to LF -- the same digest the
/// Python leg stamps into its header. The repository pins `eol=lf`, but a
/// checkout on a machine that ignores `.gitattributes` must not change the
/// stamp: it identifies the CONTENT both legs read.
fn lf_sha256(path: &Path) -> String {
    let raw = std::fs::read(path).unwrap_or_else(|e| panic!("{} is unreadable: {e}", path.display()));
    let mut normalized: Vec<u8> = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\r' && i + 1 < raw.len() && raw[i + 1] == b'\n' {
            i += 1;
            continue;
        }
        normalized.push(raw[i]);
        i += 1;
    }
    let mut hasher = Sha256::new();
    hasher.update(&normalized);
    format!("{:x}", hasher.finalize())
}

/// Runs the Python leg. ALWAYS -- never reads an answer file somebody else
/// left behind.
///
/// The previous revision returned early when `grammar_probe_python.txt`
/// already existed, which made a sabotaged `canonical_fact_value` invisible
/// as long as a stale answer file from a green run sat in the target
/// directory (review rows R3-A C-4 / R3-B C-3): the mutant never ran, so its
/// answers never differed. The file is now deleted first, regenerated by
/// spawning the interpreter, and then CHECKED against a header the runner
/// stamps with the digests of the reference it imported and the probe list it
/// read. A missing interpreter fails loud; it does not fall back to a file.
fn ensure_python_answers(dir: &Path) -> Result<String, String> {
    let path = dir.join(PYTHON_OUT);
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("{} could not be removed before regenerating: {e}", path.display()))?;
    }
    let reference_dir = crate_dir().join("reference");
    let script = reference_dir.join("run_grammar_probes.py");
    let mut last = String::new();
    let mut ran = false;
    for exe in ["python3", "python"] {
        match Command::new(exe).arg(&script).arg(dir).output() {
            Ok(o) if o.status.success() => {
                ran = true;
                break;
            }
            Ok(o) => {
                last = format!(
                    "{exe} exited {:?}: {}",
                    o.status.code(),
                    String::from_utf8_lossy(&o.stderr)
                );
            }
            Err(e) => last = format!("{exe}: {e}"),
        }
    }
    if !ran {
        return Err(format!(
            "the Python leg could not be executed ({last}); the differential probe has              no second implementation to compare against and a leftover answer file is              NOT accepted in its place"
        ));
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("{} unreadable after the runner succeeded: {e}", path.display()))?;

    // The header the runner stamped must describe the files THIS process is
    // about to compare against.
    let expected = format!(
        "# py_sha256={} probes_sha256={}",
        lf_sha256(&reference_dir.join("seetrex_verifier.py")),
        lf_sha256(&crate_dir().join(PROBES_REL)),
    );
    let first = text.split('\n').next().unwrap_or("").trim_end_matches('\r');
    if first != expected {
        return Err(format!(
            "the Python answer file does not describe the files under test.\n  \
             header  : {first}\n  expected: {expected}\nThe answers were produced \
             from a different reference or a different probe list."
        ));
    }
    Ok(text)
}

/// Leg 2: the two implementations must give the SAME answer to every probe.
///
/// Prints every differing line before failing -- the list IS the finding, and
/// a test that stopped at the first divergence would hide the other N.
///
/// ONE test, not two, on purpose: `std::panic::set_hook` is process-global, so
/// two `#[test]`s silencing it in parallel restore each other's hook and the
/// caught panics leak onto the report.
#[test]
fn test_grammar_probe_legs_agree() {
    let probes = write_rust_answers();
    let dir = out_dir();
    let rust = std::fs::read_to_string(dir.join(RUST_OUT)).expect("the Rust leg just wrote it");
    let python = match ensure_python_answers(&dir) {
        Ok(text) => text,
        Err(e) => panic!("{e}"),
    };

    fn split(text: &str) -> Vec<(String, String, String)> {
        text.lines()
            .filter(|l| !l.is_empty() && !l.starts_with("# py_sha256="))
            .map(|l| {
                let mut f = l.splitn(3, '\t');
                (
                    f.next().unwrap_or("").to_string(),
                    f.next().unwrap_or("").to_string(),
                    f.next().unwrap_or("").to_string(),
                )
            })
            .collect()
    }
    let (r, p) = (split(&rust), split(&python));
    assert_eq!(
        r.len(),
        probes.len(),
        "the Rust leg dropped a probe on the floor"
    );
    assert_eq!(
        r.len(),
        p.len(),
        "the two legs answered a different number of probes ({} vs {}) -- they did not \
         read the same probe list",
        r.len(),
        p.len()
    );

    let mut diffs: Vec<String> = Vec::new();
    let mut known: Vec<String> = Vec::new();
    for (rl, pl) in r.iter().zip(p.iter()) {
        assert_eq!(
            rl.0, pl.0,
            "the two legs answered the probes in a different order"
        );
        let value: serde_json::Value =
            serde_json::from_str(&rl.0).unwrap_or(serde_json::Value::Null);
        let banded = probe_in_declared_panic_band(&value);
        let mut diverge = |why: &str| {
            diffs.push(format!(
                "  input : {}\n    rust  : {} [{}]\n    python: {} [{}]\n    why   : {}",
                rl.0, rl.1, rl.2, pl.1, pl.2, why
            ));
        };
        if rl.1 == "PANIC" {
            if !banded {
                diverge(
                    "PANIC outside the declared reference-defect band -- a spec-valid \
                     input must not crash the reference",
                );
            } else if pl.1 == spec_fallthrough_verdict(&value) {
                known.push(rl.0.clone());
            } else {
                diverge(
                    "inside the declared band, but the Python leg did not give the \
                     specification's String fall-through -- the exemption covers the \
                     reference's crash, not a second divergence behind it",
                );
            }
            continue;
        }
        if banded {
            diverge(
                "inside the declared reference-defect band but the reference did NOT \
                 crash -- the band healed or widened without the spec sentence moving",
            );
            continue;
        }
        if rl.1 != pl.1 {
            diverge("the two implementations disagree");
        }
    }
    if !known.is_empty() {
        println!(
            "KNOWN_REFERENCE_DEFECT: {} probe(s) inside the declared crash band of \
             SPEC_VERDICT_PACKAGE_V1 4.1 (Duration) -- summed seconds of magnitude above \
             i64::MAX/1000 = {}. The reference aborts where the format says String; \
             carried as version-bump debt of the reference, not as a divergence:\n{}",
            known.len(),
            DECLARED_PANIC_BOUND_SECS,
            known
                .iter()
                .map(|v| format!("  {v}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    assert!(
        diffs.is_empty(),
        "{} of {} grammar probes diverge between the Rust and the Python \
         implementation:\n{}\n\nEach line above is a value the specification does not \
         pin tightly enough (or a reference defect). Fix the SPEC sentence first, then \
         both implementations.",
        diffs.len(),
        r.len(),
        diffs.join("\n")
    );
}
